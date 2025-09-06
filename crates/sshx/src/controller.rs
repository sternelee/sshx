//! Network gRPC client allowing server control of terminals.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use anyhow::Result;
use data_encoding::BASE32_NOPAD;
use futures_lite::StreamExt;
use iroh::protocol::Router;
use iroh::{Endpoint, NodeAddr, SecretKey, Watcher};
use iroh_gossip::{
    api::{Event, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sshx_core::proto::{client_update::ClientMessage, server_update::ServerMessage, NewShell};
use sshx_core::{rand_alphanumeric, Sid};
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::{self, Duration};
use tracing::{debug, error, warn};

use crate::encrypt::Encrypt;
use crate::runner::{Runner, ShellData};

/// A ticket that contains the necessary information to join a session.
#[derive(Debug, Serialize, Deserialize)]
struct Ticket {
    /// The gossip topic to join.
    topic: TopicId,
    /// The node addresses of the host.
    nodes: Vec<NodeAddr>,
    /// The encryption key for the session.
    key: String,
}

impl Ticket {
    /// Deserialize from a slice of bytes to a Ticket.
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(Into::into)
    }

    /// Serialize from a `Ticket` to a `Vec` of bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serde_json::to_vec is infallible")
    }
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = BASE32_NOPAD.encode(&self.to_bytes()[..]);
        text.make_ascii_lowercase();
        write!(f, "{}", text)
    }
}

impl FromStr for Ticket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        Self::from_bytes(&bytes)
    }
}

/// Handles a single session's communication with the remote server.
pub struct Controller {
    runner: Runner,
    encrypt: Encrypt,
    encryption_key: String,

    // Iroh related fields
    endpoint: Endpoint,
    gossip: Gossip,
    topic: TopicId,
    gossip_sender: Option<GossipSender>,
    gossip_receiver: Option<GossipReceiver>,
    router: Option<iroh::protocol::Router>,

    ticket: String,
    write_ticket: Option<String>,

    /// Channels with backpressure routing messages to each shell task.
    shells_tx: HashMap<Sid, mpsc::Sender<ShellData>>,
    /// Channel shared with tasks to allow them to output client messages.
    output_tx: mpsc::Sender<ClientMessage>,
    /// Owned receiving end of the `output_tx` channel.
    output_rx: mpsc::Receiver<ClientMessage>,
}

impl Controller {
    /// Construct a new controller, connecting to the remote server.
    pub async fn new(
        _origin: &str,
        _name: &str,
        runner: Runner,
        enable_readers: bool,
    ) -> Result<Self> {
        debug!("creating new iroh endpoint");
        let secret_key = SecretKey::generate(&mut OsRng);

        // Create an endpoint.
        let endpoint = Endpoint::builder()
            .secret_key(secret_key)
            .discovery_n0()
            .bind()
            .await?;

        println!("> our node id: {}", endpoint.node_id());

        let gossip = Gossip::builder().spawn(endpoint.clone());

        let router = Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .spawn();

        let topic = TopicId::from_bytes({
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            bytes
        });

        let encryption_key = rand_alphanumeric(14); // 83.3 bits of entropy

        let kdf_task = {
            let encryption_key = encryption_key.clone();
            task::spawn_blocking(move || Encrypt::new(&encryption_key))
        };

        let (write_password, _kdf_write_password_task) = if enable_readers {
            let write_password = rand_alphanumeric(14); // 83.3 bits of entropy
            let task = {
                let write_password = write_password.clone();
                task::spawn_blocking(move || Encrypt::new(&write_password))
            };
            (Some(write_password), Some(task))
        } else {
            (None, None)
        };

        let me = endpoint.node_addr().initialized().await;
        let ticket = Ticket {
            topic,
            nodes: vec![me],
            key: encryption_key.clone(),
        };
        let ticket_str = ticket.to_string();

        let write_ticket = if let Some(write_password) = write_password {
            Some(format!("{},{}", ticket_str, write_password))
        } else {
            None
        };

        let encrypt = kdf_task.await?;

        let (output_tx, output_rx) = mpsc::channel(64);
        Ok(Self {
            runner,
            encrypt,
            encryption_key,
            endpoint,
            gossip,
            topic,
            gossip_sender: None,
            gossip_receiver: None,
            router: Some(router),
            ticket: ticket_str,
            write_ticket,
            shells_tx: HashMap::new(),
            output_tx,
            output_rx,
        })
    }

    /// Returns the name of the session.
    pub fn name(&self) -> &str {
        // TODO: Is there a better name?
        "iroh-session"
    }

    /// Returns the ticket of the session.
    pub fn url(&self) -> &str {
        &self.ticket
    }

    /// Returns the write ticket of the session, if it exists.
    pub fn write_url(&self) -> Option<&str> {
        self.write_ticket.as_deref()
    }

    /// Returns the encryption key for this session, hidden from the server.
    pub fn encryption_key(&self) -> &str {
        &self.encryption_key
    }

    /// Run the controller forever, listening for requests from the server.
    pub async fn run(&mut self) -> ! {
        if let Err(err) = self.try_run().await {
            error!(%err, "controller failed");
        }
        // Loop forever to keep the process alive.
        loop {
            time::sleep(Duration::from_secs(3600)).await;
        }
    }

    async fn try_run(&mut self) -> Result<()> {
        let (sender, receiver) = self
            .gossip
            .subscribe_and_join(self.topic, vec![])
            .await?
            .split();

        self.gossip_sender = Some(sender);
        self.gossip_receiver = Some(receiver);

        let sender = self.gossip_sender.as_ref().unwrap();
        let mut receiver = self.gossip_receiver.take().unwrap();

        loop {
            tokio::select! {
                // 1. Handle outgoing messages from local shells
                Some(msg) = self.output_rx.recv() => {
                    // For now, pass raw message bytes until prost version mismatch is resolved
                    let msg_bytes = format!("{:?}", msg).into_bytes(); // Temporary workaround
                    sender.broadcast(msg_bytes.into()).await?;
                }
                // 2. Handle incoming messages from the gossip topic
                Ok(Some(event)) = receiver.try_next() => {
                    if let Event::Received(msg) = event {
                        // For now, skip deserialization until prost version mismatch is resolved
                        // TODO: Parse received messages properly once prost versions are aligned
                        warn!("Received gossip message: {} bytes", msg.content.len());
                    }
                }
            }
        }
    }

    async fn handle_server_message(&mut self, message: ServerMessage) {
        match message {
            ServerMessage::Input(input) => {
                let data = self.encrypt.segment(0x200000000, input.offset, &input.data);
                if let Some(sender) = self.shells_tx.get(&Sid(input.id)) {
                    sender.send(ShellData::Data(data)).await.ok();
                } else {
                    warn!(%input.id, "received data for non-existing shell");
                }
            }
            ServerMessage::CreateShell(new_shell) => {
                let id = Sid(new_shell.id);
                let center = (new_shell.x, new_shell.y);
                if !self.shells_tx.contains_key(&id) {
                    self.spawn_shell_task(id, center);
                } else {
                    warn!(%id, "server asked to create duplicate shell");
                }
            }
            ServerMessage::CloseShell(id) => {
                self.shells_tx.remove(&Sid(id));
            }
            ServerMessage::Sync(seqnums) => {
                for (id, seq) in seqnums.map {
                    if let Some(sender) = self.shells_tx.get(&Sid(id)) {
                        sender.send(ShellData::Sync(seq)).await.ok();
                    } else {
                        warn!(%id, "received sequence number for non-existing shell");
                    }
                }
            }
            ServerMessage::Resize(msg) => {
                if let Some(sender) = self.shells_tx.get(&Sid(msg.id)) {
                    sender.send(ShellData::Size(msg.rows, msg.cols)).await.ok();
                } else {
                    warn!(%msg.id, "received resize for non-existing shell");
                }
            }
            ServerMessage::Ping(ts) => {
                let pong = ClientMessage::Pong(ts);
                self.output_tx.send(pong).await.ok();
            }
            ServerMessage::Error(err) => {
                error!(?err, "error received from peer");
            }
        }
    }

    /// Entry point to start a new terminal task on the client.
    fn spawn_shell_task(&mut self, id: Sid, center: (i32, i32)) {
        let (shell_tx, shell_rx) = mpsc::channel(16);
        let opt = self.shells_tx.insert(id, shell_tx);
        debug_assert!(opt.is_none(), "shell ID cannot be in existing tasks");

        let runner = self.runner.clone();
        let encrypt = self.encrypt.clone();
        let output_tx = self.output_tx.clone();
        tokio::spawn(async move {
            debug!(%id, "spawning new shell");
            let new_shell = NewShell {
                id: id.0,
                x: center.0,
                y: center.1,
            };
            if let Err(err) = output_tx.send(ClientMessage::CreatedShell(new_shell)).await {
                error!(%id, ?err, "failed to send shell creation message");
                return;
            }
            if let Err(err) = runner.run(id, encrypt, shell_rx, output_tx.clone()).await {
                let err = ClientMessage::Error(err.to_string());
                output_tx.send(err).await.ok();
            }
            output_tx.send(ClientMessage::ClosedShell(id.0)).await.ok();
        });
    }

    /// Terminate this session gracefully.
    pub async fn close(&mut self) -> Result<()> {
        debug!("closing session");
        if let Some(router) = self.router.take() {
            router
                .shutdown()
                .await
                .map_err(|e| anyhow::anyhow!("router shutdown failed: {}", e))?;
        }
        Ok(())
    }
}
