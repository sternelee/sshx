//! Network gRPC client allowing server control of terminals.

use anyhow::Result;
use futures_lite::StreamExt;
use std::collections::HashMap;

use shared::{
    crypto::rand_alphanumeric,
    events::{ClientMessage, NewShell, ServerMessage},
    p2p::{P2pConfig, P2pNode, P2pSession},
    ticket::SessionTicket,
    Sid,
};
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::{self, Duration};
use tracing::{debug, error, warn};

use crate::encrypt::Encrypt;
use crate::runner::{Runner, ShellData};

/// Handles a single session's communication with the remote server.
pub struct Controller {
    runner: Runner,
    encrypt: Encrypt,
    encryption_key: String,

    // P2P networking
    p2p_node: P2pNode,
    p2p_session: P2pSession,

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
    ) -> Result<Self, anyhow::Error> {
        Self::with_relay(None, runner, enable_readers).await
    }

    /// Construct a new controller with custom relay server configuration.
    pub async fn with_relay(
        relay_url: Option<String>,
        runner: Runner,
        enable_readers: bool,
    ) -> Result<Self, anyhow::Error> {
        let p2p_config = P2pConfig {
            relay_url,
            prefer_ipv4: true,
            debug: true,
        };

        let p2p_node = P2pNode::new(p2p_config).await?;
        println!("> our node id: {}", p2p_node.node_id());

        let p2p_session = p2p_node.create_session().await?;
        let topic = *p2p_session.topic();
        let encryption_key = p2p_session.encryption_key().to_string();

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

        let me = p2p_node.node_addr().await;
        let ticket = SessionTicket::new(topic, vec![me], encryption_key.clone());
        let ticket_str = ticket.to_string();

        let write_ticket = if let Some(write_password) = write_password {
            let mut write_ticket = ticket.clone();
            write_ticket.write_password = Some(write_password);
            Some(write_ticket.to_shareable_string(true))
        } else {
            None
        };

        let encrypt = kdf_task.await?;

        let (output_tx, output_rx) = mpsc::channel(64);
        Ok(Self {
            runner,
            encrypt,
            encryption_key,
            p2p_node,
            p2p_session,
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

    async fn try_run(&mut self) -> Result<(), anyhow::Error> {
        let mut event_stream = self.p2p_session.event_stream();
        let sender = self.p2p_session.sender();

        loop {
            tokio::select! {
                // 1. Handle outgoing messages from local shells
                Some(msg) = self.output_rx.recv() => {
                    // For now, pass raw message bytes until prost version mismatch is resolved
                    let msg_bytes = format!("{:?}", msg).into_bytes(); // Temporary workaround
                    sender.broadcast(msg_bytes.into()).await?;
                }
                // 2. Handle incoming messages from the P2P session
                Some(Ok(event)) = async {
                    if let Some(ref mut stream) = event_stream {
                        stream.next().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    match event {
                        iroh_gossip::api::Event::Received(msg) => {
                            // For now, skip deserialization until prost versions are aligned
                            // TODO: Parse received messages properly once prost versions are aligned
                            warn!("Received P2P message: {} bytes", msg.content.len());
                        }
                        _ => {
                            debug!("Received other P2P event: {:?}", event);
                        }
                    }
                }
            }
        }
    }

    async fn handle_server_message(&mut self, message: ServerMessage) {
        match message {
            ServerMessage::Input(input) => {
                let data = self.encrypt.segment(0x200000000, input.offset, &input.data);
                if let Some(sender) = self.shells_tx.get(&input.id) {
                    sender.send(ShellData::Data(data)).await.ok();
                } else {
                    warn!(%input.id, "received data for non-existing shell");
                }
            }
            ServerMessage::CreateShell(new_shell) => {
                let id = new_shell.id;
                let center = (new_shell.x, new_shell.y);
                if !self.shells_tx.contains_key(&id) {
                    self.spawn_shell_task(id, center);
                } else {
                    warn!(%id, "server asked to create duplicate shell");
                }
            }
            ServerMessage::CloseShell { id } => {
                self.shells_tx.remove(&id);
            }
            ServerMessage::Sync(seqnums) => {
                for (id, seq) in seqnums.map {
                    if let Some(sender) = self.shells_tx.get(&id) {
                        sender.send(ShellData::Sync(seq)).await.ok();
                    } else {
                        warn!(%id, "received sequence number for non-existing shell");
                    }
                }
            }
            ServerMessage::Resize(msg) => {
                if let Some(sender) = self.shells_tx.get(&msg.id) {
                    sender.send(ShellData::Size(msg.rows, msg.cols)).await.ok();
                } else {
                    warn!(%msg.id, "received resize for non-existing shell");
                }
            }
            ServerMessage::Ping { timestamp } => {
                let pong = ClientMessage::Pong { timestamp };
                self.output_tx.send(pong).await.ok();
            }
            ServerMessage::Error { message } => {
                error!(?message, "error received from peer");
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
                id,
                x: center.0,
                y: center.1,
            };
            if let Err(err) = output_tx.send(ClientMessage::CreatedShell(new_shell)).await {
                error!(%id, ?err, "failed to send shell creation message");
                return;
            }
            if let Err(err) = runner.run(id, encrypt, shell_rx, output_tx.clone()).await {
                let err = ClientMessage::Error {
                    message: err.to_string(),
                };
                output_tx.send(err).await.ok();
            }
            output_tx.send(ClientMessage::ClosedShell { id }).await.ok();
        });
    }

    /// Terminate this session gracefully.
    pub async fn close(&mut self) -> Result<(), anyhow::Error> {
        debug!("closing session");
        // The P2P node will be automatically shut down when dropped
        // In a real implementation, you might want to explicitly shutdown
        Ok(())
    }
}
