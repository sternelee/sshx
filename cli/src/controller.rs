//! Network gRPC client allowing server control of terminals.

use anyhow::Result;
use futures_lite::StreamExt;
use rand::RngCore;
use std::collections::HashMap;

use shared::{
    crypto::rand_alphanumeric,
    events::{ClientMessage, ServerMessage, TerminalInput},
    p2p::{P2pNode, P2pSession},
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
        _relay_url: Option<String>,
        runner: Runner,
        enable_readers: bool,
    ) -> Result<Self, anyhow::Error> {
        let p2p_node = P2pNode::new().await?;
        println!("> our node id: {}", p2p_node.node_id());

        // Generate session parameters
        let topic = {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            iroh_gossip::proto::TopicId::from_bytes(bytes)
        };
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

        // Create a simple ticket with minimal configuration
        let ticket = SessionTicket::new(topic, vec![], encryption_key.clone());
        let ticket_str = ticket.to_string();

        let write_ticket = if let Some(write_password) = write_password {
            let mut write_ticket = ticket.clone();
            write_ticket.write_password = Some(write_password);
            Some(write_ticket.to_shareable_string(true))
        } else {
            None
        };

        let encrypt = kdf_task.await?;

        // Create P2P session after ticket is created
        let p2p_session = p2p_node.create_session(ticket.clone()).await?;

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

        debug!("P2P controller started, waiting for events...");

        loop {
            tokio::select! {
                // 1. Handle outgoing messages from local shells to send to browser
                Some(msg) = self.output_rx.recv() => {
                    // Send ServerMessage back to browser clients
                    match serde_json::to_vec(&msg) {
                        Ok(msg_bytes) => {
                            if let Err(e) = self.p2p_session.broadcast(msg_bytes).await {
                                warn!("Failed to send message to browser: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to serialize ServerMessage: {}", e);
                        }
                    }
                }
                // 2. Handle incoming messages from browser clients
                Some(Ok(event)) = async {
                    debug!("Waiting for P2P event...");
                    if let Some(ref mut stream) = event_stream {
                        stream.next().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    debug!("Received P2P event: {:?}", event);
                    match event {
                        iroh_gossip::api::Event::Received(msg) => {
                            debug!("Received message from peer: {} bytes", msg.content.len());
                            debug!("Message content preview: {:?}", &msg.content[..msg.content.len().min(100)]);
                            // Handle ClientMessage from browser clients
                            self.handle_p2p_message(&msg.content).await;
                        }
                        iroh_gossip::api::Event::NeighborUp(node_id) => {
                            debug!("Browser client connected: {}", node_id);
                        }
                        iroh_gossip::api::Event::NeighborDown(node_id) => {
                            debug!("Browser client disconnected: {}", node_id);
                        }
                        _ => {
                            debug!("Received other P2P event: {:?}", event);
                        }
                    }
                }
            }
        }
    }

    /// Handle incoming P2P messages from browser clients
    async fn handle_p2p_message(&mut self, data: &[u8]) {
        debug!("handle_p2p_message called with {} bytes", data.len());

        // CLI is the server, it should receive ClientMessage from browser clients
        match serde_json::from_slice::<ClientMessage>(data) {
            Ok(client_msg) => {
                debug!(
                    "Successfully deserialized ClientMessage from browser: {:?}",
                    client_msg
                );
                self.handle_client_message_from_browser(client_msg).await;
            }
            Err(e) => {
                warn!(
                    "Failed to deserialize P2P message as ClientMessage: {} ({} bytes)",
                    e,
                    data.len()
                );

                // Try to print the raw data as string to see what we're receiving
                if let Ok(text) = std::str::from_utf8(data) {
                    debug!("Raw message as text: {}", text);
                } else {
                    debug!(
                        "Raw message data (hex): {:02x?}",
                        &data[..data.len().min(50)]
                    );
                }
            }
        }
    }

    /// Handle ClientMessage received from browser clients
    async fn handle_client_message_from_browser(&mut self, message: ClientMessage) {
        match message {
            ClientMessage::Hello { content } => {
                debug!("Browser client connected with hello: {}", content);
                // Send initial state to the browser client
                self.send_initial_state_to_browser().await;
            }
            ClientMessage::Data(data) => {
                debug!(
                    "Received terminal data from browser: {} bytes for shell {}",
                    data.data.len(),
                    data.id
                );
                // Process terminal data from browser and send to local shell
                let input_data = TerminalInput {
                    id: data.id,
                    data: data.data,
                    offset: data.seq,
                };

                // Send to local shell for processing
                let processed_data =
                    self.encrypt
                        .segment(0x200000000, input_data.offset, &input_data.data);
                if let Some(sender) = self.shells_tx.get(&input_data.id) {
                    sender.send(ShellData::Data(processed_data)).await.ok();
                } else {
                    warn!(%input_data.id, "received data for non-existing shell");
                }
            }
            ClientMessage::CreatedShell { id } => {
                debug!(
                    "Browser requested shell creation: {}",
                    id
                );
                // Create a new shell task as requested by browser
                self.spawn_shell_task(id, (0, 0));
            }
            ClientMessage::ClosedShell { id } => {
                debug!("Browser requested shell closure: {}", id);
                // Remove the shell as requested by browser
                self.shells_tx.remove(&id);
            }
                ClientMessage::Error { message } => {
                warn!("Received error from browser: {}", message);
                // Handle browser-reported errors
            }
        }
    }

    /// Send initial state to newly connected browser client
    async fn send_initial_state_to_browser(&mut self) {
        // Send existing shells information to the browser
        for (&id, _) in &self.shells_tx {
            // This would typically send information about existing shells
            // For now, we'll just create a default shell if none exist
            if self.shells_tx.is_empty() {
                self.spawn_shell_task(id, (0, 0));
                break;
            }
        }
    }

  
    /// Entry point to start a new terminal task on the client.
    fn spawn_shell_task(&mut self, id: Sid, _center: (i32, i32)) {
        let (shell_tx, shell_rx) = mpsc::channel(16);
        let opt = self.shells_tx.insert(id, shell_tx);
        debug_assert!(opt.is_none(), "shell ID cannot be in existing tasks");

        let runner = self.runner.clone();
        let encrypt = self.encrypt.clone();
        let output_tx = self.output_tx.clone();
        tokio::spawn(async move {
            debug!(%id, "spawning new shell");

            // Notify other clients that this shell was created
            if let Err(err) = output_tx.send(ClientMessage::CreatedShell { id }).await {
                error!(%id, ?err, "failed to send shell creation message");
                return;
            }

            // Run the shell and handle any errors
            if let Err(err) = runner.run(id, encrypt, shell_rx, output_tx.clone()).await {
                let err_msg = ClientMessage::Error {
                    message: err.to_string(),
                };
                if let Err(send_err) = output_tx.send(err_msg).await {
                    error!(%id, ?send_err, "failed to send error message");
                }
            }

            // Notify other clients that this shell was closed
            if let Err(err) = output_tx.send(ClientMessage::ClosedShell { id }).await {
                error!(%id, ?err, "failed to send shell closure message");
            }
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
