//! Network gRPC client allowing server control of terminals.

use anyhow::Result;
use futures_lite::StreamExt;
use std::collections::HashMap;

use shared::{
    events::{ClientMessage, NewShell, ServerMessage, TerminalInput},
    p2p::{P2pNode, P2pSession},
    Sid,
};
use tokio::sync::mpsc;
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
        relay_url: Option<String>,
        _name: &str,
        runner: Runner,
        enable_readers: bool,
    ) -> Result<Self, anyhow::Error> {
        Self::with_relay(relay_url, runner, enable_readers).await
    }

    /// Construct a new controller with custom relay server configuration.
    pub async fn with_relay(
        relay_url: Option<String>,
        runner: Runner,
        enable_readers: bool,
    ) -> Result<Self, anyhow::Error> {
        // Configure optimized P2P settings
        let connection_strategy = shared::p2p::ConnectionStrategy {
            direct_timeout: std::time::Duration::from_secs(15),
            relay_fallback: true,
            max_attempts: 5,
            attempt_delay: std::time::Duration::from_millis(300),
        };

        let p2p_config = shared::p2p::P2pConfig {
            relay_url,
            prefer_ipv4: true,
            debug: true,
            connection_strategy,
        };

        let p2p_node = shared::p2p::P2pNode::new(p2p_config).await?;
        println!("> our node id: {}", p2p_node.node_id());

        let p2p_session = p2p_node.create_session().await?;
        let topic = *p2p_session.topic();
        let encryption_key = p2p_session.encryption_key().to_string();

        let kdf_task = {
            let encryption_key = encryption_key.clone();
            tokio::task::spawn_blocking(move || crate::encrypt::Encrypt::new(&encryption_key))
        };

        let (write_password, _kdf_write_password_task) = if enable_readers {
            let write_password = shared::crypto::rand_alphanumeric(14); // 83.3 bits of entropy
            let task = {
                let write_password = write_password.clone();
                tokio::task::spawn_blocking(move || crate::encrypt::Encrypt::new(&write_password))
            };
            (Some(write_password), Some(task))
        } else {
            (None, None)
        };

        let me = p2p_node.node_addr().await;
        let ticket = shared::ticket::SessionTicket::new(topic, vec![me], encryption_key.clone());
        let ticket_str = ticket.to_string();

        let write_ticket = if let Some(write_password) = write_password {
            let mut write_ticket = ticket.clone();
            write_ticket.write_password = Some(write_password);
            Some(write_ticket.to_shareable_string(true))
        } else {
            None
        };

        let encrypt = kdf_task
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create encryptor: {:?}", e))
            .unwrap();

        let (output_tx, output_rx) = tokio::sync::mpsc::channel(64);
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
        let sender = self.p2p_session.sender().clone();

        // Timer for periodic connection optimization
        let mut optimization_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        optimization_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        debug!("P2P controller started, waiting for events...");

        loop {
            tokio::select! {
                // 1. Handle outgoing messages from local shells to send to browser
                Some(msg) = self.output_rx.recv() => {
                    // Convert ClientMessage from local shells to ServerMessage for browser clients
                    let server_msg = self.convert_client_to_server_message(msg);
                    match serde_json::to_vec(&server_msg) {
                        Ok(msg_bytes) => {
                            if let Err(e) = sender.broadcast(msg_bytes.into()).await {
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

                            // Optimize connection when a new peer connects
                            if let Err(e) = self.p2p_session.optimize_connection().await {
                                warn!("Failed to optimize connection: {}", e);
                            }
                        }
                        iroh_gossip::api::Event::NeighborDown(node_id) => {
                            debug!("Browser client disconnected: {}", node_id);
                        }
                        _ => {
                            debug!("Received other P2P event: {:?}", event);
                        }
                    }
                }
                // 3. Periodic connection optimization
                _ = optimization_interval.tick() => {
                    debug!("Performing periodic connection optimization");
                    // Optimize connection for the current session
                    if let Err(e) = self.p2p_session.optimize_connection().await {
                        warn!("Failed to perform periodic connection optimization: {}", e);
                    }
                }
            }
        }
    }

    /// Convert ClientMessage from local shells to ServerMessage for browser clients
    fn convert_client_to_server_message(&self, client_msg: ClientMessage) -> ServerMessage {
        match client_msg {
            ClientMessage::Data(terminal_data) => {
                // Convert TerminalData to TerminalInput for browser
                let terminal_input = TerminalInput {
                    id: terminal_data.id,
                    data: terminal_data.data,
                    offset: terminal_data.seq,
                };
                ServerMessage::Input(terminal_input)
            }
            ClientMessage::CreatedShell(new_shell) => ServerMessage::CreateShell(new_shell),
            ClientMessage::ClosedShell { id } => ServerMessage::CloseShell { id },
            ClientMessage::Error { message } => ServerMessage::Error { message },
            ClientMessage::Hello { content: _ } => {
                // Hello messages from local shells are not sent to browser
                // Send a ping instead to maintain connection
                ServerMessage::Ping {
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                }
            }
            ClientMessage::Pong { timestamp } => {
                // Convert pong to ping (though this shouldn't normally happen)
                ServerMessage::Ping { timestamp }
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
                    if let Err(e) = sender.send(ShellData::Data(processed_data)).await {
                        warn!("Failed to send data to shell {}: {}", input_data.id, e);
                    }
                } else {
                    warn!(%input_data.id, "received data for non-existing shell");
                }
            }
            ClientMessage::CreatedShell(new_shell) => {
                debug!(
                    "Browser requested shell creation: {} at ({}, {})",
                    new_shell.id, new_shell.x, new_shell.y
                );
                // Create a new shell task as requested by browser
                self.spawn_shell_task(new_shell.id, (new_shell.x, new_shell.y));
            }
            ClientMessage::ClosedShell { id } => {
                debug!("Browser requested shell closure: {}", id);
                // Remove the shell as requested by browser
                self.shells_tx.remove(&id);
            }
            ClientMessage::Pong { timestamp } => {
                debug!("Received pong from browser: {}", timestamp);
                // Calculate and log latency if needed
            }
            ClientMessage::Error { message } => {
                warn!("Received error from browser: {}", message);
                // Handle browser-reported errors
            }
        }
    }

    /// Send initial state to newly connected browser client
    async fn send_initial_state_to_browser(&mut self) {
        // If no shells exist, create a default shell
        if self.shells_tx.is_empty() {
            let default_id = Sid(1);
            debug!(
                "Creating default shell {} for new browser client",
                default_id
            );
            self.spawn_shell_task(default_id, (0, 0));
        } else {
            // Send information about existing shells to the browser
            for (&shell_id, _) in &self.shells_tx {
                debug!("Notifying browser about existing shell: {}", shell_id);
                // Note: In a real implementation, you might want to send shell state
                // For now, we just let the browser discover shells through normal operation
            }
        }
    }

    /// This method is kept for compatibility but should not be used in P2P server mode
    /// CLI is the server and should only receive ClientMessage from browser clients
    async fn handle_server_message(&mut self, message: ServerMessage) {
        warn!(
            "Received unexpected ServerMessage in P2P server mode: {:?}",
            message
        );
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

            // Notify other clients that this shell was created
            if let Err(err) = output_tx.send(ClientMessage::CreatedShell(new_shell)).await {
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
