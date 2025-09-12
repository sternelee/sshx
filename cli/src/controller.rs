//! Network gRPC client allowing server control of terminals.

use anyhow::Result;
use futures_lite::StreamExt;
use rand::RngCore;
use std::collections::HashMap;

use shared::{
    crypto::rand_alphanumeric,
    events::{ClientMessage, TerminalInput},
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

/// Handles a single session's P2P terminal communication.
pub struct Controller {
    runner: Runner,
    encrypt: Encrypt,
    p2p_session: P2pSession,
    ticket: String,

    /// Channels with backpressure routing messages to each shell task.
    shells_tx: HashMap<Sid, mpsc::Sender<ShellData>>,
    /// Channel shared with tasks to allow them to output client messages.
    output_tx: mpsc::Sender<ClientMessage>,
    /// Owned receiving end of the `output_tx` channel.
    output_rx: mpsc::Receiver<ClientMessage>,
}

impl Controller {
    /// Construct a new controller with P2P networking.
    pub async fn new(runner: Runner) -> Result<Self> {
        let p2p_node = P2pNode::new().await?;
        println!("> P2P node id: {}", p2p_node.node_id());

        // Generate session parameters
        let topic = {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            iroh_gossip::proto::TopicId::from_bytes(bytes)
        };
        let encryption_key = rand_alphanumeric(14);

        // Create session ticket
        let ticket = SessionTicket::new(topic, vec![], encryption_key.clone());
        let ticket_str = ticket.to_string();

        // Create P2P session
        let p2p_session = p2p_node.create_session(ticket).await?;

        let encrypt = task::spawn_blocking(move || Encrypt::new(&encryption_key)).await?;

        let (output_tx, output_rx) = mpsc::channel(64);
        Ok(Self {
            runner,
            encrypt,
            p2p_session,
            ticket: ticket_str,
            shells_tx: HashMap::new(),
            output_tx,
            output_rx,
        })
    }

    /// Returns the ticket of the session.
    pub fn url(&self) -> &str {
        &self.ticket
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
        match serde_json::from_slice::<ClientMessage>(data) {
            Ok(client_msg) => {
                self.handle_client_message_from_browser(client_msg).await;
            }
            Err(e) => {
                warn!(
                    "Failed to deserialize P2P message: {} ({} bytes)",
                    e,
                    data.len()
                );
            }
        }
    }

    /// Handle ClientMessage received from browser clients
    async fn handle_client_message_from_browser(&mut self, message: ClientMessage) {
        match message {
            ClientMessage::Hello { .. } => {
                // Create default shell when browser connects
                if self.shells_tx.is_empty() {
                    self.spawn_shell_task(Sid(1), (0, 0));
                }
            }
            ClientMessage::Data(data) => {
                // Process terminal input from browser and send to local shell
                let input_data = TerminalInput {
                    id: data.id,
                    data: data.data,
                    offset: data.seq,
                };

                let processed_data =
                    self.encrypt
                        .segment(0x200000000, input_data.offset, &input_data.data);
                if let Some(sender) = self.shells_tx.get(&input_data.id) {
                    sender.send(ShellData::Data(processed_data)).await.ok();
                }
            }
            ClientMessage::CreatedShell { id } => {
                debug!("Browser requested shell creation: {}", id);
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

    /// Entry point to start a new terminal task on the client.
    fn spawn_shell_task(&mut self, id: Sid, _center: (i32, i32)) {
        let (shell_tx, shell_rx) = mpsc::channel(16);
        let opt = self.shells_tx.insert(id, shell_tx);
        debug_assert!(opt.is_none(), "shell ID cannot be in existing tasks");

        let runner = self.runner.clone();
        let encrypt = self.encrypt.clone();
        let output_tx = self.output_tx.clone();
        tokio::spawn(async move {
            // Notify that this shell was created
            let _ = output_tx.send(ClientMessage::CreatedShell { id }).await;

            // Run the shell and handle errors
            if let Err(err) = runner.run(id, encrypt, shell_rx, output_tx.clone()).await {
                let _ = output_tx
                    .send(ClientMessage::Error {
                        message: err.to_string(),
                    })
                    .await;
            }

            // Notify that this shell was closed
            let _ = output_tx.send(ClientMessage::ClosedShell { id }).await;
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
