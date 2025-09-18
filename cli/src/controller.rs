//! Network gRPC client allowing server control of terminals.

use anyhow::Result;
use futures_lite::StreamExt;
use rand::RngCore;
use std::collections::HashMap;

use shared::{
    crypto::rand_alphanumeric,
    events::{ClientMessage, ServerMessage, TerminalInput},
    message::Message,
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
    output_tx: mpsc::Sender<ServerMessage>,
    /// Owned receiving end of the `output_tx` channel.
    output_rx: mpsc::Receiver<ServerMessage>,
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

        // Create session ticket with CLI node as bootstrap
        let cli_node_addr = p2p_node.node_addr().await?;
        let ticket = SessionTicket::new(topic, vec![cli_node_addr], encryption_key.clone());
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
        let mut event_stream = self.p2p_session.signed_message_stream();

        debug!("P2P controller started, waiting for events...");
        println!("🎯 P2P Controller initialized and listening for browser connections");
        println!("📋 Session ticket: {}", self.ticket);

        loop {
            tokio::select! {
                // 1. Handle outgoing messages from local shells to send to browser
                Some(msg) = self.output_rx.recv() => {
                    println!("📤 CLI sending ServerMessage to browser: {:?}", msg);
                    // Send ServerMessage as a signed message back to browser clients
                    let signed_msg = Message::ServerMessage(msg);
                    if let Err(e) = self.p2p_session.broadcast_signed(signed_msg).await {
                        warn!("❌ Failed to send signed message to browser: {}", e);
                    } else {
                        println!("✅ Successfully broadcasted signed message to P2P network");
                    }
                }
                // 2. Handle incoming signed messages from browser clients
                Some(Ok(received_msg)) = async {
                    debug!("Waiting for P2P signed message...");
                    if let Some(ref mut stream) = event_stream {
                        stream.next().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    println!("📨 CLI received signed P2P message: {:?}", received_msg);
                    match received_msg.message {
                        Message::ClientMessage(client_msg) => {
                            self.handle_client_message_from_browser(client_msg).await;
                        }
                        Message::SessionEvent(session_event) => {
                            println!("🔔 Received session event: {:?}", session_event);
                            // Handle session events
                        }
                        Message::Presence { user_id, name } => {
                            println!("👤 User presence: {} {:?}", user_id, name);
                            // Handle user presence updates
                        }
                        _ => {
                            println!("🟡 Received other message type: {:?}", received_msg.message);
                        }
                    }
                }
            }
        }
    }

    /// Handle ClientMessage received from browser clients
    async fn handle_client_message_from_browser(&mut self, message: ClientMessage) {
        println!("🎯 Processing ClientMessage: {:?}", message);
        match message {
            ClientMessage::CreateShell { id } => {
                println!("🐚 Browser requested shell creation: {}", id);
                // Create a new shell task as requested by browser
                self.spawn_shell_task(id, (0, 0));
            }
            ClientMessage::Input(data) => {
                println!(
                    "⌨️ Browser sent input for shell {}: {} bytes",
                    data.id,
                    data.data.len()
                );
                // Process terminal input from browser and send to local shell
                let input_data = TerminalInput {
                    id: data.id,
                    data: data.data,
                    offset: data.offset,
                };

                let processed_data =
                    self.encrypt
                        .segment(0x200000000, input_data.offset, &input_data.data);
                if let Some(sender) = self.shells_tx.get(&input_data.id) {
                    if sender.send(ShellData::Data(processed_data)).await.is_ok() {
                        println!("✅ Input forwarded to shell {}", input_data.id);
                    } else {
                        println!("❌ Failed to forward input to shell {}", input_data.id);
                    }
                } else {
                    println!("⚠️ Shell {} not found for input", input_data.id);
                }
            }
            ClientMessage::CloseShell { id } => {
                println!("❌ Browser requested shell closure: {}", id);
                // Remove the shell as requested by browser
                self.shells_tx.remove(&id);
            }
        }
    }

    /// Entry point to start a new terminal task on the client.
    fn spawn_shell_task(&mut self, id: Sid, _center: (i32, i32)) {
        println!("🚀 Spawning shell task for ID: {}", id);
        let (shell_tx, shell_rx) = mpsc::channel(16);
        let opt = self.shells_tx.insert(id, shell_tx);
        debug_assert!(opt.is_none(), "shell ID cannot be in existing tasks");

        let runner = self.runner.clone();
        let encrypt = self.encrypt.clone();
        let output_tx = self.output_tx.clone();
        tokio::spawn(async move {
            println!("🎭 Shell task {} starting...", id);

            // Notify that this shell was created
            let created_msg = ServerMessage::CreatedShell { id };
            println!("📢 Sending CreatedShell message: {:?}", created_msg);
            let _ = output_tx.send(created_msg).await;

            // Run the shell and handle errors
            if let Err(err) = runner.run(id, encrypt, shell_rx, output_tx.clone()).await {
                let error_msg = ServerMessage::Error {
                    message: err.to_string(),
                };
                println!("🔥 Shell error, sending: {:?}", error_msg);
                let _ = output_tx.send(error_msg).await;
            }

            // Notify that this shell was closed
            let closed_msg = ServerMessage::ClosedShell { id };
            println!("🏁 Shell {} finished, sending: {:?}", id, closed_msg);
            let _ = output_tx.send(closed_msg).await;
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
