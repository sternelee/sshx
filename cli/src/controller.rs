//! Network gRPC client allowing server control of terminals.

use std::collections::HashMap;

use anyhow::Result;
use futures_lite::StreamExt;
use rand::RngCore;
use shared::{
    crypto::rand_alphanumeric,
    events::{ClientMessage, Event, ServerMessage, TerminalInput},
    message::Message,
    p2p::{P2pNode, P2pSessionSender},
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
    p2p_sender: P2pSessionSender,
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

        // Generate session ticket following reference implementation
        let ticket = SessionTicket::new_random();
        let ticket_str = ticket.serialize();

        // Create P2P session with server nickname
        let (p2p_sender, _receiver) = p2p_node.join(&ticket, "sshx-server".to_string()).await?;

        let encrypt = task::spawn_blocking(move || Encrypt::new(&ticket.key)).await?;

        let (output_tx, output_rx) = mpsc::channel(64);
        Ok(Self {
            runner,
            encrypt,
            p2p_sender,
            ticket: ticket_str,
            shells_tx: HashMap::new(),
            output_tx,
            output_rx,
        })
    }

    /// Returns the ticket of the session.
    pub fn ticket(&self) -> &str {
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
        debug!("P2P controller started, waiting for events...");

        loop {
            tokio::select! {
                // 1. Handle outgoing messages from local shells to send to browser
                Some(msg) = self.output_rx.recv() => {
                    println!("📤 CLI sending ServerMessage to browser: {:?}", msg);
                    // Send ServerMessage as a signed message back to browser clients
                    let signed_msg = Message::ServerMessage(msg);
                    if let Err(e) = self.p2p_sender.send(signed_msg).await {
                        warn!("❌ Failed to send signed message to browser: {}", e);
                    } else {
                        println!("✅ Successfully broadcasted signed message to P2P network");
                    }
                }
                // 2. Placeholder for incoming messages (would need receiver from split)
                _ = async {
                    // TODO: Implement proper message receiving using the new architecture
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await
                } => {
                    // For now, just continue the loop
                    continue;
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
