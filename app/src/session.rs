use anyhow::Result;
use shared::events::{ClientMessage, NewShell, ServerMessage, SessionEvent, TerminalData};
use shared::Sid;
use shared::p2p::{P2pConfig, P2pMessage, P2pNode, P2pSessionManager};
use shared::ticket::SessionTicket;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::StreamExt;

#[derive(Clone)]
pub struct AppState {
    pub p2p_node: Arc<P2pNode>,
    pub session_manager: Arc<Mutex<P2pSessionManager>>,
}

impl AppState {
    pub async fn new() -> Result<Self> {
        let config = P2pConfig::default();
        let p2p_node = P2pNode::new(config).await?;

        Ok(Self {
            p2p_node: Arc::new(p2p_node),
            session_manager: Arc::new(Mutex::new(P2pSessionManager::new())),
        })
    }

    pub async fn create_session(&self) -> Result<String> {
        let session = self.p2p_node.create_session().await?;
        let session_id = session.topic().to_string();

        let mut manager = self.session_manager.lock().await;
        manager.add_session(session);

        Ok(session_id)
    }

    pub async fn join_session(&self, ticket: SessionTicket) -> Result<String> {
        let session = self.p2p_node.join_session(ticket).await?;
        let session_id = session.topic().to_string();

        let mut manager = self.session_manager.lock().await;
        manager.add_session(session);

        Ok(session_id)
    }

    pub async fn get_session(&self, session_id: &str) -> bool {
        let manager = self.session_manager.lock().await;
        manager.get_session(session_id).is_some()
    }

    pub async fn send_data_to_session(&self, session_id: &str, data: Vec<u8>) -> Result<()> {
        let manager = self.session_manager.lock().await;
        if let Some(session) = manager.get_session(session_id) {
            session.broadcast(data).await?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Session not found"))
        }
    }

    pub async fn handle_session_events(&self, session_id: &str) -> Result<()> {
        let mut manager = self.session_manager.lock().await;
        if let Some(session) = manager.get_session_mut(session_id) {
            if let Some(mut event_stream) = session.event_stream() {
                drop(manager); // Release the lock

                while let Some(event) = event_stream.next().await {
                    match event {
                        Ok(gossip_event) => {
                            // Handle gossip events and convert them to session events
                            match gossip_event {
                                iroh_gossip::api::Event::Received(msg) => {
                                    // Try to deserialize the content as a P2pMessage
                                    if let Ok(p2p_message) = P2pMessage::from_bytes(&msg.content) {
                                        match p2p_message {
                                            P2pMessage::Binary(data) => {
                                                // Handle binary data as terminal data
                                                self.handle_binary_data(session_id, data).await?;
                                            }
                                            P2pMessage::Text(text) => {
                                                // Handle text messages
                                                self.handle_text_message(session_id, text).await?;
                                            }
                                            P2pMessage::Structured { msg_type, payload } => {
                                                // Handle structured messages
                                                self.handle_structured_message(
                                                    session_id, msg_type, payload,
                                                )
                                                .await?;
                                            }
                                        }
                                    }
                                }
                                iroh_gossip::api::Event::NeighborUp(node_id) => {
                                    println!("New neighbor connected: {}", node_id);
                                }
                                iroh_gossip::api::Event::NeighborDown(node_id) => {
                                    println!("Neighbor disconnected: {}", node_id);
                                }
                                _ => {
                                    // Handle other gossip events
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Error receiving gossip event: {}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_binary_data(&self, session_id: &str, data: Vec<u8>) -> Result<()> {
        // Convert binary data to terminal data event
        let session_event = SessionEvent::TerminalData(TerminalData {
            id: Sid(1), // Default shell ID for now
            data,
            seq: 0, // Sequence number would need to be tracked
        });

        // Broadcast the event to other components
        self.broadcast_session_event(session_id, session_event)
            .await
    }

    async fn handle_text_message(&self, session_id: &str, text: String) -> Result<()> {
        // Handle text messages (e.g., chat messages)
        println!("Received text message in session {}: {}", session_id, text);
        Ok(())
    }

    async fn handle_structured_message(
        &self,
        session_id: &str,
        msg_type: String,
        payload: Vec<u8>,
    ) -> Result<()> {
        // Handle structured messages based on type
        match msg_type.as_str() {
            "client_message" => {
                if let Ok(client_message) = serde_json::from_slice::<ClientMessage>(&payload) {
                    self.handle_client_message(session_id, client_message)
                        .await?;
                }
            }
            "server_message" => {
                if let Ok(server_message) = serde_json::from_slice::<ServerMessage>(&payload) {
                    self.handle_server_message(session_id, server_message)
                        .await?;
                }
            }
            _ => {
                println!("Unknown structured message type: {}", msg_type);
            }
        }
        Ok(())
    }

    async fn handle_client_message(&self, session_id: &str, message: ClientMessage) -> Result<()> {
        match message {
            ClientMessage::Hello { content } => {
                println!("Client hello in session {}: {}", session_id, content);
            }
            ClientMessage::Input(data) => {
                // Handle terminal data from client
                // Convert TerminalInput to TerminalData for SessionEvent
                let terminal_data = TerminalData {
                    id: data.id,
                    data: data.data.to_vec(),
                    seq: data.offset,
                };
                let session_event = SessionEvent::TerminalData(terminal_data);
                self.broadcast_session_event(session_id, session_event)
                    .await?;
            }
            ClientMessage::CreateShellRequest { x, y } => {
                let new_shell = NewShell { id: Sid(0), x, y };
                let session_event = SessionEvent::ShellCreated(new_shell);
                self.broadcast_session_event(session_id, session_event)
                    .await?;
            }
            ClientMessage::CloseShellRequest { id } => {
                let session_event = SessionEvent::ShellClosed { id };
                self.broadcast_session_event(session_id, session_event)
                    .await?;
            }
            ClientMessage::ListShellRequest => {
                // Handle shell list request
                println!("Shell list request received in session {}", session_id);
            }
            ClientMessage::ResizeRequest(size) => {
                // Handle terminal resize request
                let session_event = SessionEvent::TerminalResize(size);
                self.broadcast_session_event(session_id, session_event)
                    .await?;
            }
            ClientMessage::Pong { timestamp } => {
                println!("Pong received in session {}: {}", session_id, timestamp);
            }
            ClientMessage::Error { message } => {
                let session_event = SessionEvent::Error { message };
                self.broadcast_session_event(session_id, session_event)
                    .await?;
            }
        }
        Ok(())
    }

    async fn handle_server_message(&self, session_id: &str, message: ServerMessage) -> Result<()> {
        match message {
            ServerMessage::Hello { user_id, token } => {
                println!("Hello received in session {}: user_id={}, token={}", session_id, user_id, token);
            }
            ServerMessage::Data(data) => {
                // Handle terminal data from server
                println!(
                    "Server data received in session {}: {} bytes",
                    session_id,
                    data.data.len()
                );
            }
            ServerMessage::ShellCreated(shell) => {
                println!(
                    "Shell created in session {}: {:?}",
                    session_id, shell
                );
            }
            ServerMessage::ShellClosed { id } => {
                println!("Shell closed in session {}: {}", session_id, id);
            }
            ServerMessage::ShellList(shell_list) => {
                println!(
                    "Shell list received in session {}: {} shells",
                    session_id, shell_list.count
                );
            }
            ServerMessage::Sync(seq_nums) => {
                println!("Sync request in session {}: {:?}", session_id, seq_nums);
            }
            ServerMessage::ShellResized(size) => {
                let session_event = SessionEvent::TerminalResize(size);
                self.broadcast_session_event(session_id, session_event)
                    .await?;
            }
            ServerMessage::Ping { timestamp } => {
                println!("Ping received in session {}: {}", session_id, timestamp);
            }
            ServerMessage::Error { message } => {
                let session_event = SessionEvent::Error { message };
                self.broadcast_session_event(session_id, session_event)
                    .await?;
            }
        }
        Ok(())
    }

    async fn broadcast_session_event(&self, session_id: &str, event: SessionEvent) -> Result<()> {
        // Convert session event to P2pMessage and broadcast
        let payload = serde_json::to_vec(&event)?;
        let p2p_message = P2pMessage::Structured {
            msg_type: "session_event".to_string(),
            payload,
        };
        let bytes = p2p_message.to_bytes()?;

        let manager = self.session_manager.lock().await;
        if let Some(session) = manager.get_session(session_id) {
            session.broadcast(bytes).await?;
        }
        Ok(())
    }
}
