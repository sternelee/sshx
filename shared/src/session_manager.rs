//! Session management for sshx applications.
//!
//! This module provides centralized session management with support for
//! message handlers, session lifecycle management, and P2P communication.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use crate::events::ServerMessage;
use crate::message::Message;
use crate::p2p::{P2pNode, P2pSession};
use crate::ticket::SessionTicket;

/// Configuration for session creation.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session ticket for joining the P2P network.
    pub ticket: SessionTicket,
    /// Nickname for the session participant.
    pub nickname: String,
    /// Maximum number of concurrent sessions.
    pub max_concurrent_sessions: usize,
}

/// Message handler trait for processing incoming ServerMessages.
pub trait MessageHandler: Send + Sync {
    /// Handle an incoming ServerMessage.
    fn handle_message(&self, message: ServerMessage);
}

/// Arc-based message handler for easy sharing.
pub type ArcMessageHandler = Arc<dyn MessageHandler>;

/// A managed session with message handler support.
#[derive(Clone)]
pub struct ManagedSession {
    /// Unique session identifier.
    pub id: String,
    /// P2P session for network communication.
    p2p_session: Arc<P2pSession>,
    /// List of registered message handlers.
    message_handlers: Vec<ArcMessageHandler>,
    /// Cancellation token for cleanup.
    cancellation_token: Arc<CancellationToken>,
}

impl ManagedSession {
    /// Create a new managed session.
    pub fn new(id: String, p2p_session: P2pSession) -> Self {
        Self {
            id,
            p2p_session: Arc::new(p2p_session),
            message_handlers: Vec::new(),
            cancellation_token: Arc::new(CancellationToken::new()),
        }
    }

    /// Add a message handler to this session.
    pub fn add_message_handler(&mut self, handler: ArcMessageHandler) {
        self.message_handlers.push(handler);
    }

    /// Remove all message handlers.
    pub fn clear_message_handlers(&mut self) {
        self.message_handlers.clear();
    }

    /// Get the cancellation token for this session.
    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation_token
    }

    /// Process an incoming ServerMessage by calling all registered handlers.
    pub async fn process_server_message(&self, message: ServerMessage) {
        for handler in &self.message_handlers {
            handler.handle_message(message.clone());
        }
    }

    /// Send a message through this session.
    pub async fn send_message(&self, message: Message) -> anyhow::Result<()> {
        // Broadcast signed message through P2P session
        self.p2p_session.broadcast_signed(message).await?;
        Ok(())
    }
}

/// Centralized session manager for sshx applications.
pub struct SessionManager {
    /// Active sessions managed by this manager.
    sessions: Arc<RwLock<HashMap<String, ManagedSession>>>,
    /// P2P node for network communication.
    p2p_node: Arc<Mutex<Option<P2pNode>>>,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            p2p_node: Arc::new(Mutex::new(None)),
        }
    }

    /// Initialize the P2P node for session management.
    pub async fn initialize_p2p_node(&self) -> anyhow::Result<()> {
        let p2p_node = P2pNode::new().await?;
        *self.p2p_node.lock().await = Some(p2p_node);
        Ok(())
    }

    /// Join a session with the given configuration.
    pub async fn join_session(
        &self,
        p2p_node: &P2pNode,
        config: SessionConfig,
    ) -> anyhow::Result<String> {
        // Generate a unique session ID
        let session_id = format!("session_{}", uuid::Uuid::new_v4());

        // Join the P2P session
        let p2p_session = p2p_node.join_session(config.ticket).await?;

        // Create managed session
        let mut managed_session = ManagedSession::new(session_id.clone(), p2p_session);

        // Start message processing task
        self.start_message_processing(&session_id, managed_session.clone())
            .await?;

        // Store the session
        self.sessions
            .write()
            .await
            .insert(session_id.clone(), managed_session);

        Ok(session_id)
    }

    /// Join a session with a message handler.
    pub async fn join_session_with_handler(
        &self,
        p2p_node: &P2pNode,
        config: SessionConfig,
        message_handler: ArcMessageHandler,
    ) -> anyhow::Result<String> {
        let session_id = self.join_session(p2p_node, config).await?;

        // Add the message handler to the session
        if let Some(session) = self.sessions.write().await.get_mut(&session_id) {
            session.add_message_handler(message_handler);
        }

        Ok(session_id)
    }

    /// Send a message to a specific session.
    pub async fn send_message(&self, session_id: &str, message: Message) -> anyhow::Result<()> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        session.send_message(message).await
    }

    /// Remove a session and clean up resources.
    pub async fn remove_session(&self, session_id: &str) -> Option<ManagedSession> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.remove(session_id);

        if let Some(ref session) = session {
            session.cancellation_token.cancel();
        }

        session
    }

    /// Get a list of active session IDs.
    pub async fn get_active_sessions(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }

    /// Get a specific session by ID.
    pub async fn get_session(&self, session_id: &str) -> Option<ManagedSession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Start the message processing task for a session.
    async fn start_message_processing(
        &self,
        session_id: &str,
        mut session: ManagedSession,
    ) -> anyhow::Result<()> {
        let session_id = session_id.to_string();
        let sessions = self.sessions.clone();

        tokio::spawn(async move {
            // This is where you would listen for incoming messages from the P2P session
            // and process them through the message handlers
            // The actual implementation depends on the P2P session's event stream API

            // For now, this is a placeholder that would be replaced with actual message
            // processing
            let cancellation_token = session.cancellation_token.clone();

            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    tracing::info!("Session {} message processing cancelled", session_id);
                }
                // Add actual message processing logic here
                // This would involve listening to the P2P session's event stream
            }
        });

        Ok(())
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple message handler implementation for testing and basic use cases.
pub struct SimpleMessageHandler<F>
where
    F: Fn(ServerMessage) + Send + Sync,
{
    callback: F,
}

impl<F> SimpleMessageHandler<F>
where
    F: Fn(ServerMessage) + Send + Sync,
{
    /// Create a new simple message handler with the given callback.
    pub fn new(callback: F) -> Self {
        Self { callback }
    }
}

impl<F> MessageHandler for SimpleMessageHandler<F>
where
    F: Fn(ServerMessage) + Send + Sync,
{
    fn handle_message(&self, message: ServerMessage) {
        (self.callback)(message);
    }
}

/// Convenience function to create shell creation messages.
pub fn create_shell_message(shell_id: crate::Sid) -> Message {
    use crate::events::ClientMessage;
    Message::ClientMessage(ClientMessage::CreateShell { id: shell_id })
}

/// Convenience function to create input messages.
pub fn create_input_message(shell_id: crate::Sid, data: Vec<u8>, offset: u64) -> Message {
    use crate::events::{ClientMessage, TerminalInput};
    Message::ClientMessage(ClientMessage::Input(TerminalInput {
        id: shell_id,
        data,
        offset,
    }))
}

/// Convenience function to create shell close messages.
pub fn close_shell_message(shell_id: crate::Sid) -> Message {
    use crate::events::ClientMessage;
    Message::ClientMessage(ClientMessage::CloseShell { id: shell_id })
}

