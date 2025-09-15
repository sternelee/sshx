//! WebSocket handler for sshx-worker
//!
//! This module handles WebSocket connections for real-time terminal sharing,
//! adapted for Cloudflare Workers environment.

use anyhow::{anyhow, Result};
use serde_json;
use std::collections::HashSet;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use worker::*;

use crate::protocol::{WsClient, WsServer, WsWinsize};
use crate::session::{SessionManager, SessionState};
use crate::state::CloudflareServerState;
use sshx_core::{Sid, Uid};

/// WebSocket connection handler.
pub struct WebSocketHandler {
    state: Arc<CloudflareServerState>,
    _session_manager: SessionManager,
}

impl WebSocketHandler {
    pub fn new(state: Arc<CloudflareServerState>) -> Self {
        let _session_manager = SessionManager::new(Arc::clone(&state));
        Self {
            state,
            _session_manager,
        }
    }

    /// Handle a WebSocket upgrade request.
    pub async fn handle_websocket_upgrade(
        &self,
        _req: Request,
        session_name: &str,
    ) -> worker::Result<Response> {
        // Instead of handling WebSocket directly in the worker,
        // we'll route it to the Durable Object for better session management
        let _stub = self.state.durable_object(session_name);

        // Forward the request to the Durable Object
        // Note: ObjectId needs to be used differently in workers-rs 0.4.2
        // This would need to be implemented with proper Durable Object binding
        console_log!("Routing to Durable Object for session: {}", session_name);
        Response::ok("Durable Object routing not fully implemented")
    }

    /// Handle an active WebSocket connection.
    async fn handle_websocket_connection(
        &self,
        websocket: WebSocket,
        session_name: &str,
    ) -> Result<()> {
        console_log!(
            "WebSocket connection established for session: {}",
            session_name
        );

        // Get or create session state
        let mut session_state = match self
            ._session_manager
            .get_session_state(session_name)
            .await?
        {
            Some(state) => state,
            None => {
                // Session doesn't exist, close connection
                self.send_message(&websocket, WsServer::Error("Session not found".to_string()))
                    .await?;
                websocket.close(Some(1008), Some("Session not found"))?;
                return Ok(());
            }
        };

        // Generate a new user ID
        let user_id = session_state._counter.next_uid();

        // Send hello message
        self.send_message(
            &websocket,
            WsServer::Hello(user_id, session_state.metadata.name.clone()),
        )
        .await?;

        // Wait for authentication
        let can_write = match self.receive_message(&websocket).await? {
            Some(WsClient::Authenticate(bytes, write_password_bytes)) => {
                // Verify encryption key
                if !bool::from(bytes.ct_eq(session_state.metadata.encrypted_zeros.as_ref())) {
                    self.send_message(&websocket, WsServer::InvalidAuth())
                        .await?;
                    websocket.close(Some(1008), Some("Invalid authentication"))?;
                    return Ok(());
                }

                // Check write password
                match (
                    write_password_bytes,
                    &session_state.metadata.write_password_hash,
                ) {
                    // No password needed, so all users can write (default).
                    (_, None) => true,
                    // Password stored but not provided, user is read-only.
                    (None, Some(_)) => false,
                    // Password stored and provided, compare them.
                    (Some(provided), Some(stored)) => {
                        if !bool::from(provided.ct_eq(stored)) {
                            self.send_message(&websocket, WsServer::InvalidAuth())
                                .await?;
                            websocket.close(Some(1008), Some("Invalid password"))?;
                            return Ok(());
                        }
                        true
                    }
                }
            }
            _ => {
                self.send_message(&websocket, WsServer::InvalidAuth())
                    .await?;
                websocket.close(Some(1008), Some("Expected authentication"))?;
                return Ok(());
            }
        };

        // Add user to session
        session_state.add_user(user_id, can_write)?;

        // Send initial state
        self.send_message(&websocket, WsServer::Users(session_state.get_users()))
            .await?;
        self.send_message(&websocket, WsServer::Shells(session_state.get_shells()))
            .await?;

        // Track subscribed shells to prevent duplicates
        let mut subscribed_shells = HashSet::new();

        // Main message loop
        loop {
            match self.receive_message(&websocket).await? {
                Some(msg) => {
                    if !self
                        .handle_client_message(
                            &websocket,
                            &mut session_state,
                            user_id,
                            msg,
                            &mut subscribed_shells,
                        )
                        .await?
                    {
                        break;
                    }
                }
                None => {
                    // Connection closed
                    break;
                }
            }
        }

        // Remove user from session
        session_state.remove_user(user_id);

        // Save session state
        self._session_manager
            .save_session_state(session_name, &session_state)
            .await?;

        console_log!("WebSocket connection closed for session: {}", session_name);
        Ok(())
    }

    /// Handle a client message. Returns false if the connection should be closed.
    async fn handle_client_message(
        &self,
        websocket: &WebSocket,
        session_state: &mut SessionState,
        user_id: Uid,
        msg: WsClient,
        subscribed_shells: &mut HashSet<Sid>,
    ) -> Result<bool> {
        match msg {
            WsClient::Authenticate(_, _) => {
                // Already authenticated, ignore
            }
            WsClient::SetName(name) => {
                if !name.is_empty() {
                    let updated_user = session_state.update_user(user_id, |user| {
                        user.name = name;
                    })?;
                    self.broadcast_user_diff(websocket, user_id, Some(updated_user))
                        .await?;
                }
            }
            WsClient::SetCursor(cursor) => {
                let updated_user = session_state.update_user(user_id, |user| {
                    user.cursor = cursor;
                })?;
                self.broadcast_user_diff(websocket, user_id, Some(updated_user))
                    .await?;
            }
            WsClient::SetFocus(focus) => {
                let updated_user = session_state.update_user(user_id, |user| {
                    user.focus = focus;
                })?;
                self.broadcast_user_diff(websocket, user_id, Some(updated_user))
                    .await?;
            }
            WsClient::Create(x, y) => {
                if let Err(e) = session_state.check_write_permission(user_id) {
                    self.send_message(websocket, WsServer::Error(e.to_string()))
                        .await?;
                    return Ok(true);
                }
                let shell_id = session_state._counter.next_sid();
                session_state.add_shell(shell_id, (x, y))?;
                self.broadcast_shells_update(websocket, session_state.get_shells())
                    .await?;
            }
            WsClient::Close(shell_id) => {
                if let Err(e) = session_state.check_write_permission(user_id) {
                    self.send_message(websocket, WsServer::Error(e.to_string()))
                        .await?;
                    return Ok(true);
                }
                session_state.close_shell(shell_id)?;
                self.broadcast_shells_update(websocket, session_state.get_shells())
                    .await?;
            }
            WsClient::Move(shell_id, winsize) => {
                if let Err(e) = session_state.check_write_permission(user_id) {
                    self.send_message(websocket, WsServer::Error(e.to_string()))
                        .await?;
                    return Ok(true);
                }
                session_state.move_shell(shell_id, winsize)?;
                self.broadcast_shells_update(websocket, session_state.get_shells())
                    .await?;
            }
            WsClient::Data(shell_id, data, offset) => {
                if let Err(e) = session_state.check_write_permission(user_id) {
                    self.send_message(websocket, WsServer::Error(e.to_string()))
                        .await?;
                    return Ok(true);
                }
                session_state.add_data(shell_id, data, offset)?;
                // In a real implementation, this would be forwarded to the backend terminal
                console_log!(
                    "Received terminal data for shell {}: {} bytes",
                    shell_id,
                    offset
                );
            }
            WsClient::Subscribe(shell_id, chunknum) => {
                if subscribed_shells.contains(&shell_id) {
                    return Ok(true); // Skip if already subscribed
                }
                subscribed_shells.insert(shell_id);

                if let Some((seqnum, chunks)) = session_state.get_chunks(shell_id, chunknum) {
                    self.send_message(websocket, WsServer::Chunks(shell_id, seqnum, chunks))
                        .await?;
                }

                // In a real implementation, you would start a stream to monitor for new chunks
                // For now, we'll just send the initial chunks
                console_log!(
                    "Client subscribed to shell {} at chunk {}",
                    shell_id,
                    chunknum
                );
            }
            WsClient::Chat(message) => {
                let user_name = session_state
                    .users
                    .get(&user_id)
                    .map(|u| u.name.clone())
                    .unwrap_or_else(|| format!("User {}", user_id));
                self.broadcast_chat(websocket, user_id, user_name, message)
                    .await?;
            }
            WsClient::Ping(timestamp) => {
                self.send_message(websocket, WsServer::Pong(timestamp))
                    .await?;
            }
        }

        Ok(true)
    }

    /// Send a message to the WebSocket.
    async fn send_message(&self, websocket: &WebSocket, msg: WsServer) -> Result<()> {
        let serialized =
            serde_json::to_vec(&msg).map_err(|e| anyhow!("Failed to serialize message: {}", e))?;

        websocket
            .send_with_bytes(&serialized)
            .map_err(|e| anyhow!("Failed to send WebSocket message: {:?}", e))?;

        Ok(())
    }

    /// Receive a message from the WebSocket.
    async fn receive_message(&self, _websocket: &WebSocket) -> Result<Option<WsClient>> {
        // In Cloudflare Workers, we need to use event listeners for WebSocket messages
        // This is a simplified implementation - in production you'd use proper
        // WebSocket message streaming

        // For now, we'll return None to indicate no message received
        // In a real implementation, you'd set up event listeners for:
        // - 'message' events for incoming messages
        // - 'close' events for connection termination
        // - 'error' events for connection errors

        // This is a placeholder that would be replaced with actual WebSocket message handling
        // For the current implementation, we'll simulate message reception through other means
        Ok(None)
    }

    /// Broadcast user diff to all connected clients.
    async fn broadcast_user_diff(
        &self,
        _websocket: &WebSocket,
        user_id: Uid,
        user: Option<crate::protocol::WsUser>,
    ) -> Result<()> {
        // In a real implementation, this would broadcast to all connected clients
        // For now, we'll just log it
        console_log!("Broadcasting user diff for user {}: {:?}", user_id, user);
        Ok(())
    }

    /// Broadcast shells update to all connected clients.
    async fn broadcast_shells_update(
        &self,
        _websocket: &WebSocket,
        _shells: Vec<(Sid, WsWinsize)>,
    ) -> Result<()> {
        // In a real implementation, this would broadcast to all connected clients
        console_log!("Broadcasting shells update: {} shells", _shells.len());
        Ok(())
    }

    /// Broadcast chat message to all connected clients.
    async fn broadcast_chat(
        &self,
        _websocket: &WebSocket,
        _user_id: Uid,
        user_name: String,
        message: String,
    ) -> Result<()> {
        // In a real implementation, this would broadcast to all connected clients
        console_log!("Broadcasting chat from {}: {}", user_name, message);
        Ok(())
    }
}
