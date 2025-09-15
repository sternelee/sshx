//! Durable Object implementation for sshx session coordination
//!
//! This module provides a Durable Object that handles real-time coordination
//! for sshx sessions, including WebSocket connections, state synchronization,
//! and message broadcasting.

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use worker::*;

use crate::protocol::{WsClient, WsServer, WsWinsize};
use crate::session::SessionState;
use sshx_core::{Sid, Uid};

// Simplified message types for Durable Object communication
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionMessage {
    pub session_name: String,
    pub message: String,
}

/// Messages sent between the Worker and Durable Object
#[derive(Serialize, Deserialize, Debug)]
pub enum DurableObjectMessage {
    /// Join a session with WebSocket
    JoinSession {
        session_name: String,
        user_id: Uid,
        can_write: bool,
    },
    /// Leave a session
    LeaveSession { user_id: Uid },
    /// Broadcast a message to all connected clients
    Broadcast {
        message: WsServer,
        exclude_user: Option<Uid>,
    },
    /// Handle a client message
    ClientMessage { user_id: Uid, message: WsClient },
    /// Get current session state
    GetSessionState,
    /// Update session state
    UpdateSessionState { state: SessionState },
}

/// Response from Durable Object operations
#[derive(Serialize, Deserialize, Debug)]
pub enum DurableObjectResponse {
    Success,
    Error(String),
    SessionState(Option<SessionState>),
}

/// Durable Object for managing sshx sessions
#[durable_object]
pub struct SshxSession {
    _state: State,
    _env: Env,
    _session_state: RefCell<Option<SessionState>>,
}

impl DurableObject for SshxSession {
    fn new(state: State, env: Env) -> Self {
        Self {
            _state: state,
            _env: env,
            _session_state: RefCell::new(None),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        // Handle WebSocket upgrade requests
        if req.headers().get("upgrade")?.as_deref() == Some("websocket") {
            return self.handle_websocket_upgrade(req).await;
        }

        // Handle HTTP requests for session management
        match req.method() {
            Method::Post => self.handle_post_request(req).await,
            Method::Get => self.handle_get_request(req).await,
            _ => Response::error("Method not allowed", 405),
        }
    }
}

impl SshxSession {
    /// Handle WebSocket upgrade requests
    async fn handle_websocket_upgrade(&self, req: Request) -> Result<Response> {
        let WebSocketPair { client, server } = WebSocketPair::new()?;

        // Accept the WebSocket connection
        server.accept()?;

        // Parse session name from URL
        let url = req.url()?;
        let path_segments: Vec<&str> = url.path().split('/').collect();
        let session_name = if path_segments.len() >= 2 {
            path_segments[1].to_string()
        } else {
            return Response::error("Invalid session name", 400);
        };

        console_log!("WebSocket upgrade for session: {}", session_name);

        // Set up basic WebSocket handling - simplified for compatibility
        console_log!(
            "WebSocket connection established for session: {}",
            session_name
        );

        Response::from_websocket(client)
    }

    /// Handle POST requests for session operations
    async fn handle_post_request(&self, mut req: Request) -> Result<Response> {
        console_log!("Received POST request to Durable Object");

        // Parse the request body for session operations
        let body = req.bytes().await?;
        let message: DurableObjectMessage = serde_json::from_slice(&body)
            .map_err(|e| worker::Error::from(format!("Failed to parse request: {}", e)))?;

        match message {
            DurableObjectMessage::JoinSession {
                session_name,
                user_id,
                can_write,
            } => {
                self.handle_join_session(session_name, user_id, can_write)
                    .await
            }
            DurableObjectMessage::LeaveSession { user_id } => {
                self.handle_leave_session(user_id).await
            }
            DurableObjectMessage::Broadcast {
                message,
                exclude_user,
            } => self.handle_broadcast(message, exclude_user).await,
            DurableObjectMessage::ClientMessage { user_id, message } => {
                self.handle_client_message(user_id, message).await
            }
            DurableObjectMessage::GetSessionState => self.handle_get_session_state().await,
            DurableObjectMessage::UpdateSessionState { state } => {
                self.handle_update_session_state(state).await
            }
        }
    }

    /// Handle GET requests for session information
    async fn handle_get_request(&self, _req: Request) -> Result<Response> {
        console_log!("Received GET request to Durable Object");

        // Return current session state
        let response = if let Some(ref state) = *self._session_state.borrow() {
            serde_json::to_vec(&DurableObjectResponse::SessionState(Some(state.clone())))
        } else {
            serde_json::to_vec(&DurableObjectResponse::SessionState(None))
        };

        match response {
            Ok(data) => Response::from_bytes(data),
            Err(e) => Response::error(format!("Failed to serialize response: {}", e), 500),
        }
    }

    /// Handle user joining a session
    async fn handle_join_session(
        &self,
        _session_name: String,
        _user_id: Uid,
        _can_write: bool,
    ) -> Result<Response> {
        console_log!("User {} joined session", _user_id);

        // In a real implementation, this would:
        // 1. Add the user to the session state
        // 2. Store the WebSocket connection for broadcasting
        // 3. Notify other users about the new participant
        // 4. Send initial session state to the new user

        Ok(Response::ok("User joined session")?)
    }

    /// Handle user leaving a session
    async fn handle_leave_session(&self, _user_id: Uid) -> Result<Response> {
        console_log!("User {} left session", _user_id);

        // In a real implementation, this would:
        // 1. Remove the user from the session state
        // 2. Close the WebSocket connection
        // 3. Notify other users about the user leaving
        // 4. Clean up any user-specific resources

        Ok(Response::ok("User left session")?)
    }

    /// Handle broadcasting messages to all connected clients
    async fn handle_broadcast(
        &self,
        _message: WsServer,
        _exclude_user: Option<Uid>,
    ) -> Result<Response> {
        console_log!("Broadcasting message to session");

        // In a real implementation, this would:
        // 1. Serialize the message
        // 2. Send it to all connected WebSocket clients
        // 3. Handle connection failures gracefully
        // 4. Use the Durable Object's broadcast capability

        Ok(Response::ok("Message broadcast")?)
    }

    /// Handle client messages (terminal data, chat, etc.)
    async fn handle_client_message(&self, _user_id: Uid, _message: WsClient) -> Result<Response> {
        console_log!("Received client message from user {}", _user_id);

        // In a real implementation, this would:
        // 1. Process the client message based on its type
        // 2. Update session state accordingly
        // 3. Broadcast relevant changes to other clients
        // 4. Forward terminal data to the backend process

        match _message {
            WsClient::Data(shell_id, data, offset) => {
                self.handle_terminal_data(shell_id, data, offset).await
            }
            WsClient::Create(x, y) => self.handle_shell_create(x, y).await,
            WsClient::Close(shell_id) => self.handle_shell_close(shell_id).await,
            WsClient::Move(shell_id, winsize) => self.handle_shell_move(shell_id, winsize).await,
            WsClient::Chat(message) => self.handle_chat_message(_user_id, message).await,
            _ => Ok(Response::ok("Client message received")?),
        }
    }

    /// Handle terminal data from client
    async fn handle_terminal_data(
        &self,
        _shell_id: Sid,
        _data: bytes::Bytes,
        _offset: u64,
    ) -> Result<Response> {
        console_log!(
            "Terminal data for shell {}: {} bytes at offset {}",
            _shell_id,
            _data.len(),
            _offset
        );

        // In a real implementation, this would:
        // 1. Store the terminal data in the session state
        // 2. Forward the data to the backend terminal process
        // 3. Broadcast the data to other subscribed clients
        // 4. Update sequence numbers and timestamps

        Ok(Response::ok("Terminal data received")?)
    }

    /// Handle shell creation
    async fn handle_shell_create(&self, _x: i32, _y: i32) -> Result<Response> {
        console_log!("Creating new shell at position ({}, {})", _x, _y);

        // In a real implementation, this would:
        // 1. Generate a new shell ID
        // 2. Initialize the shell state
        // 3. Start the backend terminal process
        // 4. Notify all clients about the new shell

        Ok(Response::ok("Shell created")?)
    }

    /// Handle shell closure
    async fn handle_shell_close(&self, _shell_id: Sid) -> Result<Response> {
        console_log!("Closing shell {}", _shell_id);

        // In a real implementation, this would:
        // 1. Mark the shell as closed
        // 2. Stop the backend terminal process
        // 3. Clean up associated resources
        // 4. Notify all clients about the shell closure

        Ok(Response::ok("Shell closed")?)
    }

    /// Handle shell movement/resizing
    async fn handle_shell_move(
        &self,
        _shell_id: Sid,
        _winsize: Option<WsWinsize>,
    ) -> Result<Response> {
        console_log!("Moving shell {}", _shell_id);

        // In a real implementation, this would:
        // 1. Update the shell's position and/or size
        // 2. Notify the backend terminal about the resize
        // 3. Broadcast the change to all clients

        Ok(Response::ok("Shell moved")?)
    }

    /// Handle chat messages
    async fn handle_chat_message(&self, _user_id: Uid, _message: String) -> Result<Response> {
        console_log!("Chat message from user {}: {}", _user_id, _message);

        // In a real implementation, this would:
        // 1. Store the chat message in session history
        // 2. Broadcast the message to all connected clients
        // 3. Update user activity timestamps

        Ok(Response::ok("Chat message received")?)
    }

    /// Get current session state
    async fn handle_get_session_state(&self) -> Result<Response> {
        console_log!("Getting session state");

        let response = if let Some(ref state) = *self._session_state.borrow() {
            serde_json::to_vec(&DurableObjectResponse::SessionState(Some(state.clone())))
        } else {
            serde_json::to_vec(&DurableObjectResponse::SessionState(None))
        };

        match response {
            Ok(data) => Response::from_bytes(data),
            Err(e) => Response::error(format!("Failed to serialize response: {}", e), 500),
        }
    }

    /// Update session state
    async fn handle_update_session_state(&self, _state: SessionState) -> Result<Response> {
        console_log!("Updating session state");

        // Store the updated session state
        *self._session_state.borrow_mut() = Some(_state);

        // In a real implementation, this would also:
        // 1. Persist the state to storage
        // 2. Notify relevant clients about state changes
        // 3. Handle any necessary cleanup or optimization

        Ok(Response::ok("Session state updated")?)
    }
}
