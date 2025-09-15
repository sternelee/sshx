//! Durable Object implementation for sshx session coordination
//!
//! This module provides a Durable Object that handles real-time coordination
//! for sshx sessions, including WebSocket connections, state synchronization,
//! and message broadcasting.

use serde::{Deserialize, Serialize};
use worker::*;

use crate::protocol::{WsClient, WsServer};
use crate::session::SessionState;
use sshx_core::Uid;

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
    _session_state: Option<SessionState>,
}

impl DurableObject for SshxSession {
    fn new(state: State, env: Env) -> Self {
        Self {
            _state: state,
            _env: env,
            _session_state: None,
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
    async fn handle_post_request(&self, _req: Request) -> Result<Response> {
        console_log!("Received POST request to Durable Object");

        // For now, just return a success response
        Response::ok("POST request received")
    }

    /// Handle GET requests for session information
    async fn handle_get_request(&self, _req: Request) -> Result<Response> {
        console_log!("Received GET request to Durable Object");
        Response::ok("GET request received")
    }
}
