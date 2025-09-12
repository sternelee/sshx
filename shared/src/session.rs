//! Session management and state types.

use serde::{Deserialize, Serialize};

/// Request to open a new session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRequest {
    /// Web origin of the server.
    pub origin: String,
    /// Encrypted zero block, for client verification.
    pub encrypted_zeros: Vec<u8>,
    /// Name of the session (user@hostname).
    pub name: String,
}

/// Response to opening a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenResponse {
    /// Name of the session.
    pub name: String,
    /// Signed verification token for the client.
    pub token: String,
    /// Public web URL to view the session.
    pub url: String,
}

/// Request to close a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseRequest {
    /// Name of the session to terminate.
    pub name: String,
    /// Session verification token.
    pub token: String,
}

/// Response to closing a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseResponse {
    /// Whether the session was successfully closed.
    pub success: bool,
}
