//! Session management and state types.

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use crate::{Sid, Uid};
use crate::events::{SerializedSession, SerializedShell};

/// Session information and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session name.
    pub name: String,
    /// Session token for verification.
    pub token: String,
    /// Public web URL to view the session.
    pub url: String,
    /// Whether the session allows write access.
    pub writeable: bool,
    /// Creation timestamp.
    pub created_at: u64,
}

/// Request to open a new session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRequest {
    /// Web origin of the server.
    pub origin: String,
    /// Encrypted zero block, for client verification.
    pub encrypted_zeros: Vec<u8>,
    /// Name of the session (user@hostname).
    pub name: String,
    /// Hashed write password, if read-only mode is enabled.
    pub write_password_hash: Option<Vec<u8>>,
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

/// Configuration for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Maximum number of concurrent shells.
    pub max_shells: usize,
    /// Session timeout in seconds.
    pub timeout: u64,
    /// Whether to enable read-only mode.
    pub read_only: bool,
    /// Custom relay server URLs.
    pub relay_servers: Vec<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_shells: 10,
            timeout: 3600, // 1 hour
            read_only: false,
            relay_servers: vec![],
        }
    }
}

/// Current state of a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Session information.
    pub info: SessionInfo,
    /// Active shells.
    pub shells: BTreeMap<Sid, ShellState>,
    /// Connected users.
    pub users: BTreeMap<Uid, UserInfo>,
    /// Session configuration.
    pub config: SessionConfig,
}

/// State of an individual shell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellState {
    /// Shell ID.
    pub id: Sid,
    /// Current sequence number.
    pub seqnum: u64,
    /// Whether the shell is active.
    pub active: bool,
    /// Window size.
    pub size: Option<crate::events::TerminalSize>,
    /// Position on screen.
    pub position: Option<(i32, i32)>,
    /// Creation timestamp.
    pub created_at: u64,
}

/// Information about a connected user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// User ID.
    pub id: Uid,
    /// Optional display name.
    pub name: Option<String>,
    /// Whether the user has write permissions.
    pub can_write: bool,
    /// Connection timestamp.
    pub connected_at: u64,
    /// Last activity timestamp.
    pub last_seen: u64,
}

impl SessionState {
    /// Create a new session state.
    pub fn new(info: SessionInfo, config: SessionConfig) -> Self {
        Self {
            info,
            shells: BTreeMap::new(),
            users: BTreeMap::new(),
            config,
        }
    }

    /// Add a new shell to the session.
    pub fn add_shell(&mut self, shell: ShellState) {
        self.shells.insert(shell.id, shell);
    }

    /// Remove a shell from the session.
    pub fn remove_shell(&mut self, id: Sid) -> Option<ShellState> {
        self.shells.remove(&id)
    }

    /// Add a user to the session.
    pub fn add_user(&mut self, user: UserInfo) {
        self.users.insert(user.id, user);
    }

    /// Remove a user from the session.
    pub fn remove_user(&mut self, id: Uid) -> Option<UserInfo> {
        self.users.remove(&id)
    }

    /// Convert to serialized format for persistence.
    pub fn to_serialized(&self, encrypted_zeros: Vec<u8>) -> SerializedSession {
        let shells = self.shells.iter().map(|(id, shell)| {
            let serialized_shell = SerializedShell {
                seqnum: shell.seqnum,
                data: vec![], // Would contain actual shell data in real implementation
                chunk_offset: 0,
                byte_offset: 0,
                closed: !shell.active,
                winsize_x: shell.position.map(|(x, _)| x).unwrap_or(0),
                winsize_y: shell.position.map(|(_, y)| y).unwrap_or(0),
                winsize_rows: shell.size.as_ref().map(|s| s.rows).unwrap_or(24),
                winsize_cols: shell.size.as_ref().map(|s| s.cols).unwrap_or(80),
            };
            (*id, serialized_shell)
        }).collect();

        SerializedSession {
            encrypted_zeros,
            shells,
            next_sid: Sid(self.shells.keys().max().map(|s| s.0 + 1).unwrap_or(1)),
            next_uid: Uid(self.users.keys().max().map(|u| u.0 + 1).unwrap_or(1)),
            name: self.info.name.clone(),
            write_password_hash: None, // Would be populated from config in real implementation
        }
    }
}
