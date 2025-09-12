//! Event and message types for sshx communication.

use serde::{Deserialize, Serialize};

use crate::{Sid, Uid};

/// Details of bytes exchanged with the terminal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerminalData {
    /// ID of the shell.
    pub id: Sid,
    /// Encrypted, UTF-8 terminal data.
    pub data: Vec<u8>,
    /// Sequence number of the first byte.
    pub seq: u64,
}

/// Details of bytes input to the terminal (not necessarily valid UTF-8).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerminalInput {
    /// ID of the shell.
    pub id: Sid,
    /// Encrypted binary sequence of terminal data.
    pub data: Vec<u8>,
    /// Offset of the first byte for encryption.
    pub offset: u64,
}

/// Pair of a terminal ID and its associated size.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerminalSize {
    /// Number of rows for the terminal.
    pub rows: u32,
    /// Number of columns for the terminal.
    pub cols: u32,
}

/// Bidirectional streaming update from the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ClientMessage {
    /// First stream message: "name,token".
    Hello { content: String },
    /// Stream data from the terminal.
    Data(TerminalData),
    /// Acknowledge that a new shell was created.
    CreatedShell { id: Sid },
    /// Acknowledge that a shell was closed.
    ClosedShell { id: Sid },
    /// Error message.
    Error { message: String },
}

/// Bidirectional streaming update from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerMessage {
    /// Remote input bytes, received from the user.
    Input(TerminalInput),
    /// ID of a new shell.
    CreateShell { id: Sid },
    /// ID of a shell to close.
    CloseShell { id: Sid },
    /// Periodic sequence number sync.
    Sync { shells: Vec<(Sid, u64)> },
    /// Resize a terminal window.
    Resize(TerminalSize),
    /// Error message.
    Error { message: String },
}

/// Session event that can occur during a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum SessionEvent {
    /// A new peer joined the session.
    PeerJoined {
        /// The user ID of the peer.
        user_id: Uid,
        /// Optional name of the peer.
        name: Option<String>,
    },
    /// A peer left the session.
    PeerLeft {
        /// The user ID of the peer.
        user_id: Uid,
    },
    /// A shell was created.
    ShellCreated { id: Sid },
    /// A shell was closed.
    ShellClosed {
        /// ID of the shell that was closed.
        id: Sid,
    },
    /// Terminal data was received.
    TerminalData(TerminalData),
    /// Terminal was resized.
    TerminalResize { id: Sid, size: TerminalSize },
    /// Session error occurred.
    Error {
        /// Error message.
        message: String,
    },
}
