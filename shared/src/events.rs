//! Event and message types for sshx communication.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    /// ID of the shell.
    pub id: Sid,
    /// Number of rows for the terminal.
    pub rows: u32,
    /// Number of columns for the terminal.
    pub cols: u32,
}

/// Sequence numbers for all active shells, used for synchronization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SequenceNumbers {
    /// Active shells and their sequence numbers.
    pub map: BTreeMap<Sid, u64>,
}

/// Data for a new shell.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NewShell {
    /// ID of the shell.
    pub id: Sid,
    /// X position of the shell.
    pub x: i32,
    /// Y position of the shell.
    pub y: i32,
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
    CreatedShell(NewShell),
    /// Acknowledge that a shell was closed.
    ClosedShell { id: Sid },
    /// Response for latency measurement.
    Pong { timestamp: u64 },
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
    CreateShell(NewShell),
    /// ID of a shell to close.
    CloseShell { id: Sid },
    /// Periodic sequence number sync.
    Sync(SequenceNumbers),
    /// Resize a terminal window.
    Resize(TerminalSize),
    /// Request a pong, with the timestamp.
    Ping { timestamp: u64 },
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
    ShellCreated(NewShell),
    /// A shell was closed.
    ShellClosed {
        /// ID of the shell that was closed.
        id: Sid,
    },
    /// Terminal data was received.
    TerminalData(TerminalData),
    /// Terminal was resized.
    TerminalResize(TerminalSize),
    /// Session error occurred.
    Error {
        /// Error message.
        message: String,
    },
}

/// Serialized shell state for session persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedShell {
    /// Sequence number.
    pub seqnum: u64,
    /// Shell data chunks.
    pub data: Vec<Vec<u8>>,
    /// Chunk offset.
    pub chunk_offset: u64,
    /// Byte offset.
    pub byte_offset: u64,
    /// Whether the shell is closed.
    pub closed: bool,
    /// Window size X.
    pub winsize_x: i32,
    /// Window size Y.
    pub winsize_y: i32,
    /// Window size rows.
    pub winsize_rows: u32,
    /// Window size columns.
    pub winsize_cols: u32,
}

/// Snapshot of a session, used to restore state for persistence across servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedSession {
    /// Encrypted zeros block.
    pub encrypted_zeros: Vec<u8>,
    /// Shell states.
    pub shells: BTreeMap<Sid, SerializedShell>,
    /// Next shell ID.
    pub next_sid: Sid,
    /// Next user ID.
    pub next_uid: Uid,
    /// Session name.
    pub name: String,
    /// Write password hash, if read-only mode is enabled.
    pub write_password_hash: Option<Vec<u8>>,
}
