//! Event and message types for sshx communication.

use iroh::NodeId;
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
    /// Request to create a new shell.
    CreateShell { id: Sid },
    /// Input bytes from user terminal.
    Input(TerminalInput),
    /// Request to close a shell.
    CloseShell { id: Sid },
}

/// Bidirectional streaming update from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerMessage {
    /// Notification that a shell was created.
    CreatedShell { id: Sid },
    /// Terminal data from shell output.
    Data(TerminalData),

    /// Notification that a shell was closed.
    ClosedShell { id: Sid },
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
    /// Session error occurred.
    Error {
        /// Error message.
        message: String,
    },
}

/// P2P network events following the browser-chat.txt reference pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Event {
    /// A new peer joined the session
    Joined { neighbors: Vec<NodeId> },
    /// A message was received
    MessageReceived {
        from: NodeId,
        text: String,
        nickname: String,
        sent_timestamp: u64,
    },
    /// A presence update was received
    Presence {
        from: NodeId,
        nickname: String,
        sent_timestamp: u64,
    },
    /// A new peer connected
    NeighborUp { node_id: NodeId },
    /// A peer disconnected
    NeighborDown { node_id: NodeId },
    /// The client is lagging behind
    Lagged,
}
