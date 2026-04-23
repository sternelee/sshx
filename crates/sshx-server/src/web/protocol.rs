//! Serializable types sent and received by the web server.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sshx_core::{Sid, Uid};

/// Real-time message conveying the position and size of a terminal.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WsWinsize {
    /// The top-left x-coordinate of the window, offset from origin.
    pub x: i32,
    /// The top-left y-coordinate of the window, offset from origin.
    pub y: i32,
    /// The number of rows in the window.
    pub rows: u16,
    /// The number of columns in the terminal.
    pub cols: u16,
}

impl Default for WsWinsize {
    fn default() -> Self {
        WsWinsize {
            x: 0,
            y: 0,
            rows: 24,
            cols: 80,
        }
    }
}

/// Real-time message providing information about a user.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WsUser {
    /// The user's display name.
    pub name: String,
    /// Live coordinates of the mouse cursor, if available.
    pub cursor: Option<(i32, i32)>,
    /// Currently focused terminal window ID.
    pub focus: Option<Sid>,
    /// Whether the user has write permissions in the session.
    pub can_write: bool,
}

/// A real-time message sent from the server over WebSocket.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub enum WsServer {
    /// Initial server message, with the user's ID and session metadata.
    #[serde(rename = "h")]
    Hello(Uid, String),
    /// The user's authentication was invalid.
    #[serde(rename = "a")]
    InvalidAuth(),
    /// A snapshot of all current users in the session.
    #[serde(rename = "u")]
    Users(Vec<(Uid, WsUser)>),
    /// Info about a single user in the session: joined, left, or changed.
    #[serde(rename = "d")]
    UserDiff(Uid, Option<WsUser>),
    /// Notification when the set of open shells has changed.
    #[serde(rename = "s")]
    Shells(Vec<(Sid, WsWinsize)>),
    /// Subscription results, in the form of terminal data chunks.
    #[serde(rename = "c")]
    Chunks(Sid, u64, Vec<Bytes>),
    /// Get a chat message tuple `(uid, name, text)` from the room.
    #[serde(rename = "e")]
    Hear(Uid, String, String),
    /// Forward a latency measurement between the server and backend shell.
    #[serde(rename = "l")]
    ShellLatency(u64),
    /// Echo back a timestamp, for the the client's own latency measurement.
    #[serde(rename = "p")]
    Pong(u64),
    /// Alert the client of an application error.
    #[serde(rename = "x")]
    Error(String),
}

/// A real-time message sent from the client over WebSocket.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub enum WsClient {
    /// Authenticate the user's encryption key by zeros block and write password
    /// (if provided).
    #[serde(rename = "a")]
    Authenticate(Bytes, Option<Bytes>),
    /// Set the name of the current user.
    #[serde(rename = "n")]
    SetName(String),
    /// Send real-time information about the user's cursor.
    #[serde(rename = "c")]
    SetCursor(Option<(i32, i32)>),
    /// Set the currently focused shell.
    #[serde(rename = "f")]
    SetFocus(Option<Sid>),
    /// Create a new shell.
    #[serde(rename = "e")]
    Create(i32, i32),
    /// Close a specific shell.
    #[serde(rename = "x")]
    Close(Sid),
    /// Move a shell window to a new position and focus it.
    #[serde(rename = "m")]
    Move(Sid, Option<WsWinsize>),
    /// Add user data to a given shell.
    #[serde(rename = "d")]
    Data(Sid, Bytes, u64),
    /// Subscribe to a shell, starting at a given chunk index.
    #[serde(rename = "s")]
    Subscribe(Sid, u64),
    /// Send a a chat message to the room.
    #[serde(rename = "t")]
    Chat(String),
    /// Send a ping to the server, for latency measurement.
    #[serde(rename = "p")]
    Ping(u64),
}
