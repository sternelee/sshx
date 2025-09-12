//! The core crate for shared code used in the sshx application.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt::Display;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};

pub mod crypto;
pub mod events;
pub mod p2p;
pub mod session;
pub mod ticket;

// Re-export commonly used types
pub use crypto::{rand_alphanumeric, Encryptor};
pub use events::{
    ClientMessage, NewShell, SequenceNumbers, SerializedSession, SerializedShell, ServerMessage,
    SessionEvent, ShellInfo, ShellList, TerminalData, TerminalInput, TerminalSize,
};
pub use p2p::{
    P2pConfig, P2pEvent, P2pMessage, P2pNode, P2pSession, P2pSessionManager,
    SessionInfo as P2pSessionInfo,
};
pub use session::{
    CloseRequest, CloseResponse, OpenRequest, OpenResponse, SessionConfig, SessionInfo,
    SessionState, ShellState, UserInfo,
};
pub use ticket::SessionTicket;

/// Unique identifier for a shell within the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sid(pub u32);

impl Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for Sid {
    fn from(id: u32) -> Self {
        Sid(id)
    }
}

/// Unique identifier for a user within the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Uid(pub u32);

impl Display for Uid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for Uid {
    fn from(id: u32) -> Self {
        Uid(id)
    }
}

/// A counter for generating unique identifiers.
#[derive(Debug)]
pub struct IdCounter {
    next_sid: AtomicU32,
    next_uid: AtomicU32,
}

impl Default for IdCounter {
    fn default() -> Self {
        Self {
            next_sid: AtomicU32::new(1),
            next_uid: AtomicU32::new(1),
        }
    }
}

impl IdCounter {
    /// Returns the next unique shell ID.
    pub fn next_sid(&self) -> Sid {
        Sid(self.next_sid.fetch_add(1, Ordering::Relaxed))
    }

    /// Returns the next unique user ID.
    pub fn next_uid(&self) -> Uid {
        Uid(self.next_uid.fetch_add(1, Ordering::Relaxed))
    }

    /// Return the current internal values of the counter.
    pub fn get_current_values(&self) -> (Sid, Uid) {
        (
            Sid(self.next_sid.load(Ordering::Relaxed)),
            Uid(self.next_uid.load(Ordering::Relaxed)),
        )
    }

    /// Set the internal values of the counter.
    pub fn set_current_values(&self, sid: Sid, uid: Uid) {
        self.next_sid.store(sid.0, Ordering::Relaxed);
        self.next_uid.store(uid.0, Ordering::Relaxed);
    }
}
