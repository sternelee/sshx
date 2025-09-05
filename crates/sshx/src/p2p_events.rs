//! Terminal event types for P2P synchronization

use serde::{Deserialize, Serialize};

/// Terminal event types that can be synchronized over P2P
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EventType {
    /// Terminal output data
    Output,
    /// User input data
    Input,
    /// Terminal resize event
    Resize { width: u16, height: u16 },
    /// Session end event
    End,
}

/// A terminal event that can be synchronized over P2P
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalEvent {
    pub timestamp: f64,
    pub event_type: EventType,
    pub data: String,
}

/// Session header information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHeader {
    pub session_id: String,
    pub name: String,
    pub shell: String,
    pub created_at: u64,
}

/// Session information including history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub header: SessionHeader,
    pub shell: String,
    pub cwd: String,
    pub logs: Vec<String>,
}
