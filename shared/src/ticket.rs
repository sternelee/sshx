//! Ticket system for session sharing and P2P connections.

use anyhow::Result;
use data_encoding::BASE32_NOPAD;
use iroh::NodeAddr;
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// A ticket that contains the necessary information to join a session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionTicket {
    /// The gossip topic to join.
    pub topic: TopicId,
    /// The node addresses of the host.
    pub nodes: Vec<NodeAddr>,
    /// The encryption key for the session.
    pub key: String,
    /// Optional write password for read-only mode.
    pub write_password: Option<String>,
}

impl SessionTicket {
    /// Create a new session ticket.
    pub fn new(topic: TopicId, nodes: Vec<NodeAddr>, key: String) -> Self {
        Self {
            topic,
            nodes,
            key,
            write_password: None,
        }
    }

    /// Create a new session ticket with write password.
    pub fn with_write_password(
        topic: TopicId,
        nodes: Vec<NodeAddr>,
        key: String,
        write_password: String,
    ) -> Self {
        Self {
            topic,
            nodes,
            key,
            write_password: Some(write_password),
        }
    }

    /// Deserialize from a slice of bytes to a Ticket.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(Into::into)
    }

    /// Serialize from a `Ticket` to a `Vec` of bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serde_json::to_vec is infallible")
    }

    /// Get the ticket as a shareable string, optionally including write password.
    pub fn to_shareable_string(&self, include_write_password: bool) -> String {
        if include_write_password && self.write_password.is_some() {
            format!(
                "{},{}",
                self.to_string(),
                self.write_password.as_ref().unwrap()
            )
        } else {
            self.to_string()
        }
    }
}

impl fmt::Display for SessionTicket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = BASE32_NOPAD.encode(&self.to_bytes()[..]);
        text.make_ascii_lowercase();
        write!(f, "{}", text)
    }
}

impl FromStr for SessionTicket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').collect();
        let ticket_str = parts[0];
        let bytes = BASE32_NOPAD.decode(ticket_str.to_ascii_uppercase().as_bytes())?;
        let mut ticket = Self::from_bytes(&bytes)?;

        // If there's a second part, it's the write password
        if parts.len() > 1 {
            ticket.write_password = Some(parts[1].to_string());
        }

        Ok(ticket)
    }
}

/// Configuration for creating session tickets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketConfig {
    /// Whether to include the local node in the ticket.
    pub include_self: bool,
    /// Whether to include bootstrap nodes.
    pub include_bootstrap: bool,
    /// Whether to include current neighbors.
    pub include_neighbors: bool,
    /// Whether to include write password.
    pub include_write_password: bool,
}

impl Default for TicketConfig {
    fn default() -> Self {
        Self {
            include_self: true,
            include_bootstrap: true,
            include_neighbors: false,
            include_write_password: false,
        }
    }
}

/// Utility functions for ticket management.
pub mod utils {
    use super::*;
    use crate::crypto::rand_alphanumeric;
    use rand::RngCore;

    /// Generate a new random session key.
    pub fn generate_session_key() -> String {
        rand_alphanumeric(22)
    }

    /// Generate a new random topic ID.
    pub fn generate_topic_id() -> TopicId {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        TopicId::from_bytes(bytes)
    }

    /// Create a basic session ticket with minimal configuration.
    pub fn create_basic_ticket(nodes: Vec<NodeAddr>) -> SessionTicket {
        SessionTicket::new(generate_topic_id(), nodes, generate_session_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_serialization() {
        let topic = TopicId::from_bytes([1; 32]);
        let nodes = vec![];
        let key = "test_key".to_string();

        let ticket = SessionTicket::new(topic, nodes, key);
        let serialized = ticket.to_string();
        let deserialized: SessionTicket = serialized.parse().unwrap();

        assert_eq!(ticket, deserialized);
    }

    #[test]
    fn test_ticket_with_password() {
        let topic = TopicId::from_bytes([1; 32]);
        let nodes = vec![];
        let key = "test_key".to_string();
        let password = "secret".to_string();

        let ticket = SessionTicket::with_write_password(topic, nodes, key, password.clone());
        let serialized = ticket.to_shareable_string(true);
        let deserialized: SessionTicket = serialized.parse().unwrap();

        assert_eq!(ticket, deserialized);
        assert_eq!(deserialized.write_password, Some(password));
    }
}

