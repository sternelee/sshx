//! Ticket system for session sharing and P2P connections.
//!
//! This implementation follows the browser-chat.txt reference using postcard
//! serialization and BTreeSet<NodeId> for bootstrap nodes.

use std::{collections::BTreeSet, fmt, str::FromStr};

use anyhow::Result;
use iroh::NodeId;
use iroh_base::ticket::Ticket;
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};

/// A ticket that contains the necessary information to join a session.
/// Following the ChatTicket pattern from browser-chat.txt reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionTicket {
    /// The gossip topic to join.
    pub topic_id: TopicId,
    /// Bootstrap nodes for discovery.
    pub bootstrap: BTreeSet<NodeId>,
    /// The encryption key for the session.
    pub key: String,
    /// Optional write password for read-only mode.
    pub write_password: Option<String>,
}

impl SessionTicket {
    /// Create a new random session ticket.
    pub fn new_random() -> Self {
        let topic_id = TopicId::from_bytes(rand::random());
        Self::new(topic_id)
    }

    /// Create a new session ticket with a specific topic.
    pub fn new(topic_id: TopicId) -> Self {
        Self {
            topic_id,
            bootstrap: Default::default(),
            key: crate::crypto::rand_alphanumeric(22),
            write_password: None,
        }
    }

    /// Create a new session ticket with specific nodes.
    pub fn with_bootstrap(topic_id: TopicId, bootstrap: BTreeSet<NodeId>, key: String) -> Self {
        Self {
            topic_id,
            bootstrap,
            key,
            write_password: None,
        }
    }

    /// Create a new session ticket with write password.
    pub fn with_write_password(
        topic_id: TopicId,
        bootstrap: BTreeSet<NodeId>,
        key: String,
        write_password: String,
    ) -> Self {
        Self {
            topic_id,
            bootstrap,
            key,
            write_password: Some(write_password),
        }
    }

    /// Deserialize from a string using the Ticket trait.
    pub fn deserialize(input: &str) -> Result<Self> {
        <Self as Ticket>::deserialize(input).map_err(Into::into)
    }

    /// Serialize to a string using the Ticket trait.
    pub fn serialize(&self) -> String {
        <Self as Ticket>::serialize(self)
    }
}

/// Implement the Ticket trait for SessionTicket to match browser-chat.txt
/// pattern
impl Ticket for SessionTicket {
    const KIND: &'static str = "sshx";

    fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, iroh_base::ticket::ParseError> {
        let ticket = postcard::from_bytes(bytes)
            .map_err(|_| iroh_base::ticket::ParseError::verification_failed("Invalid format"))?;
        Ok(ticket)
    }
}

impl FromStr for SessionTicket {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::deserialize(s)
    }
}

impl fmt::Display for SessionTicket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.serialize())
    }
}

/// Options for generating tickets with different bootstrap configurations.
/// Following the TicketOpts pattern from browser-chat.txt reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TicketOpts {
    pub include_myself: bool,
    pub include_bootstrap: bool,
    pub include_neighbors: bool,
}

impl Default for TicketOpts {
    fn default() -> Self {
        Self {
            include_myself: true,
            include_bootstrap: true,
            include_neighbors: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_serialization() {
        let topic_id = TopicId::from_bytes([1; 32]);
        let ticket = SessionTicket::new(topic_id);
        let serialized = ticket.serialize();
        let deserialized = SessionTicket::deserialize(&serialized).unwrap();

        assert_eq!(ticket.topic_id, deserialized.topic_id);
    }

    #[test]
    fn test_ticket_from_str() {
        let topic_id = TopicId::from_bytes([1; 32]);
        let ticket = SessionTicket::new(topic_id);
        let serialized = ticket.to_string();
        let deserialized: SessionTicket = serialized.parse().unwrap();

        assert_eq!(ticket.topic_id, deserialized.topic_id);
    }
}
