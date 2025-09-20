//! Message signing and verification for sshx P2P communication.
//!
//! This module implements message signing and verification similar to the
//! browser-chat example, ensuring message integrity and authenticity.

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use iroh::{PublicKey, SecretKey};
use iroh_base::Signature;
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{
    events::{ClientMessage, ServerMessage, SessionEvent},
    Uid,
};

/// A signed message with sender information and signature
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    /// The sender's public key
    pub from: PublicKey,
    /// The serialized message data
    pub data: Vec<u8>,
    /// The signature of the data
    pub signature: Signature,
}

/// Wire message format with timestamp
#[derive(Debug, Serialize, Deserialize)]
pub enum WireMessage {
    /// Versioned message with timestamp
    VO { timestamp: u64, message: Message },
}

/// Message types for P2P communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Client message (requests from browser to CLI)
    ClientMessage(ClientMessage),
    /// Server message (responses from CLI to browser)
    ServerMessage(ServerMessage),
    /// Session event (notifications about session state)
    SessionEvent(SessionEvent),
    /// Presence message to indicate user status (following reference pattern)
    Presence { nickname: String },
}

/// Received message with metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceivedMessage {
    /// Timestamp when message was sent
    pub timestamp: u64,
    /// Sender's node ID
    pub from: iroh::NodeId,
    /// The actual message
    pub message: Message,
}

impl SignedMessage {
    /// Verify and decode a signed message
    pub fn verify_and_decode(bytes: &[u8]) -> Result<ReceivedMessage> {
        let signed_message: Self = postcard::from_bytes(bytes)?;
        let key: PublicKey = signed_message.from;
        key.verify(&signed_message.data, &signed_message.signature)?;
        let message: WireMessage = postcard::from_bytes(&signed_message.data)?;
        let WireMessage::VO { timestamp, message } = message;
        Ok(ReceivedMessage {
            from: signed_message.from.into(),
            timestamp,
            message,
        })
    }

    /// Create a new signed message
    pub fn new(secret_key: &SecretKey, message: &Message) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        let wire_message = WireMessage::VO {
            timestamp,
            message: message.clone(),
        };
        let data = postcard::to_stdvec(&wire_message)?;
        let signature = secret_key.sign(&data);
        let from: PublicKey = secret_key.public();
        Ok(Self {
            from,
            data,
            signature,
        })
    }

    /// Sign and encode a message
    pub fn sign_and_encode(secret_key: &SecretKey, message: Message) -> Result<Vec<u8>> {
        let signed_message = Self::new(secret_key, &message)?;
        let encoded = postcard::to_stdvec(&signed_message)?;
        Ok(encoded)
    }
}
