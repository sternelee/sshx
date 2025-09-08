//! P2P networking module using iroh for distributed communication.

use anyhow::{Context, Result};
use iroh::{protocol::Router, Endpoint, NodeAddr, SecretKey};
use iroh_gossip::{
    api::{Event as GossipEvent, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use n0_future::{boxed::BoxStream, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::rand_alphanumeric;
use crate::ticket::SessionTicket;

/// P2P node configuration for iroh networking
#[derive(Debug, Clone)]
pub struct P2pConfig {
    /// Custom relay server URL
    pub relay_url: Option<String>,
    /// Enable IPv4 preference
    pub prefer_ipv4: bool,
    /// Enable debug logging
    pub debug: bool,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            relay_url: None,
            prefer_ipv4: true,
            debug: false,
        }
    }
}

/// Unified P2P node that can be used by both CLI and WASM applications
pub struct P2pNode {
    secret_key: SecretKey,
    endpoint: Endpoint,
    gossip: Gossip,
    router: Router,
}

impl P2pNode {
    /// Creates a new P2P node with the given configuration
    pub async fn new(config: P2pConfig) -> Result<Self> {
        let secret_key = SecretKey::generate(&mut rand::rngs::OsRng);

        // Create iroh endpoint with configuration
        let mut endpoint_builder = Endpoint::builder().secret_key(secret_key.clone());

        // Configure IPv4/IPv6 binding based on preferences
        if config.prefer_ipv4 {
            endpoint_builder = endpoint_builder
                .bind_addr_v4(std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::UNSPECIFIED,
                    0,
                ))
                .bind_addr_v6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::LOCALHOST,
                    0,
                    0,
                    0,
                ));
        }

        // Configure relay
        let endpoint = if let Some(relay) = config.relay_url {
            if config.debug {
                tracing::debug!("Using custom relay server: {}", relay);
            }
            // Parse the relay URL and use it for discovery
            let _relay_url: url::Url = relay.parse()?;
            endpoint_builder
                .discovery_n0() // Use default discovery for now
                .bind()
                .await?
        } else {
            if config.debug {
                tracing::debug!("Using default n0 relay server");
            }
            endpoint_builder.discovery_n0().bind().await?
        };

        if config.debug {
            tracing::info!("P2P node created with ID: {}", endpoint.node_id());
        }

        let gossip = Gossip::builder().spawn(endpoint.clone());

        let router = Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .spawn();

        Ok(Self {
            secret_key,
            endpoint,
            gossip,
            router,
        })
    }

    /// Returns the node ID
    pub fn node_id(&self) -> iroh::NodeId {
        self.endpoint.node_id()
    }

    /// Returns the node address
    pub async fn node_addr(&self) -> NodeAddr {
        // For now, let's create a minimal NodeAddr using just the node ID
        // In a real implementation, you'd get the full address from the endpoint
        NodeAddr::new(self.node_id())
    }

    /// Creates a new session with a random topic
    pub async fn create_session(&self) -> Result<P2pSession> {
        let topic = Self::generate_topic();
        let encryption_key = rand_alphanumeric(14); // 83.3 bits of entropy

        let me = self.node_addr().await;
        let ticket = SessionTicket::new(topic, vec![me], encryption_key.clone());

        P2pSession::new(self, topic, ticket, encryption_key).await
    }

    /// Joins an existing session from a ticket
    pub async fn join_session(&self, ticket: SessionTicket) -> Result<P2pSession> {
        let encryption_key = ticket.key.clone();

        // Add nodes to address book first
        for node in &ticket.nodes {
            if let Err(err) = self.endpoint.add_node_addr(node.clone()) {
                tracing::warn!("Failed to add node to address book: {}", err);
            }
        }

        P2pSession::new(self, ticket.topic, ticket, encryption_key).await
    }

    /// Generates a random topic ID
    fn generate_topic() -> TopicId {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        TopicId::from_bytes(bytes)
    }

    /// Shutdown the node gracefully
    pub async fn shutdown(self) -> Result<()> {
        if let Err(err) = self.router.shutdown().await {
            tracing::warn!("Failed to shutdown router cleanly: {}", err);
        }
        self.endpoint.close().await;
        Ok(())
    }
}

/// A P2P session for managing communication over iroh gossip
pub struct P2pSession {
    topic: TopicId,
    ticket: SessionTicket,
    encryption_key: String,
    sender: GossipSender,
    receiver: Option<GossipReceiver>,
}

impl P2pSession {
    async fn new(
        node: &P2pNode,
        topic: TopicId,
        ticket: SessionTicket,
        encryption_key: String,
    ) -> Result<Self> {
        let node_ids = ticket.nodes.iter().map(|p| p.node_id).collect::<Vec<_>>();

        tracing::info!(
            "Subscribing to topic with {} bootstrap nodes",
            node_ids.len()
        );

        let topic_handle = node
            .gossip
            .subscribe(topic, node_ids)
            .await
            .context("Failed to subscribe to gossip topic")?;

        let (sender, receiver) = topic_handle.split();

        Ok(Self {
            topic,
            ticket,
            encryption_key,
            sender,
            receiver: Some(receiver),
        })
    }

    /// Returns the session topic ID
    pub fn topic(&self) -> &TopicId {
        &self.topic
    }

    /// Returns the session ticket
    pub fn ticket(&self) -> &SessionTicket {
        &self.ticket
    }

    /// Returns the encryption key
    pub fn encryption_key(&self) -> &str {
        &self.encryption_key
    }

    /// Returns the sender for broadcasting messages
    pub fn sender(&self) -> &GossipSender {
        &self.sender
    }

    /// Takes ownership of the receiver
    pub fn take_receiver(&mut self) -> Option<GossipReceiver> {
        self.receiver.take()
    }

    /// Gets a reference to the receiver
    pub fn receiver(&self) -> Option<&GossipReceiver> {
        self.receiver.as_ref()
    }

    /// Broadcasts a message to all participants in the session
    pub async fn broadcast(&self, data: Vec<u8>) -> Result<()> {
        self.sender
            .broadcast(data.into())
            .await
            .context("Failed to broadcast message")
    }

    /// Creates a stream of gossip events
    pub fn event_stream(&mut self) -> Option<BoxStream<Result<GossipEvent>>> {
        self.receiver.take().map(|receiver| {
            let stream = receiver
                .map(|event| event.map_err(|e| anyhow::anyhow!("Gossip event error: {}", e)));
            Box::pin(stream) as BoxStream<Result<GossipEvent>>
        })
    }

    /// Creates a session manager for handling multiple sessions
    pub fn into_manager(self) -> P2pSessionManager {
        P2pSessionManager::with_session(self)
    }
}

/// Manages multiple P2P sessions
pub struct P2pSessionManager {
    sessions: std::collections::HashMap<String, ManagedSession>,
}

struct ManagedSession {
    session: P2pSession,
    active: bool,
    created_at: std::time::SystemTime,
}

impl P2pSessionManager {
    /// Creates a new session manager
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
        }
    }

    /// Adds a session to the manager
    pub fn add_session(&mut self, session: P2pSession) -> String {
        let session_id = session.topic().to_string();
        let managed_session = ManagedSession {
            session,
            active: true,
            created_at: std::time::SystemTime::now(),
        };
        self.sessions.insert(session_id.clone(), managed_session);
        session_id
    }

    /// Gets a session by ID
    pub fn get_session(&self, session_id: &str) -> Option<&P2pSession> {
        self.sessions
            .get(session_id)
            .and_then(|ms| if ms.active { Some(&ms.session) } else { None })
    }

    /// Gets a mutable session by ID
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut P2pSession> {
        self.sessions.get_mut(session_id).and_then(|ms| {
            if ms.active {
                Some(&mut ms.session)
            } else {
                None
            }
        })
    }

    /// Lists all active session IDs
    pub fn list_sessions(&self) -> Vec<String> {
        self.sessions
            .iter()
            .filter(|(_, ms)| ms.active)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Removes a session from the manager
    pub fn remove_session(&mut self, session_id: &str) -> bool {
        if let Some(managed_session) = self.sessions.get_mut(session_id) {
            managed_session.active = false;
            true
        } else {
            false
        }
    }

    /// Broadcasts a message to all active sessions
    pub async fn broadcast_to_all(&self, data: Vec<u8>) -> Result<()> {
        let mut results = Vec::new();

        for managed_session in self.sessions.values() {
            if managed_session.active {
                let result = managed_session.session.broadcast(data.clone()).await;
                results.push(result);
            }
        }

        // Check if any broadcasts failed
        for result in results {
            result?;
        }

        Ok(())
    }

    /// Sends a message to a specific session
    pub async fn send_to_session(&self, session_id: &str, data: Vec<u8>) -> Result<()> {
        if let Some(managed_session) = self.sessions.get(session_id) {
            if managed_session.active {
                managed_session.session.broadcast(data).await?;
                Ok(())
            } else {
                Err(anyhow::anyhow!("Session {} is inactive", session_id))
            }
        } else {
            Err(anyhow::anyhow!("Session {} not found", session_id))
        }
    }

    /// Gets session info including metadata
    pub fn get_session_info(&self, session_id: &str) -> Option<SessionInfo> {
        self.sessions
            .get(session_id)
            .map(|managed_session| SessionInfo {
                id: session_id.to_string(),
                active: managed_session.active,
                created_at: managed_session.created_at,
                topic: *managed_session.session.topic(),
                encryption_key: managed_session.session.encryption_key().to_string(),
            })
    }
}

/// Session information metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub active: bool,
    pub created_at: std::time::SystemTime,
    pub topic: TopicId,
    pub encryption_key: String,
}

/// Event types for P2P communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2pEvent {
    /// Data message
    Data {
        /// The data payload
        data: Vec<u8>,
        /// Optional sender information
        sender: Option<String>,
    },
    /// Control message
    Control {
        /// Control message type
        command: String,
        /// Control message data
        data: Vec<u8>,
    },
    /// Session management event
    Session {
        /// Session event type
        event_type: SessionEventType,
        /// Session data
        data: Vec<u8>,
    },
}

/// Session event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionEventType {
    /// Session joined
    Joined,
    /// Session left
    Left,
    /// Session created
    Created,
    /// Session closed
    Closed,
}

impl P2pSessionManager {
    /// Creates a new session manager with an initial session
    pub fn with_session(session: P2pSession) -> Self {
        let mut manager = Self::new();
        manager.add_session(session);
        manager
    }
}

/// Message types for P2P communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2pMessage {
    /// Binary data message
    Binary(Vec<u8>),
    /// Text message
    Text(String),
    /// Structured message
    Structured {
        /// Message type identifier
        msg_type: String,
        /// Message payload
        payload: Vec<u8>,
    },
}

impl P2pMessage {
    /// Serializes the message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_stdvec(self).context("Failed to serialize P2P message")
    }

    /// Deserializes a message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).context("Failed to deserialize P2P message")
    }
}

