//! P2P networking module using iroh for distributed communication.

use anyhow::{Context, Result};
use iroh::{Endpoint, SecretKey};
use iroh_gossip::{
    api::{Event as GossipEvent, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use n0_future::{boxed::BoxStream, StreamExt};

use crate::{message::SignedMessage, ticket::SessionTicket};

/// P2P node for iroh networking
#[derive(Debug)]
pub struct P2pNode {
    secret_key: SecretKey,
    endpoint: Endpoint,
    gossip: Gossip,
}

impl P2pNode {
    /// Creates a new P2P node
    pub async fn new() -> Result<Self> {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let endpoint = Endpoint::builder()
            .secret_key(secret_key.clone())
            .discovery_n0()
            .alpns(vec![GOSSIP_ALPN.to_vec()])
            .bind()
            .await?;

        tracing::info!("P2P node created with ID: {}", endpoint.node_id());

        let gossip = Gossip::builder().spawn(endpoint.clone());

        Ok(Self {
            secret_key,
            endpoint,
            gossip,
        })
    }

    /// Returns the node ID
    pub fn node_id(&self) -> iroh::NodeId {
        self.endpoint.node_id()
    }

    /// Returns the node address with endpoints
    pub async fn node_addr(&self) -> Result<iroh::NodeAddr> {
        let node_id = self.endpoint.node_id();
        // For now just return node id without direct addresses
        // This can be improved later with proper endpoint discovery
        Ok(iroh::NodeAddr::new(node_id))
    }

    /// Creates a new session with a random topic
    pub async fn create_session(&self, ticket: SessionTicket) -> Result<P2pSession> {
        P2pSession::new(self, ticket).await
    }

    /// Joins an existing session from a ticket
    pub async fn join_session(&self, ticket: SessionTicket) -> Result<P2pSession> {
        P2pSession::new(self, ticket).await
    }

    /// Shutdown the node gracefully
    pub async fn shutdown(self) -> Result<()> {
        self.endpoint.close().await;
        Ok(())
    }
}

/// A P2P session for managing communication over iroh gossip
#[derive(Debug)]
pub struct P2pSession {
    topic: TopicId,
    ticket: SessionTicket,
    sender: GossipSender,
    receiver: Option<GossipReceiver>,
    secret_key: SecretKey,
}

impl Clone for P2pSession {
    fn clone(&self) -> Self {
        Self {
            topic: self.topic,
            ticket: self.ticket.clone(),
            sender: self.sender.clone(),
            receiver: None, // Receiver cannot be cloned
            secret_key: self.secret_key.clone(),
        }
    }
}

impl P2pSession {
    async fn new(node: &P2pNode, ticket: SessionTicket) -> Result<Self> {
        let topic = ticket.topic;
        let node_ids = ticket
            .nodes
            .iter()
            .map(|addr| addr.node_id)
            .collect::<Vec<_>>();

        tracing::info!(
            "Subscribing to topic {} with {} bootstrap nodes: {:?}",
            topic,
            node_ids.len(),
            node_ids
        );

        // If we have bootstrap nodes, establish connections to them first
        for node_addr in &ticket.nodes {
            if node_addr.node_id != node.node_id() {
                tracing::info!(
                    "Attempting to connect to bootstrap node: {}",
                    node_addr.node_id
                );
                // Try to establish direct connection to bootstrap node
                // Note: Direct connections will be established automatically by iroh's discovery
                tracing::info!(
                    "Bootstrap node {} will be discovered automatically",
                    node_addr.node_id
                );
            }
        }

        let topic_handle = node
            .gossip
            .subscribe(topic, node_ids)
            .await
            .context("Failed to subscribe to gossip topic")?;

        let (sender, receiver) = topic_handle.split();

        Ok(Self {
            topic,
            ticket,
            sender,
            receiver: Some(receiver),
            secret_key: node.secret_key.clone(),
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

    /// Broadcasts a signed message to all participants in the session
    pub async fn broadcast_signed(&self, message: crate::message::Message) -> Result<()> {
        let signed_data = SignedMessage::sign_and_encode(&self.secret_key, message)?;
        self.sender
            .broadcast(signed_data.into())
            .await
            .context("Failed to broadcast signed message")
    }

    /// Broadcasts raw data to all participants in the session
    pub async fn broadcast(&self, data: Vec<u8>) -> Result<()> {
        self.sender
            .broadcast(data.into())
            .await
            .context("Failed to broadcast message")
    }

    /// Takes ownership of the receiver
    pub fn take_receiver(&mut self) -> Option<GossipReceiver> {
        self.receiver.take()
    }

    /// Returns a reference to the sender
    pub fn sender(&self) -> &GossipSender {
        &self.sender
    }

    /// Creates a stream of gossip events
    pub fn event_stream(&mut self) -> Option<BoxStream<Result<GossipEvent>>> {
        self.receiver.take().map(|receiver| {
            let stream = receiver
                .map(|event| event.map_err(|e| anyhow::anyhow!("Gossip event error: {}", e)));
            Box::pin(stream) as BoxStream<Result<GossipEvent>>
        })
    }

    /// Creates a stream of signed messages
    pub fn signed_message_stream(&mut self) -> Option<BoxStream<Result<crate::ReceivedMessage>>> {
        self.receiver.take().map(|receiver| {
            let stream = receiver
                .map(|event| {
                    match event {
                        Ok(GossipEvent::Received(msg)) => {
                            // Try to parse and verify the signed message
                            SignedMessage::verify_and_decode(&msg.content).map_err(|e| {
                                anyhow::anyhow!("Failed to parse and verify signed message: {}", e)
                            })
                        }
                        Ok(_) => {
                            // Skip other gossip events for now
                            Err(anyhow::anyhow!("Non-message gossip event"))
                        }
                        Err(e) => Err(anyhow::anyhow!("Gossip event error: {}", e)),
                    }
                })
                .filter_map(|result| {
                    match result {
                        Ok(msg) => Some(Ok(msg)),
                        Err(_) => None, // Filter out errors for now
                    }
                });
            Box::pin(stream) as BoxStream<Result<crate::ReceivedMessage>>
        })
    }
}
