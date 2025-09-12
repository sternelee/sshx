//! P2P networking module using iroh for distributed communication.

use anyhow::{Context, Result};
use iroh::{Endpoint, SecretKey};
use iroh_gossip::{
    api::{Event as GossipEvent, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use n0_future::{boxed::BoxStream, StreamExt};

use crate::ticket::SessionTicket;

/// P2P node for iroh networking
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
pub struct P2pSession {
    topic: TopicId,
    ticket: SessionTicket,
    sender: GossipSender,
    receiver: Option<GossipReceiver>,
}

impl P2pSession {
    async fn new(node: &P2pNode, ticket: SessionTicket) -> Result<Self> {
        let topic = ticket.topic;
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

    /// Broadcasts a message to all participants in the session
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

    /// Creates a stream of gossip events
    pub fn event_stream(&mut self) -> Option<BoxStream<Result<GossipEvent>>> {
        self.receiver.take().map(|receiver| {
            let stream = receiver
                .map(|event| event.map_err(|e| anyhow::anyhow!("Gossip event error: {}", e)));
            Box::pin(stream) as BoxStream<Result<GossipEvent>>
        })
    }
}
