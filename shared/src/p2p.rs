//! P2P networking module using iroh for distributed communication.

use anyhow::{Context, Result};
use iroh::protocol::Router;
use iroh::{Endpoint, SecretKey};
use iroh_gossip::{
    api::{Event as GossipEvent, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use n0_future::{boxed::BoxStream, stream::try_unfold, StreamExt};
use tracing::{info, warn};

use crate::{message::SignedMessage, ticket::SessionTicket};

/// P2P node for iroh networking using Router pattern from reference
#[derive(Debug)]
pub struct P2pNode {
    secret_key: SecretKey,
    router: Router,
    gossip: Gossip,
}

impl P2pNode {
    /// Creates a new P2P node using Router architecture like reference implementation
    pub async fn new() -> Result<Self> {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let endpoint = Endpoint::builder()
            .secret_key(secret_key.clone())
            .alpns(vec![GOSSIP_ALPN.to_vec()])
            .bind()
            .await?;

        let node_id = endpoint.node_id();
        info!("endpoint bound");
        info!("node id: {node_id:#?}");

        let gossip = Gossip::builder().spawn(endpoint.clone());
        info!("gossip spawned");

        let router = Router::builder(endpoint)
            .accept(GOSSIP_ALPN, gossip.clone())
            .spawn();
        info!("router spawned");

        Ok(Self {
            secret_key,
            router,
            gossip,
        })
    }

    /// Returns the node ID
    pub fn node_id(&self) -> iroh::NodeId {
        self.router.endpoint().node_id()
    }

    /// Returns the node address with endpoints
    pub async fn node_addr(&self) -> Result<iroh::NodeAddr> {
        let node_id = self.router.endpoint().node_id();
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

    /// Shutdown the node gracefully like in reference implementation
    pub async fn shutdown(self) -> Result<()> {
        if let Err(err) = self.router.shutdown().await {
            warn!("failed to shutdown router cleanly: {err}");
        }
        self.router.endpoint().close().await;
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

    /// Creates a stream of signed messages using try_unfold pattern like reference implementation
    pub fn signed_message_stream(&mut self) -> Option<BoxStream<Result<crate::ReceivedMessage>>> {
        self.receiver.take().map(|receiver| {
            // Use the try_unfold pattern from browser-chat.txt reference
            let stream = try_unfold(receiver, |mut receiver| async move {
                loop {
                    // Fetch the next event
                    let Some(event) = receiver.try_next().await? else {
                        return Ok(None);
                    };

                    // Convert into our event type. This fails if we receive a message
                    // that cannot be decoded into our event type. If that is the case,
                    // we just keep and log the error.
                    match event {
                        GossipEvent::Received(msg) => {
                            match SignedMessage::verify_and_decode(&msg.content) {
                                Ok(received_msg) => {
                                    break Ok(Some((received_msg, receiver)));
                                }
                                Err(err) => {
                                    warn!("received invalid message: {err}");
                                    continue;
                                }
                            }
                        }
                        _ => {
                            // Skip other gossip events (NeighborUp, NeighborDown, etc.)
                            continue;
                        }
                    }
                }
            });
            Box::pin(stream) as BoxStream<Result<crate::ReceivedMessage>>
        })
    }
}
