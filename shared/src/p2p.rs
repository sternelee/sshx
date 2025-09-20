//! P2P networking module using iroh for distributed communication.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use iroh::protocol::Router;
use iroh::{Endpoint, NodeId, SecretKey};
use iroh_gossip::{
    api::{Event as GossipEvent, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use n0_future::{boxed::BoxStream, stream::try_unfold, StreamExt};
use tokio::sync::Mutex as TokioMutex;
use tracing::{info, warn};

use crate::{
    events::ClientMessage,
    message::{Message, SignedMessage},
    ticket::SessionTicket,
    Event,
};

/// P2P node for iroh networking using Router pattern from reference
#[derive(Debug)]
pub struct P2pNode {
    secret_key: SecretKey,
    router: Router,
    gossip: Gossip,
}

impl P2pNode {
    /// Creates a new P2P node using Router architecture like reference
    /// implementation
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

    /// Creates a new session with a ticket (same as join_session for
    /// consistency with reference)
    pub async fn create_session(&self, ticket: SessionTicket) -> Result<P2pSession> {
        P2pSession::new(self, ticket).await
    }

    /// Joins an existing session from a ticket
    pub async fn join_session(&self, ticket: SessionTicket) -> Result<P2pSession> {
        P2pSession::new(self, ticket).await
    }

    /// Joins a session following the reference implementation pattern
    pub async fn join(
        &self,
        ticket: &SessionTicket,
        _nickname: String,
    ) -> Result<(P2pSessionSender, BoxStream<Result<crate::Event>>)> {
        let session = P2pSession::new(self, ticket.clone()).await?;
        let (sender, receiver) = session.split();
        Ok((sender, receiver))
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

/// Sender for P2P messages following the ChatSender pattern from reference
#[derive(Debug, Clone)]
pub struct P2pSessionSender {
    secret_key: SecretKey,
    sender: Arc<TokioMutex<GossipSender>>,
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
        let topic = ticket.topic_id;
        let bootstrap = ticket.bootstrap.iter().cloned().collect::<Vec<_>>();

        tracing::info!(
            "Subscribing to topic {} with {} bootstrap nodes: {:?}",
            topic,
            bootstrap.len(),
            bootstrap
        );

        let topic_handle = node
            .gossip
            .subscribe(topic, bootstrap)
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

    /// Returns the session ticket for sharing
    pub fn ticket_with_opts(
        &self,
        opts: &crate::ticket::TicketOpts,
        node_id: NodeId,
    ) -> SessionTicket {
        let mut ticket = self.ticket.clone();
        if opts.include_myself {
            ticket.bootstrap.insert(node_id);
        }
        // Note: include_bootstrap and include_neighbors would require additional state
        // tracking
        ticket
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

    /// Creates a stream of our Event types
    pub fn event_stream(&mut self) -> Option<BoxStream<Result<Event>>> {
        self.receiver.take().map(|receiver| {
            let stream = receiver.map(|event| {
                event
                    .map_err(|e| anyhow::anyhow!("Gossip event error: {}", e))
                    .and_then(|gossip_event| gossip_event.try_into())
                    .map_err(|e| {
                        tracing::error!("Event conversion error: {}", e);
                        e
                    })
            });
            Box::pin(stream) as BoxStream<Result<Event>>
        })
    }

    /// Creates a stream of signed messages using try_unfold pattern like
    /// reference implementation
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

    /// Split the session into sender and receiver following reference pattern
    pub fn split(mut self) -> (P2pSessionSender, BoxStream<Result<Event>>) {
        let sender = P2pSessionSender {
            secret_key: self.secret_key.clone(),
            sender: Arc::new(TokioMutex::new(self.sender.clone())),
        };
        let receiver = if let Some(receiver) = self.receiver.take() {
            let stream = receiver.map(|event| {
                event
                    .map_err(|e| anyhow::anyhow!("Gossip event error: {}", e))
                    .and_then(|gossip_event| gossip_event.try_into())
                    .map_err(|e| {
                        tracing::error!("Event conversion error: {}", e);
                        e
                    })
            });
            Box::pin(stream) as BoxStream<Result<Event>>
        } else {
            Box::pin(n0_future::stream::empty())
        };
        (sender, receiver)
    }
}

impl P2pSessionSender {
    /// Send a message to the P2P network
    pub async fn send(&self, message: Message) -> Result<()> {
        let signed_data = SignedMessage::sign_and_encode(&self.secret_key, message)?;
        self.sender
            .lock()
            .await
            .broadcast(signed_data.into())
            .await
            .context("Failed to broadcast signed message")
    }

    /// Set nickname (placeholder for presence system)
    pub fn set_nickname(&self, _nickname: String) {
        // TODO: Implement presence system like in reference
    }
}

/// Convert GossipEvent to our Event type following reference implementation
impl TryFrom<GossipEvent> for Event {
    type Error = anyhow::Error;

    fn try_from(event: GossipEvent) -> Result<Self, Self::Error> {
        let converted = match event {
            GossipEvent::NeighborUp(node_id) => Self::NeighborUp { node_id },
            GossipEvent::NeighborDown(node_id) => Self::NeighborDown { node_id },
            GossipEvent::Received(message) => {
                let received_msg = SignedMessage::verify_and_decode(&message.content)
                    .context("failed to parse and verify signed message")?;
                match received_msg.message {
                    Message::Presence { nickname } => Self::Presence {
                        from: received_msg.from,
                        nickname,
                        sent_timestamp: received_msg.timestamp,
                    },
                    Message::ClientMessage(client_msg) => {
                        // Convert ClientMessage to text for now
                        let text = serde_json::to_string(&client_msg)
                            .unwrap_or_else(|_| "unknown message".to_string());
                        Self::MessageReceived {
                            from: received_msg.from,
                            text,
                            nickname: "client".to_string(),
                            sent_timestamp: received_msg.timestamp,
                        }
                    }
                    Message::ServerMessage(server_msg) => {
                        // Convert ServerMessage to text for now
                        let text = serde_json::to_string(&server_msg)
                            .unwrap_or_else(|_| "server message".to_string());
                        Self::MessageReceived {
                            from: received_msg.from,
                            text,
                            nickname: "server".to_string(),
                            sent_timestamp: received_msg.timestamp,
                        }
                    }
                    Message::SessionEvent(session_event) => {
                        // Convert SessionEvent to text for now
                        let text = serde_json::to_string(&session_event)
                            .unwrap_or_else(|_| "session event".to_string());
                        Self::MessageReceived {
                            from: received_msg.from,
                            text,
                            nickname: "session".to_string(),
                            sent_timestamp: received_msg.timestamp,
                        }
                    }
                }
            }
            GossipEvent::Lagged => Self::Lagged,
        };
        Ok(converted)
    }
}
