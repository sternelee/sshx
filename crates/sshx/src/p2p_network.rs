//! P2P network layer using iroh for terminal sharing

use aead::{Aead, KeyInit};
use anyhow::Result;
use bincode;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use futures::StreamExt;
use iroh::{protocol::Router, Endpoint, NodeAddr, NodeId, Watcher};
use iroh_gossip::{
    api::{Event, GossipReceiver, GossipSender},
    net::Gossip,
    proto::TopicId,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::p2p_events::{EventType, SessionHeader, SessionInfo, TerminalEvent};
use crate::string_compressor::StringCompressor;

pub type EncryptionKey = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTicket {
    pub topic_id: TopicId,
    pub nodes: Vec<NodeAddr>,
    pub key: EncryptionKey,
}

impl std::fmt::Display for SessionTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = bincode::serialize(self).map_err(|_| std::fmt::Error)?;
        let base32_string = data_encoding::BASE32.encode(&bytes);

        match StringCompressor::compress_hybrid(&base32_string) {
            Ok(compressed) => {
                write!(f, "CT_{}", compressed)
            }
            Err(_) => {
                write!(f, "{}", base32_string)
            }
        }
    }
}

impl std::str::FromStr for SessionTicket {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cleaned = s.trim().replace([' ', '\n', '\r', '\t'], "");

        if cleaned.is_empty() {
            return Err(anyhow::anyhow!("Empty ticket"));
        }

        let base32_string = if cleaned.starts_with("CT_") {
            let compressed_part = &cleaned[3..];
            StringCompressor::decompress(compressed_part)
                .map_err(|e| anyhow::anyhow!("Failed to decompress ticket: {}", e))?
        } else {
            cleaned
        };

        if !base32_string
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c) || c == '=')
        {
            return Err(anyhow::anyhow!(
                "Invalid BASE32 characters in ticket. Only A-Z, 2-7, and = are allowed"
            ));
        }

        let bytes = data_encoding::BASE32
            .decode(base32_string.as_bytes())
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to decode ticket (length: {}): {}",
                    base32_string.len(),
                    e
                )
            })?;

        if bytes.len() < 32 {
            return Err(anyhow::anyhow!(
                "Decoded ticket too short: {} bytes",
                bytes.len()
            ));
        }

        let ticket: SessionTicket = bincode::deserialize(&bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize ticket: {}", e))?;
        Ok(ticket)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TerminalMessageBody {
    SessionInfo {
        from: NodeId,
        header: SessionHeader,
    },
    Output {
        from: NodeId,
        data: String,
        timestamp: u64,
    },
    Input {
        from: NodeId,
        data: String,
        timestamp: u64,
    },
    Resize {
        from: NodeId,
        width: u16,
        height: u16,
        timestamp: u64,
    },
    SessionEnd {
        from: NodeId,
        timestamp: u64,
    },
    ParticipantJoined {
        from: NodeId,
        timestamp: u64,
    },
    HistoryData {
        from: NodeId,
        session_info: SessionInfo,
        timestamp: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTerminalMessage {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedTerminalMessage {
    pub fn new(body: TerminalMessageBody, key: &EncryptionKey) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = bincode::serialize(&body)?;
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(Self {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    pub fn decrypt(&self, key: &EncryptionKey) -> Result<TerminalMessageBody> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(&self.nonce);

        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        let body: TerminalMessageBody = bincode::deserialize(&plaintext)?;
        Ok(body)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }
}

#[derive(Debug)]
pub struct SharedSession {
    pub header: SessionHeader,
    pub participants: Vec<String>,
    pub is_host: bool,
    pub event_sender: broadcast::Sender<TerminalEvent>,
    pub input_sender: Option<mpsc::UnboundedSender<String>>,
    pub key: EncryptionKey,
    pub gossip_sender: Option<GossipSender>,
}

pub struct P2PNetwork {
    endpoint: Endpoint,
    gossip: Gossip,
    router: Router,
    pub sessions: Arc<RwLock<HashMap<String, SharedSession>>>,
    history_callback: Arc<
        RwLock<
            Option<
                Box<
                    dyn Fn(&str) -> tokio::sync::oneshot::Receiver<Option<SessionInfo>>
                        + Send
                        + Sync,
                >,
            >,
        >,
    >,
}

impl Clone for P2PNetwork {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            gossip: self.gossip.clone(),
            router: self.router.clone(),
            sessions: self.sessions.clone(),
            history_callback: self.history_callback.clone(),
        }
    }
}

impl P2PNetwork {
    pub async fn new(relay_url: Option<String>) -> Result<Self> {
        debug!("Initializing iroh P2P network with gossip...");

        let endpoint_builder = Endpoint::builder();
        let endpoint = if let Some(relay) = relay_url {
            debug!("Using custom relay server: {}", relay);
            let _relay_url: url::Url = relay.parse()?;
            endpoint_builder.discovery_n0().bind().await?
        } else {
            debug!("Using default n0 relay server");
            endpoint_builder.discovery_n0().bind().await?
        };

        let _node_id = endpoint.node_id();
        debug!("Node ID: {}", _node_id);

        let gossip = Gossip::builder().spawn(endpoint.clone());

        let router = Router::builder(endpoint.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();

        let network = Self {
            endpoint,
            gossip,
            router,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            history_callback: Arc::new(RwLock::new(None)),
        };

        Ok(network)
    }

    pub async fn create_shared_session(
        &self,
        header: SessionHeader,
    ) -> Result<(TopicId, GossipSender, mpsc::UnboundedReceiver<String>)> {
        let session_id = header.session_id.clone();
        debug!("Creating shared session");

        let topic_id = TopicId::from_bytes(rand::random());
        let key: EncryptionKey = rand::random();

        let (event_sender, _event_receiver) = broadcast::channel(1000);
        let (input_sender, input_receiver) = mpsc::unbounded_channel();

        let topic = self.gossip.subscribe(topic_id, vec![]).await?;
        let (sender, receiver) = topic.split();

        let session = SharedSession {
            header: header.clone(),
            participants: vec![self.endpoint.node_id().to_string()],
            is_host: true,
            event_sender: event_sender.clone(),
            input_sender: Some(input_sender),
            key,
            gossip_sender: Some(sender.clone()),
        };

        self.sessions
            .write()
            .await
            .insert(session_id.clone(), session);

        self.start_topic_listener(receiver, session_id).await?;

        let body = TerminalMessageBody::SessionInfo {
            from: self.endpoint.node_id(),
            header,
        };
        let message = EncryptedTerminalMessage::new(body, &key)?;
        sender.broadcast(message.to_vec()?.into()).await?;

        Ok((topic_id, sender, input_receiver))
    }

    pub async fn send_terminal_output(
        &self,
        sender: &GossipSender,
        data: String,
        session_id: &str,
    ) -> Result<()> {
        debug!("Sending terminal output length={}", data.len());
        if data.is_empty() {
            return Ok(());
        }

        let key = self.get_session_key(session_id).await?;
        let body = TerminalMessageBody::Output {
            from: self.endpoint.node_id(),
            data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        let message = EncryptedTerminalMessage::new(body, &key)?;
        sender.broadcast(message.to_vec()?.into()).await?;
        Ok(())
    }

    pub async fn send_input(
        &self,
        sender: &GossipSender,
        data: String,
        session_id: &str,
    ) -> Result<()> {
        debug!("Sending input data: {:?} (len={})", data, data.len());
        if data.is_empty() {
            return Ok(());
        }

        let key = self.get_session_key(session_id).await?;
        let body = TerminalMessageBody::Input {
            from: self.endpoint.node_id(),
            data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        let message = EncryptedTerminalMessage::new(body, &key)?;
        sender.broadcast(message.to_vec()?.into()).await?;
        Ok(())
    }

    pub async fn send_resize_event(
        &self,
        sender: &GossipSender,
        width: u16,
        height: u16,
        session_id: &str,
    ) -> Result<()> {
        debug!("Sending resize event");
        let key = self.get_session_key(session_id).await?;
        let body = TerminalMessageBody::Resize {
            from: self.endpoint.node_id(),
            width,
            height,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        let message = EncryptedTerminalMessage::new(body, &key)?;
        sender.broadcast(message.to_vec()?.into()).await?;
        Ok(())
    }

    pub async fn send_history_data(
        &self,
        sender: &GossipSender,
        session_info: SessionInfo,
        session_id: &str,
    ) -> Result<()> {
        debug!(
            "Sending history data: {} logs, shell: {}, cwd: {}",
            session_info.logs.len(),
            session_info.shell,
            session_info.cwd
        );
        let key = self.get_session_key(session_id).await?;
        let body = TerminalMessageBody::HistoryData {
            from: self.endpoint.node_id(),
            session_info,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        let message = EncryptedTerminalMessage::new(body, &key)?;
        sender.broadcast(message.to_vec()?.into()).await?;
        Ok(())
    }

    pub async fn end_session(&self, sender: &GossipSender, session_id: String) -> Result<()> {
        debug!("Ending session: {}", session_id);

        let key = self.get_session_key(&session_id).await?;

        let body = TerminalMessageBody::SessionEnd {
            from: self.endpoint.node_id(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        let message = EncryptedTerminalMessage::new(body, &key)?;
        sender.broadcast(message.to_vec()?.into()).await?;

        {
            let mut sessions = self.sessions.write().await;
            sessions.remove(&session_id);
        }

        Ok(())
    }

    async fn start_topic_listener(
        &self,
        mut receiver: GossipReceiver,
        session_id: String,
    ) -> Result<()> {
        let network_clone = self.clone();

        tokio::spawn(async move {
            debug!("Starting gossip message listener");

            loop {
                match receiver.next().await {
                    Some(Ok(Event::Received(msg))) => {
                        debug!("Received gossip message: {} bytes", msg.content.len());

                        match EncryptedTerminalMessage::from_bytes(&msg.content) {
                            Ok(encrypted_msg) => {
                                let sessions_guard = network_clone.sessions.read().await;
                                if let Some(session) = sessions_guard.get(&session_id) {
                                    let key = session.key;
                                    drop(sessions_guard);

                                    match encrypted_msg.decrypt(&key) {
                                        Ok(body) => {
                                            if let Err(e) = network_clone
                                                .handle_gossip_message(&session_id, body)
                                                .await
                                            {
                                                error!("Failed to handle gossip message: {}", e);
                                            }
                                        }
                                        Err(e) => error!("Failed to decrypt message: {}", e),
                                    }
                                } else {
                                    warn!("Session not found for incoming message");
                                }
                            }
                            Err(e) => error!("Failed to deserialize encrypted message: {}", e),
                        }
                    }
                    Some(Ok(Event::NeighborUp(peer_id))) => {
                        debug!(
                            "Peer connected: {} to session {}",
                            peer_id.fmt_short(),
                            session_id
                        );
                    }
                    Some(Ok(Event::NeighborDown(peer_id))) => {
                        debug!(
                            "Peer disconnected: {} from session {}",
                            peer_id.fmt_short(),
                            session_id
                        );
                    }
                    Some(Ok(Event::Lagged)) => {
                        warn!(
                            "Gossip topic is lagged for session {} (events may have been missed)",
                            session_id
                        );
                    }
                    Some(Err(e)) => {
                        error!("Error in gossip receiver for session {}: {}", session_id, e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                    None => {
                        warn!("Gossip receiver stream ended for session {}", session_id);
                        break;
                    }
                }
            }

            debug!("Gossip listener for session {} has ended", session_id);
        });

        Ok(())
    }

    async fn handle_gossip_message(
        &self,
        session_id: &str,
        body: TerminalMessageBody,
    ) -> Result<()> {
        let sessions_guard = self.sessions.read().await;
        if let Some(session) = sessions_guard.get(session_id) {
            match body {
                TerminalMessageBody::Output {
                    from: _,
                    data,
                    timestamp,
                } => {
                    let event = TerminalEvent {
                        timestamp: timestamp as f64,
                        event_type: EventType::Output,
                        data,
                    };
                    if let Err(_e) = session.event_sender.send(event) {
                        warn!("Failed to send output event to subscribers");
                    }
                }
                TerminalMessageBody::Input {
                    from,
                    data,
                    timestamp,
                } => {
                    debug!("Received input event from {}: {:?}", from.fmt_short(), data);
                    let event = TerminalEvent {
                        timestamp: timestamp as f64,
                        event_type: EventType::Input,
                        data: data.clone(),
                    };

                    if session.is_host {
                        if let Some(input_sender) = &session.input_sender {
                            if input_sender.send(data).is_err() {
                                warn!("Failed to send input to terminal");
                            }
                        }
                    }
                    if session.event_sender.send(event).is_err() {
                        warn!("Failed to broadcast input event");
                    }
                }
                TerminalMessageBody::Resize {
                    from: _,
                    width,
                    height,
                    timestamp,
                } => {
                    let event = TerminalEvent {
                        timestamp: timestamp as f64,
                        event_type: EventType::Resize { width, height },
                        data: format!("{}x{}", width, height),
                    };
                    if let Err(_e) = session.event_sender.send(event) {
                        warn!("Failed to send resize event to subscribers");
                    }
                }
                TerminalMessageBody::SessionEnd { from: _, timestamp } => {
                    let event = TerminalEvent {
                        timestamp: timestamp as f64,
                        event_type: EventType::End,
                        data: "Session ended".to_string(),
                    };
                    if let Err(_e) = session.event_sender.send(event) {
                        warn!("Failed to send end event to subscribers");
                    }
                }
                TerminalMessageBody::SessionInfo { from, header: _ } => {
                    debug!(
                        "Received session info from {} for session: {}",
                        from.fmt_short(),
                        session_id
                    );
                }
                TerminalMessageBody::ParticipantJoined { from, timestamp: _ } => {
                    debug!(
                        "New participant {} joined session {}",
                        from.fmt_short(),
                        session_id
                    );

                    if session.is_host {
                        debug!("We are the host, attempting to send history data");

                        let gossip_sender = session.gossip_sender.clone();
                        drop(sessions_guard);

                        if let Some(sender) = gossip_sender {
                            let callback = {
                                let history_callback_guard = self.history_callback.read().await;
                                history_callback_guard.as_ref().map(|cb| cb(session_id))
                            };

                            if let Some(receiver) = callback {
                                let network_clone = self.clone();
                                let session_id_clone = session_id.to_string();

                                tokio::spawn(async move {
                                    match receiver.await {
                                        Ok(Some(session_info)) => {
                                            debug!("Got history data, sending to new participant");

                                            if let Err(e) = network_clone
                                                .send_history_data(
                                                    &sender,
                                                    session_info,
                                                    &session_id_clone,
                                                )
                                                .await
                                            {
                                                error!("Failed to send history data: {}", e);
                                            } else {
                                                debug!(
                                                    "✅ Successfully sent history data to new participant"
                                                );
                                            }
                                        }
                                        Ok(None) => {
                                            debug!("No history data available to send");
                                        }
                                        Err(_e) => {
                                            error!("Failed to get history data");
                                        }
                                    }
                                });
                            } else {
                                warn!("No history callback set, cannot send history data");
                            }
                        } else {
                            warn!("No gossip sender available for sending history data");
                        }
                    }
                }
                TerminalMessageBody::HistoryData {
                    from,
                    session_info,
                    timestamp: _,
                } => {
                    debug!(
                        "Received history data from {}: {} logs, shell: {}, cwd: {}",
                        from.fmt_short(),
                        session_info.logs.len(),
                        session_info.shell,
                        session_info.cwd
                    );

                    let event = TerminalEvent {
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as f64,
                        event_type: EventType::Output,
                        data: format!(
                            "\r\n📜 Session History (Shell: {}, CWD: {})\r\n{}\r\n--- End of History ---\r\n",
                            session_info.shell, session_info.cwd, session_info.logs.join("\n")
                        ),
                    };

                    if let Err(_e) = session.event_sender.send(event) {
                        warn!("Failed to send history event to subscribers");
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn get_node_id(&self) -> String {
        self.endpoint.node_id().to_string()
    }

    pub async fn get_node_addr(&self) -> Result<NodeAddr> {
        debug!("Getting node address...");
        let watcher = self.endpoint.node_addr();
        let mut stream = watcher.stream();
        let node_addr = stream
            .next()
            .await
            .flatten()
            .ok_or_else(|| anyhow::anyhow!("Node address not available from watcher"))?;
        debug!("Got node address: {:?}", node_addr);
        Ok(node_addr)
    }

    pub async fn connect_to_peer(&self, node_addr: NodeAddr) -> Result<()> {
        debug!("Connecting to peer: {}", node_addr.node_id);

        self.endpoint.add_node_addr(node_addr.clone())?;
        debug!("Successfully added peer {} to endpoint", node_addr.node_id);

        Ok(())
    }

    pub async fn create_session_ticket(
        &self,
        topic_id: TopicId,
        session_id: &str,
    ) -> Result<SessionTicket> {
        let me = self.get_node_addr().await?;
        let nodes = vec![me];

        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

        Ok(SessionTicket {
            topic_id,
            nodes,
            key: session.key,
        })
    }

    pub async fn join_session(
        &self,
        ticket: &SessionTicket,
        name: &str,
    ) -> Result<(GossipSender, broadcast::Receiver<TerminalEvent>)> {
        debug!("Joining session with topic: {:?}", ticket.topic_id);

        let session_id = format!("p2p-{}", uuid::Uuid::new_v4());

        let (event_sender, event_receiver) = broadcast::channel(1000);

        let session = SharedSession {
            header: SessionHeader {
                session_id: session_id.clone(),
                name: name.to_string(),
                shell: "unknown".to_string(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            },
            participants: vec![],
            is_host: false,
            event_sender: event_sender.clone(),
            input_sender: None,
            key: ticket.key,
            gossip_sender: None,
        };

        self.sessions
            .write()
            .await
            .insert(session_id.clone(), session);

        for node_addr in &ticket.nodes {
            if let Err(e) = self.connect_to_peer(node_addr.clone()).await {
                warn!("Failed to connect to peer {}: {}", node_addr.node_id, e);
            }
        }

        let public_keys: Vec<iroh::PublicKey> =
            ticket.nodes.iter().map(|node| node.node_id).collect();
        let topic = self.gossip.subscribe(ticket.topic_id, public_keys).await?;
        let (sender, receiver) = topic.split();

        self.start_topic_listener(receiver, session_id).await?;

        let body = TerminalMessageBody::ParticipantJoined {
            from: self.endpoint.node_id(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        let message = EncryptedTerminalMessage::new(body, &ticket.key)?;
        sender.broadcast(message.to_vec()?.into()).await?;

        Ok((sender, event_receiver))
    }

    async fn get_session_key(&self, session_id: &str) -> Result<EncryptionKey> {
        let key = {
            let sessions = self.sessions.read().await;
            sessions.get(session_id).map(|s| s.key)
        };

        key.ok_or_else(|| anyhow::anyhow!("Session not found"))
    }

    pub async fn set_history_callback<F>(&self, callback: F)
    where
        F: Fn(&str) -> tokio::sync::oneshot::Receiver<Option<SessionInfo>> + Send + Sync + 'static,
    {
        let mut history_callback = self.history_callback.write().await;
        *history_callback = Some(Box::new(callback));
    }
}

