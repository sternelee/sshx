//! Peer-to-peer transport layer using iroh for direct terminal sharing.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::p2p_events::{EventType, SessionHeader, SessionInfo, TerminalEvent};
use crate::p2p_network::{P2PNetwork, SessionTicket, SharedSession};

pub enum P2pMessage {
    Input(String),
    Event(TerminalEvent),
}

/// P2P transport configuration.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    /// Session token used as identifier.
    pub token: String,
    /// Session name for display.
    pub name: String,
    /// Whether this node is the host (original session creator).
    pub is_host: bool,
    /// Optional relay servers for NAT traversal.
    pub relay_servers: Vec<String>,
}

/// P2P transport layer for terminal sharing.
pub struct P2pTransport {
    config: P2pConfig,
    network: P2PNetwork,
    session_id: String,
    topic_id: Option<iroh_gossip::proto::TopicId>,
    input_receiver: Option<mpsc::UnboundedReceiver<String>>,
    event_receiver: Option<tokio::sync::broadcast::Receiver<TerminalEvent>>,
    pub shell_command: String,
}

impl P2pTransport {
    /// Create a new P2P transport with the given configuration.
    pub async fn new(config: P2pConfig, shell_command: String) -> Result<Self> {
        info!("Initializing P2P transport for session: {}", config.name);

        let network = P2PNetwork::new(config.relay_servers.first().cloned()).await?;

        let transport = Self {
            config,
            network,
            session_id: String::new(),
            topic_id: None,
            input_receiver: None,
            event_receiver: None,
            shell_command,
        };

        Ok(transport)
    }

    /// Start the P2P transport and begin listening for messages.
    pub async fn start(&mut self) -> Result<String> {
        info!("Starting P2P transport");

        if self.config.is_host {
            self.start_as_host().await
        } else {
            self.start_as_client().await
        }
    }

    async fn start_as_host(&mut self) -> Result<String> {
        debug!("Starting as host");

        let header = SessionHeader {
            session_id: self.config.token.clone(),
            name: self.config.name.clone(),
            shell: self.shell_command.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };

        let (topic_id, gossip_sender, input_receiver) =
            self.network.create_shared_session(header).await?;

        self.session_id = self.config.token.clone();
        self.topic_id = Some(topic_id);
        self.input_receiver = Some(input_receiver);

        let ticket = self
            .network
            .create_session_ticket(topic_id, &self.session_id)
            .await?;
        let ticket_string = ticket.to_string();

        info!("P2P transport started successfully as host");
        Ok(ticket_string)
    }

    async fn start_as_client(&mut self) -> Result<String> {
        debug!("Starting as client");

        let ticket: SessionTicket = self
            .config
            .token
            .parse()
            .context("Failed to parse session ticket")?;

        let (gossip_sender, event_receiver) = self
            .network
            .join_session(&ticket, &self.config.name)
            .await?;

        self.session_id = format!("p2p-{}", uuid::Uuid::new_v4());
        self.topic_id = Some(ticket.topic_id);
        self.event_receiver = Some(event_receiver);

        info!("P2P transport started successfully as client");
        Ok("Connected to P2P session".to_string())
    }

    /// Send terminal output through P2P.
    pub async fn send_terminal_output(&self, data: String) -> Result<()> {
        if let Some(topic_id) = self.topic_id {
            let sessions = self.network.sessions.read().await;
            if let Some(session) = sessions.get(&self.session_id) {
                if let Some(sender) = &session.gossip_sender {
                    return self
                        .network
                        .send_terminal_output(sender, data, &self.session_id)
                        .await;
                }
            }
        }
        warn!("Cannot send terminal output - not connected");
        Ok(())
    }

    /// Send input through P2P.
    pub async fn send_input(&self, data: String) -> Result<()> {
        if let Some(topic_id) = self.topic_id {
            let sessions = self.network.sessions.read().await;
            if let Some(session) = sessions.get(&self.session_id) {
                if let Some(sender) = &session.gossip_sender {
                    return self
                        .network
                        .send_input(sender, data, &self.session_id)
                        .await;
                }
            }
        }
        warn!("Cannot send input - not connected");
        Ok(())
    }

    /// Send resize event through P2P.
    pub async fn send_resize_event(&self, width: u16, height: u16) -> Result<()> {
        if let Some(topic_id) = self.topic_id {
            let sessions = self.network.sessions.read().await;
            if let Some(session) = sessions.get(&self.session_id) {
                if let Some(sender) = &session.gossip_sender {
                    return self
                        .network
                        .send_resize_event(sender, width, height, &self.session_id)
                        .await;
                }
            }
        }
        warn!("Cannot send resize event - not connected");
        Ok(())
    }

    /// Receive the next input message from P2P.
    pub async fn recv_input(&mut self) -> Option<String> {
        if let Some(receiver) = &mut self.input_receiver {
            receiver.recv().await
        } else {
            None
        }
    }

    /// Receive the next terminal event from P2P.
    pub async fn recv_event(&mut self) -> Option<TerminalEvent> {
        if let Some(receiver) = &mut self.event_receiver {
            receiver.recv().await.ok()
        } else {
            None
        }
    }

    /// Receive either input or event from P2P.
    pub async fn recv_input_or_event(&mut self) -> Option<P2pMessage> {
        tokio::select! {
            // Handle input from the input receiver
            input = async {
                if let Some(ref mut receiver) = self.input_receiver {
                    receiver.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                input.map(P2pMessage::Input)
            }
            // Handle events from the event receiver
            event = async {
                if let Some(ref mut receiver) = self.event_receiver {
                    receiver.recv().await.ok()
                } else {
                    std::future::pending().await
                }
            } => {
                event.map(P2pMessage::Event)
            }
        }
    }

    /// Get the node ID of this transport.
    pub async fn node_id(&self) -> String {
        self.network.get_node_id().await
    }

    /// Create a P2P session URL that others can use to connect.
    pub fn create_session_url(&self, ticket: &str) -> String {
        format!("sshx-p2p://{}", ticket)
    }

    /// Parse a P2P session URL to extract ticket.
    pub fn parse_session_url(url: &str) -> Result<String> {
        if !url.starts_with("sshx-p2p://") {
            return Err(anyhow::anyhow!("Invalid P2P URL scheme"));
        }

        let ticket = &url[12..]; // Remove "sshx-p2p://"
        Ok(ticket.to_string())
    }

    /// Join an existing P2P session using a session URL.
    pub async fn join_session(url: &str, name: &str, shell_command: String) -> Result<Self> {
        let ticket = Self::parse_session_url(url)?;

        let config = P2pConfig {
            token: ticket,
            name: name.to_string(),
            is_host: false,
            relay_servers: vec![],
        };

        Self::new(config, shell_command).await
    }

    /// Get connected session information.
    pub fn is_connected(&self) -> bool {
        self.topic_id.is_some()
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// End the P2P session.
    pub async fn end_session(&self) -> Result<()> {
        if let Some(topic_id) = self.topic_id {
            let sessions = self.network.sessions.read().await;
            if let Some(session) = sessions.get(&self.session_id) {
                if let Some(sender) = &session.gossip_sender {
                    return self
                        .network
                        .end_session(sender, self.session_id.clone())
                        .await;
                }
            }
        }
        warn!("Cannot end session - not connected");
        Ok(())
    }
}

impl Drop for P2pTransport {
    fn drop(&mut self) {
        debug!("P2P transport shutting down");
    }
}

