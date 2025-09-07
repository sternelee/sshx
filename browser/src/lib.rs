use std::{collections::BTreeSet, str::FromStr};

use anyhow::Result;
use futures_lite::StreamExt;
use iroh::protocol::Router;
use iroh::{Endpoint, NodeAddr, SecretKey, Watcher};
use iroh_gossip::{
    api::GossipSender,
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use rand::{rngs::OsRng, RngCore};
use sshx_core::{crypto::rand_alphanumeric, ticket::SessionTicket};
use tracing::level_filters::LevelFilter;
use tracing_subscriber_wasm::MakeConsoleWriter;
use wasm_bindgen::{prelude::wasm_bindgen, JsError, JsValue};
use wasm_streams::ReadableStream;

#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();

    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .with_writer(
            // To avoid trace events in the browser from showing their JS backtrace
            MakeConsoleWriter::default().map_trace_level_to(tracing::Level::DEBUG),
        )
        // If we don't do this in the browser, we get a runtime error.
        .without_time()
        .with_ansi(false)
        .init();

    tracing::info!("SSHX WASM module initialized");
}

/// Node for SSH sessions over iroh-gossip
#[wasm_bindgen]
pub struct SshxNode(SshxNodeInner);

/// Session manager for handling multiple P2P sessions
#[wasm_bindgen]
pub struct SessionManager {
    node: SshxNode,
    sessions: std::collections::HashMap<String, ManagedSession>,
}

struct ManagedSession {
    session: Session,
    active: bool,
    created_at: js_sys::Date,
}

struct SshxNodeInner {
    endpoint: Endpoint,
    gossip: Gossip,
    router: Router,
}

#[wasm_bindgen]
impl SshxNode {
    /// Spawns a gossip node.
    pub async fn spawn() -> Result<Self, JsError> {
        let secret_key = SecretKey::generate(&mut OsRng);

        let endpoint = Endpoint::builder()
            .secret_key(secret_key)
            .discovery_n0()
            .alpns(vec![GOSSIP_ALPN.to_vec()])
            .bind()
            .await
            .map_err(to_js_err)?;

        tracing::info!("our node id: {}", endpoint.node_id());

        let gossip = Gossip::builder().spawn(endpoint.clone());

        let router = Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .spawn();

        let inner = SshxNodeInner {
            endpoint,
            gossip,
            router,
        };
        Ok(Self(inner))
    }

    /// Returns the node id of this node.
    pub fn node_id(&self) -> String {
        self.0.endpoint.node_id().to_string()
    }

    /// Returns information about all the remote nodes this [`Endpoint`] knows about.
    pub fn remote_info(&self) -> Vec<JsValue> {
        self.0
            .endpoint
            .remote_info_iter()
            .map(|info| serde_wasm_bindgen::to_value(&info).unwrap())
            .collect()
    }

    /// Creates a new SSH session.
    pub async fn create(&self) -> Result<Session, JsError> {
        let topic = TopicId::from_bytes({
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            bytes
        });

        let ticket = SessionTicket::new(
            topic,
            vec![self.0.endpoint.node_addr().initialized().await],
            rand_alphanumeric(14), // 83.3 bits of entropy
        );

        self.join_inner(ticket).await
    }

    /// Joins an SSH session from a ticket.
    pub async fn join(&self, ticket: String) -> Result<Session, JsError> {
        let ticket = SessionTicket::from_str(&ticket).map_err(to_js_err)?;
        self.join_inner(ticket).await
    }

    async fn join_inner(&self, ticket: SessionTicket) -> Result<Session, JsError> {
        tracing::info!("Joining session with topic: {}", ticket.topic);
        tracing::debug!("Bootstrap nodes: {:?}", ticket.nodes);

        // Add nodes to address book first
        for node in &ticket.nodes {
            tracing::debug!("Adding node to address book: {}", node.node_id);
            self.0
                .endpoint
                .add_node_addr(node.clone())
                .map_err(to_js_err)?;
        }

        // Subscribe to the topic with bootstrap nodes
        let node_ids = ticket.nodes.iter().map(|p| p.node_id).collect::<Vec<_>>();
        tracing::info!(
            "Subscribing to topic with {} bootstrap nodes",
            node_ids.len()
        );

        let topic_handle = self
            .0
            .gossip
            .subscribe(ticket.topic, node_ids)
            .await
            .map_err(|e| {
                tracing::error!("Failed to subscribe to gossip topic: {}", e);
                to_js_err(e)
            })?;

        tracing::info!("Successfully subscribed to topic");
        let (sender, receiver) = topic_handle.split();

        let receiver = ReadableStream::from_stream(receiver.map(|event| {
            match &event {
                Ok(e) => tracing::debug!("Received gossip event: {:?}", e),
                Err(e) => tracing::error!("Gossip event error: {}", e),
            }
            event
                .map_err(|err| JsValue::from_str(&err.to_string()))
                .map(|event| serde_wasm_bindgen::to_value(&event).unwrap())
        }))
        .into_raw();

        // Add ourselves to the ticket for sharing
        let mut share_ticket_nodes = ticket.nodes.clone();
        let our_addr = self.0.endpoint.node_addr().initialized().await;
        share_ticket_nodes.push(our_addr.clone());

        tracing::info!(
            "Session created successfully with our node: {}",
            our_addr.node_id
        );

        let session = Session {
            topic_id: ticket.topic,
            nodes: share_ticket_nodes.into_iter().collect(),
            encryption_key: ticket.key,
            sender: SessionSender(sender),
            receiver,
        };
        Ok(session)
    }
}

type SessionReceiver = wasm_streams::readable::sys::ReadableStream;

#[wasm_bindgen]
#[derive(Clone)]
pub struct Session {
    topic_id: TopicId,
    nodes: BTreeSet<NodeAddr>,
    encryption_key: String,
    sender: SessionSender,
    receiver: SessionReceiver,
}

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(getter)]
    pub fn sender(&self) -> SessionSender {
        self.sender.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn receiver(&mut self) -> SessionReceiver {
        self.receiver.clone()
    }

    pub fn ticket(&self, include_self: bool) -> Result<String, JsError> {
        let ticket = SessionTicket {
            topic: self.topic_id,
            nodes: if include_self {
                self.nodes.iter().cloned().collect()
            } else {
                // Return nodes excluding ourselves (if we can identify ourselves)
                self.nodes.iter().cloned().collect()
            },
            key: self.encryption_key.clone(),
            write_password: None,
        };
        Ok(ticket.to_string())
    }

    pub fn id(&self) -> String {
        self.topic_id.to_string()
    }

    pub fn encryption_key(&self) -> String {
        self.encryption_key.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct SessionSender(GossipSender);

#[wasm_bindgen]
impl SessionSender {
    pub async fn send(&self, data: Vec<u8>) -> Result<(), JsError> {
        self.0.broadcast(data.into()).await.map_err(to_js_err)?;
        Ok(())
    }
}

#[wasm_bindgen]
impl SessionManager {
    /// Creates a new session manager.
    pub async fn new() -> Result<SessionManager, JsError> {
        let node = SshxNode::spawn().await?;
        Ok(SessionManager {
            node,
            sessions: std::collections::HashMap::new(),
        })
    }

    /// Creates a new session and adds it to the manager.
    pub async fn create_session(&mut self) -> Result<String, JsError> {
        let session = self.node.create().await?;
        let session_id = session.id();
        let managed_session = ManagedSession {
            session,
            active: true,
            created_at: js_sys::Date::new_0(),
        };
        self.sessions.insert(session_id.clone(), managed_session);
        Ok(session_id)
    }

    /// Joins an existing session and adds it to the manager.
    pub async fn join_session(&mut self, ticket: String) -> Result<String, JsError> {
        let session = self.node.join(ticket.clone()).await?;
        let session_id = session.id();
        let managed_session = ManagedSession {
            session,
            active: true,
            created_at: js_sys::Date::new_0(),
        };
        self.sessions.insert(session_id.clone(), managed_session);
        Ok(session_id)
    }

    /// Gets a session by ID.
    pub fn get_session(&self, session_id: String) -> Result<Session, JsError> {
        self.sessions
            .get(&session_id)
            .and_then(|ms| if ms.active { Some(&ms.session) } else { None })
            .cloned()
            .ok_or_else(|| JsError::new(&format!("Session {} not found or inactive", session_id)))
    }

    /// Lists all active session IDs.
    pub fn list_sessions(&self) -> Result<js_sys::Array, JsError> {
        let sessions = js_sys::Array::new();
        for (session_id, managed_session) in self.sessions.iter() {
            if managed_session.active {
                sessions.push(&JsValue::from_str(session_id));
            }
        }
        Ok(sessions)
    }

    /// Removes a session from the manager.
    pub fn remove_session(&mut self, session_id: String) -> Result<bool, JsError> {
        if let Some(managed_session) = self.sessions.get_mut(&session_id) {
            managed_session.active = false;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Gets session info including metadata.
    pub fn get_session_info(&self, session_id: String) -> Result<JsValue, JsError> {
        if let Some(managed_session) = self.sessions.get(&session_id) {
            let info = js_sys::Object::new();
            js_sys_to_js_err(js_sys::Reflect::set(
                &info,
                &JsValue::from_str("id"),
                &JsValue::from_str(&session_id),
            ))?;
            js_sys_to_js_err(js_sys::Reflect::set(
                &info,
                &JsValue::from_str("active"),
                &JsValue::from_bool(managed_session.active),
            ))?;
            js_sys_to_js_err(js_sys::Reflect::set(
                &info,
                &JsValue::from_str("createdAt"),
                &managed_session.created_at.clone().into(),
            ))?;
            js_sys_to_js_err(js_sys::Reflect::set(
                &info,
                &JsValue::from_str("ticket"),
                &JsValue::from_str(&managed_session.session.ticket(true)?),
            ))?;
            Ok(info.into())
        } else {
            Err(JsError::new(&format!("Session {} not found", session_id)))
        }
    }

    /// Broadcasts a message to all active sessions.
    pub async fn broadcast_to_all(&self, data: Vec<u8>) -> Result<(), JsError> {
        let mut results = Vec::new();
        for managed_session in self.sessions.values() {
            if managed_session.active {
                let result = managed_session.session.sender().send(data.clone()).await;
                results.push(result);
            }
        }

        // Check if any broadcasts failed
        for result in results {
            result?;
        }
        Ok(())
    }

    /// Sends a message to a specific session.
    pub async fn send_to_session(&self, session_id: String, data: Vec<u8>) -> Result<(), JsError> {
        if let Some(managed_session) = self.sessions.get(&session_id) {
            if managed_session.active {
                managed_session.session.sender().send(data).await?;
                Ok(())
            } else {
                Err(JsError::new(&format!("Session {} is inactive", session_id)))
            }
        } else {
            Err(JsError::new(&format!("Session {} not found", session_id)))
        }
    }
}

fn to_js_err(err: impl Into<anyhow::Error>) -> JsError {
    let err: anyhow::Error = err.into();
    JsError::new(&err.to_string())
}

fn js_sys_to_js_err(result: Result<bool, JsValue>) -> Result<(), JsError> {
    result
        .map_err(|e| JsError::new(&e.as_string().unwrap_or_else(|| "Unknown error".to_string())))?;
    Ok(())
}
