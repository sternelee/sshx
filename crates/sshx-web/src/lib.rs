use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use data_encoding::BASE32_NOPAD;
use futures_lite::StreamExt;
use iroh::protocol::Router;
use iroh::{Endpoint, NodeAddr, SecretKey, Watcher};
use iroh_gossip::{
    api::{Event, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use n0_future::{time::Duration, StreamExt as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sshx_core::{rand_alphanumeric, Sid};
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

/// A ticket that contains the necessary information to join a session.
#[derive(Debug, Serialize, Deserialize)]
struct Ticket {
    /// The gossip topic to join.
    topic: TopicId,
    /// The node addresses of the host.
    nodes: Vec<NodeAddr>,
    /// The encryption key for the session.
    key: String,
}

impl Ticket {
    /// Deserialize from a slice of bytes to a Ticket.
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(Into::into)
    }

    /// Serialize from a `Ticket` to a `Vec` of bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serde_json::to_vec is infallible")
    }
}

impl std::fmt::Display for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut text = BASE32_NOPAD.encode(&self.to_bytes()[..]);
        text.make_ascii_lowercase();
        write!(f, "{}", text)
    }
}

impl std::str::FromStr for Ticket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.split(',').next().unwrap_or(s); // Ignore write password for now
        let bytes = BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        Self::from_bytes(&bytes)
    }
}

/// Node for SSH sessions over iroh-gossip
#[wasm_bindgen]
pub struct SshxNode(SshxNodeInner);

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

        let ticket = Ticket {
            topic,
            nodes: vec![self.0.endpoint.node_addr().initialized().await],
            key: rand_alphanumeric(14), // 83.3 bits of entropy
        };

        self.join_inner(ticket).await
    }

    /// Joins an SSH session from a ticket.
    pub async fn join(&self, ticket: String) -> Result<Session, JsError> {
        let ticket = Ticket::from_str(&ticket).map_err(to_js_err)?;
        self.join_inner(ticket).await
    }

    async fn join_inner(&self, ticket: Ticket) -> Result<Session, JsError> {
        // Add nodes to address book
        for node in &ticket.nodes {
            self.0
                .endpoint
                .add_node_addr(node.clone())
                .map_err(to_js_err)?;
        }

        let node_ids = ticket.nodes.iter().map(|p| p.node_id).collect();
        let (sender, receiver) = self
            .0
            .gossip
            .subscribe_and_join(ticket.topic, node_ids)
            .await
            .map_err(to_js_err)?
            .split();

        let receiver = ReadableStream::from_stream(receiver.map(|event| {
            event
                .map_err(|err| JsValue::from_str(&err.to_string()))
                .map(|event| serde_wasm_bindgen::to_value(&event).unwrap())
        }))
        .into_raw();

        // Add ourselves to the ticket for sharing
        let mut share_ticket = ticket;
        share_ticket
            .nodes
            .push(self.0.endpoint.node_addr().initialized().await);

        let session = Session {
            topic_id: share_ticket.topic,
            nodes: share_ticket.nodes.into_iter().collect(),
            encryption_key: share_ticket.key,
            sender: SessionSender(sender),
            receiver,
        };
        Ok(session)
    }
}

type SessionReceiver = wasm_streams::readable::sys::ReadableStream;

#[wasm_bindgen]
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
        let mut ticket = Ticket {
            topic: self.topic_id,
            nodes: if include_self {
                self.nodes.iter().cloned().collect()
            } else {
                // Return nodes excluding ourselves (if we can identify ourselves)
                self.nodes.iter().cloned().collect()
            },
            key: self.encryption_key.clone(),
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
    pub async fn send(&self, data: &[u8]) -> Result<(), JsError> {
        self.0.broadcast(data.into()).await.map_err(to_js_err)?;
        Ok(())
    }
}

fn to_js_err(err: impl Into<anyhow::Error>) -> JsError {
    let err: anyhow::Error = err.into();
    JsError::new(&err.to_string())
}
