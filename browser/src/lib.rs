use std::str::FromStr;

use anyhow::Result;
use futures_lite::StreamExt;
use sshx_core::{
    p2p::{P2pConfig, P2pNode, P2pSession, P2pSessionManager},
    ticket::SessionTicket,
};
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

/// Node for SSH sessions over P2P networking
#[wasm_bindgen]
pub struct SshxNode(P2pNode);

/// Session manager for handling multiple P2P sessions
#[wasm_bindgen]
pub struct SessionManager {
    p2p_manager: P2pSessionManager,
    node: SshxNode,
}

#[wasm_bindgen]
impl SshxNode {
    /// Spawns a P2P node.
    pub async fn spawn() -> Result<Self, JsError> {
        let p2p_config = P2pConfig {
            relay_url: None,
            prefer_ipv4: true,
            debug: true,
        };

        let node = P2pNode::new(p2p_config).await.map_err(to_js_err)?;

        tracing::info!("our node id: {}", node.node_id());

        Ok(Self(node))
    }

    /// Returns the node id of this node.
    pub fn node_id(&self) -> String {
        self.0.node_id().to_string()
    }

    /// Returns information about all the remote nodes this node knows about.
    pub fn remote_info(&self) -> Vec<JsValue> {
        // This would need to be implemented in the P2pNode
        // For now, return empty vector
        Vec::new()
    }

    /// Creates a new SSH session.
    pub async fn create(&self) -> Result<Session, JsError> {
        let p2p_session = self.0.create_session().await.map_err(to_js_err)?;

        Session::from_p2p_session(p2p_session).await
    }

    /// Joins an SSH session from a ticket.
    pub async fn join(&self, ticket: String) -> Result<Session, JsError> {
        let ticket = SessionTicket::from_str(&ticket).map_err(to_js_err)?;
        let p2p_session = self.0.join_session(ticket).await.map_err(to_js_err)?;

        Session::from_p2p_session(p2p_session).await
    }
}

type SessionReceiver = wasm_streams::readable::sys::ReadableStream;

#[wasm_bindgen]
pub struct Session {
    inner: P2pSession,
    receiver: Option<SessionReceiver>,
}

impl Session {
    async fn from_p2p_session(mut p2p_session: P2pSession) -> Result<Self, JsError> {
        let receiver = p2p_session.take_receiver().map(|receiver| {
            ReadableStream::from_stream(receiver.map(|event| {
                match &event {
                    Ok(e) => tracing::debug!("Received P2P event: {:?}", e),
                    Err(e) => tracing::error!("P2P event error: {}", e),
                }
                event
                    .map_err(|err| JsValue::from_str(&err.to_string()))
                    .map(|event| serde_wasm_bindgen::to_value(&event).unwrap())
            }))
            .into_raw()
        });

        Ok(Self {
            inner: p2p_session,
            receiver,
        })
    }
}

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(getter)]
    pub fn sender(&self) -> SessionSender {
        SessionSender(self.inner.sender().clone())
    }

    #[wasm_bindgen(getter)]
    pub fn receiver(&mut self) -> Option<SessionReceiver> {
        self.receiver.take()
    }

    pub fn ticket(&self, _include_self: bool) -> Result<String, JsError> {
        // For now, we'll just return the ticket as-is
        // In a real implementation, you might want to modify it based on include_self
        Ok(self.inner.ticket().to_string())
    }

    pub fn id(&self) -> String {
        self.inner.topic().to_string()
    }

    pub fn encryption_key(&self) -> String {
        self.inner.encryption_key().to_string()
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct SessionSender(iroh_gossip::api::GossipSender);

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
        let p2p_manager = P2pSessionManager::new();
        Ok(SessionManager { node, p2p_manager })
    }

    /// Creates a new session and adds it to the manager.
    pub async fn create_session(&mut self) -> Result<String, JsError> {
        let p2p_session = self.node.0.create_session().await.map_err(to_js_err)?;
        let session_id = self.p2p_manager.add_session(p2p_session);
        Ok(session_id)
    }

    /// Joins an existing session and adds it to the manager.
    pub async fn join_session(&mut self, ticket: String) -> Result<String, JsError> {
        let ticket = SessionTicket::from_str(&ticket).map_err(to_js_err)?;
        let p2p_session = self.node.0.join_session(ticket).await.map_err(to_js_err)?;
        let session_id = self.p2p_manager.add_session(p2p_session);
        Ok(session_id)
    }

    /// Gets a session by ID.
    pub fn get_session(&self, _session_id: String) -> Result<Session, JsError> {
        // For now, return an error since P2pSession is not cloneable
        // In a real implementation, you might want to redesign this
        Err(JsError::new(
            "Getting existing sessions not yet implemented",
        ))
    }

    /// Lists all active session IDs.
    pub fn list_sessions(&self) -> Result<js_sys::Array, JsError> {
        let sessions = js_sys::Array::new();
        for session_id in self.p2p_manager.list_sessions() {
            sessions.push(&JsValue::from_str(&session_id));
        }
        Ok(sessions)
    }

    /// Removes a session from the manager.
    pub fn remove_session(&mut self, session_id: String) -> Result<bool, JsError> {
        Ok(self.p2p_manager.remove_session(&session_id))
    }

    /// Gets session info including metadata.
    pub fn get_session_info(&self, session_id: String) -> Result<JsValue, JsError> {
        if let Some(info) = self.p2p_manager.get_session_info(&session_id) {
            let js_info = js_sys::Object::new();
            js_sys_to_js_err(js_sys::Reflect::set(
                &js_info,
                &JsValue::from_str("id"),
                &JsValue::from_str(&info.id),
            ))?;
            js_sys_to_js_err(js_sys::Reflect::set(
                &js_info,
                &JsValue::from_str("active"),
                &JsValue::from_bool(info.active),
            ))?;
            js_sys_to_js_err(js_sys::Reflect::set(
                &js_info,
                &JsValue::from_str("createdAt"),
                &JsValue::from_str(&format!("{:?}", info.created_at)),
            ))?;
            js_sys_to_js_err(js_sys::Reflect::set(
                &js_info,
                &JsValue::from_str("topic"),
                &JsValue::from_str(&info.topic.to_string()),
            ))?;
            js_sys_to_js_err(js_sys::Reflect::set(
                &js_info,
                &JsValue::from_str("encryptionKey"),
                &JsValue::from_str(&info.encryption_key),
            ))?;
            Ok(js_info.into())
        } else {
            Err(JsError::new(&format!("Session {} not found", session_id)))
        }
    }

    /// Broadcasts a message to all active sessions.
    pub async fn broadcast_to_all(&self, data: Vec<u8>) -> Result<(), JsError> {
        self.p2p_manager
            .broadcast_to_all(data)
            .await
            .map_err(to_js_err)?;
        Ok(())
    }

    /// Sends a message to a specific session.
    pub async fn send_to_session(&self, session_id: String, data: Vec<u8>) -> Result<(), JsError> {
        self.p2p_manager
            .send_to_session(&session_id, data)
            .await
            .map_err(to_js_err)?;
        Ok(())
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
