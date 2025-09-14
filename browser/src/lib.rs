use std::str::FromStr;

use anyhow::Result;
use futures_lite::StreamExt;
use rand::RngCore;
use shared::{
    p2p::{P2pNode, P2pSession},
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

#[wasm_bindgen]
impl SshxNode {
    /// Spawns a P2P node.
    pub async fn spawn() -> Result<Self, JsError> {
        let node = P2pNode::new().await.map_err(to_js_err)?;

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
        let topic = {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            iroh_gossip::proto::TopicId::from_bytes(bytes)
        };
        let encryption_key = shared::crypto::rand_alphanumeric(14);
        let ticket = SessionTicket::new(topic, vec![], encryption_key);

        let p2p_session = self.0.create_session(ticket).await.map_err(to_js_err)?;

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
                match event {
                    Ok(e) => {
                        tracing::debug!("Received P2P event: {:?}", e);
                        match e {
                            iroh_gossip::api::Event::Received(msg) => {
                                // Extract the actual message content from Received event
                                tracing::info!("🟢 Received P2P message: {} bytes from peer", msg.content.len());
                                tracing::info!("🔍 Message content preview: {:?}", 
                                    String::from_utf8_lossy(&msg.content[..msg.content.len().min(200)]));
                                tracing::info!("📋 Raw bytes: {:?}", &msg.content[..msg.content.len().min(50)]);
                                
                                // Convert Bytes to Vec<u8> then to Uint8Array JsValue
                                let bytes: &[u8] = &msg.content;
                                let array = js_sys::Uint8Array::from(bytes);
                                Ok(array.into())
                            }
                            _ => {
                                // For other events, return empty Uint8Array
                                tracing::info!("🟡 Received P2P event (not message): {:?}", e);
                                let array = js_sys::Uint8Array::new_with_length(0);
                                Ok(array.into())
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("P2P event error: {}", e);
                        Err(JsValue::from_str(&e.to_string()))
                    }
                }
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
        self.inner.ticket().key.clone()
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

fn to_js_err(err: impl Into<anyhow::Error>) -> JsError {
    let err: anyhow::Error = err.into();
    JsError::new(&err.to_string())
}

fn js_sys_to_js_err(result: Result<bool, JsValue>) -> Result<(), JsError> {
    result
        .map_err(|e| JsError::new(&e.as_string().unwrap_or_else(|| "Unknown error".to_string())))?;
    Ok(())
}
