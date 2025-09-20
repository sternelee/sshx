use anyhow::Result;
use futures_lite::StreamExt;
use js_sys::Uint8Array;
use shared::{
    events::ClientMessage, Event,
    message::Message,
    p2p::{P2pNode, P2pSessionSender},
    ticket::{SessionTicket, TicketOpts},
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
        tracing::info!("🚀 Starting P2P node initialization");
        
        match P2pNode::new().await {
            Ok(node) => {
                tracing::info!("✅ P2P node initialized successfully");
                tracing::info!("🆔 Node ID: {}", node.node_id());
                Ok(Self(node))
            }
            Err(e) => {
                tracing::error!("❌ Failed to initialize P2P node: {}", e);
                Err(to_js_err(e))
            }
        }
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
    pub async fn create(&self, nickname: String) -> Result<Session, JsError> {
        tracing::info!("🚀 Creating new session with nickname: {}", nickname);
        
        let ticket = SessionTicket::new_random();
        tracing::info!("🎫 Generated random ticket: {:?}", ticket);
        
        let (sender, receiver) = match self.0.join(&ticket, nickname).await {
            Ok(result) => {
                tracing::info!("✅ P2P session created successfully");
                result
            }
            Err(err) => {
                tracing::error!("❌ Failed to create P2P session: {}", err);
                return Err(JsError::new(&format!("P2P session creation failed: {}", err)));
            }
        };

        Session::from_p2p_session(ticket, self.0.node_id(), sender, receiver).await
    }

    /// Joins an SSH session from a ticket.
    pub async fn join(&self, ticket: String, nickname: String) -> Result<Session, JsError> {
        tracing::info!("🎯 Joining session with ticket: {}", ticket);
        
        let ticket = match SessionTicket::deserialize(&ticket) {
            Ok(ticket) => {
                tracing::info!("✅ Ticket deserialized successfully: {:?}", ticket);
                ticket
            }
            Err(err) => {
                tracing::error!("❌ Failed to deserialize ticket: {}", err);
                return Err(JsError::new(&format!("Ticket deserialization failed: {}", err)));
            }
        };
        
        let (sender, receiver) = match self.0.join(&ticket, nickname).await {
            Ok(result) => {
                tracing::info!("✅ P2P session joined successfully");
                result
            }
            Err(err) => {
                tracing::error!("❌ Failed to join P2P session: {}", err);
                return Err(JsError::new(&format!("P2P join failed: {}", err)));
            }
        };

        Session::from_p2p_session(ticket, self.0.node_id(), sender, receiver).await
    }
}

type SessionReceiver = wasm_streams::readable::sys::ReadableStream;

#[wasm_bindgen]
pub struct Session {
    ticket: SessionTicket,
    me: iroh::NodeId,
    sender: P2pSessionSender,
    receiver: Option<SessionReceiver>,
}

impl Session {
    async fn from_p2p_session(
        ticket: SessionTicket,
        me: iroh::NodeId,
        sender: P2pSessionSender,
        receiver: n0_future::boxed::BoxStream<Result<Event>>,
    ) -> Result<Self, JsError> {
        tracing::info!("🔧 Creating session from P2P session");
        
        let receiver = Some(ReadableStream::from_stream(receiver.map(|event| {
            match event {
                Ok(event) => {
                    tracing::debug!("✅ Received P2P event: {:?}", event);
                    match event {
                        // Handle ServerMessage events specially - convert to binary JSON
                        Event::ServerMessageReceived { from: _, message, sent_timestamp: _ } => {
                            tracing::info!("📨 Browser received ServerMessage: {:?}", message);
                            // Serialize ServerMessage to JSON bytes for TypeScript API
                            match serde_json::to_vec(&message) {
                                Ok(json_bytes) => {
                                    tracing::debug!("✅ Serialized ServerMessage to {} bytes", json_bytes.len());
                                    Ok(Uint8Array::from(&json_bytes[..]).into())
                                }
                                Err(err) => {
                                    tracing::error!("❌ Failed to serialize ServerMessage to JSON: {}", err);
                                    Err(JsValue::from(&format!("ServerMessage serialization failed: {}", err)))
                                }
                            }
                        }
                        // Handle other event types using normal serialization
                        _ => {
                            // Convert Event to JsValue using serde-wasm-bindgen
                            serde_wasm_bindgen::to_value(&event)
                                .map_err(|err| {
                                    tracing::error!("❌ Failed to serialize event to JsValue: {}", err);
                                    JsValue::from(&format!("Event serialization failed: {}", err))
                                })
                        }
                    }
                }
                Err(err) => {
                    tracing::error!("❌ Received error from P2P stream: {}", err);
                    Err(JsValue::from(&err.to_string()))
                }
            }
        }))
        .into_raw());

        tracing::info!("✅ Session created successfully from P2P session");
        
        Ok(Self {
            ticket,
            me,
            sender,
            receiver,
        })
    }
}

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(getter)]
    pub fn sender(&self) -> SessionSender {
        SessionSender {
            inner: self.sender.clone(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn receiver(&mut self) -> Option<SessionReceiver> {
        self.receiver.take()
    }

    pub fn ticket(&self, opts: JsValue) -> Result<String, JsError> {
        let opts: TicketOpts = serde_wasm_bindgen::from_value(opts)?;
        let mut ticket = self.ticket.clone();
        if opts.include_myself {
            ticket.bootstrap.insert(self.me);
        }
        Ok(ticket.serialize())
    }

    pub fn id(&self) -> String {
        self.ticket.topic_id.to_string()
    }

    pub fn encryption_key(&self) -> String {
        self.ticket.key.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct SessionSender {
    inner: P2pSessionSender,
}

#[wasm_bindgen]
impl SessionSender {
    pub async fn send(&self, data: Vec<u8>) -> Result<(), JsError> {
        // 安全检查：确保数据不为空
        if data.is_empty() {
            tracing::error!("❌ Cannot send empty data");
            return Err(JsError::new("Cannot send empty data"));
        }

        // 安全检查：数据大小限制
        if data.len() > 1024 * 1024 { // 1MB 限制
            tracing::error!("❌ Data too large: {} bytes", data.len());
            return Err(JsError::new("Data too large"));
        }

        // Parse the data as JSON to get ClientMessage
        let json_str = match String::from_utf8(data) {
            Ok(s) => {
                if s.trim().is_empty() {
                    tracing::error!("❌ Empty JSON string after UTF-8 conversion");
                    return Err(JsError::new("Empty JSON data"));
                }
                tracing::debug!("✅ Converted bytes to UTF-8 string (length: {})", s.len());
                s
            }
            Err(e) => {
                tracing::error!("❌ Failed to convert bytes to UTF-8: {}", e);
                return Err(to_js_err(e));
            }
        };

        // 安全检查：JSON 字符串长度
        if json_str.len() > 10000 {
            tracing::error!("❌ JSON string too long: {} characters", json_str.len());
            return Err(JsError::new("JSON data too large"));
        }

        let client_message = match serde_json::from_str::<ClientMessage>(&json_str) {
            Ok(msg) => {
                tracing::debug!("✅ Parsed JSON to ClientMessage: {:?}", msg);
                msg
            }
            Err(e) => {
                tracing::error!("❌ Failed to parse JSON to ClientMessage: {}", e);
                tracing::error!("JSON content (first 200 chars): {}", &json_str[..json_str.len().min(200)]);
                return Err(to_js_err(e));
            }
        };

        tracing::info!("🟢 Browser sending ClientMessage: {:?}", client_message);

        // Send as a signed Message::ClientMessage
        let message = Message::ClientMessage(client_message);
        match self.inner.send(message).await {
            Ok(()) => {
                tracing::info!("✅ Successfully sent signed ClientMessage to P2P network");
                Ok(())
            }
            Err(e) => {
                tracing::error!("❌ Failed to send message: {}", e);
                Err(to_js_err(e))
            }
        }
    }

    pub async fn send_json(&self, json_str: &str) -> Result<(), JsError> {
        // 安全检查：确保 JSON 字符串不为空
        if json_str.trim().is_empty() {
            tracing::error!("❌ Cannot send empty JSON string");
            return Err(JsError::new("Cannot send empty JSON"));
        }

        // 安全检查：JSON 字符串长度限制
        if json_str.len() > 10000 {
            tracing::error!("❌ JSON string too long: {} characters", json_str.len());
            return Err(JsError::new("JSON data too large"));
        }

        let client_message = match serde_json::from_str::<ClientMessage>(json_str) {
            Ok(msg) => {
                tracing::debug!("✅ Parsed JSON string to ClientMessage: {:?}", msg);
                msg
            }
            Err(e) => {
                tracing::error!("❌ Failed to parse JSON string: {}", e);
                tracing::error!("JSON content (first 200 chars): {}", &json_str[..json_str.len().min(200)]);
                return Err(to_js_err(e));
            }
        };

        tracing::info!(
            "🟢 Browser sending ClientMessage (JSON): {:?}",
            client_message
        );

        // Send as a signed Message::ClientMessage
        let message = Message::ClientMessage(client_message);
        match self.inner.send(message).await {
            Ok(()) => {
                tracing::info!("✅ Successfully sent signed ClientMessage to P2P network");
                Ok(())
            }
            Err(e) => {
                tracing::error!("❌ Failed to send message: {}", e);
                Err(to_js_err(e))
            }
        }
    }

    pub fn set_nickame(&self, nickname: String) {
        self.inner.set_nickname(nickname);
    }
}

fn to_js_err(err: impl Into<anyhow::Error>) -> JsError {
    let err: anyhow::Error = err.into();
    let error_msg = err.to_string();
    
    // 安全检查：确保错误消息不为空且不包含可能导致 WASM 绑定问题的字符
    let safe_error_msg = if error_msg.is_empty() {
        "Unknown error occurred".to_string()
    } else if error_msg.len() > 1000 {
        // 防止过长的错误消息导致问题
        format!("{}...", &error_msg[..1000])
    } else {
        error_msg
    };
    
    tracing::error!("🔥 Converting error to JS error: {}", safe_error_msg);
    
    // 使用安全的错误消息创建 JsError
    match JsError::new(&safe_error_msg) {
        js_err => js_err,
    }
}
