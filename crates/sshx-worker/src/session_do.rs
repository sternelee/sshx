//! Durable Object implementation for a single sshx session.

use std::cell::RefCell;
use std::collections::HashMap;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use js_sys::Date;
use prost::Message;
use sha2::Sha256;
use worker::{
    durable_object, Env, Request, Response, Result, State, WebSocket,
    WebSocketIncomingMessage, WebSocketPair,
};

use crate::generated::sshx as proto;
use crate::protocol::{Sid, Uid, WsClient, WsServer, WsUser};
use crate::state::{IdCounter, Metadata, SessionState};

/// Timeout for a disconnected session to be evicted.
const DISCONNECTED_SESSION_EXPIRY_MS: f64 = 300_000.0; // 5 minutes
/// Default session expiry in KV (seconds).
const KV_SESSION_TTL_SECONDS: u64 = 3600;
/// Interval for saving snapshot to storage.
const STORAGE_SYNC_INTERVAL_MS: f64 = 20_000.0; // 20 seconds

#[durable_object]
pub struct SessionObject {
    state: State,
    #[allow(unused)]
    env: Env,
    session: SessionState,
    /// Active frontend user IDs (for tracking who is connected).
    frontend_users: RefCell<HashMap<Uid, ()>>,
    /// Last time the backend sent a message.
    last_backend_access: RefCell<f64>,
    /// Whether an alarm is already scheduled.
    alarm_scheduled: RefCell<bool>,
}

#[durable_object]
impl DurableObject for SessionObject {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            session: SessionState::new(Metadata {
                encrypted_zeros: Bytes::new(),
                name: String::new(),
                write_password_hash: None,
            }),
            frontend_users: RefCell::new(HashMap::new()),
            last_backend_access: RefCell::new(Date::now()),
            alarm_scheduled: RefCell::new(false),
        }
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        let path = req.path();
        match path.as_str() {
            "/init" => self.handle_init(req).await,
            "/close" => self.handle_close().await,
            "/snapshot" => self.handle_snapshot_request().await,
            "/ping" => Response::ok("pong"),
            // Frontend WebSocket: Worker forwards the original path /api/s/:name
            _ if path.starts_with("/api/s/") => self.handle_frontend_upgrade(req).await,
            // Backend WebSocket: Worker forwards the original path /api/backend/:name
            _ if path.starts_with("/api/backend/") => self.handle_backend_upgrade(req).await,
            _ => Response::error("Not Found", 404),
        }
    }

    async fn alarm(&mut self) -> Result<Response> {
        *self.alarm_scheduled.borrow_mut() = false;

        let has_backend = !self.state.get_websockets_with_tag("backend").is_empty();
        let has_frontend = !self.frontend_users.borrow().is_empty();

        // Save snapshot to storage if backend is connected.
        if has_backend {
            if let Ok(snapshot) = self.session.snapshot() {
                let arr = js_sys::Uint8Array::from(&snapshot[..]);
                let _ = self.state.storage().put_raw("snapshot", arr).await;
            }
            *self.last_backend_access.borrow_mut() = Date::now();
        }

        // Refresh KV TTL if session is still active.
        if has_backend || has_frontend {
            if let Ok(kv_data) = self.state.storage().get::<String>("kv_data").await {
                if let Ok(kv) = self.env.kv("SSHX_SESSIONS") {
                    let name = self.session.metadata().name.clone();
                    if !name.is_empty() {
                        if let Ok(builder) = kv.put(&format!("session:{name}"), kv_data) {
                            let _ = builder.expiration_ttl(KV_SESSION_TTL_SECONDS).execute().await;
                        }
                    }
                }
            }
        }

        // Check if session has expired.
        let now = Date::now();
        let last = *self.last_backend_access.borrow();

        if !has_backend && !has_frontend && now - last > DISCONNECTED_SESSION_EXPIRY_MS {
            // Evict the session.
            self.session.shutdown();
            let _ = self.state.storage().delete_all().await;
            return Response::ok("evicted");
        }

        // Reschedule alarm if there are still connections.
        if has_backend || has_frontend {
            self.schedule_alarm();
        }

        Response::ok("ok")
    }

    async fn websocket_message(
        &mut self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let tags = self.state.get_tags(&ws);
        let is_frontend = tags.contains(&"frontend".to_string());

        if is_frontend {
            self.handle_frontend_message(ws, message).await
        } else {
            self.handle_backend_message(ws, message).await
        }
    }

    async fn websocket_close(
        &mut self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        let tags = self.state.get_tags(&ws);
        if tags.contains(&"frontend".to_string()) {
            if let Ok(Some(uid)) = ws.deserialize_attachment::<Uid>() {
                self.frontend_users.borrow_mut().remove(&uid);
                self.broadcast_frontend(WsServer::UserDiff(uid, None)).await;
            }
        } else {
            self.session.shutdown();
        }
        Ok(())
    }

    async fn websocket_error(&mut self, ws: WebSocket, _error: worker::Error) -> Result<()> {
        let tags = self.state.get_tags(&ws);
        if tags.contains(&"frontend".to_string()) {
            if let Ok(Some(uid)) = ws.deserialize_attachment::<Uid>() {
                self.frontend_users.borrow_mut().remove(&uid);
                self.broadcast_frontend(WsServer::UserDiff(uid, None)).await;
            }
        }
        Ok(())
    }
}

impl SessionObject {
    // ---------- WebSocket Upgrade Handlers ----------

    async fn handle_frontend_upgrade(&mut self, _req: Request) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        // Use hibernation API only — do NOT call server.accept().
        self.state
            .accept_websocket_with_tags(&server, &["frontend"]);

        // Send Hello immediately.
        let user_id = self.session.counter().next_uid();
        let metadata = self.session.metadata();
        let hello = WsServer::Hello(user_id, metadata.name.clone());
        let mut buf = Vec::new();
        if ciborium::ser::into_writer(&hello, &mut buf).is_ok() {
            let _ = server.send_with_bytes(&buf);
        }

        // Send current shell list so the frontend can render existing shells immediately.
        let shells = self.session.shells_list.borrow().clone();
        let mut buf = Vec::new();
        if ciborium::ser::into_writer(&WsServer::Shells(shells), &mut buf).is_ok() {
            let _ = server.send_with_bytes(&buf);
        }

        let _ = server.serialize_attachment(user_id);
        self.frontend_users.borrow_mut().insert(user_id, ());
        self.ensure_alarm();

        Response::from_websocket(pair.client)
    }

    async fn handle_backend_upgrade(&mut self, req: Request) -> Result<Response> {
        // Validate token from query string.
        let url = req.url()?;
        let path = url.path();
        let name = path.strip_prefix("/api/backend/").unwrap_or("").to_string();
        if name.is_empty() {
            return Response::error("missing session name", 400);
        }
        let token = url
            .query_pairs()
            .find_map(|(k, v)| if k == "token" { Some(v.into_owned()) } else { None });
        let token = match token {
            Some(t) => t,
            None => return Response::error("missing token", 401),
        };
        let secret = match self.env.secret("SESSION_SECRET") {
            Ok(s) => s.to_string(),
            Err(_) => return Response::error("SESSION_SECRET not configured", 500),
        };
        let mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        let expected = mac.chain_update(&name).finalize().into_bytes();
        let expected = BASE64_STANDARD.encode(&expected);
        if token != expected {
            return Response::error("invalid token", 403);
        }

        // Close existing backend if any.
        for ws in self.state.get_websockets_with_tag("backend") {
            let _ = ws.close(Some(1008), Some("new backend connected"));
        }

        let pair = WebSocketPair::new()?;
        let server = pair.server;
        // Use hibernation API only — do NOT call server.accept().
        self.state
            .accept_websocket_with_tags(&server, &["backend"]);

        *self.last_backend_access.borrow_mut() = Date::now();
        self.session.access();

        // Send current sequence numbers as first message.
        let sync = proto::ServerUpdate {
            server_message: Some(proto::server_update::ServerMessage::Sync(
                self.session.sequence_numbers(),
            )),
        };
        let mut buf = Vec::new();
        if sync.encode(&mut buf).is_ok() {
            let _ = server.send_with_bytes(&buf);
        }

        self.ensure_alarm();
        Response::from_websocket(pair.client)
    }

    // ---------- Message Handlers ----------

    async fn handle_frontend_message(
        &mut self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let binary = match message {
            WebSocketIncomingMessage::String(_) => return Ok(()),
            WebSocketIncomingMessage::Binary(b) => b,
        };

        let msg: WsClient = match ciborium::de::from_reader(&*binary) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };

        let user_id = ws.deserialize_attachment::<Uid>().unwrap_or(None).unwrap_or(0);

        match msg {
            WsClient::Authenticate(zeros, write_password_bytes) => {
                let metadata = self.session.metadata();
                let valid = zeros.as_ref() == metadata.encrypted_zeros.as_ref();
                if !valid {
                    let _ = self.send_frontend(&ws, WsServer::InvalidAuth()).await;
                    return Ok(());
                }
                let can_write = match (write_password_bytes, &metadata.write_password_hash) {
                    (_, None) => true,
                    (None, Some(_)) => false,
                    (Some(provided), Some(stored)) => {
                        if provided.as_ref() != stored.as_ref() {
                            let _ = self.send_frontend(&ws, WsServer::InvalidAuth()).await;
                            return Ok(());
                        }
                        true
                    }
                };
                if let Ok(user) = self.session.add_user(user_id, can_write) {
                    let _ = self.send_frontend(&ws, WsServer::Users(self.session.list_users())).await;
                    self.broadcast_frontend(WsServer::UserDiff(user_id, Some(user))).await;
                }
            }
            WsClient::SetName(name) => {
                if !name.is_empty() {
                    if let Ok(user) = self.session.update_user(user_id, |u| u.name = name) {
                        self.broadcast_frontend(WsServer::UserDiff(user_id, Some(user))).await;
                    }
                }
            }
            WsClient::SetCursor(cursor) => {
                if let Ok(user) = self.session.update_user(user_id, |u| u.cursor = cursor) {
                    self.broadcast_frontend(WsServer::UserDiff(user_id, Some(user))).await;
                }
            }
            WsClient::SetFocus(id) => {
                if let Ok(user) = self.session.update_user(user_id, |u| u.focus = id) {
                    self.broadcast_frontend(WsServer::UserDiff(user_id, Some(user))).await;
                }
            }
            WsClient::Create(x, y) => {
                if self.session.check_write_permission(user_id).is_err() {
                    let _ = self.send_frontend(&ws, WsServer::Error("No write permission".into())).await;
                    return Ok(());
                }
                let id = self.session.counter().next_sid();
                let _ = self.session.add_shell(id, (x, y));
                // Notify backend.
                self.send_backend(proto::server_update::ServerMessage::CreateShell(
                    proto::NewShell { id, x, y },
                )).await;
                self.broadcast_frontend(WsServer::Shells(self.session.shells_list.borrow().clone())).await;
            }
            WsClient::Close(id) => {
                if self.session.check_write_permission(user_id).is_err() {
                    let _ = self.send_frontend(&ws, WsServer::Error("No write permission".into())).await;
                    return Ok(());
                }
                let _ = self.session.close_shell(id);
                self.send_backend(proto::server_update::ServerMessage::CloseShell(id)).await;
                self.broadcast_frontend(WsServer::Shells(self.session.shells_list.borrow().clone())).await;
            }
            WsClient::Move(id, winsize) => {
                if self.session.check_write_permission(user_id).is_err() {
                    let _ = self.send_frontend(&ws, WsServer::Error("No write permission".into())).await;
                    return Ok(());
                }
                match self.session.move_shell(id, winsize) {
                    Ok(dims_changed) => {
                        if dims_changed {
                            if let Some(w) = winsize {
                                self.send_backend(proto::server_update::ServerMessage::Resize(
                                    proto::TerminalSize {
                                        id,
                                        rows: w.rows as u32,
                                        cols: w.cols as u32,
                                    },
                                )).await;
                            }
                        }
                        self.broadcast_frontend(WsServer::Shells(self.session.shells_list.borrow().clone())).await;
                    }
                    Err(err) => {
                        let _ = self.send_frontend(&ws, WsServer::Error(err.to_string())).await;
                    }
                }
            }
            WsClient::Data(id, data, offset) => {
                if self.session.check_write_permission(user_id).is_err() {
                    let _ = self.send_frontend(&ws, WsServer::Error("No write permission".into())).await;
                    return Ok(());
                }
                self.send_backend(proto::server_update::ServerMessage::Input(
                    proto::TerminalInput {
                        id,
                        data: data.to_vec(),
                        offset,
                    },
                )).await;
            }
            WsClient::Subscribe(id, chunknum) => {
                let ws_clone = ws.clone();
                self.session.subscribe_chunks(id, chunknum, move |seqnum, chunks| {
                    let msg = WsServer::Chunks(id, seqnum, chunks);
                    let mut buf = Vec::new();
                    if ciborium::ser::into_writer(&msg, &mut buf).is_ok() {
                        let _ = ws_clone.send_with_bytes(&buf);
                    }
                });
            }
            WsClient::Chat(msg) => {
                if let Ok((name, text)) = self.session.send_chat(user_id, &msg) {
                    self.broadcast_frontend(WsServer::Hear(user_id, name, text)).await;
                }
            }
            WsClient::Ping(ts) => {
                let _ = self.send_frontend(&ws, WsServer::Pong(ts)).await;
            }
        }

        Ok(())
    }

    async fn handle_backend_message(
        &mut self,
        _ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let binary = match message {
            WebSocketIncomingMessage::String(_) => return Ok(()),
            WebSocketIncomingMessage::Binary(b) => b,
        };

        let update = match proto::ClientUpdate::decode(&*binary) {
            Ok(u) => u,
            Err(_) => return Ok(()),
        };

        let msg = match update.client_message {
            Some(m) => m,
            None => return Ok(()), // heartbeat
        };

        self.session.access();
        *self.last_backend_access.borrow_mut() = Date::now();

        match msg {
            proto::client_update::ClientMessage::Hello(_) => {}
            proto::client_update::ClientMessage::Data(data) => {
                let id = data.id;
                let seq = data.seq;
                let bytes: Bytes = data.data.into();
                if self.session.add_data(id, bytes, seq).is_ok() {
                    // Frontend subscribers will be notified via the callback mechanism.
                }
            }
            proto::client_update::ClientMessage::CreatedShell(new_shell) => {
                let id = new_shell.id;
                let center = (new_shell.x, new_shell.y);
                let _ = self.session.add_shell(id, center);
                self.broadcast_frontend(WsServer::Shells(self.session.shells_list.borrow().clone())).await;
            }
            proto::client_update::ClientMessage::ClosedShell(id) => {
                let _ = self.session.close_shell(id);
                self.broadcast_frontend(WsServer::Shells(self.session.shells_list.borrow().clone())).await;
            }
            proto::client_update::ClientMessage::Pong(ts) => {
                let latency = (Date::now() as u64).saturating_sub(ts);
                self.broadcast_frontend(WsServer::ShellLatency(latency)).await;
            }
            proto::client_update::ClientMessage::Error(err) => {
                worker::console_log!("backend error: {}", err);
            }
        }

        Ok(())
    }

    // ---------- HTTP Handlers ----------

    async fn handle_init(&mut self, mut req: Request) -> Result<Response> {
        let body: serde_json::Value = match req.json().await {
            Ok(v) => v,
            Err(_) => return Response::error("invalid JSON", 400),
        };
        let encrypted_zeros = match body["encrypted_zeros"].as_str() {
            Some(s) => match BASE64_STANDARD.decode(s) {
                Ok(v) => Bytes::from(v),
                Err(_) => return Response::error("invalid encrypted_zeros", 400),
            },
            None => return Response::error("missing encrypted_zeros", 400),
        };
        let name = body["name"].as_str().unwrap_or("").to_string();
        let write_password_hash = body["write_password_hash"].as_str()
            .and_then(|s| BASE64_STANDARD.decode(s).ok())
            .map(Bytes::from);

        // Store KV data for TTL refresh.
        if let Some(kv_data) = body["kv_data"].as_str() {
            let _ = self.state.storage().put("kv_data", kv_data).await;
        }

        // Update metadata (this replaces the temporary one from new()).
        self.session = SessionState::new(Metadata {
            encrypted_zeros,
            name,
            write_password_hash,
        });

        // Restore snapshot if exists (must happen AFTER creating the new session).
        let storage = self.state.storage();
        if let Ok(snapshot) = storage.get::<Vec<u8>>("snapshot").await {
            let _ = self.session.restore(&snapshot);
        }

        Response::ok("initialized")
    }

    async fn handle_close(&mut self) -> Result<Response> {
        self.session.shutdown();
        let _ = self.state.storage().delete_all().await;
        Response::ok("closed")
    }

    async fn handle_snapshot_request(&mut self) -> Result<Response> {
        match self.session.snapshot() {
            Ok(data) => Response::from_bytes(data),
            Err(err) => Response::error(err.to_string(), 500),
        }
    }

    // ---------- Helpers ----------

    async fn send_frontend(&self, ws: &WebSocket, msg: WsServer) -> Result<()> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&msg, &mut buf).map_err(|e| format!("{e:?}"))?;
        ws.send_with_bytes(&buf)
    }

    async fn broadcast_frontend(&self, msg: WsServer) {
        let mut buf = Vec::new();
        if ciborium::ser::into_writer(&msg, &mut buf).is_err() {
            return;
        }
        for ws in self.state.get_websockets_with_tag("frontend") {
            let _ = ws.send_with_bytes(&buf);
        }
    }

    async fn send_backend(&self, msg: proto::server_update::ServerMessage) {
        let update = proto::ServerUpdate {
            server_message: Some(msg),
        };
        let mut buf = Vec::new();
        if update.encode(&mut buf).is_err() {
            return;
        }
        for ws in self.state.get_websockets_with_tag("backend") {
            let _ = ws.send_with_bytes(&buf);
        }
    }

    fn ensure_alarm(&self) {
        if !*self.alarm_scheduled.borrow() {
            self.schedule_alarm();
        }
    }

    fn schedule_alarm(&self) {
        let storage = self.state.storage();
        let now = Date::now();
        let target = now + STORAGE_SYNC_INTERVAL_MS;
        let fut = async move {
            let _ = storage.set_alarm(target as i64).await;
        };
        self.state.wait_until(fut);
        *self.alarm_scheduled.borrow_mut() = true;
    }
}


