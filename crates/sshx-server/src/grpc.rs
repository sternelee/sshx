//! Defines gRPC routes and application request logic.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use hmac::Mac;
use sshx_core::proto::{
    client_update::ClientMessage, server_update::ServerMessage, sshx_service_server::SshxService,
    ApiKeyResponse, AuthResponse, ClientUpdate, CloseRequest, CloseResponse, DeleteApiKeyRequest,
    DeleteApiKeyResponse, GenerateApiKeyRequest, ListApiKeysRequest, ListApiKeysResponse,
    LoginRequest, OpenRequest, OpenResponse, RegisterRequest, ServerUpdate,
};
use sshx_core::{rand_alphanumeric, Sid};
use tokio::sync::mpsc;
use tokio::time::{self, MissedTickBehavior};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info, warn};

use crate::session::{Metadata, Session};
use crate::user_service::UserService;
use crate::ServerState;

/// Interval for synchronizing sequence numbers with the client.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(5);

/// Interval for measuring client latency.
pub const PING_INTERVAL: Duration = Duration::from_secs(2);

/// Server that handles gRPC requests from the sshx command-line client.
#[derive(Clone)]
pub struct GrpcServer {
    state: Arc<ServerState>,
    user_service: Arc<UserService>,
}

impl GrpcServer {
    /// Construct a new [`GrpcServer`] instance with associated state.
    pub fn new(state: Arc<ServerState>, user_service: Arc<UserService>) -> Self {
        Self {
            state,
            user_service,
        }
    }

    /// Update user API key last used timestamp.
    async fn update_api_key_usage(
        &self,
        user_id: &str,
        api_key_token: &str,
    ) -> Result<(), anyhow::Error> {
        if let Some(mut user) = self.user_service.get_user_by_id(user_id).await? {
            let api_key_id = user
                .get_api_key_by_token(api_key_token)
                .map(|k| k.id.clone());
            if let Some(api_key_id) = api_key_id {
                user.update_api_key_last_used(&api_key_id);
                self.user_service.save_user(&user).await?;
            }
        }
        Ok(())
    }
}

type RR<T> = Result<Response<T>, Status>;

#[tonic::async_trait]
impl SshxService for GrpcServer {
    type ChannelStream = ReceiverStream<Result<ServerUpdate, Status>>;

    async fn register(&self, request: Request<RegisterRequest>) -> RR<AuthResponse> {
        let request = request.into_inner();
        let req = crate::user::RegisterRequest {
            email: request.email,
            password: request.password,
        };

        match self.user_service.register(req).await {
            Ok(auth_response) => Ok(Response::new(AuthResponse {
                token: auth_response.token,
                user_id: auth_response.user_id,
                email: auth_response.email,
            })),
            Err(err) => Err(Status::invalid_argument(err.to_string())),
        }
    }

    async fn login(&self, request: Request<LoginRequest>) -> RR<AuthResponse> {
        let request = request.into_inner();
        let req = crate::user::LoginRequest {
            email: request.email,
            password: request.password,
        };

        match self.user_service.login(req).await {
            Ok(auth_response) => Ok(Response::new(AuthResponse {
                token: auth_response.token,
                user_id: auth_response.user_id,
                email: auth_response.email,
            })),
            Err(err) => Err(Status::unauthenticated(err.to_string())),
        }
    }

    async fn generate_api_key(
        &self,
        request: Request<GenerateApiKeyRequest>,
    ) -> RR<ApiKeyResponse> {
        let request = request.into_inner();
        let req = crate::user::GenerateApiKeyRequest {
            auth_token: request.auth_token,
            name: request.name,
        };

        match self.user_service.generate_api_key(req).await {
            Ok(response) => Ok(Response::new(ApiKeyResponse {
                id: response.id,
                name: response.name,
                token: response.token,
                created_at: response.created_at,
                user_id: response.user_id,
            })),
            Err(err) => Err(Status::invalid_argument(err.to_string())),
        }
    }

    async fn delete_api_key(
        &self,
        request: Request<DeleteApiKeyRequest>,
    ) -> RR<DeleteApiKeyResponse> {
        let request = request.into_inner();
        let req = crate::user::DeleteApiKeyRequest {
            auth_token: request.auth_token,
            api_key_id: request.api_key_id,
        };

        match self.user_service.delete_api_key(req).await {
            Ok(success) => Ok(Response::new(DeleteApiKeyResponse { success })),
            Err(err) => Err(Status::invalid_argument(err.to_string())),
        }
    }

    async fn list_api_keys(&self, request: Request<ListApiKeysRequest>) -> RR<ListApiKeysResponse> {
        let request = request.into_inner();
        let req = crate::user::ListApiKeysRequest {
            auth_token: request.auth_token,
        };

        match self.user_service.list_api_keys(req).await {
            Ok(response) => {
                let api_keys = response
                    .api_keys
                    .into_iter()
                    .map(|key| sshx_core::proto::ApiKeyInfo {
                        id: key.id,
                        name: key.name,
                        created_at: key.created_at,
                        last_used: key.last_used,
                        is_active: key.is_active,
                    })
                    .collect();

                Ok(Response::new(ListApiKeysResponse { api_keys }))
            }
            Err(err) => Err(Status::invalid_argument(err.to_string())),
        }
    }

    async fn open(&self, request: Request<OpenRequest>) -> RR<OpenResponse> {
        let request = request.into_inner();
        let origin = self.state.override_origin().unwrap_or(request.origin);
        if origin.is_empty() {
            return Err(Status::invalid_argument("origin is empty"));
        }

        // Check if this is a user-authenticated session
        let (name, user_id) = if let Some(user_api_key) = request.user_api_key {
            // Verify the API key and get associated user
            let user_id = self
                .user_service
                .verify_api_key(&user_api_key)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .ok_or_else(|| Status::unauthenticated("Invalid API key"))?;

            // Generate session name based on user ID and timestamp
            let session_name = format!("user-{}-{}", &user_id[..8], chrono::Utc::now().timestamp());

            // Update API key usage
            if let Err(err) = self.update_api_key_usage(&user_id, &user_api_key).await {
                warn!(?err, "failed to update API key usage");
            }

            (session_name, Some(user_id))
        } else {
            // Generate random session name for anonymous users
            (rand_alphanumeric(10), None)
        };

        info!(%name, ?user_id, "creating new session");

        match self.state.lookup(&name) {
            Some(_) => return Err(Status::already_exists("session already exists")),
            None => {
                let metadata = Metadata {
                    encrypted_zeros: request.encrypted_zeros,
                    name: request.name,
                    write_password_hash: request.write_password_hash,
                };
                self.state.insert(&name, Arc::new(Session::new(metadata)));
            }
        };

        let token = self.state.mac().chain_update(&name).finalize();
        let url = format!("{origin}/s/{name}");

        // Log user session creation if this is a user session
        if let Some(ref user_id) = user_id {
            info!(%name, %user_id, %url, "created user session");
        }

        Ok(Response::new(OpenResponse {
            name,
            token: BASE64_STANDARD.encode(token.into_bytes()),
            url,
        }))
    }

    async fn channel(&self, request: Request<Streaming<ClientUpdate>>) -> RR<Self::ChannelStream> {
        let mut stream = request.into_inner();
        let first_update = match stream.next().await {
            Some(result) => result?,
            None => return Err(Status::invalid_argument("missing first message")),
        };
        let session_name = match first_update.client_message {
            Some(ClientMessage::Hello(hello)) => {
                let (name, token) = hello
                    .split_once(',')
                    .ok_or_else(|| Status::invalid_argument("missing name and token"))?;
                validate_token(self.state.mac(), name, token)?;
                name.to_string()
            }
            _ => return Err(Status::invalid_argument("invalid first message")),
        };
        let session = match self.state.backend_connect(&session_name).await {
            Ok(Some(session)) => session,
            Ok(None) => return Err(Status::not_found("session not found")),
            Err(err) => {
                error!(?err, "failed to connect to backend session");
                return Err(Status::internal(err.to_string()));
            }
        };

        // We now spawn an asynchronous task that sends updates to the client. Note that
        // when this task finishes, the sender end is dropped, so the receiver is
        // automatically closed.
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            if let Err(err) = handle_streaming(&tx, &session, stream).await {
                warn!(?err, "connection exiting early due to an error");
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn close(&self, request: Request<CloseRequest>) -> RR<CloseResponse> {
        let request = request.into_inner();
        validate_token(self.state.mac(), &request.name, &request.token)?;
        info!("closing session {}", request.name);
        if let Err(err) = self.state.close_session(&request.name).await {
            error!(?err, "failed to close session {}", request.name);
            return Err(Status::internal(err.to_string()));
        }
        Ok(Response::new(CloseResponse {}))
    }
}

/// Validate the client token for a session.
#[allow(clippy::result_large_err)]
fn validate_token(mac: impl Mac, name: &str, token: &str) -> tonic::Result<()> {
    if let Ok(token) = BASE64_STANDARD.decode(token) {
        if mac.chain_update(name).verify_slice(&token).is_ok() {
            return Ok(());
        }
    }
    Err(Status::unauthenticated("invalid token"))
}

type ServerTx = mpsc::Sender<Result<ServerUpdate, Status>>;

/// Handle bidirectional streaming messages RPC messages.
async fn handle_streaming(
    tx: &ServerTx,
    session: &Session,
    mut stream: Streaming<ClientUpdate>,
) -> Result<(), &'static str> {
    let mut sync_interval = time::interval(SYNC_INTERVAL);
    sync_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut ping_interval = time::interval(PING_INTERVAL);
    ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // Send periodic sync messages to the client.
            _ = sync_interval.tick() => {
                let msg = ServerMessage::Sync(session.sequence_numbers());
                if !send_msg(tx, msg).await {
                    return Err("failed to send sync message");
                }
            }
            // Send periodic pings to the client.
            _ = ping_interval.tick() => {
                send_msg(tx, ServerMessage::Ping(get_time_ms())).await;
            }
            // Send buffered server updates to the client.
            Ok(msg) = session.update_rx().recv() => {
                if !send_msg(tx, msg).await {
                    return Err("failed to send update message");
                }
            }
            // Handle incoming client messages.
            maybe_update = stream.next() => {
                if let Some(Ok(update)) = maybe_update {
                    if !handle_update(tx, session, update).await {
                        return Err("error responding to client update");
                    }
                } else {
                    // The client has hung up on their end.
                    return Ok(());
                }
            }
            // Exit on a session shutdown signal.
            _ = session.terminated() => {
                let msg = String::from("disconnecting because session is closed");
                send_msg(tx, ServerMessage::Error(msg)).await;
                return Ok(());
            }
        };
    }
}

/// Handles a singe update from the client. Returns `true` on success.
async fn handle_update(tx: &ServerTx, session: &Session, update: ClientUpdate) -> bool {
    session.access();
    match update.client_message {
        Some(ClientMessage::Hello(_)) => {
            return send_err(tx, "unexpected hello".into()).await;
        }
        Some(ClientMessage::Data(data)) => {
            if let Err(err) = session.add_data(Sid(data.id), data.data, data.seq) {
                return send_err(tx, format!("add data: {:?}", err)).await;
            }
        }
        Some(ClientMessage::CreatedShell(new_shell)) => {
            let id = Sid(new_shell.id);
            let center = (new_shell.x, new_shell.y);
            if let Err(err) = session.add_shell(id, center) {
                return send_err(tx, format!("add shell: {:?}", err)).await;
            }
        }
        Some(ClientMessage::ClosedShell(id)) => {
            if let Err(err) = session.close_shell(Sid(id)) {
                return send_err(tx, format!("close shell: {:?}", err)).await;
            }
        }
        Some(ClientMessage::Pong(ts)) => {
            let latency = get_time_ms().saturating_sub(ts);
            session.send_latency_measurement(latency);
        }
        Some(ClientMessage::Error(err)) => {
            // TODO: Propagate these errors to listeners on the web interface?
            error!(?err, "error received from client");
        }
        None => (), // Heartbeat message, ignored.
    }
    true
}

/// Attempt to send a server message to the client.
async fn send_msg(tx: &ServerTx, message: ServerMessage) -> bool {
    let update = Ok(ServerUpdate {
        server_message: Some(message),
    });
    tx.send(update).await.is_ok()
}

/// Attempt to send an error string to the client.
async fn send_err(tx: &ServerTx, err: String) -> bool {
    send_msg(tx, ServerMessage::Error(err)).await
}

fn get_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time is before the UNIX epoch")
        .as_millis() as u64
}
