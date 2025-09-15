//! gRPC-over-HTTP service implementation for sshx-worker
//!
//! This module provides HTTP endpoints that handle gRPC requests serialized with protobuf,
//! adapted for Cloudflare Workers environment where native gRPC is not available.

use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use prost::Message;
use sshx_core::proto::{
    ApiKeyResponse, AuthResponse, CloseRequest, CloseResponse, DeleteApiKeyRequest,
    DeleteApiKeyResponse, GenerateApiKeyRequest, ListApiKeysRequest, ListApiKeysResponse, LoginRequest,
    OpenRequest, OpenResponse, RegisterRequest,
};
use tracing::{error, info};

use crate::session::{SessionManager, SessionMetadata};
use crate::state::CloudflareServerState;
use crate::user_service::{
    GenerateApiKeyRequest as UserGenerateApiKeyRequest, ListApiKeysRequest as UserListApiKeysRequest,
    LoginRequest as UserLoginRequest, RegisterRequest as UserRegisterRequest, UserService,
};

/// Server that handles gRPC-over-HTTP requests from the sshx command-line client.
#[derive(Clone)]
pub struct GrpcServer {
    state: Arc<CloudflareServerState>,
    user_service: Arc<UserService>,
}

impl GrpcServer {
    /// Construct a new [`GrpcServer`] instance with associated state.
    pub fn new(state: Arc<CloudflareServerState>, user_service: Arc<UserService>) -> Self {
        Self {
            state,
            user_service,
        }
    }

    /// Create a new session and return connection information.
    async fn create_session(
        &self,
        name: &str,
        encrypted_zeros: Vec<u8>,
        write_password_hash: Option<Vec<u8>>,
        _user_id: Option<String>,
    ) -> Result<(String, String)> {
        let session_manager = SessionManager::new(Arc::clone(&self.state));

        // Check if session already exists
        if session_manager.is_session_active(name).await.unwrap_or(false) {
            return Err(anyhow::anyhow!("Session already exists"));
        }

        // Create session metadata
        let metadata = SessionMetadata {
            encrypted_zeros: encrypted_zeros.into(),
            name: name.to_string(),
            write_password_hash: write_password_hash.map(|h| h.into()),
        };

        // Create session
        session_manager.create_session(name, metadata).await?;

        // Generate connection token
        let token = format!("token_{}", name);

        // Construct URL (using default or configured host)
        let host = self.state.host().unwrap_or("sshx.io");
        let url = format!("https://{}/s/{}", host, name);

        Ok((url, token))
    }

    /// Verify authentication token and return user ID if valid.
    async fn verify_auth_token(&self, token: &str) -> Result<Option<String>> {
        self.user_service.verify_auth_token(token).await
            .map(|user| Some(user.id))
            .map_err(|_| anyhow::anyhow!("Invalid auth token"))
    }

    /// Handle Open request (create new session)
    pub async fn handle_open(&self, req: OpenRequest) -> Result<OpenResponse> {
        info!("Open request for session: {}", req.name);

        // Decode base64 encrypted zeros
        let encrypted_zeros = BASE64_STANDARD
            .decode(&req.encrypted_zeros)
            .context("Invalid encrypted_zeros format")?;

        // Decode base64 write password hash if provided
        let write_password_hash = if let Some(hash_bytes) = &req.write_password_hash {
            if !hash_bytes.is_empty() {
                let hash = BASE64_STANDARD
                    .decode(hash_bytes)
                    .context("Invalid write_password_hash format")?;
                Some(hash)
            } else {
                None
            }
        } else {
            None
        };

        // Verify API key if provided
        let user_id = if let Some(api_key) = &req.user_api_key {
            if !api_key.is_empty() {
                match self.user_service.verify_api_key(api_key).await {
                    Ok((user, _)) => Some(user.id),
                    Err(_) => return Err(anyhow::anyhow!("Invalid API key")),
                }
            } else {
                None
            }
        } else {
            None
        };

        match self.create_session(&req.name, encrypted_zeros, write_password_hash, user_id).await {
            Ok((url, token)) => {
                info!("Session created successfully: {}", req.name);
                Ok(OpenResponse {
                    name: req.name,
                    token,
                    url,
                })
            }
            Err(e) => {
                error!("Failed to create session: {}", e);
                Err(anyhow::anyhow!("Failed to create session: {}", e))
            }
        }
    }

    /// Handle Close request
    pub async fn handle_close(&self, req: CloseRequest) -> Result<CloseResponse> {
        info!("Close request for session: {}", req.name);

        // Verify auth token
        let user_id = match self.verify_auth_token(&req.token).await {
            Ok(Some(id)) => id,
            Ok(None) => return Err(anyhow::anyhow!("Invalid auth token")),
            Err(e) => {
                error!("Auth verification failed: {}", e);
                return Err(anyhow::anyhow!("Authentication failed"));
            }
        };

        let session_manager = SessionManager::new(Arc::clone(&self.state));
        match session_manager.close_session(&req.name).await {
            Ok(_) => {
                info!("Session {} closed by user {}", req.name, user_id);
                Ok(CloseResponse {})
            }
            Err(e) => {
                error!("Failed to close session: {}", e);
                Err(anyhow::anyhow!("Failed to close session: {}", e))
            }
        }
    }

    /// Handle Register request
    pub async fn handle_register(&self, req: RegisterRequest) -> Result<AuthResponse> {
        info!("Register request for user: {}", req.email);

        let user_request = UserRegisterRequest {
            email: req.email,
            password: req.password,
        };

        match self.user_service.register(user_request).await {
            Ok(auth_response) => {
                info!("User registered successfully: {}", auth_response.email);
                Ok(AuthResponse {
                    token: auth_response.token,
                    user_id: "".to_string(), // TODO: Get actual user_id from service
                    email: auth_response.email,
                })
            }
            Err(e) => {
                error!("Registration failed: {}", e);
                Err(anyhow::anyhow!("Registration failed: {}", e))
            }
        }
    }

    /// Handle Login request
    pub async fn handle_login(&self, req: LoginRequest) -> Result<AuthResponse> {
        info!("Login request for user: {}", req.email);

        let login_request = UserLoginRequest {
            email: req.email,
            password: req.password,
        };

        match self.user_service.login(login_request).await {
            Ok(auth_response) => {
                info!("User logged in successfully: {}", auth_response.email);
                Ok(AuthResponse {
                    token: auth_response.token,
                    user_id: "".to_string(), // TODO: Get actual user_id from service
                    email: auth_response.email,
                })
            }
            Err(e) => {
                error!("Login failed: {}", e);
                Err(anyhow::anyhow!("Login failed: {}", e))
            }
        }
    }

    /// Handle GenerateApiKey request
    pub async fn handle_generate_api_key(&self, req: GenerateApiKeyRequest) -> Result<ApiKeyResponse> {
        info!("Generate API key request for user");

        // Verify auth token
        let _user_id = match self.verify_auth_token(&req.auth_token).await {
            Ok(Some(id)) => id,
            Ok(None) => return Err(anyhow::anyhow!("Invalid auth token")),
            Err(e) => {
                error!("Auth verification failed: {}", e);
                return Err(anyhow::anyhow!("Authentication failed"));
            }
        };

        let generate_request = UserGenerateApiKeyRequest {
            auth_token: req.auth_token,
            name: req.name,
            permissions: None, // TODO: Add support for permissions in proto
            expires_at: None, // TODO: Add support for expires_at in proto
        };

        match self.user_service.generate_api_key(generate_request).await {
            Ok(api_key_response) => {
                info!("API key generated successfully: {}", api_key_response.name);
                Ok(ApiKeyResponse {
                    id: api_key_response.id,
                    name: api_key_response.name,
                    token: api_key_response.api_key,
                    created_at: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(), // Use current time as fallback
                    user_id: "".to_string(), // TODO: Get actual user_id
                })
            }
            Err(e) => {
                error!("API key generation failed: {}", e);
                Err(anyhow::anyhow!("API key generation failed: {}", e))
            }
        }
    }

    /// Handle DeleteApiKey request
    pub async fn handle_delete_api_key(&self, req: DeleteApiKeyRequest) -> Result<DeleteApiKeyResponse> {
        info!("Delete API key request: {}", req.api_key_id);

        // Verify auth token
        let _user_id = match self.verify_auth_token(&req.auth_token).await {
            Ok(Some(id)) => id,
            Ok(None) => return Err(anyhow::anyhow!("Invalid auth token")),
            Err(e) => {
                error!("Auth verification failed: {}", e);
                return Err(anyhow::anyhow!("Authentication failed"));
            }
        };

        let api_key_id = req.api_key_id.clone();
        let delete_request = crate::user_service::DeleteApiKeyRequest {
            auth_token: req.auth_token,
            api_key_id: api_key_id.clone(),
        };

        match self.user_service.delete_api_key(delete_request).await {
            Ok(success) => {
                info!("API key deleted successfully: {}", api_key_id);
                Ok(DeleteApiKeyResponse { success })
            }
            Err(e) => {
                error!("API key deletion failed: {}", e);
                Err(anyhow::anyhow!("API key deletion failed: {}", e))
            }
        }
    }

    /// Handle ListApiKeys request
    pub async fn handle_list_api_keys(&self, req: ListApiKeysRequest) -> Result<ListApiKeysResponse> {
        info!("List API keys request for user");

        // Verify auth token
        let _user_id = match self.verify_auth_token(&req.auth_token).await {
            Ok(Some(id)) => id,
            Ok(None) => return Err(anyhow::anyhow!("Invalid auth token")),
            Err(e) => {
                error!("Auth verification failed: {}", e);
                return Err(anyhow::anyhow!("Authentication failed"));
            }
        };

        let list_request = UserListApiKeysRequest {
            auth_token: req.auth_token,
        };

        match self.user_service.list_api_keys(list_request).await {
            Ok(response) => {
                info!("API keys listed successfully for user");
                let api_keys = response.api_keys.into_iter().map(|key| {
                    sshx_core::proto::ApiKeyInfo {
                        id: key.id,
                        name: key.name,
                        created_at: SystemTime::from(key.created_at).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
                        last_used: key.last_used_at.map(|dt| SystemTime::from(dt).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
                        is_active: true, // TODO: Determine if key is active
                    }
                }).collect();

                Ok(ListApiKeysResponse { api_keys })
            }
            Err(e) => {
                error!("Failed to list API keys: {}", e);
                Err(anyhow::anyhow!("Failed to list API keys: {}", e))
            }
        }
    }
}

/// Helper function to encode protobuf message as base64
pub fn encode_protobuf<T: Message>(msg: &T) -> String {
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();
    BASE64_STANDARD.encode(&buf)
}

/// Helper function to decode base64 as protobuf message
pub fn decode_protobuf<T: Message + Default>(data: &[u8]) -> Result<T> {
    let bytes = BASE64_STANDARD.decode(data)?;
    Ok(T::decode(&*bytes)?)
}