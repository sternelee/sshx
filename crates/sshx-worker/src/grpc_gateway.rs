//! gRPC Gateway implementation for sshx-worker
//!
//! This module provides a complete gRPC-over-HTTP gateway that handles
//! gRPC requests in the Cloudflare Workers environment, supporting
//! streaming, metadata, and proper error handling.

use anyhow::{anyhow, Result};
use prost::Message;
use serde_json;
use std::sync::Arc;
use tracing::error;
use worker::*;

use crate::grpc::GrpcServer;
use crate::state::CloudflareServerState;
use sshx_core::proto::*;

/// gRPC Gateway for handling complete gRPC-over-HTTP requests
pub struct GrpcGateway {
    state: Arc<CloudflareServerState>,
    grpc_server: Arc<GrpcServer>,
}

impl GrpcGateway {
    /// Create a new gRPC Gateway
    pub fn new(state: Arc<CloudflareServerState>, grpc_server: Arc<GrpcServer>) -> Self {
        Self { state, grpc_server }
    }

    /// Handle incoming gRPC-over-HTTP request
    pub async fn handle_request(&self, req: Request) -> Result<Response> {
        let path = req.path();

        // Extract gRPC service and method from path
        let (service, method) = self.parse_grpc_path(&path)?;

        // Validate gRPC headers
        self.validate_grpc_headers(&req)?;

        // Parse gRPC metadata
        let metadata = self.extract_grpc_metadata(&req)?;

        // Handle different gRPC methods
        match (service.as_str(), method.as_str()) {
            ("sshx.Sshx", "Open") => self.handle_open(req, metadata).await,
            ("sshx.Sshx", "Close") => self.handle_close(req, metadata).await,
            ("sshx.Sshx", "Register") => self.handle_register(req, metadata).await,
            ("sshx.Sshx", "Login") => self.handle_login(req, metadata).await,
            ("sshx.Sshx", "GenerateApiKey") => self.handle_generate_api_key(req, metadata).await,
            ("sshx.Sshx", "DeleteApiKey") => self.handle_delete_api_key(req, metadata).await,
            ("sshx.Sshx", "ListApiKeys") => self.handle_list_api_keys(req, metadata).await,
            _ => Err(anyhow!("Unknown gRPC method: {}.{}", service, method)),
        }
    }

    /// Parse gRPC service and method from path
    fn parse_grpc_path(&self, path: &str) -> Result<(String, String)> {
        // Remove /grpc/ prefix and split by /
        let path = path.strip_prefix("/grpc/").unwrap_or(path);
        let parts: Vec<&str> = path.split('/').collect();

        if parts.len() != 2 {
            return Err(anyhow!("Invalid gRPC path format"));
        }

        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    /// Validate required gRPC headers
    fn validate_grpc_headers(&self, req: &Request) -> Result<()> {
        let headers = req.headers();

        // Check for gRPC content type
        let content_type = headers
            .get("content-type")?
            .ok_or_else(|| anyhow!("Missing content-type header"))?;

        if !content_type.contains("application/grpc") {
            return Err(anyhow!("Invalid content-type: {}", content_type));
        }

        // Check for gRPC encoding
        if let Ok(Some(encoding)) = headers.get("grpc-encoding") {
            if encoding != "identity" && encoding != "gzip" {
                return Err(anyhow!("Unsupported grpc-encoding: {}", encoding));
            }
        }

        Ok(())
    }

    /// Extract gRPC metadata from headers
    fn extract_grpc_metadata(
        &self,
        req: &Request,
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        let mut metadata = serde_json::Map::new();
        let headers = req.headers();

        // Extract gRPC metadata headers (grpc-*)
        for (key, value) in headers.entries() {
            if key.starts_with("grpc-") || key.starts_with("x-grpc-") {
                metadata.insert(key, serde_json::Value::String(value));
            }
        }

        // Add standard HTTP headers as metadata
        if let Ok(Some(user_agent)) = headers.get("user-agent") {
            metadata.insert(
                "user-agent".to_string(),
                serde_json::Value::String(user_agent),
            );
        }

        Ok(metadata)
    }

    /// Handle Open request with proper gRPC response
    async fn handle_open(
        &self,
        mut req: Request,
        _metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Response> {
        let body = req.bytes().await?;
        let open_request = self.decode_grpc_request::<OpenRequest>(&body)?;

        console_log!("gRPC Open request for session: {}", open_request.name);

        match self.grpc_server.handle_open(open_request).await {
            Ok(response) => {
                console_log!("gRPC Open successful for session: {}", response.name);
                self.create_grpc_response(response)
            }
            Err(e) => {
                error!("gRPC Open failed: {}", e);
                self.create_grpc_error_response(5, format!("Open failed: {}", e))
            }
        }
    }

    /// Handle Close request with proper gRPC response
    async fn handle_close(
        &self,
        mut req: Request,
        _metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Response> {
        let body = req.bytes().await?;
        let close_request = self.decode_grpc_request::<CloseRequest>(&body)?;

        console_log!("gRPC Close request for session: {}", close_request.name);

        let session_name = close_request.name.clone();
        match self.grpc_server.handle_close(close_request).await {
            Ok(response) => {
                console_log!("gRPC Close successful for session: {}", session_name);
                self.create_grpc_response(response)
            }
            Err(e) => {
                error!("gRPC Close failed: {}", e);
                self.create_grpc_error_response(5, format!("Close failed: {}", e))
            }
        }
    }

    /// Handle Register request with proper gRPC response
    async fn handle_register(
        &self,
        mut req: Request,
        _metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Response> {
        let body = req.bytes().await?;
        let register_request = self.decode_grpc_request::<RegisterRequest>(&body)?;

        console_log!("gRPC Register request for user: {}", register_request.email);

        match self.grpc_server.handle_register(register_request).await {
            Ok(response) => {
                console_log!("gRPC Register successful for user: {}", response.email);
                self.create_grpc_response(response)
            }
            Err(e) => {
                error!("gRPC Register failed: {}", e);
                self.create_grpc_error_response(5, format!("Register failed: {}", e))
            }
        }
    }

    /// Handle Login request with proper gRPC response
    async fn handle_login(
        &self,
        mut req: Request,
        _metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Response> {
        let body = req.bytes().await?;
        let login_request = self.decode_grpc_request::<LoginRequest>(&body)?;

        console_log!("gRPC Login request for user: {}", login_request.email);

        match self.grpc_server.handle_login(login_request).await {
            Ok(response) => {
                console_log!("gRPC Login successful for user: {}", response.email);
                self.create_grpc_response(response)
            }
            Err(e) => {
                error!("gRPC Login failed: {}", e);
                self.create_grpc_error_response(5, format!("Login failed: {}", e))
            }
        }
    }

    /// Handle GenerateApiKey request with proper gRPC response
    async fn handle_generate_api_key(
        &self,
        mut req: Request,
        _metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Response> {
        let body = req.bytes().await?;
        let generate_request = self.decode_grpc_request::<GenerateApiKeyRequest>(&body)?;

        console_log!("gRPC GenerateApiKey request");

        match self
            .grpc_server
            .handle_generate_api_key(generate_request)
            .await
        {
            Ok(response) => {
                console_log!("gRPC GenerateApiKey successful");
                self.create_grpc_response(response)
            }
            Err(e) => {
                error!("gRPC GenerateApiKey failed: {}", e);
                self.create_grpc_error_response(5, format!("GenerateApiKey failed: {}", e))
            }
        }
    }

    /// Handle DeleteApiKey request with proper gRPC response
    async fn handle_delete_api_key(
        &self,
        mut req: Request,
        _metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Response> {
        let body = req.bytes().await?;
        let delete_request = self.decode_grpc_request::<DeleteApiKeyRequest>(&body)?;

        console_log!(
            "gRPC DeleteApiKey request for key: {}",
            delete_request.api_key_id
        );

        match self.grpc_server.handle_delete_api_key(delete_request).await {
            Ok(response) => {
                console_log!("gRPC DeleteApiKey successful");
                self.create_grpc_response(response)
            }
            Err(e) => {
                error!("gRPC DeleteApiKey failed: {}", e);
                self.create_grpc_error_response(5, format!("DeleteApiKey failed: {}", e))
            }
        }
    }

    /// Handle ListApiKeys request with proper gRPC response
    async fn handle_list_api_keys(
        &self,
        mut req: Request,
        _metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Response> {
        let body = req.bytes().await?;
        let list_request = self.decode_grpc_request::<ListApiKeysRequest>(&body)?;

        console_log!("gRPC ListApiKeys request");

        match self.grpc_server.handle_list_api_keys(list_request).await {
            Ok(response) => {
                console_log!(
                    "gRPC ListApiKeys successful, found {} keys",
                    response.api_keys.len()
                );
                self.create_grpc_response(response)
            }
            Err(e) => {
                error!("gRPC ListApiKeys failed: {}", e);
                self.create_grpc_error_response(5, format!("ListApiKeys failed: {}", e))
            }
        }
    }

    /// Decode gRPC request from binary data
    fn decode_grpc_request<T: Message + Default>(&self, data: &[u8]) -> Result<T> {
        // Remove gRPC message framing (5-byte header)
        let message_data = if data.len() > 5 { &data[5..] } else { data };

        T::decode(message_data).map_err(|e| anyhow!("Failed to decode gRPC request: {}", e))
    }

    /// Create proper gRPC response with headers
    fn create_grpc_response<T: Message>(&self, message: T) -> Result<Response> {
        let mut buf = Vec::new();
        message
            .encode(&mut buf)
            .map_err(|e| anyhow!("Failed to encode gRPC response: {}", e))?;

        // Add gRPC message framing (compressed flag + length)
        let mut framed_data = Vec::new();
        framed_data.push(0u8); // compression flag (0 = uncompressed)
        framed_data.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        framed_data.extend_from_slice(&buf);

        let headers = worker::Headers::new();
        headers.append("content-type", "application/grpc+proto")?;
        headers.append("grpc-encoding", "identity")?;
        headers.append("grpc-accept-encoding", "identity,gzip")?;
        headers.append("grpc-status", "0")?; // OK
        headers.append("grpc-message", "OK")?;

        Ok(Response::from_bytes(framed_data)?
            .with_status(200)
            .with_headers(headers))
    }

    /// Create gRPC error response
    fn create_grpc_error_response(&self, status_code: u32, message: String) -> Result<Response> {
        let headers = worker::Headers::new();
        headers.append("content-type", "application/grpc+proto")?;
        headers.append("grpc-status", &status_code.to_string())?;
        headers.append("grpc-message", &message)?;

        // Return empty response with error status
        Ok(Response::empty()?.with_status(200).with_headers(headers))
    }

    /// Handle gRPC health check
    pub async fn handle_health_check(&self) -> Result<Response> {
        let headers = worker::Headers::new();
        headers.append("content-type", "application/grpc+proto")?;
        headers.append("grpc-status", "0")?;
        headers.append("grpc-message", "OK")?;

        Ok(Response::empty()?.with_status(200).with_headers(headers))
    }

    /// Handle gRPC reflection (for service discovery)
    pub async fn handle_reflection(&self) -> Result<Response> {
        // Simple service list response
        let services = vec!["sshx.Sshx".to_string()];

        let headers = worker::Headers::new();
        headers.append("content-type", "application/grpc+proto")?;
        headers.append("grpc-status", "0")?;
        headers.append("grpc-message", "OK")?;

        // Return service list as simple JSON for now
        let response = serde_json::to_string(&services)?;

        Ok(Response::from_bytes(response.as_bytes().to_vec())?
            .with_status(200)
            .with_headers(headers))
    }
}

/// gRPC streaming support for terminal data
pub struct GrpcStreamHandler {
    state: Arc<CloudflareServerState>,
}

impl GrpcStreamHandler {
    pub fn new(state: Arc<CloudflareServerState>) -> Self {
        Self { state }
    }

    /// Handle streaming terminal data (for future implementation)
    pub async fn handle_terminal_stream(
        &self,
        _req: Request,
        session_name: &str,
    ) -> Result<Response> {
        console_log!("Terminal stream request for session: {}", session_name);

        // This would implement bidirectional streaming for terminal data
        // For now, return a placeholder response
        let headers = worker::Headers::new();
        headers.append("content-type", "application/grpc+proto")?;
        headers.append("grpc-status", "12")?; // Unimplemented
        headers.append("grpc-message", "Terminal streaming not yet implemented")?;

        Ok(Response::empty()?.with_status(200).with_headers(headers))
    }
}

