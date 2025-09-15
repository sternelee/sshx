use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};
use worker::*;

mod db;
mod state;
mod user_service;

use state::CloudflareServerState;
use user_service::{
    CloseUserSessionRequest, CloseUserSessionResponse, DeleteApiKeyRequest, DeleteApiKeyResponse,
    GenerateApiKeyRequest, ListApiKeysRequest, ListUserSessionsRequest, LoginRequest,
    RegisterRequest, UserService,
};

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

impl<T> SuccessResponse<T> {
    fn new(data: T) -> Self {
        Self {
            success: true,
            data,
        }
    }
}

fn error_response(message: &str, status: u16) -> Response {
    let error_response = ErrorResponse {
        error: message.to_string(),
    };
    Response::from_json(&error_response)
        .unwrap_or_else(|_| Response::error("Internal error", 500).unwrap())
        .with_status(status)
}

fn success_response<T: Serialize>(data: T) -> Response {
    Response::from_json(&SuccessResponse::new(data))
        .unwrap_or_else(|_| Response::error("Serialization error", 500).unwrap())
}

#[derive(Deserialize)]
struct AuthTokenRequest {
    auth_token: String,
}

async fn handle_register(
    mut req: Request,
    state: Arc<CloudflareServerState>,
) -> worker::Result<Response> {
    let register_request: RegisterRequest = req.json().await?;
    let user_service = UserService::new(state);

    match user_service.register(register_request).await {
        Ok(auth_response) => {
            info!("User registered successfully: {}", auth_response.email);
            Ok(success_response(auth_response))
        }
        Err(err) => {
            error!("Registration failed: {}", err);
            Ok(error_response(&err.to_string(), 400))
        }
    }
}

async fn handle_login(
    mut req: Request,
    state: Arc<CloudflareServerState>,
) -> worker::Result<Response> {
    let login_request: LoginRequest = req.json().await?;
    let user_service = UserService::new(state);

    match user_service.login(login_request).await {
        Ok(auth_response) => {
            info!("User logged in successfully: {}", auth_response.email);
            Ok(success_response(auth_response))
        }
        Err(err) => {
            error!("Login failed: {}", err);
            Ok(error_response(&err.to_string(), 401))
        }
    }
}

async fn handle_generate_api_key(
    mut req: Request,
    state: Arc<CloudflareServerState>,
) -> worker::Result<Response> {
    let generate_request: GenerateApiKeyRequest = req.json().await?;
    let user_service = UserService::new(state);

    match user_service.generate_api_key(generate_request).await {
        Ok(api_key_response) => {
            info!("API key generated successfully: {}", api_key_response.name);
            Ok(success_response(api_key_response))
        }
        Err(err) => {
            error!("API key generation failed: {}", err);
            Ok(error_response(&err.to_string(), 400))
        }
    }
}

async fn handle_list_api_keys(
    mut req: Request,
    state: Arc<CloudflareServerState>,
) -> worker::Result<Response> {
    let list_request: ListApiKeysRequest = req.json().await?;
    let user_service = UserService::new(state);

    match user_service.list_api_keys(list_request).await {
        Ok(response) => {
            info!("API keys listed successfully");
            Ok(success_response(response))
        }
        Err(err) => {
            error!("Failed to list API keys: {}", err);
            Ok(error_response(&err.to_string(), 400))
        }
    }
}

async fn handle_delete_api_key(
    req: Request,
    state: Arc<CloudflareServerState>,
) -> worker::Result<Response> {
    let url = req.url()?;
    let path_segments: Vec<&str> = url.path().split('/').collect();

    // Expected path: /api/auth/api-keys/{id}
    let api_key_id = if path_segments.len() >= 5 {
        path_segments[4].to_string()
    } else {
        return Ok(error_response("Invalid API key ID", 400));
    };

    let mut req = req;
    let auth_request: AuthTokenRequest = req.json().await?;
    let user_service = UserService::new(state);

    let delete_request = DeleteApiKeyRequest {
        auth_token: auth_request.auth_token,
        api_key_id,
    };

    match user_service.delete_api_key(delete_request).await {
        Ok(success) => {
            info!("API key deletion result: {}", success);
            Ok(success_response(DeleteApiKeyResponse { success }))
        }
        Err(err) => {
            error!("Failed to delete API key: {}", err);
            Ok(error_response(&err.to_string(), 400))
        }
    }
}

async fn handle_list_user_sessions(
    mut req: Request,
    state: Arc<CloudflareServerState>,
) -> worker::Result<Response> {
    let list_request: ListUserSessionsRequest = req.json().await?;
    let user_service = UserService::new(state);

    match user_service.list_user_sessions(list_request).await {
        Ok(response) => {
            info!("User sessions listed successfully");
            Ok(success_response(response))
        }
        Err(err) => {
            error!("Failed to list user sessions: {}", err);
            Ok(error_response(&err.to_string(), 400))
        }
    }
}

async fn handle_close_user_session(
    req: Request,
    state: Arc<CloudflareServerState>,
) -> worker::Result<Response> {
    let url = req.url()?;
    let path_segments: Vec<&str> = url.path().split('/').collect();

    // Expected path: /api/auth/sessions/{id}/close
    let session_id = if path_segments.len() >= 5 {
        path_segments[4].to_string()
    } else {
        return Ok(error_response("Invalid session ID", 400));
    };

    let mut req = req;
    let auth_request: AuthTokenRequest = req.json().await?;
    let user_service = UserService::new(state);

    let close_request = CloseUserSessionRequest {
        auth_token: auth_request.auth_token,
        session_id,
    };

    match user_service.close_user_session(close_request).await {
        Ok(success) => {
            info!("Session close result: {}", success);
            Ok(success_response(CloseUserSessionResponse { success }))
        }
        Err(err) => {
            error!("Failed to close session: {}", err);
            Ok(error_response(&err.to_string(), 400))
        }
    }
}

async fn handle_websocket(
    req: Request,
    _state: Arc<CloudflareServerState>,
) -> worker::Result<Response> {
    let url = req.url()?;
    let path_segments: Vec<&str> = url.path().split('/').collect();

    // Expected path: /api/s/{name}
    let name = if path_segments.len() >= 4 {
        path_segments[3]
    } else {
        return Ok(error_response("Invalid session name", 400));
    };

    info!("WebSocket connection requested for session: {}", name);
    Ok(Response::error("WebSocket not implemented yet", 501)?)
}

async fn route_request(
    req: Request,
    state: Arc<CloudflareServerState>,
) -> worker::Result<Response> {
    let url = req.url()?;
    let path = url.path();
    let method = req.method();

    match (&method, path) {
        (Method::Post, "/api/auth/register") => handle_register(req, state).await,
        (Method::Post, "/api/auth/login") => handle_login(req, state).await,
        (Method::Post, "/api/auth/api-keys") => handle_generate_api_key(req, state).await,
        (Method::Get, "/api/auth/api-keys") => handle_list_api_keys(req, state).await,
        (Method::Post, "/api/auth/sessions") => handle_list_user_sessions(req, state).await,
        (Method::Delete, path) if path.starts_with("/api/auth/api-keys/") && path.len() > 19 => {
            handle_delete_api_key(req, state).await
        }
        (Method::Post, path)
            if path.starts_with("/api/auth/sessions/") && path.ends_with("/close") =>
        {
            handle_close_user_session(req, state).await
        }
        (_, path) if path.starts_with("/api/s/") => handle_websocket(req, state).await,
        _ => Ok(Response::error("Not found", 404)?),
    }
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    // Initialize panic handler and logging
    console_error_panic_hook::set_once();

    // Create server state from environment
    let state = match CloudflareServerState::new(&env) {
        Ok(state) => Arc::new(state),
        Err(e) => {
            error!("Failed to create server state: {}", e);
            return Err(worker::Error::RustError(format!(
                "Failed to create server state: {}",
                e
            )));
        }
    };

    // Route the request
    route_request(req, state).await
}

