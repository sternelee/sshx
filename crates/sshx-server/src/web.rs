//! HTTP and WebSocket handlers for the sshx web interface.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{Method, StatusCode};
use axum::response::Json;
use axum::routing::{any, delete, get, get_service, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{error, info};

use crate::user::{
    ApiKeyResponse, AuthResponse, CloseUserSessionRequest, DeleteApiKeyRequest,
    GenerateApiKeyRequest, ListApiKeysRequest, ListApiKeysResponse, ListUserSessionsRequest,
    ListUserSessionsResponse, LoginRequest, RegisterRequest,
};
use crate::ServerState;

pub mod protocol;
mod socket;

/// Returns the web application server, routed with Axum.
pub fn app() -> Router<Arc<ServerState>> {
    let root_spa = ServeFile::new("build/spa.html")
        .precompressed_gzip()
        .precompressed_br();

    // Serves static SvelteKit build files.
    let static_files = ServeDir::new("build")
        .precompressed_gzip()
        .precompressed_br()
        .fallback(root_spa);

    Router::new()
        .nest("/api", backend())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
                .allow_headers(Any),
        )
        .fallback_service(get_service(static_files))
}

/// Routes for the backend web API server.
fn backend() -> Router<Arc<ServerState>> {
    Router::new()
        .route("/s/{name}", any(socket::get_session_ws))
        // User authentication routes
        .route("/auth/register", post(register_user))
        .route("/auth/login", post(login_user))
        // API key management routes
        .route("/auth/api-keys", post(generate_api_key))
        .route("/auth/api-keys", get(list_api_keys))
        .route("/auth/api-keys/:id", delete(delete_api_key))
        // User session routes
        .route("/auth/sessions", post(list_user_sessions))
        .route("/auth/sessions/:id/close", post(close_user_session))
}

/// Error response structure for API endpoints.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Success response structure for API endpoints.
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

/// Create an error response.
fn error_response(message: &str) -> Json<ErrorResponse> {
    Json(ErrorResponse {
        error: message.to_string(),
    })
}

/// User registration endpoint.
async fn register_user(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<SuccessResponse<AuthResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let user_service = match state.user_service() {
        Some(service) => service,
        None => {
            error!("User service not available");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                error_response("User service not available"),
            ));
        }
    };

    match user_service.register(request).await {
        Ok(auth_response) => {
            info!("User registered successfully: {}", auth_response.email);
            Ok(Json(SuccessResponse::new(auth_response)))
        }
        Err(err) => {
            error!("Registration failed: {}", err);
            Err((StatusCode::BAD_REQUEST, error_response(&err.to_string())))
        }
    }
}

/// User login endpoint.
async fn login_user(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<SuccessResponse<AuthResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let user_service = match state.user_service() {
        Some(service) => service,
        None => {
            error!("User service not available");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                error_response("User service not available"),
            ));
        }
    };

    match user_service.login(request).await {
        Ok(auth_response) => {
            info!("User logged in successfully: {}", auth_response.email);
            Ok(Json(SuccessResponse::new(auth_response)))
        }
        Err(err) => {
            error!("Login failed: {}", err);
            Err((StatusCode::UNAUTHORIZED, error_response(&err.to_string())))
        }
    }
}

/// Generate API key endpoint.
async fn generate_api_key(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<GenerateApiKeyRequest>,
) -> Result<Json<SuccessResponse<ApiKeyResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let user_service = match state.user_service() {
        Some(service) => service,
        None => {
            error!("User service not available");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                error_response("User service not available"),
            ));
        }
    };

    match user_service.generate_api_key(request).await {
        Ok(api_key_response) => {
            info!("API key generated successfully: {}", api_key_response.name);
            Ok(Json(SuccessResponse::new(api_key_response)))
        }
        Err(err) => {
            error!("API key generation failed: {}", err);
            Err((StatusCode::BAD_REQUEST, error_response(&err.to_string())))
        }
    }
}

/// List API keys endpoint.
async fn list_api_keys(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<ListApiKeysRequest>,
) -> Result<Json<SuccessResponse<ListApiKeysResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let user_service = match state.user_service() {
        Some(service) => service,
        None => {
            error!("User service not available");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                error_response("User service not available"),
            ));
        }
    };

    match user_service.list_api_keys(request).await {
        Ok(response) => {
            info!("API keys listed successfully");
            Ok(Json(SuccessResponse::new(response)))
        }
        Err(err) => {
            error!("Failed to list API keys: {}", err);
            Err((StatusCode::BAD_REQUEST, error_response(&err.to_string())))
        }
    }
}

/// Delete API key endpoint.
async fn delete_api_key(
    State(state): State<Arc<ServerState>>,
    Path(api_key_id): Path<String>,
    Json(auth_request): Json<AuthTokenRequest>,
) -> Result<Json<SuccessResponse<DeleteApiKeyResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let user_service = match state.user_service() {
        Some(service) => service,
        None => {
            error!("User service not available");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                error_response("User service not available"),
            ));
        }
    };

    let delete_request = DeleteApiKeyRequest {
        auth_token: auth_request.auth_token,
        api_key_id,
    };

    match user_service.delete_api_key(delete_request).await {
        Ok(success) => {
            info!("API key deletion result: {}", success);
            Ok(Json(SuccessResponse::new(DeleteApiKeyResponse { success })))
        }
        Err(err) => {
            error!("Failed to delete API key: {}", err);
            Err((StatusCode::BAD_REQUEST, error_response(&err.to_string())))
        }
    }
}

/// List user sessions endpoint.
async fn list_user_sessions(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<ListUserSessionsRequest>,
) -> Result<Json<SuccessResponse<ListUserSessionsResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let user_service = match state.user_service() {
        Some(service) => service,
        None => {
            error!("User service not available");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                error_response("User service not available"),
            ));
        }
    };

    match user_service.list_user_sessions(request).await {
        Ok(response) => {
            info!("User sessions listed successfully");
            Ok(Json(SuccessResponse::new(response)))
        }
        Err(err) => {
            error!("Failed to list user sessions: {}", err);
            Err((StatusCode::BAD_REQUEST, error_response(&err.to_string())))
        }
    }
}

/// Close user session endpoint.
async fn close_user_session(
    State(state): State<Arc<ServerState>>,
    Path(session_id): Path<String>,
    Json(auth_request): Json<AuthTokenRequest>,
) -> Result<Json<SuccessResponse<CloseSessionResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let user_service = match state.user_service() {
        Some(service) => service,
        None => {
            error!("User service not available");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                error_response("User service not available"),
            ));
        }
    };

    let close_request = CloseUserSessionRequest {
        auth_token: auth_request.auth_token,
        session_id,
    };

    match user_service.close_user_session(close_request).await {
        Ok(success) => {
            info!("Session close result: {}", success);
            Ok(Json(SuccessResponse::new(CloseSessionResponse { success })))
        }
        Err(err) => {
            error!("Failed to close session: {}", err);
            Err((StatusCode::BAD_REQUEST, error_response(&err.to_string())))
        }
    }
}

/// Request structure for endpoints that only need an auth token.
#[derive(Deserialize)]
struct AuthTokenRequest {
    auth_token: String,
}

/// Response structure for delete API key endpoint.
#[derive(Serialize)]
struct DeleteApiKeyResponse {
    success: bool,
}

/// Response structure for close session endpoint.
#[derive(Serialize)]
struct CloseSessionResponse {
    success: bool,
}
