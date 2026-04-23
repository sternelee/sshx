//! HTTP and WebSocket handlers for the sshx web interface.

use std::sync::Arc;

use axum::routing::any;
use axum::Router;

use crate::ServerState;

pub mod protocol;
mod socket;

/// Returns the web application server, routed with Axum.
#[cfg(not(feature = "embedded"))]
pub fn app() -> Router<Arc<ServerState>> {
    use axum::routing::get_service;
    use tower_http::services::{ServeDir, ServeFile};

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
        .fallback_service(get_service(static_files))
}

/// Returns the web application server with embedded assets.
#[cfg(feature = "embedded")]
pub fn app() -> Router<Arc<ServerState>> {
    Router::new()
        .nest("/api", backend())
        .fallback(axum::routing::any(crate::embed::serve))
}

/// Routes for the backend web API server.
fn backend() -> Router<Arc<ServerState>> {
    Router::new().route("/s/{name}", any(socket::get_session_ws))
}
