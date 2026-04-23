//! Embedded static assets served directly from the binary.

use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../build"]
struct Assets;

fn mime_type(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html"
    } else if path.ends_with(".js") {
        "application/javascript"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else if path.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

fn accepts_encoding(req: &Request, encoding: &str) -> bool {
    req.headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains(encoding))
        .unwrap_or(false)
}

/// Serve an embedded static asset, with precompressed fallback.
pub async fn serve(req: Request) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    let path = if path.is_empty() { "spa.html" } else { path };

    let accept_br = accepts_encoding(&req, "br");
    let accept_gzip = accepts_encoding(&req, "gzip");

    let file = if accept_br {
        Assets::get(&format!("{}.br", path))
    } else {
        None
    }
    .or_else(|| {
        if accept_gzip {
            Assets::get(&format!("{}.gz", path))
        } else {
            None
        }
    })
    .or_else(|| Assets::get(path));

    match file {
        Some(content) => {
            let mut builder = Response::builder().header(header::CONTENT_TYPE, mime_type(path));

            if accept_br && Assets::get(&format!("{}.br", path)).is_some() {
                builder = builder.header(header::CONTENT_ENCODING, "br");
            } else if accept_gzip && Assets::get(&format!("{}.gz", path)).is_some() {
                builder = builder.header(header::CONTENT_ENCODING, "gzip");
            }

            builder
                .body(Body::from(content.data))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        None => {
            // SPA fallback for client-side routing.
            match Assets::get("spa.html") {
                Some(content) => Response::builder()
                    .header(header::CONTENT_TYPE, "text/html")
                    .body(Body::from(content.data))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
    }
}
