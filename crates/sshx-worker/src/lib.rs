//! sshx-worker: Cloudflare Workers backend for sshx.
//!
//! Replaces the Rust sshx-server with a serverless architecture using:
//! - Durable Objects for per-session state and WebSocket coordination
//! - KV for session token storage and global discovery
//! - WebSocket for both frontend (CBOR) and backend (protobuf) transport

use std::collections::HashMap;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use js_sys::Date;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use worker::*;

use crate::generated::sshx as proto;

mod generated;
mod protocol;
mod session_do;
mod state;

/// KV key prefix for session tokens.
const KV_SESSION_PREFIX: &str = "session:";
/// Default session expiry in KV (seconds).
const KV_SESSION_TTL_SECONDS: u64 = 3600;

/// Open request payload (JSON).
#[derive(Deserialize)]
struct OpenBody {
    origin: String,
    encrypted_zeros: String, // base64
    name: String,
    write_password_hash: Option<String>, // base64
}

/// Open response payload (JSON).
#[derive(Serialize)]
struct OpenResp {
    name: String,
    token: String,
    url: String,
}

/// Close request payload (JSON).
#[derive(Deserialize)]
struct CloseBody {
    name: String,
    token: String,
}

#[event(fetch, respond_with_errors)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        // API: Create a new session.
        .post_async("/api/open", |mut req, ctx| async move {
            handle_open(req, ctx).await
        })
        // API: Close a session.
        .post_async("/api/close", |mut req, ctx| async move {
            handle_close(req, ctx).await
        })
        // Frontend WebSocket: browser connects here.
        .get_async("/api/s/:name", |req, ctx| async move {
            handle_frontend_ws(req, ctx).await
        })
        // Backend WebSocket: CLI connects here.
        .get_async("/api/backend/:name", |req, ctx| async move {
            handle_backend_ws(req, ctx).await
        })
        // SPA session pages: serve spa.html for any /s/:name path.
        .get_async("/s/:name", |req, ctx| async move {
            handle_spa(req, ctx).await
        })
        // All other requests: fallback to static assets (index.html, _app/, etc.)
        .get_async("/*path", |req, ctx| async move {
            handle_assets(req, ctx).await
        })
        .run(req, env)
        .await
}

async fn handle_open(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: OpenBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return Response::error("Invalid JSON", 400),
    };

    if body.origin.is_empty() {
        return Response::error("origin is empty", 400);
    }

    let name = rand_alphanumeric(10);
    let secret = ctx.secret("SESSION_SECRET")?.to_string();
    let mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    let token_bytes = mac.chain_update(&name).finalize().into_bytes();
    let token = BASE64_STANDARD.encode(&token_bytes);

    let encrypted_zeros = match BASE64_STANDARD.decode(&body.encrypted_zeros) {
        Ok(v) => v,
        Err(_) => return Response::error("invalid encrypted_zeros", 400),
    };
    let write_password_hash = body.write_password_hash.and_then(|s| BASE64_STANDARD.decode(s).ok());

    // Initialize the Durable Object.
    let namespace = ctx.env.durable_object("SESSION")?;
    let stub = namespace.id_from_name(&name)?.get_stub()?;

    let init_payload = serde_json::json!({
        "encrypted_zeros": BASE64_STANDARD.encode(&encrypted_zeros),
        "name": body.name,
        "write_password_hash": write_password_hash.as_ref().map(|b| BASE64_STANDARD.encode(b)),
    });

    let init_req = Request::new_with_init(
        "http://internal/init",
        RequestInit::new()
            .with_method(Method::Post)
            .with_body(Some(init_payload.to_string().into()))
            .with_headers(headers_from(&[("content-type", "application/json")])),
    )?;
    let init_resp = stub.fetch_with_request(init_req).await?;
    if init_resp.status_code() != 200 {
        return Response::error("failed to initialize session", 500);
    }

    // Store token in KV.
    let kv = ctx.kv("SSHX_SESSIONS")?;
    let kv_value = serde_json::json!({
        "token": token,
        "created_at": Date::now() as u64,
        "encrypted_zeros": BASE64_STANDARD.encode(&encrypted_zeros),
        "write_password_hash": write_password_hash.as_ref().map(|b| BASE64_STANDARD.encode(b)),
    });
    kv.put(
        &format!("{KV_SESSION_PREFIX}{name}"),
        kv_value.to_string(),
    )?
    .expiration_ttl(KV_SESSION_TTL_SECONDS)
    .execute()
    .await?;

    let url = format!("{}/s/{}", body.origin, name);
    Response::from_json(&OpenResp { name, token, url })
}

async fn handle_close(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: CloseBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return Response::error("Invalid JSON", 400),
    };

    // Validate token.
    let kv = ctx.kv("SSHX_SESSIONS")?;
    let kv_key = format!("{KV_SESSION_PREFIX}{}", body.name);
    let stored: Option<String> = kv.get(&kv_key).json().await?;
    let stored = match stored {
        Some(s) => s,
        None => return Response::error("session not found", 404),
    };
    let stored_json: serde_json::Value = match serde_json::from_str(&stored) {
        Ok(v) => v,
        Err(_) => return Response::error("corrupted session data", 500),
    };
    let expected_token = stored_json["token"].as_str().unwrap_or("");
    if expected_token != body.token {
        return Response::error("invalid token", 401);
    }

    // Notify DO to close.
    let namespace = ctx.env.durable_object("SESSION")?;
    let stub = namespace.id_from_name(&body.name)?.get_stub()?;
    let close_req = Request::new_with_init(
        "http://internal/close",
        RequestInit::new().with_method(Method::Post),
    )?;
    let _ = stub.fetch_with_request(close_req).await;

    // Delete from KV.
    kv.delete(&kv_key).await?;

    Response::ok("closed")
}

async fn handle_frontend_ws(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let name = match ctx.param("name") {
        Some(n) => n.to_string(),
        None => return Response::error("missing session name", 400),
    };

    let namespace = ctx.env.durable_object("SESSION")?;
    let stub = namespace.id_from_name(&name)?.get_stub()?;
    stub.fetch_with_request(req).await
}

async fn handle_backend_ws(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let name = match ctx.param("name") {
        Some(n) => n.to_string(),
        None => return Response::error("missing session name", 400),
    };

    let namespace = ctx.env.durable_object("SESSION")?;
    let stub = namespace.id_from_name(&name)?.get_stub()?;
    stub.fetch_with_request(req).await
}

fn rand_alphanumeric(len: usize) -> String {
    use rand::distr::Alphanumeric;
    use rand::{RngExt, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(js_sys::Date::now() as u64);
    rng.sample_iter(Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

async fn handle_spa(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    match ctx.env.get_binding::<worker::Fetcher>("ASSETS") {
        Ok(assets) => {
            // Rewrite the request URL to /spa.html so ASSETS serves the SPA fallback.
            let mut url = req.url()?;
            url.set_path("/spa.html");
            let spa_req = Request::new_with_init(
                url.as_str(),
                RequestInit::new().with_method(Method::Get),
            )?;
            assets.fetch_request(spa_req).await
        }
        Err(_) => Response::error("ASSETS not configured", 500),
    }
}

async fn handle_assets(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    match ctx.env.get_binding::<worker::Fetcher>("ASSETS") {
        Ok(assets) => assets.fetch_request(req).await,
        Err(_) => Response::error("Not Found", 404),
    }
}

fn headers_from(pairs: &[(&str, &str)]) -> Headers {
    let mut h = Headers::new();
    for (k, v) in pairs {
        let _ = h.set(k, v);
    }
    h
}
