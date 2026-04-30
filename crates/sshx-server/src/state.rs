//! Stateful components of the server, managing multiple sessions.

use std::pin::pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::{Context, Result};
use dashmap::DashMap;
use hmac::{Hmac, KeyInit};
use sha2::Sha256;
use sshx_core::rand_alphanumeric;
use tokio::time;
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

use self::mesh::StorageMesh;
use crate::session::Session;
use crate::ServerOptions;

pub mod mesh;

/// Timeout for a disconnected session to be evicted and closed.
///
/// If a session has no backend clients making connections in this interval,
/// then its updated timestamp will be out-of-date, so we close it and remove it
/// from the state to reduce memory usage.
const DISCONNECTED_SESSION_EXPIRY: Duration = Duration::from_secs(300);

/// After a session has been idle this long with no CLI stream and no viewers,
/// evict it from the hot map to the Redis cold tier. The snapshot remains
/// recoverable until `DISCONNECTED_SESSION_EXPIRY` elapses (Redis TTL).
///
/// Override with `SSHX_COLD_AFTER_MS`. Default 60 s. Below 5 s risks
/// flapping on brief CLI reconnects; at or above the full expiry would be
/// a no-op. Out-of-range values silently fall back to the default.
static COLD_THRESHOLD: LazyLock<Duration> = LazyLock::new(|| {
    std::env::var("SSHX_COLD_AFTER_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .filter(|d| *d >= Duration::from_secs(5) && *d < DISCONNECTED_SESSION_EXPIRY)
        .unwrap_or(Duration::from_secs(60))
});

/// Shared state object for global server logic.
pub struct ServerState {
    /// Message authentication code for signing tokens.
    mac: Hmac<Sha256>,

    /// Override the origin returned for the Open() RPC.
    override_origin: Option<String>,

    /// A concurrent map of session IDs to session objects.
    store: DashMap<String, Arc<Session>>,

    /// Storage and distributed communication provider, if enabled.
    mesh: Option<StorageMesh>,

    /// Whether to use TLS (`wss://`) for inter-server proxy connections.
    mesh_tls: bool,
}

impl ServerState {
    /// Create an empty server state using the given secret.
    pub fn new(options: ServerOptions) -> Result<Self> {
        let secret = options.secret.unwrap_or_else(|| rand_alphanumeric(22));
        let mesh = match options.redis_url {
            Some(url) => Some(StorageMesh::new(&url, options.host.as_deref())?),
            None => None,
        };
        Ok(Self {
            mac: Hmac::new_from_slice(secret.as_bytes()).unwrap(),
            override_origin: options.override_origin,
            store: DashMap::new(),
            mesh,
            mesh_tls: options.mesh_tls,
        })
    }

    /// Returns the message authentication code used for signing tokens.
    pub fn mac(&self) -> Hmac<Sha256> {
        self.mac.clone()
    }

    /// Returns the override origin for the Open() RPC.
    pub fn override_origin(&self) -> Option<String> {
        self.override_origin.clone()
    }

    /// Returns the WebSocket scheme to use for inter-server proxy connections.
    ///
    /// Returns `"wss"` when `--mesh-tls` is set, otherwise `"ws"`.
    pub fn mesh_scheme(&self) -> &'static str {
        if self.mesh_tls {
            "wss"
        } else {
            "ws"
        }
    }

    /// Lookup a local session by name.
    pub fn lookup(&self, name: &str) -> Option<Arc<Session>> {
        self.store.get(name).map(|s| s.clone())
    }

    /// Insert a session into the local store.
    pub fn insert(&self, name: &str, session: Arc<Session>) {
        if let Some(mesh) = &self.mesh {
            let name = name.to_string();
            let session = session.clone();
            let mesh = mesh.clone();
            tokio::spawn(async move {
                mesh.background_sync(&name, session).await;
            });
        }
        if let Some(prev_session) = self.store.insert(name.to_string(), session) {
            warn!(
                name,
                "replacing an existing in-memory session on concurrent reconnect; the previous \
                 session will be shut down"
            );
            prev_session.shutdown();
        }
    }

    /// Remove a session from the local store.
    pub fn remove(&self, name: &str) -> bool {
        if let Some((_, session)) = self.store.remove(name) {
            session.shutdown();
            true
        } else {
            false
        }
    }

    /// Close a session permanently on this and other servers.
    pub async fn close_session(&self, name: &str) -> Result<()> {
        self.remove(name);
        if let Some(mesh) = &self.mesh {
            mesh.mark_closed(name).await?;
        }
        Ok(())
    }

    /// Snapshot the session and write it to Redis, **without** marking it
    /// closed. Used by the cold-tier sweeper to evict an idle session
    /// while keeping its state recoverable from the mesh snapshot.
    ///
    /// Errors when mesh is disabled or Redis fails.
    async fn evict_to_cold(&self, name: &str, session: &Arc<Session>) -> Result<()> {
        let mesh = self.mesh.as_ref().context("mesh disabled")?;
        let snapshot = session.snapshot()?;
        mesh.write_snapshot(name, snapshot).await?;
        Ok(())
    }

    /// Connect to a session by name from the `sshx` client, which provides the
    /// actual terminal backend.
    pub async fn backend_connect(&self, name: &str) -> Result<Option<Arc<Session>>> {
        if let Some(session) = self.lookup(name) {
            return Ok(Some(session));
        }

        if let Some(mesh) = &self.mesh {
            let (owner, snapshot) = mesh.get_owner_snapshot(name).await?;
            if let Some(snapshot) = snapshot {
                let session = Arc::new(Session::restore(&snapshot)?);
                self.insert(name, session.clone());
                if let Some(owner) = owner {
                    mesh.notify_transfer(name, &owner).await?;
                }
                return Ok(Some(session));
            }
        }

        Ok(None)
    }

    /// Connect to a session from a web browser frontend, possibly redirecting.
    pub async fn frontend_connect(
        &self,
        name: &str,
    ) -> Result<Result<Arc<Session>, Option<String>>> {
        if let Some(session) = self.lookup(name) {
            return Ok(Ok(session));
        }

        if let Some(mesh) = &self.mesh {
            let mut owner = mesh.get_owner(name).await?;
            if owner.is_some() && owner.as_deref() == mesh.host() {
                // Do not redirect back to the same server.
                owner = None;
            }
            return Ok(Err(owner));
        }

        Ok(Err(None))
    }

    /// Listen for and remove sessions that are transferred away from this host.
    pub async fn listen_for_transfers(&self) {
        if let Some(mesh) = &self.mesh {
            let mut transfers = pin!(mesh.listen_for_transfers());
            while let Some(name) = transfers.next().await {
                // Drop the local ownership cache before removing the session
                // so that any concurrent `get_owner(&name)` lookup misses the
                // cache and re-reads from Redis, preventing stale routing.
                mesh.invalidate_ownership(&name);
                self.remove(&name);
            }
        }
    }

    /// Close (full expiry) and cold-evict (idle but pre-expiry) old sessions.
    pub async fn close_old_sessions(&self) {
        loop {
            time::sleep(DISCONNECTED_SESSION_EXPIRY / 5).await;
            let mut to_close = Vec::new();
            let mut to_evict = Vec::new();
            for entry in &self.store {
                let session = entry.value();
                let idle = session.last_accessed_elapsed();
                if idle > DISCONNECTED_SESSION_EXPIRY {
                    to_close.push(entry.key().clone());
                } else if self.mesh.is_some()
                    && !session.has_active_grpc()
                    && session.user_count() == 0
                    && idle > *COLD_THRESHOLD
                {
                    to_evict.push(entry.key().clone());
                }
            }
            for name in to_close {
                if let Err(err) = self.close_session(&name).await {
                    error!(?err, "failed to close old session {name}");
                }
            }
            for name in to_evict {
                let Some(session) = self.lookup(&name) else {
                    continue;
                };
                if let Err(err) = self.evict_to_cold(&name, &session).await {
                    warn!(?err, "skip evict; could not sync {name}");
                    continue;
                }
                // Order matters: snapshot is durable in Redis BEFORE we
                // remove from the hot map and shut down background_sync.
                self.store.remove(&name);
                session.shutdown();
                info!(name, "session evicted to cold tier");
            }
        }
    }

    /// Send a graceful shutdown signal to every session.
    pub fn shutdown(&self) {
        for entry in &self.store {
            entry.value().shutdown();
        }
    }
}

#[cfg(test)]
mod cold_threshold_tests {
    use super::*;

    fn parse(env: Option<&str>) -> Duration {
        env.and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_millis)
            .filter(|d| *d >= Duration::from_secs(5) && *d < DISCONNECTED_SESSION_EXPIRY)
            .unwrap_or(Duration::from_secs(60))
    }

    #[test]
    fn cold_threshold_default_60s() {
        assert_eq!(parse(None), Duration::from_secs(60));
    }

    #[test]
    fn cold_threshold_rejects_oversize() {
        // 999_999 ms = 999 s, > DISCONNECTED_SESSION_EXPIRY (300 s) -> reject.
        assert_eq!(parse(Some("999999")), Duration::from_secs(60));
    }

    #[test]
    fn cold_threshold_rejects_too_small() {
        // 1000 ms = 1 s, < 5 s minimum -> reject.
        assert_eq!(parse(Some("1000")), Duration::from_secs(60));
    }

    #[test]
    fn cold_threshold_accepts_valid() {
        // 30 s is in range [5, 300).
        assert_eq!(parse(Some("30000")), Duration::from_secs(30));
    }
}
