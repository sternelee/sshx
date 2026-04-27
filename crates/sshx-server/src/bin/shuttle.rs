use std::net::SocketAddr;

use anyhow::Context;
use shuttle_runtime::SecretStore;
use sshx_server::{Server, ServerOptions};
use tracing::info;

struct ShuttleSshxServer {
    server: Server,
}

#[shuttle_runtime::main]
async fn shuttle(
    #[shuttle_runtime::Secrets] secrets: SecretStore,
) -> Result<ShuttleSshxServer, shuttle_runtime::Error> {
    let mut options = ServerOptions::default();
    options.secret = secrets.get("SSHX_SECRET");
    options.override_origin = secrets.get("SSHX_OVERRIDE_ORIGIN");
    options.redis_url = secrets.get("SSHX_REDIS_URL");
    options.host = secrets.get("SSHX_HOST");
    options.mesh_tls = parse_bool_secret(&secrets, "SSHX_MESH_TLS")?;

    if options.secret.is_none() {
        info!(
            "SSHX_SECRET is not set; Shuttle deployments should usually configure it to keep session tokens stable across restarts"
        );
    }

    Ok(ShuttleSshxServer {
        server: Server::new(options)?,
    })
}

#[shuttle_runtime::async_trait]
impl shuttle_runtime::Service for ShuttleSshxServer {
    async fn bind(self, addr: SocketAddr) -> Result<(), shuttle_runtime::Error> {
        info!("server listening at {addr}");
        self.server.bind(&addr).await?;
        Ok(())
    }
}

fn parse_bool_secret(secrets: &SecretStore, key: &str) -> anyhow::Result<bool> {
    match secrets.get(key) {
        Some(value) => value
            .parse::<bool>()
            .with_context(|| format!("{key} must be either true or false")),
        None => Ok(false),
    }
}

