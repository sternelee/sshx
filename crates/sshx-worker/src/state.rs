use crate::db::D1Store;
use anyhow::Result;
use std::sync::Arc;
use worker::{D1Database, Env};

pub struct CloudflareServerState {
    pub db: Arc<D1Store>,
    pub secret: String,
    pub _override_origin: Option<String>,
    pub host: Option<String>,
    pub durable_objects: worker::ObjectNamespace,
}

impl CloudflareServerState {
    pub fn new(env: &Env) -> Result<Self> {
        // Get D1 database
        let d1_db: D1Database = env.d1("SSHX_DB")?;
        let db = Arc::new(D1Store::new(d1_db));

        // Get configuration from environment
        let secret = env
            .secret("SSHX_SECRET")
            .map(|s| s.to_string())
            .unwrap_or_else(|_| "default-secret".to_string());

        let _override_origin = env.var("SSHX_OVERRIDE_ORIGIN").map(|v| v.to_string()).ok();

        let host = env.var("SSHX_HOST").map(|v| v.to_string()).ok();

        // Get Durable Object namespace
        let durable_objects = env.durable_object("SSHX_SESSIONS")?;

        Ok(Self {
            db,
            secret,
            _override_origin,
            host,
            durable_objects,
        })
    }

    pub fn db(&self) -> Arc<D1Store> {
        Arc::clone(&self.db)
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub fn durable_object(&self, session_name: &str) -> worker::ObjectId<'_> {
        self.durable_objects
            .id_from_name(session_name)
            .unwrap_or_else(|_| {
                // Fallback to a default ID if name generation fails
                self.durable_objects.id_from_name("default").unwrap()
            })
    }
}
