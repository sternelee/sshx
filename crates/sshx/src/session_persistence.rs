//! Session persistence for sshx client to maintain consistent URLs across restarts.

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Persistent session information that can be restored across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Unique session identifier based on stable factors.
    pub session_id: String,
    /// Encryption key for the session.
    pub encryption_key: String,
    /// Write password for read-only mode (if enabled).
    pub write_password: Option<String>,
    /// Session name returned by server.
    pub session_name: String,
    /// Session token for authentication.
    pub session_token: String,
    /// Base URL without encryption key.
    pub base_url: String,
    /// Full session URL with encryption key.
    pub full_url: String,
    /// Write URL (if read-only mode is enabled).
    pub write_url: Option<String>,
    /// Server origin.
    pub server_origin: String,
    /// API key used (if any).
    pub api_key: Option<String>,
    /// Timestamp when session was created.
    pub created_at: u64,
    /// Timestamp when session was last accessed.
    pub last_accessed: u64,
}

/// Session persistence manager.
pub struct SessionPersistence {
    /// Directory to store session files.
    session_dir: PathBuf,
}

impl SessionPersistence {
    /// Create a new session persistence manager.
    pub fn new() -> Result<Self> {
        let session_dir = Self::get_session_dir()?;
        fs::create_dir_all(&session_dir)
            .with_context(|| format!("Failed to create session directory: {:?}", session_dir))?;

        Ok(Self { session_dir })
    }

    /// Generate a stable session identifier based on execution context.
    pub fn generate_session_id(
        api_key: Option<&str>,
        server_origin: &str,
        working_dir: Option<&Path>,
    ) -> String {
        let mut hasher = DefaultHasher::new();

        // Hash API key (most important for user sessions)
        if let Some(key) = api_key {
            key.hash(&mut hasher);
        }

        // Hash server origin
        server_origin.hash(&mut hasher);

        // Hash working directory
        let work_dir = working_dir
            .or_else(|| std::env::current_dir().ok().as_deref())
            .unwrap_or_else(|| Path::new("."));
        work_dir.hash(&mut hasher);

        // Hash hostname for additional uniqueness
        if let Ok(hostname) = whoami::fallible::hostname() {
            hostname.hash(&mut hasher);
        }

        // Hash username
        whoami::username().hash(&mut hasher);

        format!("sshx-{:016x}", hasher.finish())
    }

    /// Save session state to disk.
    pub fn save_session(&self, state: &SessionState) -> Result<()> {
        let file_path = self.session_dir.join(format!("{}.json", state.session_id));
        let json_data = serde_json::to_string_pretty(state)
            .context("Failed to serialize session state")?;

        fs::write(&file_path, json_data)
            .with_context(|| format!("Failed to write session file: {:?}", file_path))?;

        debug!("Session state saved to {:?}", file_path);
        Ok(())
    }

    /// Load session state from disk.
    pub fn load_session(&self, session_id: &str) -> Result<Option<SessionState>> {
        let file_path = self.session_dir.join(format!("{}.json", session_id));

        if !file_path.exists() {
            return Ok(None);
        }

        let json_data = fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read session file: {:?}", file_path))?;

        let mut state: SessionState = serde_json::from_str(&json_data)
            .with_context(|| format!("Failed to parse session file: {:?}", file_path))?;

        // Update last accessed time
        state.last_accessed = chrono::Utc::now().timestamp() as u64;

        debug!("Session state loaded from {:?}", file_path);
        Ok(Some(state))
    }

    /// Remove session state from disk.
    pub fn remove_session(&self, session_id: &str) -> Result<()> {
        let file_path = self.session_dir.join(format!("{}.json", session_id));

        if file_path.exists() {
            fs::remove_file(&file_path)
                .with_context(|| format!("Failed to remove session file: {:?}", file_path))?;
            debug!("Session state removed: {:?}", file_path);
        }

        Ok(())
    }

    /// List all stored sessions.
    pub fn list_sessions(&self) -> Result<Vec<SessionState>> {
        let mut sessions = Vec::new();

        if !self.session_dir.exists() {
            return Ok(sessions);
        }

        let entries = fs::read_dir(&self.session_dir)
            .with_context(|| format!("Failed to read session directory: {:?}", self.session_dir))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(Some(session)) = self.load_session(stem) {
                        sessions.push(session);
                    }
                }
            }
        }

        // Sort by last accessed time (most recent first)
        sessions.sort_by(|a, b| b.last_accessed.cmp(&a.last_accessed));

        Ok(sessions)
    }

    /// Clean up old session files (older than specified days).
    pub fn cleanup_old_sessions(&self, max_age_days: u64) -> Result<usize> {
        let cutoff_time = chrono::Utc::now().timestamp() as u64 - (max_age_days * 24 * 60 * 60);
        let sessions = self.list_sessions()?;
        let mut removed_count = 0;

        for session in sessions {
            if session.last_accessed < cutoff_time {
                if let Err(err) = self.remove_session(&session.session_id) {
                    warn!("Failed to remove old session {}: {}", session.session_id, err);
                } else {
                    removed_count += 1;
                    info!("Removed old session: {}", session.session_id);
                }
            }
        }

        Ok(removed_count)
    }

    /// Get the session storage directory.
    fn get_session_dir() -> Result<PathBuf> {
        let base_dir = if let Some(config_dir) = dirs::config_dir() {
            config_dir
        } else if let Some(home_dir) = dirs::home_dir() {
            home_dir.join(".config")
        } else {
            PathBuf::from(".")
        };

        Ok(base_dir.join("sshx").join("sessions"))
    }

    /// Check if a session is still valid (not too old).
    pub fn is_session_valid(&self, state: &SessionState, max_age_hours: u64) -> bool {
        let max_age_seconds = max_age_hours * 60 * 60;
        let current_time = chrono::Utc::now().timestamp() as u64;

        current_time.saturating_sub(state.created_at) <= max_age_seconds
    }
}

impl Default for SessionPersistence {
    fn default() -> Self {
        Self::new().expect("Failed to create session persistence")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_session_id_generation() {
        let api_key = Some("test-api-key");
        let server = "http://localhost:3000";
        let work_dir = Some(Path::new("/tmp/test"));

        let id1 = SessionPersistence::generate_session_id(api_key, server, work_dir);
        let id2 = SessionPersistence::generate_session_id(api_key, server, work_dir);

        // Same inputs should generate same ID
        assert_eq!(id1, id2);

        // Different API key should generate different ID
        let id3 = SessionPersistence::generate_session_id(Some("different-key"), server, work_dir);
        assert_ne!(id1, id3);

        // Different server should generate different ID
        let id4 = SessionPersistence::generate_session_id(api_key, "http://different.com", work_dir);
        assert_ne!(id1, id4);
    }

    #[test]
    fn test_session_state_serialization() {
        let state = SessionState {
            session_id: "test-session".to_string(),
            encryption_key: "test-key".to_string(),
            write_password: Some("write-pass".to_string()),
            session_name: "test-name".to_string(),
            session_token: "test-token".to_string(),
            base_url: "http://example.com/s/test".to_string(),
            full_url: "http://example.com/s/test#key".to_string(),
            write_url: Some("http://example.com/s/test#key,write".to_string()),
            server_origin: "http://example.com".to_string(),
            api_key: Some("api-key".to_string()),
            created_at: 1640995200,
            last_accessed: 1640995300,
        };

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: SessionState = serde_json::from_str(&json).unwrap();

        assert_eq!(state.session_id, deserialized.session_id);
        assert_eq!(state.encryption_key, deserialized.encryption_key);
        assert_eq!(state.api_key, deserialized.api_key);
    }
}