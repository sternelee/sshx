//! Session management for sshx-worker
//!
//! This module provides session state management adapted for Cloudflare Workers,
//! using D1 database for persistence and Durable Objects for real-time coordination.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sshx_core::{IdCounter, Sid, Uid};
use std::collections::HashMap;
use std::sync::Arc;
use worker::*;

use crate::protocol::{WsUser, WsWinsize};
use crate::state::CloudflareServerState;

/// Static metadata for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// Used to validate that clients have the correct encryption key.
    pub encrypted_zeros: Bytes,
    /// Name of the session (human-readable).
    pub name: String,
    /// Password for write access to the session.
    pub write_password_hash: Option<Bytes>,
}

/// In-memory state for a shell within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellState {
    /// Sequence number, indicating how many bytes have been received.
    pub seqnum: u64,
    /// Terminal data chunks.
    pub data: Vec<Bytes>,
    /// Number of pruned data chunks before `data[0]`.
    pub chunk_offset: u64,
    /// Number of bytes in pruned data chunks.
    pub byte_offset: u64,
    /// Set when this shell is terminated.
    pub closed: bool,
    /// Window size and position.
    pub winsize: WsWinsize,
}

impl Default for ShellState {
    fn default() -> Self {
        Self {
            seqnum: 0,
            data: Vec::new(),
            chunk_offset: 0,
            byte_offset: 0,
            closed: false,
            winsize: WsWinsize::default(),
        }
    }
}

/// Session state that can be persisted to D1 and synchronized across workers.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionState {
    /// Session metadata.
    pub metadata: SessionMetadata,
    /// Shell states indexed by shell ID.
    pub shells: HashMap<Sid, ShellState>,
    /// Connected users indexed by user ID.
    pub users: HashMap<Uid, WsUser>,
    /// ID counter for generating new IDs (serialized as individual values).
    #[serde(skip)]
    pub _counter: IdCounter,
    #[serde(skip_serializing, skip_deserializing)]
    pub next_uid_value: u32,
    #[serde(skip_serializing, skip_deserializing)]
    pub next_sid_value: u32,
    /// Last activity timestamp.
    pub last_activity: u64,
}

impl Clone for SessionState {
    fn clone(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
            shells: self.shells.clone(),
            users: self.users.clone(),
            _counter: IdCounter::default(), // Reset counter for clone
            next_uid_value: self.next_uid_value,
            next_sid_value: self.next_sid_value,
            last_activity: self.last_activity,
        }
    }
}

impl SessionState {
    /// Create a new session state.
    pub fn new(metadata: SessionMetadata) -> Self {
        Self {
            metadata,
            shells: HashMap::new(),
            users: HashMap::new(),
            _counter: IdCounter::default(),
            next_uid_value: 0,
            next_sid_value: 0,
            last_activity: js_sys::Date::now() as u64,
        }
    }

    /// Add a new shell to the session.
    pub fn add_shell(&mut self, id: Sid, center: (i32, i32)) -> Result<()> {
        if self.shells.contains_key(&id) {
            return Err(anyhow!("shell already exists with id={}", id));
        }

        let winsize = WsWinsize {
            x: center.0,
            y: center.1,
            ..Default::default()
        };

        let shell_state = ShellState {
            winsize,
            ..Default::default()
        };

        self.shells.insert(id, shell_state);
        self.update_activity();
        Ok(())
    }

    /// Close a shell.
    pub fn close_shell(&mut self, id: Sid) -> Result<()> {
        match self.shells.get_mut(&id) {
            Some(shell) if !shell.closed => {
                shell.closed = true;
                self.update_activity();
                Ok(())
            }
            Some(_) => Ok(()), // Already closed
            None => Err(anyhow!("cannot close shell with id={}, does not exist", id)),
        }
    }

    /// Move a shell to a new position/size.
    pub fn move_shell(&mut self, id: Sid, winsize: Option<WsWinsize>) -> Result<()> {
        match self.shells.get_mut(&id) {
            Some(shell) if !shell.closed => {
                if let Some(new_winsize) = winsize {
                    shell.winsize = new_winsize;
                }
                self.update_activity();
                Ok(())
            }
            Some(_) => Err(anyhow!("cannot move shell with id={}, already closed", id)),
            None => Err(anyhow!("cannot move shell with id={}, does not exist", id)),
        }
    }

    /// Add data to a shell.
    pub fn add_data(&mut self, id: Sid, data: Bytes, seq: u64) -> Result<()> {
        let shell = self
            .shells
            .get_mut(&id)
            .ok_or_else(|| anyhow!("shell with id={} does not exist", id))?;

        if shell.closed {
            return Err(anyhow!("cannot add data to closed shell with id={}", id));
        }

        if seq <= shell.seqnum && seq + data.len() as u64 > shell.seqnum {
            let start = shell.seqnum - seq;
            let segment = data.slice(start as usize..);
            shell.seqnum += segment.len() as u64;
            shell.data.push(segment);

            // Prune old chunks if we've exceeded the maximum stored bytes.
            const SHELL_STORED_BYTES: u64 = 1 << 21; // 2 MiB
            let mut stored_bytes = shell.seqnum - shell.byte_offset;
            if stored_bytes > SHELL_STORED_BYTES {
                let mut offset = 0;
                while offset < shell.data.len() && stored_bytes > SHELL_STORED_BYTES {
                    let bytes = shell.data[offset].len() as u64;
                    stored_bytes -= bytes;
                    shell.chunk_offset += 1;
                    shell.byte_offset += bytes;
                    offset += 1;
                }
                shell.data.drain(..offset);
            }

            self.update_activity();
        }

        Ok(())
    }

    /// Add a user to the session.
    pub fn add_user(&mut self, id: Uid, can_write: bool) -> Result<()> {
        if self.users.contains_key(&id) {
            return Err(anyhow!("user already exists with id={}", id));
        }

        let user = WsUser {
            name: format!("User {}", id),
            cursor: None,
            focus: None,
            can_write,
        };

        self.users.insert(id, user);
        self.update_activity();
        Ok(())
    }

    /// Remove a user from the session.
    pub fn remove_user(&mut self, id: Uid) -> bool {
        let removed = self.users.remove(&id).is_some();
        if removed {
            self.update_activity();
        }
        removed
    }

    /// Update a user's properties.
    pub fn update_user<F>(&mut self, id: Uid, f: F) -> Result<WsUser>
    where
        F: FnOnce(&mut WsUser),
    {
        let user = self
            .users
            .get_mut(&id)
            .ok_or_else(|| anyhow!("user not found"))?;
        f(user);
        let updated_user = user.clone();
        self.update_activity();
        Ok(updated_user)
    }

    /// Get the list of active shells.
    pub fn get_shells(&self) -> Vec<(Sid, WsWinsize)> {
        self.shells
            .iter()
            .filter(|(_, shell)| !shell.closed)
            .map(|(id, shell)| (*id, shell.winsize))
            .collect()
    }

    /// Get the list of users.
    pub fn get_users(&self) -> Vec<(Uid, WsUser)> {
        self.users
            .iter()
            .map(|(id, user)| (*id, user.clone()))
            .collect()
    }

    /// Check if a user has write permission.
    pub fn check_write_permission(&self, user_id: Uid) -> Result<()> {
        let user = self
            .users
            .get(&user_id)
            .ok_or_else(|| anyhow!("user not found"))?;
        if !user.can_write {
            return Err(anyhow!("No write permission"));
        }
        Ok(())
    }

    /// Get chunks for a shell starting from a given chunk number.
    pub fn get_chunks(&self, id: Sid, chunknum: u64) -> Option<(u64, Vec<Bytes>)> {
        let shell = self.shells.get(&id)?;
        if shell.closed {
            return None;
        }

        let current_chunks = shell.chunk_offset + shell.data.len() as u64;
        if chunknum < current_chunks {
            let start = chunknum.saturating_sub(shell.chunk_offset) as usize;
            let mut seqnum = shell.byte_offset;
            seqnum += shell.data[..start]
                .iter()
                .map(|x| x.len() as u64)
                .sum::<u64>();
            let chunks = shell.data[start..].to_vec();
            Some((seqnum, chunks))
        } else {
            Some((shell.seqnum, Vec::new()))
        }
    }

    /// Update the last activity timestamp.
    fn update_activity(&mut self) {
        self.last_activity = js_sys::Date::now() as u64;
    }
}

/// Session manager for Cloudflare Workers.
pub struct SessionManager {
    state: Arc<CloudflareServerState>,
}

impl SessionManager {
    pub fn new(state: Arc<CloudflareServerState>) -> Self {
        Self { state }
    }

    /// Create a new session.
    pub async fn create_session(&self, name: &str, metadata: SessionMetadata) -> Result<()> {
        let db = self.state.db();

        // Check if session already exists
        if db.get_session_by_name(name).await?.is_some() {
            return Err(anyhow!("Session already exists"));
        }

        // Create session in database
        db.create_session(name, None, None, self.state.host())
            .await?;

        // Store session state in KV
        let session_state = SessionState::new(metadata);
        self.save_session_state(name, &session_state).await?;

        Ok(())
    }

    /// Get session state from KV.
    pub async fn get_session_state(&self, name: &str) -> Result<Option<SessionState>> {
        let kv_key = format!("session:{}", name);

        match self.state.kv_store.get(&kv_key).text().await {
            Ok(Some(json_str)) => match serde_json::from_str::<SessionState>(&json_str) {
                Ok(state) => Ok(Some(state)),
                Err(e) => {
                    console_log!("Failed to deserialize session state from KV: {}", e);
                    Ok(None)
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                console_log!("Failed to get session state from KV: {}", e);
                Ok(None)
            }
        }
    }

    /// Save session state to KV.
    pub async fn save_session_state(&self, name: &str, state: &SessionState) -> Result<()> {
        let kv_key = format!("session:{}", name);
        let json_str = serde_json::to_string(state)?;

        // Store in KV with expiration (e.g., 24 hours)
        let expiration_ttl = 24 * 60 * 60;
        let json_len = json_str.len();
        let put_op = match self.state.kv_store.put(&kv_key, json_str) {
            Ok(op) => op,
            Err(e) => return Err(anyhow!("Failed to create KV put operation: {:?}", e)),
        };

        match put_op.expiration_ttl(expiration_ttl).execute().await {
            Ok(_) => {}
            Err(e) => return Err(anyhow!("Failed to store session state in KV: {:?}", e)),
        }

        // Also update activity in D1 for tracking
        let db = self.state.db();
        if let Some(session) = db.get_session_by_name(name).await? {
            db.update_session_activity(&session.id).await?;
        }

        console_log!("Saved session state for {}: {} bytes to KV", name, json_len);

        Ok(())
    }

    /// Close a session.
    pub async fn close_session(&self, name: &str) -> Result<()> {
        let db = self.state.db();

        // Mark session as closed in database
        if let Some(session) = db.get_session_by_name(name).await? {
            if let Some(user_id) = &session.user_id {
                db.close_session(&session.id, user_id).await?;
                console_log!("Closed session: {}", name);
            } else {
                // For sessions without user_id, use a different approach
                console_log!("Cannot close session {} without user_id", name);
            }
        } else {
            console_log!("Session not found for closing: {}", name);
        }

        // Remove session state from KV
        let kv_key = format!("session:{}", name);
        match self.state.kv_store.delete(&kv_key).await {
            Ok(_) => {}
            Err(e) => return Err(anyhow!("Failed to remove session state from KV: {:?}", e)),
        }
        console_log!("Removed session state from KV: {}", name);

        Ok(())
    }

    /// Check if a session exists and is active
    pub async fn is_session_active(&self, name: &str) -> Result<bool> {
        let db = self.state.db();
        if let Some(session) = db.get_session_by_name(name).await? {
            Ok(session.status == crate::db::SessionStatus::Active)
        } else {
            Ok(false)
        }
    }

    /// Get session information including stats
    pub async fn get_session_info(&self, name: &str) -> Result<Option<SessionInfo>> {
        let db = self.state.db();

        if let Some(session) = db.get_session_by_name(name).await? {
            let session_state = self.get_session_state(name).await?;

            let user_count = session_state.as_ref().map(|s| s.users.len()).unwrap_or(0);
            let shell_count = session_state.as_ref().map(|s| s.shells.len()).unwrap_or(0);
            let has_write_password = session_state
                .as_ref()
                .map(|s| s.metadata.write_password_hash.is_some())
                .unwrap_or(false);

            let info = SessionInfo {
                id: session.id,
                name: session.name,
                user_id: session.user_id,
                created_at: session.created_at,
                last_activity: session.last_activity,
                status: session.status,
                user_count,
                shell_count,
                has_write_password,
            };

            Ok(Some(info))
        } else {
            Ok(None)
        }
    }
}

/// Information about a session
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub name: String,
    pub user_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub status: crate::db::SessionStatus,
    pub user_count: usize,
    pub shell_count: usize,
    pub has_write_password: bool,
}
