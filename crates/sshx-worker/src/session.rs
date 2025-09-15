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
    pub fn update_activity(&mut self) {
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

    /// Handle terminal data from client
    pub async fn handle_terminal_data(
        &self,
        session_name: &str,
        shell_id: Sid,
        data: Bytes,
        seq: u64,
    ) -> Result<()> {
        let mut session_state = match self.get_session_state(session_name).await? {
            Some(state) => state,
            None => return Err(anyhow!("Session not found: {}", session_name)),
        };

        session_state.add_data(shell_id, data.clone(), seq)?;
        self.save_session_state(session_name, &session_state)
            .await?;

        console_log!(
            "Terminal data processed for session {}, shell {}: {} bytes at seq {}",
            session_name,
            shell_id,
            data.len(),
            seq
        );

        Ok(())
    }

    /// Handle shell creation
    pub async fn handle_shell_create(&self, session_name: &str, x: i32, y: i32) -> Result<Sid> {
        let mut session_state = match self.get_session_state(session_name).await? {
            Some(state) => state,
            None => return Err(anyhow!("Session not found: {}", session_name)),
        };

        let shell_id = session_state._counter.next_sid();
        session_state.add_shell(shell_id, (x, y))?;
        self.save_session_state(session_name, &session_state)
            .await?;

        console_log!(
            "Shell created for session {}: ID {} at position ({}, {})",
            session_name,
            shell_id,
            x,
            y
        );

        Ok(shell_id)
    }

    /// Handle shell closure
    pub async fn handle_shell_close(&self, session_name: &str, shell_id: Sid) -> Result<()> {
        let mut session_state = match self.get_session_state(session_name).await? {
            Some(state) => state,
            None => return Err(anyhow!("Session not found: {}", session_name)),
        };

        session_state.close_shell(shell_id)?;
        self.save_session_state(session_name, &session_state)
            .await?;

        console_log!("Shell closed for session {}: ID {}", session_name, shell_id);

        Ok(())
    }

    /// Handle shell movement/resizing
    pub async fn handle_shell_move(
        &self,
        session_name: &str,
        shell_id: Sid,
        winsize: Option<WsWinsize>,
    ) -> Result<()> {
        let mut session_state = match self.get_session_state(session_name).await? {
            Some(state) => state,
            None => return Err(anyhow!("Session not found: {}", session_name)),
        };

        session_state.move_shell(shell_id, winsize)?;
        self.save_session_state(session_name, &session_state)
            .await?;

        console_log!("Shell moved for session {}: ID {}", session_name, shell_id);

        Ok(())
    }

    /// Handle user joining a session
    pub async fn handle_user_join(
        &self,
        session_name: &str,
        user_id: Uid,
        can_write: bool,
    ) -> Result<()> {
        let mut session_state = match self.get_session_state(session_name).await? {
            Some(state) => state,
            None => return Err(anyhow!("Session not found: {}", session_name)),
        };

        session_state.add_user(user_id, can_write)?;
        self.save_session_state(session_name, &session_state)
            .await?;

        console_log!(
            "User {} joined session {} with write permission: {}",
            user_id,
            session_name,
            can_write
        );

        Ok(())
    }

    /// Handle user leaving a session
    pub async fn handle_user_leave(&self, session_name: &str, user_id: Uid) -> Result<()> {
        let mut session_state = match self.get_session_state(session_name).await? {
            Some(state) => state,
            None => return Err(anyhow!("Session not found: {}", session_name)),
        };

        let removed = session_state.remove_user(user_id);
        if removed {
            self.save_session_state(session_name, &session_state)
                .await?;
            console_log!("User {} left session {}", user_id, session_name);
        }

        Ok(())
    }

    /// Handle chat message
    pub async fn handle_chat_message(
        &self,
        session_name: &str,
        user_id: Uid,
        message: String,
    ) -> Result<String> {
        let session_state = match self.get_session_state(session_name).await? {
            Some(state) => state,
            None => return Err(anyhow!("Session not found: {}", session_name)),
        };

        let user_name = session_state
            .users
            .get(&user_id)
            .map(|u| u.name.clone())
            .unwrap_or_else(|| format!("User {}", user_id));

        console_log!(
            "Chat message from {} in session {}: {}",
            user_name,
            session_name,
            message
        );

        Ok(user_name)
    }

    /// Get terminal data chunks for a shell
    pub async fn get_shell_chunks(
        &self,
        session_name: &str,
        shell_id: Sid,
        chunknum: u64,
    ) -> Result<Option<(u64, Vec<Bytes>)>> {
        let session_state = match self.get_session_state(session_name).await? {
            Some(state) => state,
            None => return Err(anyhow!("Session not found: {}", session_name)),
        };

        Ok(session_state.get_chunks(shell_id, chunknum))
    }

    /// Broadcast session update to all connected clients
    pub async fn broadcast_session_update(&self, session_name: &str) -> Result<()> {
        let session_state = match self.get_session_state(session_name).await? {
            Some(state) => state,
            None => return Err(anyhow!("Session not found: {}", session_name)),
        };

        // Get Durable Object for this session
        let _durable_object = self.state.durable_object(session_name);

        // In a real implementation, this would send messages to all connected WebSocket clients
        // through the Durable Object's broadcast capability
        console_log!(
            "Broadcasting session update for {}: {} users, {} shells",
            session_name,
            session_state.users.len(),
            session_state.shells.len()
        );

        Ok(())
    }

    /// Clean up inactive sessions
    pub async fn cleanup_inactive_sessions(&self, max_age_hours: u64) -> Result<Vec<String>> {
        let db = self.state.db();
        let mut cleaned_sessions = Vec::new();

        // Get all sessions
        let sessions = db.get_all_sessions().await?;
        let now = js_sys::Date::now() as u64;
        let max_age_ms = max_age_hours * 60 * 60 * 1000;

        for session in sessions {
            if session.status == crate::db::SessionStatus::Active {
                let session_state = self.get_session_state(&session.name).await?;

                if let Some(state) = session_state {
                    // Check if session is inactive
                    if now - state.last_activity > max_age_ms {
                        console_log!("Cleaning up inactive session: {}", session.name);
                        self.close_session(&session.name).await?;
                        cleaned_sessions.push(session.name);
                    }
                }
            }
        }

        console_log!("Cleaned up {} inactive sessions", cleaned_sessions.len());
        Ok(cleaned_sessions)
    }

    /// Get session statistics
    pub async fn get_session_stats(&self) -> Result<SessionStats> {
        let db = self.state.db();
        let sessions = db.get_all_sessions().await?;

        let mut active_sessions = 0;
        let mut total_users = 0;
        let mut total_shells = 0;
        let mut recently_active = 0;

        let now = js_sys::Date::now() as u64;
        let recent_threshold = now - (5 * 60 * 1000); // 5 minutes ago

        for session in sessions {
            if session.status == crate::db::SessionStatus::Active {
                active_sessions += 1;

                if let Ok(session_state) = self.get_session_state(&session.name).await {
                    if let Some(state) = session_state {
                        total_users += state.users.len();
                        total_shells += state.shells.len();

                        if state.last_activity > recent_threshold {
                            recently_active += 1;
                        }
                    }
                }
            }
        }

        Ok(SessionStats {
            active_sessions,
            total_users,
            total_shells,
            recently_active,
        })
    }

    /// Create a session snapshot for persistence
    pub async fn create_session_snapshot(&self, session_name: &str) -> Result<SessionSnapshot> {
        // Get session state from KV
        let session_state = self
            .get_session_state(session_name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_name))?;

        // Serialize the session state
        let snapshot_data = serde_json::to_vec(&session_state)
            .map_err(|e| anyhow::anyhow!("Failed to serialize session state: {}", e))?;

        Ok(SessionSnapshot::new(
            session_name.to_string(),
            snapshot_data,
        ))
    }

    /// Restore a session from a snapshot
    pub async fn restore_session_from_snapshot(&self, snapshot: SessionSnapshot) -> Result<()> {
        // Deserialize session state
        let session_state: SessionState = serde_json::from_slice(&snapshot.snapshot_data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize session snapshot: {}", e))?;

        // Restore session state to KV
        self.save_session_state(&snapshot.session_id, &session_state)
            .await?;

        // Update session activity in database
        let db = self.state.db();
        db.update_session_activity(&snapshot.session_id).await?;

        console_log!("Session restored from snapshot: {}", snapshot.session_id);
        Ok(())
    }

    /// List available session snapshots for a session
    pub async fn list_session_snapshots(
        &self,
        _session_name: &str,
    ) -> Result<Vec<SessionSnapshot>> {
        // This would query D1 or KV for stored snapshots
        // For now, return empty vector as placeholder
        Ok(Vec::new())
    }

    /// Delete old session snapshots to save space
    pub async fn cleanup_old_snapshots(
        &self,
        _session_name: &str,
        _max_age_hours: u64,
    ) -> Result<usize> {
        // This would delete snapshots older than max_age_hours
        // For now, return 0 as placeholder
        Ok(0)
    }
}

/// Session snapshot for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub id: String,
    pub session_id: String,
    pub snapshot_data: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub version: u32,
}

impl SessionSnapshot {
    pub fn new(session_id: String, snapshot_data: Vec<u8>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            session_id,
            snapshot_data,
            created_at: chrono::Utc::now(),
            version: 1,
        }
    }
}

/// Session statistics
#[derive(Debug, Clone, Serialize)]
pub struct SessionStats {
    pub active_sessions: usize,
    pub total_users: usize,
    pub total_shells: usize,
    pub recently_active: usize,
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
