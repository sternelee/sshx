//! Core session state, ported from sshx-server/session.rs for the Workers environment.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::DerefMut;

use bytes::Bytes;
use js_sys::Date;
use prost::Message;

use crate::protocol::{Sid, Uid, WsUser, WsWinsize};
use crate::generated::sshx as proto;

/// Store a rolling buffer with at most this quantity of output, per shell.
const SHELL_STORED_BYTES: u64 = 1 << 21; // 2 MiB

/// Persist at most this many bytes of output in a snapshot, per shell.
const SHELL_SNAPSHOT_BYTES: u64 = 1 << 15; // 32 KiB

const MAX_SNAPSHOT_SIZE: usize = 1 << 22; // 4 MiB

/// Static metadata for this session.
#[derive(Debug, Clone)]
pub struct Metadata {
    /// Used to validate that clients have the correct encryption key.
    pub encrypted_zeros: Bytes,
    /// Name of the session (human-readable).
    pub name: String,
    /// Password for write access to the session.
    pub write_password_hash: Option<Bytes>,
}

/// Internal state for each shell.
#[derive(Default)]
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
    /// Subscribers waiting for new chunks.
    pub chunk_subscribers: Vec<(u64, Box<dyn FnMut(u64, Vec<Bytes>)>)>,
}

impl std::fmt::Debug for ShellState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShellState")
            .field("seqnum", &self.seqnum)
            .field("data_chunks", &self.data.len())
            .field("chunk_offset", &self.chunk_offset)
            .field("byte_offset", &self.byte_offset)
            .field("closed", &self.closed)
            .field("chunk_subscribers", &self.chunk_subscribers.len())
            .finish()
    }
}

/// In-memory state for a single sshx session.
#[derive(Debug)]
pub struct SessionState {
    /// Static metadata for this session.
    metadata: Metadata,
    /// In-memory state for the session.
    shells: RefCell<HashMap<Sid, ShellState>>,
    /// Metadata for currently connected users.
    users: RefCell<HashMap<Uid, WsUser>>,
    /// Atomic counter to get new, unique IDs.
    counter: IdCounter,
    /// Timestamp of the last backend client message from an active connection.
    last_accessed: RefCell<f64>,
    /// Ordered list of open shells and sizes.
    pub shells_list: RefCell<Vec<(Sid, WsWinsize)>>,
    /// Set when this session has been closed and removed.
    shutdown: RefCell<bool>,
}

/// Counter for generating unique IDs.
#[derive(Debug, Default)]
pub struct IdCounter {
    next_sid: std::sync::atomic::AtomicU32,
    next_uid: std::sync::atomic::AtomicU32,
}

impl IdCounter {
    pub fn next_sid(&self) -> Sid {
        self.next_sid.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
    pub fn next_uid(&self) -> Uid {
        self.next_uid.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
    pub fn get_current_values(&self) -> (Sid, Uid) {
        (
            self.next_sid.load(std::sync::atomic::Ordering::Relaxed),
            self.next_uid.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
    pub fn set_current_values(&self, sid: Sid, uid: Uid) {
        self.next_sid.store(sid, std::sync::atomic::Ordering::Relaxed);
        self.next_uid.store(uid, std::sync::atomic::Ordering::Relaxed);
    }
}

impl SessionState {
    pub fn new(metadata: Metadata) -> Self {
        SessionState {
            metadata,
            shells: RefCell::new(HashMap::new()),
            users: RefCell::new(HashMap::new()),
            counter: IdCounter::default(),
            last_accessed: RefCell::new(Date::now()),
            shells_list: RefCell::new(Vec::new()),
            shutdown: RefCell::new(false),
        }
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn counter(&self) -> &IdCounter {
        &self.counter
    }

    pub fn sequence_numbers(&self) -> proto::SequenceNumbers {
        let shells = self.shells.borrow();
        let mut map = HashMap::with_capacity(shells.len());
        for (key, value) in &*shells {
            if !value.closed {
                map.insert(*key, value.seqnum);
            }
        }
        proto::SequenceNumbers { map }
    }

    pub fn is_shutdown(&self) -> bool {
        *self.shutdown.borrow()
    }

    pub fn shutdown(&self) {
        *self.shutdown.borrow_mut() = true;
    }

    fn chunk_overhead(&self) -> u64 {
        match self.metadata.encrypted_zeros.len() {
            16 => 0,  // v1: AES-128-CTR
            44 => 28, // v2: AES-256-GCM (12-byte nonce + 16-byte tag)
            _ => 0,
        }
    }

    fn plaintext_len(&self, encrypted_len: u64) -> u64 {
        encrypted_len.saturating_sub(self.chunk_overhead())
    }

    pub fn add_shell(&self, id: Sid, center: (i32, i32)) -> anyhow::Result<()> {
        use std::collections::hash_map::Entry::*;
        let mut shells = self.shells.borrow_mut();
        match shells.entry(id) {
            Occupied(_) => anyhow::bail!("shell already exists with id={id}"),
            Vacant(v) => {
                v.insert(ShellState::default());
            }
        }
        drop(shells);
        let mut list = self.shells_list.borrow_mut();
        list.push((id, WsWinsize {
            x: center.0,
            y: center.1,
            ..Default::default()
        }));
        Ok(())
    }

    pub fn close_shell(&self, id: Sid) -> anyhow::Result<()> {
        let mut shells = self.shells.borrow_mut();
        match shells.get_mut(&id) {
            Some(shell) if !shell.closed => {
                shell.closed = true;
                // Notify chunk subscribers that the stream is ending
                for (_, cb) in &mut shell.chunk_subscribers {
                    cb(shell.byte_offset, vec![]);
                }
                shell.chunk_subscribers.clear();
            }
            Some(_) => return Ok(()),
            None => anyhow::bail!("cannot close shell with id={id}, does not exist"),
        }
        drop(shells);
        self.shells_list.borrow_mut().retain(|&(x, _)| x != id);
        Ok(())
    }

    fn get_shell_mut(&self, id: Sid) -> anyhow::Result<impl DerefMut<Target = ShellState> + '_> {
        let shells = self.shells.borrow_mut();
        match shells.get(&id) {
            Some(shell) if !shell.closed => {
                Ok(std::cell::RefMut::map(shells, |s| s.get_mut(&id).unwrap()))
            }
            Some(_) => anyhow::bail!("cannot update shell with id={id}, already closed"),
            None => anyhow::bail!("cannot update shell with id={id}, does not exist"),
        }
    }

    pub fn move_shell(&self, id: Sid, winsize: Option<WsWinsize>) -> anyhow::Result<bool> {
        let _guard = self.get_shell_mut(id)?;
        let mut list = self.shells_list.borrow_mut();
        if let Some(idx) = list.iter().position(|&(sid, _)| sid == id) {
            let (_, oldsize) = list.remove(idx);
            let newsize = winsize.unwrap_or(oldsize);
            let dims_changed = newsize.rows != oldsize.rows || newsize.cols != oldsize.cols;
            list.push((id, newsize));
            Ok(dims_changed)
        } else {
            Ok(false)
        }
    }

    pub fn add_data(&self, id: Sid, data: Bytes, seq: u64) -> anyhow::Result<()> {
        let mut shell = self.get_shell_mut(id)?;
        let overhead = self.chunk_overhead();
        let plaintext_len = self.plaintext_len(data.len() as u64);

        if seq <= shell.seqnum && seq + plaintext_len > shell.seqnum {
            let start = shell.seqnum - seq;
            let (segment, segment_plaintext) = if overhead > 0 {
                if start > 0 {
                    return Ok(());
                }
                (data, plaintext_len)
            } else {
                let seg = data.slice(start as usize..);
                let seg_len = seg.len() as u64;
                (seg, seg_len)
            };
            shell.seqnum += segment_plaintext;
            shell.data.push(segment.clone());

            // Prune old chunks
            let mut stored_bytes = shell.seqnum - shell.byte_offset;
            if stored_bytes > SHELL_STORED_BYTES {
                let mut offset = 0;
                while offset < shell.data.len() && stored_bytes > SHELL_STORED_BYTES {
                    let bytes = self.plaintext_len(shell.data[offset].len() as u64);
                    stored_bytes -= bytes;
                    shell.chunk_offset += 1;
                    shell.byte_offset += bytes;
                    offset += 1;
                }
                shell.data.drain(..offset);
            }

            // Notify subscribers
            let current_chunks = shell.chunk_offset + shell.data.len() as u64;
            let chunk_offset = shell.chunk_offset;
            let byte_offset = shell.byte_offset;
            let shell_data: Vec<Bytes> = shell.data.clone();
            shell.chunk_subscribers.retain_mut(|(chunknum, cb)| {
                if *chunknum < current_chunks {
                    let start = chunknum.saturating_sub(chunk_offset) as usize;
                    let seq_at_start = byte_offset + shell_data[..start]
                        .iter()
                        .map(|x| self.plaintext_len(x.len() as u64))
                        .sum::<u64>();
                    let chunks = shell_data[start..].to_vec();
                    *chunknum = current_chunks;
                    cb(seq_at_start, chunks);
                    true
                } else {
                    true
                }
            });
        }
        Ok(())
    }

    pub fn list_users(&self) -> Vec<(Uid, WsUser)> {
        self.users
            .borrow()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    pub fn update_user(&self, id: Uid, f: impl FnOnce(&mut WsUser)) -> anyhow::Result<WsUser> {
        let mut users = self.users.borrow_mut();
        let user = users.get_mut(&id).ok_or_else(|| anyhow::anyhow!("user not found"))?;
        f(user);
        Ok(user.clone())
    }

    pub fn add_user(&self, id: Uid, can_write: bool) -> anyhow::Result<WsUser> {
        use std::collections::hash_map::Entry::*;
        let mut users = self.users.borrow_mut();
        match users.entry(id) {
            Occupied(_) => anyhow::bail!("user already exists with id={id}"),
            Vacant(v) => {
                let user = WsUser {
                    name: format!("User {id}"),
                    cursor: None,
                    focus: None,
                    can_write,
                };
                v.insert(user.clone());
                Ok(user)
            }
        }
    }

    pub fn remove_user(&self, id: Uid) {
        self.users.borrow_mut().remove(&id);
    }

    pub fn check_write_permission(&self, user_id: Uid) -> anyhow::Result<()> {
        let users = self.users.borrow();
        let user = users.get(&user_id).ok_or_else(|| anyhow::anyhow!("user not found"))?;
        if !user.can_write {
            anyhow::bail!("No write permission");
        }
        Ok(())
    }

    pub fn send_chat(&self, id: Uid, msg: &str) -> anyhow::Result<(String, String)> {
        let users = self.users.borrow();
        let name = users.get(&id).ok_or_else(|| anyhow::anyhow!("user not found"))?.name.clone();
        Ok((name, msg.to_string()))
    }

    pub fn access(&self) {
        *self.last_accessed.borrow_mut() = Date::now();
    }

    pub fn last_accessed(&self) -> f64 {
        *self.last_accessed.borrow()
    }

    pub fn snapshot(&self) -> anyhow::Result<Vec<u8>> {
        let ids = self.counter.get_current_values();
        let winsizes: HashMap<Sid, WsWinsize> = self.shells_list.borrow().iter().cloned().collect();
        let shells = self.shells.borrow();
        let message = proto::SerializedSession {
            encrypted_zeros: self.metadata.encrypted_zeros.to_vec(),
            shells: shells
                .iter()
                .map(|(sid, shell)| {
                    let mut prefix = 0;
                    let mut chunk_offset = shell.chunk_offset;
                    let mut byte_offset = shell.byte_offset;

                    for i in 0..shell.data.len() {
                        if shell.seqnum - byte_offset > SHELL_SNAPSHOT_BYTES {
                            prefix += 1;
                            chunk_offset += 1;
                            byte_offset += self.plaintext_len(shell.data[i].len() as u64);
                        } else {
                            break;
                        }
                    }

                    let winsize = winsizes.get(sid).cloned().unwrap_or_default();
                    let shell = proto::SerializedShell {
                        seqnum: shell.seqnum,
                        data: shell.data[prefix..].iter().map(|b| b.to_vec()).collect(),
                        chunk_offset,
                        byte_offset,
                        closed: shell.closed,
                        winsize_x: winsize.x,
                        winsize_y: winsize.y,
                        winsize_rows: winsize.rows.into(),
                        winsize_cols: winsize.cols.into(),
                    };
                    (*sid, shell)
                })
                .collect(),
            next_sid: ids.0,
            next_uid: ids.1,
            name: self.metadata.name.clone(),
            write_password_hash: self.metadata.write_password_hash.clone().map(|b| b.to_vec()),
        };
        let data = message.encode_to_vec();
        if data.len() >= MAX_SNAPSHOT_SIZE {
            anyhow::bail!("snapshot too large");
        }
        Ok(data)
    }

    pub fn restore(&self, data: &[u8]) -> anyhow::Result<()> {
        let message = proto::SerializedSession::decode(data)?;

        let mut shells = self.shells.borrow_mut();
        let mut winsizes = Vec::new();
        for (sid, shell) in message.shells {
            winsizes.push((
                sid,
                WsWinsize {
                    x: shell.winsize_x,
                    y: shell.winsize_y,
                    rows: shell.winsize_rows.try_into()?,
                    cols: shell.winsize_cols.try_into()?,
                },
            ));
            let state = ShellState {
                seqnum: shell.seqnum,
                data: shell.data.into_iter().map(|v| v.into()).collect(),
                chunk_offset: shell.chunk_offset,
                byte_offset: shell.byte_offset,
                closed: shell.closed,
                chunk_subscribers: vec![],
            };
            shells.insert(sid, state);
        }
        drop(shells);
        *self.shells_list.borrow_mut() = winsizes;
        self.counter
            .set_current_values(message.next_sid, message.next_uid);
        Ok(())
    }

    /// Subscribe to chunks from a shell.
    pub fn subscribe_chunks<F>(&self, id: Sid, mut chunknum: u64, mut callback: F)
    where
        F: FnMut(u64, Vec<Bytes>) + 'static,
    {
        let mut shells = self.shells.borrow_mut();
        let shell = match shells.get_mut(&id) {
            Some(shell) if !shell.closed => shell,
            _ => return,
        };
        let current_chunks = shell.chunk_offset + shell.data.len() as u64;
        if chunknum < current_chunks {
            let start = chunknum.saturating_sub(shell.chunk_offset) as usize;
            let seqnum = shell.byte_offset + shell.data[..start]
                .iter()
                .map(|x| self.plaintext_len(x.len() as u64))
                .sum::<u64>();
            let chunks = shell.data[start..].to_vec();
            chunknum = current_chunks;
            drop(shells);
            callback(seqnum, chunks);
            // Re-borrow to insert subscriber for future chunks
            let mut shells = self.shells.borrow_mut();
            if let Some(shell) = shells.get_mut(&id) {
                if !shell.closed {
                    shell.chunk_subscribers.push((chunknum, Box::new(callback)));
                }
            }
        } else {
            shell.chunk_subscribers.push((chunknum, Box::new(callback)));
        }
    }
}
