//! Snapshot and restore sessions from serialized state.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use parking_lot::Mutex;
use prost::Message;
use sshx_core::{
    proto::{SerializedSession, SerializedShell},
    Sid, Uid,
};

use super::{Metadata, Session, State};
use crate::web::protocol::WsWinsize;

/// Persist at most this many bytes of output in storage, per shell.
///
/// Tied to the in-memory rolling buffer cap so a cold-tier round-trip
/// preserves the same scrollback users see when the session is hot.
fn shell_snapshot_bytes() -> u64 {
    *crate::session::SHELL_STORED_BYTES
}

/// Hard cap on the encoded snapshot size before zstd compression.
///
/// Sized for ~16 shells × 2 MiB plus protobuf framing overhead. Real
/// blobs are far smaller after zstd-3 (typical 4-10× ratio on terminal
/// output) but we leave headroom for pathological pre-compression input.
const MAX_SNAPSHOT_SIZE: usize = 64 << 20; // 64 MiB

impl Session {
    /// Snapshot the session, returning a compressed representation.
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        let ids = self.counter.get_current_values();
        let winsizes: BTreeMap<Sid, WsWinsize> = self.source.borrow().iter().cloned().collect();
        let message = SerializedSession {
            encrypted_zeros: self.metadata().encrypted_zeros.clone(),
            shells: self
                .shells
                .read()
                .iter()
                .map(|(sid, shell_arc)| {
                    // Lock each per-shell mutex briefly to read its state.
                    // Snapshot is rare (every 20 s) so contention with
                    // add_data is negligible.
                    let shell = shell_arc.lock();
                    // Prune off data until its total length is at most `SHELL_SNAPSHOT_BYTES`.
                    let mut prefix = 0;
                    let mut chunk_offset = shell.chunk_offset;
                    let mut byte_offset = shell.byte_offset;

                    for i in 0..shell.data.len() {
                        if shell.seqnum - byte_offset > shell_snapshot_bytes() {
                            prefix += 1;
                            chunk_offset += 1;
                            byte_offset += shell.data[i].len() as u64;
                        } else {
                            break;
                        }
                    }

                    let winsize = winsizes.get(sid).cloned().unwrap_or_default();
                    let shell = SerializedShell {
                        seqnum: shell.seqnum,
                        // `Bytes` clones are refcount bumps, no allocation.
                        data: shell.data[prefix..].to_vec(),
                        chunk_offset,
                        byte_offset,
                        closed: shell.closed,
                        winsize_x: winsize.x,
                        winsize_y: winsize.y,
                        winsize_rows: winsize.rows.into(),
                        winsize_cols: winsize.cols.into(),
                    };
                    (sid.0, shell)
                })
                .collect(),
            next_sid: ids.0 .0,
            next_uid: ids.1 .0,
            name: self.metadata().name.clone(),
            write_password_hash: self.metadata().write_password_hash.clone(),
        };
        let data = message.encode_to_vec();
        ensure!(data.len() < MAX_SNAPSHOT_SIZE, "snapshot too large");
        // Level 3 gives ~3-5x faster compression vs level 15 with only
        // ~10-20% larger output. Snapshots are short-lived in Redis, so CPU
        // matters more than ratio.
        Ok(zstd::bulk::compress(&data, 3)?)
    }

    /// Restore the session from a previous compressed snapshot.
    pub fn restore(data: &[u8]) -> Result<Self> {
        let data = zstd::bulk::decompress(data, MAX_SNAPSHOT_SIZE)?;
        let message = SerializedSession::decode(&*data)?;

        let metadata = Metadata {
            encrypted_zeros: message.encrypted_zeros,
            name: message.name,
            write_password_hash: message.write_password_hash,
        };

        let session = Self::new(metadata);
        let mut shells = session.shells.write();
        let mut winsizes = Vec::new();
        for (sid, shell) in message.shells {
            winsizes.push((
                Sid(sid),
                WsWinsize {
                    x: shell.winsize_x,
                    y: shell.winsize_y,
                    rows: shell.winsize_rows.try_into().context("rows overflow")?,
                    cols: shell.winsize_cols.try_into().context("cols overflow")?,
                },
            ));
            let shell = State {
                seqnum: shell.seqnum,
                data: shell.data,
                chunk_offset: shell.chunk_offset,
                byte_offset: shell.byte_offset,
                closed: shell.closed,
                notify: Default::default(),
            };
            shells.insert(Sid(sid), Arc::new(Mutex::new(shell)));
        }
        drop(shells);
        session.source.send_replace(winsizes);
        session
            .counter
            .set_current_values(Sid(message.next_sid), Uid(message.next_uid));

        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::session::{Metadata, Session};

    #[test]
    fn snapshot_preserves_full_rolling_buffer() {
        let session = Session::new(Metadata {
            encrypted_zeros: Bytes::from_static(&[0u8; 16]),
            name: "test".into(),
            write_password_hash: None,
        });
        let sid = session.counter().next_sid();
        session.add_shell(sid, (0, 0)).unwrap();

        // 1 MiB of unique chunks so compression cannot collapse them.
        let chunk = vec![0xABu8; 4096];
        for i in 0..256u64 {
            let mut buf = chunk.clone();
            buf[0..8].copy_from_slice(&i.to_le_bytes());
            session.add_data(sid, Bytes::from(buf), i * 4096).unwrap();
        }

        let blob = session.snapshot().expect("snapshot");
        let restored = Session::restore(&blob).expect("restore");

        // Snapshot must retain the full 1 MiB written above (well above 32 KiB).
        let shells = restored.shells.read();
        let shell = shells.get(&sid).unwrap().lock();
        let total: usize = shell.data.iter().map(|b| b.len()).sum();
        assert!(total >= 1 << 20, "expected >= 1 MiB retained, got {total}");
    }
}
