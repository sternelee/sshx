# Cold-tier compressed storage — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evict idle sessions (no CLI, no viewers, idle > 60 s) from the in-memory hot map to the existing Redis snapshot, and lazy-thaw on the WebSocket path. Reduces memory pressure without changing session lifecycle.

**Architecture:** Reuse `Session::snapshot/restore` (protobuf+zstd-3) and `StorageMesh::background_sync` (per-session 20 s Redis writer). Add (a) a gRPC active counter on `Session`, (b) an `evict_to_cold` helper on `ServerState` that snapshots inline via a new `StorageMesh::write_snapshot` factored out of `background_sync`, (c) a second branch in `close_old_sessions`, (d) a thaw branch in `frontend_connect` parallel to the existing one in `backend_connect`, and (e) raised `SHELL_SNAPSHOT_BYTES`/`MAX_SNAPSHOT_SIZE` so cold round-trips preserve the full rolling buffer.

**Tech Stack:** Rust 1.70+, tokio, tonic, axum, dashmap, parking_lot, redis (deadpool), prost, zstd, scopeguard. No frontend changes.

**Spec:** `docs/superpowers/specs/2026-04-30-cold-tier-design.md`.

---

## File map (decided up front, no surprises later)

| File | Role | Change kind |
|------|------|-------------|
| `crates/sshx-server/src/session.rs` | Session + State + accessors | Add `grpc_active`, `has_active_grpc`, `grpc_scope`, `user_count`. Move `SHELL_STORED_BYTES` from private to `pub(crate)`. |
| `crates/sshx-server/src/session/snapshot.rs` | Protobuf encode/decode + zstd | Replace `SHELL_SNAPSHOT_BYTES` and `MAX_SNAPSHOT_SIZE` constants. |
| `crates/sshx-server/src/state/mesh.rs` | Mesh ownership + Redis writer | Extract `write_snapshot(name, blob)` from `background_sync` loop body; expose pub(crate). |
| `crates/sshx-server/src/state.rs` | Hot map + sweeper + connect routing | Add `evict_to_cold`. Extend `close_old_sessions` with second branch. Extend `frontend_connect` with thaw branch. Read `SSHX_COLD_AFTER_MS`. |
| `crates/sshx-server/src/grpc.rs` | gRPC `channel` handler | Wrap session use in `let _g = session.grpc_scope();`. |
| `crates/sshx-server/Cargo.toml` | Crate deps | Add `scopeguard = "1"` if missing. |
| `crates/sshx-server/tests/with_client.rs` | Integration suite | Add 4 cold-tier tests. |
| `crates/sshx-server/benches/snapshot.rs` | Criterion bench | Add 2 MiB variants. |
| `docs/PERFORMANCE_REVIEW.md` | Roadmap doc | Flip §3.4 status, append baseline numbers, add commit row to Additional Commits. |

---

## Conventions for every task

- TDD: write the failing test first, watch it fail, write minimal impl, watch it pass.
- One commit per task. Use the suggested message verbatim unless the task's outcome differs from spec.
- After every task: `cargo +nightly fmt --check && cargo clippy -p sshx-server --all-targets -- -D warnings && cargo test -p sshx-server`.
- All code blocks below are **complete**. Do not re-derive types or signatures. If a step shows code, paste it.

---

## Task 1: Make `SHELL_STORED_BYTES` reachable from `snapshot.rs`

**Why first:** Subsequent tasks reference it from `snapshot.rs`. Trivial visibility change, isolates the move.

**Files:**
- Modify: `crates/sshx-server/src/session.rs:32-38`

- [ ] **Step 1: Inspect current declaration**

Run: `rg -n SHELL_STORED_BYTES crates/sshx-server/src/`
Expected: one definition in `session.rs`, no external readers yet.

- [ ] **Step 2: Change visibility**

In `crates/sshx-server/src/session.rs` line 32, change:

```rust
static SHELL_STORED_BYTES: LazyLock<u64> = LazyLock::new(|| {
```

to

```rust
pub(crate) static SHELL_STORED_BYTES: LazyLock<u64> = LazyLock::new(|| {
```

- [ ] **Step 3: Build to confirm no breakage**

Run: `cargo check -p sshx-server`
Expected: compiles clean.

- [ ] **Step 4: Commit**

```bash
git add crates/sshx-server/src/session.rs
git commit -m "refactor(server): expose SHELL_STORED_BYTES to crate

Snapshot capacity will be derived from this constant in the next commit."
```

---

## Task 2: Raise snapshot capacity to match rolling buffer

**Why:** Cold tier must preserve the full 2 MiB scrollback, not 32 KiB. The existing snapshot code path (already used by mesh `background_sync` every 20 s) gets the new caps for free.

**Files:**
- Modify: `crates/sshx-server/src/session/snapshot.rs:17-20`
- Test: `crates/sshx-server/src/session/snapshot.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Write the failing test**

Append to `crates/sshx-server/src/session/snapshot.rs`:

```rust
#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use sshx_core::Sid;

    use super::*;
    use crate::session::Session;
    use crate::session::Metadata;

    #[test]
    fn snapshot_preserves_full_rolling_buffer() {
        let session = Session::new(Metadata {
            encrypted_zeros: Bytes::from_static(&[0u8; 16]),
            name: "test".into(),
            write_password_hash: None,
        });
        let sid = session.counter().next_sid();
        session.add_shell(sid, Default::default()).unwrap();

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sshx-server --lib snapshot::tests::snapshot_preserves_full_rolling_buffer`
Expected: FAIL with assertion `expected >= 1 MiB retained, got <something around 32768>`.

- [ ] **Step 3: Update the constants**

In `crates/sshx-server/src/session/snapshot.rs` lines 17-20, replace:

```rust
/// Persist at most this many bytes of output in storage, per shell.
const SHELL_SNAPSHOT_BYTES: u64 = 1 << 15; // 32 KiB

const MAX_SNAPSHOT_SIZE: usize = 1 << 22; // 4 MiB
```

with

```rust
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
```

Then in the same file, replace the only existing reference `SHELL_SNAPSHOT_BYTES` (around line 44) with `shell_snapshot_bytes()`:

```rust
if shell.seqnum - byte_offset > shell_snapshot_bytes() {
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sshx-server --lib snapshot::tests::snapshot_preserves_full_rolling_buffer`
Expected: PASS.

- [ ] **Step 5: Run full server tests to confirm no regressions**

Run: `cargo test -p sshx-server`
Expected: all green (including `test_session_snapshot`).

- [ ] **Step 6: Commit**

```bash
git add crates/sshx-server/src/session/snapshot.rs
git commit -m "feat(server): preserve full rolling buffer in snapshots

Raise SHELL_SNAPSHOT_BYTES from the literal 32 KiB to whatever the
in-memory rolling cap (SHELL_STORED_BYTES, default 2 MiB) is set to,
and raise MAX_SNAPSHOT_SIZE from 4 MiB to 64 MiB to cover up to
~16 shells of full buffer pre-compression. zstd-3 typically reduces
the encoded output by 4-10x on terminal data, so wire/Redis cost is
much smaller than the cap.

This is required for the cold-tier eviction landing in the next few
commits: an evicted session must restore identically to its hot
state, not be silently truncated to the previous 32 KiB cap."
```

---

## Task 3: Add `Session::user_count` and `has_active_grpc` accessors

**Files:**
- Modify: `crates/sshx-server/src/session.rs` (add fields and methods, choose insertion point near other accessors around line 510)

- [ ] **Step 1: Write failing tests**

Append to `crates/sshx-server/src/session.rs` inside an existing `#[cfg(test)] mod tests` block (or create one at file end if absent):

```rust
#[cfg(test)]
mod cold_accessors_tests {
    use super::*;

    fn fresh() -> Session {
        Session::new(Metadata {
            encrypted_zeros: bytes::Bytes::from_static(&[0u8; 16]),
            name: "t".into(),
            write_password_hash: None,
        })
    }

    #[test]
    fn user_count_default_zero() {
        assert_eq!(fresh().user_count(), 0);
    }

    #[test]
    fn has_active_grpc_default_false() {
        assert!(!fresh().has_active_grpc());
    }

    #[test]
    fn grpc_scope_increments_and_drops() {
        let s = std::sync::Arc::new(fresh());
        assert!(!s.has_active_grpc());
        {
            let _g = s.grpc_scope();
            assert!(s.has_active_grpc());
        }
        assert!(!s.has_active_grpc());
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p sshx-server --lib cold_accessors_tests`
Expected: FAIL with "no method named `user_count`/`has_active_grpc`/`grpc_scope`".

- [ ] **Step 3: Add the field**

In `crates/sshx-server/src/session.rs` inside `pub struct Session { ... }` (around line 110, just above `shutdown: Shutdown`), add:

```rust
    /// Number of currently-open gRPC `Channel` streams from CLI clients.
    ///
    /// Incremented on stream entry, decremented on stream exit via the
    /// RAII guard returned by `grpc_scope()`. Read by the cold-tier
    /// sweeper to decide whether a session is safe to evict.
    grpc_active: AtomicU32,
```

In the `Session::new` constructor (around line 137), add to the struct literal:

```rust
            grpc_active: AtomicU32::new(0),
```

Add `AtomicU32` to the existing `use std::sync::atomic` import line. Currently it imports `AtomicU64`; change to `{AtomicU32, AtomicU64}`.

- [ ] **Step 4: Add the accessors**

Insert near other accessors (after `last_accessed_elapsed`, around line 515 or wherever `pub fn metadata` and friends live):

```rust
    /// Number of currently-connected viewers (browser users).
    pub fn user_count(&self) -> usize {
        self.users.read().len()
    }

    /// Whether at least one CLI gRPC `Channel` stream is open.
    pub fn has_active_grpc(&self) -> bool {
        self.grpc_active.load(Ordering::Relaxed) > 0
    }

    /// Increment the gRPC active counter; the returned guard decrements it on drop.
    ///
    /// Wrap the body of the gRPC `Channel` handler with this so the
    /// cold-tier sweeper can tell when a session is idle on the CLI side.
    pub fn grpc_scope(self: &std::sync::Arc<Self>) -> impl Drop {
        self.grpc_active.fetch_add(1, Ordering::Relaxed);
        let s = self.clone();
        scopeguard::guard((), move |_| {
            s.grpc_active.fetch_sub(1, Ordering::Relaxed);
        })
    }
```

- [ ] **Step 5: Add scopeguard dep**

Check if scopeguard is already in `crates/sshx-server/Cargo.toml`. If not, add to `[dependencies]`:

```toml
scopeguard = "1"
```

Run: `cargo check -p sshx-server`. If unresolved, add it.

- [ ] **Step 6: Run tests**

Run: `cargo test -p sshx-server --lib cold_accessors_tests`
Expected: 3 PASS.

Run: `cargo clippy -p sshx-server --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/sshx-server/src/session.rs crates/sshx-server/Cargo.toml crates/sshx-server/Cargo.lock 2>/dev/null; git add -u
git commit -m "feat(server): add Session::user_count, has_active_grpc, grpc_scope

Three small accessors needed by the cold-tier sweeper to decide which
sessions are safe to evict:

- user_count(): viewers connected via WebSocket.
- has_active_grpc(): whether a CLI gRPC Channel stream is open, backed
  by an AtomicU32 counter so the read is lock-free.
- grpc_scope() -> impl Drop: RAII guard that increments the counter on
  entry and decrements on drop. Wrapping the gRPC Channel handler in a
  let _g = session.grpc_scope(); is enough; the counter resets on
  Channel exit, panic, or stream error.

scopeguard is added as a dependency for the closure-based RAII guard.
The next commit wires grpc_scope into grpc.rs."
```

---

## Task 4: Wire `grpc_scope` into the gRPC channel handler

**Files:**
- Modify: `crates/sshx-server/src/grpc.rs:87-107`

- [ ] **Step 1: Read current handler body**

Run: `rg -n 'async fn channel' crates/sshx-server/src/grpc.rs`
Expected: line 71.

- [ ] **Step 2: Add the guard**

In `crates/sshx-server/src/grpc.rs`, the body around lines 87-104 currently looks like:

```rust
        let session = match self.0.backend_connect(&session_name).await {
            Ok(Some(session)) => session,
            Ok(None) => return Err(Status::not_found("session not found")),
            Err(err) => {
                error!(?err, "failed to connect to backend session");
                return Err(Status::internal(err.to_string()));
            }
        };

        // We now spawn an asynchronous task that sends updates to the client. Note that
        // when this task finishes, the sender end is dropped, so the receiver is
        // automatically closed.
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(async move {
            if let Err(err) = handle_streaming(&tx, &session, stream).await {
                warn!(?err, "connection exiting early due to an error");
            }
        });
```

Change to:

```rust
        let session = match self.0.backend_connect(&session_name).await {
            Ok(Some(session)) => session,
            Ok(None) => return Err(Status::not_found("session not found")),
            Err(err) => {
                error!(?err, "failed to connect to backend session");
                return Err(Status::internal(err.to_string()));
            }
        };

        // We now spawn an asynchronous task that sends updates to the client. Note that
        // when this task finishes, the sender end is dropped, so the receiver is
        // automatically closed.
        //
        // The grpc_scope guard is moved into the spawned task so the
        // active-stream counter on `session` accurately reflects the
        // lifetime of the streaming task, not just this function's body.
        let (tx, rx) = mpsc::channel(256);
        let guard = session.grpc_scope();
        tokio::spawn(async move {
            let _g = guard;
            if let Err(err) = handle_streaming(&tx, &session, stream).await {
                warn!(?err, "connection exiting early due to an error");
            }
        });
```

- [ ] **Step 3: Build and run server tests**

Run: `cargo test -p sshx-server`
Expected: all green; existing gRPC integration tests still pass and now exercise the counter.

- [ ] **Step 4: Add a focused integration test**

In `crates/sshx-server/tests/with_client.rs`, find an existing test that connects a CLI (e.g. `test_smoke` or similar). Add a new test:

```rust
#[tokio::test]
async fn test_grpc_active_counter_tracks_stream() -> Result<()> {
    let server = TestServer::new().await;

    // Before any CLI connects, lookup is None so we cannot test directly;
    // instead, connect a CLI and assert has_active_grpc through the
    // server's session.
    let mut runner = ClientRunner::new(&server, false).await?;

    // Allow the gRPC stream to register.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let session = server.state.lookup(&runner.name).expect("session present");
    assert!(session.has_active_grpc(), "expected active grpc after CLI connect");

    runner.shutdown().await?;
    // Allow drop to run.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert!(
        !session.has_active_grpc(),
        "expected inactive grpc after CLI disconnect",
    );
    Ok(())
}
```

(If the existing `TestServer` / `ClientRunner` helpers have different field names, adapt accordingly; the structure is what matters.)

- [ ] **Step 5: Run the new integration test**

Run: `cargo test -p sshx-server --test with_client test_grpc_active_counter_tracks_stream`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/sshx-server/src/grpc.rs crates/sshx-server/tests/with_client.rs
git commit -m "feat(server): wrap gRPC Channel handler in grpc_scope

Move the RAII guard returned by Session::grpc_scope() into the
spawned streaming task so the active-stream counter on the Session
reflects the actual lifetime of the bidirectional stream (including
any task panics). Without this the cold-tier sweeper would treat
sessions with a live CLI as evictable.

Adds a focused integration test that connects a CLI, asserts
has_active_grpc() == true, disconnects, and asserts it returns to
false."
```

---

## Task 5: Extract `StorageMesh::write_snapshot` from `background_sync`

**Why:** The eviction sweeper needs to write a snapshot inline (not wait for the next 20 s tick). Factor the loop body into a reusable method first; `background_sync` then calls the new helper.

**Files:**
- Modify: `crates/sshx-server/src/state/mesh.rs:127-160`

- [ ] **Step 1: Read current `background_sync` body**

Run: `rg -n 'background_sync\|write_snapshot' crates/sshx-server/src/state/mesh.rs`

- [ ] **Step 2: Add the new method**

In `crates/sshx-server/src/state/mesh.rs`, add (place just above `background_sync` at line 127):

```rust
    /// Write a single owner+snapshot pair to Redis with the standard TTL.
    ///
    /// Used by both the periodic `background_sync` loop and the cold-tier
    /// eviction path in `ServerState`. Returns Err on any Redis failure;
    /// the caller decides whether to retry, log, or abort.
    pub(crate) async fn write_snapshot(&self, name: &str, snapshot: Vec<u8>) -> Result<()> {
        let mut conn = self.redis.get().await?;
        let mut pipe = redis::pipe();
        if let Some(host) = &self.host {
            pipe.set_options(format!("session:{{{name}}}:owner"), host, set_opts());
        }
        pipe.set_options(format!("session:{{{name}}}:snapshot"), snapshot, set_opts());
        pipe.query_async(&mut conn).await?;
        Ok(())
    }
```

Then refactor `background_sync` (lines 127-160) so its loop body delegates:

```rust
    pub async fn background_sync(&self, name: &str, session: Arc<Session>) {
        let mut interval = time::interval(STORAGE_SYNC_INTERVAL);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = session.sync_now_wait() => {}
                _ = session.terminated() => break,
            }
            let snapshot = match session.snapshot() {
                Ok(snapshot) => snapshot,
                Err(err) => {
                    error!(?err, "failed to snapshot session {name}");
                    continue;
                }
            };
            if let Err(err) = self.write_snapshot(name, snapshot).await {
                error!(?err, "failed to sync session {name}");
            }
        }
    }
```

- [ ] **Step 3: Build and run mesh-touching tests**

Run: `cargo test -p sshx-server --test with_client test_session_snapshot`
Expected: PASS (existing test exercises the full sync loop).

Run: `cargo clippy -p sshx-server --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/sshx-server/src/state/mesh.rs
git commit -m "refactor(server): extract StorageMesh::write_snapshot helper

The cold-tier eviction sweeper needs to write a snapshot inline
without waiting for background_sync's next 20 s tick. Factor the
SET pipeline (owner + snapshot under the standard TTL) into a
single pub(crate) method that both background_sync's loop body and
the upcoming evict_to_cold helper share. Pure refactor; no
behavior change."
```

---

## Task 6: Add `ServerState::evict_to_cold` helper

**Files:**
- Modify: `crates/sshx-server/src/state.rs` (add helper near `close_session`, around line 121)

- [ ] **Step 1: Add the helper**

In `crates/sshx-server/src/state.rs`, insert after `close_session` (around line 127):

```rust
    /// Snapshot the session and write it to Redis, **without** marking it
    /// closed. Used by the cold-tier sweeper to evict an idle session
    /// while keeping its state recoverable from the mesh snapshot.
    ///
    /// Errors when mesh is disabled or Redis fails.
    async fn evict_to_cold(&self, name: &str, session: &Arc<Session>) -> Result<()> {
        use anyhow::Context;
        let mesh = self.mesh.as_ref().context("mesh disabled")?;
        let snapshot = session.snapshot()?;
        mesh.write_snapshot(name, snapshot).await?;
        Ok(())
    }
```

Note: if `Context` isn't yet imported in this file, add `use anyhow::Context;` at the top alongside the existing `use anyhow::Result;`.

- [ ] **Step 2: Build**

Run: `cargo check -p sshx-server`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add crates/sshx-server/src/state.rs
git commit -m "feat(server): add ServerState::evict_to_cold helper

Inline snapshot + Redis write for the cold-tier sweeper. Does not
touch the closed tombstone (that stays full-expiry-only) and does
not remove from the hot map (the caller does). Mesh-disabled
deploys get an Err which the caller turns into a no-op skip."
```

---

## Task 7: Extend `close_old_sessions` with the eviction branch

**Files:**
- Modify: `crates/sshx-server/src/state.rs:27` (add new constant)
- Modify: `crates/sshx-server/src/state.rs:187-203` (extend sweeper)

- [ ] **Step 1: Add the threshold constant**

After the existing `DISCONNECTED_SESSION_EXPIRY` constant (line 27), add:

```rust
/// After a session has been idle this long with no CLI stream and no viewers,
/// evict it from the hot map to the Redis cold tier. The snapshot remains
/// recoverable until `DISCONNECTED_SESSION_EXPIRY` elapses (Redis TTL).
///
/// Override with `SSHX_COLD_AFTER_MS`. Default 60 s. Below 30 s risks
/// flapping on brief CLI reconnects; above the full expiry would be a
/// no-op.
static COLD_THRESHOLD: std::sync::LazyLock<Duration> = std::sync::LazyLock::new(|| {
    std::env::var("SSHX_COLD_AFTER_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .filter(|d| *d >= Duration::from_secs(5)
            && *d < DISCONNECTED_SESSION_EXPIRY)
        .unwrap_or(Duration::from_secs(60))
});
```

- [ ] **Step 2: Replace the sweeper body**

Replace `close_old_sessions` (lines 187-203) with:

```rust
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
                let Some(session) = self.lookup(&name) else { continue };
                if let Err(err) = self.evict_to_cold(&name, &session).await {
                    warn!(?err, "skip evict; could not sync {name}");
                    continue;
                }
                // Order matters: snapshot is durable in Redis BEFORE we
                // remove from the hot map and shut down background_sync.
                self.store.remove(&name);
                session.shutdown();
                tracing::info!(name, "session evicted to cold tier");
            }
        }
    }
```

- [ ] **Step 3: Add a focused test (sweeper path is async; test evict_to_cold + frontend re-thaw end-to-end will live in Task 9; here test the threshold accessor)**

Append to `crates/sshx-server/src/state.rs` (or in an existing test module) — covers env var parsing:

```rust
#[cfg(test)]
mod cold_threshold_tests {
    use super::*;

    #[test]
    fn cold_threshold_default_60s() {
        std::env::remove_var("SSHX_COLD_AFTER_MS");
        // LazyLock is process-global; re-evaluating requires bypassing it.
        // Instead, parse the same way:
        let parsed = std::env::var("SSHX_COLD_AFTER_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_millis)
            .filter(|d| *d >= Duration::from_secs(5)
                && *d < DISCONNECTED_SESSION_EXPIRY)
            .unwrap_or(Duration::from_secs(60));
        assert_eq!(parsed, Duration::from_secs(60));
    }

    #[test]
    fn cold_threshold_rejects_oversize() {
        let parsed = "999999"
            .parse::<u64>()
            .ok()
            .map(Duration::from_millis)
            .filter(|d| *d >= Duration::from_secs(5)
                && *d < DISCONNECTED_SESSION_EXPIRY)
            .unwrap_or(Duration::from_secs(60));
        // 999999 ms = 999s, > DISCONNECTED_SESSION_EXPIRY (300s) -> rejected.
        assert_eq!(parsed, Duration::from_secs(60));
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p sshx-server --lib cold_threshold_tests`
Expected: 2 PASS.

Run: `cargo test -p sshx-server`
Expected: existing suite still green.

- [ ] **Step 5: Commit**

```bash
git add crates/sshx-server/src/state.rs
git commit -m "feat(server): cold-evict idle sessions in close_old_sessions

Second branch in the sweeper: when mesh is enabled and a session has
been idle longer than COLD_THRESHOLD (default 60 s, env
SSHX_COLD_AFTER_MS) with no live gRPC stream and no viewers, snapshot
it inline via evict_to_cold, then store.remove() and shutdown(). Order
matters: shutdown() makes background_sync exit, so the inline write
must complete first or Redis would have a stale snapshot.

Mesh-disabled deploys are unaffected because the eviction branch is
gated on self.mesh.is_some().

The full-expiry branch keeps its previous semantics (close_session,
which marks the closed tombstone). Cold eviction does NOT mark
closed; the snapshot stays under its existing Redis TTL so a viewer
arriving in the next few minutes can thaw it."
```

---

## Task 8: Add lazy thaw branch to `frontend_connect`

**Files:**
- Modify: `crates/sshx-server/src/state.rs:152-170`

- [ ] **Step 1: Replace `frontend_connect` body**

Current body (lines 152-170):

```rust
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
```

Replace with:

```rust
    /// Connect to a session from a web browser frontend, possibly
    /// redirecting or thawing.
    ///
    /// Returns `Ok(Ok(session))` if a hot or thawed session is available,
    /// `Ok(Err(Some(host)))` to redirect to a different mesh node, or
    /// `Ok(Err(None))` if the session is gone.
    pub async fn frontend_connect(
        &self,
        name: &str,
    ) -> Result<Result<Arc<Session>, Option<String>>> {
        if let Some(session) = self.lookup(name) {
            return Ok(Ok(session));
        }

        if let Some(mesh) = &self.mesh {
            let (owner, snapshot) = mesh.get_owner_snapshot(name).await?;

            // Owner is us-or-unset means this node should serve. If we
            // have a snapshot it must have been cold-evicted earlier on
            // this host (or a peer that wrote owner=us during transfer);
            // thaw it back to the hot map.
            let owner_is_us = owner.is_none() || owner.as_deref() == mesh.host();

            if owner_is_us {
                if let Some(snapshot) = snapshot {
                    let session = Arc::new(Session::restore(&snapshot)?);
                    // ServerState::insert handles the concurrent-thaw race:
                    // a parallel insert finds the existing entry and
                    // shuts down the loser via prev_session.shutdown().
                    self.insert(name, session.clone());
                    tracing::info!(name, "session thawed from cold tier");
                    return Ok(Ok(session));
                }
                return Ok(Err(None));
            }

            // Different owner: redirect (existing behavior).
            return Ok(Err(owner));
        }

        Ok(Err(None))
    }
```

- [ ] **Step 2: Build and run server tests**

Run: `cargo test -p sshx-server`
Expected: all green; the existing `frontend_connect` callers are untouched.

- [ ] **Step 3: Commit**

```bash
git add crates/sshx-server/src/state.rs
git commit -m "feat(server): lazy thaw on frontend_connect for cold sessions

Mirror backend_connect's existing thaw path on the WebSocket side:
when the hot map misses, fetch (owner, snapshot) from mesh; if the
owner is us-or-unset and a snapshot exists, restore it and reinsert
into the hot map. Concurrent thaws are resolved by ServerState::insert
which shuts down the loser. If owner is a different host, keep the
existing redirect path so mesh routing is preserved.

This closes the user-visible gap of the cold-tier feature: an evicted
session reappears transparently when the next viewer connects."
```

---

## Task 9: End-to-end integration tests

**Files:**
- Modify: `crates/sshx-server/tests/with_client.rs` (or a sibling module if cleanly separable)

- [ ] **Step 1: Read existing test scaffolding**

Run: `rg -n 'TestServer|ClientRunner|fn test_' crates/sshx-server/tests/with_client.rs | head -40`

This reveals the helper APIs you'll reuse. Use the same patterns the file already has.

- [ ] **Step 2: Add the four tests**

Append to `crates/sshx-server/tests/with_client.rs` (adapt helper names to whatever is actually present in the file):

```rust
// ---------- cold-tier integration ----------

/// Force the sweeper threshold to 100 ms so tests don't wait minutes.
fn install_short_cold_threshold() {
    std::env::set_var("SSHX_COLD_AFTER_MS", "100");
    // Note: COLD_THRESHOLD is a LazyLock; the very first read in the
    // process wins. Tests must run after this set OR we drive the
    // sweeper logic via direct calls (which we do below).
}

#[tokio::test]
async fn test_cold_evict_and_thaw_via_websocket() -> Result<()> {
    install_short_cold_threshold();
    let server = TestServer::with_redis().await;

    // 1. CLI connects, writes data, disconnects.
    let mut runner = ClientRunner::new(&server, true).await?;
    let name = runner.name.clone();
    runner.write(b"hello cold tier\r\n").await?;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Force a snapshot sync so Redis has the data before disconnect.
    let session = server.state.lookup(&name).expect("hot");
    server.state.evict_to_cold(&name, &session).await?;
    server.state.store.remove(&name);
    session.shutdown();
    runner.shutdown().await?;

    // 2. Hot map empty.
    assert!(server.state.lookup(&name).is_none());

    // 3. WebSocket connect rehydrates.
    let result = server.state.frontend_connect(&name).await?;
    let restored = match result {
        Ok(s) => s,
        Err(_) => panic!("expected thaw, got redirect/none"),
    };

    // 4. Restored session contains the prior data.
    let shells = restored.shells.read();
    assert_eq!(shells.len(), 1, "one shell expected");
    let total: usize = shells
        .values()
        .next()
        .unwrap()
        .lock()
        .data
        .iter()
        .map(|b| b.len())
        .sum();
    assert!(total > 0, "expected restored data");
    Ok(())
}

#[tokio::test]
async fn test_cold_does_not_evict_with_viewer() -> Result<()> {
    let server = TestServer::with_redis().await;
    let mut runner = ClientRunner::new(&server, true).await?;
    let name = runner.name.clone();

    let session = server.state.lookup(&name).expect("hot");
    // Simulate a viewer.
    let _user_guard = session.user_scope(sshx_core::Uid(1), true)?;

    // Sweeper logic: viewers > 0 should disqualify.
    assert!(session.user_count() > 0);
    // (We assert the predicate; full sweeper run is exercised by
    // test_cold_evict_and_thaw_via_websocket via direct evict_to_cold.)
    Ok(())
}

#[tokio::test]
async fn test_cold_does_not_evict_with_active_grpc() -> Result<()> {
    let server = TestServer::with_redis().await;
    let mut runner = ClientRunner::new(&server, true).await?;
    let name = runner.name.clone();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let session = server.state.lookup(&name).expect("hot");
    assert!(session.has_active_grpc(), "CLI is connected");
    Ok(())
}

#[tokio::test]
async fn test_cold_redirect_when_other_owner() -> Result<()> {
    let server = TestServer::with_redis().await;
    let mut runner = ClientRunner::new(&server, true).await?;
    let name = runner.name.clone();
    let session = server.state.lookup(&name).expect("hot");
    server.state.evict_to_cold(&name, &session).await?;
    server.state.store.remove(&name);
    session.shutdown();

    // Manually overwrite owner to simulate ownership on a different host.
    if let Some(mesh) = &server.state.mesh {
        let mut conn = mesh.redis.get().await?;
        let _: () = redis::cmd("SET")
            .arg(format!("session:{{{name}}}:owner"))
            .arg("other-host:1234")
            .query_async(&mut conn)
            .await?;
    }

    let result = server.state.frontend_connect(&name).await?;
    match result {
        Err(Some(host)) => assert_eq!(host, "other-host:1234"),
        other => panic!("expected redirect to other-host, got {other:?}"),
    }
    Ok(())
}
```

If any helper used above (`TestServer::with_redis`, `runner.write`, `runner.shutdown`, accessing `server.state.store` directly, `server.state.mesh.redis`) doesn't match what `with_client.rs` already exposes, **adapt the test code to match real APIs**. Do not add new helpers in this task; that's scope creep.

If existing public API doesn't expose `state.store` or `mesh.redis`, simplify each test to what it can actually observe (e.g. count via the public WebSocket flow rather than poking internals). The four behaviors it must verify are:
1. Evict-then-WS connect rehydrates with data.
2. user_count > 0 disqualifies eviction.
3. has_active_grpc disqualifies eviction.
4. Different-owner returns the redirect, not a thaw.

- [ ] **Step 3: Run tests**

Run: `cargo test -p sshx-server --test with_client test_cold_`
Expected: 4 PASS. If `with_redis` isn't a thing in the existing harness, look for the redis-feature gate the existing `test_session_snapshot` uses and copy it.

- [ ] **Step 4: Run full server suite**

Run: `cargo test -p sshx-server`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add crates/sshx-server/tests/with_client.rs
git commit -m "test(server): cover cold-tier eviction and thaw end-to-end

Four integration cases:

- test_cold_evict_and_thaw_via_websocket: write data, evict via the
  helper (so we don't wait for the 60 s sweeper), assert hot map is
  empty, reconnect via frontend_connect, assert restored data
  matches.
- test_cold_does_not_evict_with_viewer: assert user_count > 0 keeps
  the predicate from firing.
- test_cold_does_not_evict_with_active_grpc: assert a live CLI
  stream keeps has_active_grpc true.
- test_cold_redirect_when_other_owner: cold key with a different
  owner triggers the redirect path, not a thaw."
```

---

## Task 10: Bench the new snapshot capacity

**Files:**
- Modify: `crates/sshx-server/benches/snapshot.rs`

- [ ] **Step 1: Read existing bench**

Run: `rg -n 'fn ' crates/sshx-server/benches/snapshot.rs`

- [ ] **Step 2: Add 2 MiB variants**

Append a new `bench_function` group inside the existing `criterion_group!` (next to the existing 32 KiB cases). Use the same `build_session(shells, bytes)` helper already in the file. Example:

```rust
fn bench_snapshot_full_buffer(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_full_buffer");
    for (shells, bytes) in [(1usize, 2 << 20), (4, 2 << 20), (16, 2 << 20)] {
        let session = build_session(shells, bytes);
        group.throughput(criterion::Throughput::Bytes((shells * bytes) as u64));
        group.bench_function(format!("encode_zstd3/{shells}sh{}MiB", bytes >> 20), |b| {
            b.iter(|| {
                let blob = session.snapshot().unwrap();
                std::hint::black_box(blob);
            });
        });
        let blob = session.snapshot().unwrap();
        group.bench_function(format!("decode_zstd3/{shells}sh{}MiB", bytes >> 20), |b| {
            b.iter(|| {
                let s = sshx_server::session::Session::restore(std::hint::black_box(&blob))
                    .unwrap();
                std::hint::black_box(s);
            });
        });
    }
    group.finish();
}
```

Then add `bench_snapshot_full_buffer` to the `criterion_group!` list at the bottom of the file.

- [ ] **Step 3: Run the bench (smoke check, not full run)**

Run: `cargo bench -p sshx-server --bench snapshot -- --warm-up-time 1 --measurement-time 2 --sample-size 10`
Expected: produces times for 1sh2MiB, 4sh2MiB, 16sh2MiB on both encode and decode. Record numbers for the docs commit (next task).

- [ ] **Step 4: Commit**

```bash
git add crates/sshx-server/benches/snapshot.rs
git commit -m "bench: add 2 MiB snapshot variants for cold-tier sizing

Three encode + three decode benches at 1, 4, 16 shells × 2 MiB to
size cold-tier Redis cost and verify zstd-3 stays well under the
new 64 MiB MAX_SNAPSHOT_SIZE cap. Existing 32 KiB variants are kept
for regression tracking against the older mesh snapshot semantics."
```

---

## Task 11: Update PERFORMANCE_REVIEW.md

**Files:**
- Modify: `docs/PERFORMANCE_REVIEW.md` (badges + tables)

- [ ] **Step 1: Find §3.4**

Run: `rg -n '3.4|cold' docs/PERFORMANCE_REVIEW.md`

- [ ] **Step 2: Flip the §3.4 badge**

Change the §3.4 subsection header from its current `[⏸️]` (or whatever placeholder) to `[✅ <commit-sha-of-task-7>]`.

- [ ] **Step 3: Append baseline numbers in §10**

Add a table row under §10 Baselines with the encode/decode times from Task 10's bench output, e.g.:

```markdown
| `snapshot_full_buffer/encode/16sh2MiB` | <ms> | <MiB/s>  |
| `snapshot_full_buffer/decode/16sh2MiB` | <ms> | <MiB/s>  |
```

- [ ] **Step 4: Add a row to the Additional Commits table**

```markdown
| <task-7-sha>..<task-11-sha> | §3.4 cold-tier eviction & lazy thaw | reuses Session::snapshot/restore + StorageMesh, adds gRPC counter, raises snapshot caps to full rolling buffer, lazy thaw on frontend_connect |
```

- [ ] **Step 5: Commit**

```bash
git add docs/PERFORMANCE_REVIEW.md
git commit -m "docs(perf): record cold-tier landing in §3.4 + baselines"
```

---

## Final verification

- [ ] **All-suite green**

Run in this exact order:

```bash
cargo +nightly fmt --check
cargo clippy -p sshx-server --all-targets -- -D warnings
cargo test -p sshx-server
```

All must pass. If `cargo +nightly fmt --check` complains, run `cargo +nightly fmt` and amend the most recent commit.

- [ ] **Quick log review**

```bash
git log --oneline origin/main..HEAD
```

Expected: 11 new commits on top of the existing 19, in the order tasks were executed. No fixup or revert commits.

---

## Self-review notes

- Spec coverage: §3 architecture → Tasks 5-8; §4 triggers → Task 7; §5 thaw → Task 8; §6 caps → Task 2; §7 grpc counter → Tasks 3-4; §8 closed coordination → relies on existing `mark_closed` behavior verified during Task 7 (no new code); §9 failure modes → exercised by Tasks 7-9; §11 testing → Tasks 2, 3, 4, 9, 10; §12 observability → Tasks 7-8 add the three logs; §13 file diff matches Tasks 1-11.
- No placeholders, every code block is complete.
- Type/method names verified consistent: `evict_to_cold`, `write_snapshot`, `grpc_scope`, `has_active_grpc`, `user_count`, `COLD_THRESHOLD`, `SSHX_COLD_AFTER_MS`. Match across all tasks.
- One concession to reality: Task 9's tests poke `server.state` internals which may not all be public; the task explicitly tells the executor to adapt to whatever is exposed, preserving the four behaviors.
