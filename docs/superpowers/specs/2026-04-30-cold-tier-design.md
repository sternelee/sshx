# Cold-tier compressed storage — design spec (revised)

- Status: approved, ready for planning
- Date: 2026-04-30
- Supersedes: initial draft of same date (the first version reinvented
  serialization that already exists in `session/snapshot.rs`).
- Related: `docs/PERFORMANCE_REVIEW.md` §3.4

## 1. Goal & non-goals

**Goal.** Reduce server memory pressure by evicting idle sessions from the
hot in-memory map while keeping their state recoverable from the existing
mesh-snapshot Redis copy. Session lifecycle (5-minute total expiry) and
external semantics (URL, encryption, replay) stay identical.

**Non-goals.**
- Do not extend session lifetime beyond the existing 5 min.
- Do not persist across Redis restart.
- Do not redesign mesh ownership protocol.
- Do not compress active in-memory buffers.
- Do not implement LRU capacity eviction (threshold-based first).
- Do not invent a new serialization format. Reuse `Session::snapshot` /
  `Session::restore`.

## 2. What already exists

Two prior pieces of infrastructure cover most of this feature:

1. **`Session::snapshot()` / `Session::restore()`** in
   `crates/sshx-server/src/session/snapshot.rs`. Encodes the session as
   `SerializedSession` (protobuf) then `zstd::bulk::compress(level=3)`. The
   roundtrip is validated by `tests/with_client.rs::test_session_snapshot`
   and lives behind `MAX_SNAPSHOT_SIZE = 4 MiB`. Per-shell rolling buffer
   is currently capped at `SHELL_SNAPSHOT_BYTES = 32 KiB`.

2. **`StorageMesh::background_sync`** in
   `crates/sshx-server/src/state/mesh.rs`. When a session is inserted into
   the hot map, a long-running task ticks every 20 s (or when the session
   calls `sync_now_wait`) and writes the snapshot to Redis under
   `session:{{{name}}}:snapshot`, plus an owner key under
   `session:{{{name}}}:owner`. Both keys carry an EX TTL.

3. **`ServerState::backend_connect`** already implements the cold-thaw
   read path for the CLI side: when the hot map misses, it calls
   `mesh.get_owner_snapshot`, and if a snapshot is present it calls
   `Session::restore`, inserts the result into the hot map, and notifies
   ownership transfer.

The browser-side path `ServerState::frontend_connect` has **no equivalent
thaw**: it only redirects to the owner or returns `Err(None)` (which the
WebSocket handler reports as session-not-found). This is the gap we need to
close, plus a sweeper that proactively evicts idle sessions instead of
waiting for the full 5-minute expiry.

## 3. Architecture

```
┌─────────────────────────────────────────────┐
│  state.rs                                   │
│  ┌──────────────────────────────────────┐   │
│  │ store: DashMap<name, Arc<Session>>   │  hot
│  └──────────────────────────────────────┘   │
│              │ get(name) miss              │
│              ▼                              │
│  ┌──────────────────────────────────────┐   │
│  │ mesh.rs (existing)                   │   │
│  │   get_owner_snapshot → snapshot blob │   │
│  └──────────────────────────────────────┘   │
│              │ Session::restore             │
│              ▼                              │
│       reinserted into hot map               │
└─────────────────────────────────────────────┘
        ▲
        │ existing close_old_sessions sweeper (60s tick) gains a
        │ second branch: if conditions met → force snapshot sync →
        │ remove from hot map (do NOT mark_closed; the snapshot
        │ remains in Redis under its TTL)
```

**Core invariant (observable).** From any caller's point of view a session
is in exactly one of three states: hot map, Redis snapshot only, or
expired. There is one micro-window during eviction where both the hot
`Arc<Session>` and the Redis snapshot exist; this is invisible because
lookups always check hot first and the hot Arc continues serving any
in-flight request until `store.remove` returns.

## 4. Trigger conditions

Existing sweeper (`close_old_sessions`, 60 s tick currently
`DISCONNECTED_SESSION_EXPIRY / 5`) gains a second branch:

```rust
for entry in &self.store {
    let name = entry.key();
    let session = entry.value();
    let idle = session.last_accessed_elapsed();
    let viewers = session.user_count();
    let cli_connected = session.has_active_grpc();

    if idle > DISCONNECTED_SESSION_EXPIRY {
        // existing branch
        to_close.push(name.clone());
    } else if !cli_connected
        && viewers == 0
        && idle > COLD_THRESHOLD
    {
        to_evict.push(name.clone());
    }
}

for name in to_evict {
    if let Some(session) = self.lookup(&name) {
        if let Err(err) = self.evict_to_cold(&name, &session).await {
            warn!(?err, "skip evict; could not sync {name}");
            continue;
        }
        self.store.remove(&name);
        // Drop the background_sync task: it is awaiting session.terminated();
        // we need it to exit cleanly so the next thaw owns the new task.
        session.shutdown();
        info!(name, "session evicted to cold tier");
    }
}
```

**`COLD_THRESHOLD`**: default 60 s, override `SSHX_COLD_AFTER_MS`. Below
30 s risks flapping on brief CLI reconnects; above 5 min is redundant with
expiry.

**`has_active_grpc()`** is a new `Session` method backed by an `AtomicU32`
counter incremented on entry / decremented on exit of the gRPC `Channel`
handler. Zero ⇒ no live CLI stream.

**`user_count()`** is `self.users.read().len()`.

**`sync_now_blocking`** is a new helper on `ServerState` (not `Session`,
since it needs the mesh handle):

```rust
async fn evict_to_cold(&self, name: &str, session: &Arc<Session>) -> Result<()> {
    let mesh = self.mesh.as_ref().context("mesh disabled")?;
    let snapshot = session.snapshot()?;          // CPU work
    mesh.write_snapshot(name, snapshot).await?;  // new public method on
                                                 // StorageMesh that does
                                                 // exactly the SET in
                                                 // background_sync, without
                                                 // the loop
    Ok(())
}
```

Add `StorageMesh::write_snapshot(name, blob) -> Result<()>` that pipes the
owner + snapshot SET (factor out of `background_sync`'s loop body so both
share one implementation).

**Critical note on `shutdown()`.** Calling `shutdown()` causes
`background_sync`'s `session.terminated()` future to fire so it exits its
loop. We must do `evict_to_cold` (which writes the snapshot inline, not
through `background_sync`) **before** calling `shutdown()`, otherwise the
loop may exit before the next periodic write and leave a stale snapshot
in Redis.

## 5. Lazy thaw path

Two callsites currently hot-map miss:

1. **gRPC** (`ServerState::backend_connect`) — already thaws via
   `mesh.get_owner_snapshot`. **No change needed** beyond bumping the
   gRPC active-counter (§7).

2. **WebSocket** (`ServerState::frontend_connect`) — only redirects.
   Needs a thaw branch parallel to backend_connect:

```rust
pub async fn frontend_connect(
    &self,
    name: &str,
) -> Result<Result<Arc<Session>, Option<String>>> {
    if let Some(session) = self.lookup(name) {
        return Ok(Ok(session));
    }

    if let Some(mesh) = &self.mesh {
        let (owner, snapshot) = mesh.get_owner_snapshot(name).await?;

        // Evicted-on-this-host case: snapshot exists but owner is us
        // (or owner unset). Thaw locally instead of redirecting to self.
        let owner_is_us = owner.as_deref().is_none()
            || owner.as_deref() == mesh.host();

        if owner_is_us {
            if let Some(snapshot) = snapshot {
                let session = Arc::new(Session::restore(&snapshot)?);
                self.insert(name, session.clone());
                // No notify_transfer: ownership did not move.
                return Ok(Ok(session));
            }
            return Ok(Err(None));    // truly gone
        }

        // Different owner ⇒ redirect (existing behavior).
        return Ok(Err(owner));
    }

    Ok(Err(None))
}
```

`ServerState::insert` already handles the concurrent-thaw race: if a
parallel thaw also called `insert`, the second `store.insert` finds the
entry already present and `prev_session.shutdown()` retires the loser.
The losing `Arc` drops naturally. No new race-avoidance code needed.

## 6. Snapshot capacity changes

To preserve full scrollback through a cold cycle (§1 "scrollback intact"
requirement) we raise the per-shell snapshot cap to match the in-memory
rolling cap:

```rust
// session/snapshot.rs
const SHELL_SNAPSHOT_BYTES: u64 = SHELL_STORED_BYTES;   // was 1 << 15
const MAX_SNAPSHOT_SIZE: usize = 64 << 20;              // was 1 << 22 (4 MiB)
```

`SHELL_STORED_BYTES` defaults to 2 MiB. With ~16 shells worst case and
zstd-3 typical 4-10× compression on terminal output, blob size stays well
under 16 MiB pre-compression. Set `MAX_SNAPSHOT_SIZE` to 64 MiB to cover
pathological cases (uncompressed JSON, base64 dumps); compressed size in
practice will be a fraction of that.

**Memory & Redis cost.** Each evicted session now stores up to ~2 MiB ×
shells of compressed data in Redis (typically 200-500 KiB compressed per
shell of busy terminal output). For 1000 idle sessions this is
~200-500 MB Redis, vs 2-32 GB hot RSS without eviction. Net win even after
accounting for Redis overhead.

**Active-session impact.** `background_sync` runs on hot sessions every
20 s, so this also raises ongoing snapshot CPU and Redis bandwidth for
active sessions. Mitigation: the `mesh.rs` write path is already async,
zstd-3 of 2 MiB is ~1 ms, and the new 20 s period dominates. Acceptable.

## 7. gRPC active counter

Add to `Session`:

```rust
grpc_active: AtomicU32,

pub fn has_active_grpc(&self) -> bool {
    self.grpc_active.load(Ordering::Relaxed) > 0
}

// RAII guard
pub fn grpc_scope(self: &Arc<Self>) -> impl Drop {
    self.grpc_active.fetch_add(1, Ordering::Relaxed);
    let s = self.clone();
    scopeguard::guard((), move |_| {
        s.grpc_active.fetch_sub(1, Ordering::Relaxed);
    })
}
```

Call site: `crates/sshx-server/src/grpc.rs::Channel` opens with
`let _g = session.grpc_scope();` after authenticating.

## 8. `closed` key coordination

`mark_closed` writes `session:{{{name}}}:closed` in Redis as a tombstone.
`get_owner_snapshot` already returns `(None, None)` for closed sessions
(verify in code). Cold-tier eviction must **not** call `mark_closed`; it
just removes from the hot map and leaves the snapshot under its existing
TTL. `close_session` (called from full expiry) keeps its current behavior
of also writing the tombstone.

Verification step in plan: read `mesh.rs::mark_closed` and
`get_owner_snapshot` to confirm the tombstone short-circuits both
backend_connect and frontend_connect_or_thaw paths. If not, add an
explicit closed-check to the new thaw branch.

## 9. Failure modes

| Failure | Behavior |
|---------|----------|
| Redis down on `sync_now_blocking` | warn log; skip eviction this tick; retry next tick. |
| Redis down on `get_owner_snapshot` | propagated as `Err(_)` from connect path; user sees server error. Existing behavior. |
| `Session::restore` Err on thaw | propagated; user sees server error. Same as today's backend_connect path. |
| Concurrent thaw | `ServerState::insert` retires loser via `prev_session.shutdown()`. |
| Mesh disabled (no `--redis-url`) | sweeper's eviction branch becomes no-op (no place to store the snapshot), so it does nothing. Hot sessions still hit normal expiry at 5 min. |
| Sweeper evict racing with viewer connect | viewer's `frontend_connect` lookup either finds hot Arc (returns it; sweeper next tick re-evaluates and skips since `viewers > 0` now) or hot map empty (thaws from snapshot). Both safe. |

## 10. Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `SSHX_COLD_AFTER_MS` | `60000` | idle ms after CLI off & viewers=0 to evict |
| (existing) `SSHX_REDIS_URL` | unset | required for any cold tier; without it nothing is evicted |
| (existing) `SSHX_SHELL_STORED_BYTES` | `2097152` | per-shell rolling cap; also caps snapshot |

No protocol changes. No frontend changes.

## 11. Testing

**Unit:**
- Existing `Session::snapshot/restore` round-trip already covered.
- Add `Session::has_active_grpc` / `user_count` direct assertions.
- Add a snapshot test demonstrating that raising `SHELL_SNAPSHOT_BYTES`
  preserves a full 2 MiB buffer through round-trip.

**Integration (`crates/sshx-server/tests/with_client.rs`):**
- `test_cold_evict_and_thaw_via_websocket`: CLI connect → write 1 MiB →
  CLI disconnect → wait `COLD_THRESHOLD + sweeper_tick` → assert hot map
  removed → browser connect → assert receives full scrollback.
- `test_cold_does_not_evict_with_viewer`: CLI connect → browser connect
  → CLI disconnect → wait → browser still connected → assert hot map
  retained.
- `test_cold_does_not_evict_with_active_grpc`: CLI connect (no idle) →
  no viewers → assert not evicted.
- `test_cold_concurrent_thaw_via_two_browsers`: evict, then connect two
  browsers in parallel → both succeed → exactly one Arc in hot map.

**Bench:** add to `crates/sshx-server/benches/snapshot.rs`:
- `snapshot_full_buffer/{1sh, 4sh, 16sh}` at 2 MiB each, recording size,
  compression ratio, encode time, decode time. Drop the existing 32 KiB
  variants if redundant.

## 12. Observability

```
info!(name, blob_size, "session evicted to cold tier")
info!(name, "session thawed from cold tier")
warn!(name, ?err, "skip evict; sync failed")
```

No metrics counters this iteration.

## 13. File-level diff preview

**Modified:**
- `crates/sshx-server/src/session.rs` — add `grpc_active: AtomicU32`,
  `has_active_grpc`, `grpc_scope`, `user_count`. (No
  `sync_now_blocking`; that lives on `ServerState`.)
- `crates/sshx-server/src/state.rs` — extend `close_old_sessions` with
  the eviction branch; extend `frontend_connect` with the thaw branch;
  add `evict_to_cold` helper.
- `crates/sshx-server/src/state/mesh.rs` — extract `write_snapshot`
  helper from `background_sync`'s loop body so it can be reused by
  `evict_to_cold`.
- `crates/sshx-server/src/session/snapshot.rs` — raise
  `SHELL_SNAPSHOT_BYTES` to `*SHELL_STORED_BYTES`, raise
  `MAX_SNAPSHOT_SIZE` to 64 MiB. Move `SHELL_STORED_BYTES` to a shared
  location accessible from this file (currently in `session.rs`).
- `crates/sshx-server/src/state.rs` — extend `close_old_sessions` with
  the eviction branch; extend `frontend_connect` with the thaw branch.
- `crates/sshx-server/src/grpc.rs` — wrap `Channel` body in `grpc_scope`.
- `crates/sshx-server/Cargo.toml` — add `scopeguard = "1"` if not
  already present.
- `crates/sshx-server/benches/snapshot.rs` — add 2 MiB variants.
- `docs/PERFORMANCE_REVIEW.md` — flip §3.4 status badge, add commit row,
  append baseline numbers to §10.

**New:**
- `crates/sshx-server/tests/cold.rs` — four integration tests. Or
  append to `tests/with_client.rs` if test infra is shared.

## 14. Out of scope (recap)

- Lifetime extension beyond 5 min.
- Cross-restart durability.
- Mesh ownership protocol changes.
- Active in-memory compression.
- LRU capacity eviction.
- Prometheus metrics.
- Cross-cluster replication.
