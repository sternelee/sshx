# Cold-tier compressed storage — design spec

- Status: approved, ready for planning
- Date: 2026-04-30
- Related: `docs/PERFORMANCE_REVIEW.md` §3.4

## 1. Goal & non-goals

**Goal.** Reduce server memory pressure by compressing and offloading idle
sessions to Redis. The session lifecycle (5-minute total expiry) and external
semantics (URL, encryption, replay) stay identical. The optimization is
invisible to clients except for the first WebSocket / gRPC request after a
cold transition, which incurs a one-shot Redis round trip and zstd decode.

**Non-goals.**
- Do not extend session lifetime. Total expiry stays 5 min after last access.
- Do not persist across Redis restart. Redis loss = session loss, same as
  today's mesh snapshot.
- Do not change the mesh ownership protocol. Cold tier and mesh share a
  Redis client but use disjoint key namespaces.
- Do not compress active in-memory buffers. Hot-path `Bytes` stay raw.
- Do not implement LRU capacity eviction. Threshold-based freeze first; add
  pressure eviction only if measurements show the need.

## 2. Architecture

```
┌─────────────────────────────────────────────┐
│  state.rs                                   │
│  ┌──────────────────────────────────────┐   │
│  │ store: DashMap<name, Arc<Session>>   │  hot tier
│  └──────────────────────────────────────┘   │
│              │ get(name) miss              │
│              ▼                              │
│  ┌──────────────────────────────────────┐   │
│  │ state/cold.rs                        │   │
│  │   freeze(&Session) -> Vec<u8>        │   │
│  │   thaw(&[u8]) -> Result<Session>     │   │
│  │   ColdTier { put / get / delete }    │   │
│  └──────────────────────────────────────┘   │
│              │ Redis SET / GET              │
│              ▼                              │
│  Redis key:  sshx:cold:{name}   EX <ttl>    │
└─────────────────────────────────────────────┘
        ▲
        │ existing close_old_sessions sweeper (60s tick)
        │   if conditions met: freeze → SET → remove from hot map
```

**Core invariant (observable).** From any caller's point of view, a session
appears in exactly one of three states: hot map, Redis cold tier, or
expired. Internally there is one micro-window during freeze where both
hot and cold copies coexist (see §5); this is invisible because lookups
always check hot first and the hot copy serves any in-flight request
during the overlap.

## 3. Trigger conditions

The existing `close_old_sessions` background task (60 s tick) gains a second
branch:

```rust
for entry in store.iter() {
    let session = entry.value();
    let idle_ms = session.idle_ms_now();
    let viewers = session.user_count();
    let cli_connected = session.has_active_grpc();

    if idle_ms > EXPIRY_MS {
        session.shutdown();
        store.remove(name);
        cold.delete(name).await.ok();   // also clean cold copy
    } else if !cli_connected
        && viewers == 0
        && idle_ms > COLD_THRESHOLD_MS
    {
        let blob = cold::freeze(&session)?;
        let ttl = EXPIRY - Duration::from_millis(idle_ms);
        cold.put(name, blob, ttl).await?;   // put first ...
        store.remove(name);                  // ... then remove (see §5)
        // do NOT shutdown(): thaw will rebuild the session
    }
}
```

`COLD_THRESHOLD_MS` defaults to **60 000** (1 min after CLI disconnect with
no viewers). Override with `SSHX_COLD_AFTER_MS`. Below 30 s would risk
flapping on brief CLI reconnects; above 5 min would be redundant with full
expiry.

`has_active_grpc()` is a new `Session` method backed by an `AtomicU32`
counter incremented on entry and decremented on exit of the gRPC `Channel`
handler. Zero means no live CLI stream.

## 4. Cold schema

Located in `crates/sshx-server/src/state/cold.rs`. Encoded with `bincode`
2.x using its `Encode` / `Decode` derives, then framed with zstd level 3
(matching the in-memory snapshot level chosen in §3.1 of the perf review).

```rust
#[derive(Encode, Decode)]
struct ColdSession {
    version: u8,                       // = 1
    metadata: ColdMetadata,
    shells: Vec<(u32, ColdShell)>,     // (Sid.0, shell)
    next_sid: u32,                     // IdCounter restoration
    next_uid: u32,
}

#[derive(Encode, Decode)]
struct ColdMetadata {
    encrypted_zeros: Vec<u8>,
    name: String,
    write_password_hash: Option<Vec<u8>>,
}

#[derive(Encode, Decode)]
struct ColdShell {
    seqnum: u64,
    chunk_offset: u64,
    byte_offset: u64,
    closed: bool,
    winsize: ColdWinsize,
    data: Vec<Vec<u8>>,                // Bytes -> Vec<u8>
}

#[derive(Encode, Decode)]
struct ColdWinsize { x: i32, y: i32, rows: u16, cols: u16 }
```

**Not persisted** (rebuilt during thaw with defaults):

| Field | Reason |
|-------|--------|
| `users`             | Trigger requires viewers == 0. Restored empty. |
| `broadcast`         | Runtime-only; recreated. |
| `source` (watch)    | Recreated from shell list. |
| `update_tx/rx`      | Recreated. |
| `sync_notify`       | Recreated. |
| `shutdown`          | Recreated; old one dropped. |
| `epoch`             | Recreated; `last_accessed_ms` reset to 0 on thaw. |

**Versioning.** `version: u8 = 1`. A mismatched value during thaw returns
`Err`, treated as data corruption (delete key, log error, return None to the
caller). Future schema migration adds explicit version branches.

**`Bytes` ↔ `Vec<u8>`.** bincode 2 has no built-in `bytes::Bytes` codec.
Convert `Bytes -> Vec<u8>` on freeze (one copy), `Vec<u8> -> Bytes::from(v)`
on thaw (zero copy). Cost is paid once per cold transition.

## 5. Lazy thaw path

Two callsites currently lookup hot map and 4xx on miss:

1. WebSocket: `web/socket.rs::get_session_websocket` — browser session join.
2. gRPC: `grpc.rs::Channel` — CLI reconnect. (CLI does not normally hit a
   cold session because freezing requires CLI disconnect, but reconnect
   from a flapping CLI within the cold window must work.)

Both adopt:

```rust
pub async fn lookup_or_thaw(&self, name: &str) -> Option<Arc<Session>> {
    if let Some(s) = self.store.get(name) {
        return Some(s.value().clone());
    }
    let blob = self.cold.as_ref()?.get(name).await.ok().flatten()?;
    let session = match cold::thaw(&blob) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(?name, error=?e, "cold thaw failed; deleting");
            let _ = self.cold.as_ref().unwrap().delete(name).await;
            return None;
        }
    };
    let arc = Arc::new(session);

    // race-safe insert
    let entry = self.store.entry(name.to_string())
        .or_insert_with(|| arc.clone());
    let final_arc = entry.value().clone();

    // only the winning thaw deletes the Redis copy
    if Arc::ptr_eq(&final_arc, &arc) {
        let _ = self.cold.as_ref().unwrap().delete(name).await;
        tracing::info!(?name, "session thawed");
    }
    final_arc.touch();
    Some(final_arc)
}
```

**Race analysis.**
- Two concurrent thaws: both `get` from Redis, both `thaw`, but only one
  wins the DashMap entry. Loser drops its `Arc<Session>`; one Redis
  `delete` happens; correctness preserved.
- Sweeper freeze racing with thaw: order is **`cold.put` first, then
  `store.remove`**. The hot `Arc<Session>` continues serving any
  in-flight request during the brief window both copies exist
  (microseconds inside the sweeper). Once `remove` lands, the next
  miss thaws from cold. There is no observable inconsistency because
  `lookup_or_thaw` always checks hot first.
- More dangerous order would be `remove` then `put`: a `lookup` between
  the two operations would see neither hot nor cold and return None
  even though the session is alive. **Do not use that order.**

## 6. Redis client integration

Reuse the existing `redis::Client` already held by `state/mesh.rs`. Cold
tier lives in a sibling module and shares the same `Option<Arc<Client>>`
lifecycle.

```rust
// state/cold.rs

pub struct ColdTier {
    client: redis::aio::ConnectionManager,
    key_prefix: &'static str,           // "sshx:cold:"
}

impl ColdTier {
    pub async fn put(&self, name: &str, blob: Vec<u8>, ttl: Duration) -> Result<()>;
    pub async fn get(&self, name: &str) -> Result<Option<Vec<u8>>>;
    pub async fn delete(&self, name: &str) -> Result<()>;
}

pub fn freeze(session: &Session) -> Result<Vec<u8>>;
pub fn thaw(blob: &[u8]) -> Result<Session>;
```

`State` holds `Option<Arc<ColdTier>>`. Single-node deploys without a Redis
URL get `None`, so cold tier is fully bypassed (sweeper skips the freeze
branch, lookup_or_thaw short-circuits). Mirrors the existing optional mesh
pattern; no breaking config change.

## 7. Failure modes

| Failure | Behavior |
|---------|----------|
| Redis unavailable on `put` | freeze aborts; hot session retained; warn log; sweeper retries next tick. |
| Redis unavailable on `get` | lookup returns None; user sees "not found" (same as expired). warn log. |
| `thaw` returns Err (corruption / version mismatch) | delete Redis key; return None; error log. |
| `delete` after thaw fails | non-fatal; session is hot, cold copy stale; next sweeper tick will overwrite via `put`, or expire via Redis TTL. warn log. |
| Concurrent thaws | DashMap entry API picks one winner; loser's `Arc` is dropped; one delete. |
| Sweeper freeze racing with thaw | put-then-remove ordering keeps hot serving until cold is durable; brief overlap is invisible to callers. |

## 8. Testing

**Unit (cold.rs):**
- `freeze` → `thaw` round trip preserves all shells, seqnums, closed flags,
  winsizes, metadata.
- Truncated blob → `thaw` returns Err.
- Wrong version byte → `thaw` returns Err.

**Integration (`crates/sshx-server/tests/with_client.rs`):**
- `test_cold_freeze_thaw`: CLI connect → write data → CLI disconnect → wait
  past `COLD_THRESHOLD_MS` → trigger sweeper → assert hot map removed →
  browser connect → assert full scrollback received → assert hot map
  repopulated.
- `test_cold_redis_unavailable`: configure dead Redis → freeze fails →
  hot session remains.
- `test_cold_concurrent_thaw`: two WebSocket connects in parallel after
  cold → both succeed → hot map has exactly one Arc → Redis key gone.

**Bench:** add `cold_freeze_thaw/{1sh32K, 4sh64K, 16sh128K}` to
`crates/sshx-server/benches/snapshot.rs`. Record freeze time, blob size
(compression ratio), thaw time in `docs/PERFORMANCE_REVIEW.md` §10.

## 9. Observability

`tracing` events:
- `info!(session_name, blob_size, shells, "session frozen")`
- `info!(session_name, "session thawed")`
- `warn!(?error, "cold tier put failed")`
- `warn!(?error, "cold tier delete failed")`
- `error!(session_name, ?error, "cold thaw failed; deleting blob")`

No metrics counters in this iteration. Add `sshx_cold_sessions{state}` and
`sshx_cold_blob_size_bytes` histogram only if production observability
needs them; keep diff small for now.

## 10. Configuration summary

| Env var | Default | Meaning |
|---------|---------|---------|
| `SSHX_COLD_AFTER_MS` | `60000` | idle ms after CLI disconnect & viewers=0 to freeze |
| (existing) `SSHX_REDIS_URL` | unset | required for cold tier; bypassed if unset |
| (existing) `SSHX_SHELL_STORED_BYTES` | `2097152` | per-shell rolling buffer cap; bounds blob size |

## 11. Out of scope (recap)

- Lifetime extension beyond 5 min.
- Cross-restart durability.
- Mesh ownership integration.
- Active session in-memory compression.
- Capacity-based LRU eviction.
- Prometheus metrics (deferred until needed).
- Cross-cluster replication of cold blobs.

## 12. File-level diff preview

New:
- `crates/sshx-server/src/state/cold.rs` (~250 LOC)
- `crates/sshx-server/tests/cold.rs` integration cases
- bench addition in `crates/sshx-server/benches/snapshot.rs`

Modified:
- `crates/sshx-server/src/state.rs` — `Option<Arc<ColdTier>>`,
  `lookup_or_thaw`, sweeper branch.
- `crates/sshx-server/src/state/mod.rs` — `mod cold;`
- `crates/sshx-server/src/session.rs` — `has_active_grpc()`,
  `idle_ms_now()`, `user_count()`, `touch()`, accessors for freeze.
- `crates/sshx-server/src/grpc.rs` — inc/dec gRPC counter; use
  `lookup_or_thaw`.
- `crates/sshx-server/src/web/socket.rs` — use `lookup_or_thaw`.
- `crates/sshx-server/Cargo.toml` — `bincode = "2"` if not present.
- `docs/PERFORMANCE_REVIEW.md` — flip §3.4 status badge, add row to
  Additional Commits, append baseline numbers to §10.
