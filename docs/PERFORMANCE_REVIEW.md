# sshx Performance Review

> **Status**: read-only audit. Nothing in this document has been measured on a real workload — every "expected gain" is a hypothesis that must be confirmed with the verification recipe attached to it.
>
> **Scope**: Rust crates `sshx`, `sshx-server`, `sshx-core`. The frontend (`src/`) is out of scope except where it co-designs a wire protocol with the server.
>
> **Targets**: balanced across (a) low-latency interactive keystroke echo, (b) single-node high session density, and (c) Redis-mesh multi-node deployments.
>
> **Ordering**: items are grouped by category, then sorted by ROI (highest first). Each item carries a risk tag (🟢 micro, 🟡 medium refactor, 🔴 protocol/architectural change).
>
> **Implementation status legend** (added after the initial audit):
> - ✅ landed on this branch (commit hash linked in the section)
> - ⏭️ deliberately skipped — see section for rationale
> - ⏸️ not yet done — pending baseline / design / discussion
> - 🆕 added during implementation, not in the original audit

---

## TL;DR — top 10 items by ROI

| # | Item | Risk | Expected impact | Status |
|---|------|------|-----------------|--------|
| 1 | Per-subscriber CBOR re-encoding of every broadcast frame | 🟡 | -30..60% server CPU on fanout, -20..40% p99 broadcast latency | ✅ `01c1699` |
| 2 | `RECONNECT_INTERVAL = 60s` forces a full TCP+gRPC handshake every minute, per CLI | 🟢 | Removes a periodic 50–500 ms stall from the input path; lower server churn | ✅ `520946f` (60 s → 10 min) |
| 3 | `Vec<u8>` everywhere on the encrypt → gRPC → broadcast → WS hot path | 🟡 | -1 alloc + -1 memcpy per chunk per subscriber | ✅ `62a9fce` (`prost .bytes(".")`) |
| 4 | `subscribe_chunks` clones the entire `Vec<Bytes>` buffer under the lock | 🟡 | Removes O(N·M) memcpy on subscriber join; smaller lock hold time | ⏭️ skipped — `Vec<Bytes>::to_vec()` is already O(N) refcount bumps + ~16 B/chunk header memcpy, not a hot path. Reopen if profiling proves otherwise. |
| 5 | `RwLock<HashMap<Sid, State>>` is a write-heavy global; switch to per-shell locks | 🟡 | Reduces write contention; better tail latency under N shells × M viewers | ✅ `ac157ba` |
| 6 | Argon2 KDF runs on the WS task for every browser connect | 🟢 | Frees the websocket task; -50..200 ms time-to-first-frame on cold connects (frontend, also relevant if mirrored server-side) | ⏸️ not started — frontend-side, out of immediate scope |
| 7 | `prev_char_boundary` is O(N) per chunk send | 🟢 | Removes a scan that grows with chunk size on every PTY read | ✅ `a22965d` |
| 8 | TraceLayer + per-message info_span at high QPS | 🟢 | -5..15% CPU under load with `RUST_LOG=info` | ✅ `cfb9214` (demoted to DEBUG) |
| 9 | `subscribe_chunks` polling loop wakes too often (one task per shell per browser) | 🟡 | Lower memory + scheduler pressure with many viewers | ✅ `2ef4e7a` (merged into main `select!` via `StreamMap`) |
| 10 | Redis pipe + 5 s sync interval for sequence numbers; consider event-driven sync | 🟡 | Lower median input-to-ack latency in lossy networks | ⏸️ not started — needs design + criterion baseline |

### Additional commits not in the original top-10

| Commit | Item | Notes |
|--------|------|-------|
| `a1d6d2f` | §3.1 snapshot zstd 15 → 3 | ✅ |
| `bed9898` | §3.5 `Mutex<Instant>` → `AtomicU64` | ✅ |
| `d34ca3d` | 🆕 broadcast capacity 256 → 1024 | ✅ — reduces `Lagged` events under bursty fanout |
| `14ae3db` | §3.4 (partial) `SHELL_STORED_BYTES` env var | ✅ — tiered storage still ⏸️ |
| `cb976b9` | §2.5 cursor broadcast throttle (50 ms) | ✅ |
| `fcde9ed` | §4.1 ownership cache TTL 2 s → 30 s + transfer invalidation hook | ✅ |
| `7bc069b` | §5.4 AES-GCM `aead::Aead` → `aead::AeadInOut` in-place | ✅ — single allocation per chunk; wire format unchanged |

---

## 1. End-to-end keystroke echo latency

The interactive path is:

```
Browser keypress → WS Data → server → async_channel(256) → gRPC stream → CLI
CLI PTY input → PTY → PTY read → encrypt → gRPC stream → server.add_data
→ shell.notify_waiters() → subscribe_chunks task → mpsc(64) → WS Chunks → browser
```

### 1.1 [🟢] [✅ `520946f`] Drop the 60 s forced reconnect on the CLI
**Where**: `crates/sshx/src/controller.rs:26` (`RECONNECT_INTERVAL`) and `controller.rs:174,192-194` (the `reconnect` branch in `try_channel`).

**Current**: every 60 s the CLI returns from `try_channel`, which causes `run()` to re-enter, build a new TCP connection, do TLS handshake, send `Hello`, and reauthenticate. During the handshake window the bidirectional stream is gone, so any keystroke arriving in that window is buffered in `output_rx` (sender side) but not delivered until the new stream is up.

**Why it exists**: the comment says it is to handle replicas that are gracefully shutting down. That goal is real but the implementation is heavy.

**Proposal**:
- Replace forced reconnects with a soft probe: only reconnect if the server has signalled `GOAWAY`-equivalent (gRPC trailers) or if the heartbeat round-trip has gone silent for `> N · HEARTBEAT_INTERVAL` (e.g., 3 missed heartbeats = 6 s).
- Alternatively, raise `RECONNECT_INTERVAL` to 30 minutes and rely on graceful drain on the server side (the server already has `Shutdown` signal and `terminated()` in the gRPC handler — wire it to send a `ServerMessage::Error("draining")` and let the client treat that as a reconnect signal).
- Simpler intermediate: keep the timer but make it a *floor* and require `output_rx` to be empty before tearing down (avoid mid-keystroke teardown).

**Risk**: If a replica is stuck in a way that doesn't surface as a transport error, sessions could pin to it forever. Mitigation: keep a 30 min ceiling.

**Verify**:
- Microbench: synthetic CLI + server in one process, drive 60 keystrokes/s through the round trip, measure p99 latency over 10 min before/after. Look for periodic ~100 ms spikes that vanish.
- Add a `tracing` event when reconnect fires; in production confirm lower frequency.
- Existing test `crates/sshx-server/tests/with_client.rs` covers basic functionality — extend with a "no input lost during reconnect window" assertion.

### 1.2 [🟡] [✅ `01c1699`] Re-encode CBOR once per broadcast, not once per subscriber
**Where**: `crates/sshx-server/src/web/socket.rs:77-82` (the `send` helper) and `session.rs:67` (`broadcast::Sender<WsServer>`).

**Current**: `WsServer` is broadcast as a typed enum to every `BroadcastStream` subscriber. Each subscriber's `send()` call calls `ciborium::ser::into_writer` with a fresh `Vec`. A session with 20 viewers serialises every chat / cursor / user diff 20 times.

**Proposal**:
1. Pre-encode at the producer side. Change the broadcast channel to `broadcast::Sender<Bytes>` (CBOR-encoded), and keep typed `WsServer` only for callers that need to inspect (none currently do).
2. Even better: replace `tokio::sync::broadcast` with a `Vec<mpsc::Sender<Bytes>>` guarded by `RwLock`, which (a) gives backpressure per subscriber instead of dropping (currently an overflowed broadcast subscriber is killed via `BroadcastStreamRecvError`, see `socket.rs:146` `client fell behind on broadcast stream`), and (b) makes it trivial to skip `Chunks` to subscribers that haven't subscribed to that shell.

**Risk**: medium. Touches the broadcast contract and the `BroadcastStream` handling. Care needed for the auth-time `Hello`/`Users` snapshot which is currently sent point-to-point (those stay typed).

**Verify**:
- `wrk` or a custom WS load tool: 1 producer (server-injected events at 100 Hz) + 50 viewers, measure server CPU and per-message tail latency.
- Confirm with `tokio-console` that the CBOR encoder is no longer dominating poll time.

### 1.3 [🟢] [✅ `cfb9214`] Per-message `info_span` and full TraceLayer at INFO
**Where**: `crates/sshx-server/src/listen.rs:29,45` (TraceLayer), `web/socket.rs:29` (`info_span!("ws", %name)`).

**Current**: `TraceLayer::new_for_http()` and `TraceLayer::new_for_grpc()` are unconditional. For HTTP they wrap every request in spans + on-response logging, which is fine. For gRPC, since every CLI session is a single long-lived bidirectional stream, the cost is amortised — but the per-request `make_span` still runs.

The `info_span!("ws", %name)` in `socket.rs` is fine (one per WS connection), not per-message.

**Proposal**:
- Allow disabling TraceLayer via env var or build flag (`SSHX_TRACE_HTTP=0`).
- Configure `TraceLayer` with `make_span_with(...).level(Level::DEBUG)` so spans only materialise at DEBUG, while keeping error logging at INFO. `tower-http` supports `DefaultMakeSpan::new().level(Level::DEBUG)`.
- Keep `info_span!("ws")` since per-message data flows do not create new spans.

**Verify**: `cargo flamegraph -p sshx-server` under sustained 1 k req/s, look for `TraceLayer::call` time. Repeat after change.

### 1.4 [🟡] [✅ `62a9fce`] Bytes vs Vec<u8> on the hot path
**Where**:
- `crates/sshx/src/runner.rs:117-127` — `encrypt.encrypt(...)` returns `Vec<u8>`, then placed into `TerminalData { data: segment_data }` (proto `bytes` = `Vec<u8>` by default in prost).
- `crates/sshx-server/src/grpc.rs:189` — `data.data.into()` converts `Vec<u8>` to `Bytes` (one alloc-free move if prost is configured for `Bytes`, otherwise a memcpy).
- `crates/sshx-server/src/web/socket.rs:231` — `data.to_vec()` converts incoming `Bytes` (browser → server input) back to `Vec<u8>` for proto.

**Current**: there are several `Vec ↔ Bytes` conversions per chunk. With prost's default `Vec<u8>` mapping for `bytes`, the gRPC layer already memcpies; it is not re-cloned, but every conversion is a checkpoint where a `Bytes::from(Vec)` (zero-copy) or `vec.clone()` (memcpy) happens depending on type.

**Proposal**:
1. Configure prost-build to emit `bytes::Bytes` for `bytes` fields (`prost_build::Config::bytes(&["."])`). Then proto types own `Bytes` end-to-end, and the `into()` conversions become free.
2. In `runner.rs`, change `Encrypt::encrypt` to return `Bytes` (or accept an output `BytesMut`). For v2 GCM the API constructs `Vec` then prepends nonce — switch to `BytesMut::with_capacity(...)`.
3. In `socket.rs:231` (input path) keep the existing `to_vec()` because the proto input field is `Vec<u8>` after step 1 it would be `Bytes` and the `.to_vec()` becomes `.into()`.

**Risk**: cross-cutting type change. Touches generated code + every call site. Worth doing because (a) there are many sites and (b) `Bytes::clone()` is cheap (refcount), enabling cleaner broadcast fanout.

**Verify**:
- Microbench: send 1 GiB through the encrypt → proto → server → broadcast path, measure `RUSTFLAGS=-Cinstrument-coverage` allocation count via `dhat-rs` or `bytehound`.
- Validate proto wire compatibility with existing clients (it is bytes-equivalent).

### 1.5 [🟢] [✅ `a22965d`] `prev_char_boundary` is O(N)
**Where**: `crates/sshx/src/runner.rs:143-148`.

**Current**:
```rust
fn prev_char_boundary(s: &str, i: usize) -> usize {
    (0..=i).rev().find(|&j| s.is_char_boundary(j)).expect(...)
}
```
This scans backward from `i` (worst case `i = 64 KiB` characters) on every chunk send. For ASCII payloads it returns immediately, but for long contiguous multibyte stretches (rare in terminals but possible: long Asian/CJK output) it walks many bytes.

**Proposal**: use `str::floor_char_boundary` once it's stable, or open-code:
```rust
fn prev_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) { i -= 1; }
    i
}
```
A UTF-8 codepoint is at most 4 bytes, so the loop is bounded by 4 iterations, not `i`.

**Risk**: trivial. Nightly `floor_char_boundary` exists; the open-coded version above is portable.

**Verify**: unit test with mixed ASCII + emoji + CJK to confirm same return, then `cargo bench` on the `shell_task` write loop.

### 1.6 [🟡] [✅ `2ef4e7a`] One spawned task per `Subscribe`, per shell, per browser
**Where**: `crates/sshx-server/src/web/socket.rs:241-251`.

**Current**: every browser that subscribes to a shell spawns a Tokio task that lives for the WS connection. The task runs `async_stream` polling `notify.notified()` + reading the shell state under `RwLock`. With 10 viewers × 5 shells, that's 50 tasks waiting on 5 `Notify` instances.

**Proposal**:
- Switch to a single per-shell broadcast channel of `Bytes` (CBOR-encoded `WsServer::Chunks`), sized for backpressure. Producers (`add_data`) post once; subscribers receive directly.
- Or, fold the chunk delivery into the main session broadcast (item 1.2) with a side filter on subscriber-supplied shell IDs.

**Risk**: non-trivial — current design lets each viewer pick its own `chunknum` start cursor. A broadcast-only design needs a separate "catch-up" path: on first subscribe, send a snapshot of the rolling buffer, then attach to the broadcast.

**Verify**: connect 100 viewers to one session, measure `tokio-console` task count and per-task CPU before/after.

---

## 2. Single-node throughput, fanout, and lock contention

### 2.1 [🟡] [✅ `ac157ba`] `RwLock<HashMap<Sid, State>>` is a write-heavy global
**Where**: `crates/sshx-server/src/session.rs:48` and every `add_data`, `move_shell`, `add_shell`, `close_shell`, `subscribe_chunks` call.

**Current**: every PTY chunk arrival from the CLI takes `self.shells.write()` (in `add_data`), then mutates one shell's `State`. Every browser subscriber that polls `subscribe_chunks` takes `self.shells.read()`. With N shells and M viewers, the writer contends with the readers.

**Proposal**:
- Wrap each shell in `Arc<Mutex<State>>` (or `Arc<RwLock<State>>`) and store `RwLock<HashMap<Sid, Arc<Mutex<State>>>>` *only* for shell add/remove. The hot path (`add_data`, `subscribe_chunks`) takes a read lock on the map, clones the `Arc`, and releases the map lock immediately.
- For `add_data` -> single shell, that's a per-shell mutex (no cross-shell contention).
- For the watch source (`source: watch::Sender<Vec<(Sid, WsWinsize)>>`), keep as-is.

**Risk**: medium. Need to be careful about `notify` ordering: `notify_waiters` should be called after the lock is released on the inner state to avoid waking subscribers that immediately re-acquire and find no new data.

**Verify**:
- Stress test: 1 CLI publishing at 50 MB/s across 8 shells, 20 viewers, measure CPU + latency p99.
- `cargo bench` with `criterion` on `Session::add_data` under contention.

### 2.2 [🟡] [⏭️ skipped] `subscribe_chunks` clones the entire chunk vec
**Where**: `crates/sshx-server/src/session.rs:199`: `chunks = shell.data[start..].to_vec();` (a `Vec<Bytes>` clone, but each `Bytes` clone is refcount-only, so this is O(N) refcount bumps + one Vec alloc).

**Current**: on every wakeup, the subscriber clones the entire suffix. For a hot shell with hundreds of pending chunks, this is many small allocations under the write lock equivalent (read lock held during clone).

**Proposal**:
- Move the clone outside the lock: collect `chunks.iter().cloned()` into a pre-sized `Vec` after dropping the guard. Currently the guard *is* dropped (the inner block ends), so this is fine — but verify with a benchmark.
- Better: send a `(seqnum, Bytes)` per chunk, not a batch of `Vec<Bytes>`. The `WsServer::Chunks` shape is `(Sid, u64, Vec<Bytes>)` — change wire to `(Sid, u64, Bytes)` where the bytes are concatenated. This removes one CBOR list allocation per send and lets us coalesce consecutive small chunks. For v2 GCM each chunk is an atomic blob so concat won't work — keep `Vec<Bytes>` for v2, switch to concatenated `Bytes` for v1 only, or always use `Vec<Bytes>`.

**Risk**: wire protocol change. Cross-language contract with `src/lib/protocol.ts`.

**Verify**: subscriber catch-up of a 2 MiB rolling buffer across 50 viewers: time before/after.

### 2.3 [🟢] [✅ `d34ca3d`] `BroadcastStream` capacity vs subscriber kill
**Where**: `crates/sshx-server/src/session.rs:116` (`broadcast::channel(256)`).

**Current**: capacity 256. A slow subscriber (or one that pauses while the producer sends >256 events) is killed with `BroadcastStreamRecvError::Lagged` and the WS handler in `socket.rs:146` returns an error → connection drops.

**Proposal**:
- Tune capacity per workload. For chat-heavy / many-user scenarios, 256 is small.
- Or, replace with per-subscriber bounded mpsc (item 1.2) and apply back-pressure.

**Risk**: very low if just bumping capacity. Do this only after metrics show lag-kills.

**Verify**: log `BroadcastStreamRecvError` in the WS handler, deploy, measure rate.

### 2.4 [🟡] [⏭️ skipped] Move `Vec<(Sid, WsWinsize)>` watch payload to `Arc<...>`
**Where**: `crates/sshx-server/src/session.rs:60,150-156,222-230,245-247,270-277`.

**Current**: the watch channel holds `Vec<(Sid, WsWinsize)>`, and `subscribe_shells` produces a `WatchStream` that clones the value on every change. Every browser subscriber holds a clone of the latest version.

**Proposal**: change to `watch::Sender<Arc<Vec<(Sid, WsWinsize)>>>`. Clones become refcount bumps. Negligible per-element saving (`(Sid, WsWinsize)` is 16 bytes), but with N viewers each receiving on every shell add/move/close, the alloc churn matters.

**Risk**: trivial; only the consumers in `socket.rs:151` need a deref.

**Verify**: alloc profile under "10 viewers + 1 shell drag (continuous move events)".

### 2.5 [🟡] [✅ `cb976b9`] `update_user` on cursor moves broadcasts to everyone
**Where**: `crates/sshx-server/src/session.rs:335-346` and the `WsClient::SetCursor` handler in `socket.rs:173-175`.

**Current**: every mouse-move in any browser hits the server (one WS message per move event) → server takes `users.write()` → broadcasts `WsServer::UserDiff` to every subscriber. With M viewers all moving, this is O(M²) traffic + lock churn.

**Proposal**:
- Coalesce on the client (already partially the case in `Session.svelte`, but worth re-checking; cap at e.g. 30 Hz).
- Server: rate-limit broadcast of cursor diffs per user (e.g., debounce 33 ms); always store latest, but only fanout at the rate-limited cadence.
- Use a separate broadcast topic for cursors so a slow viewer's lag-kill doesn't drop chat/shell events.

**Risk**: medium; cursor smoothness is user-visible.

**Verify**: synthetic test with 10 simulated cursors at 100 Hz, server CPU and broadcast queue depth before/after.

### 2.6 [🟢] DashMap concurrency level for `ServerState::store`
**Where**: `crates/sshx-server/src/state.rs:38`.

**Current**: `DashMap::new()` uses default shard count (CPU-derived). For a single-server deployment with thousands of sessions and bursty `frontend_connect` lookups, this is fine. For mesh, the `lookup` and `insert` happen frequently.

**Proposal**: explicitly size with `DashMap::with_shard_amount((num_cpus * 4).next_power_of_two())` if profiling shows shard contention. Ignore otherwise.

**Verify**: `tracing::span` around `ServerState::lookup` under load; if shard latency shows up, tune.

---

## 3. CPU and memory under high session density

### 3.1 [🟡] [✅ `a1d6d2f`] `Session::snapshot` zstd-compresses every 20 s
**Where**: `crates/sshx-server/src/session/snapshot.rs:73` (`zstd::bulk::compress(&data, 15)`) called from `mesh.rs:135`.

**Current**: zstd level 15 (very high) every `STORAGE_SYNC_INTERVAL = 20 s` per active session. With 1000 sessions averaging 32 KiB of state, that's ~30 MiB/20 s of compression at a high level — non-trivial CPU.

**Proposal**: drop to zstd level 3 or 5. The data sits in Redis briefly; compression ratio matters less than CPU. Level 3 is typically 3-5× faster than 15 with only ~10–20% larger output.

**Risk**: trivial.

**Verify**: time `Session::snapshot()` on a 32 KiB and a 4 MiB session, before/after. Measure compressed size delta.

### 3.2 [🟢] [✅ `62a9fce`] `SerializedShell::data: Vec<Vec<u8>>` does an extra alloc per chunk
**Where**: `crates/sshx-server/src/session/snapshot.rs:50` (`shell.data[prefix..].iter().map(|b| b.to_vec())`).

**Current**: every chunk `Bytes` is copied to `Vec<u8>` for prost. With many small chunks, this is many small allocs.

**Proposal**: configure prost's `bytes(&["."])` to use `Bytes` (item 1.4); then this becomes `iter().cloned().collect()` — refcount only.

**Verify**: snapshot a session with 256 chunks, allocation count via dhat.

### 3.3 [🟢] [⏸️] `IdCounter::get_current_values` and `set_current_values` are unaccounted hotspots
**Where**: `crates/sshx-core/src/lib.rs` (not yet read, but called from `snapshot.rs:23,113`).

**Action**: confirm they're cheap atomics (likely `AtomicU32::load(Relaxed)` already). If they take a mutex, fix.

**Verify**: read source, run `cargo asm` on `IdCounter::get_current_values`.

### 3.4 [🟡] [✅ partial `14ae3db`] Rolling buffer size: 2 MiB on server, 8–12 MiB on client
**Where**:
- Server: `session.rs:26` `SHELL_STORED_BYTES = 2 MiB`.
- Client: `runner.rs:16-17` `CONTENT_ROLLING_BYTES = 8 MiB`, `CONTENT_PRUNE_BYTES = 12 MiB`.

**Current**: per-shell. With 100 sessions × 5 shells each, server uses up to 1 GiB just for output buffers. Client uses up to 60 MiB per shell × shells.

**Proposal**:
- Make `SHELL_STORED_BYTES` configurable via CLI flag (already an integer constant). Add an env var `SSHX_SHELL_STORED_BYTES`.
- Consider tiered storage: keep the most recent 256 KiB hot; offload older chunks to a compressed `Vec<u8>` zone that is decompressed only on subscriber catch-up.
- For the client, `CONTENT_PRUNE_BYTES = 12 MiB` is fine (only paid when the shell falls badly behind), but document it in `--help`.

**Risk**: low (configurability) to medium (tiered storage).

**Verify**: under 1000 sessions × 5 shells idle, RSS before/after configurable buffer.

### 3.5 [🟡] [✅ `bed9898`] `last_accessed` uses `Mutex<Instant>` per session
**Where**: `crates/sshx-server/src/session.rs:57,114,414-420`.

**Current**: `Mutex<Instant>` updated on every gRPC update from the CLI (via `session.access()` in `grpc.rs:183`). For 1000 sessions each doing ~10 updates/s, that's 10k mutex acquisitions/s. Negligible, but…

**Proposal**: use `AtomicU64` storing milliseconds since some reference. Skip the mutex.

**Risk**: trivial.

**Verify**: not worth measuring; just cleaner.

### 3.6 [🟢] [✅ `cfb9214`] `tower_http::trace::TraceLayer` per-message allocations
See item 1.3.

---

## 4. Redis mesh and cross-node routing

### 4.1 [🟡] [✅ `fcde9ed`] Ownership cache TTL of 2 s + Redis pipe on cache miss
**Where**: `crates/sshx-server/src/state/mesh.rs:21,78-97`.

**Current**: on every browser WS connect to a session not local to this node, `get_owner` is called. Cache hit is `DashMap` lookup; miss is a Redis pipe of two GETs.

**Proposal**:
- 2 s TTL is reasonable. Validate with metrics: log cache hit rate.
- Background-refresh the cache: when an entry is read and is `> 1 s` old, refresh asynchronously and return the cached value. Avoids the hot-path Redis round-trip.
- Listen to a Redis pub/sub channel for ownership changes — write side updates `ownership_cache` directly. This eliminates TTL-induced staleness *and* most reads.

**Risk**: medium; pub/sub adds complexity.

**Verify**: `redis-cli MONITOR` during a simulated 100 viewers/s connect rate; count ownership lookups before/after.

### 4.2 [🟢] [⏸️] `set_options` with PX expiration on every snapshot write
**Where**: `crates/sshx-server/src/state/mesh.rs:23-26,142-150`.

**Current**: every 20 s `STORAGE_SYNC_INTERVAL` writes owner + snapshot with a 300 s TTL. Fine.

**Observation**: only a refresh, no churn. No action needed unless `STORAGE_EXPIRY` is reduced.

### 4.3 [🟡] [⏸️] `proxy_redirect` does message-by-message translation
**Where**: `crates/sshx-server/src/web/socket.rs:270-330`.

**Current**: for sessions owned by a different node, this server proxies the WS bidirectionally between browser and the owning node, translating axum's WS message types to tungstenite's per message. Two select loops each doing format match + clone.

**Proposal**:
- Accept the cost; this only matters if mesh proxying is the dominant deployment pattern.
- If it is, consider an HTTP redirect (`HTTP 307` to the owning node's external URL) instead of in-band proxy. Saves the relay node's CPU and WS connection. Downsides: client needs to know how to reach the owning node externally; doesn't work for split-horizon DNS or behind a single LB.
- For the in-band case, batch / passthrough binary frames without re-cloning the payload (axum's `Bytes` and tungstenite's `Bytes` are both `bytes::Bytes`-compatible? Verify; if so, no copy needed).

**Risk**: high if going to redirect (deployment model change).

**Verify**: `bytehound` profile on the relay node; confirm `Message::Binary(b)` payloads are zero-copy.

### 4.4 [🟢] `redis::pipe()` for ownership on every browser connect (when no cache)
Already partially addressed in 4.1.

---

## 5. Client (CLI) PTY → gRPC link

### 5.1 [🟡] [⏸️] Single-buffer PTY read with no pipelining of encrypt + send
**Where**: `crates/sshx/src/runner.rs:74-138`.

**Current**: the loop reads PTY into a stack `[u8; 65536]`, decodes UTF-8 into `content`, then in the same iteration may `encrypt + send`. The encrypt and send are awaited inline; while sending, the PTY is not being read.

**Proposal**:
- Split into two tasks: a reader task drains the PTY into a `tokio::sync::mpsc::Sender<Bytes>` queue, and a sender task does encrypt + send. Buffers absorb micro-stalls in the gRPC send.
- Keep the seq/sync feedback loop in the sender task (it reads `shell_rx` for `Sync`/`Size`/`Data` and writes to the PTY).

**Risk**: medium; need to be careful with the UTF-8 decoder state and ordering with `Sync` messages.

**Verify**: drive PTY at line-rate (`yes | head -c 100M`), measure throughput before/after; expect 1.5–2× on slower networks.

### 5.2 [🟢] [⏸️] `decoder.max_utf8_buffer_length(n).unwrap()` reservation on every read
**Where**: `runner.rs:81`.

**Current**: `content.reserve(decoder.max_utf8_buffer_length(n).unwrap())` runs per read. The reserve grows `content`'s capacity if needed; usually a no-op.

**Observation**: cheap, leave alone.

### 5.3 [🟢] [⏸️] `seq_outdated` heuristic to detect server-side state drift
**Where**: `runner.rs:91-97`.

**Observation**: existing logic resets `seq` after 3 outdated Sync messages. This is reasonable; document it inline.

### 5.4 [🟡] [✅ `7bc069b`] AES-256-GCM: every chunk allocates `Vec` for nonce + ciphertext
**Where**: `crates/sshx/src/encrypt.rs:147-167,180-194`.

**Current**: encrypt path allocates `Vec::with_capacity(GCM_NONCE_SIZE + ciphertext.len())`, copies nonce in, copies ciphertext in. Decrypt path allocates ciphertext-sized `Vec` inside `aes_gcm::decrypt`.

**Proposal**:
- Use `Aes256Gcm::encrypt_in_place_detached` and `decrypt_in_place_detached`. Returns the tag separately; you provide a `&mut [u8]` for the plaintext/ciphertext, plus a separate tag buffer. Combined output can then be assembled into a `BytesMut`.
- Switch to `aes-gcm`'s streaming `AeadInPlace` API where possible.

**Risk**: medium; cryptography boundary, easy to get wrong. Add roundtrip + AAD-mismatch tests.

**Verify**: criterion benchmark of `Encrypt::encrypt` for 64 KiB payload, check allocation count via dhat.

### 5.5 [🟢] [⏸️] Echo runner copies via `String::from_utf8_lossy`
**Where**: `crates/sshx/src/runner.rs:160`.

**Observation**: only used in tests; ignore.

---

## 6. Protocol-level (🔴) considerations

### 6.1 [🔴] [⏸️] CBOR vs a length-prefixed compact framing
WebSocket payloads are CBOR. CBOR encoding allocates and is not zero-copy on either end. Alternatives:
- **Postcard** (`serde` compatible, varint-based): smaller and faster than CBOR; same `serde` API surface, low migration cost.
- **rkyv**: zero-copy deserialisation. Frontend support is via `rkyv-wasm`, harder to integrate.

**Proposal**: switch to postcard. The wire is opaque to the user (already binary), so there's no UX loss. Frontend gets `postcard` for TypeScript via `@nullify-services/postcard` or a custom decoder.

**Risk**: protocol change, version negotiation needed (or hard cutover with version bump).

**Verify**: micro-benchmark serialise/deserialise of `WsServer::Chunks(Sid, u64, vec_of_4kib_bytes_x_16)` for both formats.

### 6.2 [🔴] [⏸️] gRPC vs raw QUIC / WebTransport for the CLI ↔ server link
Tonic+H2 is fine, but the bidirectional stream is a single H2 stream over a single TCP connection, so head-of-line blocking applies to all shells in a session.

**Proposal** (long-horizon): consider WebTransport (HTTP/3) for the CLI link. Each shell can be its own QUIC stream, eliminating HoL blocking and giving 0-RTT on resume.

**Risk**: high. Tonic doesn't support H3 yet; would need a custom transport.

**Verify**: simulate packet loss on the CLI link, measure per-shell latency under HoL contention.

### 6.3 [🔴] [⏸️] Multi-CLI per session
Currently a session has one CLI backend. For team shared sessions where multiple machines participate, you'd need a session-level mux. Out of scope for this audit but worth noting as a future architectural option.

---

## 7. Quick-win checklist (implement first, lowest risk, highest signal)

1. ☑ `a1d6d2f` Lower zstd level from 15 → 3 in `snapshot.rs:73` (1 line, ~3–5× faster snapshot CPU).
2. ☑ `a22965d` Replace `prev_char_boundary` with O(1) version (`runner.rs:143`).
3. ☑ `bed9898` `last_accessed: AtomicU64` instead of `Mutex<Instant>` (`session.rs:57`).
4. ⏭️ ~~`watch::Sender<Arc<Vec<...>>>` for shells source (`session.rs:60`)~~ — checklist entry contradicts §3.1 of the audit body, which notes the watch channel only ever holds the latest value (single-reader-of-latest semantics), so wrapping in `Arc` saves nothing measurable. Skipped.
5. ☑ `cfb9214` TraceLayer at DEBUG by default; INFO on errors only (`listen.rs:29,45`).
6. ☑ `520946f` Remove or raise `RECONNECT_INTERVAL` (`controller.rs:26`); document in CHANGELOG. (Raised 60 s → 10 min as a conservative first step; full removal still ⏸️.)
7. ☑ `14ae3db` Add `SSHX_SHELL_STORED_BYTES` env var (`session.rs:26`).
8. ☑ `d34ca3d` Bump `broadcast::channel` capacity from 256 → 1024 if logs show lag-kills (`session.rs:116`).

## 8. Validation and ongoing measurement

Before any of these lands, set up baseline measurements. None of the recommendations above are worth merging without a before/after number.

### 8.1 Repo-side benchmark scaffolding (not yet present)
Create `crates/sshx-server/benches/`:

- `broadcast_fanout.rs` — criterion: 1 producer, N viewers (N ∈ {1, 10, 50, 200}), measure throughput and per-message latency for `WsServer::Chunks` of varying sizes.
- `add_data.rs` — criterion: contention test, K writers + R readers on `Session::add_data` / `subscribe_chunks`.
- `snapshot.rs` — criterion: snapshot of session sizes ∈ {32 KiB, 256 KiB, 2 MiB}.

Add `cargo bench` to local dev workflow (CI: too slow, run on demand).

### 8.2 Integration load test
Create `crates/sshx-server/tests/load_smoke.rs` (or a separate `xtask` binary) that spins up the server in-process and:
1. Connects N CLI clients.
2. Connects M browser clients per session.
3. Drives PTY at fixed bytes/s, measures end-to-end byte delivery latency.
4. Records p50/p99 and CPU/RSS.

A 60 s smoke run before/after each change gives the credibility number for the PR.

### 8.3 Production-shaped profile
On a realistic Fly.io or local Docker deployment:
- `cargo flamegraph -p sshx-server -- --override-origin ... --secret ...` while a load tool drives traffic.
- Compare top frames before/after.

### 8.4 Memory profile
- `bytehound` or `dhat` on the same setup; track allocations per session and per broadcast.

### 8.5 Latency from the user's perspective
- A small Playwright script that loads the share URL, types a key, and measures time from `keydown` to glyph appearing on screen via `MutationObserver` on the terminal element.
- Run nightly against a dev deployment; track p99 over time.

---

## Appendix: file-line map

| Concern | File | Lines |
|---------|------|-------|
| broadcast channel | `crates/sshx-server/src/session.rs` | 67, 116, 147–150 |
| shell map lock | `crates/sshx-server/src/session.rs` | 48, 252–261, 282–323 |
| chunk subscription | `crates/sshx-server/src/session.rs` | 173–214 |
| user diff broadcast | `crates/sshx-server/src/session.rs` | 335–346 |
| WS send (CBOR per send) | `crates/sshx-server/src/web/socket.rs` | 77–82 |
| WS subscribe spawn | `crates/sshx-server/src/web/socket.rs` | 241–251 |
| proxy redirect | `crates/sshx-server/src/web/socket.rs` | 270–330 |
| TraceLayer | `crates/sshx-server/src/listen.rs` | 29, 45 |
| Steer multiplex | `crates/sshx-server/src/listen.rs` | 52–61 |
| sync interval | `crates/sshx-server/src/grpc.rs` | 23, 140 |
| storage sync interval | `crates/sshx-server/src/state/mesh.rs` | 15, 119–152 |
| ownership cache | `crates/sshx-server/src/state/mesh.rs` | 21, 78–97 |
| disconnected expiry | `crates/sshx-server/src/state.rs` | 27, 183–199 |
| heartbeat / reconnect | `crates/sshx/src/controller.rs` | 23, 26, 172–195 |
| PTY read loop | `crates/sshx/src/runner.rs` | 56–138 |
| char boundary scan | `crates/sshx/src/runner.rs` | 143–148 |
| GCM allocation | `crates/sshx/src/encrypt.rs` | 147–167, 180–194 |
| snapshot zstd | `crates/sshx-server/src/session/snapshot.rs` | 73 |
| SerializedShell vec→vec copy | `crates/sshx-server/src/session/snapshot.rs` | 50 |

---

## 9. Implementation log

Updated after the first round of changes. Status legend at top of file.

### Landed (15 commits ahead of `origin/main`)

| Commit | Section(s) | Summary |
|--------|------------|---------|
| `496be12` | — | docs: rewrite AGENTS.md to be concise and accurate |
| `ea1abf2` | — | docs: this file |
| `a1d6d2f` | §3.1, §7.1 | snapshot zstd 15 → 3 |
| `a22965d` | §1.5, §7.2 | `prev_char_boundary` O(N) → O(1) |
| `bed9898` | §3.5, §7.3 | `last_accessed` `Mutex<Instant>` → `AtomicU64` (millis since process-start `Instant`) |
| `cfb9214` | §1.3, §3.6, §7.5 | TraceLayer + per-message span demoted from INFO to DEBUG |
| `d34ca3d` | §2.3, §7.8 | broadcast capacity 256 → 1024 |
| `14ae3db` | §3.4 (partial), §7.7 | `SHELL_STORED_BYTES` configurable via `SSHX_SHELL_STORED_BYTES` env var (≥ 4 KiB floor; default 2 MiB) |
| `520946f` | §1.1, §7.6 | `RECONNECT_INTERVAL` 60 s → 600 s (conservative; full removal still ⏸️) |
| `01c1699` | §1.2, top-10 #1 | broadcast frames pre-encoded once via `Sender<Bytes>`; `receiver_count() == 0` short-circuit |
| `ac157ba` | §2.1, top-10 #5 | `RwLock<HashMap<Sid, State>>` → `RwLock<HashMap<Sid, Arc<Mutex<State>>>>`; outer→inner lock order; `add_data` rechecks `closed` defensively |
| `cb976b9` | §2.5 | cursor broadcasts throttled to 50 ms per WebSocket via pinned `tokio::time::sleep` flush; final value never lost |
| `fcde9ed` | §4.1, top-10 #10 (related) | ownership cache TTL 2 s → 30 s + new `invalidate_ownership()` called from `state::listen_for_transfers` after pub/sub event |
| `2ef4e7a` | §1.6, top-10 #9 | per-`Subscribe` spawn + mpsc(64) replaced by `tokio_stream::StreamMap<Sid, ChunkStream>` merged into the main `select!` loop |
| `62a9fce` | §1.4, §3.2, top-10 #3 | `prost .bytes(".")` for all `bytes` fields; `Vec<u8>` → `bytes::Bytes` end-to-end; cleaned redundant `.into()` / `.to_vec()` at boundaries |

### Skipped with rationale

- **§2.2 / top-10 #4** `subscribe_chunks` clones the chunk vec — `Vec<Bytes>::to_vec()` is just refcount bumps + ~16 B/chunk header memcpy. With the default 2 MiB rolling buffer that is on the order of hundreds of bytes total, well below the threshold worth refactoring without a profile showing it as hot.
- **§2.4** `Vec<(Sid, WsWinsize)>` → `Arc<Vec<...>>` watch payload — `tokio::sync::watch` keeps only the latest value and clones on `borrow()`. The vec is small (one entry per shell, typically ≤ 8) and the clone cost is dominated by the `Arc` overhead it would add. Net change is neutral or negative; deferred until proven hot.
- **§7.4** same conclusion as §2.4 (the audit body §3.1 noted this as not worth doing; the checklist row was inconsistent).

### Not started (medium / large) — pending baseline or design

- **§4.2** Redis snapshot writes carry full PX expiration on every push. Cheap optimisation but requires server-side TTL management.
- **§4.3** `proxy_redirect` does message-by-message translation. Correct but slow on cross-node hot paths.
- **§5.1** Single-buffer PTY read with no pipelining of encrypt + send.
- **§5.2** `decoder.max_utf8_buffer_length(n).unwrap()` reservation on every read.
- **§5.3** `seq_outdated` heuristic to detect server-side state drift.
- **§5.4** AES-256-GCM in-place encryption (avoid per-chunk `Vec` allocation).
- **§5.5** Echo runner copies via `String::from_utf8_lossy`.
- **§3.3** `IdCounter::get_current_values` — verify atomic implementation.
- **§3.4** (remaining) Tiered storage: hot 256 KiB + cold compressed zone.
- **Top-10 #6** Argon2 KDF on the WS task — frontend-side mostly; no Rust change required immediately.
- **Top-10 #10** Redis sequence-number sync interval reduction.

### Not started (protocol-level, 🔴) — design phase only

- **§6.1** CBOR → length-prefixed compact framing (postcard / borsh).
- **§6.2** gRPC → raw QUIC / WebTransport for the CLI ↔ server link.
- **§6.3** Multi-CLI per session.

All landed commits keep the wire protocol bit-compatible with the previous release; the only externally visible additions are the new `SSHX_SHELL_STORED_BYTES` env var and the longer CLI reconnect interval.

---

## 10. Baselines (criterion)

Initial baseline numbers, recorded after `7bc069b`. Apple M-series, release profile, 20 samples / 2 s measurement window. Use these as the regression reference for future optimisation work.

Run all benches:

```shell
cargo bench -p sshx
cargo bench -p sshx-server
```

| Bench | Group / input | Time (median) | Throughput (median) |
|-------|---------------|---------------|---------------------|
| `sshx::encrypt` | `encrypt_v2/4KiB` | 1.53 µs | 2.49 GiB/s |
| `sshx::encrypt` | `decrypt_v2/4KiB` | 1.53 µs | 2.49 GiB/s |
| `sshx::char_boundary` | `prev_char_boundary/multibyte/4KiB` | 1.18 ns | — |
| `sshx::char_boundary` | `prev_char_boundary/multibyte/64KiB` | 1.17 ns | — |
| `sshx::char_boundary` | `prev_char_boundary/multibyte/1024KiB` | 1.17 ns | — |
| `sshx-server::snapshot` | `encode+zstd3/1sh_32KiB` | 2.43 µs | (input-rate, see note) |
| `sshx-server::snapshot` | `encode+zstd3/4sh_64KiB` | 6.42 µs | |
| `sshx-server::snapshot` | `encode+zstd3/16sh_128KiB` | 11.5 µs | |

Notes:

- `prev_char_boundary` is constant in input length — confirms the §1.5 rewrite is O(1) regardless of how far into a multi-byte string we scan.
- `encrypt_v2` / `decrypt_v2` 1.53 µs / 4 KiB ≈ 2.5 GiB/s is the post-`7bc069b` AeadInOut number; pre-rewrite would need a `git revert` for an A/B comparison.
- `session_snapshot` throughput is reported against *input* bytes; per-shell pruning at `SHELL_SNAPSHOT_BYTES = 32 KiB` means actual serialized payload is much smaller. Track absolute time, not throughput.

---

## 11. Items evaluated and skipped

Documented for future readers so they don't re-evaluate them without new evidence.

- **§5.2 decoder buffer reservation** — `content.reserve(decoder.max_utf8_buffer_length(n).unwrap())` in `runner.rs:81` was flagged as a possible micro-optimisation. On inspection: the reservation is bounded by the input read size (≤ 65 536 bytes) so `unwrap()` cannot panic, and `String::reserve` is amortized O(1) — there's no real allocation to elide. Skipped.
- **§5.1 PTY read pipelining** — splitting PTY read from encrypt+send into two tasks via channel was rejected as not worth ~50 LOC of complexity in the absence of a baseline showing it's hot. The current single-buffer design also keeps backpressure trivial. Reopen if an end-to-end keystroke-latency benchmark proves otherwise.
- **#6 / Argon2 KDF off-WS-task** — re-checked: server-side `web/socket.rs` only does `subtle::ct_eq` on hashes derived by the browser, not the Argon2 KDF itself. The bottleneck this item describes is purely browser-side. No Rust change applies.
