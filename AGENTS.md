# AGENTS.md

Project-specific context for AI agents working in the `sshx` repository.

## Quick-start commands

```shell
# Prerequisites: Rust 1.70+, Node 18+, npm 9+, protoc, mprocs, Docker
docker compose up -d          # Start Redis on port 12601
npm install                   # Install frontend deps
mprocs                        # Run server + client + Vite in parallel
```

`mprocs` runs:
- **Server**: `cargo run --bin sshx-server -- --override-origin http://localhost:5173 --secret dev-secret --redis-url redis://localhost:12601`
- **Client**: `cargo run --bin sshx -- --server http://localhost:8051`
- **Web**: `npm run dev` (Vite on port 5173, proxies `/api` → `http://[::1]:8051`)

## CI gate — all must pass before merge

```shell
cargo +nightly fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo test -p sshx            # also run on Windows in CI for conpty
npm run lint                  # prettier --check + ESLINT_USE_FLAT_CONFIG=false eslint
npm run check                 # svelte-check type checking
npm run build
```

Note: CI uses `npm ci`, not `npm install`.

## Running focused tests

```shell
# Single integration test (server crate)
cargo test -p sshx-server --test with_client test_ws_basic

# Single unit test (client crate)
cargo test -p sshx --lib terminal::tests::winsize

# All server integration tests (requires protoc)
cargo test -p sshx-server
```

## Protobuf / code generation

Proto sources are **pre-generated** and committed to `crates/sshx-core/src/generated/`. To regenerate after editing `crates/sshx-core/proto/sshx.proto`:

```shell
SSHX_REGENERATE_PROTO=1 cargo build -p sshx-core
```

Do NOT just run `cargo build` — the env var gates regeneration.

## Rust code style

- Format: `cargo +nightly fmt` — uses nightly features (`group_imports`, `format_strings`, `wrap_comments`).
- `sshx-core` and `sshx-server`: `#![forbid(unsafe_code)]`.
- `sshx` (client): `#![deny(unsafe_code)]`; unsafe only in `terminal/unix.rs` and `terminal/windows.rs`.
- All crates: `#![warn(missing_docs)]`.
- Errors: `anyhow::Result`. Logging: `tracing`.

## TypeScript / Svelte style

- `npm run lint` runs: `prettier --check . && ESLINT_USE_FLAT_CONFIG=false eslint .`
- Svelte files are excluded from ESLint (`ignorePatterns` in `.eslintrc.cjs`).
- Strict TypeScript mode. No JS unit test runner — frontend validation is lint + check + build.
- Svelte 5 is used (`^5.55.4`) but component code uses legacy `$:` reactive syntax, not runes.

## Architecture

Three Rust crates under `crates/`:

| Crate | Role |
|-------|------|
| `sshx-core` | Shared protobuf/gRPC types, `Sid`/`Uid`/`IdCounter`, `rand_alphanumeric()` |
| `sshx-server` | Axum HTTP/WS + Tonic gRPC, session state, Redis mesh |
| `sshx` | CLI client — PTY + gRPC + AES-CTR encryption |

**Protocol boundaries:**
- CLI ↔ Server: gRPC bidirectional streaming (`SshxService::Channel` in `sshx.proto`)
- Browser ↔ Server: WebSocket `/api/s/{name}` with CBOR messages (`WsServer`/`WsClient` in `protocol.rs`)

**Data flow:**
1. CLI calls gRPC `Open` → gets share URL; encryption key lives only in the URL fragment.
2. Browser loads `/s/[id]`, derives key, authenticates over WebSocket (encrypted zero-block check).
3. Input: WebSocket → server session → gRPC stream → CLI PTY.
4. Output: CLI PTY → gRPC stream → session rolling buffer → WebSocket subscribers.

## Key source files

### Server

- `crates/sshx-server/src/listen.rs` — **Multiplexes HTTP/WebSocket and gRPC on the same port** by inspecting `Content-Type`. Start here if transport routing changes.
- `crates/sshx-server/src/session.rs` — Authoritative in-memory model for a live session: shells, rolling output chunks, users, broadcasts.
- `crates/sshx-server/src/state.rs` — Global session registry: lookup/insert/remove, expiry (5 min after disconnect), mesh-aware routing.
- `crates/sshx-server/src/state/mesh.rs` — Redis-backed snapshot and cross-node ownership.
- `crates/sshx-server/src/web/socket.rs` — Browser WebSocket auth, subscriptions, shell events, redirect/proxy.
- `crates/sshx-server/src/web/protocol.rs` — WebSocket message types (keep in sync with `src/lib/protocol.ts`).

### Client

- `crates/sshx/src/controller.rs` — gRPC channel lifecycle: `Open`, `Channel`, reconnects, heartbeats.
- `crates/sshx/src/runner.rs` — Shell task, UTF-8 buffering, encrypted output forwarding.
- `crates/sshx/src/encrypt.rs` — AES-CTR encryption (keep in sync with `src/lib/encrypt.ts`).

### Frontend (`src/`)

- `src/routes/s/[id]/+page.svelte` — Session route entrypoint.
- `src/lib/Session.svelte` — Main canvas orchestrator: WebSocket auth, shell subscriptions, terminal placement/resize, cursors, chat.
- `src/lib/ui/XTerm.svelte` — Wraps `@wterm/dom` for terminal rendering and input.
- `src/lib/srocket.ts` — Reconnecting CBOR-over-WebSocket transport used by the frontend.
- `src/lib/encrypt.ts` — Browser-side encryption (mirror of Rust `encrypt.rs`).
- `src/lib/protocol.ts` — TypeScript mirrors of WebSocket message types.

Build output goes to `build/` (served by the Rust server in production). SvelteKit uses `adapter-static` with `fallback: "spa.html"`.

## Cross-language contracts (must stay in sync)

| Contract | Rust | TypeScript |
|----------|------|-----------|
| gRPC/protobuf | `crates/sshx-core/proto/sshx.proto` | (generated) |
| WebSocket protocol | `crates/sshx-server/src/web/protocol.rs` | `src/lib/protocol.ts` |
| E2E encryption | `crates/sshx/src/encrypt.rs` | `src/lib/encrypt.ts` |

## Frontend event handling (non-obvious, easy to break)

- **Terminal drag**: Handled only in `XTerm.svelte` via `handleTitlePointerDown/Move/Up` with `setPointerCapture`. Dispatches `startMove` event; handled by the `on:startMove` handler in `Session.svelte`. Do NOT add global `pointermove`/`pointerup` window listeners for drag — this was removed due to duplicate `move` messages and race conditions.
- **Canvas pan**: `TouchZoom` (`src/lib/action/touchZoom.ts`) using `@use-gesture/vanilla` on `fabricEl`.
- **Resize**: Small handle div inside `Session.svelte`.
- Global window listeners should only handle: resize events (checking `resizingPointerId`) and cursor position updates (`setCursor`).
- `mousedown` and `pointerdown` are independent. `stopPropagation()` on `pointerdown` does NOT stop `mousedown`. In `.term-container`, guard `bringToFront` with `!isDragging`.

## Terminal rendering

`@wterm/dom` replaced `xterm.js`. Cell dimensions are measured by injecting temporary DOM elements with wterm CSS classes — not by reading canvas bounds.

## Ports

| Service | Port |
|---------|------|
| Redis | 12601 |
| Rust server | 8051 |
| Vite dev | 5173 |
