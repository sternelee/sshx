# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development commands

- Requirements: Rust 1.70+, Node 18, npm 9, Docker, and `mprocs`.
- Start Redis for local development: `docker compose up -d`
- Run the full local stack: `npm install && mprocs`
  - `mprocs` starts:
    - server: `cargo run --bin sshx-server -- --override-origin http://localhost:5173 --secret dev-secret --redis-url redis://localhost:12601`
    - client: `cargo run --bin sshx -- --server http://localhost:8051`
    - web: `npm run dev`
- Web dev server only: `npm run dev`
- Web checks:
  - `npm run lint`
  - `npm run check`
  - `npm run build`
- Rust checks:
  - `cargo test`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo +nightly fmt -- --check`
- Build release binaries: `cargo build --release`
- Build/install the CLI from source: `cargo install --path crates/sshx`
- Run a single Rust integration test: `cargo test -p sshx-server --test with_client test_ws_basic`
- Run a single Rust unit test: `cargo test -p sshx --lib terminal::tests::winsize`

Local ports used by the default dev workflow:
- Redis: `12601`
- Rust server: `8051`
- Vite dev server: `5173`

Protobuf sources are pre-generated in `crates/sshx-core/src/generated/`. To regenerate after changing `sshx.proto`, install `protoc` and run with `SSHX_REGENERATE_PROTO=1 cargo build -p sshx-core`.

## CI expectations

Before considering work complete, match the CI checks in `.github/workflows/ci.yaml`:
- `cargo +nightly fmt -- --check`
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test -p sshx` on Windows
- `npm run lint`
- `npm run check`
- `npm run build`

Deploys are handled separately by Fly and only run on pushes to `main`.

## Architecture overview

This repository is a Rust workspace plus a Svelte frontend:
- `crates/sshx-core/` — shared protobuf definitions and core ID/types used by both binaries.
- `crates/sshx/` — the CLI/session owner. It opens sessions over gRPC, owns PTY subprocesses, and encrypts terminal traffic.
- `crates/sshx-server/` — the Rust backend. It serves the built web app, manages session state, and bridges browser clients to the owning CLI.
- `src/` — the SvelteKit frontend, built as a static SPA and served by the Rust backend in production.

### End-to-end data flow

1. The CLI opens a session via gRPC `Open`.
2. The server returns a share URL; the encryption key stays only in the URL fragment, so the server never receives it.
3. The browser loads `/s/[id]`, derives the key from the fragment, and authenticates over WebSocket using the encrypted zero-block check.
4. Browser input flows `WebSocket -> server session -> gRPC stream -> CLI PTY`.
5. PTY output flows `CLI PTY -> gRPC stream -> server session rolling buffer -> WebSocket subscribers`.

### Important subsystems

- `crates/sshx-server/src/listen.rs` multiplexes HTTP/WebSocket traffic and gRPC on the same listener by checking `Content-Type`. If transport routing changes, start here.
- `crates/sshx-server/src/session.rs` is the authoritative in-memory model for a live collaborative session: shells, rolling output chunks, connected users, broadcasts, and queued backend updates. Most session semantics changes belong here.
- `crates/sshx-server/src/state.rs` is the global session registry. It handles lookup/insert/remove, expiry of disconnected sessions, and mesh-aware frontend/backend connection routing.
- `crates/sshx-server/src/state/mesh.rs` is the Redis-backed cross-node ownership/snapshot layer. It persists session snapshots and coordinates handoff between nodes.
- `crates/sshx-server/src/web/socket.rs` handles browser WebSocket auth, subscriptions, shell create/close/move/input events, chat, and redirect/proxy behavior when another node owns the session.

### CLI/client internals

- `crates/sshx/src/controller.rs` owns the gRPC channel lifecycle: `Open`, `Channel`, reconnects, heartbeats, and shell task orchestration.
- `crates/sshx/src/runner.rs` runs each shell task, manages UTF-8 output buffering/chunking, and forwards encrypted terminal data back to the server.
- `crates/sshx/src/terminal/unix.rs` and `crates/sshx/src/terminal/windows.rs` are the OS-specific PTY implementations.

### Frontend internals

- `src/routes/s/[id]/+page.svelte` is the session route entrypoint.
- `src/lib/Session.svelte` is the main browser-side orchestrator. It handles URL-fragment auth, the reconnecting WebSocket, shell subscriptions, terminal placement/resizing, cursor presence, chat, and read-only vs write access.
- `src/lib/ui/XTerm.svelte` wraps `@wterm/dom` for terminal rendering and input forwarding.
- `src/lib/srocket.ts` is the reconnecting CBOR-over-WebSocket transport used by the frontend.

### Cross-language contracts that must stay in sync

These files define protocols shared across Rust and TypeScript. If one side changes, update the other side in the same change.

- gRPC/protobuf contract: `crates/sshx-core/proto/sshx.proto`
- WebSocket protocol:
  - Rust: `crates/sshx-server/src/web/protocol.rs`
  - TypeScript: `src/lib/protocol.ts`
- End-to-end encryption implementation:
  - Rust: `crates/sshx/src/encrypt.rs`
  - TypeScript: `src/lib/encrypt.ts`

### Frontend/backend integration details

- In development, Vite proxies `/api` to `http://[::1]:8051`.
- In production, SvelteKit uses `adapter-static` with `spa.html` fallback, and the Rust server serves the generated assets from `build/`.
- There are effectively no SvelteKit server endpoints here; browser clients talk to the Rust backend over `/api`.

### Testing shape

- Most behavior-heavy tests are Rust integration tests under `crates/sshx-server/tests/`.
- There is no dedicated JS unit test runner configured in `package.json`; frontend validation is done with `npm run lint`, `npm run check`, and `npm run build`.
