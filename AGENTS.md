# AGENTS.md

This file contains project-specific context for AI coding agents working on the
`sshx` repository. It is written in the same language as the project's comments
and documentation (English).

## Project overview

`sshx` is a secure, web-based, collaborative terminal. A user runs a local CLI
client that opens a pseudoterminal (PTY) and streams encrypted terminal I/O to a
lightweight Rust server. Other users can then join the session from a browser
link and interact with the terminal in real time on an infinite canvas.

Key features:

- End-to-end encryption (AES-CTR + Argon2id) — the server never sees plaintext.
- Multiplayer infinite canvas with draggable, resizable terminal windows.
- Real-time cursors, presence, and chat.
- Automatic reconnection and latency estimation.
- Predictive local echo (à la Mosh).
- Optional read-only mode with separate viewer/writer URLs.

The repository contains:

1. A Rust workspace with three crates (client, server, shared core).
2. A SvelteKit SPA frontend (TypeScript + Tailwind CSS).
3. Infrastructure configs for Fly.io, Docker, and GitHub Actions.

## Technology stack

- **Backend**: Rust 1.70+, Tokio async runtime, Tonic (gRPC), Axum (HTTP / WebSocket).
- **Frontend**: SvelteKit (Svelte 5), Vite, Tailwind CSS v4, TypeScript.
- **Data / Mesh**: Redis (for distributed session storage and server meshing).
- **Build tools**: Cargo, NPM / PNPM, Protobuf compiler (`protoc`), `mprocs`.
- **Deployment**: Fly.io (Docker multi-stage build), AWS S3 (release binaries).

## Architecture

### Rust workspace (`Cargo.toml`)

The workspace lives at the repo root and contains three crates under `crates/`:

| Crate | Purpose |
|-------|---------|
| `sshx-core` | Protobuf/gRPC definitions (via `tonic-prost-build`), shared types (`Sid`, `Uid`, `IdCounter`), and `rand_alphanumeric()`. All other crates depend on this. |
| `sshx-server` | Axum HTTP/WebSocket server + Tonic gRPC services. Serves static files from `build/`. Uses Redis for multi-server mesh and session snapshotting. |
| `sshx` | CLI client binary. Opens a local PTY (`nix` on Unix, `conpty` on Windows) and streams encrypted terminal data to the server over gRPC. |

**Protocol boundaries:**

- **CLI ↔ Server**: gRPC bidirectional streaming (`SshxService::Channel`), defined in `crates/sshx-core/proto/sshx.proto`.
- **Browser ↔ Server**: WebSocket on `/api/s/{name}` with CBOR-serialized messages (`WsServer` / `WsClient` enums in `crates/sshx-server/src/web/protocol.rs`).
- **Encryption**: A random 83-bit key is stretched with Argon2id and used for AES-CTR encryption of terminal byte streams. The TypeScript implementation in `src/lib/encrypt.ts` must be kept consistent with the Rust implementation in `crates/sshx/src/encrypt.rs`.

### Web frontend (`src/`)

- **Framework**: SvelteKit configured as a static SPA (`adapter-static` with `fallback: "spa.html"`).
- **Routes**:
  - `/` — Landing page with installation instructions (`src/routes/+page.svelte`).
  - `/s/[id]` — Active terminal session (`src/routes/s/[id]/+page.svelte`).
- **Dev proxy**: Vite proxies `/api` to `http://[::1]:8051` (the Rust server), including WebSocket upgrades.
- **Key libraries**: `@wterm/dom` (terminal rendering), `@use-gesture/vanilla` (pan/zoom), `perfect-cursors` (live cursors), `argon2-browser` (key derivation), `cbor-x` (CBOR serialization).

### Server state model

- `ServerState` holds an in-memory `DashMap` of active sessions.
- When Redis is configured (`--redis-url`), the server participates in a mesh:
  - Sessions are snapshotted to Redis.
  - Backend client connections can be redirected to the server that owns the session.
  - WebSocket connections may be redirected to the owning server.
- Disconnected sessions are evicted after 5 minutes.

## Key directories and files

```
├── crates/
│   ├── sshx-core/
│   │   ├── proto/sshx.proto          # gRPC service definition
│   │   ├── build.rs                  # tonic-prost-build code generation
│   │   └── src/lib.rs                # Shared types and proto re-exports
│   ├── sshx-server/
│   │   ├── src/
│   │   │   ├── main.rs               # Server CLI entry point
│   │   │   ├── lib.rs                # Server struct and options
│   │   │   ├── grpc.rs               # Tonic gRPC request handlers
│   │   │   ├── web.rs                # Axum HTTP router + static files
│   │   │   ├── web/socket.rs         # WebSocket session handler
│   │   │   ├── web/protocol.rs       # WebSocket message types
│   │   │   ├── state.rs              # In-memory session store + mesh logic
│   │   │   ├── state/mesh.rs         # Redis-backed distributed mesh
│   │   │   ├── session.rs            # Per-session logic and broadcast
│   │   │   └── listen.rs             # Hybrid Axum/Tonic server binding
│   │   └── tests/                    # Integration tests (requires server)
│   └── sshx/
│       ├── src/
│       │   ├── main.rs               # CLI entry point
│       │   ├── lib.rs                # Library exports
│       │   ├── controller.rs         # Main client event loop
│       │   ├── encrypt.rs            # E2E encryption (AES-CTR)
│       │   ├── runner.rs             # Shell command runner
│       │   ├── terminal.rs           # PTY abstraction
│       │   ├── terminal/unix.rs      # Unix PTY via nix
│       │   └── terminal/windows.rs   # Windows PTY via conpty
│       └── examples/stdin_client.rs  # Example non-interactive client
├── src/                              # SvelteKit frontend
│   ├── routes/                       # SvelteKit routes
│   ├── lib/                          # Reusable components and utilities
│   │   ├── Session.svelte            # Main collaborative canvas component
│   │   ├── encrypt.ts                # Browser-side E2E encryption
│   │   ├── protocol.ts               # WebSocket message type mirrors
│   │   └── ui/                       # Svelte UI components
│   ├── app.html                      # HTML template
│   └── app.css                       # Global styles
├── build/                            # Vite production build output (served by server)
├── static/                           # Static assets (favicon, images)
├── scripts/release.sh                # Manual cross-compilation release script
├── Dockerfile                        # Multi-stage Docker build
├── fly.toml                          # Fly.io deployment configuration
├── compose.yaml                      # Docker Compose (dev Redis only)
├── mprocs.yaml                       # Dev process orchestration
├── Cargo.toml                        # Workspace manifest
├── package.json                      # NPM scripts and dependencies
├── svelte.config.js                  # SvelteKit static adapter config
├── vite.config.ts                    # Vite dev server + Tailwind plugin
├── tsconfig.json                     # TypeScript strict mode
├── rustfmt.toml                      # Nightly rustfmt options
├── .eslintrc.cjs                     # ESLint + TypeScript config
└── .prettierrc                       # Prettier formatting config
```

## Development setup

### Prerequisites

- Rust 1.70+
- Node.js v18+ and NPM v9+ (PNPM lockfile is present but not required)
- `protoc` (Protobuf compiler)
- `mprocs` (`cargo install mprocs` or via package manager)
- Docker (for local Redis)

### Starting services

```shell
docker compose up -d       # Starts Redis on port 12601
npm install                # Install frontend dependencies
```

### Running the full dev stack

```shell
mprocs                     # Runs server, client, and web dev in parallel
```

The `mprocs.yaml` spins up:

- **Server**: `cargo run --bin sshx-server -- --override-origin http://localhost:5173 --secret dev-secret --redis-url redis://localhost:12601`
- **Client**: `cargo run --bin sshx -- --server http://localhost:8051`
- **Web**: `npm run dev` (Vite dev server on port 5173)

### Dev server flags reference

The server binary accepts these flags (see `crates/sshx-server/src/main.rs`):

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8051` | TCP port to listen on |
| `--listen` | `::1` | IP address / network interface |
| `--secret` | random | HMAC secret for signing session tokens |
| `--override-origin` | — | Override the origin URL returned by `Open()` |
| `--redis-url` | — | Redis URL for distributed mesh |
| `--host` | — | Hostname of this server (for meshing) |

The client binary accepts:

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `https://sshx.io` | Remote sshx server address |
| `--shell` | default shell | Local shell command to run |
| `--quiet` | — | Only print the session URL |
| `--name` | `user@host` | Session name displayed in the title |
| `--enable-readers` | — | Enable read-only mode with separate URLs |

## Build commands

### Rust

```shell
cargo build --release      # Strip binaries (configured in workspace Cargo.toml)
cargo test                 # Run tests for all crates
cargo test -p sshx         # Run client tests only (includes Windows tests)
cargo clippy --all-targets -- -D warnings   # Lint; warnings are treated as errors
cargo +nightly fmt         # Format with nightly rustfmt features
```

### Web

```shell
npm run dev                # Vite dev server with HMR
npm run build              # Production build to build/
npm run preview            # Preview the production build
npm run check              # Svelte type-checking (svelte-check)
npm run check:watch        # Type-checking in watch mode
npm run lint               # Prettier + ESLint
npm run format             # Prettier --write
```

## Code style guidelines

### Rust

- Use `cargo +nightly fmt` for formatting. The project relies on nightly features:
  - `group_imports = "StdExternalCrate"`
  - `wrap_comments = true`
  - `format_strings = true`
  - `normalize_comments = true`
  - `reorder_impl_items = true`
- `sshx-core` and `sshx-server` forbid unsafe code (`#![forbid(unsafe_code)]`).
- `sshx` (client) denies unsafe code at the library level (`#![deny(unsafe_code)]`); unsafe is only allowed in `terminal/unix.rs` and `terminal/windows.rs` for OS PTY APIs.
- All crates warn on missing docs (`#![warn(missing_docs)]`).
- Prefer `anyhow::Result` for error handling in application code.
- Use `tracing` for structured logging.

### TypeScript / Svelte

- Prettier config: `proseWrap: "always"`, `trailingComma: "all"`.
- ESLint extends `eslint:recommended`, `@typescript-eslint/recommended`, and `prettier`.
- Svelte files are **excluded** from ESLint (ignorePatterns includes `src/**/*.svelte`).
- Strict TypeScript mode is enabled (`tsconfig.json` extends SvelteKit generated config).

## Testing instructions

### Rust tests

- **Unit / integration tests**: `cargo test` runs all Rust tests.
- **Windows client tests**: `cargo test -p sshx` is run on `windows-latest` in CI to test the Windows `conpty` integration.
- **Server integration tests**: Located in `crates/sshx-server/tests/`. They spin up a real `TestServer` and exercise gRPC and HTTP endpoints. Requires `protoc` at build time.

### Web tests

- There is no dedicated unit-test runner (Jest/Vitest) configured.
- `npm run check` performs Svelte + TypeScript type checking and is treated as the web test gate.
- `npm run lint` and `npm run build` must also pass in CI.

### CI gate

The following must pass before merge (see `.github/workflows/ci.yaml`):

1. `cargo +nightly fmt -- --check`
2. `cargo test`
3. `cargo clippy --all-targets -- -D warnings`
4. `cargo test -p sshx` (Windows runner)
5. `npm run lint`
6. `npm run check`
7. `npm run build`

## Deployment process

### Production hosting

The project author hosts on **Fly.io** with **Redis Cloud**. Self-hosted
deployments are not officially supported because they require implementing HTTP/TCP
reverse proxies, gRPC forwarding, TLS termination, private mesh networking, and
graceful shutdown.

### Fly.io deployment

- `fly.toml` configures the app with TCP services on port 8051 and an HTTP
  service on port 3000 (internal). The server is started via an experimental
  `cmd` that binds to `::` and advertises its Fly VM hostname.
- The `Dockerfile` is a multi-stage build:
  1. Rust Alpine stage builds `sshx-server`.
  2. Node Alpine stage builds the SvelteKit frontend into `build/`.
  3. Final Alpine image copies the binary and `build/` folder.
- **Do not run the development commands in a public setting**, as the dev
  configuration is insecure (no TLS, fixed secret).

### Release binaries

`scripts/release.sh` cross-compiles the `sshx` CLI for multiple targets
(Linux musl, macOS, FreeBSD, Windows MSVC) and uploads archives to AWS S3.
This is currently run manually and could be moved to CI.

## Security considerations

- **End-to-end encryption**: Terminal data is encrypted with AES-CTR using a
  per-session random key. Argon2id (19 MiB, 2 iterations) is used for key
  stretching. The server only forwards ciphertext.
- **Session tokens**: Signed with HMAC-SHA256 using the server's `--secret`.
- **Read-only mode**: When `--enable-readers` is used, a write-password hash is
  stored in session metadata. Viewers get a separate URL without write access.
- **TLS**: The client uses `rustls` with the `ring` crypto provider. The server
  expects TLS termination at the edge (e.g., Fly.io or a reverse proxy).
- **Dev mode**: The dev server uses an unencrypted HTTP connection and a
  hardcoded secret. Never expose the dev stack publicly.

## Key ports

| Service | Port | Notes |
|---------|------|-------|
| Redis   | 12601 | Bound to 127.0.0.1 in Docker Compose |
| Server  | 8051  | Default gRPC + HTTP listen port |
| Web dev | 5173  | Vite HMR dev server |

## Frontend event handling architecture (critical)

Terminal drag, resize, and canvas pan use **pointer events** and have subtle
interactions that are easy to break:

- **Terminal drag**: Handled entirely inside `XTerm.svelte` via
  `handleTitlePointerDown/Move/Up`. It calls `setPointerCapture` on the title
  bar element. These handlers dispatch `startMove` events to `Session.svelte`.
- **Canvas pan**: Handled by `TouchZoom` (`src/lib/action/touchZoom.ts`) using
  `@use-gesture/vanilla` on `fabricEl`.
- **Resize**: Handled by a small handle div inside `Session.svelte`.

**Do not duplicate drag handling in global window listeners.**
`Session.svelte` previously had global `pointermove`/`pointerup` listeners on
`window` that also tried to process terminal drag events. This caused duplicate
`move` messages and race conditions. Terminal drag must be handled ONLY by the
inline `on:startMove` handler in `XTerm.svelte`.

The global window listeners should only handle:
1. Resize events (checking `resizingPointerId`)
2. Cursor position updates (`setCursor`)

**`mousedown` and `pointerdown` are separate events.**
`XTerm.svelte`'s `.term-container` has `on:mousedown` (for `bringToFront`) and
`on:pointerdown` (with `stopPropagation()`). Stopping `pointerdown` does NOT
stop `mousedown`, so `bringToFront` fires even during drag. Guard it with
`!isDragging`.

## Recent major changes

- **Svelte 5 + Tailwind v4 upgrade** (commit `8a1b214`): The project migrated
  from Svelte 4 to Svelte 5 and Tailwind v3 to v4. Component code still uses
  legacy `$:` reactive syntax (not Svelte 5 runes). Check for reactivity quirks
  if drag/resize behaves unexpectedly.
- **xterm.js replaced with wterm** (`@wterm/dom`): Terminal rendering no longer
  uses `xterm.js`. Cell dimensions are measured by injecting temporary DOM
  elements with wterm's CSS classes, not by reading canvas bounds.

## Useful notes for agents

- When modifying protobuf definitions, run `cargo build` to regenerate Rust code
  via `tonic-prost-build`. The generated code is not committed.
- Any change to encryption logic must be mirrored in both
  `crates/sshx/src/encrypt.rs` and `src/lib/encrypt.ts`.
- The server serves static files from `./build/` relative to the working
  directory of the binary. If you move or rename build outputs, update
  `crates/sshx-server/src/web.rs` accordingly.
- Adding new WebSocket message types requires updating both
  `crates/sshx-server/src/web/protocol.rs` and `src/lib/protocol.ts`.
