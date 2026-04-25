# sshx-worker

Cloudflare Workers backend for sshx. Replaces the Rust `sshx-server` with a
serverless architecture using Durable Objects, KV, and WebSockets.

## Architecture

| Component          | Cloudflare Service         | Purpose                                                                |
| ------------------ | -------------------------- | ---------------------------------------------------------------------- |
| Session state      | **Durable Objects**        | Per-session state machine, hibernatable WebSockets, persistent storage |
| Global discovery   | **KV**                     | Session tokens, metadata, and snapshot backups                         |
| Frontend transport | **WebSocket (DO)**         | CBOR messages between browser and session DO                           |
| Backend transport  | **WebSocket (DO)**         | Protobuf messages between CLI and session DO                           |
| Static files       | **Workers Assets / Pages** | SvelteKit SPA build output                                             |

### Why Durable Objects?

- **Single-writer guarantee**: Each session gets its own DO instance,
  eliminating the need for Redis distributed locks or mesh forwarding.
- **Hibernatable WebSockets**: DOs can sleep while keeping WebSocket connections
  alive, drastically reducing CPU usage for idle sessions.
- **Transactional storage**: DO `storage()` API provides atomic reads/writes for
  session snapshots without external databases.

## Protocol Changes

The original `sshx-server` used gRPC (Tonic) for CLI backend connections.
Cloudflare Workers does not natively host gRPC servers, so the backend protocol
has been migrated to **WebSocket with protobuf framing**.

- `POST /api/open` — Create session (JSON request/response)
- `POST /api/close` — Close session (JSON request/response)
- `WS /api/s/:name` — Frontend browser connection (CBOR)
- `WS /api/backend/:name` — CLI backend connection (protobuf `ClientUpdate` /
  `ServerUpdate`)

**The CLI client (`crates/sshx`) needs a corresponding update** to use WebSocket
instead of Tonic gRPC. See `src/lib.rs` routing for the expected message flow.

## Deployment

### Prerequisites

- [Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- Rust toolchain with `wasm32-unknown-unknown` target
- `protoc` (Protobuf compiler)

### 1. Configure bindings

Edit `wrangler.toml` and fill in real IDs:

```toml
[[kv_namespaces]]
binding = "SSHX_SESSIONS"
id = "your-kv-namespace-id"
preview_id = "your-preview-kv-namespace-id"
```

Create the KV namespace:

```bash
npx wrangler kv:namespace create SSHX_SESSIONS
```

Set the session secret:

```bash
npx wrangler secret put SESSION_SECRET
```

### 2. Build and deploy

```bash
cd crates/sshx-worker
npx wrangler deploy
```

### 3. Serve static assets

Static assets are served via the **Workers Assets** binding (configured in
`wrangler.toml`):

```toml
[assets]
directory = "../../build"
binding = "ASSETS"
html_handling = "auto-trailing-slash"
not_found_handling = "404-page"
```

The Worker handles the following routing:

| Route       | Handler                                                  |
| ----------- | -------------------------------------------------------- |
| `/`         | `ASSETS` returns `build/index.html` (landing page)       |
| `/s/:name`  | Worker returns `build/spa.html` (SvelteKit SPA fallback) |
| `/_app/*`   | `ASSETS` returns static JS/CSS files                     |
| `/api/*`    | Worker API / WebSocket handlers                          |
| other paths | `ASSETS` fallback                                        |

Build the frontend before deploying:

```bash
cd ../..
npm run build
```

> **Note:** SvelteKit generates `spa.html` with absolute asset paths
> (`/_app/...`), making it safe to serve from any `/s/:name` path. `index.html`
> uses relative paths (`./_app/...`) and should only be served from `/`.

## Local Development

```bash
cd crates/sshx-worker
npx wrangler dev
```

This starts a local Miniflare instance with Durable Object and KV emulation.

## Differences from sshx-server

| Feature              | sshx-server           | sshx-worker                        |
| -------------------- | --------------------- | ---------------------------------- |
| Runtime              | Tokio + Axum + Tonic  | Cloudflare Workers (WASM)          |
| Session state        | `DashMap` + Redis     | Durable Object storage             |
| Mesh/redirect        | Redis pub/sub + proxy | Not needed (single DO per session) |
| Frontend WS          | Axum WebSocket        | DO hibernatable WebSocket          |
| Backend transport    | gRPC streaming        | WebSocket + protobuf               |
| Snapshot compression | zstd                  | None (raw protobuf)                |
| Static files         | `ServeDir` / embedded | Workers Assets or Pages            |

## License

MIT
