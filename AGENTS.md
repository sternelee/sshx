# AGENTS.md

## Dev setup

```shell
docker compose up -d       # Start Redis on port 12601
mprocs                     # Run server, client, and web in parallel
```

Requires: Rust 1.70+, Node v18, NPM v9, mprocs.

## Build commands

```shell
# Rust
cargo build --release      # Strip binaries
cargo test                # All crates
cargo clippy --all-targets -- -D warnings  # Lint (warnings = errors)

# Web
npm run lint              # prettier + eslint
npm run check             # svelte-check --tsconfig ./tsconfig.json
npm run build             # Vite build to build/
```

## Architecture

- `crates/sshx-core/` — Protobuf message definitions (prost). All other crates
  depend on this.
- `crates/sshx-server/` — Axum HTTP/WS server, Redis connection pool, gRPC
  services.
- `crates/sshx/` — Terminal client binary. Uses unix `nix` crate or Windows
  `conpty` for PTY.
- `src/` — SvelteKit web frontend. Proxies `/api` to `http://[::1]:8051`.

## Key ports

| Service | Port  |
| ------- | ----- |
| Redis   | 12601 |
| Server  | 8051  |
| Web dev | 5173  |

## CI gate

All of rustfmt (nightly), cargo test, cargo clippy, npm lint, npm check, npm
build must pass before merge. Deploy is separate and only on `main` push.

## Misc

- `rustfmt.toml` uses nightly features. Run `cargo +nightly fmt` for formatting.
- Windows client tests only run on the `sshx` package.
- Dev server flags:
  `--override-origin http://localhost:5173 --secret dev-secret --redis-url redis://localhost:12601`
