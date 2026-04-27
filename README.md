# sshx

A secure web-based, collaborative terminal.

![](https://i.imgur.com/Q3qKAHW.png)

**Features:**

- Run a single command to share your terminal with anyone.
- Resize, move windows, and freely zoom and pan on an infinite canvas.
- See other people's cursors moving in real time.
- Connect to the nearest server in a globally distributed mesh.
- End-to-end encryption with Argon2 and AES.
- Automatic reconnection and real-time latency estimates.
- Predictive echo for faster local editing (à la Mosh).

Visit [sshx.io](https://sshx.io) to learn more.

## Installation

Just run this command to get the `sshx` binary for your platform.

```shell
curl -sSf https://sshx.io/get | sh
```

Supports Linux and MacOS on x86_64 and ARM64 architectures, as well as embedded
ARMv6 and ARMv7-A systems. The Linux binaries are statically linked.

For Windows, there are binaries for x86_64, x86, and ARM64, linked to MSVC for
maximum compatibility.

If you just want to try it out without installing, use:

```shell
curl -sSf https://sshx.io/get | sh -s run
```

Inspect the script for additional options.

You can also install it with [Homebrew](https://brew.sh/) on macOS.

```shell
brew install sshx
```

### CI/CD

You can run sshx in continuous integration workflows to help debug tricky
issues, like in GitHub Actions.

```yaml
name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      # ... other steps ...

      - run: curl -sSf https://sshx.io/get | sh -s run
      #      ^
      #      └ This will open a remote terminal session and print the URL. It
      #        should take under a second.
```

We don't have a prepackaged action because it's just a single command. It works
anywhere: GitLab CI, CircleCI, Buildkite, CI on your Raspberry Pi, etc.

Be careful adding this to a public GitHub repository, as any user can view the
logs of a CI job while it is running.

## Development

Here's how to work on the project, if you want to contribute.

### Building from source

To build the latest version of the client from source, clone this repository and
run, with [Rust](https://rust-lang.com/) installed:

```shell
cargo install --path crates/sshx
```

This will compile the `sshx` binary and place it in your `~/.cargo/bin` folder.

### Workflow

First, start service containers for development.

```shell
docker compose up -d
```

Install [Rust 1.70+](https://www.rust-lang.org/),
[Node v18](https://nodejs.org/), [NPM v9](https://www.npmjs.com/), and
[mprocs](https://github.com/pvolok/mprocs). Then, run

```shell
npm install
mprocs
```

This will compile and start the server, an instance of the client, and the web
frontend in parallel on your machine.

## Deployment

### Shuttle

You can deploy `sshx-server` to [Shuttle](https://www.shuttle.dev/) using the
included Shuttle entrypoint at `crates/sshx-server/src/bin/shuttle.rs`.

This deployment path uses:

- a **custom Shuttle service** so `sshx-server` keeps serving Axum HTTP,
  WebSocket, and Tonic gRPC traffic on the same port;
- the existing `embedded` static-assets feature so the Svelte frontend is baked
  into the Rust binary at build time;
- `shuttle_prebuild.sh`, which installs Node.js/NPM in Shuttle's builder image
  and runs `npm ci && npm run build` before `cargo build`.

**Prerequisites:**

- [cargo-shuttle / shuttle CLI](https://docs.shuttle.dev/guides/cli)
- a Shuttle account linked in the CLI

1. Create or link a Shuttle project:

   ```shell
   shuttle project create --name <your-project-name>
   # or: shuttle project link --name <your-project-name>
   ```

2. Copy `Secrets.toml.example` to `Secrets.toml` in the workspace root and fill
   in your values:

   ```toml
   SSHX_SECRET = "replace-this-with-a-long-random-secret"

   # Optional: set this if you want sshx to always generate browser URLs with a
   # custom domain or a fixed public origin.
   # SSHX_OVERRIDE_ORIGIN = "https://sshx.example.com"

   # Optional: Redis snapshot storage.
   # SSHX_REDIS_URL = "redis://..."

   # Optional: only needed if you have a real multi-node mesh with per-node
   # addresses. This is usually not practical on Shuttle.
   # SSHX_HOST = "node-1.internal.example.com"
   # SSHX_MESH_TLS = "true"
   ```

3. Deploy:

   ```shell
   shuttle deploy
   ```

4. Find the public URL in the Shuttle dashboard or CLI output, then connect the
   client to that exact HTTPS origin:

   ```shell
   sshx --server https://<your-project-name>-<nonce>.shuttle.app
   ```

**Notes:**

- Shuttle's default hostname includes a random suffix (`<name>-<nonce>`). If
  you want stable session URLs, attach a custom domain and set
  `SSHX_OVERRIDE_ORIGIN`.
- Shuttle performs rolling deployments. Because `sshx-server` keeps active PTY
  sessions in memory, existing sessions may be interrupted during redeploys or
  instance replacement.
- Redis alone does **not** make Shuttle redeploys seamless for sshx. The mesh
  mode also needs per-instance hostnames (`SSHX_HOST`) so nodes can redirect
  browsers and transfer session ownership, which Shuttle does not expose in an
  sshx-friendly way by default.
- The Shuttle integration is compiled behind the `shuttle` cargo feature. Local
  development with the normal `sshx-server` binary is unchanged.

### Fly.io

You can self-host `sshx-server` on [Fly.io](https://fly.io/) with the
included `Dockerfile` and `fly.toml`.

**Prerequisites:** [flyctl](https://fly.io/docs/hands-on/install-flyctl/) installed and authenticated.

1. Create a new Fly app (choose a globally unique name):

   ```shell
   fly apps create <your-app-name>
   ```

2. Update `fly.toml` with your app name and preferred region (e.g. `sin` for
   Singapore, `nrt` for Tokyo, `ewr` for New York):

   ```toml
   app = '<your-app-name>'
   primary_region = 'sin'
   ```

3. Allocate a dedicated IPv4 and IPv6 address (required for DNS to resolve):

   ```shell
   fly ips allocate-v4 --yes
   fly ips allocate-v6
   ```

4. Deploy:

   ```shell
   fly deploy
   ```

5. Connect using your self-hosted server:

   ```shell
   sshx --server https://<your-app-name>.fly.dev
   ```

**Notes:**

- The server runs as a single machine by default. If you scale to multiple
  machines, you must add a shared Redis instance (`SSHX_REDIS_URL` env var)
  so all machines share session state:

  ```shell
  fly redis create
  fly secrets set SSHX_REDIS_URL=<redis-url>
  ```

- `fly deploy` uses Depot to build the image remotely (Rust + Node multi-stage
  build). The first build may take several minutes.
