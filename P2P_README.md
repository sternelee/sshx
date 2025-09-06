# SSHX P2P Backend Implementation

This implementation adds P2P functionality to SSHX using the iroh library, replacing the traditional server-client architecture with a decentralized peer-to-peer network.

## Architecture Overview

### Components

1. **sshx-web** (WASM module): Handles P2P communication using iroh
2. **sshx-api.ts**: TypeScript API wrapper for the WASM module
3. **P2PSession.svelte**: Svelte component that integrates P2P with existing SSHX UI
4. **P2P routes**: New routes for P2P sessions (`/p2p` and `/p2p/[id]`)

### Key Features

- **Decentralized**: No central server required
- **End-to-end encrypted**: All communication is encrypted
- **WebRTC support**: Direct peer-to-peer connections
- **NAT traversal**: Works behind NATs using iroh's hole punching
- **Fallback to relay**: Uses iroh's relay servers when direct connection fails

## Usage

### Building the WASM Module

```bash
# Build the WASM package
./scripts/build-wasm.sh

# Or manually:
cd crates/sshx-web
wasm-pack build --target web --out-dir ../../static/sshx-web-pkg --dev
```

### Accessing P2P Sessions

1. **Create a new P2P session**: Navigate to `/p2p`
2. **Join existing session**: Navigate to `/p2p/[id]` with a ticket parameter

### Sharing Sessions

When you create a P2P session, you'll get a ticket that you can share with others:

```
https://yourdomain.com/p2p?ticket=<base32-encoded-ticket>
```

## Implementation Details

### WASM Module (sshx-web)

The WASM module provides:
- `SshxNode`: Main P2P node management
- `Session`: Individual session handling
- `SessionSender`: Message broadcasting
- Event streaming through ReadableStream

### TypeScript API (sshx-api.ts)

Provides a clean interface for Svelte components:
- `SshxClient`: Main client class
- Event handling for SSHX events
- Automatic reconnection
- Message encryption/decryption

### Svelte Integration (P2PSession.svelte)

Integrates with existing SSHX UI:
- Replaces WebSocket communication with P2P
- Maintains existing UI components and interactions
- Handles P2P-specific events and states

## Configuration

### Dependencies Added

```toml
# crates/sshx-web/Cargo.toml
serde_json = "1.0"
# ... other iroh dependencies
```

### New Routes

- `/p2p` - Main P2P session page
- `/p2p/[id]` - P2P session with specific ID

## Event Handling

The P2P implementation handles the same events as the original WebSocket implementation:

- `hello`: Initial connection and user ID assignment
- `users`: User list updates
- `shells`: Terminal session management
- `chunks`: Terminal output data
- `hear`: Chat messages
- `shellLatency`/`pong`: Latency measurements

## Security Considerations

1. **End-to-end encryption**: All messages are encrypted using the existing SSHX encryption
2. **Ticket authentication**: Sessions require valid tickets to join
3. **No central server**: Eliminates single point of failure and server-side data storage

## Performance Considerations

- **Direct connections**: P2P connections reduce latency
- **No server overhead**: Eliminates server-side processing
- **Bandwidth efficient**: Direct peer-to-peer data transfer

## Limitations

1. **Browser support**: Requires modern browsers with WebRTC support
2. **NAT traversal**: Some restrictive networks may block P2P connections
3. **Discovery**: Peers must have a way to discover each other (tickets, DHT, etc.)

## Future Improvements

1. **Enhanced discovery**: Implement DHT-based peer discovery
2. **File sharing**: Add P2P file transfer capabilities
3. **Audio/video**: Integrate WebRTC for real-time communication
4. **Mobile support**: Optimize for mobile browsers and networks