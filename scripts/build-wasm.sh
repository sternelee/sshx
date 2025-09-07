#!/bin/bash

# Build the sshx-web WASM package
echo "Building sshx-web WASM package..."

# Change to the sshx-web directory
cd browser

# Build the package
wasm-pack build --target web --out-dir ../static/pkg --dev

# Copy the types file if needed
if [ -f "../static/pkg/sshx_web.d.ts" ]; then
  cp "../static/pkg/sshx_web.d.ts" "../static/pkg/sshx.d.ts"
fi

echo "WASM package built successfully!"
echo "Files created in static/pkg/"
