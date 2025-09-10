#!/bin/bash

# sshx Tauri Development and Testing Script

set -e

echo "🚀 sshx Tauri Development Setup"
echo "================================"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command_exists cargo; then
    echo "❌ Rust/Cargo not found. Please install Rust: https://rustup.rs/"
    exit 1
fi

if ! command_exists npm; then
    echo "❌ Node.js/npm not found. Please install Node.js: https://nodejs.org/"
    exit 1
fi

echo "✅ Prerequisites check passed"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
echo "Installing frontend dependencies..."
npm install

echo "Building WebAssembly..."
npm run build:wasm

# Check Tauri compilation
echo ""
echo "🔧 Checking Tauri compilation..."
cd app
echo "Checking Rust dependencies and compilation..."
cargo check

if [ $? -eq 0 ]; then
    echo "✅ Tauri compilation check passed"
else
    echo "❌ Tauri compilation failed"
    cd ..
    exit 1
fi

cd ..

# Build frontend
echo ""
echo "🎯 Building frontend..."
npm run build

# Test basic functionality
echo ""
echo "🧪 Running basic tests..."

# Check if Tauri API files exist
if [ -f "src/lib/tauri-api.ts" ]; then
    echo "✅ Tauri API module found"
else
    echo "❌ Tauri API module missing"
    exit 1
fi

if [ -f "src/lib/ui/TauriToolbar.svelte" ]; then
    echo "✅ Tauri Toolbar component found"
else
    echo "❌ Tauri Toolbar component missing"
    exit 1
fi

if [ -f "src/routes/app/+page.svelte" ]; then
    echo "✅ Desktop app page found"
else
    echo "❌ Desktop app page missing"
    exit 1
fi

# Check Tauri configuration
if [ -f "app/tauri.conf.json" ]; then
    echo "✅ Tauri configuration found"
else
    echo "❌ Tauri configuration missing"
    exit 1
fi

echo ""
echo "🎉 All checks passed!"
echo ""
echo "🚀 Ready to develop!"
echo ""
echo "Available commands:"
echo "  npm run dev          - Start web development server"
echo "  npm run tauri:dev    - Start Tauri development (desktop app)"
echo "  npm run tauri:build  - Build Tauri app for production"
echo "  npm run build        - Build web version"
echo ""
echo "Desktop app URL: http://localhost:5173/app"
echo "P2P session URL: http://localhost:5173/p2p"
echo ""
echo "Happy coding! 🎯"