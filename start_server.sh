#!/bin/bash

# SSHX Server 启动脚本

echo "🚀 Starting SSHX Server with User Authentication"
echo "=============================================="

# 检查 Redis 是否运行
if ! pgrep -x "redis-server" > /dev/null; then
    echo "⚠️  Redis is not running. Starting Redis..."
    redis-server --daemonize yes
    sleep 2
fi

echo "✅ Redis is running"

# 启动 sshx-server
echo "🔧 Starting sshx-server..."
cd crates/sshx-server

# 设置环境变量
export RUST_LOG=info
export JWT_SECRET="your-super-secret-jwt-key-change-in-production"

# 启动服务器
cargo run --bin sshx-server -- \
    --redis-url redis://localhost:6379 \
    --host 0.0.0.0 \
    --port 3000

echo "🎉 Server started successfully!"
echo ""
echo "📋 Available endpoints:"
echo "   - Web UI: http://localhost:5173 (run 'npm run dev' in another terminal)"
echo "   - API: http://localhost:3000/api"
echo "   - WebSocket: ws://localhost:3000/api/s/{session_name}"
echo ""
echo "🧪 Test the API:"
echo "   cargo run --example http_api_test"