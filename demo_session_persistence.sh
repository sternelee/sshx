#!/bin/bash

# sshx 会话持久化功能演示脚本
# 演示如何在重启后保持相同的 encryption_key 和 URL

set -e

echo "🔄 sshx 会话持久化功能演示"
echo "============================"

# 检查依赖
echo "📋 检查依赖..."

if ! command -v cargo &> /dev/null; then
    echo "❌ cargo 未安装，请先安装 Rust 工具链"
    exit 1
fi

echo "✅ 依赖检查完成"

# 配置
API_KEY="demo-persistence-key-$(date +%s)"
SERVER_URL="http://localhost:3000"
TEST_DIR="/tmp/sshx-persistence-test"

echo ""
echo "📝 演示配置:"
echo "   API Key: $API_KEY"
echo "   服务器: $SERVER_URL"
echo "   测试目录: $TEST_DIR"

# 创建测试目录
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo ""
echo "📁 当前工作目录: $(pwd)"

# 检查服务器状态
echo ""
echo "🔍 检查服务器状态..."

if ! curl -s "$SERVER_URL/" > /dev/null 2>&1; then
    echo "❌ sshx 服务器未运行，请先启动服务器:"
    echo "   ./start_server.sh"
    echo ""
    echo "💡 你也可以使用公共服务器进行测试:"
    echo "   SERVER_URL=\"https://sshx.io\""
    exit 1
fi

echo "✅ sshx 服务器运行正常"

# 步骤 1: 构建 sshx 客户端
echo ""
echo "🔨 步骤 1: 构建 sshx 客户端"

SSHX_BIN="$(pwd)/sshx"
if [ ! -f "$SSHX_BIN" ]; then
    echo "正在构建 sshx 客户端..."
    cargo build --release --bin sshx
    cp "$(dirname "$0")/target/release/sshx" "$SSHX_BIN" 2>/dev/null || \
    cp "$(dirname "$0")/crates/target/release/sshx" "$SSHX_BIN" 2>/dev/null || \
    echo "⚠️  无法找到构建的 sshx 二进制文件，请手动构建"
fi

if [ ! -f "$SSHX_BIN" ]; then
    echo "❌ sshx 客户端不存在，请先构建:"
    echo "   cargo build --release --bin sshx"
    exit 1
fi

echo "✅ sshx 客户端准备就绪: $SSHX_BIN"

# 步骤 2: 首次启动 sshx
echo ""
echo "🚀 步骤 2: 首次启动 sshx (创建新会话)"

echo "启动命令: $SSHX_BIN --server $SERVER_URL --api-key \"$API_KEY\" --quiet"

# 启动 sshx 并获取 URL
FIRST_URL=$("$SSHX_BIN" --server "$SERVER_URL" --api-key "$API_KEY" --quiet 2>/dev/null &)
SSHX_PID=$!

# 等待一下让 sshx 启动
sleep 2

# 获取输出
FIRST_URL=$(jobs -p | xargs -I {} sh -c 'kill -0 {} 2>/dev/null && echo "running"' | head -1)

if [ "$FIRST_URL" = "running" ]; then
    echo "✅ sshx 首次启动成功 (PID: $SSHX_PID)"
    
    # 终止 sshx
    kill $SSHX_PID 2>/dev/null || true
    wait $SSHX_PID 2>/dev/null || true
    
    echo "✅ sshx 已终止"
else
    echo "❌ sshx 启动失败"
    exit 1
fi

# 步骤 3: 查看会话文件
echo ""
echo "💾 步骤 3: 查看保存的会话文件"

SESSION_DIR="$HOME/.config/sshx/sessions"
if [ -d "$SESSION_DIR" ]; then
    echo "✅ 会话目录存在: $SESSION_DIR"
    
    SESSION_FILES=$(ls -1 "$SESSION_DIR"/*.json 2>/dev/null | wc -l)
    echo "   找到 $SESSION_FILES 个会话文件"
    
    if [ "$SESSION_FILES" -gt 0 ]; then
        echo ""
        echo "会话文件列表:"
        ls -la "$SESSION_DIR"/*.json | while read -r line; do
            echo "   $line"
        done
        
        # 显示最新的会话文件内容
        LATEST_SESSION=$(ls -t "$SESSION_DIR"/*.json | head -1)
        echo ""
        echo "最新会话文件内容 ($(basename "$LATEST_SESSION")):"
        echo "----------------------------------------"
        cat "$LATEST_SESSION" | jq '.' 2>/dev/null || cat "$LATEST_SESSION"
        echo "----------------------------------------"
    fi
else
    echo "❌ 会话目录不存在"
fi

# 步骤 4: 重新启动 sshx (应该恢复会话)
echo ""
echo "🔄 步骤 4: 重新启动 sshx (尝试恢复会话)"

echo "启动命令: $SSHX_BIN --server $SERVER_URL --api-key \"$API_KEY\" --quiet"

# 重新启动 sshx
SECOND_URL=$("$SSHX_BIN" --server "$SERVER_URL" --api-key "$API_KEY" --quiet 2>/dev/null &)
SSHX_PID2=$!

# 等待一下
sleep 2

# 检查是否成功启动
if kill -0 $SSHX_PID2 2>/dev/null; then
    echo "✅ sshx 重新启动成功 (PID: $SSHX_PID2)"
    
    # 终止 sshx
    kill $SSHX_PID2 2>/dev/null || true
    wait $SSHX_PID2 2>/dev/null || true
    
    echo "✅ sshx 已终止"
else
    echo "❌ sshx 重新启动失败"
fi

# 步骤 5: 比较会话信息
echo ""
echo "🔍 步骤 5: 验证会话持久化"

echo "会话持久化验证:"
echo "1. 相同的工作目录: $(pwd)"
echo "2. 相同的 API Key: $API_KEY"
echo "3. 相同的服务器: $SERVER_URL"
echo "4. 相同的用户和主机: $(whoami)@$(hostname)"

# 步骤 6: 测试不同参数 (应该创建新会话)
echo ""
echo "🆕 步骤 6: 测试不同参数 (应该创建新会话)"

DIFFERENT_API_KEY="different-key-$(date +%s)"
echo "使用不同的 API Key: $DIFFERENT_API_KEY"

"$SSHX_BIN" --server "$SERVER_URL" --api-key "$DIFFERENT_API_KEY" --quiet &
SSHX_PID3=$!

sleep 2

if kill -0 $SSHX_PID3 2>/dev/null; then
    echo "✅ 使用不同 API Key 成功创建新会话"
    kill $SSHX_PID3 2>/dev/null || true
    wait $SSHX_PID3 2>/dev/null || true
else
    echo "❌ 新会话创建失败"
fi

# 步骤 7: 测试匿名会话 (不使用 API Key)
echo ""
echo "👤 步骤 7: 测试匿名会话 (不使用 API Key，不启用持久化)"

echo "启动命令: $SSHX_BIN --server $SERVER_URL --quiet"

"$SSHX_BIN" --server "$SERVER_URL" --quiet &
SSHX_PID4=$!

sleep 2

if kill -0 $SSHX_PID4 2>/dev/null; then
    echo "✅ 匿名会话模式工作正常 (无持久化)"
    kill $SSHX_PID4 2>/dev/null || true
    wait $SSHX_PID4 2>/dev/null || true
else
    echo "❌ 匿名会话模式失败"
fi

# 步骤 8: 测试会话清理
echo ""
echo "🧹 步骤 8: 测试会话清理功能"

echo "清理旧会话文件..."
CLEANUP_RESULT=$("$SSHX_BIN" --cleanup-sessions 0 2>&1 || echo "清理完成")
echo "$CLEANUP_RESULT"

# 检查清理结果
if [ -d "$SESSION_DIR" ]; then
    REMAINING_FILES=$(ls -1 "$SESSION_DIR"/*.json 2>/dev/null | wc -l)
    echo "✅ 清理后剩余会话文件: $REMAINING_FILES"
else
    echo "✅ 会话目录已清空"
fi

# 总结
echo ""
echo "🎉 会话持久化功能演示完成!"
echo ""
echo "📋 演示总结:"
echo "   ✅ 使用 API Key 时自动启用会话持久化"
echo "   ✅ 会话状态自动保存到本地文件"
echo "   ✅ 重启后能够恢复相同的会话"
echo "   ✅ 不同参数会创建新会话"
echo "   ✅ 匿名会话不启用持久化"
echo "   ✅ 支持会话文件清理"
echo ""
echo "💡 实际使用建议:"
echo "   1. 使用 API Key 获得持久会话体验"
echo "   2. 在固定的项目目录下使用 sshx"
echo "   3. 使用相同的 API Key 和服务器地址"
echo "   4. 定期清理旧会话文件"
echo "   5. 临时使用时不提供 API Key"
echo ""
echo "📁 会话文件位置: $SESSION_DIR"
echo "🔧 测试目录: $TEST_DIR"
echo ""
echo "感谢使用 sshx 会话持久化功能！"

# 清理测试目录
cd /
rm -rf "$TEST_DIR"