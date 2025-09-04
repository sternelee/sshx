#!/bin/bash

# sshx 用户会话管理功能演示脚本
# 此脚本演示完整的用户会话管理工作流程

set -e

echo "🚀 sshx 用户会话管理功能演示"
echo "================================"

# 检查依赖
echo "📋 检查依赖..."

if ! command -v curl &> /dev/null; then
    echo "❌ curl 未安装，请先安装 curl"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "❌ jq 未安装，请先安装 jq 用于 JSON 处理"
    exit 1
fi

if ! command -v redis-cli &> /dev/null; then
    echo "⚠️  redis-cli 未安装，建议安装以便检查 Redis 状态"
fi

echo "✅ 依赖检查完成"

# 配置
API_BASE="http://localhost:3000/api"
WEB_URL="http://localhost:5173"
TEST_EMAIL="demo_user_$(date +%s)@example.com"
TEST_PASSWORD="demo123456"

echo ""
echo "📝 演示配置:"
echo "   API 地址: $API_BASE"
echo "   Web 界面: $WEB_URL"
echo "   测试邮箱: $TEST_EMAIL"

# 检查服务器状态
echo ""
echo "🔍 检查服务器状态..."

if ! curl -s "$API_BASE/../" > /dev/null; then
    echo "❌ sshx 服务器未运行，请先启动服务器:"
    echo "   ./start_server.sh"
    exit 1
fi

echo "✅ sshx 服务器运行正常"

# 步骤 1: 用户注册
echo ""
echo "👤 步骤 1: 用户注册"

REGISTER_RESPONSE=$(curl -s -X POST "$API_BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")

if echo "$REGISTER_RESPONSE" | jq -e '.success' > /dev/null; then
    JWT_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.data.token')
    USER_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.data.user_id')
    echo "✅ 用户注册成功"
    echo "   用户ID: $USER_ID"
    echo "   JWT Token: ${JWT_TOKEN:0:20}..."
else
    echo "❌ 用户注册失败:"
    echo "$REGISTER_RESPONSE" | jq -r '.error // "未知错误"'
    exit 1
fi

# 步骤 2: 生成 API Key
echo ""
echo "🔑 步骤 2: 生成 API Key"

API_KEY_RESPONSE=$(curl -s -X POST "$API_BASE/auth/api-keys" \
  -H "Content-Type: application/json" \
  -d "{\"auth_token\":\"$JWT_TOKEN\",\"name\":\"Demo API Key\"}")

if echo "$API_KEY_RESPONSE" | jq -e '.success' > /dev/null; then
    API_KEY_TOKEN=$(echo "$API_KEY_RESPONSE" | jq -r '.data.token')
    API_KEY_ID=$(echo "$API_KEY_RESPONSE" | jq -r '.data.id')
    echo "✅ API Key 生成成功"
    echo "   API Key ID: $API_KEY_ID"
    echo "   API Key Token: ${API_KEY_TOKEN:0:20}..."
else
    echo "❌ API Key 生成失败:"
    echo "$API_KEY_RESPONSE" | jq -r '.error // "未知错误"'
    exit 1
fi

# 步骤 3: 显示使用说明
echo ""
echo "🖥️  步骤 3: 使用 API Key 启动 sshx"
echo ""
echo "现在你可以使用以下命令启动 sshx 客户端:"
echo ""
echo "方法 1 - 使用命令行参数:"
echo "  sshx --server http://localhost:3000 --api-key \"$API_KEY_TOKEN\""
echo ""
echo "方法 2 - 使用环境变量:"
echo "  export SSHX_API_KEY=\"$API_KEY_TOKEN\""
echo "  sshx --server http://localhost:3000"
echo ""
echo "方法 3 - 如果你已经构建了 sshx 客户端:"
echo "  cargo run --bin sshx -- --server http://localhost:3000 --api-key \"$API_KEY_TOKEN\""
echo ""

# 等待用户启动会话
echo "请在另一个终端窗口中运行上述命令之一来创建会话..."
echo "然后按 Enter 键继续演示会话管理功能..."
read -r

# 步骤 4: 查看会话列表
echo ""
echo "📋 步骤 4: 查看用户会话列表"

SESSIONS_RESPONSE=$(curl -s -X POST "$API_BASE/auth/sessions" \
  -H "Content-Type: application/json" \
  -d "{\"auth_token\":\"$JWT_TOKEN\"}")

if echo "$SESSIONS_RESPONSE" | jq -e '.success' > /dev/null; then
    SESSION_COUNT=$(echo "$SESSIONS_RESPONSE" | jq '.data.sessions | length')
    echo "✅ 会话列表查询成功"
    echo "   活跃会话数量: $SESSION_COUNT"
    
    if [ "$SESSION_COUNT" -gt 0 ]; then
        echo ""
        echo "会话详情:"
        echo "$SESSIONS_RESPONSE" | jq -r '.data.sessions[] | "  - 名称: \(.name)\n    URL: \(.url)\n    创建时间: \(.created_at)\n    状态: \(if .is_active then "活跃" else "已关闭" end)\n"'
        
        # 获取第一个会话的ID用于演示关闭功能
        FIRST_SESSION_ID=$(echo "$SESSIONS_RESPONSE" | jq -r '.data.sessions[0].id // empty')
        FIRST_SESSION_NAME=$(echo "$SESSIONS_RESPONSE" | jq -r '.data.sessions[0].name // empty')
    else
        echo "   没有找到活跃会话"
        echo "   请确保你已经使用 API Key 启动了 sshx 客户端"
    fi
else
    echo "❌ 会话列表查询失败:"
    echo "$SESSIONS_RESPONSE" | jq -r '.error // "未知错误"'
fi

# 步骤 5: 演示会话关闭（如果有会话）
if [ -n "$FIRST_SESSION_ID" ]; then
    echo ""
    echo "❌ 步骤 5: 演示会话关闭功能"
    echo "即将关闭会话: $FIRST_SESSION_NAME"
    echo "按 Enter 键继续，或 Ctrl+C 取消..."
    read -r
    
    CLOSE_RESPONSE=$(curl -s -X POST "$API_BASE/auth/sessions/$FIRST_SESSION_ID/close" \
      -H "Content-Type: application/json" \
      -d "{\"auth_token\":\"$JWT_TOKEN\"}")
    
    if echo "$CLOSE_RESPONSE" | jq -e '.data.success' > /dev/null; then
        echo "✅ 会话关闭成功"
        echo "   会话ID: $FIRST_SESSION_ID"
    else
        echo "❌ 会话关闭失败:"
        echo "$CLOSE_RESPONSE" | jq -r '.error // "未知错误"'
    fi
fi

# 步骤 6: 查看 API Key 列表
echo ""
echo "🔑 步骤 6: 查看 API Key 列表"

LIST_KEYS_RESPONSE=$(curl -s -X POST "$API_BASE/auth/api-keys" \
  -H "Content-Type: application/json" \
  -d "{\"auth_token\":\"$JWT_TOKEN\"}")

if echo "$LIST_KEYS_RESPONSE" | jq -e '.success' > /dev/null; then
    KEY_COUNT=$(echo "$LIST_KEYS_RESPONSE" | jq '.data.api_keys | length')
    echo "✅ API Key 列表查询成功"
    echo "   API Key 数量: $KEY_COUNT"
    
    echo ""
    echo "API Key 详情:"
    echo "$LIST_KEYS_RESPONSE" | jq -r '.data.api_keys[] | "  - 名称: \(.name)\n    ID: \(.id)\n    创建时间: \(.created_at)\n    状态: \(if .is_active then "激活" else "停用" end)\n"'
else
    echo "❌ API Key 列表查询失败:"
    echo "$LIST_KEYS_RESPONSE" | jq -r '.error // "未知错误"'
fi

# 步骤 7: Web 界面演示
echo ""
echo "🌐 步骤 7: Web 界面演示"
echo ""
echo "现在你可以访问 Web 界面来管理你的会话和 API Key:"
echo "  $WEB_URL"
echo ""
echo "登录信息:"
echo "  邮箱: $TEST_EMAIL"
echo "  密码: $TEST_PASSWORD"
echo ""
echo "在 Web 界面中你可以:"
echo "  ✅ 查看和管理 API Key"
echo "  ✅ 查看活跃会话列表"
echo "  ✅ 关闭不需要的会话"
echo "  ✅ 复制会话链接"
echo "  ✅ 直接进入会话"

# 清理选项
echo ""
echo "🧹 清理选项"
echo ""
echo "演示完成！你可以选择:"
echo "  1. 保留测试数据继续体验"
echo "  2. 清理测试数据"
echo ""
echo -n "是否清理测试数据？(y/N): "
read -r CLEANUP

if [[ $CLEANUP =~ ^[Yy]$ ]]; then
    echo ""
    echo "🧹 清理测试数据..."
    
    # 删除 API Key
    if [ -n "$API_KEY_ID" ]; then
        DELETE_RESPONSE=$(curl -s -X DELETE "$API_BASE/auth/api-keys/$API_KEY_ID" \
          -H "Content-Type: application/json" \
          -d "{\"auth_token\":\"$JWT_TOKEN\"}")
        
        if echo "$DELETE_RESPONSE" | jq -e '.data.success' > /dev/null; then
            echo "✅ API Key 已删除"
        else
            echo "⚠️  API Key 删除失败，请手动清理"
        fi
    fi
    
    echo "✅ 清理完成"
else
    echo ""
    echo "📝 测试数据已保留，你可以继续使用:"
    echo "   邮箱: $TEST_EMAIL"
    echo "   密码: $TEST_PASSWORD"
    echo "   API Key: ${API_KEY_TOKEN:0:20}..."
fi

echo ""
echo "🎉 sshx 用户会话管理功能演示完成！"
echo ""
echo "💡 更多信息:"
echo "   - 用户指南: USER_SESSION_MANAGEMENT_GUIDE.md"
echo "   - API 文档: HTTP_API_GUIDE.md"
echo "   - 测试示例: cargo run --example session_management_test"
echo ""
echo "感谢使用 sshx！"