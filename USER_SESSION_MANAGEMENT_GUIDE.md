# 用户会话管理指南

## 概述

sshx 现在支持完整的用户会话管理功能！用户可以通过 API key 启动终端会话，并在 Web 界面中管理所有活跃的会话。

## 功能特性

### ✅ **API Key 认证启动**
- 支持 `--api-key` 参数启动 sshx 客户端
- 自动将会话与用户账户绑定
- 生成用户专属的会话名称

### ✅ **会话管理 Web 界面**
- 查看所有活跃会话
- 显示会话创建时间和最后活动时间
- 一键关闭不需要的会话
- 快速访问会话 URL

### ✅ **会话持久化存储**
- 会话信息存储在 Redis 中
- 支持跨服务器会话查询
- 自动更新会话活动状态

## 使用流程

### 1. 用户注册和登录

```bash
# 访问 Web 界面
http://localhost:5173

# 或使用 API
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'
```

### 2. 生成 API Key

在 Web 界面的控制台页面：
1. 点击 "Generate New API Key"
2. 输入 API Key 名称（如 "My Terminal"）
3. 复制生成的 API Key

或使用 API：
```bash
curl -X POST http://localhost:3000/api/auth/api-keys \
  -H "Content-Type: application/json" \
  -d '{"auth_token":"YOUR_JWT_TOKEN","name":"My Terminal"}'
```

### 3. 使用 API Key 启动 sshx

```bash
# 方法 1: 使用命令行参数
sshx --api-key "YOUR_API_KEY"

# 方法 2: 使用环境变量
export SSHX_API_KEY="YOUR_API_KEY"
sshx

# 方法 3: 指定服务器地址
sshx --server http://localhost:3000 --api-key "YOUR_API_KEY"
```

### 4. 管理会话

在 Web 界面的控制台页面：
- **查看会话列表**: 显示所有活跃会话
- **访问会话**: 点击会话 URL 直接访问
- **关闭会话**: 点击 "Close" 按钮关闭不需要的会话

## API 端点

### 会话管理 API

#### 获取用户会话列表
```http
POST /api/auth/sessions
Content-Type: application/json

{
  "auth_token": "YOUR_JWT_TOKEN"
}
```

响应：
```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "id": "session-uuid",
        "name": "user-12345678-1640995200",
        "url": "http://localhost:3000/s/user-12345678-1640995200",
        "user_id": "user-uuid",
        "api_key_id": "api-key-uuid",
        "created_at": 1640995200,
        "last_activity": 1640995300,
        "is_active": true,
        "metadata": null
      }
    ]
  }
}
```

#### 关闭用户会话
```http
POST /api/auth/sessions/{session_id}/close
Content-Type: application/json

{
  "auth_token": "YOUR_JWT_TOKEN"
}
```

响应：
```json
{
  "success": true,
  "data": {
    "success": true
  }
}
```

## 会话命名规则

用户认证的会话使用以下命名格式：
```
user-{user_id前8位}-{时间戳}
```

例如：`user-12345678-1640995200`

## 安全特性

### 🔒 **API Key 验证**
- 每次启动都验证 API Key 有效性
- 自动更新 API Key 使用时间
- 支持 API Key 禁用和删除

### 🔒 **会话隔离**
- 用户只能查看和管理自己的会话
- JWT token 验证确保操作安全性
- 会话 URL 包含加密密钥

### 🔒 **活动追踪**
- 记录会话创建时间
- 自动更新最后活动时间
- 支持会话状态管理

## 开发和测试

### 启动开发环境

```bash
# 1. 启动 Redis
redis-server

# 2. 启动 sshx 服务器
./start_server.sh

# 3. 启动前端开发服务器
npm run dev

# 4. 访问 Web 界面
open http://localhost:5173
```

### 测试 API Key 功能

```bash
# 1. 注册用户并获取 JWT token
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123456"}'

# 2. 生成 API Key
curl -X POST http://localhost:3000/api/auth/api-keys \
  -H "Content-Type: application/json" \
  -d '{"auth_token":"JWT_TOKEN","name":"Test Key"}'

# 3. 使用 API Key 启动 sshx
sshx --server http://localhost:3000 --api-key "API_KEY_TOKEN"

# 4. 查看用户会话
curl -X POST http://localhost:3000/api/auth/sessions \
  -H "Content-Type: application/json" \
  -d '{"auth_token":"JWT_TOKEN"}'
```

## 故障排除

### 常见问题

1. **API Key 无效**
   - 检查 API Key 是否正确复制
   - 确认 API Key 未被删除或禁用
   - 验证服务器地址是否正确

2. **会话未显示**
   - 确认使用了正确的 API Key 启动
   - 检查 Redis 连接是否正常
   - 验证 JWT token 是否有效

3. **无法关闭会话**
   - 确认会话属于当前用户
   - 检查网络连接
   - 验证认证 token

### 日志查看

```bash
# 查看服务器日志
RUST_LOG=info cargo run --bin sshx-server -- --redis-url redis://localhost:6379

# 查看详细调试日志
RUST_LOG=debug cargo run --bin sshx-server -- --redis-url redis://localhost:6379
```

## 下一步计划

- [ ] 会话共享功能
- [ ] 会话历史记录
- [ ] 会话统计和分析
- [ ] 批量会话操作
- [ ] 会话标签和分类
- [ ] 会话自动清理策略

现在你可以享受完整的 sshx 用户会话管理体验！🚀