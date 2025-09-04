# SSHX HTTP API 使用指南

## 概述

我已经为 sshx-server 添加了完整的 HTTP REST API，支持用户认证和 API Key 管理。这些 API 可以被前端 Web 应用或其他客户端调用。

## API 端点

### 基础 URL
```
http://localhost:3000/api
```

### 认证端点

#### 1. 用户注册
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

**响应:**
```json
{
  "success": true,
  "data": {
    "token": "jwt_token_here",
    "user_id": "user_id_here",
    "email": "user@example.com"
  }
}
```

#### 2. 用户登录
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

**响应:**
```json
{
  "success": true,
  "data": {
    "token": "jwt_token_here",
    "user_id": "user_id_here",
    "email": "user@example.com"
  }
}
```

### API Key 管理端点

#### 3. 生成 API Key
```http
POST /api/auth/api-keys
Content-Type: application/json

{
  "auth_token": "jwt_token_here",
  "name": "My Development Key"
}
```

**响应:**
```json
{
  "success": true,
  "data": {
    "id": "api_key_id",
    "name": "My Development Key",
    "token": "api_key_token_here",
    "created_at": 1640995200,
    "user_id": "user_id_here"
  }
}
```

#### 4. 列出 API Keys
```http
POST /api/auth/api-keys
Content-Type: application/json

{
  "auth_token": "jwt_token_here"
}
```

**响应:**
```json
{
  "success": true,
  "data": {
    "api_keys": [
      {
        "id": "api_key_id",
        "name": "My Development Key",
        "created_at": 1640995200,
        "last_used": 1640995300,
        "is_active": true
      }
    ]
  }
}
```

#### 5. 删除 API Key
```http
DELETE /api/auth/api-keys/{api_key_id}
Content-Type: application/json

{
  "auth_token": "jwt_token_here"
}
```

**响应:**
```json
{
  "success": true,
  "data": {
    "success": true
  }
}
```

### 会话管理端点

#### 6. 获取用户会话列表
```http
POST /api/auth/sessions
Content-Type: application/json

{
  "auth_token": "jwt_token_here"
}
```

**响应:**
```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "name": "user-12345678-1640995200",
        "url": "https://sshx.io/s/user-12345678-1640995200",
        "created_at": 1640995200
      }
    ]
  }
}
```

## 错误响应

所有端点在出错时返回以下格式：

```json
{
  "error": "Error message here"
}
```

常见的 HTTP 状态码：
- `200 OK`: 请求成功
- `400 Bad Request`: 请求参数错误
- `401 Unauthorized`: 认证失败
- `503 Service Unavailable`: 用户服务不可用（Redis 未连接）

## 使用示例

### 1. 启动服务器

```bash
# 启动 Redis
redis-server

# 启动 sshx-server
./start_server.sh

# 或者手动启动
cd crates/sshx-server
cargo run --bin sshx-server -- --redis-url redis://localhost:6379
```

### 2. 测试 API

```bash
# 运行 HTTP API 测试
cd crates/sshx-server
cargo run --example http_api_test
```

### 3. 使用 curl 测试

```bash
# 注册用户
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123456"}'

# 登录用户
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123456"}'

# 生成 API Key（需要替换 JWT token）
curl -X POST http://localhost:3000/api/auth/api-keys \
  -H "Content-Type: application/json" \
  -d '{"auth_token":"YOUR_JWT_TOKEN","name":"Test Key"}'
```

## 前端集成

前端 Web 应用已经集成了这些 API：

1. **启动前端开发服务器:**
   ```bash
   npm run dev
   ```

2. **访问 Web 界面:**
   ```
   http://localhost:5173
   ```

3. **功能特性:**
   - 用户注册/登录界面
   - API Key 管理控制台
   - 会话列表和切换
   - 响应式设计

## CORS 配置

服务器已配置 CORS 以允许前端访问：

```rust
CorsLayer::new()
    .allow_origin(Any)
    .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
    .allow_headers(Any)
```

## 安全注意事项

1. **JWT Secret**: 在生产环境中设置强密码
   ```bash
   export JWT_SECRET="your-super-secret-jwt-key"
   ```

2. **HTTPS**: 生产环境中使用 HTTPS
3. **CORS**: 生产环境中限制 CORS 来源
4. **Rate Limiting**: 考虑添加请求频率限制

## 数据存储

- **用户数据**: 存储在 Redis 中，键格式为 `user:id:{user_id}`
- **API Key 映射**: 存储在 Redis 中，键格式为 `apikey:user:{api_key_token}`
- **会话数据**: 与用户账户关联存储

## 扩展功能

### 计划中的功能
1. **会话历史**: 完整的会话历史记录
2. **团队管理**: 多用户团队功能
3. **权限控制**: 细粒度的 API Key 权限
4. **使用统计**: 详细的使用分析

### 自定义扩展
可以通过修改 `crates/sshx-server/src/web.rs` 添加新的 API 端点：

```rust
// 添加新的路由
.route("/auth/custom-endpoint", post(custom_handler))

// 实现处理函数
async fn custom_handler(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<CustomRequest>,
) -> Result<Json<SuccessResponse<CustomResponse>>, (StatusCode, Json<ErrorResponse>)> {
    // 自定义逻辑
}
```

## 故障排除

### 常见问题

1. **连接被拒绝**
   - 确保 sshx-server 正在运行
   - 检查端口 3000 是否被占用

2. **Redis 连接失败**
   - 确保 Redis 服务正在运行
   - 检查 Redis URL 配置

3. **CORS 错误**
   - 确保前端从正确的端口访问
   - 检查 CORS 配置

### 调试方法

1. **启用详细日志**
   ```bash
   RUST_LOG=debug cargo run --bin sshx-server
   ```

2. **检查 Redis 数据**
   ```bash
   redis-cli
   > keys user:*
   > keys apikey:*
   ```

3. **测试 API 连通性**
   ```bash
   curl -v http://localhost:3000/api/auth/register
   ```

## 总结

HTTP API 功能已完全集成到 sshx-server 中，提供了：

- ✅ 完整的用户认证系统
- ✅ API Key 生命周期管理
- ✅ RESTful API 设计
- ✅ CORS 支持
- ✅ 错误处理和日志记录
- ✅ 前端集成
- ✅ 测试工具和文档

这为 sshx 提供了现代化的 Web API 接口，支持各种客户端应用的集成。