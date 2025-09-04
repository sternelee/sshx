# SSHX 用户 API Key 功能指南

## 概述

本功能为已登录的用户提供了生成持久 API Key 的能力，用户可以通过这些 API Key 来运行 sshx 客户端，自动将会话绑定到用户账户上。API Key 作为持久的认证凭据，支持创建、列表查看和删除操作。

## 功能特性

### 1. API Key 管理
- 已认证用户可以生成多个 API Key
- 支持自定义 API Key 名称和描述
- API Key 与用户账户绑定，便于管理
- 支持删除不需要的 API Key

### 2. 客户端集成
- sshx 客户端支持 `--api-key` 参数
- 支持 `SSHX_API_KEY` 环境变量
- 自动生成基于用户的会话名称

### 3. 会话管理
- 用户会话自动绑定到用户账户
- 支持会话使用统计和追踪
- API Key 使用时间自动更新

## API 接口

### gRPC 接口

#### 生成 API Key
```protobuf
rpc GenerateApiKey(GenerateApiKeyRequest) returns (ApiKeyResponse);

message GenerateApiKeyRequest {
  string auth_token = 1;  // JWT 认证 token
  string name = 2;        // API key 名称/描述
}

message ApiKeyResponse {
  string id = 1;          // API key 唯一标识符
  string name = 2;        // API key 名称
  string token = 3;       // API key token
  uint64 created_at = 4;  // 创建时间戳
  string user_id = 5;     // 用户 ID
}
```

#### 删除 API Key
```protobuf
rpc DeleteApiKey(DeleteApiKeyRequest) returns (DeleteApiKeyResponse);

message DeleteApiKeyRequest {
  string auth_token = 1;  // JWT 认证 token
  string api_key_id = 2;  // API key ID
}

message DeleteApiKeyResponse {
  bool success = 1;       // 是否删除成功
}
```

#### 列出 API Keys
```protobuf
rpc ListApiKeys(ListApiKeysRequest) returns (ListApiKeysResponse);

message ListApiKeysRequest {
  string auth_token = 1;  // JWT 认证 token
}

message ListApiKeysResponse {
  repeated ApiKeyInfo api_keys = 1;
}

message ApiKeyInfo {
  string id = 1;                    // API key 唯一标识符
  string name = 2;                  // API key 名称
  uint64 created_at = 3;            // 创建时间戳
  optional uint64 last_used = 4;    // 最后使用时间戳
  bool is_active = 5;               // 是否激活
}
```

#### 创建用户会话
```protobuf
message OpenRequest {
  string origin = 1;
  bytes encrypted_zeros = 2;
  string name = 3;
  optional bytes write_password_hash = 4;
  optional string user_api_key = 5; // 新增：用户 API key
}
```

## 使用流程

### 1. 用户注册/登录
```bash
# 使用测试客户端
cargo run --example api_key_test
```

### 2. 生成 API Key
```rust
// 调用 gRPC 接口
let api_key_req = GenerateApiKeyRequest {
    auth_token: "your_jwt_token".to_string(),
    name: "My Development Key".to_string(),
};

let response = client.generate_api_key(api_key_req).await?;
let api_key = response.into_inner();
println!("API Key: {}", api_key.token);
```

### 3. 使用 API Key 运行 sshx
```bash
# 方式 1: 命令行参数
sshx --api-key "your_api_key_token_here"

# 方式 2: 环境变量
export SSHX_API_KEY="your_api_key_token_here"
sshx

# 示例
sshx --api-key "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### 4. 管理 API Keys
```rust
// 列出所有 API Keys
let list_req = ListApiKeysRequest {
    auth_token: "your_jwt_token".to_string(),
};
let response = client.list_api_keys(list_req).await?;

// 删除 API Key
let delete_req = DeleteApiKeyRequest {
    auth_token: "your_jwt_token".to_string(),
    api_key_id: "api_key_id_to_delete".to_string(),
};
let response = client.delete_api_key(delete_req).await?;
```

## 数据存储结构

### Redis 键值结构
```
# 用户数据 (包含 API Keys 列表)
user:id:{user_id} -> {
  "id": "user_id",
  "email": "user@example.com",
  "api_keys": [
    {
      "id": "api_key_id",
      "name": "My API Key",
      "token": "api_key_token",
      "created_at": 1640995200,
      "last_used": 1640995300,
      "is_active": true
    }
  ]
}

# API Key 到用户的映射
apikey:user:{api_key_token} -> user_id
```

### 用户 API Key 数据结构
```rust
pub struct UserApiKey {
    pub id: String,           // API key 唯一标识符
    pub name: String,         // API key 名称
    pub token: String,        // API key token
    pub created_at: u64,      // 创建时间戳
    pub last_used: Option<u64>, // 最后使用时间
    pub is_active: bool,      // 是否激活
}
```

## 安全机制

### 1. Token 生成
- 使用 HMAC-SHA256 算法生成 API key token
- 基于服务器密钥和唯一标识符
- Token 格式：`base64(hmac_sha256(secret, api_key_id:random_data))`

### 2. Token 验证
- 服务器验证 API key token 的有效性
- 检查 API key 是否处于激活状态
- 验证通过后绑定会话到用户

### 3. 权限控制
- 只有认证用户可以生成 API key
- 用户只能管理自己的 API key
- 支持 API key 的激活/停用控制

## 实现细节

### 1. 服务器端变更

#### UserService 新增方法
```rust
// 生成 API key
pub async fn generate_api_key(&self, req: GenerateApiKeyRequest) -> Result<ApiKeyResponse>

// 删除 API key
pub async fn delete_api_key(&self, req: DeleteApiKeyRequest) -> Result<bool>

// 列出 API keys
pub async fn list_api_keys(&self, req: ListApiKeysRequest) -> Result<ListApiKeysResponse>

// 验证 API key
pub async fn verify_api_key(&self, api_key_token: &str) -> Result<Option<String>>
```

#### gRPC 服务新增接口
```rust
// 生成 API key
async fn generate_api_key(&self, request: Request<GenerateApiKeyRequest>) -> RR<ApiKeyResponse>

// 删除 API key
async fn delete_api_key(&self, request: Request<DeleteApiKeyRequest>) -> RR<DeleteApiKeyResponse>

// 列出 API keys
async fn list_api_keys(&self, request: Request<ListApiKeysRequest>) -> RR<ListApiKeysResponse>

// 修改 open 方法支持 API key
async fn open(&self, request: Request<OpenRequest>) -> RR<OpenResponse>
```

### 2. 客户端变更

#### 命令行参数
```rust
#[clap(long, env = "SSHX_API_KEY")]
api_key: Option<String>,
```

#### Controller 修改
```rust
pub async fn new(
    origin: &str,
    name: &str,
    runner: Runner,
    enable_readers: bool,
    api_key: Option<String>, // 新增参数
) -> Result<Self>
```

## 测试和验证

### 1. 运行测试
```bash
# 启动服务器 (需要 Redis)
cargo run --bin sshx-server -- --redis-url redis://localhost:6379

# 运行 API key 管理测试
cargo run --example api_key_test
```

### 2. 完整流程测试
```bash
# 1. 注册用户并生成 API key
cargo run --example api_key_test

# 2. 使用生成的 API key 运行 sshx
sshx --api-key "generated_api_key_here"
```

### 3. 验证会话绑定
- 检查 Redis 中的用户数据是否包含 API key 信息
- 验证 API key 使用时间是否正确更新
- 确认会话与用户的关联关系

## API Key 管理最佳实践

### 1. 命名规范
- 使用描述性的名称，如 "Development Key", "Production Deploy Key"
- 包含使用场景和环境信息
- 避免在名称中包含敏感信息

### 2. 安全使用
- 定期轮换 API key
- 删除不再使用的 API key
- 监控 API key 的使用情况

### 3. 权限管理
- 为不同用途创建不同的 API key
- 及时停用或删除泄露的 API key
- 记录 API key 的使用日志

## 后续扩展

### 1. API Key 权限控制
- 支持 API key 的权限范围设置
- 实现基于角色的访问控制
- 添加 API key 过期时间设置

### 2. 使用统计和监控
- API key 使用频率统计
- 会话创建和使用分析
- 异常使用行为检测

### 3. 管理界面
- Web 界面管理 API key
- 批量操作和导入导出
- 使用情况可视化展示

## 故障排除

### 常见问题

1. **API Key 无效**
   - 检查 API key 是否正确复制
   - 验证 API key 是否处于激活状态
   - 确认 API key 没有被删除

2. **认证失败**
   - 验证 JWT token 是否有效
   - 检查服务器密钥配置
   - 确认用户账户状态

3. **会话创建失败**
   - 确认 Redis 连接正常
   - 检查用户数据是否存在
   - 验证 API key 映射关系

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

3. **验证 API Key 生成**
   ```bash
   cargo run --example api_key_test
   ```

## 总结

用户 API Key 功能成功实现了：
- ✅ 用户认证和 API key 生成
- ✅ sshx 客户端 API key 参数支持
- ✅ 会话与用户账户的自动绑定
- ✅ API key 的完整生命周期管理
- ✅ 安全的 token 生成和验证机制
- ✅ 持久化存储和使用统计

该功能为 sshx 提供了企业级的用户认证和会话管理能力，支持多 API key 管理和精细的权限控制需求。用户可以通过持久的 API key 来管理和追踪他们的 sshx 会话，实现了会话与用户账户的完美绑定。