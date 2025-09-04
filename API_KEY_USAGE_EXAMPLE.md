# SSHX API Key 使用示例

## 快速开始

### 1. 启动 sshx 服务器
```bash
# 确保 Redis 正在运行
redis-server

# 启动 sshx 服务器
cargo run --bin sshx-server -- --redis-url redis://localhost:6379
```

### 2. 生成 API Key
```bash
# 运行 API key 管理测试程序
cargo run --example api_key_test

# 输出示例：
# 🔑 SSHX API Key Management Test
# ================================
# ✅ Connected to sshx server
# ✅ User registered successfully
# ✅ API key generated successfully
#    Token: eyJhbGciOiJIUzI1NiIs...
```

### 3. 使用 API Key 运行 sshx
```bash
# 方式 1: 使用环境变量
export SSHX_API_KEY="your_generated_api_key_here"
sshx

# 方式 2: 使用命令行参数
sshx --api-key "your_generated_api_key_here"
```

## 完整示例

### 用户注册和 API Key 管理
```rust
use sshx_core::proto::{
    sshx_service_client::SshxServiceClient, 
    RegisterRequest, GenerateApiKeyRequest, ListApiKeysRequest
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 连接服务器
    let mut client = SshxServiceClient::connect("http://127.0.0.1:3000").await?;
    
    // 注册用户
    let register_req = RegisterRequest {
        email: "user@example.com".to_string(),
        password: "secure_password".to_string(),
    };
    let auth_response = client.register(register_req).await?.into_inner();
    
    // 生成 API Key
    let api_key_req = GenerateApiKeyRequest {
        auth_token: auth_response.token.clone(),
        name: "My Development Key".to_string(),
    };
    let api_key = client.generate_api_key(api_key_req).await?.into_inner();
    
    println!("Generated API Key: {}", api_key.token);
    
    // 列出所有 API Keys
    let list_req = ListApiKeysRequest {
        auth_token: auth_response.token,
    };
    let keys = client.list_api_keys(list_req).await?.into_inner();
    
    println!("Total API Keys: {}", keys.api_keys.len());
    
    Ok(())
}
```

### 使用 API Key 创建会话
```bash
# 设置 API Key
export SSHX_API_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 运行 sshx (会话将自动绑定到用户账户)
sshx

# 输出示例：
#   sshx v0.4.1
# 
#   ➜  Link:  https://sshx.io/s/user-12345678-1640995200#encryption_key
#   ➜  Shell: /bin/zsh
```

## API Key 管理操作

### 生成新的 API Key
```bash
# 使用测试程序生成
cargo run --example api_key_test

# 或者通过 gRPC 客户端
grpcurl -plaintext -d '{
  "auth_token": "your_jwt_token",
  "name": "Production Key"
}' localhost:3000 sshx.SshxService/GenerateApiKey
```

### 列出所有 API Keys
```bash
grpcurl -plaintext -d '{
  "auth_token": "your_jwt_token"
}' localhost:3000 sshx.SshxService/ListApiKeys
```

### 删除 API Key
```bash
grpcurl -plaintext -d '{
  "auth_token": "your_jwt_token",
  "api_key_id": "api_key_id_to_delete"
}' localhost:3000 sshx.SshxService/DeleteApiKey
```

## 环境变量配置

### 客户端环境变量
```bash
# API Key (推荐)
export SSHX_API_KEY="your_api_key_here"

# 服务器地址 (可选)
export SSHX_SERVER="https://your-sshx-server.com"

# 运行 sshx
sshx
```

### 服务器环境变量
```bash
# Redis 连接 URL
export REDIS_URL="redis://localhost:6379"

# JWT 密钥
export JWT_SECRET="your_jwt_secret_key"

# 启动服务器
cargo run --bin sshx-server
```

## 安全注意事项

### 1. API Key 保护
- 不要在代码中硬编码 API Key
- 使用环境变量或安全的配置文件
- 定期轮换 API Key

### 2. 网络安全
- 在生产环境中使用 HTTPS
- 配置适当的防火墙规则
- 启用 Redis 认证

### 3. 访问控制
- 及时删除不需要的 API Key
- 监控 API Key 的使用情况
- 实施最小权限原则

## 故障排除

### 常见错误

1. **连接被拒绝**
   ```
   Error: transport error
   ```
   - 检查服务器是否正在运行
   - 验证服务器地址和端口

2. **API Key 无效**
   ```
   Error: Invalid API key
   ```
   - 检查 API Key 是否正确
   - 验证 API Key 是否已被删除

3. **Redis 连接失败**
   ```
   Error: Redis connection failed
   ```
   - 确保 Redis 服务正在运行
   - 检查 Redis 连接 URL

### 调试技巧

1. **启用详细日志**
   ```bash
   RUST_LOG=debug cargo run --bin sshx-server
   ```

2. **检查 Redis 数据**
   ```bash
   redis-cli
   127.0.0.1:6379> keys user:*
   127.0.0.1:6379> keys apikey:*
   ```

3. **测试 gRPC 连接**
   ```bash
   grpcurl -plaintext localhost:3000 list
   ```

## 高级用法

### 1. 批量 API Key 管理
```rust
// 生成多个 API Key
for i in 1..=5 {
    let req = GenerateApiKeyRequest {
        auth_token: auth_token.clone(),
        name: format!("Key {}", i),
    };
    let api_key = client.generate_api_key(req).await?;
    println!("Generated: {}", api_key.into_inner().name);
}
```

### 2. API Key 使用统计
```rust
// 获取 API Key 使用信息
let keys = client.list_api_keys(list_req).await?.into_inner();
for key in keys.api_keys {
    println!("Key: {}, Last used: {:?}", key.name, key.last_used);
}
```

### 3. 自动化脚本
```bash
#!/bin/bash
# 自动生成和使用 API Key

# 生成 API Key
API_KEY=$(cargo run --example api_key_test 2>/dev/null | grep "Token:" | cut -d' ' -f2)

# 使用 API Key 运行 sshx
export SSHX_API_KEY="$API_KEY"
sshx --quiet
```

这个示例展示了如何完整地使用 SSHX 的 API Key 功能，从用户注册到会话创建的整个流程。