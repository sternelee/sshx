# sshx 会话持久化功能指南

## 🎯 功能概述

sshx 现在支持会话持久化功能！当 sshx 客户端异常重启或重新执行时（在相同的执行目录和网络环境下），能够自动恢复到之前的会话，保持相同的 `encryption_key` 和 `URL`，用户无需重新分享链接。

## ✨ 核心特性

### 🔄 **自动会话恢复**
- 基于稳定因素生成唯一会话标识符
- 自动保存会话状态到本地文件
- 重启时智能恢复之前的会话

### 🔑 **智能会话识别**
- 基于 API Key + 服务器地址 + 工作目录 + 主机名生成会话ID
- 确保相同环境下的会话能够被正确识别和恢复

### 💾 **本地状态管理**
- 会话文件存储在 `~/.config/sshx/sessions/`
- 包含加密密钥、URL、token 等完整会话信息
- 支持会话有效期检查和自动清理

## 🏗️ 技术原理

### 会话标识符生成算法

```rust
fn generate_session_id(
    api_key: Option<&str>,
    server_origin: &str,
    working_dir: Option<&Path>,
) -> String {
    // 基于以下因素生成哈希:
    // 1. API Key (最重要，用于用户会话区分)
    // 2. 服务器地址
    // 3. 工作目录
    // 4. 主机名
    // 5. 用户名
    format!("sshx-{:016x}", hash_result)
}
```

### 会话状态结构

```json
{
  "session_id": "sshx-1234567890abcdef",
  "encryption_key": "abcd1234efgh5678",
  "write_password": "write_pass_if_enabled",
  "session_name": "user-12345678-1640995200",
  "session_token": "server_auth_token",
  "base_url": "http://localhost:3000/s/user-12345678-1640995200",
  "full_url": "http://localhost:3000/s/user-12345678-1640995200#abcd1234efgh5678",
  "write_url": "http://localhost:3000/s/user-12345678-1640995200#abcd1234efgh5678,write_pass",
  "server_origin": "http://localhost:3000",
  "api_key": "user_api_key",
  "created_at": 1640995200,
  "last_accessed": 1640995300
}
```

## 🚀 使用方法

### 基本使用

```bash
# 正常启动 (启用持久化)
sshx --api-key "YOUR_API_KEY"

# 第一次运行会创建新会话
# 后续在相同环境下运行会自动恢复之前的会话
```

### 高级选项

```bash
# 持久会话 (使用 API Key 自动启用持久化)
sshx --api-key "YOUR_API_KEY"

# 临时会话 (不使用 API Key，不启用持久化)
sshx

# 清理旧会话文件 (清理7天前的会话)
sshx --cleanup-sessions 7

# 清理所有会话文件
sshx --cleanup-sessions 0
```

### 环境变量支持

```bash
# 使用环境变量设置 API Key
export SSHX_API_KEY="YOUR_API_KEY"
sshx

# 指定服务器地址
export SSHX_SERVER="http://localhost:3000"
sshx
```

## 📋 会话恢复条件

会话能够成功恢复需要满足以下条件：

### ✅ **必要条件**
1. **相同的 API Key** - 用于用户身份识别
2. **相同的服务器地址** - 确保连接到同一服务器
3. **相同的工作目录** - 保证执行环境一致
4. **相同的主机和用户** - 确保是同一台机器的同一用户

### ✅ **有效性检查**
1. **会话文件存在** - 本地保存的会话状态文件
2. **会话未过期** - 默认24小时内的会话才会尝试恢复
3. **服务器会话有效** - 服务器端的会话仍然存在且可连接

### ❌ **恢复失败情况**
- 会话文件不存在或损坏
- 会话超过24小时未使用
- 服务器端会话已被清理
- API Key 已失效或被删除
- 网络连接问题

## 🔍 故障排除

### 查看会话状态

```bash
# 查看会话文件位置
ls -la ~/.config/sshx/sessions/

# 查看具体会话内容 (JSON格式)
cat ~/.config/sshx/sessions/sshx-1234567890abcdef.json
```

### 常见问题

#### 1. **会话无法恢复**

**可能原因:**
- 工作目录发生变化
- API Key 已过期或被删除
- 服务器端会话已清理

**解决方案:**
```bash
# 使用临时会话 (不启用持久化)
sshx

# 清理本地会话文件
sshx --cleanup-sessions 0
```

#### 2. **会话文件过多**

**解决方案:**
```bash
# 清理7天前的会话
sshx --cleanup-sessions 7

# 清理所有会话
sshx --cleanup-sessions 0
```

#### 3. **权限问题**

**解决方案:**
```bash
# 检查会话目录权限
ls -la ~/.config/sshx/

# 修复权限
chmod 700 ~/.config/sshx/
chmod 600 ~/.config/sshx/sessions/*
```

## 🔒 安全考虑

### 本地文件安全
- 会话文件包含敏感信息（加密密钥、token）
- 文件权限设置为仅用户可读写 (600)
- 会话目录权限设置为仅用户可访问 (700)

### 会话有效期
- 默认24小时会话有效期
- 超期会话自动清理
- 支持手动清理旧会话

### 服务器验证
- 恢复时验证服务器端会话仍然有效
- 无效会话自动清理本地文件
- 失败时回退到创建新会话

## 📊 使用场景

### 🎯 **适用场景**

1. **开发环境**
   - 频繁重启 sshx 进行调试
   - 保持相同的分享链接给团队成员

2. **CI/CD 流水线**
   - 脚本化的 sshx 使用
   - 需要稳定的会话 URL

3. **长期项目**
   - 项目开发期间保持相同会话
   - 避免频繁更新分享链接

### ❌ **不适用场景**

1. **临时使用**
   - 一次性的会话分享
   - 不提供 API Key

2. **多环境切换**
   - 频繁在不同目录下工作
   - 每个环境需要独立会话

3. **安全敏感环境**
   - 不希望在本地保存会话信息
   - 不提供 API Key

## 🧪 测试和验证

### 功能测试

```bash
# 运行持久化功能测试
cd crates/sshx
cargo run --example session_persistence_test

# 测试实际会话恢复
# 1. 启动 sshx
sshx --api-key "YOUR_API_KEY"

# 2. 记录 URL
# 3. 终止 sshx (Ctrl+C)
# 4. 重新启动
sshx --api-key "YOUR_API_KEY"

# 5. 验证 URL 是否相同
```

### 性能测试

```bash
# 测试会话恢复速度
time sshx --api-key "YOUR_API_KEY" --quiet

# 测试临时会话创建速度
time sshx --quiet
```

## 📈 监控和日志

### 日志级别

```bash
# 查看详细日志
RUST_LOG=debug sshx --api-key "YOUR_API_KEY"

# 查看持久化相关日志
RUST_LOG=sshx::session_persistence=debug sshx --api-key "YOUR_API_KEY"
```

### 关键日志信息

- `Successfully restored session from previous run` - 会话恢复成功
- `Failed to restore session, creating new one` - 会话恢复失败，创建新会话
- `Previous session too old, creating new one` - 会话过期，创建新会话
- `Session state saved` - 会话状态保存成功

## 🔮 未来增强

### 短期计划
- [ ] 支持多服务器会话管理
- [ ] 会话恢复重试机制
- [ ] 更细粒度的有效期控制

### 中期计划
- [ ] 会话状态加密存储
- [ ] 跨设备会话同步
- [ ] 会话使用统计

### 长期计划
- [ ] 云端会话备份
- [ ] 会话分享和协作
- [ ] 企业级会话管理

## 💡 最佳实践

### 1. **API Key 管理**
```bash
# 使用环境变量管理 API Key
echo 'export SSHX_API_KEY="your-api-key"' >> ~/.bashrc
source ~/.bashrc
```

### 2. **定期清理**
```bash
# 添加到 crontab 定期清理
# 每周清理30天前的会话
0 0 * * 0 sshx --cleanup-sessions 30
```

### 3. **项目特定配置**
```bash
# 在项目根目录创建启动脚本
#!/bin/bash
cd "$(dirname "$0")"
sshx --api-key "$PROJECT_SSHX_API_KEY"
```

### 4. **安全配置**
```bash
# 确保会话目录权限正确
chmod 700 ~/.config/sshx/
chmod 600 ~/.config/sshx/sessions/*
```

现在你可以享受无缝的 sshx 会话恢复体验！🚀