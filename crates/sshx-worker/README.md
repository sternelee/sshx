# sshx-worker

sshx server adapted for Cloudflare Workers using the `workers-rs` framework with D1 database.

## 功能特性

- 基于 Rust 和 `workers-rs` 框架
- 使用 Cloudflare D1 SQLite 数据库
- 支持用户认证和会话管理
- API 密钥管理
- 实时 WebSocket 连接
- 全球边缘部署

## 快速开始

### 先决条件

1. 安装 Rust 和 Cargo
2. 安装 Node.js 和 npm
3. 安装 Wrangler CLI:
   ```bash
   npm install -g wrangler
   ```
4. 安装 worker-build:
   ```bash
   cargo install worker-build
   ```

### 数据库设置

1. 创建 D1 数据库:
   ```bash
   npx wrangler d1 create sshx
   ```

2. 记录数据库 ID 并更新 `wrangler.toml` 中的 `database_id`

3. 初始化数据库结构:
   ```bash
   npm run db:init
   ```

### 本地开发

1. 克隆项目并进入目录:
   ```bash
   cd crates/sshx-worker
   ```

2. 配置环境变量:
   编辑 `wrangler.toml` 文件中的 `vars` 部分：
   ```toml
   [vars]
   SSHX_SECRET = "your-secret-key"
   SSHX_OVERRIDE_ORIGIN = "https://your-domain.com"
   SSHX_HOST = "worker-1"
   ```

3. 启动本地开发服务器:
   ```bash
   npm run dev
   ```

### 部署到 Cloudflare Workers

1. 登录 Cloudflare:
   ```bash
   npx wrangler login
   ```

2. 部署到生产环境:
   ```bash
   npm run deploy
   ```

## 配置选项

### 环境变量

- `SSHX_SECRET`: 用于签名会话令牌的密钥
- `SSHX_OVERRIDE_ORIGIN`: 覆盖返回的来源URL
- `SSHX_HOST`: 服务器主机名 (可选)

### D1 数据库

D1 是 Cloudflare 的全球分布式 SQLite 数据库：

```toml
[[d1_databases]]
binding = "SSHX_DB"
database_name = "sshx"
database_id = "your-database-id"
```

### 可选服务

#### KV 命名空间 (用于缓存)
```toml
[[kv_namespaces]]
binding = "SESSIONS_CACHE"
id = "your-sessions-kv-namespace-id"
```

#### Durable Objects (用于实时功能)
```toml
[durable_objects]
bindings = [
  { name = "SSHX_SESSION", class_name = "SshxSession" }
]
```

#### R2 存储桶 (用于文件存储)
```toml
[[r2_buckets]]
binding = "FILES"
bucket_name = "sshx-files"
```

## API 端点

- `POST /api/auth/register` - 用户注册
- `POST /api/auth/login` - 用户登录
- `POST /api/auth/api-keys` - 生成 API 密钥
- `GET /api/auth/api-keys` - 列出 API 密钥
- `DELETE /api/auth/api-keys/:id` - 删除 API 密钥
- `POST /api/auth/sessions` - 列出用户会话
- `POST /api/auth/sessions/:id/close` - 关闭用户会话
- `GET /api/s/:name` - WebSocket 会话连接

## 数据库结构

### 主要表

- `users` - 用户信息和认证
- `api_keys` - API 密钥管理
- `sessions` - 终端会话
- `session_snapshots` - 会话快照和状态
- `session_connections` - 活跃连接追踪

### 数据库命令

- `npm run db:init` - 初始化数据库结构
- `npm run db:migrate` - 运行数据库迁移

## 架构说明

该适配器完全重写了数据存储层，主要变化包括：

1. **数据库**: 从 Redis 迁移到 Cloudflare D1 SQLite
2. **状态管理**: 实现了自定义的 `CloudflareServerState`
3. **用户服务**: 完整的用户认证和会话管理系统
4. **数据访问层**: 基于 D1 的 ORM 风格数据访问
5. **WebSocket 支持**: 适配 Cloudflare Workers 的 WebSocket API

## D1 数据库优势

- **全球分布**: 数据自动复制到全球边缘位置
- **低延迟**: 数据就近访问
- **SQLite 兼容**: 标准 SQL 语法
- **无服务器**: 按使用量付费，无需管理基础设施
- **强一致性**: 写入操作具有强一致性

## 限制和注意事项

- D1 数据库有读写频率限制
- WebSocket 连接受 Cloudflare Workers 的持续时间限制
- 某些 Tokio 功能可能不完全兼容
- 大文件存储建议使用 R2

## 开发和调试

启用详细日志:
```bash
RUST_LOG=debug npm run dev
```

查看 Worker 日志:
```bash
npm run tail
```

查看 D1 数据库:
```bash
npx wrangler d1 query sshx "SELECT * FROM users;"
```

## 贡献

欢迎提交 issue 和 pull request!