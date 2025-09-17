import type { RequestHandler } from "@sveltejs/kit";
import { Hono } from "hono";
import { upgradeWebSocket } from "hono/cloudflare-workers";
// WSContext type
type WSContext<T = any> = {
  raw: WebSocket;
  send: (data: string | ArrayBuffer) => void;
  close: (code?: number, reason?: string) => void;
};
import { cors } from "hono/cors";
// D1Database and KVNamespace types are globally available from worker-configuration.d.ts

// 定义绑定类型
type Bindings = {
  DB: D1Database;
  SESSIONS: KVNamespace;
  ENCRYPTION_KEY: string;
};

// 错误类型定义
enum ErrorCode {
  INVALID_INPUT = "INVALID_INPUT",
  AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED",
  SESSION_NOT_FOUND = "SESSION_NOT_FOUND",
  SESSION_ALREADY_EXISTS = "SESSION_ALREADY_EXISTS",
  PERMISSION_DENIED = "PERMISSION_DENIED",
  DATABASE_ERROR = "DATABASE_ERROR",
  NETWORK_ERROR = "NETWORK_ERROR",
  INTERNAL_ERROR = "INTERNAL_ERROR",
  CONNECTION_LIMIT_EXCEEDED = "CONNECTION_LIMIT_EXCEEDED",
  DATA_TOO_LARGE = "DATA_TOO_LARGE",
  INVALID_TOKEN = "INVALID_TOKEN",
  USER_NOT_FOUND = "USER_NOT_FOUND",
  SHELL_NOT_FOUND = "SHELL_NOT_FOUND",
}

// 错误类
class SshxError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: Record<string, any>;

  constructor(
    code: ErrorCode,
    message: string,
    statusCode: number = 500,
    details?: Record<string, any>,
  ) {
    super(message);
    this.name = "SshxError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }

  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        details: this.details,
      },
    };
  }
}

// 验证错误
class ValidationError extends SshxError {
  constructor(field: string, message: string, details?: Record<string, any>) {
    super(
      ErrorCode.INVALID_INPUT,
      `Validation failed for ${field}: ${message}`,
      400,
      {
        field,
        ...details,
      },
    );
    this.name = "ValidationError";
  }
}

// 认证错误
class AuthenticationError extends SshxError {
  constructor(message: string, details?: Record<string, any>) {
    super(ErrorCode.AUTHENTICATION_FAILED, message, 401, details);
    this.name = "AuthenticationError";
  }
}

// 权限错误
class PermissionError extends SshxError {
  constructor(action: string, details?: Record<string, any>) {
    super(ErrorCode.PERMISSION_DENIED, `Permission denied: ${action}`, 403, {
      action,
      ...details,
    });
    this.name = "PermissionError";
  }
}

// 数据库错误
class DatabaseError extends SshxError {
  constructor(
    operation: string,
    originalError?: Error,
    details?: Record<string, any>,
  ) {
    super(
      ErrorCode.DATABASE_ERROR,
      `Database operation failed: ${operation}`,
      500,
      {
        operation,
        originalError: originalError?.message,
        ...details,
      },
    );
    this.name = "DatabaseError";
  }
}

// 错误处理中间件
function handleError(error: unknown, context?: string): SshxError {
  console.error(`Error in ${context || "unknown context"}:`, error);

  if (error instanceof SshxError) {
    return error;
  }

  if (error instanceof Error) {
    // 根据错误消息类型推断错误类型
    if (error.message.includes("UNIQUE constraint failed")) {
      return new SshxError(
        ErrorCode.SESSION_ALREADY_EXISTS,
        "Resource already exists",
        409,
      );
    }

    if (error.message.includes("no such table")) {
      return new DatabaseError("table access", error);
    }

    if (
      error.message.includes("network") ||
      error.message.includes("connection")
    ) {
      return new SshxError(
        ErrorCode.NETWORK_ERROR,
        "Network error occurred",
        503,
      );
    }

    return new SshxError(ErrorCode.INTERNAL_ERROR, error.message, 500, {
      stack: error.stack,
    });
  }

  // 未知错误
  return new SshxError(
    ErrorCode.INTERNAL_ERROR,
    "An unknown error occurred",
    500,
  );
}

// 输入验证工具
function validateInput(value: any, type: string, fieldName: string): void {
  if (value === null || value === undefined) {
    throw new ValidationError(fieldName, `${fieldName} is required`);
  }

  switch (type) {
    case "string":
      if (typeof value !== "string") {
        throw new ValidationError(fieldName, `${fieldName} must be a string`);
      }
      if (value.trim() === "") {
        throw new ValidationError(fieldName, `${fieldName} cannot be empty`);
      }
      break;

    case "array":
      if (!Array.isArray(value)) {
        throw new ValidationError(fieldName, `${fieldName} must be an array`);
      }
      break;

    case "number":
      if (typeof value !== "number" || isNaN(value)) {
        throw new ValidationError(
          fieldName,
          `${fieldName} must be a valid number`,
        );
      }
      break;

    case "object":
      if (typeof value !== "object" || value === null) {
        throw new ValidationError(fieldName, `${fieldName} must be an object`);
      }
      break;
  }
}

// 验证会话名称格式
function validateSessionName(name: string): void {
  validateInput(name, "string", "session_name");

  if (!/^[a-z0-9]{10}$/.test(name)) {
    throw new ValidationError(
      "session_name",
      "Session name must be exactly 10 lowercase alphanumeric characters",
    );
  }
}

// 验证数组格式（用于加密数据）
function validateEncryptedArray(data: any, fieldName: string): void {
  validateInput(data, "array", fieldName);

  for (let i = 0; i < data.length; i++) {
    if (typeof data[i] !== "number" || data[i] < 0 || data[i] > 255) {
      throw new ValidationError(
        fieldName,
        `Invalid byte value at index ${i}: must be 0-255`,
      );
    }
  }
}

// 创建 Hono 应用
const app = new Hono<{ Bindings: Bindings }>().basePath("/api");

// 添加 CORS 支持
app.use("*", cors());

// 请求体解析中间件
app.use("*", async (c, next) => {
  if (c.req.method === "POST" || c.req.method === "PUT") {
    const contentType = c.req.header("content-type");
    if (contentType && contentType.includes("application/json")) {
      try {
        const body = await c.req.json();
        // Store parsed body in a way that's compatible with Hono's context
        (c as any).parsedBody = body;
      } catch (error) {
        const sshxError = handleError(error, "JSON parsing");
        return c.json(sshxError.toJSON(), sshxError.statusCode as any);
      }
    }
  }
  await next();
});

// 全局错误处理中间件
app.use("*", async (c, next) => {
  try {
    await next();
  } catch (error) {
    const sshxError = handleError(error, "global middleware");

    // 记录详细的错误信息
    console.error("Global error handler caught:", {
      url: c.req.url,
      method: c.req.method,
      userAgent: c.req.header("user-agent"),
      error: sshxError.toJSON(),
    });

    return c.json(sshxError.toJSON(), sshxError.statusCode as any);
  }
});

// 创建会话端点
app.post("/sessions", async (c) => {
  try {
    const body = (c as any).parsedBody || (await c.req.json());

    // 输入验证
    validateInput(body, "object", "request_body");

    const { origin, encrypted_zeros, name, write_password_hash } = body;

    // 验证必需字段
    validateEncryptedArray(encrypted_zeros, "encrypted_zeros");

    if (write_password_hash !== undefined) {
      validateEncryptedArray(write_password_hash, "write_password_hash");
    }

    // 验证或生成会话名称
    let sessionName: string;
    if (name) {
      validateSessionName(name);
      sessionName = name;
    } else {
      sessionName = generateSessionName();
    }

    // 检查会话名称是否已存在
    try {
      const existingSession = await c.env.DB.prepare(
        "SELECT id FROM sessions WHERE name = ?",
      )
        .bind(sessionName)
        .first();

      if (existingSession) {
        throw new SshxError(
          ErrorCode.SESSION_ALREADY_EXISTS,
          "Session name already exists",
          409,
          { sessionName },
        );
      }
    } catch (error) {
      if (error instanceof SshxError) throw error;
      throw new DatabaseError("session existence check", error as Error, {
        sessionName,
      });
    }

    // 生成会话 ID
    const sessionId = crypto.randomUUID();

    // 创建会话记录
    try {
      await c.env.DB.prepare(
        "INSERT INTO sessions (id, name, encrypted_zeros, write_password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
      )
        .bind(
          sessionId,
          sessionName,
          JSON.stringify(encrypted_zeros),
          write_password_hash ? JSON.stringify(write_password_hash) : null,
          Math.floor(Date.now() / 1000),
        )
        .run();
    } catch (error) {
      throw new DatabaseError("session creation", error as Error, {
        sessionId,
        sessionName,
      });
    }

    // 生成访问令牌
    let token: string;
    try {
      token = await generateToken(sessionName, c.env.ENCRYPTION_KEY);
    } catch (error) {
      throw new SshxError(
        ErrorCode.INTERNAL_ERROR,
        "Failed to generate access token",
        500,
        { originalError: (error as Error)?.message },
      );
    }

    // 构建会话 URL
    const sessionUrl = origin
      ? `${origin}/s/${sessionName}`
      : `/s/${sessionName}`;

    // 返回响应
    return c.json({
      name: sessionName,
      token,
      url: sessionUrl,
      created_at: Math.floor(Date.now() / 1000),
    });
  } catch (error) {
    const sshxError = handleError(error, "session creation");
    return c.json(sshxError.toJSON(), sshxError.statusCode as any);
  }
});

// 获取会话列表端点
app.get("/sessions", async (c) => {
  try {
    const sessions = await c.env.DB.prepare(
      "SELECT name, created_at, write_password_hash IS NOT NULL as has_write_password FROM sessions ORDER BY created_at DESC",
    ).all();

    return c.json({
      sessions: sessions.results.map((session: any) => ({
        name: session.name,
        created_at: session.created_at,
        has_write_password: session.has_write_password === 1,
      })),
    });
  } catch (error) {
    console.error("Error fetching sessions:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// 获取特定会话信息端点
app.get("/sessions/:name", async (c) => {
  try {
    const { name } = c.req.param();

    const session = await c.env.DB.prepare(
      "SELECT name, created_at, write_password_hash IS NOT NULL as has_write_password FROM sessions WHERE name = ?",
    )
      .bind(name)
      .first();

    if (!session) {
      return c.json({ error: "Session not found" }, 404);
    }

    // 获取连接统计
    const connections = await c.env.SESSIONS.get(`connections:${name}`);
    const connectionCount = connections
      ? Object.keys(JSON.parse(connections)).length
      : 0;

    // 获取用户统计
    const users = await c.env.DB.prepare(
      "SELECT COUNT(*) as count FROM users WHERE session_id = (SELECT id FROM sessions WHERE name = ?)",
    )
      .bind(name)
      .first();

    // 获取终端统计
    const shells = await c.env.DB.prepare(
      "SELECT COUNT(*) as count FROM shells WHERE session_id = (SELECT id FROM sessions WHERE name = ?)",
    )
      .bind(name)
      .first();

    return c.json({
      name: session.name,
      created_at: session.created_at,
      has_write_password: session.has_write_password === 1,
      connection_count: connectionCount,
      user_count: users?.count || 0,
      shell_count: shells?.count || 0,
    });
  } catch (error) {
    console.error("Error fetching session info:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// 关闭会话端点
app.post("/sessions/:name/close", async (c) => {
  try {
    const { name } = c.req.param();
    const body = (c as any).parsedBody || (await c.req.json());

    // 验证 token
    if (!body || !body.token) {
      return c.json({ error: "Token is required" }, 400);
    }

    const isValidToken = await verifyToken(
      name,
      body.token,
      c.env.ENCRYPTION_KEY,
    );
    if (!isValidToken) {
      return c.json({ error: "Invalid token" }, 401);
    }

    // 获取会话信息
    const session = await c.env.DB.prepare(
      "SELECT id FROM sessions WHERE name = ?",
    )
      .bind(name)
      .first();

    if (!session) {
      return c.json({ error: "Session not found" }, 404);
    }

    // 删除会话相关数据
    await c.env.DB.prepare("DELETE FROM chat_messages WHERE session_id = ?")
      .bind(session.id)
      .run();

    await c.env.DB.prepare(
      "DELETE FROM terminal_data WHERE shell_id IN (SELECT id FROM shells WHERE session_id = ?)",
    )
      .bind(session.id)
      .run();

    await c.env.DB.prepare("DELETE FROM shells WHERE session_id = ?")
      .bind(session.id)
      .run();

    await c.env.DB.prepare("DELETE FROM users WHERE session_id = ?")
      .bind(session.id)
      .run();

    await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?")
      .bind(session.id)
      .run();

    // 清理 KV 中的连接信息
    await c.env.SESSIONS.delete(`connections:${name}`);

    // 通知所有连接的客户端会话已关闭
    if (activeConnections.has(name)) {
      const connections = activeConnections.get(name)!;
      const closeMessage = JSON.stringify({
        type: "SessionClosed",
        message: "Session has been closed",
      });

      for (const ws of connections) {
        try {
          ws.send(closeMessage);
          ws.close();
        } catch (error) {
          console.error("Error closing WebSocket connection:", error);
        }
      }

      activeConnections.delete(name);
    }

    return c.json({ success: true, message: "Session closed successfully" });
  } catch (error) {
    console.error("Error closing session:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// 管理员端点 - 强制关闭会话
app.delete("/admin/sessions/:name", async (c) => {
  try {
    const { name } = c.req.param();

    // 获取会话信息
    const session = await c.env.DB.prepare(
      "SELECT id FROM sessions WHERE name = ?",
    )
      .bind(name)
      .first();

    if (!session) {
      return c.json({ error: "Session not found" }, 404);
    }

    // 删除会话相关数据
    await c.env.DB.prepare("DELETE FROM chat_messages WHERE session_id = ?")
      .bind(session.id)
      .run();

    await c.env.DB.prepare(
      "DELETE FROM terminal_data WHERE shell_id IN (SELECT id FROM shells WHERE session_id = ?)",
    )
      .bind(session.id)
      .run();

    await c.env.DB.prepare("DELETE FROM shells WHERE session_id = ?")
      .bind(session.id)
      .run();

    await c.env.DB.prepare("DELETE FROM users WHERE session_id = ?")
      .bind(session.id)
      .run();

    await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?")
      .bind(session.id)
      .run();

    // 清理 KV 中的连接信息
    await c.env.SESSIONS.delete(`connections:${name}`);

    // 通知所有连接的客户端会话已关闭
    if (activeConnections.has(name)) {
      const connections = activeConnections.get(name)!;
      const closeMessage = JSON.stringify({
        type: "SessionClosed",
        message: "Session has been closed by admin",
      });

      for (const ws of connections) {
        try {
          ws.send(closeMessage);
          ws.close();
        } catch (error) {
          console.error("Error closing WebSocket connection:", error);
        }
      }

      activeConnections.delete(name);
    }

    return c.json({ success: true, message: "Session force closed by admin" });
  } catch (error) {
    console.error("Error force closing session:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// 服务器统计端点
app.get("/stats", async (c) => {
  try {
    // 获取会话统计
    const sessionStats = await c.env.DB.prepare(
      "SELECT COUNT(*) as total_sessions FROM sessions",
    ).first();

    // 获取用户统计
    const userStats = await c.env.DB.prepare(
      "SELECT COUNT(*) as total_users FROM users",
    ).first();

    // 获取终端统计
    const shellStats = await c.env.DB.prepare(
      "SELECT COUNT(*) as total_shells FROM shells",
    ).first();

    // 获取终端数据统计
    const dataStats = await c.env.DB.prepare(
      "SELECT COUNT(*) as total_data_points FROM terminal_data",
    ).first();

    // 获取聊天消息统计
    const chatStats = await c.env.DB.prepare(
      "SELECT COUNT(*) as total_messages FROM chat_messages",
    ).first();

    // 获取活动连接统计
    const activeConnectionsList = await c.env.SESSIONS.list({
      prefix: "connections:",
    });
    let totalActiveConnections = 0;
    for (const key of activeConnectionsList.keys) {
      const connections = await c.env.SESSIONS.get(key.name);
      if (connections) {
        totalActiveConnections += Object.keys(JSON.parse(connections)).length;
      }
    }

    return c.json({
      total_sessions: sessionStats?.total_sessions || 0,
      total_users: userStats?.total_users || 0,
      total_shells: shellStats?.total_shells || 0,
      total_data_points: dataStats?.total_data_points || 0,
      total_messages: chatStats?.total_messages || 0,
      active_connections: totalActiveConnections,
      memory_connections: activeConnections.size,
    });
  } catch (error) {
    console.error("Error fetching stats:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// 触发清理端点
app.post("/admin/cleanup", async (c) => {
  try {
    await cleanupExpiredSessions(c);
    return c.json({ success: true, message: "Cleanup completed" });
  } catch (error) {
    console.error("Error during cleanup:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// 兼容性端点 - 与原始 sshx-server API 保持一致
app.post("/open", async (c) => {
  try {
    const body = (c as any).parsedBody || (await c.req.json());

    // 重定向到新的会话创建端点
    const response = await c.req.json();
    const result = await (async () => {
      // 重复会话创建逻辑以保持兼容性
      if (!body || typeof body !== "object") {
        return { error: "Invalid request body" };
      }

      const { origin, encrypted_zeros, name, write_password_hash } = body;

      if (!Array.isArray(encrypted_zeros)) {
        return { error: "encrypted_zeros is required and must be an array" };
      }

      if (write_password_hash && !Array.isArray(write_password_hash)) {
        return { error: "write_password_hash must be an array" };
      }

      const sessionName = name || generateSessionName();

      const existingSession = await c.env.DB.prepare(
        "SELECT id FROM sessions WHERE name = ?",
      )
        .bind(sessionName)
        .first();

      if (existingSession) {
        return { error: "Session name already exists" };
      }

      const sessionId = crypto.randomUUID();

      await c.env.DB.prepare(
        "INSERT INTO sessions (id, name, encrypted_zeros, write_password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
      )
        .bind(
          sessionId,
          sessionName,
          JSON.stringify(encrypted_zeros),
          write_password_hash ? JSON.stringify(write_password_hash) : null,
          Math.floor(Date.now() / 1000),
        )
        .run();

      const token = await generateToken(sessionName, c.env.ENCRYPTION_KEY);
      const sessionUrl = origin
        ? `${origin}/s/${sessionName}`
        : `/s/${sessionName}`;

      return {
        name: sessionName,
        token,
        url: sessionUrl,
      };
    })();

    if (result.error) {
      return c.json({ error: result.error }, 400);
    }

    return c.json(result);
  } catch (error) {
    console.error("Error in /open endpoint:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// 兼容性端点 - 关闭会话
app.post("/close", async (c) => {
  try {
    const body = (c as any).parsedBody || (await c.req.json());

    if (!body || !body.name || !body.token) {
      return c.json({ error: "name and token are required" }, 400);
    }

    const isValidToken = await verifyToken(
      body.name,
      body.token,
      c.env.ENCRYPTION_KEY,
    );
    if (!isValidToken) {
      return c.json({ error: "Invalid token" }, 401);
    }

    // 使用现有的关闭会话逻辑
    const session = await c.env.DB.prepare(
      "SELECT id FROM sessions WHERE name = ?",
    )
      .bind(body.name)
      .first();

    if (!session) {
      return c.json({ error: "Session not found" }, 404);
    }

    // 删除会话相关数据
    await c.env.DB.prepare("DELETE FROM chat_messages WHERE session_id = ?")
      .bind(session.id)
      .run();

    await c.env.DB.prepare(
      "DELETE FROM terminal_data WHERE shell_id IN (SELECT id FROM shells WHERE session_id = ?)",
    )
      .bind(session.id)
      .run();

    await c.env.DB.prepare("DELETE FROM shells WHERE session_id = ?")
      .bind(session.id)
      .run();

    await c.env.DB.prepare("DELETE FROM users WHERE session_id = ?")
      .bind(session.id)
      .run();

    await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?")
      .bind(session.id)
      .run();

    // 清理 KV 中的连接信息
    await c.env.SESSIONS.delete(`connections:${body.name}`);

    // 通知所有连接的客户端会话已关闭
    if (activeConnections.has(body.name)) {
      const connections = activeConnections.get(body.name)!;
      const closeMessage = JSON.stringify({
        type: "SessionClosed",
        message: "Session has been closed",
      });

      for (const ws of connections) {
        try {
          ws.send(closeMessage);
          ws.close();
        } catch (error) {
          console.error("Error closing WebSocket connection:", error);
        }
      }

      activeConnections.delete(body.name);
    }

    return c.json({ success: true });
  } catch (error) {
    console.error("Error in /close endpoint:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// 会话元数据接口
interface SessionMetadata {
  encrypted_zeros: number[];
  name: string;
  write_password_hash?: number[];
}

// WebSocket 消息类型定义
interface WsUser {
  name: string;
  cursor: [number, number] | null;
  focus: string | null;
  can_write: boolean;
}

interface WsWinsize {
  x: number;
  y: number;
  rows: number;
  cols: number;
}

type WsServerMessage =
  | { type: "Hello"; user_id: string; session_name: string }
  | { type: "InvalidAuth" }
  | { type: "Users"; users: [string, WsUser][] }
  | { type: "UserDiff"; user_id: string; user: WsUser | null }
  | { type: "Shells"; shells: [string, WsWinsize][] }
  | { type: "Chunks"; shell_id: string; seqnum: number; chunks: number[][] }
  | { type: "Hear"; user_id: string; name: string; message: string }
  | { type: "ShellLatency"; latency: number }
  | { type: "Pong"; timestamp: number }
  | { type: "Error"; message: string };

type WsClientMessage =
  | {
      type: "Authenticate";
      encrypted_zeros: number[];
      write_password?: number[];
    }
  | { type: "SetName"; name: string }
  | { type: "SetCursor"; cursor: [number, number] | null }
  | { type: "SetFocus"; focus: string | null }
  | { type: "Create"; x: number; y: number }
  | { type: "Close"; shell_id: string }
  | { type: "Move"; shell_id: string; winsize: WsWinsize | null }
  | { type: "Data"; shell_id: string; data: number[]; offset: number }
  | { type: "Subscribe"; shell_id: string; chunknum: number }
  | { type: "Chat"; message: string }
  | { type: "Ping"; timestamp: number }
  | { type: "Heartbeat" };

// 存储活动连接的全局映射
// 在实际的 Cloudflare Worker 中，这需要使用 Durable Objects 或外部存储
// 这里我们使用内存存储作为临时解决方案
// 注意：在实际生产环境中，应使用 Durable Objects 来管理 WebSocket 连接
const activeConnections = new Map<string, WebSocket[]>();

// 存储终端订阅信息
const shellSubscriptions = new Map<string, Set<WebSocket>>();

// WebSocket 连接处理器
app.get(
  "/s/:name",
  upgradeWebSocket((c) => {
    const { name } = c.req.param();

    // 存储连接相关的状态
    let userId: string | null = null;
    let sessionId: string | null = null;
    let canWrite: boolean = false;
    const subscribedShells = new Set<string>();
    let connectionId: string | null = null;
    let lastHeartbeat: number = Date.now();

    return {
      onOpen(evt: Event, ws: WSContext) {
        // 连接建立时的处理逻辑
        console.log(`WebSocket connection opened for session: ${name}`);
        // 生成连接 ID
        connectionId = generateConnectionId();
        (ws.raw as any).connectionId = connectionId;

        // 将 WebSocket 连接存储到全局状态中，以便广播消息
        (ws.raw as any).sessionName = name;
        (ws.raw as any).connectionTime = Date.now();

        // 初始化连接列表
        if (!activeConnections.has(name)) {
          activeConnections.set(name, []);
        }
        activeConnections.get(name)!.push(ws.raw as WebSocket);

        // 在 KV 中存储连接信息
        try {
          const kvKey = `connections:${name}`;
          const existingConnections = c.env.SESSIONS.get(kvKey);
          const connections: Record<string, { timestamp: number }> =
            existingConnections ? JSON.parse(existingConnections) : {};
          if (connectionId) {
            connections[connectionId] = { timestamp: Date.now() };
            c.env.SESSIONS.put(kvKey, JSON.stringify(connections));
          }
        } catch (error) {
          console.error("Error storing connection in KV:", error);
        }
      },

      async onMessage(evt: MessageEvent, ws: WSContext) {
        try {
          // 解析客户端消息
          const message = JSON.parse(evt.data as string) as WsClientMessage;

          switch (message.type) {
            case "Authenticate":
              // 处理认证消息
              const authResult = await handleAuthenticate(c, name, message);
              if (
                authResult.success &&
                authResult.userId &&
                authResult.sessionId !== null
              ) {
                userId = authResult.userId;
                sessionId = authResult.sessionId;
                canWrite = authResult.canWrite;
                (ws as any).userId = userId;
                ws.send(
                  JSON.stringify({
                    type: "Hello",
                    user_id: userId,
                    session_name: name,
                  } as WsServerMessage),
                );

                // 发送当前用户列表
                const users = await getAllUsers(c, sessionId);
                ws.send(
                  JSON.stringify({ type: "Users", users } as WsServerMessage),
                );

                // 发送当前终端列表
                const shells = await getAllShells(c, sessionId);
                ws.send(
                  JSON.stringify({ type: "Shells", shells } as WsServerMessage),
                );
              } else {
                ws.send(
                  JSON.stringify({ type: "InvalidAuth" } as WsServerMessage),
                );
              }
              break;

            case "SetName":
              // 处理设置用户名消息
              if (userId && sessionId) {
                await handleSetName(c, sessionId, userId, message);
              }
              break;

            case "SetCursor":
              // 处理设置光标位置消息
              if (userId && sessionId) {
                await handleSetCursor(c, sessionId, userId, message);
              }
              break;

            case "SetFocus":
              // 处理设置焦点消息
              if (userId && sessionId) {
                await handleSetFocus(c, sessionId, userId, message);
              }
              break;

            case "Create":
              // 处理创建终端消息
              if (userId && sessionId && canWrite) {
                await handleCreateShell(c, sessionId, userId, message);
              } else if (userId && sessionId && !canWrite) {
                ws.send(
                  JSON.stringify({
                    type: "Error",
                    message: "No write permission",
                  } as WsServerMessage),
                );
              }
              break;

            case "Close":
              // 处理关闭终端消息
              if (userId && sessionId && canWrite) {
                await handleCloseShell(c, sessionId, userId, message);
              } else if (userId && sessionId && !canWrite) {
                ws.send(
                  JSON.stringify({
                    type: "Error",
                    message: "No write permission",
                  } as WsServerMessage),
                );
              }
              break;

            case "Move":
              // 处理移动终端消息
              if (userId && sessionId && canWrite) {
                await handleMoveShell(c, sessionId, userId, message);
              } else if (userId && sessionId && !canWrite) {
                ws.send(
                  JSON.stringify({
                    type: "Error",
                    message: "No write permission",
                  } as WsServerMessage),
                );
              }
              break;

            case "Data":
              // 处理终端数据消息
              if (userId && sessionId && canWrite) {
                await handleTerminalData(c, sessionId, userId, message);
              } else if (userId && sessionId && !canWrite) {
                ws.send(
                  JSON.stringify({
                    type: "Error",
                    message: "No write permission",
                  } as WsServerMessage),
                );
              }
              break;

            case "Subscribe":
              // 处理订阅终端数据消息
              if (userId && sessionId) {
                await handleSubscribe(
                  c,
                  sessionId,
                  userId,
                  message,
                  ws.raw as WebSocket,
                );
                subscribedShells.add(message.shell_id);
              }
              break;

            case "Chat":
              // 处理聊天消息
              if (userId && sessionId) {
                await handleChatMessage(c, sessionId, userId, message);
              }
              break;

            case "Ping":
              // 处理 ping 消息
              const now = Date.now();
              const latency = now - message.timestamp;

              // 发送 pong 响应
              ws.send(
                JSON.stringify({
                  type: "Pong",
                  timestamp: message.timestamp,
                } as WsServerMessage),
              );

              // 如果延迟过高，记录日志
              if (latency > 1000) {
                console.warn(
                  `High latency detected: ${latency}ms for user ${userId}`,
                );
              }

              // 广播延迟统计给会话中的其他用户
              if (userId && sessionId && latency > 0) {
                await broadcastLatency(c, sessionId, userId, latency);
              }
              break;

            case "Heartbeat":
              // 处理心跳消息
              lastHeartbeat = Date.now();

              // 更新连接的最后活动时间
              if (connectionId) {
                try {
                  const kvKey = `connections:${name}`;
                  const existingConnections = await c.env.SESSIONS.get(kvKey);
                  const connections: Record<string, { timestamp: number }> =
                    existingConnections ? JSON.parse(existingConnections) : {};

                  if (connections[connectionId]) {
                    connections[connectionId].timestamp = lastHeartbeat;
                    await c.env.SESSIONS.put(
                      kvKey,
                      JSON.stringify(connections),
                    );
                  }
                } catch (error) {
                  console.error("Error updating connection heartbeat:", error);
                }
              }
              break;

            default:
              console.warn(`Unknown message type: ${(message as any).type}`);
          }
        } catch (error) {
          console.error("Error processing WebSocket message:", error);
          ws.send(
            JSON.stringify({
              type: "Error",
              message: "Internal server error",
            } as WsServerMessage),
          );
        }
      },

      onClose(evt: CloseEvent, ws: WSContext) {
        // 连接关闭时的处理逻辑
        console.log(`WebSocket connection closed for session: ${name}`);
        // 从活动连接中移除
        if (activeConnections.has(name)) {
          const connections = activeConnections.get(name)!;
          const index = connections.indexOf(ws.raw as WebSocket);
          if (index !== -1) {
            connections.splice(index, 1);
          }
        }

        // 从所有订阅列表中移除连接
        for (const [shellId, subscribers] of shellSubscriptions.entries()) {
          if (subscribers.has(ws.raw as WebSocket)) {
            subscribers.delete(ws.raw as WebSocket);
            // 如果订阅列表为空，移除它
            if (subscribers.size === 0) {
              shellSubscriptions.delete(shellId);
            }
          }
        }

        // 从 KV 中移除连接信息
        if (connectionId) {
          try {
            const kvKey = `connections:${name}`;
            const existingConnections = c.env.SESSIONS.get(kvKey);
            if (existingConnections) {
              const connections: Record<string, { timestamp: number }> =
                JSON.parse(existingConnections);
              delete connections[connectionId];
              c.env.SESSIONS.put(kvKey, JSON.stringify(connections));
            }
          } catch (error) {
            console.error("Error removing connection from KV:", error);
          }
        }

        // 清理用户连接
        if (userId && sessionId) {
          removeUser(c, sessionId, userId);
        }
      },

      onError(evt: Event, ws: WSContext) {
        // 连接错误时的处理逻辑
        console.error("WebSocket error:", evt);
      },
    };
  }),
);

// 处理认证消息
async function handleAuthenticate(
  c: any,
  sessionName: string,
  message: Extract<WsClientMessage, { type: "Authenticate" }>,
) {
  // 输入验证
  if (!sessionName || typeof sessionName !== "string") {
    return { success: false, userId: null, sessionId: null, canWrite: false };
  }

  if (!Array.isArray(message.encrypted_zeros)) {
    return { success: false, userId: null, sessionId: null, canWrite: false };
  }

  if (message.write_password && !Array.isArray(message.write_password)) {
    return { success: false, userId: null, sessionId: null, canWrite: false };
  }

  const db = c.env.DB;

  // 获取会话元数据
  const sessionResult: {
    id: string;
    encrypted_zeros: number[];
    write_password_hash: number[] | null;
  } | null = (await db
    .prepare(
      "SELECT id, encrypted_zeros, write_password_hash FROM sessions WHERE name = ?",
    )
    .bind(sessionName)
    .first()) as any;

  if (!sessionResult) {
    return { success: false, userId: null, sessionId: null, canWrite: false };
  }

  // 验证加密零块 (常量时间比较以防止时序攻击)
  if (!arraysEqual(message.encrypted_zeros, sessionResult.encrypted_zeros)) {
    return { success: false, userId: null, sessionId: null, canWrite: false };
  }

  // 生成用户 ID
  const userId = generateUserId();

  // 检查写权限
  let canWrite = true;
  if (sessionResult.write_password_hash && message.write_password) {
    canWrite = arraysEqual(
      message.write_password,
      sessionResult.write_password_hash,
    );
  } else if (sessionResult.write_password_hash && !message.write_password) {
    canWrite = false;
  }

  // 保存用户信息到数据库
  const userName = `User ${userId.substring(0, 8)}`;
  try {
    await db
      .prepare(
        "INSERT INTO users (id, session_id, name, can_write) VALUES (?, ?, ?, ?)",
      )
      .bind(userId, sessionResult.id, userName, canWrite ? 1 : 0)
      .run();
  } catch (error) {
    console.error("Error creating user:", error);
    return { success: false, userId: null, sessionId: null, canWrite: false };
  }

  return {
    success: true,
    userId,
    sessionId: sessionResult.id,
    canWrite,
  };
}

// 处理设置用户名消息
async function handleSetName(
  c: any,
  sessionId: string,
  userId: string,
  message: Extract<WsClientMessage, { type: "SetName" }>,
) {
  const db = c.env.DB;

  // 更新用户信息
  await db
    .prepare("UPDATE users SET name = ? WHERE id = ? AND session_id = ?")
    .bind(message.name, userId, sessionId)
    .run();

  // 通知所有客户端用户信息更新
  const user: {
    id: string;
    name: string;
    can_write: number;
    cursor_x: number | null;
    cursor_y: number | null;
    focus_shell_id: string | null;
  } | null = await db
    .prepare(
      "SELECT id, name, can_write, cursor_x, cursor_y, focus_shell_id FROM users WHERE id = ? AND session_id = ?",
    )
    .bind(userId, sessionId)
    .first();

  if (user) {
    const wsUser: WsUser = {
      name: user.name,
      cursor:
        user.cursor_x !== null && user.cursor_y !== null
          ? [user.cursor_x, user.cursor_y]
          : null,
      focus: user.focus_shell_id,
      can_write: user.can_write === 1,
    };

    await broadcastToSession(c, sessionId, {
      type: "UserDiff",
      user_id: user.id,
      user: wsUser,
    } as WsServerMessage);
  }
}

// 处理设置光标位置消息
async function handleSetCursor(
  c: any,
  sessionId: string,
  userId: string,
  message: Extract<WsClientMessage, { type: "SetCursor" }>,
) {
  const db = c.env.DB;

  // 更新用户光标位置
  if (message.cursor) {
    await db
      .prepare(
        "UPDATE users SET cursor_x = ?, cursor_y = ? WHERE id = ? AND session_id = ?",
      )
      .bind(message.cursor[0], message.cursor[1], userId, sessionId)
      .run();
  } else {
    await db
      .prepare(
        "UPDATE users SET cursor_x = NULL, cursor_y = NULL WHERE id = ? AND session_id = ?",
      )
      .bind(userId, sessionId)
      .run();
  }

  // 通知所有客户端用户信息更新
  const user: {
    id: string;
    name: string;
    can_write: number;
    cursor_x: number | null;
    cursor_y: number | null;
    focus_shell_id: string | null;
  } | null = await db
    .prepare(
      "SELECT id, name, can_write, cursor_x, cursor_y, focus_shell_id FROM users WHERE id = ? AND session_id = ?",
    )
    .bind(userId, sessionId)
    .first();

  if (user) {
    const wsUser: WsUser = {
      name: user.name,
      cursor:
        user.cursor_x !== null && user.cursor_y !== null
          ? [user.cursor_x, user.cursor_y]
          : null,
      focus: user.focus_shell_id,
      can_write: user.can_write === 1,
    };

    await broadcastToSession(c, sessionId, {
      type: "UserDiff",
      user_id: user.id,
      user: wsUser,
    } as WsServerMessage);
  }
}

// 处理设置焦点消息
async function handleSetFocus(
  c: any,
  sessionId: string,
  userId: string,
  message: Extract<WsClientMessage, { type: "SetFocus" }>,
) {
  const db = c.env.DB;

  // 更新用户焦点
  if (message.focus) {
    await db
      .prepare(
        "UPDATE users SET focus_shell_id = ? WHERE id = ? AND session_id = ?",
      )
      .bind(message.focus, userId, sessionId)
      .run();
  } else {
    await db
      .prepare(
        "UPDATE users SET focus_shell_id = NULL WHERE id = ? AND session_id = ?",
      )
      .bind(userId, sessionId)
      .run();
  }

  // 通知所有客户端用户信息更新
  const user: {
    id: string;
    name: string;
    can_write: number;
    cursor_x: number | null;
    cursor_y: number | null;
    focus_shell_id: string | null;
  } | null = await db
    .prepare(
      "SELECT id, name, can_write, cursor_x, cursor_y, focus_shell_id FROM users WHERE id = ? AND session_id = ?",
    )
    .bind(userId, sessionId)
    .first();

  if (user) {
    const wsUser: WsUser = {
      name: user.name,
      cursor:
        user.cursor_x !== null && user.cursor_y !== null
          ? [user.cursor_x, user.cursor_y]
          : null,
      focus: user.focus_shell_id,
      can_write: user.can_write === 1,
    };

    await broadcastToSession(c, sessionId, {
      type: "UserDiff",
      user_id: user.id,
      user: wsUser,
    } as WsServerMessage);
  }
}

// 处理创建终端消息
async function handleCreateShell(
  c: any,
  sessionId: string,
  userId: string,
  message: Extract<WsClientMessage, { type: "Create" }>,
) {
  // 输入验证
  if (!sessionId || typeof sessionId !== "string") {
    console.error("Invalid session ID");
    return;
  }

  if (typeof message.x !== "number" || typeof message.y !== "number") {
    console.error("Invalid coordinates");
    return;
  }

  const db = c.env.DB;

  // 生成终端 ID
  const shellId = generateShellId();

  // 创建终端记录
  try {
    await db
      .prepare(
        "INSERT INTO shells (id, session_id, x, y, rows, cols) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .bind(shellId, sessionId, message.x, message.y, 24, 80)
      .run();
  } catch (error) {
    console.error("Error creating shell:", error);
    return;
  }

  // 通知所有客户端终端列表更新
  try {
    const shells = await getAllShells(c, sessionId);
    await broadcastToSession(c, sessionId, {
      type: "Shells",
      shells,
    } as WsServerMessage);
  } catch (error) {
    console.error("Error broadcasting shells update:", error);
  }
}

// 处理关闭终端消息
async function handleCloseShell(
  c: any,
  sessionId: string,
  userId: string,
  message: Extract<WsClientMessage, { type: "Close" }>,
) {
  const db = c.env.DB;

  // 删除终端记录
  await db
    .prepare("DELETE FROM shells WHERE id = ? AND session_id = ?")
    .bind(message.shell_id, sessionId)
    .run();

  // 通知所有客户端终端列表更新
  const shells = await getAllShells(c, sessionId);
  await broadcastToSession(c, sessionId, {
    type: "Shells",
    shells,
  } as WsServerMessage);
}

// 处理移动终端消息
async function handleMoveShell(
  c: any,
  sessionId: string,
  userId: string,
  message: Extract<WsClientMessage, { type: "Move" }>,
) {
  const db = c.env.DB;

  // 更新终端位置
  if (message.winsize) {
    await db
      .prepare(
        "UPDATE shells SET x = ?, y = ?, rows = ?, cols = ? WHERE id = ? AND session_id = ?",
      )
      .bind(
        message.winsize.x,
        message.winsize.y,
        message.winsize.rows,
        message.winsize.cols,
        message.shell_id,
        sessionId,
      )
      .run();
  }

  // 通知所有客户端终端列表更新
  const shells = await getAllShells(c, sessionId);
  await broadcastToSession(c, sessionId, {
    type: "Shells",
    shells,
  } as WsServerMessage);
}

// 数据压缩接口
interface CompressionResult {
  compressed: Uint8Array;
  compressionRatio: number;
  algorithm: string;
}

// 处理终端数据消息
async function handleTerminalData(
  c: any,
  sessionId: string,
  userId: string,
  message: Extract<WsClientMessage, { type: "Data" }>,
) {
  try {
    // 输入验证
    validateInput(sessionId, "string", "session_id");
    validateInput(message.shell_id, "string", "shell_id");
    validateInput(message.data, "array", "data");
    validateInput(message.offset, "number", "offset");

    const db = c.env.DB;
    const MAX_DATA_SIZE = 2 * 1024 * 1024; // 2MB limit per shell (matching original)

    // 检查是否需要清理旧数据
    await pruneTerminalData(c, message.shell_id, MAX_DATA_SIZE);

    // 转换数据为 Uint8Array
    const uint8Data = new Uint8Array(message.data);

    // 尝试压缩数据
    const compressionResult = await tryCompressData(uint8Data);

    // 保存压缩的终端数据
    try {
      await db
        .prepare(
          "INSERT INTO terminal_data (shell_id, sequence_number, data, compression_algorithm, compression_ratio, original_size) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(
          message.shell_id,
          message.offset,
          compressionResult.compressed,
          compressionResult.algorithm,
          compressionResult.compressionRatio,
          uint8Data.length,
        )
        .run();

      // 记录压缩统计
      if (compressionResult.compressionRatio > 1.1) {
        console.log(
          `Compressed terminal data for shell ${message.shell_id}: ${uint8Data.length} -> ${compressionResult.compressed.length} bytes (${compressionResult.compressionRatio.toFixed(2)}x ratio)`,
        );
      }
    } catch (error) {
      throw new DatabaseError("terminal data insertion", error as Error, {
        shell_id: message.shell_id,
        sequence_number: message.offset,
        data_size: uint8Data.length,
      });
    }

    // 通知订阅了此终端的客户端有新数据（发送原始未压缩数据）
    notifySubscribers(message.shell_id, message.offset, message.data);
  } catch (error) {
    console.error("Error handling terminal data:", error);
    // 不重新抛出错误，避免中断 WebSocket 连接
  }
}

// 清理终端数据（当超过大小限制时）
async function pruneTerminalData(c: any, shellId: string, maxSize: number) {
  const db = c.env.DB;

  // 获取当前数据大小（优先使用原始大小，如果没有则使用压缩后大小）
  const sizeResult = await db
    .prepare(
      "SELECT SUM(COALESCE(original_size, LENGTH(data))) as total_size FROM terminal_data WHERE shell_id = ?",
    )
    .bind(shellId)
    .first();

  const currentSize = sizeResult?.total_size || 0;

  if (currentSize > maxSize) {
    // 计算需要删除的数据量
    const excess = currentSize - maxSize;
    const targetSize = maxSize * 0.8; // 清理到80%的容量

    // 获取数据块并按优先级排序（优先删除旧的、压缩率低的数据）
    const dataBlocks = await db
      .prepare(
        `
        SELECT
          sequence_number,
          COALESCE(original_size, LENGTH(data)) as size,
          COALESCE(compression_ratio, 1.0) as compression_ratio,
          created_at
        FROM terminal_data
        WHERE shell_id = ?
        ORDER BY
          created_at ASC,                    -- 优先删除旧数据
          compression_ratio ASC,            -- 然后删除压缩率低的（节省空间少）
          size DESC                          -- 最后删除大块数据
      `,
      )
      .bind(shellId)
      .all();

    let accumulatedSize = 0;
    let deleteUpToSequence = 0;
    let deletedBlocks = 0;

    for (const block of dataBlocks.results) {
      if (accumulatedSize < targetSize) {
        accumulatedSize += block.size;
        deleteUpToSequence = block.sequence_number;
        deletedBlocks++;
      } else {
        break;
      }
    }

    // 删除旧数据块
    if (deleteUpToSequence > 0) {
      const result = await db
        .prepare(
          "DELETE FROM terminal_data WHERE shell_id = ? AND sequence_number <= ?",
        )
        .bind(shellId, deleteUpToSequence)
        .run();

      console.log(
        `Pruned terminal data for shell ${shellId}: deleted ${deletedBlocks} blocks up to sequence ${deleteUpToSequence}, kept ${accumulatedSize} bytes (from ${currentSize})`,
      );

      // 记录清理统计
      const finalSize = await getTerminalDataSize(c, shellId);
      const savingsRatio =
        currentSize > 0 ? (currentSize - finalSize) / currentSize : 0;
      console.log(
        `Cleanup savings: ${Math.round(savingsRatio * 100)}% reduction (${currentSize} -> ${finalSize} bytes)`,
      );

      // 记录压缩效果统计
      const compressionStats = await getCompressionStats(c, shellId);
      if (compressionStats.totalCompressed > 0) {
        const overallRatio =
          compressionStats.totalOriginal / compressionStats.totalCompressed;
        console.log(
          `Compression stats for shell ${shellId}: ${overallRatio.toFixed(2)}x ratio (${compressionStats.totalOriginal} -> ${compressionStats.totalCompressed} bytes, ${compressionStats.compressedBlocks}/${compressionStats.totalBlocks} blocks compressed)`,
        );
      }
    }
  }
}

// 获取终端数据大小
async function getTerminalDataSize(c: any, shellId: string): Promise<number> {
  const db = c.env.DB;
  const result = await db
    .prepare(
      "SELECT SUM(LENGTH(data)) as total_size FROM terminal_data WHERE shell_id = ?",
    )
    .bind(shellId)
    .first();

  return result?.total_size || 0;
}

// 获取终端数据块统计
async function getTerminalDataStats(
  c: any,
  shellId: string,
): Promise<{
  count: number;
  total_size: number;
  min_seq: number;
  max_seq: number;
}> {
  const db = c.env.DB;
  const result = await db
    .prepare(
      `
      SELECT
        COUNT(*) as count,
        SUM(LENGTH(data)) as total_size,
        MIN(sequence_number) as min_seq,
        MAX(sequence_number) as max_seq
      FROM terminal_data
      WHERE shell_id = ?
    `,
    )
    .bind(shellId)
    .first();

  return {
    count: result?.count || 0,
    total_size: result?.total_size || 0,
    min_seq: result?.min_seq || 0,
    max_seq: result?.max_seq || 0,
  };
}

// 获取压缩统计信息
async function getCompressionStats(
  c: any,
  shellId: string,
): Promise<{
  totalBlocks: number;
  compressedBlocks: number;
  totalOriginal: number;
  totalCompressed: number;
  averageCompressionRatio: number;
}> {
  const db = c.env.DB;
  const result = await db
    .prepare(
      `
      SELECT
        COUNT(*) as total_blocks,
        SUM(CASE WHEN compression_algorithm != 'none' AND compression_algorithm IS NOT NULL THEN 1 ELSE 0 END) as compressed_blocks,
        SUM(COALESCE(original_size, LENGTH(data))) as total_original,
        SUM(LENGTH(data)) as total_compressed,
        AVG(COALESCE(compression_ratio, 1.0)) as avg_compression_ratio
      FROM terminal_data
      WHERE shell_id = ?
    `,
    )
    .bind(shellId)
    .first();

  return {
    totalBlocks: result?.total_blocks || 0,
    compressedBlocks: result?.compressed_blocks || 0,
    totalOriginal: result?.total_original || 0,
    totalCompressed: result?.total_compressed || 0,
    averageCompressionRatio: result?.avg_compression_ratio || 1.0,
  };
}

// 处理订阅终端数据消息
async function handleSubscribe(
  c: any,
  sessionId: string,
  userId: string,
  message: Extract<WsClientMessage, { type: "Subscribe" }>,
  ws: WebSocket,
) {
  // 输入验证
  if (!sessionId || typeof sessionId !== "string") {
    console.error("Invalid session ID");
    return;
  }

  if (!message.shell_id || typeof message.shell_id !== "string") {
    console.error("Invalid shell ID");
    return;
  }

  if (typeof message.chunknum !== "number") {
    console.error("Invalid chunknum");
    return;
  }

  const db = c.env.DB;

  // 获取从指定 chunknum 开始的所有数据（包含压缩信息）
  try {
    const dataResult: {
      results: {
        sequence_number: number;
        data: Uint8Array;
        compression_algorithm: string;
        original_size: number;
      }[];
    } = await db
      .prepare(
        "SELECT sequence_number, data, compression_algorithm, original_size FROM terminal_data WHERE shell_id = ? AND sequence_number >= ? ORDER BY sequence_number ASC LIMIT 100",
      )
      .bind(message.shell_id, message.chunknum)
      .all();

    // 发送数据块给客户端（自动解压）
    for (const row of dataResult.results) {
      let finalData = row.data;

      // 如果数据被压缩，先解压
      if (row.compression_algorithm && row.compression_algorithm !== "none") {
        try {
          finalData = await decompressData(row.data, row.compression_algorithm);
        } catch (error) {
          console.error(
            `Failed to decompress data for sequence ${row.sequence_number}:`,
            error,
          );
          // 继续使用原始数据（可能是压缩失败的数据）
        }
      }

      ws.send(
        JSON.stringify({
          type: "Chunks",
          shell_id: message.shell_id,
          seqnum: row.sequence_number,
          chunks: [Array.from(finalData)],
        } as WsServerMessage),
      );
    }

    // 如果还有更多数据，发送一个提示消息
    if (dataResult.results.length === 100) {
      // 客户端可能需要请求更多数据
      console.log(`More data available for shell ${message.shell_id}`);
    }
  } catch (error) {
    console.error("Error fetching terminal data:", error);
    return;
  }

  // 添加到订阅列表
  if (!shellSubscriptions.has(message.shell_id)) {
    shellSubscriptions.set(message.shell_id, new Set());
  }
  shellSubscriptions.get(message.shell_id)!.add(ws);
}

// 处理聊天消息
async function handleChatMessage(
  c: any,
  sessionId: string,
  userId: string,
  message: Extract<WsClientMessage, { type: "Chat" }>,
) {
  // 输入验证
  if (!sessionId || typeof sessionId !== "string") {
    console.error("Invalid session ID");
    return;
  }

  if (!userId || typeof userId !== "string") {
    console.error("Invalid user ID");
    return;
  }

  if (!message.message || typeof message.message !== "string") {
    console.error("Invalid message");
    return;
  }

  // 限制消息长度
  if (message.message.length > 1000) {
    console.error("Message too long");
    return;
  }

  const db = c.env.DB;

  // 保存聊天消息
  try {
    await db
      .prepare(
        "INSERT INTO chat_messages (session_id, user_id, message) VALUES (?, ?, ?)",
      )
      .bind(sessionId, userId, message.message)
      .run();
  } catch (error) {
    console.error("Error saving chat message:", error);
    return;
  }

  // 获取用户名
  try {
    const user: { name: string } | null = await db
      .prepare("SELECT name FROM users WHERE id = ? AND session_id = ?")
      .bind(userId, sessionId)
      .first();

    if (user) {
      // 通知所有客户端聊天消息
      await broadcastToSession(c, sessionId, {
        type: "Hear",
        user_id: userId,
        name: user.name,
        message: message.message,
      } as WsServerMessage);
    }
  } catch (error) {
    console.error("Error broadcasting chat message:", error);
  }
}

// 获取会话中的所有用户
async function getAllUsers(
  c: any,
  sessionId: string,
): Promise<[string, WsUser][]> {
  const db = c.env.DB;

  const usersResult = await db
    .prepare(
      "SELECT id, name, can_write, cursor_x, cursor_y, focus_shell_id FROM users WHERE session_id = ?",
    )
    .bind(sessionId)
    .all();

  return usersResult.results.map((user: any) => [
    user.id,
    {
      name: user.name,
      cursor:
        user.cursor_x !== null && user.cursor_y !== null
          ? [user.cursor_x, user.cursor_y]
          : null,
      focus: user.focus_shell_id,
      can_write: user.can_write === 1,
    },
  ]);
}

// 获取会话中的所有终端
async function getAllShells(
  c: any,
  sessionId: string,
): Promise<[string, WsWinsize][]> {
  const db = c.env.DB;

  const shellsResult = await db
    .prepare("SELECT id, x, y, rows, cols FROM shells WHERE session_id = ?")
    .bind(sessionId)
    .all();

  return shellsResult.results.map((shell: any) => [
    shell.id,
    {
      x: shell.x,
      y: shell.y,
      rows: shell.rows,
      cols: shell.cols,
    },
  ]);
}

// 移除用户
async function removeUser(c: any, sessionId: string, userId: string) {
  const db = c.env.DB;

  // 从数据库中删除用户
  await db
    .prepare("DELETE FROM users WHERE id = ? AND session_id = ?")
    .bind(userId, sessionId)
    .run();

  // 通知所有客户端用户已离开
  await broadcastToSession(c, sessionId, {
    type: "UserDiff",
    user_id: userId,
    user: null,
  } as WsServerMessage);
}

// 向会话中的所有客户端广播消息
async function broadcastToSession(
  c: any,
  sessionId: string,
  message: WsServerMessage,
) {
  // 获取会话名称
  const db = c.env.DB;
  const sessionResult: { name: string } | null = await db
    .prepare("SELECT name FROM sessions WHERE id = ?")
    .bind(sessionId)
    .first();

  if (!sessionResult) return;

  const sessionName = sessionResult.name;
  const messageStr = JSON.stringify(message);

  // 向所有连接广播消息
  if (activeConnections.has(sessionName)) {
    const connections = activeConnections.get(sessionName)!;

    // 向所有连接发送消息
    for (const ws of connections) {
      try {
        ws.send(messageStr);
      } catch (error) {
        console.error("Error sending message to client:", error);
      }
    }
  }

  // 同时将消息存储到 KV 中，以便在需要时可以重新发送
  try {
    const kvKey = `broadcast:${sessionName}:${Date.now()}`;
    await c.env.SESSIONS.put(kvKey, messageStr, { expirationTtl: 60 }); // 1分钟过期
  } catch (error) {
    console.error("Error storing broadcast message in KV:", error);
  }
}

// 生成用户 ID
function generateUserId(): string {
  return "user_" + Math.random().toString(36).substr(2, 9);
}

// 生成终端 ID
function generateShellId(): string {
  return "shell_" + Math.random().toString(36).substr(2, 9);
}

// 生成连接 ID
function generateConnectionId(): string {
  return "conn_" + Math.random().toString(36).substr(2, 9);
}

// 通知订阅了此终端的客户端有新数据
function notifySubscribers(shellId: string, seqnum: number, data: number[]) {
  if (shellSubscriptions.has(shellId)) {
    const subscribers = shellSubscriptions.get(shellId)!;
    const message: WsServerMessage = {
      type: "Chunks",
      shell_id: shellId,
      seqnum,
      chunks: [data],
    };
    const messageStr = JSON.stringify(message);

    for (const ws of subscribers) {
      try {
        ws.send(messageStr);
      } catch (error) {
        console.error("Error sending data to subscriber:", error);
        // 移除无效的订阅者
        subscribers.delete(ws);
      }
    }
  }
}

// 生成随机会话名称 (10个字符)
function generateSessionName(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 10; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// 数据压缩工具函数
async function tryCompressData(data: Uint8Array): Promise<{
  compressed: Uint8Array;
  algorithm: string;
  compressionRatio: number;
}> {
  try {
    // 使用 CompressionStream API 进行压缩
    const stream = new Response(data).body;
    if (!stream) throw new Error("Failed to create stream");

    const compressedStream = stream.pipeThrough(
      new CompressionStream("deflate"),
    );
    const compressedResponse = new Response(compressedStream);
    const compressedArrayBuffer = await compressedResponse.arrayBuffer();
    const compressed = new Uint8Array(compressedArrayBuffer);

    const ratio = compressed.length / data.length;

    // 只有当压缩提供实际收益时才使用压缩
    if (ratio >= 0.9) {
      return {
        compressed: data,
        algorithm: "none",
        compressionRatio: 1.0,
      };
    }

    return {
      compressed,
      algorithm: "deflate",
      compressionRatio: ratio,
    };
  } catch (error) {
    console.warn("Compression failed, using raw data:", error);
    return {
      compressed: data,
      algorithm: "none",
      compressionRatio: 1.0,
    };
  }
}

async function decompressData(
  data: Uint8Array,
  algorithm: string,
): Promise<Uint8Array> {
  if (algorithm === "none" || algorithm === null) {
    return data;
  }

  try {
    const stream = new Response(data).body;
    if (!stream) throw new Error("Failed to create stream");

    const decompressedStream = stream.pipeThrough(
      new DecompressionStream(algorithm as CompressionFormat),
    );
    const decompressedResponse = new Response(decompressedStream);
    const decompressedArrayBuffer = await decompressedResponse.arrayBuffer();
    return new Uint8Array(decompressedArrayBuffer);
  } catch (error) {
    console.error("Decompression failed:", error);
    throw new Error(`Failed to decompress data with algorithm: ${algorithm}`);
  }
}

// 生成 HMAC-SHA256 token
async function generateToken(
  sessionName: string,
  secret: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(sessionName);

  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign("HMAC", key, messageData);
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// 验证 HMAC-SHA256 token
async function verifyToken(
  sessionName: string,
  token: string,
  secret: string,
): Promise<boolean> {
  const expectedToken = await generateToken(sessionName, secret);
  return constantTimeCompare(token, expectedToken);
}

// 常量时间比较
function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// 清理过期的会话和连接
async function cleanupExpiredSessions(c: any) {
  const now = Date.now();
  const expirationTime = 5 * 60 * 1000; // 5分钟

  // 获取所有会话连接信息
  const list: { keys: { name: string }[] } = await c.env.SESSIONS.list({
    prefix: "connections:",
  });

  for (const key of list.keys) {
    const sessionName = key.name.replace("connections:", "");

    // 获取连接信息
    const connectionsStr = await c.env.SESSIONS.get(key.name);
    if (connectionsStr) {
      try {
        const connections: Record<string, { timestamp: number }> =
          JSON.parse(connectionsStr);
        let hasActiveConnections = false;

        // 检查连接是否过期
        for (const [connId, connInfo] of Object.entries(connections)) {
          if (now - connInfo.timestamp > expirationTime) {
            // 连接过期，移除它
            delete connections[connId];
          } else {
            hasActiveConnections = true;
          }
        }

        // 如果没有活动连接，清理会话数据
        if (!hasActiveConnections) {
          // 从 KV 中移除连接信息
          await c.env.SESSIONS.delete(key.name);

          // 获取会话 ID
          const sessionResult: { id: string } | null = await c.env.DB.prepare(
            "SELECT id FROM sessions WHERE name = ?",
          )
            .bind(sessionName)
            .first();

          if (sessionResult) {
            // 删除会话相关的所有数据
            await c.env.DB.prepare(
              "DELETE FROM chat_messages WHERE session_id = ?",
            )
              .bind(sessionResult.id)
              .run();

            await c.env.DB.prepare(
              "DELETE FROM terminal_data WHERE shell_id IN (SELECT id FROM shells WHERE session_id = ?)",
            )
              .bind(sessionResult.id)
              .run();

            await c.env.DB.prepare("DELETE FROM shells WHERE session_id = ?")
              .bind(sessionResult.id)
              .run();

            await c.env.DB.prepare("DELETE FROM users WHERE session_id = ?")
              .bind(sessionResult.id)
              .run();

            // 删除会话本身
            await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?")
              .bind(sessionResult.id)
              .run();
          }
        } else {
          // 更新连接信息
          await c.env.SESSIONS.put(key.name, JSON.stringify(connections));
        }
      } catch (error) {
        console.error("Error cleaning up session:", error);
      }
    }
  }
}

// 延迟测量统计
interface LatencyStats {
  user_id: string;
  latency: number;
  timestamp: number;
}

// 存储用户延迟统计的映射
const userLatencyStats = new Map<string, LatencyStats[]>();

// 广播延迟统计
async function broadcastLatency(
  c: any,
  sessionId: string,
  userId: string,
  latency: number,
) {
  // 存储延迟统计
  if (!userLatencyStats.has(userId)) {
    userLatencyStats.set(userId, []);
  }

  const stats = userLatencyStats.get(userId)!;
  stats.push({
    user_id: userId,
    latency,
    timestamp: Date.now(),
  });

  // 保持最近100个测量值
  if (stats.length > 100) {
    stats.shift();
  }

  // 计算平均延迟
  const recentStats = stats.slice(-10); // 最近10次测量
  const avgLatency =
    recentStats.reduce((sum, stat) => sum + stat.latency, 0) /
    recentStats.length;

  // 每30秒广播一次延迟统计
  const shouldBroadcast = stats.length % 10 === 0; // 每10次ping广播一次

  if (shouldBroadcast) {
    await broadcastToSession(c, sessionId, {
      type: "ShellLatency",
      latency: Math.round(avgLatency),
    } as WsServerMessage);
  }
}

// 获取用户延迟统计
function getUserLatencyStats(userId: string): {
  average: number;
  min: number;
  max: number;
  count: number;
} {
  const stats = userLatencyStats.get(userId) || [];

  if (stats.length === 0) {
    return { average: 0, min: 0, max: 0, count: 0 };
  }

  const latencies = stats.map((stat) => stat.latency);
  return {
    average: Math.round(
      latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length,
    ),
    min: Math.min(...latencies),
    max: Math.max(...latencies),
    count: latencies.length,
  };
}

// 心跳检查 - 检查不活跃的连接
function checkInactiveConnections() {
  const now = Date.now();
  const heartbeatTimeout = 2 * 60 * 1000; // 2分钟无心跳视为不活跃

  for (const [sessionName, connections] of activeConnections.entries()) {
    const inactiveConnections: WebSocket[] = [];

    for (const ws of connections) {
      try {
        const lastActivity =
          (ws as any).lastHeartbeat || (ws as any).connectionTime;
        if (now - lastActivity > heartbeatTimeout) {
          console.warn(
            `Inactive connection detected for session ${sessionName}, closing connection`,
          );
          inactiveConnections.push(ws);
        }
      } catch (error) {
        console.error("Error checking connection activity:", error);
      }
    }

    // 关闭不活跃的连接
    for (const ws of inactiveConnections) {
      try {
        ws.close(1000, "Connection inactive");
      } catch (error) {
        console.error("Error closing inactive connection:", error);
      }
    }
  }
}

// 清理过期的延迟统计
function cleanupLatencyStats() {
  const now = Date.now();
  const expirationTime = 5 * 60 * 1000; // 5分钟

  for (const [userId, stats] of userLatencyStats.entries()) {
    // 过滤掉过期的统计
    const validStats = stats.filter(
      (stat) => now - stat.timestamp < expirationTime,
    );

    if (validStats.length === 0) {
      userLatencyStats.delete(userId);
    } else {
      userLatencyStats.set(userId, validStats);
    }
  }
}

// 比较两个数组是否相等 (常量时间比较以防止时序攻击)
function arraysEqual(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

// 健康检查端点
app.get("/health", (c) => {
  return c.json({ status: "ok" });
});

// 清理端点
app.get("/cleanup", async (c) => {
  try {
    await cleanupExpiredSessions(c);
    return c.json({ status: "cleanup completed" });
  } catch (error) {
    console.error("Error during cleanup:", error);
    return c.json(
      { status: "cleanup failed", error: (error as Error).message },
      500,
    );
  }
});

// 定期清理过期会话的后台任务
async function scheduleCleanupTask(c: any) {
  try {
    // 立即执行一次清理
    await cleanupExpiredSessions(c);

    // 清理延迟统计
    cleanupLatencyStats();

    // 检查不活跃的连接
    checkInactiveConnections();

    // 在 Cloudflare Workers 中，我们可以使用 cron triggers 或定期调用
    // 这里我们设置一个 KV 记录来跟踪上次清理时间
    await c.env.SESSIONS.put("last_cleanup", Date.now().toString());

    console.log("Cleanup task completed successfully");
  } catch (error) {
    console.error("Error in cleanup task:", error);
  }
}

// 数据库初始化和索引创建
async function initializeDatabase(c: any) {
  const db = c.env.DB;

  try {
    // 检查数据库是否已经初始化
    const initialized = await db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'",
      )
      .first();

    if (!initialized) {
      console.log("Database not initialized, creating tables and indexes...");

      // 创建表结构
      await db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY,
          name TEXT UNIQUE NOT NULL,
          encrypted_zeros TEXT NOT NULL,
          write_password_hash TEXT,
          created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          name TEXT NOT NULL,
          can_write INTEGER NOT NULL DEFAULT 0,
          cursor_x INTEGER,
          cursor_y INTEGER,
          focus_shell_id TEXT,
          created_at INTEGER NOT NULL,
          FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS shells (
          id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          x INTEGER NOT NULL,
          y INTEGER NOT NULL,
          rows INTEGER NOT NULL,
          cols INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS terminal_data (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          shell_id TEXT NOT NULL,
          sequence_number INTEGER NOT NULL,
          data BLOB NOT NULL,
          compression_algorithm TEXT DEFAULT 'none',
          compression_ratio REAL DEFAULT 1.0,
          original_size INTEGER,
          created_at INTEGER NOT NULL,
          FOREIGN KEY (shell_id) REFERENCES shells(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS chat_messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          message TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
      `);

      // 创建关键索引
      await db.exec(`
        -- 会话相关索引
        CREATE INDEX IF NOT EXISTS idx_sessions_name ON sessions(name);
        CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);

        -- 用户相关索引
        CREATE INDEX IF NOT EXISTS idx_users_session_id ON users(session_id);
        CREATE INDEX IF NOT EXISTS idx_users_session_can_write ON users(session_id, can_write);
        CREATE INDEX IF NOT EXISTS idx_users_focus_shell_id ON users(focus_shell_id);

        -- 终端相关索引
        CREATE INDEX IF NOT EXISTS idx_shells_session_id ON shells(session_id);
        CREATE INDEX IF NOT EXISTS idx_shells_position ON shells(session_id, x, y);

        -- 终端数据索引（最重要的性能优化）
        CREATE INDEX IF NOT EXISTS idx_terminal_data_shell_id ON terminal_data(shell_id);
        CREATE INDEX IF NOT EXISTS idx_terminal_data_shell_sequence ON terminal_data(shell_id, sequence_number);
        CREATE INDEX IF NOT EXISTS idx_terminal_data_sequence ON terminal_data(sequence_number);

        -- 聊天消息索引
        CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);
        CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at);
      `);

      console.log("Database initialized successfully with indexes");
    }
  } catch (error) {
    console.error("Error initializing database:", error);
    throw error;
  }
}

// 导出为 SvelteKit 请求处理器
export const GET: RequestHandler = async ({ request, platform }) => {
  // 初始化数据库（如果需要）
  const env = (platform as any)?.env;
  if (env?.DB) {
    try {
      await initializeDatabase({ env });
    } catch (error) {
      console.error("Failed to initialize database:", error);
    }
  }
  return app.fetch(request);
};

export const POST: RequestHandler = async ({ request, platform }) => {
  // 初始化数据库（如果需要）
  const env = (platform as any)?.env;
  if (env?.DB) {
    try {
      await initializeDatabase({ env });
    } catch (error) {
      console.error("Failed to initialize database:", error);
    }
  }
  return app.fetch(request);
};
