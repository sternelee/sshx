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

// 错误处理中间件（增强版）
function handleError(error: unknown, context?: string): SshxError {
  const timestamp = new Date().toISOString();
  const errorContext = context || "unknown context";

  // 增强的错误日志记录
  console.error(`[${timestamp}] Error in ${errorContext}:`, {
    error,
    type: typeof error,
    stack: error instanceof Error ? error.stack : undefined,
    message: error instanceof Error ? error.message : String(error),
    context: errorContext,
  });

  if (error instanceof SshxError) {
    // 记录已知的 SshxError 类型
    console.warn(
      `[${timestamp}] Known SshxError: ${error.code} - ${error.message}`,
    );
    return error;
  }

  if (error instanceof Error) {
    // 根据错误消息类型推断错误类型（增强版）
    const errorMessage = error.message.toLowerCase();

    if (errorMessage.includes("unique constraint failed")) {
      return new SshxError(
        ErrorCode.SESSION_ALREADY_EXISTS,
        "Resource already exists",
        409,
      );
    }

    if (
      errorMessage.includes("no such table") ||
      errorMessage.includes("database schema")
    ) {
      return new DatabaseError("table access", error);
    }

    if (
      errorMessage.includes("network") ||
      errorMessage.includes("connection")
    ) {
      return new SshxError(
        ErrorCode.NETWORK_ERROR,
        "Network error occurred",
        503,
      );
    }

    if (errorMessage.includes("timeout") || errorMessage.includes("time out")) {
      return new SshxError(ErrorCode.NETWORK_ERROR, "Operation timeout", 504);
    }

    if (
      errorMessage.includes("memory") ||
      errorMessage.includes("out of memory")
    ) {
      return new SshxError(
        ErrorCode.INTERNAL_ERROR,
        "Memory limit exceeded",
        507,
      );
    }

    if (
      errorMessage.includes("permission") ||
      errorMessage.includes("unauthorized")
    ) {
      return new PermissionError("database operation", {
        originalError: error.message,
      });
    }

    return new SshxError(ErrorCode.INTERNAL_ERROR, error.message, 500, {
      stack: error.stack,
      timestamp,
    });
  }

  // 未知错误
  console.error(`[${timestamp}] Unknown error type:`, error);
  return new SshxError(
    ErrorCode.INTERNAL_ERROR,
    "An unknown error occurred",
    500,
    { timestamp },
  );
}

// 输入验证工具（增强版）
function validateInput(
  value: any,
  type: string,
  fieldName: string,
  options: {
    required?: boolean;
    minLength?: number;
    maxLength?: number;
    pattern?: RegExp;
    min?: number;
    max?: number;
    allowedValues?: any[];
  } = {},
): void {
  const {
    required = true,
    minLength,
    maxLength,
    pattern,
    min,
    max,
    allowedValues,
  } = options;

  if (value === null || value === undefined) {
    if (required) {
      throw new ValidationError(fieldName, `${fieldName} is required`);
    }
    return;
  }

  switch (type) {
    case "string":
      if (typeof value !== "string") {
        throw new ValidationError(fieldName, `${fieldName} must be a string`);
      }

      const trimmedValue = value.trim();
      if (required && trimmedValue === "") {
        throw new ValidationError(fieldName, `${fieldName} cannot be empty`);
      }

      if (minLength && trimmedValue.length < minLength) {
        throw new ValidationError(
          fieldName,
          `${fieldName} must be at least ${minLength} characters`,
        );
      }

      if (maxLength && trimmedValue.length > maxLength) {
        throw new ValidationError(
          fieldName,
          `${fieldName} must be at most ${maxLength} characters`,
        );
      }

      if (pattern && !pattern.test(trimmedValue)) {
        throw new ValidationError(fieldName, `${fieldName} format is invalid`);
      }

      // 检查潜在的危险字符
      if (
        trimmedValue.includes("<") ||
        trimmedValue.includes(">") ||
        trimmedValue.includes("&") ||
        trimmedValue.includes('"') ||
        trimmedValue.includes("'") ||
        trimmedValue.includes("`")
      ) {
        console.warn(`Potential XSS attempt in ${fieldName}:`, value);
      }
      break;

    case "array":
      if (!Array.isArray(value)) {
        throw new ValidationError(fieldName, `${fieldName} must be an array`);
      }

      if (minLength !== undefined && value.length < minLength) {
        throw new ValidationError(
          fieldName,
          `${fieldName} must have at least ${minLength} elements`,
        );
      }

      if (maxLength !== undefined && value.length > maxLength) {
        throw new ValidationError(
          fieldName,
          `${fieldName} must have at most ${maxLength} elements`,
        );
      }

      // 验证数组元素
      if (allowedValues) {
        for (const item of value) {
          if (!allowedValues.includes(item)) {
            throw new ValidationError(
              fieldName,
              `Invalid value in ${fieldName}: ${item}`,
            );
          }
        }
      }
      break;

    case "number":
      if (typeof value !== "number" || isNaN(value)) {
        throw new ValidationError(
          fieldName,
          `${fieldName} must be a valid number`,
        );
      }

      if (min !== undefined && value < min) {
        throw new ValidationError(
          fieldName,
          `${fieldName} must be at least ${min}`,
        );
      }

      if (max !== undefined && value > max) {
        throw new ValidationError(
          fieldName,
          `${fieldName} must be at most ${max}`,
        );
      }
      break;

    case "object":
      if (typeof value !== "object" || value === null) {
        throw new ValidationError(fieldName, `${fieldName} must be an object`);
      }

      // 检查原型污染
      if (value.__proto__ !== Object.prototype) {
        throw new ValidationError(
          fieldName,
          `${fieldName} contains unsafe prototype`,
        );
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

// 添加 CORS 支持（安全配置）
app.use(
  "*",
  cors({
    origin: (origin, c) => {
      // 允许的源列表
      const allowedOrigins = [
        "http://localhost:3000",
        "http://localhost:5173",
        "https://sshx.io",
        // 添加其他允许的源
      ];

      // 开发环境允许所有源
      if (c.env.ENVIRONMENT === "development") {
        return "*";
      }

      // 生产环境严格检查
      if (!origin || allowedOrigins.includes(origin)) {
        return origin;
      }

      return null; // 拒绝请求
    },
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    maxAge: 86400, // 24小时
  }),
);

// 安全中间件
app.use("*", async (c, next) => {
  // 添加安全头
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("X-XSS-Protection", "1; mode=block");
  c.header("Referrer-Policy", "strict-origin-when-cross-origin");
  c.header(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
  );

  // 请求大小限制
  const contentLength = parseInt(c.req.header("content-length") || "0");
  const MAX_REQUEST_SIZE = 10 * 1024 * 1024; // 10MB

  if (contentLength > MAX_REQUEST_SIZE) {
    return c.json(
      {
        error: "Request too large",
        code: "REQUEST_TOO_LARGE",
        max_size: MAX_REQUEST_SIZE,
      },
      413,
    );
  }

  await next();
});

// 简单的内存速率限制（生产环境建议使用 Redis 或 Durable Objects）
const rateLimits = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1分钟
const RATE_LIMIT_MAX_REQUESTS = 100; // 每分钟最多100个请求

// 速率限制中间件
app.use("*", async (c, next) => {
  const ip =
    c.req.header("cf-connecting-ip") ||
    c.req.header("x-forwarded-for") ||
    "unknown";
  const now = Date.now();

  // 清理过期的速率限制记录
  for (const [key, limit] of rateLimits.entries()) {
    if (now > limit.resetTime) {
      rateLimits.delete(key);
    }
  }

  // 检查速率限制
  const limit = rateLimits.get(ip) || {
    count: 0,
    resetTime: now + RATE_LIMIT_WINDOW,
  };

  if (now > limit.resetTime) {
    limit.count = 1;
    limit.resetTime = now + RATE_LIMIT_WINDOW;
  } else {
    limit.count++;
  }

  rateLimits.set(ip, limit);

  if (limit.count > RATE_LIMIT_MAX_REQUESTS) {
    return c.json(
      {
        error: "Rate limit exceeded",
        code: "RATE_LIMIT_EXCEEDED",
        retry_after: Math.ceil((limit.resetTime - now) / 1000),
      },
      429,
    );
  }

  // 添加速率限制头
  c.header("X-RateLimit-Limit", RATE_LIMIT_MAX_REQUESTS.toString());
  c.header(
    "X-RateLimit-Remaining",
    Math.max(0, RATE_LIMIT_MAX_REQUESTS - limit.count).toString(),
  );
  c.header("X-RateLimit-Reset", Math.ceil(limit.resetTime / 1000).toString());

  await next();
});

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

// 全局错误处理中间件（增强版）
app.use("*", async (c, next) => {
  const startTime = Date.now();
  const requestId = generateRequestId();

  // 添加请求ID到上下文
  (c as any).requestId = requestId;

  try {
    await next();

    // 记录成功请求
    const duration = Date.now() - startTime;
    console.log(
      `[${requestId}] ${c.req.method} ${c.req.url} - ${c.res.status} (${duration}ms)`,
    );
  } catch (error) {
    const sshxError = handleError(error, "global middleware");
    const duration = Date.now() - startTime;

    // 记录详细的错误信息
    console.error(`[${requestId}] Global error handler caught:`, {
      url: c.req.url,
      method: c.req.method,
      userAgent: c.req.header("user-agent"),
      ip: c.req.header("cf-connecting-ip") || "unknown",
      duration: `${duration}ms`,
      error: sshxError.toJSON(),
    });

    // 根据错误类型添加适当的响应头
    c.header("X-Request-ID", requestId);
    c.header("X-Error-Code", sshxError.code);

    return c.json(
      {
        ...sshxError.toJSON(),
        requestId,
        timestamp: new Date().toISOString(),
      },
      sshxError.statusCode as any,
    );
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

// 获取会话列表端点（优化版）
app.get("/sessions", async (c) => {
  try {
    // 使用优化的查询和分页
    const page = parseInt(c.req.query("page") || "1");
    const limit = Math.min(parseInt(c.req.query("limit") || "50"), 100); // 最大100条
    const offset = (page - 1) * limit;

    // 获取总数
    const countResult = await c.env.DB.prepare(
      "SELECT COUNT(*) as total FROM sessions",
    ).first();
    const total = countResult?.total || 0;

    // 获取分页数据
    const sessions = await c.env.DB.prepare(
      `
      SELECT s.name, s.created_at,
             s.write_password_hash IS NOT NULL as has_write_password,
             COUNT(u.id) as user_count,
             COUNT(sh.id) as shell_count
      FROM sessions s
      LEFT JOIN users u ON s.id = u.session_id
      LEFT JOIN shells sh ON s.id = sh.session_id
      GROUP BY s.id, s.name, s.created_at
      ORDER BY s.created_at DESC
      LIMIT ? OFFSET ?
    `,
    )
      .bind(limit, offset)
      .all();

    return c.json({
      sessions: sessions.results.map((session: any) => ({
        name: session.name,
        created_at: session.created_at,
        has_write_password: session.has_write_password === 1,
        user_count: session.user_count || 0,
        shell_count: session.shell_count || 0,
      })),
      pagination: {
        current_page: page,
        per_page: limit,
        total_pages: Math.ceil(total / limit),
        total_items: total,
      },
    });
  } catch (error) {
    console.error("Error fetching sessions:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// 获取特定会话信息端点（优化版）
app.get("/sessions/:name", async (c) => {
  try {
    const { name } = c.req.param();

    // 使用单一查询获取会话信息（避免N+1查询）
    const sessionInfo = await c.env.DB.prepare(
      `
      SELECT
        s.name, s.created_at,
        s.write_password_hash IS NOT NULL as has_write_password,
        COUNT(DISTINCT u.id) as user_count,
        COUNT(DISTINCT sh.id) as shell_count,
        COALESCE(SUM(CASE WHEN u.can_write = 1 THEN 1 ELSE 0 END), 0) as write_users_count
      FROM sessions s
      LEFT JOIN users u ON s.id = u.session_id
      LEFT JOIN shells sh ON s.id = sh.session_id
      WHERE s.name = ?
      GROUP BY s.id, s.name, s.created_at
    `,
    )
      .bind(name)
      .first();

    if (!sessionInfo) {
      return c.json({ error: "Session not found" }, 404);
    }

    // 获取连接统计
    let connectionCount = 0;
    try {
      const connections = await c.env.SESSIONS.get(`connections:${name}`);
      connectionCount = connections
        ? Object.keys(JSON.parse(connections)).length
        : 0;
    } catch (error) {
      console.warn(
        `Error getting connection count for session ${name}:`,
        error,
      );
    }

    // 获取终端数据统计（使用视图）
    let terminalStats = { total_chunks: 0, total_size: 0 };
    try {
      const statsResult = await c.env.DB.prepare(
        `
        SELECT COUNT(*) as total_chunks, SUM(LENGTH(td.data)) as total_size
        FROM terminal_data td
        WHERE td.shell_id IN (SELECT id FROM shells WHERE session_id = ?)
      `,
      )
        .bind(sessionInfo.id)
        .first();

      terminalStats = {
        total_chunks: statsResult?.total_chunks || 0,
        total_size: statsResult?.total_size || 0,
      };
    } catch (error) {
      console.warn(`Error getting terminal stats for session ${name}:`, error);
    }

    // 获取最近的聊天消息
    let recentMessages = [];
    try {
      const messagesResult = await c.env.DB.prepare(
        `
        SELECT u.name, cm.message, cm.created_at
        FROM chat_messages cm
        JOIN users u ON cm.user_id = u.id
        WHERE cm.session_id = ?
        ORDER BY cm.created_at DESC
        LIMIT 5
      `,
      )
        .bind(sessionInfo.id)
        .all();

      recentMessages = messagesResult.results || [];
    } catch (error) {
      console.warn(`Error getting recent messages for session ${name}:`, error);
    }

    return c.json({
      name: sessionInfo.name,
      created_at: sessionInfo.created_at,
      has_write_password: sessionInfo.has_write_password === 1,
      connection_count: connectionCount,
      user_count: sessionInfo.user_count || 0,
      shell_count: sessionInfo.shell_count || 0,
      write_users_count: sessionInfo.write_users_count || 0,
      terminal_stats: terminalStats,
      recent_messages: recentMessages,
      last_activity: Math.max(
        sessionInfo.created_at,
        recentMessages.length > 0 ? recentMessages[0].created_at : 0,
      ),
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
// 使用 WeakMap 来避免内存泄漏
const activeConnections = new Map<string, Set<WebSocket>>();

// 存储终端订阅信息
const shellSubscriptions = new Map<string, Set<WebSocket>>();

// 连接统计和限制
const MAX_CONNECTIONS_PER_SESSION = 100;
const MAX_TOTAL_CONNECTIONS = 1000;
const CONNECTION_TIMEOUT = 5 * 60 * 1000; // 5分钟

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

        // 检查连接限制
        if (activeConnections.size >= MAX_TOTAL_CONNECTIONS) {
          console.warn(
            "Maximum total connections reached, rejecting connection",
          );
          ws.close(1008, "Server overloaded");
          return;
        }

        const sessionConnections = activeConnections.get(name) || new Set();
        if (sessionConnections.size >= MAX_CONNECTIONS_PER_SESSION) {
          console.warn(`Maximum connections reached for session: ${name}`);
          ws.close(1008, "Session full");
          return;
        }

        // 生成连接 ID
        connectionId = generateConnectionId();
        (ws.raw as any).connectionId = connectionId;
        (ws.raw as any).sessionName = name;
        (ws.raw as any).connectionTime = Date.now();
        (ws.raw as any).lastHeartbeat = Date.now();

        // 使用 Set 来避免重复连接
        if (!activeConnections.has(name)) {
          activeConnections.set(name, new Set());
        }
        activeConnections.get(name)!.add(ws.raw as WebSocket);

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

        // 发送连接成功消息
        ws.send(
          JSON.stringify({
            type: "ConnectionEstablished",
            connectionId,
            timestamp: Date.now(),
          }),
        );
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

        // 从活动连接中移除（使用 Set 优化）
        if (activeConnections.has(name)) {
          const connections = activeConnections.get(name)!;
          connections.delete(ws.raw as WebSocket);

          // 如果会话没有连接了，清理内存
          if (connections.size === 0) {
            activeConnections.delete(name);
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

              // 如果没有连接了，删除整个 KV 键
              if (Object.keys(connections).length === 0) {
                c.env.SESSIONS.delete(kvKey);
              } else {
                c.env.SESSIONS.put(kvKey, JSON.stringify(connections));
              }
            }
          } catch (error) {
            console.error("Error removing connection from KV:", error);
          }
        }

        // 清理用户连接
        if (userId && sessionId) {
          removeUser(c, sessionId, userId);
        }

        // 记录连接统计
        console.log(
          `Active connections: ${Array.from(activeConnections.values()).reduce((sum, set) => sum + set.size, 0)}`,
        );
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

  // 获取会话元数据（使用重试机制）
  const sessionResult: {
    id: string;
    encrypted_zeros: number[];
    write_password_hash: number[] | null;
  } | null = await withRetry(
    async () => {
      return (await db
        .prepare(
          "SELECT id, encrypted_zeros, write_password_hash FROM sessions WHERE name = ?",
        )
        .bind(sessionName)
        .first()) as any;
    },
    3,
    500,
    "session authentication",
  );

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
  originalSize: number;
  compressedSize: number;
  timeTaken: number;
}

// 压缩算法类型
const COMPRESSION_ALGORITHMS = ["none", "deflate", "gzip"] as const;
type CompressionAlgorithm = (typeof COMPRESSION_ALGORITHMS)[number];

// 压缩配置
interface CompressionConfig {
  minSizeForCompression: number; // 最小压缩大小
  thresholdRatio: number; // 压缩率阈值
  maxCompressionTime: number; // 最大压缩时间
  preferredAlgorithm: CompressionAlgorithm;
}

const DEFAULT_COMPRESSION_CONFIG: CompressionConfig = {
  minSizeForCompression: 128, // 小于128字节不压缩
  thresholdRatio: 0.9, // 压缩率必须小于90%
  maxCompressionTime: 50, // 最大50ms
  preferredAlgorithm: "deflate",
};

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

// 向会话中的所有客户端广播消息（优化版）
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
  let successCount = 0;
  let failureCount = 0;

  // 向所有连接广播消息
  if (activeConnections.has(sessionName)) {
    const connections = activeConnections.get(sessionName)!;
    const deadConnections: WebSocket[] = [];

    // 批量发送消息
    for (const ws of connections) {
      try {
        ws.send(messageStr);
        successCount++;
      } catch (error) {
        console.error("Error sending message to client:", error);
        failureCount++;
        deadConnections.push(ws);
      }
    }

    // 清理无效连接
    for (const deadWs of deadConnections) {
      connections.delete(deadWs);
    }

    // 如果没有连接了，清理内存
    if (connections.size === 0) {
      activeConnections.delete(sessionName);
    }
  }

  // 记录广播统计
  if (failureCount > 0) {
    console.log(
      `Broadcast stats for ${sessionName}: ${successCount} success, ${failureCount} failed`,
    );
  }

  // 仅在必要时存储消息到 KV（减少 KV 调用）
  if (message.type !== "Chunks" && message.type !== "Pong") {
    try {
      const kvKey = `broadcast:${sessionName}:${Date.now()}`;
      await c.env.SESSIONS.put(kvKey, messageStr, { expirationTtl: 30 }); // 30秒过期
    } catch (error) {
      console.error("Error storing broadcast message in KV:", error);
    }
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

// 生成请求 ID
function generateRequestId(): string {
  return (
    "req_" + Date.now().toString(36) + Math.random().toString(36).substr(2, 6)
  );
}

// 数据库重试机制
async function withRetry<T>(
  operation: () => Promise<T>,
  maxRetries: number = 3,
  delayMs: number = 1000,
  context: string = "database operation",
): Promise<T> {
  let lastError: Error;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;

      // 如果是网络相关错误，则重试
      if (
        attempt < maxRetries &&
        error instanceof Error &&
        (error.message.includes("network") ||
          error.message.includes("connection") ||
          error.message.includes("timeout") ||
          error.message.includes("ECONNRESET"))
      ) {
        const delay = delayMs * attempt; // 指数退避
        console.warn(
          `[${context}] Attempt ${attempt} failed, retrying in ${delay}ms...`,
          error.message,
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }

      // 非重试错误或达到最大重试次数
      throw error;
    }
  }

  throw lastError!;
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

// 数据压缩工具函数（增强版）
async function tryCompressData(
  data: Uint8Array,
  config: CompressionConfig = DEFAULT_COMPRESSION_CONFIG,
): Promise<CompressionResult> {
  const startTime = performance.now();
  const originalSize = data.length;

  // 小数据跳过压缩
  if (originalSize < config.minSizeForCompression) {
    return {
      compressed: data,
      compressionRatio: 1.0,
      algorithm: "none",
      originalSize,
      compressedSize: originalSize,
      timeTaken: 0,
    };
  }

  // 尝试多种压缩算法
  const results: CompressionResult[] = [];

  for (const algorithm of COMPRESSION_ALGORITHMS) {
    if (algorithm === "none") continue;

    try {
      const result = await compressWithAlgorithm(data, algorithm);
      results.push(result);

      // 如果压缩时间过长，停止尝试
      if (result.timeTaken > config.maxCompressionTime) {
        console.warn(
          `Compression with ${algorithm} took too long: ${result.timeTaken}ms`,
        );
        break;
      }
    } catch (error) {
      console.warn(`Compression with ${algorithm} failed:`, error);
    }
  }

  // 选择最佳压缩结果
  let bestResult: CompressionResult = {
    compressed: data,
    compressionRatio: 1.0,
    algorithm: "none",
    originalSize,
    compressedSize: originalSize,
    timeTaken: performance.now() - startTime,
  };

  for (const result of results) {
    if (
      result.compressionRatio < config.thresholdRatio &&
      result.compressionRatio < bestResult.compressionRatio
    ) {
      bestResult = result;
    }
  }

  // 记录压缩统计
  if (bestResult.algorithm !== "none") {
    console.log(
      `Compressed ${originalSize} -> ${bestResult.compressedSize} bytes ` +
        `(${bestResult.compressionRatio.toFixed(2)}x ratio, ${bestResult.timeTaken.toFixed(2)}ms, ${bestResult.algorithm})`,
    );
  }

  return bestResult;
}

// 使用特定算法压缩
async function compressWithAlgorithm(
  data: Uint8Array,
  algorithm: CompressionAlgorithm,
): Promise<CompressionResult> {
  const startTime = performance.now();

  if (algorithm === "none") {
    return {
      compressed: data,
      compressionRatio: 1.0,
      algorithm: "none",
      originalSize: data.length,
      compressedSize: data.length,
      timeTaken: 0,
    };
  }

  try {
    const stream = new Response(data).body;
    if (!stream) throw new Error("Failed to create stream");

    const compressedStream = stream.pipeThrough(
      new CompressionStream(algorithm),
    );
    const compressedResponse = new Response(compressedStream);
    const compressedArrayBuffer = await compressedResponse.arrayBuffer();
    const compressed = new Uint8Array(compressedArrayBuffer);

    const timeTaken = performance.now() - startTime;
    const compressionRatio = compressed.length / data.length;

    return {
      compressed,
      compressionRatio,
      algorithm,
      originalSize: data.length,
      compressedSize: compressed.length,
      timeTaken,
    };
  } catch (error) {
    throw new Error(`Failed to compress with ${algorithm}: ${error}`);
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
    const startTime = performance.now();
    const stream = new Response(data).body;
    if (!stream) throw new Error("Failed to create stream");

    const decompressedStream = stream.pipeThrough(
      new DecompressionStream(algorithm as CompressionFormat),
    );
    const decompressedResponse = new Response(decompressedStream);
    const decompressedArrayBuffer = await decompressedResponse.arrayBuffer();
    const decompressed = new Uint8Array(decompressedArrayBuffer);

    const decompressionTime = performance.now() - startTime;

    // 记录解压统计
    if (decompressionTime > 10) {
      console.warn(
        `Slow decompression: ${decompressionTime.toFixed(2)}ms for ${data.length} bytes with ${algorithm}`,
      );
    }

    return decompressed;
  } catch (error) {
    console.error("Decompression failed:", error);
    throw new Error(`Failed to decompress data with algorithm: ${algorithm}`);
  }
}

// 数据去重和增量压缩
class DataDeduplicator {
  private chunkCache = new Map<string, Uint8Array>();
  private maxSize = 1000; // 最大缓存块数

  // 计算数据的哈希值
  private hashData(data: Uint8Array): string {
    // 简单的哈希算法，生产环境建议使用更安全的算法
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      hash = (hash << 5) - hash + data[i];
      hash = hash & hash; // 转换为32位整数
    }
    return hash.toString(36);
  }

  // 尝试去重压缩
  async deduplicateCompress(data: Uint8Array): Promise<{
    compressed: Uint8Array;
    isDuplicate: boolean;
    hash: string;
    compressionRatio: number;
  }> {
    const hash = this.hashData(data);

    // 检查是否已经存在相同的数据
    if (this.chunkCache.has(hash)) {
      return {
        compressed: new Uint8Array(), // 空数据表示重复
        isDuplicate: true,
        hash,
        compressionRatio: 0.01, // 99% 压缩率
      };
    }

    // 压缩数据
    const compressionResult = await tryCompressData(data);

    // 缓存原始数据
    if (this.chunkCache.size < this.maxSize) {
      this.chunkCache.set(hash, data);
    } else {
      // 清理最旧的缓存
      const oldestKey = this.chunkCache.keys().next().value;
      this.chunkCache.delete(oldestKey);
      this.chunkCache.set(hash, data);
    }

    return {
      compressed: compressionResult.compressed,
      isDuplicate: false,
      hash,
      compressionRatio: compressionResult.compressionRatio,
    };
  }

  // 解压和去重复原
  async deduplicateDecompress(
    compressed: Uint8Array,
    hash: string,
    isDuplicate: boolean,
    algorithm: string,
  ): Promise<Uint8Array> {
    if (isDuplicate) {
      // 从缓存中获取原始数据
      const original = this.chunkCache.get(hash);
      if (!original) {
        throw new Error(`Duplicate data not found in cache: ${hash}`);
      }
      return original;
    }

    // 正常解压
    return decompressData(compressed, algorithm);
  }

  // 清理缓存
  cleanup(): void {
    this.chunkCache.clear();
  }
}

// 全局去重器实例
const dataDeduplicator = new DataDeduplicator();

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

// 清理过期的会话和连接（增强版）
async function cleanupExpiredSessions(c: any): Promise<CleanupStats> {
  const startTime = Date.now();
  const now = Date.now();
  const connectionExpirationTime = 5 * 60 * 1000; // 5分钟
  const sessionExpirationTime = 30 * 60 * 1000; // 30分钟

  const stats: CleanupStats = {
    connectionsCleaned: 0,
    sessionsCleaned: 0,
    terminalDataCleaned: 0,
    chatMessagesCleaned: 0,
    memoryFreed: 0,
    timeTaken: 0,
  };

  try {
    // 1. 清理过期连接
    const connectionStats = await cleanupExpiredConnections(
      c,
      now,
      connectionExpirationTime,
    );
    stats.connectionsCleaned = connectionStats.connectionsRemoved;

    // 2. 清理没有连接的过期会话
    const sessionStats = await cleanupInactiveSessions(
      c,
      now,
      sessionExpirationTime,
    );
    stats.sessionsCleaned = sessionStats.sessionsRemoved;
    stats.terminalDataCleaned = sessionStats.terminalDataRemoved;
    stats.chatMessagesCleaned = sessionStats.chatMessagesRemoved;

    // 3. 清理内存中的资源
    const memoryStats = cleanupMemoryResources();
    stats.memoryFreed = memoryStats;

    // 4. 清理过期的压缩缓存
    dataDeduplicator.cleanup();

    stats.timeTaken = Date.now() - startTime;

    console.log(`Cleanup completed in ${stats.timeTaken}ms:`, stats);

    // 5. 记录统计信息到 KV
    try {
      await c.env.SESSIONS.put(
        `cleanup_stats:${Date.now()}`,
        JSON.stringify({
          ...stats,
          timestamp: now,
        }),
        { expirationTtl: 3600 }, // 1小时过期
      );
    } catch (error) {
      console.warn("Failed to store cleanup stats:", error);
    }

    return stats;
  } catch (error) {
    console.error("Error during cleanup:", error);
    stats.timeTaken = Date.now() - startTime;
    return stats;
  }
}

// 清理过期连接
async function cleanupExpiredConnections(
  c: any,
  now: number,
  expirationTime: number,
): Promise<{
  connectionsRemoved: number;
  sessionsToClean: string[];
}> {
  const connectionsRemoved = 0;
  const sessionsToClean: string[] = [];

  try {
    const list: { keys: { name: string }[] } = await c.env.SESSIONS.list({
      prefix: "connections:",
    });

    for (const key of list.keys) {
      const sessionName = key.name.replace("connections:", "");
      const connectionsStr = await c.env.SESSIONS.get(key.name);

      if (connectionsStr) {
        try {
          const connections: Record<string, { timestamp: number }> =
            JSON.parse(connectionsStr);
          let hasActiveConnections = false;
          let removedCount = 0;

          // 检查连接是否过期
          for (const [connId, connInfo] of Object.entries(connections)) {
            if (now - connInfo.timestamp > expirationTime) {
              delete connections[connId];
              removedCount++;
            } else {
              hasActiveConnections = true;
            }
          }

          if (!hasActiveConnections) {
            sessionsToClean.push(sessionName);
            await c.env.SESSIONS.delete(key.name);
          } else if (removedCount > 0) {
            await c.env.SESSIONS.put(key.name, JSON.stringify(connections));
          }
        } catch (error) {
          console.error(
            `Error cleaning connections for ${sessionName}:`,
            error,
          );
        }
      }
    }
  } catch (error) {
    console.error("Error listing connections:", error);
  }

  return { connectionsRemoved, sessionsToClean };
}

// 清理非活动会话
async function cleanupInactiveSessions(
  c: any,
  now: number,
  expirationTime: number,
): Promise<{
  sessionsRemoved: number;
  terminalDataRemoved: number;
  chatMessagesRemoved: number;
}> {
  let sessionsRemoved = 0;
  let terminalDataRemoved = 0;
  let chatMessagesRemoved = 0;

  try {
    // 获取所有过期会话
    const expiredSessions = await c.env.DB.prepare(
      `
      SELECT id, name FROM sessions
      WHERE created_at < ?
      AND name NOT IN (
        SELECT REPLACE(name, 'connections:', '')
        FROM (SELECT name FROM (SELECT name FROM kv_keys WHERE name LIKE 'connections:%'))
      )
    `,
    )
      .bind(Math.floor((now - expirationTime) / 1000))
      .all();

    for (const session of expiredSessions.results) {
      try {
        // 删除聊天消息
        const chatResult = await c.env.DB.prepare(
          "DELETE FROM chat_messages WHERE session_id = ?",
        )
          .bind(session.id)
          .run();
        chatMessagesRemoved += chatResult.changes || 0;

        // 删除终端数据
        const terminalResult = await c.env.DB.prepare(
          `
          DELETE FROM terminal_data
          WHERE shell_id IN (SELECT id FROM shells WHERE session_id = ?)
        `,
        )
          .bind(session.id)
          .run();
        terminalDataRemoved += terminalResult.changes || 0;

        // 删除终端
        await c.env.DB.prepare("DELETE FROM shells WHERE session_id = ?")
          .bind(session.id)
          .run();

        // 删除用户
        await c.env.DB.prepare("DELETE FROM users WHERE session_id = ?")
          .bind(session.id)
          .run();

        // 删除会话
        await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?")
          .bind(session.id)
          .run();

        sessionsRemoved++;
        console.log(`Cleaned up expired session: ${session.name}`);
      } catch (error) {
        console.error(`Error cleaning session ${session.name}:`, error);
      }
    }
  } catch (error) {
    console.error("Error finding expired sessions:", error);
  }

  return { sessionsRemoved, terminalDataRemoved, chatMessagesRemoved };
}

// 清理内存资源
function cleanupMemoryResources(): number {
  let freedMemory = 0;

  try {
    // 清理延迟统计
    const beforeStats = userLatencyStats.size;
    cleanupLatencyStats();
    const afterStats = userLatencyStats.size;
    freedMemory += (beforeStats - afterStats) * 1000; // 估算

    // 清理无效的 WebSocket 连接
    for (const [sessionName, connections] of activeConnections.entries()) {
      const deadConnections: WebSocket[] = [];

      for (const ws of connections) {
        try {
          // 测试连接是否仍然有效
          if (
            ws.readyState === WebSocket.CLOSED ||
            ws.readyState === WebSocket.CLOSING
          ) {
            deadConnections.push(ws);
          }
        } catch (error) {
          deadConnections.push(ws);
        }
      }

      // 移除无效连接
      for (const deadWs of deadConnections) {
        connections.delete(deadWs);
        freedMemory += 500; // 估算每个连接500字节
      }

      // 如果没有连接了，清理会话
      if (connections.size === 0) {
        activeConnections.delete(sessionName);
      }
    }

    // 清理无效的订阅
    for (const [shellId, subscribers] of shellSubscriptions.entries()) {
      const deadSubscribers: WebSocket[] = [];

      for (const ws of subscribers) {
        try {
          if (
            ws.readyState === WebSocket.CLOSED ||
            ws.readyState === WebSocket.CLOSING
          ) {
            deadSubscribers.push(ws);
          }
        } catch (error) {
          deadSubscribers.push(ws);
        }
      }

      for (const deadWs of deadSubscribers) {
        subscribers.delete(deadWs);
        freedMemory += 100; // 估算每个订阅100字节
      }

      if (subscribers.size === 0) {
        shellSubscriptions.delete(shellId);
      }
    }
  } catch (error) {
    console.error("Error cleaning memory resources:", error);
  }

  return freedMemory;
}

// 清理统计接口
interface CleanupStats {
  connectionsCleaned: number;
  sessionsCleaned: number;
  terminalDataCleaned: number;
  chatMessagesCleaned: number;
  memoryFreed: number;
  timeTaken: number;
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

// 性能监控和日志系统
class PerformanceMonitor {
  private metrics = new Map<string, number[]>();
  private timers = new Map<string, number>();
  private counters = new Map<string, number>();

  // 记录指标
  recordMetric(name: string, value: number): void {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    const values = this.metrics.get(name)!;
    values.push(value);

    // 保持最近100个值
    if (values.length > 100) {
      values.shift();
    }
  }

  // 开始计时
  startTimer(name: string): void {
    this.timers.set(name, Date.now());
  }

  // 结束计时并记录
  endTimer(name: string): number {
    const startTime = this.timers.get(name);
    if (!startTime) return 0;

    const duration = Date.now() - startTime;
    this.recordMetric(`${name}_duration`, duration);
    this.timers.delete(name);
    return duration;
  }

  // 增加计数器
  incrementCounter(name: string, value: number = 1): void {
    const current = this.counters.get(name) || 0;
    this.counters.set(name, current + value);
  }

  // 获取统计信息
  getStats(name: string): {
    min: number;
    max: number;
    avg: number;
    count: number;
    p95: number;
  } | null {
    const values = this.metrics.get(name);
    if (!values || values.length === 0) return null;

    const sorted = [...values].sort((a, b) => a - b);
    const p95Index = Math.floor(sorted.length * 0.95);

    return {
      min: sorted[0],
      max: sorted[sorted.length - 1],
      avg: sorted.reduce((sum, val) => sum + val, 0) / sorted.length,
      count: sorted.length,
      p95: sorted[p95Index],
    };
  }

  // 获取所有指标
  getAllMetrics(): Record<string, any> {
    const result: Record<string, any> = {};

    // 指标统计
    for (const [name, _] of this.metrics) {
      result[name] = this.getStats(name);
    }

    // 计数器
    for (const [name, value] of this.counters) {
      result[`counter_${name}`] = value;
    }

    // 系统指标
    result["active_connections"] = Array.from(
      activeConnections.values(),
    ).reduce((sum, set) => sum + set.size, 0);
    result["active_sessions"] = activeConnections.size;
    result["shell_subscriptions"] = shellSubscriptions.size;
    result["memory_usage"] = {
      latency_stats: userLatencyStats.size,
      dedupe_cache: (dataDeduplicator as any).chunkCache?.size || 0,
      rate_limits: rateLimits.size,
    };

    return result;
  }

  // 重置指标
  reset(): void {
    this.metrics.clear();
    this.timers.clear();
    this.counters.clear();
  }
}

// 全局性能监控实例
const performanceMonitor = new PerformanceMonitor();

// 增强的日志记录器
class Logger {
  private context: string;

  constructor(context: string) {
    this.context = context;
  }

  private formatMessage(level: string, message: string, data?: any): string {
    const timestamp = new Date().toISOString();
    const structuredLog = {
      timestamp,
      level,
      context: this.context,
      message,
      ...(data && { data }),
    };
    return JSON.stringify(structuredLog);
  }

  info(message: string, data?: any): void {
    console.log(this.formatMessage("INFO", message, data));
  }

  warn(message: string, data?: any): void {
    console.warn(this.formatMessage("WARN", message, data));
  }

  error(message: string, data?: any): void {
    console.error(this.formatMessage("ERROR", message, data));
  }

  debug(message: string, data?: any): void {
    if (process.env.NODE_ENV === "development") {
      console.debug(this.formatMessage("DEBUG", message, data));
    }
  }

  // 性能日志
  performance(operation: string, duration: number, metadata?: any): void {
    performanceMonitor.recordMetric(`perf_${operation}`, duration);
    this.info(`Performance: ${operation}`, {
      duration,
      unit: "ms",
      ...metadata,
    });
  }
}

// 创建上下文日志记录器
function createLogger(context: string): Logger {
  return new Logger(context);
}

// 健康检查端点（增强版）
app.get("/health", async (c) => {
  const startTime = Date.now();
  const logger = createLogger("health");

  try {
    // 检查数据库连接
    const dbCheckStart = Date.now();
    await c.env.DB.prepare("SELECT 1").first();
    const dbLatency = Date.now() - dbCheckStart;

    // 检查 KV 存储
    const kvCheckStart = Date.now();
    await c.env.SESSIONS.put("health_check", "ok", { expirationTtl: 10 });
    await c.env.SESSIONS.get("health_check");
    const kvLatency = Date.now() - kvCheckStart;

    // 获取系统指标
    const metrics = performanceMonitor.getAllMetrics();

    // 检查内存使用
    const memoryUsage = {
      activeConnections: metrics.active_connections,
      activeSessions: metrics.active_sessions,
      shellSubscriptions: metrics.shell_subscriptions,
      rateLimits: rateLimits.size,
      latencyStats: userLatencyStats.size,
    };

    // 计算总体健康状态
    const isHealthy = dbLatency < 1000 && kvLatency < 1000;
    const totalDuration = Date.now() - startTime;

    logger.performance("health_check", totalDuration, {
      db_latency: dbLatency,
      kv_latency: kvLatency,
      healthy: isHealthy,
    });

    const response = {
      status: isHealthy ? "healthy" : "degraded",
      timestamp: new Date().toISOString(),
      uptime: process.uptime ? process.uptime() : 0,
      checks: {
        database: {
          status: dbLatency < 1000 ? "healthy" : "slow",
          latency: dbLatency,
        },
        kv_storage: {
          status: kvLatency < 1000 ? "healthy" : "slow",
          latency: kvLatency,
        },
      },
      metrics: {
        connections: memoryUsage.activeConnections,
        sessions: memoryUsage.activeSessions,
        subscriptions: memoryUsage.shellSubscriptions,
        rate_limits: memoryUsage.rateLimits,
      },
      performance: {
        request_duration: totalDuration,
        memory_usage: memoryUsage,
      },
    };

    return c.json(response, isHealthy ? 200 : 503);
  } catch (error) {
    logger.error("Health check failed", { error: error.message });
    return c.json(
      {
        status: "unhealthy",
        error: error.message,
        timestamp: new Date().toISOString(),
      },
      503,
    );
  }
});

// 指标端点
app.get("/metrics", async (c) => {
  try {
    const metrics = performanceMonitor.getAllMetrics();

    // 添加额外的系统指标
    const systemMetrics = {
      ...metrics,
      system: {
        uptime: process.uptime ? process.uptime() : 0,
        memory_usage: process.memoryUsage ? process.memoryUsage() : null,
        cpu_usage: process.cpuUsage ? process.cpuUsage() : null,
      },
      timestamp: new Date().toISOString(),
    };

    return c.json(systemMetrics);
  } catch (error) {
    console.error("Error getting metrics:", error);
    return c.json({ error: "Failed to get metrics" }, 500);
  }
});

// 重置指标端点（管理员）
app.post("/admin/metrics/reset", async (c) => {
  try {
    performanceMonitor.reset();
    return c.json({ success: true, message: "Metrics reset" });
  } catch (error) {
    return c.json({ error: "Failed to reset metrics" }, 500);
  }
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

      // 创建关键索引（优化版）
      await db.exec(`
        -- 会话相关索引
        CREATE INDEX IF NOT EXISTS idx_sessions_name ON sessions(name);
        CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
        CREATE INDEX IF NOT EXISTS idx_sessions_created_at_desc ON sessions(created_at DESC);

        -- 用户相关索引
        CREATE INDEX IF NOT EXISTS idx_users_session_id ON users(session_id);
        CREATE INDEX IF NOT EXISTS idx_users_session_can_write ON users(session_id, can_write);
        CREATE INDEX IF NOT EXISTS idx_users_focus_shell_id ON users(focus_shell_id);
        CREATE INDEX IF NOT EXISTS idx_users_cursor_position ON users(cursor_x, cursor_y);
        CREATE INDEX IF NOT EXISTS idx_users_name_search ON users(name COLLATE NOCASE);

        -- 终端相关索引
        CREATE INDEX IF NOT EXISTS idx_shells_session_id ON shells(session_id);
        CREATE INDEX IF NOT EXISTS idx_shells_position ON shells(session_id, x, y);
        CREATE INDEX IF NOT EXISTS idx_shells_size ON shells(rows, cols);

        -- 终端数据索引（最重要的性能优化）
        CREATE INDEX IF NOT EXISTS idx_terminal_data_shell_id ON terminal_data(shell_id);
        CREATE INDEX IF NOT EXISTS idx_terminal_data_shell_sequence ON terminal_data(shell_id, sequence_number);
        CREATE INDEX IF NOT EXISTS idx_terminal_data_sequence ON terminal_data(sequence_number);
        CREATE INDEX IF NOT EXISTS idx_terminal_data_compression ON terminal_data(compression_algorithm);
        CREATE INDEX IF NOT EXISTS idx_terminal_data_created_at ON terminal_data(created_at);
        CREATE INDEX IF NOT EXISTS idx_terminal_data_shell_sequence_composite ON terminal_data(shell_id, sequence_number, created_at);

        -- 聊天消息索引
        CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);
        CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at);
        CREATE INDEX IF NOT EXISTS idx_chat_messages_session_created ON chat_messages(session_id, created_at DESC);

        -- 复合索引用于常见查询
        CREATE INDEX IF NOT EXISTS idx_sessions_composite ON sessions(name, created_at);
        CREATE INDEX IF NOT EXISTS idx_users_composite ON users(session_id, can_write, created_at);
      `);

      --创建用于清理和统计的视图;
      await db.exec(`
        -- 活跃会话视图
        CREATE VIEW IF NOT EXISTS active_sessions AS
        SELECT s.name, s.created_at, COUNT(u.id) as user_count, COUNT(sh.id) as shell_count
        FROM sessions s
        LEFT JOIN users u ON s.id = u.session_id
        LEFT JOIN shells sh ON s.id = sh.session_id
        GROUP BY s.id, s.name, s.created_at;

        -- 终端数据统计视图
        CREATE VIEW IF NOT EXISTS terminal_data_stats AS
        SELECT
          shell_id,
          COUNT(*) as chunk_count,
          SUM(LENGTH(data)) as total_size,
          SUM(COALESCE(original_size, LENGTH(data))) as original_size,
          MIN(sequence_number) as min_seq,
          MAX(sequence_number) as max_seq,
          AVG(COALESCE(compression_ratio, 1.0)) as avg_compression_ratio
        FROM terminal_data
        GROUP BY shell_id;
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
