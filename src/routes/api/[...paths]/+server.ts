import type { RequestHandler } from "@sveltejs/kit";
import { Hono } from "hono";
import { upgradeWebSocket } from "hono/cloudflare-workers";
import { cors } from "hono/cors";

// 定义绑定类型
type Bindings = {
  DB: D1Database;
  SESSIONS: KVNamespace;
  ENCRYPTION_KEY: string;
};

// 简单的错误类
class SshxError extends Error {
  constructor(
    public message: string,
    public statusCode: number = 500,
    public code: string = "UNKNOWN_ERROR",
  ) {
    super(message);
    this.name = "SshxError";
  }
}

// 会话数据结构
interface SessionData {
  name: string;
  owner: string;
  createdAt: number;
  lastAccessed: number;
  encryptedZeros: string;
  writePasswordHash?: string;
  shells: Map<string, ShellData>;
  users: Map<string, UserData>;
}

interface ShellData {
  id: string;
  x: number;
  y: number;
  rows: number;
  cols: number;
  data: string[];
  seqnum: number;
  closed: boolean;
}

interface UserData {
  id: string;
  name: string;
  cursor?: [number, number];
  focus?: string;
  canWrite: boolean;
}

// WebSocket 消息类型
interface WsMessage {
  type: string;
  data?: any;
}

interface ClientMessage {
  type:
    | "authenticate"
    | "setName"
    | "setCursor"
    | "setFocus"
    | "create"
    | "close"
    | "move"
    | "data"
    | "subscribe"
    | "chat"
    | "ping";
  data?: any;
}

interface ServerMessage {
  type:
    | "hello"
    | "invalidAuth"
    | "users"
    | "userDiff"
    | "shells"
    | "chunks"
    | "hear"
    | "shellLatency"
    | "pong"
    | "error";
  data?: any;
}

// 简单的性能监控
class SimpleMonitor {
  private startTime = Date.now();
  private requestCount = 0;

  recordRequest() {
    this.requestCount++;
  }

  getMetrics() {
    return {
      uptime: Date.now() - this.startTime,
      requests: this.requestCount,
    };
  }
}

// 简单的压缩工具
async function compressData(data: string): Promise<string> {
  if (data.length < 1000) return data;

  try {
    // 使用简单的 base64 编码替代复杂压缩
    return btoa(data);
  } catch {
    return data;
  }
}

async function decompressData(data: string): Promise<string> {
  try {
    return atob(data);
  } catch {
    return data;
  }
}

// 会话管理器
class SessionManager {
  private sessions = new Map<string, SessionData>();
  private connections = new Set<WebSocket>();
  private monitor = new SimpleMonitor();

  constructor(private bindings: Bindings) {}

  async createSession(
    name: string,
    owner: string,
    encryptedZeros: string,
    writePasswordHash?: string,
  ): Promise<SessionData> {
    if (this.sessions.has(name)) {
      throw new SshxError("Session already exists", 409, "SESSION_EXISTS");
    }

    const session: SessionData = {
      name,
      owner,
      createdAt: Date.now(),
      lastAccessed: Date.now(),
      encryptedZeros,
      writePasswordHash,
      shells: new Map(),
      users: new Map(),
    };

    this.sessions.set(name, session);
    await this.saveSession(name);

    return session;
  }

  async getSession(name: string): Promise<SessionData | null> {
    // 先检查内存
    let session = this.sessions.get(name);
    if (session) {
      session.lastAccessed = Date.now();
      return session;
    }

    // 从数据库加载
    try {
      const result = await this.bindings.DB.prepare(
        "SELECT * FROM sessions WHERE name = ?",
      )
        .bind(name)
        .first();

      if (!result) return null;

      session = {
        name: result.name,
        owner: result.owner,
        createdAt: result.created_at,
        lastAccessed: result.last_accessed,
        encryptedZeros: result.encrypted_zeros,
        writePasswordHash: result.write_password_hash,
        shells: new Map(),
        users: new Map(),
      };

      this.sessions.set(name, session);
      return session;
    } catch (error) {
      console.error("Error loading session:", error);
      return null;
    }
  }

  async saveSession(name: string): Promise<void> {
    const session = this.sessions.get(name);
    if (!session) return;

    try {
      await this.bindings.DB.prepare(
        `
          INSERT OR REPLACE INTO sessions
          (name, owner, created_at, last_accessed, encrypted_zeros, write_password_hash)
          VALUES (?, ?, ?, ?, ?, ?)
        `,
      )
        .bind(
          session.name,
          session.owner,
          session.createdAt,
          session.lastAccessed,
          session.encryptedZeros,
          session.writePasswordHash || null,
        )
        .run();
    } catch (error) {
      console.error("Error saving session:", error);
    }
  }

  addConnection(ws: WebSocket) {
    this.connections.add(ws);
  }

  removeConnection(ws: WebSocket) {
    this.connections.delete(ws);
  }

  broadcast(message: ServerMessage, exclude?: WebSocket) {
    const data = JSON.stringify(message);
    for (const conn of this.connections) {
      if (conn !== exclude && conn.readyState === WebSocket.OPEN) {
        try {
          conn.send(data);
        } catch (error) {
          console.error("Error sending message:", error);
        }
      }
    }
  }

  getMetrics() {
    return {
      ...this.monitor.getMetrics(),
      activeSessions: this.sessions.size,
      activeConnections: this.connections.size,
    };
  }
}

// 创建应用
const app = new Hono<{ Bindings: Bindings }>();

// CORS 配置
app.use(
  "*",
  cors({
    origin: ["http://localhost:5173", "http://localhost:4173"],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
  }),
);

// WebSocket 处理
app.get(
  "/api/s/:name",
  upgradeWebSocket((c) => {
    return {
      onOpen: async (ws, req) => {
        const sessionName = req.param("name");
        const sessionManager = new SessionManager(c.env);

        try {
          const session = await sessionManager.getSession(sessionName);
          if (!session) {
            ws.close(4404, "Session not found");
            return;
          }

          sessionManager.addConnection(ws);

          // 发送欢迎消息
          const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
          ws.send(
            JSON.stringify({
              type: "hello",
              data: { userId, sessionName: session.name },
            }),
          );
        } catch (error) {
          console.error("WebSocket open error:", error);
          ws.close(4500, "Internal error");
        }
      },

      onMessage: async (ws, msg) => {
        try {
          const data =
            typeof msg === "string" ? msg : new TextDecoder().decode(msg);
          const message: ClientMessage = JSON.parse(data);
          const sessionName = new URL(ws.url).pathname.split("/").pop();

          if (!sessionName) return;

          const sessionManager = new SessionManager(ws["env"]);
          await handleClientMessage(ws, message, sessionName, sessionManager);
        } catch (error) {
          console.error("Message handling error:", error);
          ws.send(
            JSON.stringify({
              type: "error",
              data: { message: "Invalid message format" },
            }),
          );
        }
      },

      onClose: async (ws, code, reason) => {
        const sessionManager = new SessionManager(ws["env"]);
        sessionManager.removeConnection(ws);
        console.log(`WebSocket closed: ${code} - ${reason}`);
      },

      onError: async (ws, error) => {
        console.error("WebSocket error:", error);
        const sessionManager = new SessionManager(ws["env"]);
        sessionManager.removeConnection(ws);
      },
    };
  }),
);

// 处理客户端消息
async function handleClientMessage(
  ws: WebSocket,
  message: ClientMessage,
  sessionName: string,
  sessionManager: SessionManager,
) {
  switch (message.type) {
    case "authenticate":
      await handleAuthenticate(ws, message.data, sessionName, sessionManager);
      break;
    case "setName":
      await handleSetName(ws, message.data, sessionName, sessionManager);
      break;
    case "create":
      await handleCreateShell(ws, message.data, sessionName, sessionManager);
      break;
    case "data":
      await handleShellData(ws, message.data, sessionName, sessionManager);
      break;
    case "chat":
      await handleChat(ws, message.data, sessionName, sessionManager);
      break;
    case "ping":
      ws.send(JSON.stringify({ type: "pong", data: message.data }));
      break;
    default:
      ws.send(
        JSON.stringify({
          type: "error",
          data: { message: "Unknown message type" },
        }),
      );
  }
}

// 设置用户名
async function handleSetName(
  ws: WebSocket,
  data: any,
  sessionName: string,
  sessionManager: SessionManager,
) {
  const { userId, name } = data;

  const session = await sessionManager.getSession(sessionName);
  if (!session) return;

  const user = session.users.get(userId);
  if (!user) return;

  user.name = name;

  // 广播用户更新
  sessionManager.broadcast({
    type: "userDiff",
    data: { userId, user },
  });
}

// 认证处理
async function handleAuthenticate(
  ws: WebSocket,
  data: any,
  sessionName: string,
  sessionManager: SessionManager,
) {
  const { encryptedZeros, writePassword } = data;

  const session = await sessionManager.getSession(sessionName);
  if (!session) {
    ws.send(JSON.stringify({ type: "invalidAuth" }));
    return;
  }

  // 简单的认证检查
  if (encryptedZeros !== session.encryptedZeros) {
    ws.send(JSON.stringify({ type: "invalidAuth" }));
    return;
  }

  const canWrite =
    !session.writePasswordHash || writePassword === session.writePasswordHash;

  // 添加用户到会话
  const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const userData: UserData = {
    id: userId,
    name: `User ${userId.slice(0, 8)}`,
    canWrite,
  };

  session.users.set(userId, userData);

  // 广播用户列表
  const users = Array.from(session.users.entries()).map(([id, user]) => [
    id,
    user,
  ]);
  sessionManager.broadcast({ type: "users", data: users });
}

// 创建 Shell
async function handleCreateShell(
  ws: WebSocket,
  data: any,
  sessionName: string,
  sessionManager: SessionManager,
) {
  const { x, y } = data;

  const session = await sessionManager.getSession(sessionName);
  if (!session) return;

  const shellId = `shell_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const shellData: ShellData = {
    id: shellId,
    x,
    y,
    rows: 24,
    cols: 80,
    data: [],
    seqnum: 0,
    closed: false,
  };

  session.shells.set(shellId, shellData);

  // 广播 Shell 列表
  const shells = Array.from(session.shells.entries()).map(([id, shell]) => [
    id,
    {
      x: shell.x,
      y: shell.y,
      rows: shell.rows,
      cols: shell.cols,
    },
  ]);

  sessionManager.broadcast({ type: "shells", data: shells });
}

// 处理 Shell 数据
async function handleShellData(
  ws: WebSocket,
  data: any,
  sessionName: string,
  sessionManager: SessionManager,
) {
  const { shellId, data: shellData, seq } = data;

  const session = await sessionManager.getSession(sessionName);
  if (!session) return;

  const shell = session.shells.get(shellId);
  if (!shell || shell.closed) return;

  // 存储数据
  shell.data.push(shellData);
  shell.seqnum = seq;

  // 广播数据
  sessionManager.broadcast({
    type: "chunks",
    data: { shellId, seqnum: shell.seqnum, chunks: [shellData] },
  });
}

// 处理聊天消息
async function handleChat(
  ws: WebSocket,
  data: any,
  sessionName: string,
  sessionManager: SessionManager,
) {
  const { message, userId } = data;

  const session = await sessionManager.getSession(sessionName);
  if (!session) return;

  const user = session.users.get(userId);
  if (!user) return;

  sessionManager.broadcast({
    type: "hear",
    data: { userId, name: user.name, message },
  });
}

// HTTP API 端点
app.get("/api/health", (c) => {
  const sessionManager = new SessionManager(c.env);
  return c.json({
    status: "healthy",
    timestamp: Date.now(),
    ...sessionManager.getMetrics(),
  });
});

app.post("/api/sessions", async (c) => {
  try {
    const { name, owner, encryptedZeros, writePasswordHash } =
      await c.req.json();

    if (!name || !owner || !encryptedZeros) {
      return c.json({ error: "Missing required fields" }, 400);
    }

    const sessionManager = new SessionManager(c.env);
    const session = await sessionManager.createSession(
      name,
      owner,
      encryptedZeros,
      writePasswordHash,
    );

    return c.json({
      name: session.name,
      owner: session.owner,
      createdAt: session.createdAt,
    });
  } catch (error) {
    console.error("Create session error:", error);
    return c.json({ error: "Failed to create session" }, 500);
  }
});

// 初始化数据库
async function initializeDatabase(db: D1Database) {
  try {
    await db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        name TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_accessed INTEGER NOT NULL,
        encrypted_zeros TEXT NOT NULL,
        write_password_hash TEXT,
        updated_at INTEGER DEFAULT (strftime('%s', 'now'))
      );

      CREATE INDEX IF NOT EXISTS idx_sessions_owner ON sessions(owner);
      CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
      CREATE INDEX IF NOT EXISTS idx_sessions_last_accessed ON sessions(last_accessed);
    `);
  } catch (error) {
    console.error("Database initialization error:", error);
  }
}

// SvelteKit 请求处理器
export const GET: RequestHandler = async ({ request, platform }) => {
  if (!platform?.env) {
    return new Response("Environment not available", { status: 500 });
  }

  // 初始化数据库
  await initializeDatabase(platform.env.DB);

  return app.fetch(request, {}, platform.env);
};

export const POST: RequestHandler = async ({ request, platform }) => {
  if (!platform?.env) {
    return new Response("Environment not available", { status: 500 });
  }

  return app.fetch(request, {}, platform.env);
};

