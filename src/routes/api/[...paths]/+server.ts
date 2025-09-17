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

// 创建 Hono 应用
const app = new Hono<{ Bindings: Bindings }>().basePath("/api");

// 添加 CORS 支持
app.use("*", cors());

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
  | { type: "Ping"; timestamp: number };

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

    return {
      onOpen(evt: Event, ws: WSContext<WebSocket>) {
        // 连接建立时的处理逻辑
        console.log(`WebSocket connection opened for session: ${name}`);
        // 生成连接 ID
        connectionId = generateConnectionId();
        (ws.raw as any).connectionId = connectionId;

        // 将 WebSocket 连接存储到全局状态中，以便广播消息
        (ws.raw as any).sessionName = name;

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

      async onMessage(evt: MessageEvent, ws: WSContext<WebSocket>) {
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
                await handleSubscribe(c, sessionId, userId, message, ws);
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
              ws.send(
                JSON.stringify({
                  type: "Pong",
                  timestamp: message.timestamp,
                } as WsServerMessage),
              );
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

      onClose(evt: CloseEvent, ws: WSContext<WebSocket>) {
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

      onError(evt: Event, ws: WSContext<WebSocket>) {
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
  } | null = await db
    .prepare(
      "SELECT id, encrypted_zeros, write_password_hash FROM sessions WHERE name = ?",
    )
    .bind(sessionName)
    .first() as any;

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

// 处理终端数据消息
async function handleTerminalData(
  c: any,
  sessionId: string,
  userId: string,
  message: Extract<WsClientMessage, { type: "Data" }>,
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

  if (!Array.isArray(message.data)) {
    console.error("Invalid data format");
    return;
  }

  if (typeof message.offset !== "number") {
    console.error("Invalid offset");
    return;
  }

  const db = c.env.DB;

  // 保存终端数据
  try {
    await db
      .prepare(
        "INSERT INTO terminal_data (shell_id, sequence_number, data) VALUES (?, ?, ?)",
      )
      .bind(message.shell_id, message.offset, new Uint8Array(message.data))
      .run();
  } catch (error) {
    console.error("Error saving terminal data:", error);
    return;
  }

  // 通知订阅了此终端的客户端有新数据
  notifySubscribers(message.shell_id, message.offset, message.data);
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

  // 获取从指定 chunknum 开始的所有数据
  try {
    const dataResult: {
      results: { sequence_number: number; data: Uint8Array }[];
    } = await db
      .prepare(
        "SELECT sequence_number, data FROM terminal_data WHERE shell_id = ? AND sequence_number >= ? ORDER BY sequence_number ASC LIMIT 100",
      )
      .bind(message.shell_id, message.chunknum)
      .all();

    // 发送数据块给客户端
    for (const row of dataResult.results) {
      ws.send(
        JSON.stringify({
          type: "Chunks",
          shell_id: message.shell_id,
          seqnum: row.sequence_number,
          chunks: [Array.from(row.data)],
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

// 导出为 SvelteKit 请求处理器
export const GET: RequestHandler = async ({ request }) => {
  return app.fetch(request);
};

export const POST: RequestHandler = async ({ request }) => {
  return app.fetch(request);
};
