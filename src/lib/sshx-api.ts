import init, { SshxNode, Session, SessionManager } from "$lib/sshx-web-pkg";

// Type definitions for SSHX events
export interface SshxEvent {
  hello?: [number, string];
  invalidAuth?: [];
  users?: [number, User][];
  userDiff?: [number, User | null];
  shells?: [number, Winsize][];
  chunks?: [number, number, Uint8Array[]];
  hear?: [number, string, string];
  shellLatency?: number | bigint;
  pong?: number | bigint;
  error?: string;
}

export interface User {
  name: string;
  cursor: [number, number] | null;
  focus: number | null;
  canWrite: boolean;
}

export interface Winsize {
  x: number;
  y: number;
  rows: number;
  cols: number;
}

export interface SshxClientOptions {
  onEvent(event: SshxEvent, sessionId?: string): void;
  onConnect?(sessionId?: string): void;
  onDisconnect?(sessionId?: string): void;
  onClose?(event: CloseEvent, sessionId?: string): void;
}

export interface SessionInfo {
  id: string;
  active: boolean;
  createdAt: Date;
  ticket: string;
}

export class SshxClient {
  #node: SshxNode | null = null;
  #session: Session | null = null;
  #sender: any = null;
  #receiver: any = null;
  #options: SshxClientOptions;
  #connected: boolean = false;

  constructor(options: SshxClientOptions) {
    this.#options = options;
  }

  async createSession(): Promise<string> {
    if (!this.#node) {
      await this.#initializeNode();
    }

    this.#session = await this.#node!.create();
    this.#setupSession();
    return this.#session!.ticket(true);
  }

  async joinSession(ticket: string): Promise<void> {
    if (!this.#node) {
      await this.#initializeNode();
    }

    this.#session = await this.#node!.join(ticket);
    this.#setupSession();
  }

  async #initializeNode(): Promise<void> {
    await init();
    this.#node = await SshxNode.spawn();
  }

  #setupSession(): void {
    if (!this.#session) return;

    this.#sender = this.#session.sender();
    this.#receiver = this.#session.receiver();

    // Set up event stream handling
    const stream = this.#receiver.getReader();
    this.#readStream(stream);

    this.#connected = true;
    this.#options.onConnect?.();
  }

  async #readStream(stream: ReadableStreamDefaultReader): Promise<void> {
    try {
      while (true) {
        const { done, value } = await stream.read();
        if (done) break;

        // Convert JsValue to our event format
        const event = this.#convertToEvent(value);
        this.#options.onEvent(event);
      }
    } catch (error) {
      console.error("Stream reading error:", error);
      this.#handleDisconnect();
    }
  }

  #convertToEvent(jsValue: any): SshxEvent {
    // This would need to be implemented based on the actual event format
    // For now, return the value as-is
    return jsValue as SshxEvent;
  }

  async sendData(shellId: number, data: Uint8Array): Promise<void> {
    if (!this.#sender) {
      throw new Error("Session not initialized");
    }

    // Encode the data with shell ID for the server to understand
    const message = new Uint8Array(4 + data.length);
    new DataView(message.buffer).setUint32(0, shellId);
    message.set(data, 4);

    await this.#sender.send(message);
  }

  async sendCommand(command: any): Promise<void> {
    if (!this.#sender) {
      throw new Error("Session not initialized");
    }

    // Convert command to bytes and send
    const encoder = new TextEncoder();
    const commandJson = JSON.stringify(command);
    const data = encoder.encode(commandJson);

    await this.#sender.send(data);
  }

  #handleDisconnect(): void {
    this.#connected = false;
    this.#options.onDisconnect?.();
  }

  get connected(): boolean {
    return this.#connected;
  }

  get sessionId(): string {
    return this.#session?.id() || "";
  }

  get encryptionKey(): string {
    return this.#session?.encryption_key() || "";
  }

  dispose(): void {
    this.#sender = null;
    this.#receiver = null;
    this.#session = null;
    this.#node = null;
    this.#connected = false;
  }
}

export class MultiSessionSshxClient {
  #sessionManager: SessionManager | null = null;
  #sessions: Map<string, SessionData> = new Map();
  #options: SshxClientOptions;

  constructor(options: SshxClientOptions) {
    this.#options = options;
  }

  async initialize(): Promise<void> {
    await init();
    this.#sessionManager = await SessionManager.new();
  }

  async createSession(): Promise<string> {
    if (!this.#sessionManager) {
      await this.initialize();
    }

    const sessionId = await this.#sessionManager!.create_session();
    const session = this.#sessionManager!.get_session(sessionId);

    const sessionData: SessionData = {
      session,
      sessionId,
      active: true,
      sender: session.sender(),
      receiver: session.receiver(),
    };

    this.#sessions.set(sessionId, sessionData);
    this.#setupSessionHandlers(sessionId);

    this.#options.onConnect?.(sessionId);
    return session.ticket(true);
  }

  async joinSession(ticket: string): Promise<string> {
    if (!this.#sessionManager) {
      await this.initialize();
    }

    const sessionId = await this.#sessionManager!.join_session(ticket);
    const session = this.#sessionManager!.get_session(sessionId);

    const sessionData: SessionData = {
      session,
      sessionId,
      active: true,
      sender: session.sender(),
      receiver: session.receiver(),
    };

    this.#sessions.set(sessionId, sessionData);
    this.#setupSessionHandlers(sessionId);

    this.#options.onConnect?.(sessionId);
    return sessionId;
  }

  #setupSessionHandlers(sessionId: string): void {
    const sessionData = this.#sessions.get(sessionId);
    if (!sessionData) return;

    const stream = sessionData.receiver.getReader();
    this.#readStream(stream, sessionId);
  }

  async #readStream(
    stream: ReadableStreamDefaultReader,
    sessionId: string,
  ): Promise<void> {
    try {
      while (true) {
        const { done, value } = await stream.read();
        if (done) break;

        const event = this.#convertToEvent(value);
        this.#options.onEvent(event, sessionId);
      }
    } catch (error) {
      console.error(`Stream reading error for session ${sessionId}:`, error);
      this.#handleDisconnect(sessionId);
    }
  }

  async sendData(
    sessionId: string,
    shellId: number,
    data: Uint8Array,
  ): Promise<void> {
    const sessionData = this.#sessions.get(sessionId);
    if (!sessionData?.active) {
      throw new Error(`Session ${sessionId} not found or inactive`);
    }

    const message = new Uint8Array(4 + data.length);
    new DataView(message.buffer).setUint32(0, shellId);
    message.set(data, 4);

    await sessionData.sender.send(message);
  }

  async sendCommand(sessionId: string, command: any): Promise<void> {
    const sessionData = this.#sessions.get(sessionId);
    if (!sessionData?.active) {
      throw new Error(`Session ${sessionId} not found or inactive`);
    }

    const encoder = new TextEncoder();
    const commandJson = JSON.stringify(command);
    const data = encoder.encode(commandJson);

    await sessionData.sender.send(data);
  }

  async broadcastToAll(data: Uint8Array): Promise<void> {
    if (!this.#sessionManager) {
      throw new Error("Session manager not initialized");
    }

    await this.#sessionManager.broadcast_to_all(data);
  }

  async sendToSession(sessionId: string, data: Uint8Array): Promise<void> {
    if (!this.#sessionManager) {
      throw new Error("Session manager not initialized");
    }

    await this.#sessionManager.send_to_session(sessionId, data);
  }

  getSessionIds(): string[] {
    return Array.from(this.#sessions.keys());
  }

  getActiveSessions(): string[] {
    return Array.from(this.#sessions.entries())
      .filter(([_, data]) => data.active)
      .map(([id]) => id);
  }

  getSessionInfo(sessionId: string): SessionInfo | null {
    try {
      if (!this.#sessionManager) {
        return null;
      }

      const info = this.#sessionManager.get_session_info(sessionId);
      return {
        id: sessionId,
        active: info.active,
        createdAt: new Date(info.createdAt),
        ticket: info.ticket,
      };
    } catch (error) {
      return null;
    }
  }

  getAllSessionInfo(): SessionInfo[] {
    return this.getSessionIds()
      .map((id) => this.getSessionInfo(id))
      .filter(Boolean) as SessionInfo[];
  }

  async removeSession(sessionId: string): Promise<boolean> {
    if (!this.#sessionManager) {
      return false;
    }

    const result = await this.#sessionManager.remove_session(sessionId);
    if (result) {
      this.#sessions.delete(sessionId);
      this.#handleDisconnect(sessionId);
    }
    return result;
  }

  #convertToEvent(jsValue: any): SshxEvent {
    return jsValue as SshxEvent;
  }

  #handleDisconnect(sessionId: string): void {
    const sessionData = this.#sessions.get(sessionId);
    if (sessionData) {
      sessionData.active = false;
    }
    this.#options.onDisconnect?.(sessionId);
  }

  isSessionActive(sessionId: string): boolean {
    const sessionData = this.#sessions.get(sessionId);
    return sessionData?.active || false;
  }

  getSessionCount(): number {
    return this.#sessions.size;
  }

  getActiveSessionCount(): number {
    return this.getActiveSessions().length;
  }

  dispose(): void {
    this.#sessions.forEach((_, sessionId) => {
      this.#handleDisconnect(sessionId);
    });
    this.#sessions.clear();
    this.#sessionManager = null;
  }
}

interface SessionData {
  session: Session;
  sessionId: string;
  active: boolean;
  sender: any;
  receiver: any;
}
