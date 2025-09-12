import { SshxNode, Session, SessionSender, SessionManager } from "./browser";
// import { isTauri, getTauriApi, type TauriAPI } from "./tauri-api";

const isTauri = () => false;

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
  shellCreated?: { id: number; x: number; y: number };
  shellClosed?: { id: number };
  shellList?: { shells: Array<{ id: number; x: number; y: number; active: boolean; createdAt?: number }>; count: number };
  shellResized?: { id: number; rows: number; cols: number };
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

// We want to only ever create the API once, therefore we define a module-level
// singleton that holds the promise to create the API.
// As promises can be awaited any number of times in JavaScript, this gives us
// an async singleton instance to the wasm API.
const api = importAndInitOnce();

export async function initApi() {
  return await api;
}

async function importAndInitOnce() {
  try {
    let apiInstance;

    if (isTauri()) {
      // In Tauri environment, use the Tauri-specific API
      console.log("Running in Tauri environment, using Tauri API");
      // apiInstance = new TauriSshxAPI(getTauriApi());
    } else {
      // Web environment, use the WASM-based API
      console.log("Running in web environment, using WASM API");
      const node = await SshxNode.spawn();
      apiInstance = new WebSshxAPI(node);
    }

    return apiInstance;
  } catch (err) {
    console.error("Failed to import or launch sshx", err);
    throw err;
  }
}

// Base interface for SSHX API implementations
export interface SshxAPI {
  createSession(): Promise<string>;
  joinSession(ticket: string): Promise<string>;
  sendData(sessionId: string, data: Uint8Array): Promise<void>;
  subscribeToEvents(
    sessionId: string,
    callback: (event: SshxEvent) => void,
  ): () => void;
  getSessionTicket(sessionId: string, includeSelf?: boolean): string;
  getSessionInfo(sessionId: string): { id: string; connected: boolean } | null;
  closeSession(sessionId: string): Promise<void>;
  getNodeId(): string;
}

// Tauri-specific implementation
class TauriSshxAPI implements SshxAPI {
  private tauriApi: TauriAPI;

  constructor(tauriApi: TauriAPI) {
    this.tauriApi = tauriApi;
  }

  async createSession(): Promise<string> {
    return await this.tauriApi.createSession();
  }

  async joinSession(ticket: string): Promise<string> {
    return await this.tauriApi.joinSession(ticket);
  }

  async sendData(sessionId: string, data: Uint8Array): Promise<void> {
    await this.tauriApi.sendData(sessionId, data);
  }

  subscribeToEvents(
    sessionId: string,
    callback: (event: SshxEvent) => void,
  ): () => void {
    return this.tauriApi.subscribeToEvents(sessionId, callback);
  }

  getSessionTicket(sessionId: string, includeSelf: boolean = true): string {
    // This is async in Tauri, but sync in the interface for compatibility
    // We'll need to handle this appropriately in the calling code
    throw new Error("Use getSessionTicketAsync for Tauri environment");
  }

  async getSessionTicketAsync(
    sessionId: string,
    includeSelf: boolean = true,
  ): Promise<string> {
    return await this.tauriApi.getSessionTicket(sessionId, includeSelf);
  }

  getSessionInfo(sessionId: string): { id: string; connected: boolean } | null {
    return this.tauriApi.getSessionInfo(sessionId);
  }

  async closeSession(sessionId: string): Promise<void> {
    await this.tauriApi.closeSession(sessionId);
  }

  getNodeId(): string {
    // This is async in Tauri, but sync in the interface for compatibility
    throw new Error("Use getNodeIdAsync for Tauri environment");
  }

  async getNodeIdAsync(): Promise<string> {
    return await this.tauriApi.getNodeId();
  }
}

// Web-based implementation (existing code)
type SessionState = {
  id: string;
  session: Session;
  sender: SessionSender;
  receiver: ReadableStream;
  subscribers: ((event: SshxEvent) => void)[];
  connected: boolean;
};

class WebSshxAPI implements SshxAPI {
  private node: SshxNode;
  private sessions: Map<string, SessionState> = new Map();

  constructor(node: SshxNode) {
    this.node = node;
  }

  async createSession(): Promise<string> {
    const session = await this.node.create();
    return this.setupSession(session);
  }

  async joinSession(ticket: string): Promise<string> {
    const session = await this.node.join(ticket);
    return this.setupSession(session);
  }

  private setupSession(session: Session): string {
    const id = session.id();
    const sender = session.sender;
    const receiver = session.receiver;

    if (!receiver) {
      throw new Error(`Session ${id} does not have a receiver stream`);
    }

    const state: SessionState = {
      id,
      session,
      sender,
      receiver,
      subscribers: [],
      connected: true,
    };

    this.sessions.set(id, state);
    this.startEventStream(state);

    // Notify that connection is established
    setTimeout(() => {
      for (const subscriber of state.subscribers) {
        // Send a hello event to trigger connection handling
        subscriber({ hello: [Date.now(), "connected"] });
      }
    }, 100);

    return id;
  }

  private async startEventStream(state: SessionState): Promise<void> {
    try {
      const reader = state.receiver.getReader();
      while (state.connected) {
        const { done, value } = await reader.read();
        if (done) break;

        const event = this.convertToEvent(value);
        for (const subscriber of state.subscribers) {
          subscriber(event);
        }
      }
    } catch (error) {
      console.error("Stream reading error:", error);
      state.connected = false;
    }
  }

  async sendData(sessionId: string, data: Uint8Array): Promise<void> {
    const state = this.sessions.get(sessionId);
    if (!state || !state.connected) {
      throw new Error(`Session ${sessionId} not found or disconnected`);
    }
    await state.sender.send(data);
  }

  subscribeToEvents(
    sessionId: string,
    callback: (event: SshxEvent) => void,
  ): () => void {
    const state = this.sessions.get(sessionId);
    if (!state) {
      throw new Error(`Session ${sessionId} not found`);
    }

    state.subscribers.push(callback);
    return () => {
      const index = state.subscribers.indexOf(callback);
      if (index > -1) {
        state.subscribers.splice(index, 1);
      }
    };
  }

  getSessionTicket(sessionId: string, includeSelf: boolean = true): string {
    const state = this.sessions.get(sessionId);
    if (!state) {
      throw new Error(`Session ${sessionId} not found`);
    }
    return state.session.ticket(includeSelf);
  }

  getSessionInfo(sessionId: string): { id: string; connected: boolean } | null {
    const state = this.sessions.get(sessionId);
    if (!state) {
      return null;
    }
    return {
      id: state.id,
      connected: state.connected,
    };
  }

  async closeSession(sessionId: string): Promise<void> {
    const state = this.sessions.get(sessionId);
    if (state) {
      state.connected = false;
      this.sessions.delete(sessionId);
    }
  }

  getNodeId(): string {
    return this.node.node_id();
  }

  private convertToEvent(jsValue: any): SshxEvent {
    // Handle events from WASM
    try {
      // Handle raw binary data that might be encoded
      if (jsValue instanceof Uint8Array) {
        try {
          const decoder = new TextDecoder();
          const messageStr = decoder.decode(jsValue);
          const parsedMessage = JSON.parse(messageStr);

          // Convert ServerMessage to SshxEvent format
          return this.serverMessageToSshxEvent(parsedMessage);
        } catch (e) {
          console.warn("Received non-JSON binary data:", jsValue);
          return { error: "Invalid binary message format" };
        }
      }

      // Handle direct SshxEvent objects
      if (jsValue && typeof jsValue === "object") {
        if (
          jsValue.hello ||
          jsValue.invalidAuth ||
          jsValue.users ||
          jsValue.userDiff ||
          jsValue.shells ||
          jsValue.chunks ||
          jsValue.hear ||
          jsValue.shellLatency ||
          jsValue.pong ||
          jsValue.error
        ) {
          return jsValue as SshxEvent;
        }
      }

      // Fallback: return as-is if it already looks like an SshxEvent
      return jsValue as SshxEvent;
    } catch (error) {
      console.error("Error converting WASM event:", error, jsValue);
      return { error: "Event conversion failed" };
    }
  }

  private serverMessageToSshxEvent(serverMessage: any): SshxEvent {
    // Convert ServerMessage format to SshxEvent format
    switch (serverMessage.type) {
      case "Hello":
        return {
          hello: [Date.now(), serverMessage.data.token || "connected"],
        };
      case "Data":
        return {
          chunks: [
            serverMessage.data.id,
            serverMessage.data.seq,
            [serverMessage.data.data],
          ],
        };
      case "ShellCreated":
        return {
          shellCreated: {
            id: serverMessage.data.id,
            x: serverMessage.data.x,
            y: serverMessage.data.y,
          },
        };
      case "ShellClosed":
        return {
          shellClosed: {
            id: serverMessage.data.id,
          },
        };
      case "ShellList":
        return {
          shellList: {
            shells: serverMessage.data.shells.map((shell: any) => ({
              id: shell.id,
              x: shell.x,
              y: shell.y,
              active: shell.active,
              createdAt: shell.created_at,
            })),
            count: serverMessage.data.count,
          },
        };
      case "ShellResized":
        return {
          shellResized: {
            id: serverMessage.data.id,
            rows: serverMessage.data.rows,
            cols: serverMessage.data.cols,
          },
        };
      case "Ping":
        return {
          pong: serverMessage.data.timestamp,
        };
      case "Error":
        return {
          error: serverMessage.data.message,
        };
      default:
        console.warn("Unknown server message type:", serverMessage.type);
        return { error: "Unknown message type" };
    }
  }
}
