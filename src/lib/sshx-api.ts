import { SshxNode, Session, SessionSender } from "sshx-web";

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

// Check if we're running in a Tauri environment
const isTauri = () => {
  return typeof window !== 'undefined' && (window as any).__TAURI__ !== undefined;
};

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
    let node;
    
    if (isTauri()) {
      // In Tauri environment, we might want to use a different initialization
      // For now, we'll still use the web version but this is where Tauri-specific
      // logic would go
      console.log("Running in Tauri environment");
      node = await SshxNode.spawn();
    } else {
      // Web environment
      node = await SshxNode.spawn();
    }
    
    return new SshxAPI(node);
  } catch (err) {
    console.error("Failed to import or launch sshx", err);
    throw err;
  }
}

type SessionState = {
  id: string;
  session: Session;
  sender: SessionSender;
  receiver: ReadableStream;
  subscribers: ((event: SshxEvent) => void)[];
  connected: boolean;
};

export class SshxAPI {
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
      if (jsValue && typeof jsValue === "object") {
        // Try to parse as direct SshxEvent first
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

        // Handle raw binary data that might be encoded
        if (jsValue instanceof Uint8Array) {
          try {
            const decoder = new TextDecoder();
            const messageStr = decoder.decode(jsValue);
            const parsedMessage = JSON.parse(messageStr);
            return parsedMessage as SshxEvent;
          } catch (e) {
            console.warn("Received non-JSON binary data:", jsValue);
            return { error: "Invalid binary message format" };
          }
        }
      }

      // Fallback: return as-is if it already looks like an SshxEvent
      return jsValue as SshxEvent;
    } catch (error) {
      console.error("Error converting WASM event:", error, jsValue);
      return { error: "Event conversion failed" };
    }
  }
}