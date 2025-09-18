import { SshxNode, Session, SessionSender } from "./browser";

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
  return (
    typeof window !== "undefined" && (window as any).__TAURI__ !== undefined
  );
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
      console.log("🚀 Started event stream for session:", state.id);

      while (state.connected) {
        const { done, value } = await reader.read();
        if (done) {
          console.log("🔴 Event stream ended for session:", state.id);
          break;
        }

        console.log("📨 Raw stream value received:", {
          type: typeof value,
          constructor: value?.constructor?.name,
          length: value instanceof Uint8Array ? value.length : "N/A",
          preview:
            value instanceof Uint8Array
              ? Array.from(value.slice(0, 20))
                  .map((b) => b.toString(16).padStart(2, "0"))
                  .join(" ")
              : String(value).slice(0, 100),
        });

        // Skip empty events (connection/disconnection events)
        if (value instanceof Uint8Array && value.length === 0) {
          console.log("⏭️ Skipping empty event (connection/disconnection)");
          continue;
        }

        const event = this.convertToEvent(value);
        console.log("🔄 Converted event:", event);

        // Only process events that have actual content
        if (event && Object.keys(event).length > 0) {
          for (const subscriber of state.subscribers) {
            subscriber(event);
          }
        }
      }
    } catch (error) {
      console.error("🔥 Stream reading error:", error);
      state.connected = false;
    }
  }

  async sendData(sessionId: string, data: Uint8Array): Promise<void> {
    const state = this.sessions.get(sessionId);
    if (!state || !state.connected) {
      throw new Error(`Session ${sessionId} not found or disconnected`);
    }

    console.log("📤 Sending data to CLI:", {
      sessionId,
      dataLength: data.length,
      preview: Array.from(data.slice(0, 50))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" "),
      // decoded: new TextDecoder().decode(data),
    });

    await state.sender.send(data);
  }

  async sendClientMessage(sessionId: string, message: any): Promise<void> {
    const state = this.sessions.get(sessionId);
    if (!state || !state.connected) {
      throw new Error(`Session ${sessionId} not found or disconnected`);
    }

    console.log("📤 Sending ClientMessage to CLI:", message);

    // Convert the message to JSON and send as binary data
    const jsonStr = JSON.stringify(message);
    const encoder = new TextEncoder();
    const data = encoder.encode(jsonStr);
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
      console.log("🔧 Converting to event:", {
        type: typeof jsValue,
        constructor: jsValue?.constructor?.name,
        isUint8Array: jsValue instanceof Uint8Array,
        length: jsValue instanceof Uint8Array ? jsValue.length : "N/A",
      });

      // Handle raw binary data that might be encoded
      if (jsValue instanceof Uint8Array) {
        try {
          const decoder = new TextDecoder();
          const messageStr = decoder.decode(jsValue);
          console.log("📋 Decoded message string:", messageStr);

          const parsedMessage = JSON.parse(messageStr);
          console.log("🔍 Parsed JSON message:", parsedMessage);

          // Convert ServerMessage to SshxEvent format
          const event = this.serverMessageToSshxEvent(parsedMessage);
          console.log("✅ Final converted event:", event);
          return event;
        } catch (e) {
          console.warn(
            "⚠️ Failed to decode/parse binary data:",
            e,
            "Data:",
            jsValue,
          );
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
          jsValue.error
        ) {
          console.log("✅ Direct SshxEvent detected:", jsValue);
          return jsValue as SshxEvent;
        }
      }

      // Fallback: return as-is if it already looks like an SshxEvent
      console.log("🤷 Fallback conversion:", jsValue);
      return jsValue as SshxEvent;
    } catch (error) {
      console.error("🔥 Error converting WASM event:", error, jsValue);
      return { error: "Event conversion failed" };
    }
  }

  private serverMessageToSshxEvent(serverMessage: any): SshxEvent {
    // Convert ServerMessage format to SshxEvent format
    console.log("🔄 Converting ServerMessage to SshxEvent:", serverMessage);

    switch (serverMessage.type) {
      case "Data":
        const dataEvent: SshxEvent = {
          chunks: [
            serverMessage.data.id as number,
            serverMessage.data.seq as number,
            [new Uint8Array(serverMessage.data.data as ArrayBuffer)],
          ],
        };
        console.log("📊 Created Data event:", dataEvent);
        return dataEvent;

      case "CreatedShell":
        const createdEvent: SshxEvent = {
          shells: [
            [
              serverMessage.data.id as number,
              { x: 0, y: 0, rows: 24, cols: 80 },
            ],
          ],
        };
        console.log("🐚 Created CreatedShell event:", createdEvent);
        return createdEvent;

      case "ClosedShell":
        const closedEvent: SshxEvent = {
          shells: [], // Empty shells array triggers shell removal
        };
        console.log("❌ Created ClosedShell event:", closedEvent);
        return closedEvent;

      case "Error":
        const errorEvent: SshxEvent = {
          error: serverMessage.data.message as string,
        };
        console.log("🔥 Created Error event:", errorEvent);
        return errorEvent;

      default:
        console.warn("⚠️ Unknown server message type:", serverMessage.type);
        return { error: "Unknown message type" };
    }
  }
}
