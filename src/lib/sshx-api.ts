import init, { SshxNode, Session } from "$lib/sshx-web-pkg";

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
  onEvent(event: SshxEvent): void;
  onConnect?(): void;
  onDisconnect?(): void;
  onClose?(event: CloseEvent): void;
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

