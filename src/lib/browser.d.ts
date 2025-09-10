/* tslint:disable */
/* eslint-disable */
export function start(): void;
/**
 * The `ReadableStreamType` enum.
 *
 * *This API requires the following crate features to be activated: `ReadableStreamType`*
 */
type ReadableStreamType = "bytes";
export class IntoUnderlyingByteSource {
  private constructor();
  free(): void;
  start(controller: ReadableByteStreamController): void;
  pull(controller: ReadableByteStreamController): Promise<any>;
  cancel(): void;
  readonly type: ReadableStreamType;
  readonly autoAllocateChunkSize: number;
}
export class IntoUnderlyingSink {
  private constructor();
  free(): void;
  write(chunk: any): Promise<any>;
  close(): Promise<any>;
  abort(reason: any): Promise<any>;
}
export class IntoUnderlyingSource {
  private constructor();
  free(): void;
  pull(controller: ReadableStreamDefaultController): Promise<any>;
  cancel(): void;
}
export class Session {
  private constructor();
  free(): void;
  ticket(_include_self: boolean): string;
  id(): string;
  encryption_key(): string;
  readonly sender: SessionSender;
  readonly receiver: ReadableStream | undefined;
}
/**
 * Session manager for handling multiple P2P sessions
 */
export class SessionManager {
  private constructor();
  free(): void;
  /**
   * Creates a new session manager.
   */
  static new(): Promise<SessionManager>;
  /**
   * Creates a new session and adds it to the manager.
   */
  create_session(): Promise<string>;
  /**
   * Joins an existing session and adds it to the manager.
   */
  join_session(ticket: string): Promise<string>;
  /**
   * Gets a session by ID.
   */
  get_session(_session_id: string): Session;
  /**
   * Lists all active session IDs.
   */
  list_sessions(): Array<any>;
  /**
   * Removes a session from the manager.
   */
  remove_session(session_id: string): boolean;
  /**
   * Gets session info including metadata.
   */
  get_session_info(session_id: string): any;
  /**
   * Broadcasts a message to all active sessions.
   */
  broadcast_to_all(data: Uint8Array): Promise<void>;
  /**
   * Sends a message to a specific session.
   */
  send_to_session(session_id: string, data: Uint8Array): Promise<void>;
  /**
   * Optimize connections for all active sessions
   */
  optimize_all_connections(): Promise<void>;
}
export class SessionSender {
  private constructor();
  free(): void;
  send(data: Uint8Array): Promise<void>;
}
/**
 * Node for SSH sessions over P2P networking
 */
export class SshxNode {
  private constructor();
  free(): void;
  /**
   * Spawns a P2P node.
   */
  static spawn(): Promise<SshxNode>;
  /**
   * Returns the node id of this node.
   */
  node_id(): string;
  /**
   * Returns information about all the remote nodes this node knows about.
   */
  remote_info(): any[];
  /**
   * Creates a new SSH session.
   */
  create(): Promise<Session>;
  /**
   * Joins an SSH session from a ticket.
   */
  join(ticket: string): Promise<Session>;
}
