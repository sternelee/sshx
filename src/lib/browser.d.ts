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
