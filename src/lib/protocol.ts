type Sid = number; // u32
type Uid = number; // u32

/** Position and size of a window, see the Rust version. */
export type WsWinsize = {
  x: number;
  y: number;
  rows: number;
  cols: number;
};

/** Information about a user, see the Rust version */
export type WsUser = {
  name: string;
  cursor: [number, number] | null;
  focus: number | null;
  canWrite: boolean;
};

/** Server message type, see the Rust version. */
export type WsServer = {
  h?: [Uid, string];
  a?: [];
  u?: [Uid, WsUser][];
  d?: [Uid, WsUser | null];
  s?: [Sid, WsWinsize][];
  c?: [Sid, number, Uint8Array[]];
  e?: [Uid, string, string];
  l?: number | bigint;
  p?: number | bigint;
  x?: string;
};

/** Client message type, see the Rust version. */
export type WsClient = {
  a?: [Uint8Array, Uint8Array | null];
  n?: string;
  c?: [number, number] | null;
  f?: number | null;
  e?: [number, number];
  x?: Sid;
  m?: [Sid, WsWinsize | null];
  d?: [Sid, Uint8Array, bigint];
  s?: [Sid, number];
  t?: string;
  p?: bigint;
};
