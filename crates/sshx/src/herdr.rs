//! Client for herdr-core (`hc`), a terminal runtime.
//!
//! herdr-core runs programs in terminals that outlive the process that started
//! them, and relays their raw bytes to any viewer. This module speaks its
//! JSON-RPC API (see `hc schema`) and exposes one attached terminal as a byte
//! stream, so the runner can relay it exactly like a local PTY.
//!
//! Protocol, in short:
//!
//! - A connection starts in plain mode: JSON-RPC 2.0, one message per line.
//! - `hello {"framed": true}` replies in plain mode, then switches the connection to framed mode.
//! - A frame is `[channel u32 LE][kind u8][len u32 LE][payload]`. Channel 0 carries JSON-RPC;
//!   `terminal.attach` hands back a channel whose DATA frames are the program's raw output.
//! - The viewer sends keys as DATA on that channel, RESIZE to resize it, CREDIT to return
//!   flow-control credit, and CLOSE to detach.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Frame kind carrying stream bytes, or a JSON-RPC message on channel 0.
const FRAME_DATA: u8 = 0;
/// Frame kind returning flow-control credit for bytes the viewer consumed.
const FRAME_CREDIT: u8 = 1;
/// Frame kind ending a channel.
const FRAME_CLOSE: u8 = 2;
/// Frame kind resizing a terminal: `u16 LE cols, u16 LE rows`.
const FRAME_RESIZE: u8 = 3;

/// Size of a frame header: channel, kind, payload length.
const HEADER_LEN: usize = 9;

/// Largest payload a single frame may carry.
const MAX_PAYLOAD: usize = 16 << 20;

#[cfg(unix)]
type Transport = tokio::net::UnixStream;
#[cfg(windows)]
type Transport = tokio::net::windows::named_pipe::NamedPipeClient;

/// One frame read from a herdr-core connection.
#[derive(Debug)]
pub enum Frame {
    /// Stream bytes on a channel.
    Data(u32, Vec<u8>),
    /// Flow-control credit the peer returned.
    Credit(u32, u32),
    /// The channel is over; the payload is the core's JSON reason, if any.
    Close(u32, Option<Value>),
    /// A terminal was resized to `cols` by `rows`.
    Resize(u32, u16, u16),
    /// A frame kind this client does not act on.
    Other(u8, u32, Vec<u8>),
}

/// A connection to a running herdr-core.
pub struct Herdr {
    writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    frame_rx: mpsc::Receiver<Result<Frame>>,
    reader_task: Option<JoinHandle<()>>,
    next_id: u64,
    /// Frames read while waiting for a reply, handed back to the stream in FIFO order.
    deferred: VecDeque<Frame>,
}

impl Drop for Herdr {
    fn drop(&mut self) {
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }
    }
}

impl Herdr {
    /// Connect to herdr-core and switch the connection to framed mode.
    ///
    /// `endpoint` overrides the socket path; otherwise the default location for
    /// the current session is used.
    pub async fn connect(endpoint: Option<&Path>) -> Result<Self> {
        let path = match endpoint {
            Some(path) => path.to_path_buf(),
            None => default_endpoint()?,
        };
        let stream = open_transport(&path).await?;
        Self::from_stream(stream).await
    }

    /// Negotiate framed mode over an already-connected byte stream.
    pub(crate) async fn from_stream<S>(stream: S) -> Result<Self>
    where
        S: AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);
        let mut writer = Box::new(writer);

        // The reply to this one is still a plain line; framed mode starts after.
        let reply = call_plain(
            &mut reader,
            &mut writer,
            1,
            "hello",
            json!({ "framed": true }),
        )
        .await?;
        let result = reply.get("result").context("malformed hello reply")?;
        if result.get("framed").and_then(Value::as_bool) != Some(true) {
            bail!("herdr-core did not accept framed mode");
        }

        // Move `reader` (preserving any bytes already buffered by BufReader) into a
        // dedicated reader task so `Herdr::read_frame` only awaits an mpsc channel
        // and stays cancel-safe inside `tokio::select!`.
        let (frame_tx, frame_rx) = mpsc::channel(64);
        let reader_task = tokio::spawn(async move {
            loop {
                let res = read_frame_raw(&mut reader).await;
                let is_err = res.is_err();
                if frame_tx.send(res).await.is_err() || is_err {
                    break;
                }
            }
        });

        Ok(Self {
            writer,
            frame_rx,
            reader_task: Some(reader_task),
            next_id: 1,
            deferred: VecDeque::new(),
        })
    }

    /// Start a program in a new terminal and return its address (`t7`).
    ///
    /// The terminal is labelled so a later run can find and reattach to it. It
    /// is not removed when its program exits, so its screen stays readable.
    pub async fn run_terminal(
        &mut self,
        argv: &[String],
        cols: u16,
        rows: u16,
        label: &str,
        slot: &str,
    ) -> Result<String> {
        let reply = self
            .call(
                "terminal.run",
                json!({
                    "argv": argv,
                    "cols": cols,
                    "rows": rows,
                    "no_parent": true,
                    "labels": { label: slot },
                }),
            )
            .await?;
        reply
            .get("address")
            .and_then(Value::as_str)
            .map(str::to_string)
            .context("terminal.run returned no address")
    }

    /// Find live terminals carrying `label` = `slot`, oldest first.
    ///
    /// Used to reattach to a terminal that outlived the session that started it.
    pub async fn find_live(&mut self, label: &str, slot: &str) -> Result<Vec<String>> {
        let reply = self
            .call("terminal.list", json!({ "labels": { label: slot } }))
            .await?;
        let terminals = reply
            .get("terminals")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(terminals
            .iter()
            .filter(|term| term.get("state").and_then(Value::as_str) == Some("live"))
            .filter_map(|term| term.get("address").and_then(Value::as_str))
            .map(str::to_string)
            .collect())
    }

    /// Attach to a terminal and return the stream channel for it.
    ///
    /// `resumed` tells the core this viewer is back after a dropped line, so it
    /// sets the size only once the viewer is active again.
    pub async fn attach(
        &mut self,
        terminal: &str,
        cols: u16,
        rows: u16,
        resumed: bool,
    ) -> Result<u32> {
        let reply = self
            .call(
                "terminal.attach",
                json!({
                    "terminal": terminal,
                    "cols": cols,
                    "rows": rows,
                    "resumed": resumed,
                }),
            )
            .await?;
        let channel = reply
            .get("channel")
            .and_then(Value::as_u64)
            .context("terminal.attach returned no channel")?;
        Ok(channel as u32)
    }

    /// Read the next frame, returning any deferred ones first.
    ///
    /// Cancel-safe: reads come from an `mpsc` receiver fed by a dedicated
    /// reader task, so cancelling this future inside `tokio::select!` cannot
    /// drop half of an in-flight frame.
    pub async fn read_frame(&mut self) -> Result<Frame> {
        if let Some(frame) = self.deferred.pop_front() {
            return Ok(frame);
        }
        self.recv_frame().await
    }

    async fn recv_frame(&mut self) -> Result<Frame> {
        self.frame_rx
            .recv()
            .await
            .unwrap_or_else(|| Err(anyhow::anyhow!("herdr-core connection closed")))
    }

    /// Send input bytes to an attached terminal.
    pub async fn write_data(&mut self, channel: u32, data: &[u8]) -> Result<()> {
        self.write_frame(channel, FRAME_DATA, data).await
    }

    /// Return flow-control credit for bytes already written out.
    pub async fn write_credit(&mut self, channel: u32, bytes: usize) -> Result<()> {
        let payload = (bytes as u32).to_le_bytes();
        self.write_frame(channel, FRAME_CREDIT, &payload).await
    }

    /// Resize an attached terminal.
    pub async fn write_resize(&mut self, channel: u32, cols: u16, rows: u16) -> Result<()> {
        let mut payload = [0u8; 4];
        payload[..2].copy_from_slice(&cols.to_le_bytes());
        payload[2..].copy_from_slice(&rows.to_le_bytes());
        self.write_frame(channel, FRAME_RESIZE, &payload).await
    }

    /// Detach from a channel.
    pub async fn close_channel(&mut self, channel: u32) -> Result<()> {
        self.write_frame(channel, FRAME_CLOSE, &[]).await
    }

    /// Send a JSON-RPC call on channel 0 and wait for its reply.
    ///
    /// Frames for other channels that arrive meanwhile are kept for
    /// [`Herdr::read_frame`] rather than dropped.
    async fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let mut line = serde_json::to_vec(&request)?;
        line.push(b'\n');
        self.write_frame(0, FRAME_DATA, &line).await?;

        loop {
            let frame = self.recv_frame().await?;
            match frame {
                Frame::Data(0, payload) => {
                    let reply: Value = serde_json::from_slice(&payload)
                        .with_context(|| format!("malformed reply to {method}"))?;
                    if reply.get("id").and_then(Value::as_u64) != Some(id) {
                        continue; // A notification, not our reply.
                    }
                    if let Some(error) = reply.get("error") {
                        let message = error
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown error");
                        let hint = error
                            .get("data")
                            .and_then(|data| data.get("hint"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if hint.is_empty() {
                            bail!("herdr-core {method} failed: {message}");
                        }
                        bail!("herdr-core {method} failed: {message} ({hint})");
                    }
                    return Ok(reply.get("result").cloned().unwrap_or(Value::Null));
                }
                other => self.deferred.push_back(other),
            }
        }
    }

    /// Write one frame to the connection.
    async fn write_frame(&mut self, channel: u32, kind: u8, payload: &[u8]) -> Result<()> {
        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&channel.to_le_bytes());
        header[4] = kind;
        header[5..9].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        self.writer.write_all(&header).await?;
        if !payload.is_empty() {
            self.writer.write_all(payload).await?;
        }
        self.writer.flush().await?;
        Ok(())
    }
}

/// Send a JSON-RPC call in plain mode, before framed mode begins.
async fn call_plain<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    id: u64,
    method: &str,
    params: Value,
) -> Result<Value>
where
    R: AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let request = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });
    let mut line = serde_json::to_vec(&request)?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await?;

    let mut reply = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            bail!("herdr-core closed the connection during {method}");
        }
        if byte[0] == b'\n' {
            break;
        }
        reply.push(byte[0]);
    }
    let reply: Value =
        serde_json::from_slice(&reply).with_context(|| format!("malformed reply to {method}"))?;
    if let Some(error) = reply.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        bail!("herdr-core {method} failed: {message}");
    }
    Ok(reply)
}

/// Read one frame from the connection.
async fn read_frame_raw<R>(reader: &mut BufReader<R>) -> Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .context("herdr-core connection closed")?;

    let channel = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let kind = header[4];
    let len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
    if len > MAX_PAYLOAD {
        bail!("herdr-core sent an oversized frame ({len} bytes)");
    }

    let mut payload = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut payload).await?;
    }

    Ok(match kind {
        FRAME_DATA => Frame::Data(channel, payload),
        FRAME_CREDIT => {
            let credit = payload
                .get(..4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            Frame::Credit(channel, credit)
        }
        FRAME_CLOSE => {
            let reason = serde_json::from_slice(&payload).ok();
            Frame::Close(channel, reason)
        }
        FRAME_RESIZE => {
            let cols = payload
                .get(..2)
                .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            let rows = payload
                .get(2..4)
                .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            Frame::Resize(channel, cols, rows)
        }
        other => Frame::Other(other, channel, payload),
    })
}

/// Resolve the socket for the current session.
///
/// Mirrors herdr-core's own search order: `HC_SOCKET`, then the runtime
/// directory, then the session's state directory.
pub fn default_endpoint() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("HC_SOCKET") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }

    let session = std::env::var("HC_SESSION").unwrap_or_else(|_| "default".to_string());
    let mut candidates = Vec::new();

    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime.is_empty() {
            candidates.push(
                Path::new(&runtime)
                    .join("herdr-core")
                    .join(format!("{session}.sock")),
            );
        }
    }

    #[cfg(unix)]
    if let Ok(home) = std::env::var("HOME") {
        let state = std::env::var("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| Path::new(&home).join(".local/state"));
        candidates.push(
            state
                .join("herdr-core")
                .join(&session)
                .join(format!("{session}.sock")),
        );
    }

    #[cfg(windows)]
    {
        // herdr-core listens on `\\.\pipe\herdr-core\<session>.sock` (or with a
        // per-account prefix in some setups; `HC_SOCKET` overrides when needed).
        candidates.push(PathBuf::from(format!(
            r"\\.\pipe\herdr-core\{session}.sock"
        )));
    }

    for candidate in &candidates {
        // On Windows named pipes (`\\.\pipe\...`), `Path::exists()` cannot
        // reliably probe without opening a handle; skip the existence check and
        // let `open_transport` connect directly.
        if cfg!(windows) || candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    candidates.into_iter().next().with_context(|| {
        "no herdr-core socket found; run `hc ls` to start the core, or pass --herdr-socket"
    })
}

#[cfg(unix)]
async fn open_transport(path: &Path) -> Result<Transport> {
    tokio::net::UnixStream::connect(path)
        .await
        .with_context(|| {
            format!(
                "connecting to herdr-core at {} (run `hc ls` to start the core)",
                path.display()
            )
        })
}

#[cfg(windows)]
async fn open_transport(path: &Path) -> Result<Transport> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let name = path.to_string_lossy();
    // Named pipes return ERROR_PIPE_BUSY (231) when all server instances are
    // momentarily accepting; retry briefly before failing.
    const ERROR_PIPE_BUSY: i32 = 231;
    for _ in 0..20 {
        match ClientOptions::new().open(name.as_ref()) {
            Ok(client) => return Ok(client),
            Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            Err(err) => {
                return Err(err).with_context(|| format!("connecting to herdr-core pipe {name}"));
            }
        }
    }
    ClientOptions::new()
        .open(name.as_ref())
        .with_context(|| format!("connecting to herdr-core pipe {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_roundtrip() {
        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&7u32.to_le_bytes());
        header[4] = FRAME_RESIZE;
        header[5..9].copy_from_slice(&4u32.to_le_bytes());

        assert_eq!(u32::from_le_bytes(header[0..4].try_into().unwrap()), 7);
        assert_eq!(header[4], FRAME_RESIZE);
        assert_eq!(u32::from_le_bytes(header[5..9].try_into().unwrap()), 4);
    }

    #[test]
    fn resize_payload_is_cols_then_rows() {
        let mut payload = [0u8; 4];
        payload[..2].copy_from_slice(&120u16.to_le_bytes());
        payload[2..].copy_from_slice(&40u16.to_le_bytes());

        let cols = u16::from_le_bytes(payload[..2].try_into().unwrap());
        let rows = u16::from_le_bytes(payload[2..4].try_into().unwrap());
        assert_eq!((cols, rows), (120, 40));
    }

    #[test]
    fn slot_is_scoped_to_the_workspace() {
        // Shell IDs restart at 1 in every run, so the workspace identifier is
        // what keeps two workspaces from claiming the same herdr terminal.
        let slot = |workspace: &str, sid: u32| format!("{workspace}-{sid}");

        assert_eq!(slot("k3f9x2mq7p1a", 1), "k3f9x2mq7p1a-1");
        assert_eq!(slot("z8w4n6rt5y2b", 1), "z8w4n6rt5y2b-1");
        assert_ne!(slot("k3f9x2mq7p1a", 1), slot("z8w4n6rt5y2b", 1));
    }

    fn encode_frame(channel: u32, kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(&channel.to_le_bytes());
        out.push(kind);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    async fn read_plain_line(
        reader: &mut BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    ) -> Value {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = reader.read(&mut byte).await.unwrap();
            assert!(n > 0);
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        serde_json::from_slice(&line).unwrap()
    }

    #[tokio::test]
    async fn deferred_frames_keep_fifo_order() {
        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let (sr, mut sw) = tokio::io::split(server);
            let mut sr = BufReader::new(sr);

            // 1. Handshake in plain mode.
            let req = read_plain_line(&mut sr).await;
            let reply = json!({ "jsonrpc": "2.0", "id": req["id"], "result": { "framed": true } });
            let mut raw = serde_json::to_vec(&reply).unwrap();
            raw.push(b'\n');
            sw.write_all(&raw).await.unwrap();
            sw.flush().await.unwrap();

            // 2. Read the framed RPC call on channel 0.
            let frame = read_frame_raw(&mut sr).await.unwrap();
            let req_id = match frame {
                Frame::Data(0, payload) => {
                    serde_json::from_slice::<Value>(&payload).unwrap()["id"].clone()
                }
                other => panic!("unexpected frame: {other:?}"),
            };

            // 3. Emit two channel-1 frames BEFORE the channel-0 RPC reply.
            sw.write_all(&encode_frame(1, FRAME_DATA, b"first"))
                .await
                .unwrap();
            sw.write_all(&encode_frame(1, FRAME_DATA, b"second"))
                .await
                .unwrap();
            let rpc_reply = json!({ "jsonrpc": "2.0", "id": req_id, "result": { "ok": true } });
            let mut rpc_raw = serde_json::to_vec(&rpc_reply).unwrap();
            rpc_raw.push(b'\n');
            sw.write_all(&encode_frame(0, FRAME_DATA, &rpc_raw))
                .await
                .unwrap();
            sw.flush().await.unwrap();
            (sr, sw)
        });

        let mut herdr = Herdr::from_stream(client).await.unwrap();
        let res = herdr.call("ping", json!({})).await.unwrap();
        assert_eq!(res["ok"], true);

        match herdr.read_frame().await.unwrap() {
            Frame::Data(1, data) => assert_eq!(data, b"first"),
            other => panic!("expected first frame, got {other:?}"),
        }
        match herdr.read_frame().await.unwrap() {
            Frame::Data(1, data) => assert_eq!(data, b"second"),
            other => panic!("expected second frame, got {other:?}"),
        }
        drop(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn read_frame_is_cancel_safe_under_select() {
        let (client, server) = tokio::io::duplex(65536);
        let expected: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
        let expected_send = expected.clone();

        let server_task = tokio::spawn(async move {
            let (sr, mut sw) = tokio::io::split(server);
            let mut sr = BufReader::new(sr);

            let req = read_plain_line(&mut sr).await;
            let reply = json!({ "jsonrpc": "2.0", "id": req["id"], "result": { "framed": true } });
            let mut raw = serde_json::to_vec(&reply).unwrap();
            raw.push(b'\n');
            sw.write_all(&raw).await.unwrap();
            sw.flush().await.unwrap();

            // Drip a 16 KiB frame in small chunks while the client keeps cancelling select!
            let frame = encode_frame(3, FRAME_DATA, &expected_send);
            for chunk in frame.chunks(127) {
                sw.write_all(chunk).await.unwrap();
                sw.flush().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            sw.write_all(&encode_frame(3, FRAME_CLOSE, b"{}"))
                .await
                .unwrap();
            sw.flush().await.unwrap();
        });

        let mut herdr = Herdr::from_stream(client).await.unwrap();
        let (tick_tx, mut tick_rx) = mpsc::channel::<()>(16);
        let ticker = tokio::spawn(async move {
            for _ in 0..40 {
                if tick_tx.send(()).await.is_err() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });

        let mut got = None;
        loop {
            tokio::select! {
                _ = tick_rx.recv() => {
                    // Cancels any pending `herdr.read_frame()` future repeatedly.
                }
                frame = herdr.read_frame() => {
                    match frame.unwrap() {
                        Frame::Data(3, data) => got = Some(data),
                        Frame::Close(3, _) => break,
                        other => panic!("unexpected frame: {other:?}"),
                    }
                }
            }
        }
        ticker.abort();
        server_task.await.unwrap();
        assert_eq!(got.as_deref(), Some(expected.as_slice()));
    }
}
