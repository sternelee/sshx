//! Defines tasks that control the behavior of a single shell in the client.

use anyhow::Result;
use encoding_rs::{CoderResult, UTF_8};
use sshx_core::proto::{client_update::ClientMessage, TerminalData};
use sshx_core::Sid;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

use crate::encrypt::Encrypt;
use crate::herdr::{Frame, Herdr};
use crate::terminal::Terminal;

const CONTENT_CHUNK_SIZE: usize = 1 << 16; // Send at most this many bytes at a time.
const CONTENT_ROLLING_BYTES: usize = 8 << 20; // Store at least this much content.
const CONTENT_PRUNE_BYTES: usize = 12 << 20; // Prune when we exceed this length.

/// Label key marking a herdr terminal as belonging to an sshx shell slot.
///
/// The value combines the persisted local workspace ID and the shell's ID, so a
/// restarted client reattaches to the terminal its predecessor left running
/// instead of starting another.
const SLOT_LABEL: &str = "sshx-slot";

/// Variants of terminal behavior that are used by the controller.
#[derive(Debug, Clone)]
pub enum Runner {
    /// Spawns the specified shell as a subprocess, forwarding PTYs.
    Shell(String),

    /// Runs the specified command in a herdr-core terminal, forwarding its
    /// bytes. The program outlives this client, so it can be reattached to.
    Herdr {
        /// Program and arguments, or a bare shell when empty.
        argv: Vec<String>,
        /// Socket to reach herdr-core on, when not the default.
        socket: Option<std::path::PathBuf>,
        /// Stable identifier for this machine's workspace, so a restarted client
        /// finds the terminals its predecessor left running.
        workspace: String,
    },

    /// Mock runner that only echos its input, useful for testing.
    Echo,
}

/// Internal message routed to shell runners.
pub enum ShellData {
    /// Sequence of input bytes from the server.
    Data(Vec<u8>),
    /// Information about the server's current sequence number.
    Sync(u64),
    /// Resize the shell to a different number of rows and columns.
    Size(u32, u32),
}

impl Runner {
    /// Asynchronous task to run a single shell with process I/O.
    pub async fn run(
        &self,
        id: Sid,
        encrypt: Encrypt,
        shell_rx: mpsc::Receiver<ShellData>,
        output_tx: mpsc::Sender<ClientMessage>,
    ) -> Result<()> {
        match self {
            Self::Shell(shell) => shell_task(id, encrypt, shell, shell_rx, output_tx).await,
            Self::Herdr {
                argv,
                socket,
                workspace,
            } => {
                herdr_task(
                    id,
                    encrypt,
                    argv,
                    socket.as_deref(),
                    workspace,
                    shell_rx,
                    output_tx,
                )
                .await
            }
            Self::Echo => echo_task(id, encrypt, shell_rx, output_tx).await,
        }
    }
}

/// Asynchronous task handling a single shell within the session.
async fn shell_task(
    id: Sid,
    encrypt: Encrypt,
    shell: &str,
    mut shell_rx: mpsc::Receiver<ShellData>,
    output_tx: mpsc::Sender<ClientMessage>,
) -> Result<()> {
    let mut term = Terminal::new(shell).await?;
    term.set_winsize(24, 80)?;

    let mut content = String::new(); // content from the terminal
    let mut content_offset = 0; // bytes before the first character of `content`
    let mut decoder = UTF_8.new_decoder(); // UTF-8 streaming decoder
    let mut seq = 0; // our log of the server's sequence number
    let mut seq_outdated = 0; // number of times seq has been outdated
    let mut buf = [0u8; 4096]; // buffer for reading
    let mut finished = false; // set when this is done

    while !finished {
        tokio::select! {
            result = term.read(&mut buf) => {
                let n = result?;
                if n == 0 {
                    finished = true;
                } else {
                    content.reserve(decoder.max_utf8_buffer_length(n).unwrap());
                    let (result, _, _) = decoder.decode_to_string(&buf[..n], &mut content, false);
                    debug_assert!(result == CoderResult::InputEmpty);
                }
            }
            item = shell_rx.recv() => {
                match item {
                    Some(ShellData::Data(data)) => {
                        term.write_all(&data).await?;
                    }
                    Some(ShellData::Sync(seq2)) => {
                        if seq2 < seq as u64 {
                            seq_outdated += 1;
                            if seq_outdated >= 3 {
                                seq = seq2 as usize;
                            }
                        }
                    }
                    Some(ShellData::Size(rows, cols)) => {
                        term.set_winsize(rows as u16, cols as u16)?;
                    }
                    None => finished = true, // Server closed this shell.
                }
            }
        }

        if finished {
            content.reserve(decoder.max_utf8_buffer_length(0).unwrap());
            let (result, _, _) = decoder.decode_to_string(&[], &mut content, true);
            debug_assert!(result == CoderResult::InputEmpty);
        }

        // Send data if the server has fallen behind.
        if content_offset + content.len() > seq {
            let start = prev_char_boundary(&content, seq - content_offset);
            let end = prev_char_boundary(&content, (start + CONTENT_CHUNK_SIZE).min(content.len()));
            let data = encrypt.segment(
                0x100000000 | id.0 as u64, // stream number
                (content_offset + start) as u64,
                &content.as_bytes()[start..end],
            );
            let data = TerminalData {
                id: id.0,
                data: data.into(),
                seq: (content_offset + start) as u64,
            };
            output_tx.send(ClientMessage::Data(data)).await?;
            seq = content_offset + end;
            seq_outdated = 0;
        }

        if content.len() > CONTENT_PRUNE_BYTES && seq - CONTENT_ROLLING_BYTES > content_offset {
            let pruned = (seq - CONTENT_ROLLING_BYTES) - content_offset;
            let pruned = prev_char_boundary(&content, pruned);
            content_offset += pruned;
            content.drain(..pruned);
        }
    }
    Ok(())
}

/// Find the last char boundary before an index in O(1) time.
fn prev_char_boundary(s: &str, i: usize) -> usize {
    (0..=i)
        .rev()
        .find(|&j| s.is_char_boundary(j))
        .expect("no previous char boundary")
}

async fn echo_task(
    id: Sid,
    encrypt: Encrypt,
    mut shell_rx: mpsc::Receiver<ShellData>,
    output_tx: mpsc::Sender<ClientMessage>,
) -> Result<()> {
    let mut seq = 0;
    while let Some(item) = shell_rx.recv().await {
        match item {
            ShellData::Data(data) => {
                let msg = String::from_utf8_lossy(&data);
                let term_data = TerminalData {
                    id: id.0,
                    data: encrypt
                        .segment(0x100000000 | id.0 as u64, seq, msg.as_bytes())
                        .into(),
                    seq,
                };
                output_tx.send(ClientMessage::Data(term_data)).await?;
                seq += msg.len() as u64;
            }
            ShellData::Sync(_) => (),
            ShellData::Size(_, _) => (),
        }
    }
    Ok(())
}

/// Asynchronous task relaying a herdr-core terminal to the session.
///
/// The program runs under herdr-core rather than as a child of this process, so
/// it survives this client exiting. This task owns the attach stream: it
/// forwards the terminal's bytes outward and the session's input inward, and
/// detaches when the session closes the shell rather than killing the program.
///
/// A terminal is reused across sessions: the slot label identifies it, so a
/// client that reconnects attaches to the program that is still running instead
/// of starting a second one.
async fn herdr_task(
    id: Sid,
    encrypt: Encrypt,
    argv: &[String],
    socket: Option<&std::path::Path>,
    workspace: &str,
    mut shell_rx: mpsc::Receiver<ShellData>,
    output_tx: mpsc::Sender<ClientMessage>,
) -> Result<()> {
    let mut herdr = Herdr::connect(socket).await?;

    // The session's own size arrives as a Size message; start at the same
    // default the PTY path uses so the first paint is not 0x0.
    let (rows, cols) = (24u16, 80u16);

    // Scope the slot to this machine's workspace, not the server's session name:
    // the server generates a fresh name per run, so only a local identifier can
    // find the terminal a previous run left behind.
    let slot = format!("{workspace}-{}", id.0);

    // Reattach to a terminal left running by an earlier session, if there is
    // one. Otherwise start a new program.
    let existing = herdr.find_live(SLOT_LABEL, &slot).await?;
    let (terminal, resumed) = match existing.into_iter().next() {
        Some(address) => {
            tracing::debug!(%id, %address, "reattaching to a running herdr terminal");
            (address, true)
        }
        None => (
            herdr
                .run_terminal(argv, cols, rows, SLOT_LABEL, &slot)
                .await?,
            false,
        ),
    };

    let channel = herdr.attach(&terminal, cols, rows, resumed).await?;
    relay_herdr(id, &encrypt, &mut herdr, channel, &mut shell_rx, &output_tx).await?;

    // The session is done with this shell, but the program keeps running under
    // herdr-core so a later session can attach to it again. Detaching only ends
    // this viewer's stream.
    herdr.close_channel(channel).await.ok();
    Ok(())
}

/// Relay bytes and control events on an already-attached herdr channel.
async fn relay_herdr(
    id: Sid,
    encrypt: &Encrypt,
    herdr: &mut Herdr,
    channel: u32,
    shell_rx: &mut mpsc::Receiver<ShellData>,
    output_tx: &mpsc::Sender<ClientMessage>,
) -> Result<()> {
    let mut content = String::new(); // content from the terminal
    let mut content_offset = 0; // bytes before the first character of `content`
    let mut decoder = UTF_8.new_decoder(); // UTF-8 streaming decoder
    let mut seq = 0; // our log of the server's sequence number
    let mut seq_outdated = 0; // number of times seq has been outdated
    let mut finished = false; // set when this is done

    while !finished {
        tokio::select! {
            frame = herdr.read_frame() => {
                match frame {
                    Ok(Frame::Data(ch, data)) if ch == channel => {
                        // Return credit so the core keeps sending.
                        if !data.is_empty() {
                            herdr.write_credit(channel, data.len()).await?;

                            content.reserve(decoder.max_utf8_buffer_length(data.len()).unwrap());
                            let (result, _, _) =
                                decoder.decode_to_string(&data, &mut content, false);
                            debug_assert!(result == CoderResult::InputEmpty);
                        }
                    }
                    Ok(Frame::Close(ch, reason)) if ch == channel => {
                        tracing::debug!(%id, ?reason, "herdr terminal closed");
                        finished = true;
                    }
                    Ok(Frame::Resize(ch, _new_cols, _new_rows)) if ch == channel => {
                        // Another viewer resized it; herdr-core owns the grid,
                        // so there is nothing to apply here.
                    }
                    Ok(_) => (),
                    Err(err) => {
                        tracing::warn!(%id, "herdr-core stream ended: {err:#}");
                        finished = true;
                    }
                }
            }
            item = shell_rx.recv() => {
                match item {
                    Some(ShellData::Data(data)) => {
                        herdr.write_data(channel, &data).await?;
                    }
                    Some(ShellData::Sync(seq2)) => {
                        if seq2 < seq as u64 {
                            seq_outdated += 1;
                            if seq_outdated >= 3 {
                                seq = (seq2 as usize).max(content_offset);
                            }
                        }
                    }
                    Some(ShellData::Size(new_rows, new_cols)) => {
                        herdr.write_resize(channel, new_cols as u16, new_rows as u16).await?;
                    }
                    None => finished = true, // Server closed this shell.
                }
            }
        }

        if finished {
            content.reserve(decoder.max_utf8_buffer_length(0).unwrap());
            let (result, _, _) = decoder.decode_to_string(&[], &mut content, true);
            debug_assert!(result == CoderResult::InputEmpty);
        }

        // Drain all buffered data in chunks so large initial repaints or sync
        // catch-ups do not stall waiting for the next frame.
        while content_offset + content.len() > seq {
            let start = prev_char_boundary(&content, seq.saturating_sub(content_offset));
            let end = prev_char_boundary(&content, (start + CONTENT_CHUNK_SIZE).min(content.len()));
            if end == start {
                break;
            }
            let data = encrypt.segment(
                0x100000000 | id.0 as u64, // stream number
                (content_offset + start) as u64,
                &content.as_bytes()[start..end],
            );
            let data = TerminalData {
                id: id.0,
                data: data.into(),
                seq: (content_offset + start) as u64,
            };
            output_tx.send(ClientMessage::Data(data)).await?;
            seq = content_offset + end;
            seq_outdated = 0;
        }

        if content.len() > CONTENT_PRUNE_BYTES
            && seq.saturating_sub(CONTENT_ROLLING_BYTES) > content_offset
        {
            let pruned = (seq - CONTENT_ROLLING_BYTES) - content_offset;
            let pruned = prev_char_boundary(&content, pruned);
            content_offset += pruned;
            content.drain(..pruned);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use super::*;

    #[tokio::test]
    async fn relay_herdr_drains_large_frame_before_waiting() {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let payload_len = CONTENT_CHUNK_SIZE * 2 + 123;
        let big_payload = "A".repeat(payload_len);
        let big_bytes = big_payload.as_bytes().to_vec();

        // Keep server half alive until client exits so the stream stays open
        // while we check that all chunks arrive without waiting for a second frame.
        let server_task = tokio::spawn(async move {
            let (sr, mut sw) = tokio::io::split(server);
            let mut sr = BufReader::new(sr);
            let mut line = String::new();
            sr.read_line(&mut line).await.unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            let reply = json!({ "jsonrpc": "2.0", "id": req["id"], "result": { "framed": true } });
            let mut raw = serde_json::to_vec(&reply).unwrap();
            raw.push(b'\n');
            sw.write_all(&raw).await.unwrap();

            // Send one 128+ KiB DATA frame on channel 1, then stay quiet!
            let mut frame = Vec::with_capacity(9 + big_bytes.len());
            frame.extend_from_slice(&1u32.to_le_bytes());
            frame.push(0u8); // FRAME_DATA
            frame.extend_from_slice(&(big_bytes.len() as u32).to_le_bytes());
            frame.extend_from_slice(&big_bytes);
            sw.write_all(&frame).await.unwrap();
            sw.flush().await.unwrap();
            (sr, sw)
        });

        let mut herdr = Herdr::from_stream(client).await.unwrap();
        let encrypt = Encrypt::new("test-key");
        let encrypt_check = encrypt.clone();
        let (_shell_tx, mut shell_rx) = mpsc::channel(8);
        let (output_tx, mut output_rx) = mpsc::channel(16);

        let relay = tokio::spawn(async move {
            relay_herdr(Sid(1), &encrypt, &mut herdr, 1, &mut shell_rx, &output_tx)
                .await
                .unwrap();
        });

        let mut received = Vec::new();
        while received.len() < payload_len {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(2), output_rx.recv())
                .await
                .expect("timed out waiting for remaining chunks")
                .expect("output channel closed early");
            match msg {
                ClientMessage::Data(td) => {
                    assert_eq!(td.seq, received.len() as u64);
                    let plain = encrypt_check.segment(0x100000000 | 1, td.seq, &td.data);
                    received.extend_from_slice(&plain);
                }
                other => panic!("unexpected message: {other:?}"),
            }
        }
        assert_eq!(received.len(), payload_len);
        assert!(received.iter().all(|&b| b == b'A'));

        drop(_shell_tx);
        relay.await.unwrap();
        drop(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn relay_herdr_clamps_stale_sync_below_content_offset() {
        let (client, server) = tokio::io::duplex(256 * 1024);
        // Send enough bytes in chunks to trigger pruning (`CONTENT_PRUNE_BYTES` = 12 MiB).
        let chunk_len = 1 << 20; // 1 MiB
        let total_chunks = 14usize; // 14 MiB > 12 MiB -> prunes ~6 MiB

        let server_task = tokio::spawn(async move {
            let (sr, mut sw) = tokio::io::split(server);
            let mut sr = BufReader::new(sr);
            let mut line = String::new();
            sr.read_line(&mut line).await.unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            let reply = json!({ "jsonrpc": "2.0", "id": req["id"], "result": { "framed": true } });
            let mut raw = serde_json::to_vec(&reply).unwrap();
            raw.push(b'\n');
            sw.write_all(&raw).await.unwrap();
            sw.flush().await.unwrap();

            let payload = vec![b'B'; chunk_len];
            let mut header = [0u8; 9];
            header[0..4].copy_from_slice(&1u32.to_le_bytes());
            header[4] = 0u8;
            header[5..9].copy_from_slice(&(payload.len() as u32).to_le_bytes());
            for _ in 0..total_chunks {
                sw.write_all(&header).await.unwrap();
                sw.write_all(&payload).await.unwrap();
            }
            sw.flush().await.unwrap();
            (sr, sw)
        });

        let mut herdr = Herdr::from_stream(client).await.unwrap();
        let encrypt = Encrypt::new("test-key");
        let (shell_tx, mut shell_rx) = mpsc::channel(16);
        let (output_tx, mut output_rx) = mpsc::channel(256);

        let relay = tokio::spawn(async move {
            relay_herdr(Sid(1), &encrypt, &mut herdr, 1, &mut shell_rx, &output_tx)
                .await
                .unwrap();
        });

        // Drain all 14 MiB so pruning advances `content_offset` past 0.
        let mut received_bytes = 0usize;
        let expected_total = chunk_len * total_chunks;
        while received_bytes < expected_total {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(5), output_rx.recv())
                .await
                .expect("timed out draining 14 MiB")
                .expect("output channel closed early");
            if let ClientMessage::Data(td) = msg {
                received_bytes += td.data.len();
            }
        }

        // Send 3 stale Sync(0) messages; previously this underflowed `seq - content_offset`.
        for _ in 0..3 {
            shell_tx.send(ShellData::Sync(0)).await.unwrap();
        }

        // Must replay from the earliest retained offset (`content_offset > 0`), without panicking.
        let replayed = tokio::time::timeout(std::time::Duration::from_secs(2), output_rx.recv())
            .await
            .expect("timed out waiting for clamped replay")
            .expect("output channel closed");
        match replayed {
            ClientMessage::Data(td) => {
                assert!(td.seq > 0, "expected clamped seq > 0, got {}", td.seq);
            }
            other => panic!("unexpected message: {other:?}"),
        }

        drop(shell_tx);
        relay.await.unwrap();
        drop(server_task.await.unwrap());
    }
}
