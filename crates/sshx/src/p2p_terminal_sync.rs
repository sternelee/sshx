//! P2P terminal synchronization logic

use anyhow::Result;
use encoding_rs::{CoderResult, UTF_8};
use std::io::{self, Read};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task;
use tokio::time::{sleep, Instant};
use tracing::{debug, error, info};

use crate::p2p::P2pTransport;
use crate::p2p_events::{EventType, TerminalEvent};
use crate::terminal::Terminal;

const INPUT_BUFFER_SIZE: usize = 1024;

/// P2P terminal synchronization that mimics the original server mode behavior
pub struct P2PTerminalSync {
    transport: P2pTransport,
    terminal: Terminal,
    shell: String,
    is_host: bool,
}

impl P2PTerminalSync {
    pub async fn new(mut transport: P2pTransport, terminal: Terminal, is_host: bool) -> Self {
        let shell = transport.shell_command.clone();
        Self {
            transport,
            terminal,
            shell,
            is_host,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Starting P2P terminal synchronization");

        if self.is_host {
            self.run_host_mode().await
        } else {
            self.run_client_mode().await
        }
    }

    /// Host mode: Run terminal and broadcast output to peers while handling peer input
    async fn run_host_mode(&mut self) -> Result<()> {
        info!("Running P2P terminal in host mode");

        let mut content = String::new();
        let mut content_offset = 0;
        let mut decoder = UTF_8.new_decoder();
        let mut buf = [0u8; 4096];
        let mut finished = false;

        while !finished {
            tokio::select! {
                // Read terminal output and send to peers
                result = self.terminal.read(&mut buf) => {
                    let n = result?;
                    if n == 0 {
                        finished = true;
                    } else {
                        content.reserve(decoder.max_utf8_buffer_length(n).unwrap());
                        let (result, _, _) = decoder.decode_to_string(&buf[..n], &mut content, false);
                        debug_assert!(result == CoderResult::InputEmpty);

                        // Send terminal output to P2P network
                        if let Err(e) = self.send_terminal_output(&content[content_offset..]).await {
                            error!("Failed to send terminal output: {}", e);
                        }
                        content_offset = content.len();
                    }
                }

                // Handle P2P input from peers and write to local terminal
                p2p_message = self.transport.recv_input_or_event() => {
                    if let Some(msg) = p2p_message {
                        match msg {
                            crate::p2p::P2pMessage::Input(input) => {
                                debug!("Host received input from peer: {:?}", input);
                                if let Err(e) = self.handle_terminal_input(&input).await {
                                    error!("Failed to handle peer input: {}", e);
                                }
                            }
                            crate::p2p::P2pMessage::Event(event) => {
                                debug!("Host received event: {:?}", event);
                                let should_end = event.event_type == EventType::End;
                                if let Err(e) = self.handle_p2p_event(event).await {
                                    error!("Failed to handle P2P event: {}", e);
                                }
                                if should_end {
                                    finished = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        info!("Terminal session ended");
        Ok(())
    }

    /// Client mode: Display terminal output from host while sending local input
    async fn run_client_mode(&mut self) -> Result<()> {
        info!("Running P2P terminal in client mode");

        let mut finished = false;

        // Spawn stdin reader task for local input
        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);

        task::spawn(async move {
            let mut stdin = io::stdin();
            loop {
                let mut buffer = vec![0u8; INPUT_BUFFER_SIZE];
                match stdin.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        buffer.truncate(n);
                        if stdin_tx.send(buffer).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        while !finished {
            tokio::select! {
                // Handle P2P events (terminal output from host)
                p2p_message = self.transport.recv_input_or_event() => {
                    if let Some(msg) = p2p_message {
                        match msg {
                            crate::p2p::P2pMessage::Input(input) => {
                                debug!("Client received input from peer: {:?}", input);
                                // In client mode, we might receive input from other clients
                                // Forward this input to the host
                                if let Err(e) = self.transport.send_input(input).await {
                                    error!("Failed to forward peer input to host: {}", e);
                                }
                            }
                            crate::p2p::P2pMessage::Event(event) => {
                                debug!("Client received event: {:?}", event);
                                let should_end = event.event_type == EventType::End;
                                if let Err(e) = self.handle_p2p_event(event).await {
                                    error!("Error handling P2P event: {}", e);
                                }
                                if should_end {
                                    finished = true;
                                }
                            }
                        }
                    }
                }

                // Handle local terminal input (send to host)
                input_data = stdin_rx.recv() => {
                    if let Some(data) = input_data {
                        let input = String::from_utf8_lossy(&data);
                        debug!("Client sending local input to host: {:?}", input);
                        if let Err(e) = self.transport.send_input(input.to_string()).await {
                            error!("Failed to send input to host: {}", e);
                        }
                    } else {
                        // Stdin closed
                        debug!("Stdin closed, ending client session");
                        finished = true;
                    }
                }

                // Periodic check to keep the loop responsive
                _ = sleep(Duration::from_millis(100)) => {
                    // Keep the loop responsive
                }
            }
        }

        info!("Client session ended");
        Ok(())
    }

    /// Send terminal output to P2P network
    async fn send_terminal_output(&self, data: &str) -> Result<()> {
        if let Err(e) = self.transport.send_terminal_output(data.to_string()).await {
            error!("Failed to send terminal output to P2P: {}", e);
        }
        Ok(())
    }

    /// Handle terminal input from peers (host mode only)
    async fn handle_terminal_input(&mut self, input: &str) -> Result<()> {
        debug!("Writing input to terminal: {:?}", input);
        // Write input to terminal
        self.terminal.write_all(input.as_bytes()).await?;
        self.terminal.flush().await?;
        Ok(())
    }

    /// Handle P2P events (resize, session end, etc.)
    async fn handle_p2p_event(&mut self, event: TerminalEvent) -> Result<()> {
        match event.event_type {
            EventType::Output => {
                if !self.is_host {
                    // Client: display output from host
                    debug!("Client displaying output from host: {}", event.data);
                    // Write output to client's terminal
                    self.terminal.write_all(event.data.as_bytes()).await?;
                    self.terminal.flush().await?;
                }
            }
            EventType::Input => {
                debug!("Received input event: {}", event.data);
                // Input events are handled by recv_input
            }
            EventType::Resize { width, height } => {
                debug!("Terminal resize event: {}x{}", width, height);
                if !self.is_host {
                    // Client: resize local terminal
                    if let Err(e) = self.terminal.set_winsize(width, height) {
                        error!("Failed to resize terminal: {}", e);
                    }
                }
            }
            EventType::End => {
                info!("Received session end event");
                return Err(anyhow::anyhow!("Session ended"));
            }
        }
        Ok(())
    }
}
