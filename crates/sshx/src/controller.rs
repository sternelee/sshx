//! Network client allowing server control of terminals over HTTP and WebSocket.

use std::collections::HashMap;
use std::pin::pin;

use anyhow::{Context, Result};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sshx_core::proto::{
    client_update::ClientMessage, server_update::ServerMessage, ClientUpdate, NewShell,
    ServerUpdate,
};
use sshx_core::{rand_alphanumeric, Sid};
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::{self, Duration, Instant, MissedTickBehavior};
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tracing::{debug, error, warn};

use crate::encrypt::Encrypt;
use crate::runner::{Runner, ShellData};

/// Interval for sending empty heartbeat messages to the server.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

/// Interval to automatically reestablish connections.
const RECONNECT_INTERVAL: Duration = Duration::from_secs(60);

/// JSON request body for opening a session.
#[derive(Serialize)]
struct OpenBody {
    origin: String,
    encrypted_zeros: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    write_password_hash: Option<String>,
}

/// JSON response body from opening a session.
#[derive(Deserialize)]
struct OpenResp {
    name: String,
    token: String,
    url: String,
}

/// JSON request body for closing a session.
#[derive(Serialize)]
struct CloseBody {
    name: String,
    token: String,
}

/// Handles a single session's communication with the remote server.
pub struct Controller {
    origin: String,
    http_client: HttpClient,
    runner: Runner,
    encrypt: Encrypt,
    encryption_key: String,

    name: String,
    token: String,
    url: String,
    write_url: Option<String>,

    /// Channels with backpressure routing messages to each shell task.
    shells_tx: HashMap<Sid, mpsc::Sender<ShellData>>,
    /// Channel shared with tasks to allow them to output client messages.
    output_tx: mpsc::Sender<ClientMessage>,
    /// Owned receiving end of the `output_tx` channel.
    output_rx: mpsc::Receiver<ClientMessage>,
}

impl Controller {
    /// Construct a new controller, connecting to the remote server.
    pub async fn new(
        origin: &str,
        name: &str,
        runner: Runner,
        enable_readers: bool,
    ) -> Result<Self> {
        debug!(%origin, "connecting to server");
        let encryption_key = rand_alphanumeric(14); // 83.3 bits of entropy

        let kdf_task = {
            let encryption_key = encryption_key.clone();
            task::spawn_blocking(move || Encrypt::new(&encryption_key))
        };

        let (write_password, kdf_write_password_task) = if enable_readers {
            let write_password = rand_alphanumeric(14); // 83.3 bits of entropy
            let task = {
                let write_password = write_password.clone();
                task::spawn_blocking(move || Encrypt::new(&write_password))
            };
            (Some(write_password), Some(task))
        } else {
            (None, None)
        };

        let http_client = HttpClient::new();
        let encrypt = kdf_task.await?;
        let write_password_hash = if let Some(task) = kdf_write_password_task {
            Some(task.await?.zeros())
        } else {
            None
        };

        let req = OpenBody {
            origin: origin.into(),
            encrypted_zeros: BASE64_STANDARD.encode(encrypt.zeros()),
            name: name.into(),
            write_password_hash: write_password_hash.map(|b| BASE64_STANDARD.encode(b)),
        };
        let mut resp = http_client
            .post(format!("{origin}/api/open"))
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json::<OpenResp>()
            .await?;
        resp.url = resp.url + "#" + &encryption_key;

        let write_url = if let Some(write_password) = write_password {
            Some(resp.url.clone() + "," + &write_password)
        } else {
            None
        };

        let (output_tx, output_rx) = mpsc::channel(256);
        Ok(Self {
            origin: origin.into(),
            http_client,
            runner,
            encrypt,
            encryption_key,
            name: resp.name,
            token: resp.token,
            url: resp.url,
            write_url,
            shells_tx: HashMap::new(),
            output_tx,
            output_rx,
        })
    }

    /// Returns the name of the session.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the URL of the session.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the write URL of the session, if it exists.
    pub fn write_url(&self) -> Option<&str> {
        self.write_url.as_deref()
    }

    /// Returns the encryption key for this session, hidden from the server.
    pub fn encryption_key(&self) -> &str {
        &self.encryption_key
    }

    /// Run the controller forever, listening for requests from the server.
    pub async fn run(&mut self) -> ! {
        let mut last_retry = Instant::now();
        let mut retries = 0;
        loop {
            if let Err(err) = self.try_channel().await {
                if last_retry.elapsed() >= Duration::from_secs(10) {
                    retries = 0;
                }
                let secs = 2_u64.pow(retries.min(4));
                error!(%err, "disconnected, retrying in {secs}s...");
                time::sleep(Duration::from_secs(secs)).await;
                retries += 1;
            }
            last_retry = Instant::now();
        }
    }

    /// Helper function used by `run()` that can return errors.
    async fn try_channel(&mut self) -> Result<()> {
        let ws_url = self
            .origin
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        let ws_url = format!("{ws_url}/api/backend/{}", self.name);

        let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url).await?;
        let (mut ws_write, mut ws_read) = ws_stream.split();

        // Send the hello message as the first protobuf frame.
        let hello = ClientMessage::Hello(format!("{},{}", self.name, self.token));
        let hello_update = ClientUpdate {
            client_message: Some(hello),
        };
        let mut hello_buf = Vec::new();
        hello_update.encode(&mut hello_buf)?;
        ws_write.send(WsMessage::Binary(hello_buf.into())).await?;

        // Bridge the internal mpsc channel to the WebSocket writer.
        let (tx, mut rx) = mpsc::channel::<ClientUpdate>(256);
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                let mut buf = Vec::new();
                if update.encode(&mut buf).is_ok() {
                    if ws_write.send(WsMessage::Binary(buf.into())).await.is_err() {
                        break;
                    }
                }
            }
        });

        let mut interval = time::interval(HEARTBEAT_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut reconnect = pin!(time::sleep(RECONNECT_INTERVAL));
        loop {
            let message = tokio::select! {
                // Send periodic heartbeat messages to the server.
                _ = interval.tick() => {
                    tx.send(ClientUpdate::default()).await.ok();
                    continue;
                }
                // Send buffered server updates to the client.
                msg = self.output_rx.recv() => {
                    let msg = msg.context("unreachable: output_tx was closed?")?;
                    send_msg(&tx, msg).await?;
                    interval.reset();
                    continue;
                }
                // Handle incoming WebSocket messages.
                item = ws_read.next() => {
                    match item {
                        Some(Ok(WsMessage::Binary(data))) => {
                            let update = ServerUpdate::decode(&*data)
                                .context("failed to decode server update")?;
                            match update.server_message {
                                Some(msg) => msg,
                                None => continue, // heartbeat
                            }
                        }
                        Some(Ok(WsMessage::Close(_))) | None => {
                            return Ok(()); // Graceful close, trigger reconnect.
                        }
                        Some(Ok(_)) => continue, // Ignore text/ping/pong frames.
                        Some(Err(err)) => return Err(err.into()),
                    }
                }
                // Automatically reconnect after a fixed interval.
                _ = &mut reconnect => {
                    return Ok(());
                }
            };

            match message {
                ServerMessage::Input(input) => {
                    let data = self
                        .encrypt
                        .decrypt(0x200000000, input.offset, &input.data)
                        .expect("failed to decrypt input");
                    if let Some(sender) = self.shells_tx.get(&Sid(input.id)) {
                        // This line applies backpressure if the shell task is overloaded.
                        sender.send(ShellData::Data(data)).await.ok();
                    } else {
                        warn!(%input.id, "received data for non-existing shell");
                    }
                }
                ServerMessage::CreateShell(new_shell) => {
                    let id = Sid(new_shell.id);
                    let center = (new_shell.x, new_shell.y);
                    if !self.shells_tx.contains_key(&id) {
                        self.spawn_shell_task(id, center);
                    } else {
                        warn!(%id, "server asked to create duplicate shell");
                    }
                }
                ServerMessage::CloseShell(id) => {
                    // Closes the channel when it is dropped, notifying the task to shut down.
                    self.shells_tx.remove(&Sid(id));
                    send_msg(&tx, ClientMessage::ClosedShell(id)).await?;
                }
                ServerMessage::Sync(seqnums) => {
                    for (id, seq) in seqnums.map {
                        if let Some(sender) = self.shells_tx.get(&Sid(id)) {
                            sender.send(ShellData::Sync(seq)).await.ok();
                        } else {
                            warn!(%id, "received sequence number for non-existing shell");
                            send_msg(&tx, ClientMessage::ClosedShell(id)).await?;
                        }
                    }
                }
                ServerMessage::Resize(msg) => {
                    if let Some(sender) = self.shells_tx.get(&Sid(msg.id)) {
                        sender.send(ShellData::Size(msg.rows, msg.cols)).await.ok();
                    } else {
                        warn!(%msg.id, "received resize for non-existing shell");
                    }
                }
                ServerMessage::Ping(ts) => {
                    // Echo back the timestamp, for stateless latency measurement.
                    send_msg(&tx, ClientMessage::Pong(ts)).await?;
                }
                ServerMessage::Error(err) => {
                    error!(?err, "error received from server");
                }
            }
        }
    }

    /// Entry point to start a new terminal task on the client.
    fn spawn_shell_task(&mut self, id: Sid, center: (i32, i32)) {
        let (shell_tx, shell_rx) = mpsc::channel(256);
        let opt = self.shells_tx.insert(id, shell_tx);
        debug_assert!(opt.is_none(), "shell ID cannot be in existing tasks");

        let runner = self.runner.clone();
        let encrypt = self.encrypt.clone();
        let output_tx = self.output_tx.clone();
        tokio::spawn(async move {
            debug!(%id, "spawning new shell");
            let new_shell = NewShell {
                id: id.0,
                x: center.0,
                y: center.1,
            };
            if let Err(err) = output_tx.send(ClientMessage::CreatedShell(new_shell)).await {
                error!(%id, ?err, "failed to send shell creation message");
                return;
            }
            if let Err(err) = runner.run(id, encrypt, shell_rx, output_tx.clone()).await {
                let err = ClientMessage::Error(err.to_string());
                output_tx.send(err).await.ok();
            }
            output_tx.send(ClientMessage::ClosedShell(id.0)).await.ok();
        });
    }

    /// Terminate this session gracefully.
    pub async fn close(&self) -> Result<()> {
        debug!("closing session");
        let req = CloseBody {
            name: self.name.clone(),
            token: self.token.clone(),
        };
        self.http_client
            .post(format!("{}/api/close", self.origin))
            .json(&req)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

/// Attempt to send a client message over an update channel.
async fn send_msg(tx: &mpsc::Sender<ClientUpdate>, message: ClientMessage) -> Result<()> {
    let update = ClientUpdate {
        client_message: Some(message),
    };
    tx.send(update)
        .await
        .context("failed to send message to server")
}
