//! Network gRPC client allowing server control of terminals.

use std::collections::HashMap;
use std::pin::pin;

use anyhow::{Context, Result};
use sshx_core::proto::{
    client_update::ClientMessage, server_update::ServerMessage,
    sshx_service_client::SshxServiceClient, ClientUpdate, CloseRequest, NewShell, OpenRequest,
};
use sshx_core::{rand_alphanumeric, Sid};
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::{self, Duration, Instant, MissedTickBehavior};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

use crate::encrypt::Encrypt;
use crate::runner::{Runner, ShellData};
use crate::session_persistence::{SessionPersistence, SessionState};

/// Interval for sending empty heartbeat messages to the server.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

/// Interval to automatically reestablish connections.
const RECONNECT_INTERVAL: Duration = Duration::from_secs(60);

/// Handles a single session's communication with the remote server.
pub struct Controller {
    origin: String,
    runner: Runner,
    encrypt: Encrypt,
    encryption_key: String,

    name: String,
    token: String,
    url: String,
    write_url: Option<String>,

    /// Session persistence manager.
    persistence: SessionPersistence,
    /// Session ID for persistence.
    session_id: String,
    /// Whether this session was restored from disk.
    is_restored: bool,

    /// Channels with backpressure routing messages to each shell task.
    shells_tx: HashMap<Sid, mpsc::Sender<ShellData>>,
    /// Channel shared with tasks to allow them to output client messages.
    output_tx: mpsc::Sender<ClientMessage>,
    /// Owned receiving end of the `output_tx` channel.
    output_rx: mpsc::Receiver<ClientMessage>,
}

impl Controller {
    /// Construct a new controller, connecting to the remote server.
    /// Attempts to restore from a previous session if possible.
    pub async fn new(
        origin: &str,
        name: &str,
        runner: Runner,
        enable_readers: bool,
        api_key: Option<String>,
    ) -> Result<Self> {
        Self::new_with_persistence(origin, name, runner, enable_readers, api_key, true).await
    }

    /// Construct a new controller with optional session persistence.
    pub async fn new_with_persistence(
        origin: &str,
        name: &str,
        runner: Runner,
        enable_readers: bool,
        api_key: Option<String>,
        enable_persistence: bool,
    ) -> Result<Self> {
        debug!(%origin, "connecting to server");

        let persistence = SessionPersistence::new()?;
        let session_id = SessionPersistence::generate_session_id(
            api_key.as_deref(),
            origin,
            std::env::current_dir().ok().as_deref(),
        );

        // Try to restore existing session if persistence is enabled
        if enable_persistence {
            if let Some(restored_state) = persistence.load_session(&session_id)? {
                // Check if the session is still valid (not too old)
                if persistence.is_session_valid(&restored_state, 24) {
                    // Verify the session still exists on the server
                    if let Ok(controller) =
                        Self::restore_from_state(restored_state, runner.clone(), &persistence, &session_id)
                            .await
                    {
                        info!("Successfully restored session from previous run");
                        return Ok(controller);
                    } else {
                        warn!("Failed to restore session, creating new one");
                        // Remove invalid session file
                        let _ = persistence.remove_session(&session_id);
                    }
                } else {
                    info!("Previous session too old, creating new one");
                    // Remove expired session file
                    let _ = persistence.remove_session(&session_id);
                }
            }
        }

        // Create new session
        Self::create_new_session(
            origin,
            name,
            runner,
            enable_readers,
            api_key,
            persistence,
            session_id,
            enable_persistence,
        )
        .await
    }

    /// Create a completely new session.
    async fn create_new_session(
        origin: &str,
        name: &str,
        runner: Runner,
        enable_readers: bool,
        api_key: Option<String>,
        persistence: SessionPersistence,
        session_id: String,
        enable_persistence: bool,
    ) -> Result<Self> {
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

        let mut client = Self::connect(origin).await?;
        let encrypt = kdf_task.await?;
        let write_password_hash = if let Some(task) = kdf_write_password_task {
            Some(task.await?.zeros().into())
        } else {
            None
        };

        let req = OpenRequest {
            origin: origin.into(),
            encrypted_zeros: encrypt.zeros().into(),
            name: name.into(),
            write_password_hash,
            user_api_key: api_key.clone(),
        };
        let mut resp = client.open(req).await?.into_inner();
        resp.url = resp.url + "#" + &encryption_key;

        let write_url = if let Some(ref write_password) = write_password {
            Some(resp.url.clone() + "," + write_password)
        } else {
            None
        };

        // Save session state for future restoration
        if enable_persistence {
            let session_state = SessionState {
                session_id: session_id.clone(),
                encryption_key: encryption_key.clone(),
                write_password: write_password.clone(),
                session_name: resp.name.clone(),
                session_token: resp.token.clone(),
                base_url: resp.url.split('#').next().unwrap_or(&resp.url).to_string(),
                full_url: resp.url.clone(),
                write_url: write_url.clone(),
                server_origin: origin.to_string(),
                api_key: api_key.clone(),
                created_at: chrono::Utc::now().timestamp() as u64,
                last_accessed: chrono::Utc::now().timestamp() as u64,
            };

            if let Err(err) = persistence.save_session(&session_state) {
                warn!("Failed to save session state: {}", err);
            }
        }

        let (output_tx, output_rx) = mpsc::channel(64);
        Ok(Self {
            origin: origin.into(),
            runner,
            encrypt,
            encryption_key,
            name: resp.name,
            token: resp.token,
            url: resp.url,
            write_url,
            persistence,
            session_id,
            is_restored: false,
            shells_tx: HashMap::new(),
            output_tx,
            output_rx,
        })
    }

    /// Restore controller from saved session state.
    async fn restore_from_state(
        state: SessionState,
        runner: Runner,
        persistence: &SessionPersistence,
        session_id: &str,
    ) -> Result<Self> {
        debug!("Attempting to restore session: {}", state.session_name);

        // Recreate encryption objects
        let encrypt = {
            let encryption_key = state.encryption_key.clone();
            task::spawn_blocking(move || Encrypt::new(&encryption_key)).await?
        };

        // Test connection to server to verify session is still valid
        let mut client = Self::connect(&state.server_origin).await?;

        // Try to establish a channel connection to verify the session exists
        let hello = ClientMessage::Hello(format!("{},{}", state.session_name, state.session_token));
        let (tx, rx) = mpsc::channel(16);

        // Send hello message
        let update = ClientUpdate {
            client_message: Some(hello),
        };
        tx.send(update)
            .await
            .context("Failed to send hello message")?;

        // Try to establish channel - if this fails, the session doesn't exist
        let _resp = client
            .channel(ReceiverStream::new(rx))
            .await
            .context("Session no longer exists on server")?;

        // Session is valid, create controller
        let (output_tx, output_rx) = mpsc::channel(64);
        Ok(Self {
            origin: state.server_origin,
            runner,
            encrypt,
            encryption_key: state.encryption_key,
            name: state.session_name,
            token: state.session_token,
            url: state.full_url,
            write_url: state.write_url,
            persistence: persistence.clone(),
            session_id: session_id.to_string(),
            is_restored: true,
            shells_tx: HashMap::new(),
            output_tx,
            output_rx,
        })
    }

    /// Create a new gRPC client to the HTTP(S) origin.
    ///
    /// This is used on reconnection to the server, since some replicas may be
    /// gracefully shutting down, which means connected clients need to start a
    /// new TCP handshake.
    async fn connect(origin: &str) -> Result<SshxServiceClient<Channel>, tonic::transport::Error> {
        SshxServiceClient::connect(String::from(origin)).await
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

    /// Returns whether this session was restored from a previous run.
    pub fn is_restored(&self) -> bool {
        self.is_restored
    }

    /// Returns the session ID used for persistence.
    pub fn session_id(&self) -> &str {
        &self.session_id
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
        let (tx, rx) = mpsc::channel(16);

        let hello = ClientMessage::Hello(format!("{},{}", self.name, self.token));
        send_msg(&tx, hello).await?;

        let mut client = Self::connect(&self.origin).await?;
        let resp = client.channel(ReceiverStream::new(rx)).await?;
        let mut messages = resp.into_inner(); // A stream of server messages.

        let mut interval = time::interval(HEARTBEAT_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut reconnect = pin!(time::sleep(RECONNECT_INTERVAL));
        loop {
            let message = tokio::select! {
                _ = interval.tick() => {
                    tx.send(ClientUpdate::default()).await?;
                    continue;
                }
                msg = self.output_rx.recv() => {
                    let msg = msg.context("unreachable: output_tx was closed?")?;
                    send_msg(&tx, msg).await?;
                    continue;
                }
                item = messages.next() => {
                    item.context("server closed connection")??
                        .server_message
                        .context("server message is missing")?
                }
                _ = &mut reconnect => {
                    return Ok(()); // Reconnect to the server.
                }
            };

            match message {
                ServerMessage::Input(input) => {
                    let data = self.encrypt.segment(0x200000000, input.offset, &input.data);
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
        let (shell_tx, shell_rx) = mpsc::channel(16);
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

        // Remove session state from disk
        if let Err(err) = self.persistence.remove_session(&self.session_id) {
            warn!("Failed to remove session state: {}", err);
        }

        let req = CloseRequest {
            name: self.name.clone(),
            token: self.token.clone(),
        };
        let mut client = Self::connect(&self.origin).await?;
        client.close(req).await?;
        Ok(())
    }

    /// Update session access time for persistence.
    pub fn update_access_time(&self) {
        // This could be called periodically to update the last_accessed time
        // For now, we'll update it when the session is saved
    }

    /// Clean up old session files.
    pub fn cleanup_old_sessions(&self, max_age_days: u64) -> Result<usize> {
        self.persistence.cleanup_old_sessions(max_age_days)
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
