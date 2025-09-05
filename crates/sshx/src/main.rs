use std::process::ExitCode;

use ansi_term::Color::{Cyan, Fixed, Green};
use anyhow::Result;
use clap::Parser;
use sshx::{
    controller::Controller,
    p2p::{P2pConfig, P2pTransport},
    p2p_terminal_sync::P2PTerminalSync,
    runner::Runner,
    session_persistence::SessionPersistence,
    terminal::{get_default_shell, Terminal},
};
use sshx_core::rand_alphanumeric;
use tokio::signal;
use tracing::{error, info};

/// A secure web-based, collaborative terminal.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Address of the remote sshx server.
    #[clap(long, default_value = "https://sshx.io", env = "SSHX_SERVER")]
    server: String,

    /// Local shell command to run in the terminal.
    #[clap(long)]
    shell: Option<String>,

    /// Quiet mode, only prints the URL to stdout.
    #[clap(short, long)]
    quiet: bool,

    /// Session name displayed in the title (defaults to user@hostname).
    #[clap(long)]
    name: Option<String>,

    /// Enable read-only access mode - generates separate URLs for viewers and
    /// editors.
    #[clap(long)]
    enable_readers: bool,

    /// User API key for authenticated sessions.
    /// When provided, enables session persistence to maintain consistent URLs across restarts.
    #[clap(long, env = "SSHX_API_KEY")]
    api_key: Option<String>,

    /// Enable peer-to-peer mode using iroh protocol for direct terminal sharing.
    /// This bypasses the central server and creates a direct P2P connection.
    #[clap(long)]
    p2p: bool,

    /// Join an existing P2P session using a session URL.
    #[clap(long)]
    join: Option<String>,

    /// Clean up old session files (older than specified days).
    #[clap(long)]
    cleanup_sessions: Option<u64>,

    /// Relay servers for P2P mode.
    #[clap(long)]
    relay_servers: Option<Vec<String>>,
}

fn print_greeting(shell: &str, controller: &Controller) {
    let version_str = match option_env!("CARGO_PKG_VERSION") {
        Some(version) => format!("v{version}"),
        None => String::from("[dev]"),
    };

    let status_indicator = if controller.is_restored() {
        format!(" {}", Fixed(8).paint("(restored)"))
    } else {
        String::new()
    };

    if let Some(write_url) = controller.write_url() {
        println!(
            r#"
  {sshx} {version}{status}

  {arr}  Read-only link: {link_v}
  {arr}  Writable link:  {link_e}
  {arr}  Shell:          {shell_v}
"#,
            sshx = Green.bold().paint("sshx"),
            version = Green.paint(&version_str),
            status = status_indicator,
            arr = Green.paint("➜"),
            link_v = Cyan.underline().paint(controller.url()),
            link_e = Cyan.underline().paint(write_url),
            shell_v = Fixed(8).paint(shell),
        );
    } else {
        println!(
            r#"
  {sshx} {version}{status}

  {arr}  Link:  {link_v}
  {arr}  Shell: {shell_v}
"#,
            sshx = Green.bold().paint("sshx"),
            version = Green.paint(&version_str),
            status = status_indicator,
            arr = Green.paint("➜"),
            link_v = Cyan.underline().paint(controller.url()),
            shell_v = Fixed(8).paint(shell),
        );
    }
}

#[tokio::main]
async fn start(args: Args) -> Result<()> {
    // Handle session cleanup if requested
    if let Some(max_age_days) = args.cleanup_sessions {
        let persistence = SessionPersistence::new()?;
        let removed_count = persistence.cleanup_old_sessions(max_age_days)?;
        println!("Cleaned up {} old session files", removed_count);
        return Ok(());
    }

    let shell = match args.shell {
        Some(ref shell) => shell.clone(),
        None => get_default_shell().await,
    };

    let name = args.name.clone().unwrap_or_else(|| {
        let mut name = whoami::username();
        if let Ok(host) = whoami::fallible::hostname() {
            // Trim domain information like .lan or .local
            let host = host.split('.').next().unwrap_or(&host);
            name += "@";
            name += host;
        }
        name
    });

    if args.p2p || args.join.is_some() {
        start_p2p_mode(args, shell, name).await
    } else {
        start_server_mode(args, shell, name).await
    }
}

async fn start_server_mode(args: Args, shell: String, name: String) -> Result<()> {
    let runner = Runner::Shell(shell.clone());

    // Enable session persistence only when using API key
    let enable_persistence = args.api_key.is_some();

    let mut controller = Controller::new_with_persistence(
        &args.server,
        &name,
        runner,
        args.enable_readers,
        args.api_key,
        enable_persistence,
    )
    .await?;

    if args.quiet {
        if let Some(write_url) = controller.write_url() {
            println!("{}", write_url);
        } else {
            println!("{}", controller.url());
        }
    } else {
        print_greeting(&shell, &controller);
    }

    let exit_signal = signal::ctrl_c();
    tokio::pin!(exit_signal);
    tokio::select! {
        _ = controller.run() => unreachable!(),
        Ok(()) = &mut exit_signal => (),
    };
    controller.close().await?;

    Ok(())
}

async fn start_p2p_mode(args: Args, shell: String, name: String) -> Result<()> {
    if let Some(join_url) = args.join {
        // Join existing P2P session
        start_p2p_client(join_url, name, shell, args.quiet).await
    } else {
        // Create new P2P session
        start_p2p_host(args, shell, name).await
    }
}

async fn start_p2p_host(args: Args, shell: String, name: String) -> Result<()> {
    info!("Starting P2P host session");

    // Generate a token for the P2P session
    let token = rand_alphanumeric(16);

    // Create P2P transport configuration
    let p2p_config = P2pConfig {
        token: token.clone(),
        name: name.clone(),
        is_host: true,
        relay_servers: args.relay_servers.unwrap_or_default(),
    };

    let mut transport = P2pTransport::new(p2p_config, shell.clone()).await?;
    let ticket = transport.start().await?;

    let p2p_url = transport.create_session_url(&ticket);

    if args.quiet {
        println!("{}", p2p_url);
    } else {
        print_p2p_greeting(&shell, &name, &p2p_url, &token);
    }

    // Create terminal
    let mut terminal = Terminal::new(&shell).await?;

    // Create P2P terminal sync
    let mut sync = P2PTerminalSync::new(transport, terminal, true).await;

    let exit_signal = signal::ctrl_c();
    tokio::pin!(exit_signal);
    tokio::select! {
        result = sync.run() => {
            if let Err(e) = result {
                error!("P2P sync error: {}", e);
            }
        },
        Ok(()) = &mut exit_signal => {
            info!("Received Ctrl+C, shutting down P2P session");
        },
    }

    Ok(())
}

async fn start_p2p_client(
    join_url: String,
    name: String,
    shell: String,
    quiet: bool,
) -> Result<()> {
    info!("Joining P2P session: {}", join_url);

    let mut transport = P2pTransport::join_session(&join_url, &name, shell.clone()).await?;
    let connection_info = transport.start().await?;

    if !quiet {
        println!("Connected to P2P session: {}", connection_info);
    }

    // Create terminal
    let mut terminal = Terminal::new(&shell).await?;

    // Create P2P terminal sync (client mode)
    let mut sync = P2PTerminalSync::new(transport, terminal, false).await;

    let exit_signal = signal::ctrl_c();
    tokio::pin!(exit_signal);
    tokio::select! {
        result = sync.run() => {
            if let Err(e) = result {
                error!("P2P sync error: {}", e);
            }
        },
        Ok(()) = &mut exit_signal => {
            info!("Received Ctrl+C, disconnecting from P2P session");
        },
    }

    Ok(())
}

fn print_p2p_greeting(shell: &str, name: &str, p2p_url: &str, token: &str) {
    let version_str = match option_env!("CARGO_PKG_VERSION") {
        Some(version) => format!("v{version}"),
        None => String::from("[dev]"),
    };

    println!(
        r#"
  {sshx} {version} (P2P Mode)

  {arr}  P2P Link:  {link}
  {arr}  Token:     {token}
  {arr}  Name:      {name}
  {arr}  Shell:     {shell}

  Share the P2P link with others to connect directly!
"#,
        sshx = Green.bold().paint("sshx"),
        version = Green.paint(&version_str),
        arr = Green.paint("➜"),
        link = Cyan.underline().paint(p2p_url),
        token = Fixed(8).paint(token),
        name = Fixed(8).paint(name),
        shell = Fixed(8).paint(shell),
    );
}

fn main() -> ExitCode {
    let args = Args::parse();

    let default_level = if args.quiet { "error" } else { "info" };

    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or(default_level.into()))
        .with_writer(std::io::stderr)
        .init();

    match start(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!("{err:?}");
            ExitCode::FAILURE
        }
    }
}

