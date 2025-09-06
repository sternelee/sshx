use anyhow::Result;
use clap::Parser;
use data_encoding::BASE32_NOPAD;
use futures_lite::StreamExt;
use iroh::net::{Endpoint, NodeAddr};
use iroh::protocol::Router;
use iroh::SecretKey;
use iroh_gossip::{
    net::{Event, Gossip, GossipEvent},
    proto::TopicId,
};
use prost::Message;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sshx_core::proto::{
    server_update::ServerMessage, ClientUpdate, NewShell, ServerUpdate, TerminalInput,
};
use std::str::FromStr;
use std::time::Duration;
use tokio::time;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The ticket to connect to a session.
    ticket: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Ticket {
    topic: TopicId,
    nodes: Vec<NodeAddr>,
    key: String,
}

impl Ticket {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(Into::into)
    }
}

impl FromStr for Ticket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.split(',').next().unwrap_or(s); // Ignore write password for now
        let bytes = BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        Self::from_bytes(&bytes)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("Connecting to ticket: {}", args.ticket);

    let ticket = Ticket::from_str(&args.ticket)?;

    let secret_key = SecretKey::generate_with(&mut rand::rngs::OsRng);
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .discovery_n0()
        .bind()
        .await?;

    println!("> our node id: {}", endpoint.node_id());

    for node in ticket.nodes.iter() {
        endpoint.add_node_addr(node.clone())?;
    }

    let gossip = Gossip::builder().spawn(endpoint.clone()).await?;

    let _router = Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.clone())
        .spawn();

    let topic = ticket.topic;

    let node_ids = ticket.nodes.iter().map(|p| p.node_id).collect();
    let (sender, mut receiver) = gossip.subscribe_and_join(topic, node_ids).await?.split();

    println!("> connected to topic!");

    tokio::spawn(async move {
        while let Ok(Some(event)) = receiver.try_next().await {
            if let Event::Gossip(GossipEvent::Received(msg)) = event {
                if let Ok(update) = ClientUpdate::decode(&msg.content[..]) {
                    println!("Received message: {:?}", update.client_message);
                }
            }
        }
    });

    println!("Sending a message to create a shell...");
    let create_shell_msg = ServerMessage::CreateShell(NewShell {
        id: 1,
        x: 10,
        y: 10,
    });
    let update = ServerUpdate {
        server_message: Some(create_shell_msg),
    };
    let mut buf = Vec::new();
    update.encode(&mut buf)?;
    sender.broadcast(buf.into()).await?;

    time::sleep(Duration::from_secs(1)).await;

    println!("Sending some input to the shell...");
    let input_msg = ServerMessage::Input(TerminalInput {
        id: 1,
        data: b"hello from p2p_client\n".to_vec(),
        offset: 0,
    });
    let update = ServerUpdate {
        server_message: Some(input_msg),
    };
    let mut buf = Vec::new();
    update.encode(&mut buf)?;
    sender.broadcast(buf.into()).await?;

    println!("Done. Waiting for messages...");

    // Wait forever
    time::sleep(Duration::from_secs(3600)).await;

    Ok(())
}
