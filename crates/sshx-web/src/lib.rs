use anyhow::Result;
use futures_lite::StreamExt;
use iroh::net::{Endpoint, NodeAddr};
use iroh::protocol::Router;
use iroh::SecretKey;
use iroh_gossip::{
    net::{Event, Gossip, GossipEvent},
    proto::TopicId,
};
use prost::Message;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sshx_core::proto::{ClientUpdate, ServerUpdate};
use std::str::FromStr;
use wasm_bindgen::prelude::*;
use web_sys::console;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
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
        let bytes = data_encoding::BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        Self::from_bytes(&bytes)
    }
}

#[wasm_bindgen]
pub struct WebClient {
    sender: iroh_gossip::net::GossipSender,
}

#[wasm_bindgen]
impl WebClient {
    #[wasm_bindgen(constructor)]
    pub async fn new(ticket_str: &str, on_message: js_sys::Function) -> Result<WebClient, JsValue> {
        console_error_panic_hook::set_once();

        let ticket = Ticket::from_str(ticket_str).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let secret_key = SecretKey::generate_with(&mut OsRng);
        let endpoint = Endpoint::builder()
            .secret_key(secret_key)
            .discovery_n0()
            .bind()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        console_log!("> our node id: {}", endpoint.node_id());

        for node in ticket.nodes.iter() {
            endpoint.add_node_addr(node.clone()).map_err(|e| JsValue::from_str(&e.to_string()))?;
        }

        let gossip = Gossip::builder()
            .spawn(endpoint.clone())
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let _router = Router::builder(endpoint.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();

        let topic = ticket.topic;

        let node_ids = ticket.nodes.iter().map(|p| p.node_id).collect();
        let (sender, mut receiver) = gossip
            .subscribe_and_join(topic, node_ids)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?
            .split();

        console_log!("> connected to topic!");

        wasm_bindgen_futures::spawn_local(async move {
            while let Ok(Some(event)) = receiver.try_next().await {
                if let Event::Gossip(GossipEvent::Received(msg)) = event {
                    if let Ok(_update) = ClientUpdate::decode(&msg.content[..]) {
                        let this = JsValue::NULL;
                        let js_buf = js_sys::Uint8Array::from(&msg.content[..]);
                        on_message.call1(&this, &js_buf).unwrap();
                    }
                }
            }
        });

        Ok(WebClient {
            sender,
        })
    }

    pub async fn send(&self, data: &[u8]) -> Result<(), JsValue> {
        self.sender
            .broadcast(data.into())
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(())
    }
}
