use std::sync::Arc;

use serde::{Deserialize, Serialize};
use shared::{
    close_shell_message, create_input_message, create_shell_message,
    events::{ClientMessage, ServerMessage},
    message::Message,
    p2p::P2pNode,
    ticket::SessionTicket,
    SessionConfig, SessionManager, Sid, SimpleMessageHandler,
};
use tauri::{Emitter, State};
use tokio::sync::RwLock;
use tracing_subscriber::{prelude::*, util::SubscriberInitExt, EnvFilter, Layer};

/// Maximum number of concurrent sessions to prevent memory exhaustion
const MAX_CONCURRENT_SESSIONS: usize = 50;

#[derive(Default)]
pub struct AppState {
    session_manager: SessionManager,
    p2p_node: Arc<RwLock<Option<P2pNode>>>,
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub session_ticket: String,
    pub nickname: String,
}

#[tauri::command]
async fn initialize_p2p_node(state: State<'_, AppState>) -> Result<String, String> {
    let p2p_node = P2pNode::new()
        .await
        .map_err(|e| format!("Failed to initialize P2P node: {}", e))?;

    let node_id = p2p_node.node_id().to_string();

    // Store the P2P node in state
    *state.p2p_node.write().await = Some(p2p_node.clone());

    #[cfg(any(debug_assertions, not(feature = "release-logging")))]
    tracing::info!("🎯 P2P node initialized: {}", node_id);

    Ok(node_id)
}

#[tauri::command]
async fn join_terminal_session(
    config: ConnectionConfig,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    // Parse session ticket
    let ticket = config
        .session_ticket
        .parse::<SessionTicket>()
        .map_err(|e| format!("Invalid session ticket format: {}", e))?;

    // Get or create P2P node
    let p2p_node_guard = state.p2p_node.read().await;
    let p2p_node = p2p_node_guard
        .as_ref()
        .ok_or_else(|| "P2P node not initialized. Call initialize_p2p_node first.".to_string())?
        .clone();

    let session_config = SessionConfig {
        ticket,
        nickname: config.nickname,
        max_concurrent_sessions: MAX_CONCURRENT_SESSIONS,
    };

    // Create message handler to forward ServerMessages to Tauri frontend
    let app_handle_clone = app_handle.clone();
    let message_handler = Arc::new(SimpleMessageHandler::new(move |msg: ServerMessage| {
        let event_name = "terminal-event".to_string();
        let _ = app_handle_clone.emit(&event_name, msg);
    }));

    // Join session with message handler
    let session_id = state
        .session_manager
        .join_session_with_handler(&p2p_node, session_config, message_handler)
        .await
        .map_err(|e| format!("Failed to join session: {}", e))?;

    #[cfg(any(debug_assertions, not(feature = "release-logging")))]
    tracing::info!("✅ Tauri client joined P2P session: {}", session_id);

    Ok(session_id)
}

/// Send ClientMessage to CLI (like Browser does)
#[tauri::command]
async fn send_client_message(
    session_id: String,
    client_message: ClientMessage,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let message = Message::ClientMessage(client_message);
    state
        .session_manager
        .send_message(&session_id, message)
        .await
        .map_err(|e| format!("Failed to send message: {}", e))
}

/// Create a new shell (send CreateShell message)
#[tauri::command]
async fn create_shell(
    session_id: String,
    shell_id: u32,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let message = create_shell_message(Sid(shell_id));
    state
        .session_manager
        .send_message(&session_id, message)
        .await
        .map_err(|e| format!("Failed to create shell: {}", e))
}

/// Send terminal input (send Input message)
#[tauri::command]
async fn send_input(
    session_id: String,
    shell_id: u32,
    data: Vec<u8>,
    offset: u64,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let message = create_input_message(Sid(shell_id), data, offset);
    state
        .session_manager
        .send_message(&session_id, message)
        .await
        .map_err(|e| format!("Failed to send input: {}", e))
}

/// Close a shell (send CloseShell message)
#[tauri::command]
async fn close_shell(
    session_id: String,
    shell_id: u32,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let message = close_shell_message(Sid(shell_id));
    state
        .session_manager
        .send_message(&session_id, message)
        .await
        .map_err(|e| format!("Failed to close shell: {}", e))
}

/// Disconnect from session
#[tauri::command]
async fn disconnect_session(session_id: String, state: State<'_, AppState>) -> Result<(), String> {
    #[cfg(any(debug_assertions, not(feature = "release-logging")))]
    tracing::info!("Disconnecting session: {}", session_id);

    if let Some(session) = state.session_manager.remove_session(&session_id).await {
        // Cancel all async tasks for this session
        session.cancellation_token().cancel();

        #[cfg(any(debug_assertions, not(feature = "release-logging")))]
        tracing::info!("Session {} disconnected successfully", session_id);
    } else {
        #[cfg(any(debug_assertions, not(feature = "release-logging")))]
        tracing::info!("Session {} not found during disconnect", session_id);
    }

    Ok(())
}

/// Get active sessions
#[tauri::command]
async fn get_active_sessions(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let sessions = state.session_manager.get_active_sessions().await;
    Ok(sessions)
}

/// Get P2P node ID
#[tauri::command]
async fn get_node_id() -> Result<String, String> {
    // For now, return a placeholder since we don't store the node
    // In a real implementation, you'd manage P2P node lifecycle properly
    Err("P2P node not stored in state. Call initialize_p2p_node first.".to_string())
}

/// Initialize tracing
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(filter))
        .init();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    init_tracing();

    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            initialize_p2p_node,
            join_terminal_session,
            create_shell,
            send_input,
            close_shell,
            disconnect_session,
            get_active_sessions,
            get_node_id
        ])
        .setup(|_app| Ok(()))
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// Note: To properly handle ServerMessages from CLI, we need to modify the
// session manager to support callbacks or channels for message handling. For
// now, the session manager logs the messages, but in a real implementation,
// we'd want to forward them to the Tauri frontend via events. This would
// require modifying the shared session manager to accept a callback function or
// channel for message processing.}

// Example of how to handle ServerMessages in the session manager:
// In session_manager.rs, we could add:
//
// pub type MessageHandler = Arc<dyn Fn(ServerMessage) + Send + Sync>;
//
// And modify the session manager to accept a handler:
// pub async fn join_session_with_handler(
//     &self,
//     p2p_node: &P2pNode,
//     config: SessionConfig,
//     message_handler: MessageHandler,
// ) -> Result<ManagedSession> {
//     // ... existing code ...
//
//     // In handle_p2p_event, call the handler:
//     if let Ok(server_msg) = serde_json::from_str::<ServerMessage>(&text) {
//         message_handler(server_msg);
//     }
// }<Paste>
// Example usage in Tauri:
// let message_handler = Arc::new(move |msg: ServerMessage| {
//     let _ = app_handle.emit("terminal-event", msg);
// });<Paste>
// let session = session_manager.join_session_with_handler(&p2p_node, config,
// message_handler).await?;
