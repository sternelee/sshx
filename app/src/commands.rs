use shared::ticket::SessionTicket;
use std::sync::Arc;
use tauri::{AppHandle, Runtime, State};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::session::AppState;

#[tauri::command]
pub async fn create_session(
    _app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<String, String> {
    info!("Creating new session");
    let app_state = state.lock().await;

    match app_state.create_session().await {
        Ok(session_id) => {
            info!("Session created successfully: {}", session_id);
            Ok(session_id)
        }
        Err(e) => {
            error!("Failed to create session: {}", e);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
pub async fn join_session(
    _app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
    ticket: String,
) -> Result<String, String> {
    info!("Joining session with ticket");
    let app_state = state.lock().await;

    match serde_json::from_str::<SessionTicket>(&ticket) {
        Ok(session_ticket) => match app_state.join_session(session_ticket).await {
            Ok(session_id) => {
                info!("Successfully joined session: {}", session_id);
                Ok(session_id)
            }
            Err(e) => {
                error!("Failed to join session: {}", e);
                Err(e.to_string())
            }
        },
        Err(e) => {
            error!("Failed to parse session ticket: {}", e);
            Err(format!("Failed to parse ticket: {}", e))
        }
    }
}

#[tauri::command]
pub async fn send_data(
    _app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
    session_id: String,
    data: Vec<u8>,
) -> Result<(), String> {
    let app_state = state.lock().await;
    let p2p_message = shared::p2p::P2pMessage::Binary(data);

    match p2p_message.to_bytes() {
        Ok(bytes) => match app_state.send_data_to_session(&session_id, bytes).await {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Failed to send data to session {}: {}", session_id, e);
                Err(e.to_string())
            }
        },
        Err(e) => {
            error!("Failed to serialize data: {}", e);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
pub async fn get_sessions(
    _app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<Vec<String>, String> {
    let app_state = state.lock().await;
    let manager = app_state.session_manager.lock().await;
    Ok(manager.list_sessions())
}

#[tauri::command]
pub async fn close_session(
    _app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
    session_id: String,
) -> Result<bool, String> {
    info!("Closing session: {}", session_id);
    let app_state = state.lock().await;
    let mut manager = app_state.session_manager.lock().await;
    let result = manager.remove_session(&session_id);

    if result {
        info!("Session {} closed successfully", session_id);
    } else {
        warn!("Session {} not found when trying to close", session_id);
    }

    Ok(result)
}

#[tauri::command]
pub async fn get_session_ticket(
    _app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
    session_id: String,
    _include_self: Option<bool>,
) -> Result<String, String> {
    let app_state = state.lock().await;
    let manager = app_state.session_manager.lock().await;

    if let Some(session) = manager.get_session(&session_id) {
        let ticket = session.ticket();
        Ok(serde_json::to_string(&ticket).unwrap_or_default())
    } else {
        Err("Session not found".to_string())
    }
}

#[tauri::command]
pub async fn get_node_id(
    _app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<String, String> {
    let app_state = state.lock().await;
    Ok(app_state.p2p_node.node_id().to_string())
}

#[tauri::command]
pub async fn send_notification(
    _app_handle: AppHandle,
    _title: String,
    _body: String,
) -> Result<(), String> {
    // Placeholder for notification functionality
    warn!("Notification feature not implemented");
    Ok(())
}

#[tauri::command]
pub async fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command]
pub async fn open_external_url(url: String) -> Result<(), String> {
    match webbrowser::open(&url) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("Failed to open URL {}: {}", url, e);
            Err(e.to_string())
        }
    }
}

pub fn setup_app<R: Runtime>(_app: &mut tauri::App<R>) -> Result<(), Box<dyn std::error::Error>> {
    info!("Setting up Tauri application");
    Ok(())
}
