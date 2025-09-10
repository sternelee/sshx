use shared::ticket::SessionTicket;
use std::sync::Arc;
use tauri::{AppHandle, Manager, Runtime, State};
use tokio::sync::Mutex;

use crate::session::AppState;

#[tauri::command]
pub async fn create_session(
    app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<String, String> {
    let app_state = state.lock().await;
    app_state.create_session().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn join_session(
    app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
    ticket: String,
) -> Result<String, String> {
    let app_state = state.lock().await;
    // Parse ticket here
    match serde_json::from_str::<SessionTicket>(&ticket) {
        Ok(session_ticket) => app_state
            .join_session(session_ticket)
            .await
            .map_err(|e| e.to_string()),
        Err(e) => Err(format!("Failed to parse ticket: {}", e)),
    }
}

#[tauri::command]
pub async fn send_data(
    app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
    session_id: String,
    data: Vec<u8>,
) -> Result<(), String> {
    // Send data to session
    let app_state = state.lock().await;
    let p2p_message = shared::p2p::P2pMessage::Binary(data);
    let bytes = p2p_message.to_bytes().map_err(|e| e.to_string())?;
    app_state
        .send_data_to_session(&session_id, bytes)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn get_sessions(
    app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<Vec<String>, String> {
    let app_state = state.lock().await;
    let manager = app_state.session_manager.lock().await;
    Ok(manager.list_sessions())
}

#[tauri::command]
pub async fn close_session(
    app_handle: AppHandle,
    state: State<'_, Arc<Mutex<AppState>>>,
    session_id: String,
) -> Result<bool, String> {
    let app_state = state.lock().await;
    let mut manager = app_state.session_manager.lock().await;
    Ok(manager.remove_session(&session_id))
}

pub fn setup_app<R: Runtime>(app: &mut tauri::App<R>) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
