// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sshx_app_lib::{AppState, SessionInfo};
use tauri::Manager;

#[tauri::command]
fn get_system_info() -> serde_json::Value {
    serde_json::json!({
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "version": env!("CARGO_PKG_VERSION")
    })
}

#[tauri::command]
fn show_window(app: tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        window.show().unwrap();
        window.set_focus().unwrap();
    }
}

#[tauri::command]
fn hide_window(app: tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        window.hide().unwrap();
    }
}

#[tauri::command]
fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

#[tauri::command]
async fn create_p2p_session(state: tauri::State<'_, AppState>) -> Result<SessionInfo, String> {
    sshx_app_lib::create_p2p_session_impl(&state).await
}

#[tauri::command]
async fn join_p2p_session(ticket: String, state: tauri::State<'_, AppState>) -> Result<SessionInfo, String> {
    sshx_app_lib::join_p2p_session_impl(ticket, &state).await
}

#[tauri::command]
async fn list_sessions(state: tauri::State<'_, AppState>) -> Result<Vec<SessionInfo>, String> {
    sshx_app_lib::list_sessions_impl(&state).await
}

#[tauri::command]
async fn close_session(session_id: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    sshx_app_lib::close_session_impl(session_id, &state).await
}

#[tauri::command]
async fn send_session_message(session_id: String, message: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    sshx_app_lib::send_session_message_impl(session_id, message, &state).await
}

#[tauri::command]
async fn broadcast_message(message: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    sshx_app_lib::broadcast_message_impl(message, &state).await
}

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .setup(|app| {
            // Create the main window
            let main_window = tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::App("index.html".parse().unwrap()))
                .title("SSHx App")
                .inner_size(1200.0, 800.0)
                .min_inner_size(800.0, 600.0)
                .center()
                .build()?;

            // Create tray menu (simplified for now)
            // Note: Disabled for now to avoid icon issues
            // let _tray = TrayIconBuilder::new()
            //     .tooltip("SSHx App")
            //     .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            show_window,
            hide_window,
            quit_app,
            create_p2p_session,
            join_p2p_session,
            list_sessions,
            close_session,
            send_session_message,
            broadcast_message
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}