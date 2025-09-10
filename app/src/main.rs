// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use app::{commands::*, AppState};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();
    info!("Starting sshx Tauri application");

    // Initialize app state
    let app_state = match AppState::new().await {
        Ok(state) => {
            info!("App state initialized successfully");
            Arc::new(Mutex::new(state))
        }
        Err(e) => {
            error!("Failed to initialize app state: {}", e);
            std::process::exit(1);
        }
    };

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            create_session,
            join_session,
            send_data,
            get_sessions,
            close_session,
            get_session_ticket,
            get_node_id,
            send_notification,
            get_app_version,
            open_external_url
        ])
        .plugin(tauri_plugin_cli::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            info!("Tauri application setup completed");

            // Handle CLI arguments
            #[cfg(desktop)]
            {
                if let Ok(_matches) = app.handle().plugin(tauri_plugin_cli::init()) {
                    // Handle CLI here if needed
                }
            }

            Ok(())
        })
        .run(tauri::generate_context!());

    if let Err(e) = result {
        error!("Error running Tauri application: {}", e);
        std::process::exit(1);
    }
}
