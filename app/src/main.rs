// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use tokio::sync::Mutex;
use app::{AppState, commands::*};

#[tokio::main]
async fn main() {
    // Initialize app state
    let app_state = match AppState::new().await {
        Ok(state) => Arc::new(Mutex::new(state)),
        Err(e) => {
            eprintln!("Failed to initialize app state: {}", e);
            return;
        }
    };

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            create_session,
            join_session,
            send_data,
            get_sessions,
            close_session
        ])
        .setup(|app| {
            #[cfg(desktop)]
            {
                let _ = app.handle().plugin(tauri_plugin_cli::init());
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

