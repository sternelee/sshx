use std::sync::Mutex;

// Application state
pub struct AppState {
    pub sessions: Mutex<Vec<SessionInfo>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub ticket: String,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub is_active: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(Vec::new()),
        }
    }
}

// Initialize WASM module
pub async fn init_wasm_module() -> Result<(), Box<dyn std::error::Error>> {
    // This will be implemented to initialize the sshx-web WASM module
    tracing::info!("Initializing SSHx WASM module");
    Ok(())
}

// Session management functions (non-command versions)
pub async fn create_p2p_session_impl(state: &AppState) -> Result<SessionInfo, String> {
    let session_id = uuid::Uuid::new_v4().to_string();
    let ticket = format!("ticket_{}", session_id);
    
    let session = SessionInfo {
        id: session_id.clone(),
        ticket: ticket.clone(),
        name: format!("Session {}", state.sessions.lock().unwrap().len() + 1),
        created_at: chrono::Utc::now(),
        is_active: true,
    };
    
    state.sessions.lock().unwrap().push(session.clone());
    
    tracing::info!("Created P2P session: {}", session_id);
    Ok(session)
}

pub async fn join_p2p_session_impl(
    ticket: String,
    state: &AppState,
) -> Result<SessionInfo, String> {
    // Parse ticket and join session
    let session_id = uuid::Uuid::new_v4().to_string();
    
    let session = SessionInfo {
        id: session_id.clone(),
        ticket: ticket.clone(),
        name: format!("Joined Session {}", state.sessions.lock().unwrap().len() + 1),
        created_at: chrono::Utc::now(),
        is_active: true,
    };
    
    state.sessions.lock().unwrap().push(session.clone());
    
    tracing::info!("Joined P2P session: {}", session_id);
    Ok(session)
}

pub async fn list_sessions_impl(state: &AppState) -> Result<Vec<SessionInfo>, String> {
    let sessions = state.sessions.lock().unwrap().clone();
    Ok(sessions)
}

pub async fn close_session_impl(
    session_id: String,
    state: &AppState,
) -> Result<(), String> {
    let mut sessions = state.sessions.lock().unwrap();
    if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id) {
        session.is_active = false;
        tracing::info!("Closed session: {}", session_id);
        Ok(())
    } else {
        Err("Session not found".to_string())
    }
}

pub async fn send_session_message_impl(
    session_id: String,
    message: String,
    _state: &AppState,
) -> Result<(), String> {
    // Send message to specific session
    tracing::info!("Sending message to session {}: {}", session_id, message);
    Ok(())
}

pub async fn broadcast_message_impl(
    message: String,
    state: &AppState,
) -> Result<(), String> {
    // Broadcast message to all active sessions
    let sessions = state.sessions.lock().unwrap();
    let active_count = sessions.iter().filter(|s| s.is_active).count();
    
    tracing::info!("Broadcasting message to {} active sessions: {}", active_count, message);
    Ok(())
}