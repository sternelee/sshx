use anyhow::Result;
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User account information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique user identifier.
    pub id: String,
    /// User's email address.
    pub email: String,
    /// Hashed password.
    pub password_hash: String,
    /// Account creation timestamp.
    pub created_at: u64,
    /// Last login timestamp.
    pub last_login: Option<u64>,
}

/// Request to register a new user account.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// User's email address.
    pub email: String,
    /// User's password.
    pub password: String,
}

/// Request to login with existing credentials.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// User's email address.
    pub email: String,
    /// User's password.
    pub password: String,
}

/// Authentication response containing user info and token.
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    /// JWT authentication token.
    pub token: String,
    /// User's unique identifier.
    pub user_id: String,
    /// User's email address.
    pub email: String,
}

impl User {
    /// Create a new user with hashed password.
    pub fn new(email: String, password: &str) -> Result<Self> {
        let password_hash = hash(password, DEFAULT_COST)?;
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            email,
            password_hash,
            created_at: chrono::Utc::now().timestamp() as u64,
            last_login: None,
        })
    }

    /// Verify if the provided password matches the stored hash.
    pub fn verify_password(&self, password: &str) -> bool {
        verify(password, &self.password_hash).unwrap_or(false)
    }

    /// Update the last login timestamp to current time.
    pub fn update_last_login(&mut self) {
        self.last_login = Some(chrono::Utc::now().timestamp() as u64);
    }
}

