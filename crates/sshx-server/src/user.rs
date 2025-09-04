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
    /// API keys owned by this user.
    pub api_keys: Vec<UserApiKey>,
}

/// Information about a user's API key for persistent session access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserApiKey {
    /// API key unique identifier.
    pub id: String,
    /// API key name/description.
    pub name: String,
    /// API key token for access.
    pub token: String,
    /// API key creation timestamp.
    pub created_at: u64,
    /// Last used timestamp.
    pub last_used: Option<u64>,
    /// Whether the API key is active.
    pub is_active: bool,
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

/// Request to generate an API key.
#[derive(Debug, Deserialize)]
pub struct GenerateApiKeyRequest {
    /// JWT authentication token.
    pub auth_token: String,
    /// API key name/description.
    pub name: String,
}

/// Response containing API key information.
#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    /// API key unique identifier.
    pub id: String,
    /// API key name.
    pub name: String,
    /// API key token.
    pub token: String,
    /// Creation timestamp.
    pub created_at: u64,
    /// User ID.
    pub user_id: String,
}

/// Request to delete an API key.
#[derive(Debug, Deserialize)]
pub struct DeleteApiKeyRequest {
    /// JWT authentication token.
    pub auth_token: String,
    /// API key ID to delete.
    pub api_key_id: String,
}

/// Request to list user's API keys.
#[derive(Debug, Deserialize)]
pub struct ListApiKeysRequest {
    /// JWT authentication token.
    pub auth_token: String,
}

/// Response containing list of API keys.
#[derive(Debug, Serialize)]
pub struct ListApiKeysResponse {
    /// List of API keys (without tokens for security).
    pub api_keys: Vec<ApiKeyInfo>,
}

/// API key information without the token.
#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    /// API key unique identifier.
    pub id: String,
    /// API key name.
    pub name: String,
    /// Creation timestamp.
    pub created_at: u64,
    /// Last used timestamp.
    pub last_used: Option<u64>,
    /// Whether the API key is active.
    pub is_active: bool,
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
            api_keys: Vec::new(),
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

    /// Add an API key to the user's API key list.
    pub fn add_api_key(&mut self, api_key: UserApiKey) {
        self.api_keys.push(api_key);
    }

    /// Remove an API key from the user's API key list.
    pub fn remove_api_key(&mut self, api_key_id: &str) -> bool {
        let initial_len = self.api_keys.len();
        self.api_keys.retain(|k| k.id != api_key_id);
        self.api_keys.len() != initial_len
    }

    /// Get an API key by ID.
    pub fn get_api_key(&self, api_key_id: &str) -> Option<&UserApiKey> {
        self.api_keys.iter().find(|k| k.id == api_key_id)
    }

    /// Get an API key by token.
    pub fn get_api_key_by_token(&self, token: &str) -> Option<&UserApiKey> {
        self.api_keys
            .iter()
            .find(|k| k.token == token && k.is_active)
    }

    /// Update API key last used timestamp.
    pub fn update_api_key_last_used(&mut self, api_key_id: &str) {
        if let Some(api_key) = self.api_keys.iter_mut().find(|k| k.id == api_key_id) {
            api_key.last_used = Some(chrono::Utc::now().timestamp() as u64);
        }
    }

    /// Get API key info list (without tokens).
    pub fn get_api_key_info_list(&self) -> Vec<ApiKeyInfo> {
        self.api_keys
            .iter()
            .map(|k| ApiKeyInfo {
                id: k.id.clone(),
                name: k.name.clone(),
                created_at: k.created_at,
                last_used: k.last_used,
                is_active: k.is_active,
            })
            .collect()
    }
}
