use anyhow::{anyhow, Result};
use bcrypt::{hash, verify, DEFAULT_COST};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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

/// Permission scope for API keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ApiKeyPermission {
    /// Read access to sessions.
    SessionRead,
    /// Write access to sessions.
    SessionWrite,
    /// Create new sessions.
    SessionCreate,
    /// Delete sessions.
    SessionDelete,
    /// Manage API keys.
    ApiKeyManage,
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
    /// Permissions granted to this API key.
    pub permissions: HashSet<ApiKeyPermission>,
    /// Expiration timestamp (None means never expires).
    pub expires_at: Option<u64>,
    /// Number of times this key has been used.
    pub usage_count: u64,
    /// Maximum number of uses allowed (None means unlimited).
    pub max_usage: Option<u64>,
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
    /// Permissions to grant to this API key.
    pub permissions: Option<Vec<ApiKeyPermission>>,
    /// Expiration time in hours (None means never expires).
    pub expires_in_hours: Option<u64>,
    /// Maximum number of uses allowed (None means unlimited).
    pub max_usage: Option<u64>,
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
    /// Permissions granted to this API key.
    pub permissions: HashSet<ApiKeyPermission>,
    /// Expiration timestamp.
    pub expires_at: Option<u64>,
    /// Maximum usage allowed.
    pub max_usage: Option<u64>,
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
    /// Permissions granted to this API key.
    pub permissions: HashSet<ApiKeyPermission>,
    /// Expiration timestamp.
    pub expires_at: Option<u64>,
    /// Usage count.
    pub usage_count: u64,
    /// Maximum usage allowed.
    pub max_usage: Option<u64>,
    /// Whether the key is expired.
    pub is_expired: bool,
}

/// User session information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    /// Session unique identifier.
    pub id: String,
    /// Session name.
    pub name: String,
    /// Session URL.
    pub url: String,
    /// User ID who owns this session.
    pub user_id: String,
    /// API key used to create this session.
    pub api_key_id: Option<String>,
    /// Session creation timestamp.
    pub created_at: u64,
    /// Last activity timestamp.
    pub last_activity: u64,
    /// Whether the session is currently active.
    pub is_active: bool,
    /// Session metadata.
    pub metadata: Option<String>,
}

/// Request to list user sessions.
#[derive(Debug, Deserialize)]
pub struct ListUserSessionsRequest {
    /// JWT authentication token.
    pub auth_token: String,
}

/// Response containing list of user sessions.
#[derive(Debug, Serialize)]
pub struct ListUserSessionsResponse {
    /// List of user sessions.
    pub sessions: Vec<UserSession>,
}

/// Request to close a user session.
#[derive(Debug, Deserialize)]
pub struct CloseUserSessionRequest {
    /// JWT authentication token.
    pub auth_token: String,
    /// Session ID to close.
    pub session_id: String,
}

/// Password validation result.
#[derive(Debug)]
pub struct PasswordValidation {
    /// Whether the password is valid.
    pub is_valid: bool,
    /// List of validation errors.
    pub errors: Vec<String>,
    /// Password strength score (0-100).
    pub strength_score: u8,
}

/// Password validation configuration.
pub struct PasswordPolicy {
    /// Minimum password length.
    pub min_length: usize,
    /// Require uppercase letters.
    pub require_uppercase: bool,
    /// Require lowercase letters.
    pub require_lowercase: bool,
    /// Require numbers.
    pub require_numbers: bool,
    /// Require special characters.
    pub require_special: bool,
    /// List of common passwords to reject.
    pub forbidden_passwords: HashSet<String>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        let mut forbidden = HashSet::new();
        // Add common passwords
        let common_passwords = [
            "password",
            "123456",
            "123456789",
            "qwerty",
            "abc123",
            "password123",
            "admin",
            "root",
            "user",
            "guest",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "master",
        ];
        for pwd in &common_passwords {
            forbidden.insert(pwd.to_string());
        }

        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
            forbidden_passwords: forbidden,
        }
    }
}

impl PasswordPolicy {
    /// Validate a password against this policy.
    pub fn validate(&self, password: &str) -> PasswordValidation {
        let mut errors = Vec::new();
        let mut score = 0u8;

        // Check length
        if password.len() < self.min_length {
            errors.push(format!(
                "Password must be at least {} characters long",
                self.min_length
            ));
        } else {
            score += 20;
            if password.len() >= 12 {
                score += 10;
            }
        }

        // Check for uppercase letters
        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            errors.push("Password must contain at least one uppercase letter".to_string());
        } else if password.chars().any(|c| c.is_uppercase()) {
            score += 15;
        }

        // Check for lowercase letters
        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            errors.push("Password must contain at least one lowercase letter".to_string());
        } else if password.chars().any(|c| c.is_lowercase()) {
            score += 15;
        }

        // Check for numbers
        if self.require_numbers && !password.chars().any(|c| c.is_numeric()) {
            errors.push("Password must contain at least one number".to_string());
        } else if password.chars().any(|c| c.is_numeric()) {
            score += 15;
        }

        // Check for special characters
        if self.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            errors.push("Password must contain at least one special character".to_string());
        } else if password.chars().any(|c| !c.is_alphanumeric()) {
            score += 15;
        }

        // Check against common passwords
        if self.forbidden_passwords.contains(&password.to_lowercase()) {
            errors.push("Password is too common and not secure".to_string());
            score = 0; // Reset score for common passwords
        }

        // Check for repeated characters
        let mut char_counts = std::collections::HashMap::new();
        for c in password.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }
        let max_repeats = char_counts.values().max().unwrap_or(&0);
        if *max_repeats > password.len() / 3 {
            errors.push("Password contains too many repeated characters".to_string());
            score = score.saturating_sub(20);
        }

        // Bonus points for variety
        if password.len() > 12 && char_counts.len() > password.len() * 2 / 3 {
            score += 10;
        }

        // Cap the score at 100
        score = score.min(100);

        PasswordValidation {
            is_valid: errors.is_empty(),
            errors,
            strength_score: score,
        }
    }
}

/// Email validation using proper regex.
pub fn validate_email(email: &str) -> Result<()> {
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        .map_err(|_| anyhow!("Failed to compile email regex"))?;

    if !email_regex.is_match(email) {
        return Err(anyhow!("Invalid email format"));
    }

    // Additional checks
    if email.len() > 254 {
        return Err(anyhow!("Email address is too long"));
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid email format"));
    }

    let local_part = parts[0];
    let domain_part = parts[1];

    if local_part.len() > 64 {
        return Err(anyhow!("Email local part is too long"));
    }

    if domain_part.len() > 253 {
        return Err(anyhow!("Email domain part is too long"));
    }

    // Check for consecutive dots
    if email.contains("..") {
        return Err(anyhow!("Email contains consecutive dots"));
    }

    Ok(())
}

impl Default for ApiKeyPermission {
    fn default() -> Self {
        ApiKeyPermission::SessionRead
    }
}

impl ApiKeyPermission {
    /// Get all available permissions.
    pub fn all() -> HashSet<ApiKeyPermission> {
        let mut permissions = HashSet::new();
        permissions.insert(ApiKeyPermission::SessionRead);
        permissions.insert(ApiKeyPermission::SessionWrite);
        permissions.insert(ApiKeyPermission::SessionCreate);
        permissions.insert(ApiKeyPermission::SessionDelete);
        permissions.insert(ApiKeyPermission::ApiKeyManage);
        permissions
    }

    /// Get default permissions for new API keys.
    pub fn default_permissions() -> HashSet<ApiKeyPermission> {
        let mut permissions = HashSet::new();
        permissions.insert(ApiKeyPermission::SessionRead);
        permissions.insert(ApiKeyPermission::SessionWrite);
        permissions.insert(ApiKeyPermission::SessionCreate);
        permissions
    }
}

impl UserApiKey {
    /// Create a new API key with specified permissions.
    pub fn new(
        id: String,
        name: String,
        token: String,
        permissions: HashSet<ApiKeyPermission>,
        expires_in_hours: Option<u64>,
        max_usage: Option<u64>,
    ) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        let expires_at = expires_in_hours.map(|hours| now + (hours * 3600));

        Self {
            id,
            name,
            token,
            created_at: now,
            last_used: None,
            is_active: true,
            permissions,
            expires_at,
            usage_count: 0,
            max_usage,
        }
    }

    /// Check if the API key has a specific permission.
    pub fn has_permission(&self, permission: &ApiKeyPermission) -> bool {
        self.permissions.contains(permission)
    }

    /// Check if the API key is expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = chrono::Utc::now().timestamp() as u64;
            return now > expires_at;
        }
        false
    }

    /// Check if the API key has exceeded its usage limit.
    pub fn is_usage_exceeded(&self) -> bool {
        if let Some(max_usage) = self.max_usage {
            return self.usage_count >= max_usage;
        }
        false
    }

    /// Check if the API key is usable (active, not expired, not exceeded usage).
    pub fn is_usable(&self) -> bool {
        self.is_active && !self.is_expired() && !self.is_usage_exceeded()
    }

    /// Increment usage count and update last used timestamp.
    pub fn record_usage(&mut self) {
        self.usage_count += 1;
        self.last_used = Some(chrono::Utc::now().timestamp() as u64);
    }
}

impl User {
    /// Create a new user with validated password.
    pub fn new(email: String, password: &str) -> Result<Self> {
        // Validate email
        validate_email(&email)?;

        // Validate password
        let policy = PasswordPolicy::default();
        let validation = policy.validate(password);

        if !validation.is_valid {
            return Err(anyhow!(
                "Password validation failed: {}",
                validation.errors.join(", ")
            ));
        }

        if validation.strength_score < 50 {
            return Err(anyhow!(
                "Password is too weak (score: {}). Please choose a stronger password.",
                validation.strength_score
            ));
        }

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

    /// Get an API key by token with permission and expiry checks.
    pub fn get_api_key_by_token(&self, token: &str) -> Option<&UserApiKey> {
        self.api_keys
            .iter()
            .find(|k| k.token == token && k.is_usable())
    }

    /// Update API key usage (increment count and update timestamp).
    pub fn update_api_key_usage(&mut self, api_key_id: &str) -> bool {
        if let Some(api_key) = self.api_keys.iter_mut().find(|k| k.id == api_key_id) {
            api_key.record_usage();
            true
        } else {
            false
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
                permissions: k.permissions.clone(),
                expires_at: k.expires_at,
                usage_count: k.usage_count,
                max_usage: k.max_usage,
                is_expired: k.is_expired(),
            })
            .collect()
    }

    /// Check if user has reached API key limit.
    pub fn can_create_api_key(&self) -> bool {
        const MAX_API_KEYS: usize = 10;
        let active_keys = self.api_keys.iter().filter(|k| k.is_active).count();
        active_keys < MAX_API_KEYS
    }

    /// Validate password strength.
    pub fn validate_password_strength(password: &str) -> PasswordValidation {
        let policy = PasswordPolicy::default();
        policy.validate(password)
    }
}
