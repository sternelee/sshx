use crate::user::{
    ApiKeyResponse, AuthResponse, CloseUserSessionRequest, DeleteApiKeyRequest,
    GenerateApiKeyRequest, ListApiKeysRequest, ListApiKeysResponse, ListUserSessionsRequest,
    ListUserSessionsResponse, LoginRequest, RegisterRequest, User, UserApiKey, UserSession,
};
use anyhow::{anyhow, Result};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::Sha256;
use sshx_core::rand_alphanumeric;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// JWT token claims structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// User ID (subject).
    pub sub: String,
    /// User email address.
    pub email: String,
    /// Token expiration timestamp.
    pub exp: usize,
}

/// Service for user authentication and management operations.
pub struct UserService {
    redis: deadpool_redis::Pool,
    jwt_secret: String,
}

impl UserService {
    /// Create a new user service with Redis connection pool and JWT secret.
    pub fn new(redis: deadpool_redis::Pool, jwt_secret: String) -> Self {
        Self { redis, jwt_secret }
    }

    /// Register a new user account.
    pub async fn register(&self, req: RegisterRequest) -> Result<AuthResponse> {
        // Validate email format
        if !self.is_valid_email(&req.email) {
            return Err(anyhow!("Invalid email format"));
        }

        // Check if user already exists
        if self.user_exists(&req.email).await? {
            return Err(anyhow!("User already exists"));
        }

        // Create new user
        let user = User::new(req.email.clone(), &req.password)?;

        // Save to Redis
        self.save_user(&user).await?;

        // Generate JWT token
        let token = self.generate_token(&user)?;

        Ok(AuthResponse {
            token,
            user_id: user.id,
            email: user.email,
        })
    }

    /// Authenticate user login with email and password.
    pub async fn login(&self, req: LoginRequest) -> Result<AuthResponse> {
        // Get user from Redis
        let mut user = self
            .get_user_by_email(&req.email)
            .await?
            .ok_or_else(|| anyhow!("Invalid credentials"))?;

        // Verify password
        if !user.verify_password(&req.password) {
            return Err(anyhow!("Invalid credentials"));
        }

        // Update last login
        user.update_last_login();
        self.save_user(&user).await?;

        // Generate JWT token
        let token = self.generate_token(&user)?;

        Ok(AuthResponse {
            token,
            user_id: user.id,
            email: user.email,
        })
    }

    /// Verify and decode a JWT token, returning the claims if valid.
    pub async fn verify_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_ref()),
            &Validation::default(),
        )?;
        Ok(token_data.claims)
    }

    /// Generate an API key for authenticated users.
    pub async fn generate_api_key(&self, req: GenerateApiKeyRequest) -> Result<ApiKeyResponse> {
        // Verify the JWT token
        let claims = self.verify_token(&req.auth_token).await?;

        // Get user from database
        let mut user = self
            .get_user_by_id(&claims.sub)
            .await?
            .ok_or_else(|| anyhow!("User not found"))?;

        // Generate unique API key ID and token
        let api_key_id = Uuid::new_v4().to_string();
        let token_data = format!("{}:{}", api_key_id, rand_alphanumeric(32));

        // Generate API key token using HMAC
        let mut mac = Hmac::<Sha256>::new_from_slice(self.jwt_secret.as_bytes())
            .map_err(|_| anyhow!("Invalid JWT secret"))?;
        mac.update(token_data.as_bytes());
        let api_key_token = BASE64_STANDARD.encode(mac.finalize().into_bytes());

        // Create user API key record
        let user_api_key = UserApiKey {
            id: api_key_id.clone(),
            name: req.name.clone(),
            token: api_key_token.clone(),
            created_at: chrono::Utc::now().timestamp() as u64,
            last_used: None,
            is_active: true,
        };

        // Add API key to user and save
        user.add_api_key(user_api_key);
        self.save_user(&user).await?;

        // Store API key -> user mapping in Redis
        self.save_api_key_user_mapping(&api_key_token, &user.id)
            .await?;

        Ok(ApiKeyResponse {
            id: api_key_id,
            name: req.name,
            token: api_key_token,
            created_at: chrono::Utc::now().timestamp() as u64,
            user_id: user.id,
        })
    }

    /// Delete an API key for authenticated users.
    pub async fn delete_api_key(&self, req: DeleteApiKeyRequest) -> Result<bool> {
        // Verify the JWT token
        let claims = self.verify_token(&req.auth_token).await?;

        // Get user from database
        let mut user = self
            .get_user_by_id(&claims.sub)
            .await?
            .ok_or_else(|| anyhow!("User not found"))?;

        // Get the API key to be deleted (to get its token)
        let api_key = user
            .get_api_key(&req.api_key_id)
            .ok_or_else(|| anyhow!("API key not found"))?;
        let api_key_token = api_key.token.clone();

        // Remove API key from user
        let removed = user.remove_api_key(&req.api_key_id);

        if removed {
            // Save updated user data
            self.save_user(&user).await?;

            // Remove API key -> user mapping from Redis
            self.remove_api_key_user_mapping(&api_key_token).await?;
        }

        Ok(removed)
    }

    /// List all API keys for authenticated users.
    pub async fn list_api_keys(&self, req: ListApiKeysRequest) -> Result<ListApiKeysResponse> {
        // Verify the JWT token
        let claims = self.verify_token(&req.auth_token).await?;

        // Get user from database
        let user = self
            .get_user_by_id(&claims.sub)
            .await?
            .ok_or_else(|| anyhow!("User not found"))?;

        // Get API key info list (without tokens for security)
        let api_keys = user.get_api_key_info_list();

        Ok(ListApiKeysResponse { api_keys })
    }

    /// Verify an API key and return the associated user ID.
    pub async fn verify_api_key(&self, api_key_token: &str) -> Result<Option<String>> {
        // First try to get user ID from Redis mapping
        if let Some(user_id) = self.get_api_key_user(&api_key_token).await? {
            // Get user and verify the API key is still valid
            if let Some(mut user) = self.get_user_by_id(&user_id).await? {
                let api_key_info = user
                    .get_api_key_by_token(api_key_token)
                    .map(|k| (k.id.clone(), k.is_active));

                if let Some((api_key_id, is_active)) = api_key_info {
                    if is_active {
                        // Update last used timestamp
                        user.update_api_key_last_used(&api_key_id);
                        self.save_user(&user).await?;
                        return Ok(Some(user_id));
                    }
                }
            }
        }
        Ok(None)
    }

    async fn user_exists(&self, email: &str) -> Result<bool> {
        let mut conn = self.redis.get().await?;
        let exists: bool = conn.exists(format!("user:email:{}", email)).await?;
        Ok(exists)
    }

    /// Save user data to Redis.
    pub async fn save_user(&self, user: &User) -> Result<()> {
        let mut conn = self.redis.get().await?;
        let user_json = serde_json::to_string(user)?;

        // Save user data with user ID as key
        conn.set::<_, _, ()>(format!("user:id:{}", user.id), &user_json)
            .await?;

        // Create email -> user_id mapping
        conn.set::<_, _, ()>(format!("user:email:{}", user.email), &user.id)
            .await?;

        Ok(())
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let mut conn = self.redis.get().await?;

        // Get user ID from email
        let user_id: Option<String> = conn.get(format!("user:email:{}", email)).await?;

        if let Some(user_id) = user_id {
            // Get user data
            let user_json: Option<String> = conn.get(format!("user:id:{}", user_id)).await?;
            if let Some(user_json) = user_json {
                let user: User = serde_json::from_str(&user_json)?;
                return Ok(Some(user));
            }
        }

        Ok(None)
    }

    /// Get user by ID from Redis.
    pub async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>> {
        let mut conn = self.redis.get().await?;
        let user_json: Option<String> = conn.get(format!("user:id:{}", user_id)).await?;

        if let Some(user_json) = user_json {
            let user: User = serde_json::from_str(&user_json)?;
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    async fn save_api_key_user_mapping(&self, api_key_token: &str, user_id: &str) -> Result<()> {
        let mut conn = self.redis.get().await?;
        conn.set::<_, _, ()>(format!("apikey:user:{}", api_key_token), user_id)
            .await?;
        Ok(())
    }

    async fn remove_api_key_user_mapping(&self, api_key_token: &str) -> Result<()> {
        let mut conn = self.redis.get().await?;
        conn.del::<_, ()>(format!("apikey:user:{}", api_key_token))
            .await?;
        Ok(())
    }

    /// Get user ID associated with an API key.
    pub async fn get_api_key_user(&self, api_key_token: &str) -> Result<Option<String>> {
        let mut conn = self.redis.get().await?;
        let user_id: Option<String> = conn.get(format!("apikey:user:{}", api_key_token)).await?;
        Ok(user_id)
    }

    fn generate_token(&self, user: &User) -> Result<String> {
        let expiration = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 24 * 60 * 60; // 24 hours

        let claims = Claims {
            sub: user.id.clone(),
            email: user.email.clone(),
            exp: expiration as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )?;

        Ok(token)
    }

    fn is_valid_email(&self, email: &str) -> bool {
        email.contains('@') && email.contains('.')
    }

    /// Create a new user session record.
    pub async fn create_user_session(
        &self,
        user_id: &str,
        session_name: &str,
        session_url: &str,
        api_key_id: Option<String>,
    ) -> Result<UserSession> {
        let session = UserSession {
            id: Uuid::new_v4().to_string(),
            name: session_name.to_string(),
            url: session_url.to_string(),
            user_id: user_id.to_string(),
            api_key_id,
            created_at: chrono::Utc::now().timestamp() as u64,
            last_activity: chrono::Utc::now().timestamp() as u64,
            is_active: true,
            metadata: None,
        };

        // Save session to Redis
        self.save_user_session(&session).await?;

        // Add session to user's session list
        self.add_session_to_user(user_id, &session.id).await?;

        Ok(session)
    }

    /// List all active sessions for a user.
    pub async fn list_user_sessions(
        &self,
        req: ListUserSessionsRequest,
    ) -> Result<ListUserSessionsResponse> {
        // Verify the JWT token
        let claims = self.verify_token(&req.auth_token).await?;

        // Get user's session IDs
        let session_ids = self.get_user_session_ids(&claims.sub).await?;

        // Get session details
        let mut sessions = Vec::new();
        for session_id in session_ids {
            if let Some(session) = self.get_user_session(&session_id).await? {
                if session.is_active {
                    sessions.push(session);
                }
            }
        }

        // Sort by creation time (newest first)
        sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(ListUserSessionsResponse { sessions })
    }

    /// Close a user session.
    pub async fn close_user_session(&self, req: CloseUserSessionRequest) -> Result<bool> {
        // Verify the JWT token
        let claims = self.verify_token(&req.auth_token).await?;

        // Get session and verify ownership
        if let Some(mut session) = self.get_user_session(&req.session_id).await? {
            if session.user_id != claims.sub {
                return Err(anyhow!("Session not found or access denied"));
            }

            // Mark session as inactive
            session.is_active = false;
            session.last_activity = chrono::Utc::now().timestamp() as u64;

            // Save updated session
            self.save_user_session(&session).await?;

            return Ok(true);
        }

        Ok(false)
    }

    /// Update session activity timestamp.
    pub async fn update_session_activity(&self, session_name: &str) -> Result<()> {
        // Try to find session by name
        if let Some(session_id) = self.get_session_id_by_name(session_name).await? {
            if let Some(mut session) = self.get_user_session(&session_id).await? {
                session.last_activity = chrono::Utc::now().timestamp() as u64;
                self.save_user_session(&session).await?;
            }
        }
        Ok(())
    }

    /// Get session by name (for activity updates).
    pub async fn get_session_by_name(&self, session_name: &str) -> Result<Option<UserSession>> {
        if let Some(session_id) = self.get_session_id_by_name(session_name).await? {
            self.get_user_session(&session_id).await
        } else {
            Ok(None)
        }
    }

    async fn save_user_session(&self, session: &UserSession) -> Result<()> {
        let mut conn = self.redis.get().await?;
        let session_json = serde_json::to_string(session)?;

        // Save session data
        conn.set::<_, _, ()>(format!("session:id:{}", session.id), &session_json)
            .await?;

        // Create session name -> session ID mapping
        conn.set::<_, _, ()>(format!("session:name:{}", session.name), &session.id)
            .await?;

        Ok(())
    }

    async fn get_user_session(&self, session_id: &str) -> Result<Option<UserSession>> {
        let mut conn = self.redis.get().await?;
        let session_json: Option<String> = conn.get(format!("session:id:{}", session_id)).await?;

        if let Some(session_json) = session_json {
            let session: UserSession = serde_json::from_str(&session_json)?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    async fn get_session_id_by_name(&self, session_name: &str) -> Result<Option<String>> {
        let mut conn = self.redis.get().await?;
        let session_id: Option<String> = conn.get(format!("session:name:{}", session_name)).await?;
        Ok(session_id)
    }

    async fn add_session_to_user(&self, user_id: &str, session_id: &str) -> Result<()> {
        let mut conn = self.redis.get().await?;
        conn.sadd::<_, _, ()>(format!("user:sessions:{}", user_id), session_id)
            .await?;
        Ok(())
    }

    async fn get_user_session_ids(&self, user_id: &str) -> Result<Vec<String>> {
        let mut conn = self.redis.get().await?;
        let session_ids: Vec<String> = conn.smembers(format!("user:sessions:{}", user_id)).await?;
        Ok(session_ids)
    }
}
