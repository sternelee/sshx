use crate::user::{AuthResponse, LoginRequest, RegisterRequest, User};
use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json;
use std::time::{SystemTime, UNIX_EPOCH};

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

    async fn user_exists(&self, email: &str) -> Result<bool> {
        let mut conn = self.redis.get().await?;
        let exists: bool = conn.exists(format!("user:email:{}", email)).await?;
        Ok(exists)
    }

    async fn save_user(&self, user: &User) -> Result<()> {
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
}

