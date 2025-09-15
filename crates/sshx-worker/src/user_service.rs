use anyhow::Result;
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    db::{ApiKey, User},
    state::CloudflareServerState,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user id
    pub email: String,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub email: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct GenerateApiKeyRequest {
    pub auth_token: String,
    pub name: String,
    pub permissions: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub api_key: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ListApiKeysRequest {
    pub auth_token: String,
}

#[derive(Debug, Serialize)]
pub struct ListApiKeysResponse {
    pub api_keys: Vec<ApiKeyInfo>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteApiKeyRequest {
    pub auth_token: String,
    pub api_key_id: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteApiKeyResponse {
    pub success: bool,
}

#[derive(Debug, Deserialize)]
pub struct ListUserSessionsRequest {
    pub auth_token: String,
}

#[derive(Debug, Serialize)]
pub struct ListUserSessionsResponse {
    pub sessions: Vec<SessionInfo>,
}

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct CloseUserSessionRequest {
    pub auth_token: String,
    pub session_id: String,
}

#[derive(Debug, Serialize)]
pub struct CloseUserSessionResponse {
    pub success: bool,
}

pub struct UserService {
    state: Arc<CloudflareServerState>,
}

impl UserService {
    pub fn new(state: Arc<CloudflareServerState>) -> Self {
        Self { state }
    }

    pub async fn register(&self, request: RegisterRequest) -> Result<AuthResponse> {
        let db = self.state.db();

        // Check if user already exists
        if db.get_user_by_email(&request.email).await?.is_some() {
            return Err(anyhow::anyhow!("User with this email already exists"));
        }

        // Hash password
        let password_hash = hash(request.password, DEFAULT_COST)?;

        // Create user
        let user = db.create_user(&request.email, &password_hash).await?;

        // Generate JWT token
        let expires_at = Utc::now() + Duration::days(30);
        let token = self.generate_jwt_token(&user, expires_at)?;

        Ok(AuthResponse {
            email: user.email,
            token,
            expires_at,
        })
    }

    pub async fn login(&self, request: LoginRequest) -> Result<AuthResponse> {
        let db = self.state.db();

        // Get user by email
        let user = db
            .get_user_by_email(&request.email)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid email or password"))?;

        // Verify password
        if !verify(request.password, &user.password_hash)? {
            return Err(anyhow::anyhow!("Invalid email or password"));
        }

        // Generate JWT token
        let expires_at = Utc::now() + Duration::days(30);
        let token = self.generate_jwt_token(&user, expires_at)?;

        Ok(AuthResponse {
            email: user.email,
            token,
            expires_at,
        })
    }

    pub async fn generate_api_key(&self, request: GenerateApiKeyRequest) -> Result<ApiKeyResponse> {
        let user = self.verify_auth_token(&request.auth_token).await?;
        let db = self.state.db();

        // Generate API key
        let api_key_value = format!("sshx_{}", Uuid::new_v4().to_string().replace('-', ""));
        let key_hash = hash(&api_key_value, DEFAULT_COST)?;

        let permissions = request
            .permissions
            .unwrap_or_else(|| vec!["read".to_string()]);

        let api_key = db
            .create_api_key(
                &user.id,
                &request.name,
                &key_hash,
                &permissions,
                request.expires_at,
            )
            .await?;

        Ok(ApiKeyResponse {
            id: api_key.id,
            name: api_key.name,
            api_key: api_key_value,
            permissions: api_key.permissions,
            expires_at: api_key.expires_at,
        })
    }

    pub async fn list_api_keys(&self, request: ListApiKeysRequest) -> Result<ListApiKeysResponse> {
        let user = self.verify_auth_token(&request.auth_token).await?;
        let db = self.state.db();

        let api_keys = db.list_api_keys_by_user(&user.id).await?;

        let api_key_infos = api_keys
            .into_iter()
            .map(|key| ApiKeyInfo {
                id: key.id,
                name: key.name,
                permissions: key.permissions,
                created_at: key.created_at,
                expires_at: key.expires_at,
                last_used_at: key.last_used_at,
            })
            .collect();

        Ok(ListApiKeysResponse {
            api_keys: api_key_infos,
        })
    }

    pub async fn delete_api_key(&self, request: DeleteApiKeyRequest) -> Result<bool> {
        let user = self.verify_auth_token(&request.auth_token).await?;
        let db = self.state.db();

        db.delete_api_key(&request.api_key_id, &user.id).await
    }

    pub async fn list_user_sessions(
        &self,
        request: ListUserSessionsRequest,
    ) -> Result<ListUserSessionsResponse> {
        let user = self.verify_auth_token(&request.auth_token).await?;
        let db = self.state.db();

        let sessions = db.list_sessions_by_user(&user.id).await?;

        let session_infos = sessions
            .into_iter()
            .map(|session| SessionInfo {
                id: session.id,
                name: session.name,
                created_at: session.created_at,
                last_activity: session.last_activity,
                status: session.status.as_str().to_string(),
            })
            .collect();

        Ok(ListUserSessionsResponse {
            sessions: session_infos,
        })
    }

    pub async fn close_user_session(&self, request: CloseUserSessionRequest) -> Result<bool> {
        let user = self.verify_auth_token(&request.auth_token).await?;
        let db = self.state.db();

        db.close_session(&request.session_id, &user.id).await
    }

    pub async fn verify_api_key(&self, api_key: &str) -> Result<(User, ApiKey)> {
        let key_hash = hash(api_key, DEFAULT_COST)?;
        let db = self.state.db();

        let api_key_record = db
            .get_api_key_by_hash(&key_hash)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid API key"))?;

        // Check if API key is expired
        if let Some(expires_at) = api_key_record.expires_at {
            if Utc::now() > expires_at {
                return Err(anyhow::anyhow!("API key has expired"));
            }
        }

        let user = db
            .get_user_by_id(&api_key_record.user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        Ok((user, api_key_record))
    }

    pub async fn verify_auth_token(&self, token: &str) -> Result<User> {
        let decoding_key = DecodingKey::from_secret(self.state.secret().as_bytes());
        let validation = Validation::default();

        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
        let claims = token_data.claims;

        let db = self.state.db();
        let user = db
            .get_user_by_id(&claims.sub)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        Ok(user)
    }

    fn generate_jwt_token(&self, user: &User, expires_at: DateTime<Utc>) -> Result<String> {
        let claims = Claims {
            sub: user.id.clone(),
            email: user.email.clone(),
            exp: expires_at.timestamp() as usize,
            iat: Utc::now().timestamp() as usize,
        };

        let encoding_key = EncodingKey::from_secret(self.state.secret().as_bytes());
        let token = encode(&Header::default(), &claims, &encoding_key)?;

        Ok(token)
    }
}
