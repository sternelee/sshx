use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::D1Database;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub key_hash: String,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub user_id: Option<String>,
    pub api_key_id: Option<String>,
    pub host: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub status: SessionStatus,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Active,
    Closed,
    Expired,
}

impl SessionStatus {
    pub fn as_str(&self) -> &str {
        match self {
            SessionStatus::Active => "active",
            SessionStatus::Closed => "closed",
            SessionStatus::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub id: String,
    pub session_id: String,
    pub snapshot_data: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConnection {
    pub id: String,
    pub session_id: String,
    pub connection_id: String,
    pub user_id: Option<String>,
    pub connected_at: DateTime<Utc>,
    pub last_ping: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

pub struct D1Store {
    db: D1Database,
}

impl D1Store {
    pub fn new(db: D1Database) -> Self {
        Self { db }
    }

    // User operations
    pub async fn create_user(&self, email: &str, password_hash: &str) -> Result<User> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        let query = "
            INSERT INTO users (id, email, password_hash, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
        ";

        let _result = self
            .db
            .prepare(query)
            .bind(&[
                id.clone().into(),
                email.into(),
                password_hash.into(),
                now.clone().into(),
                now.clone().into(),
            ])?
            .run()
            .await?;

        Ok(User {
            id,
            email: email.to_string(),
            password_hash: password_hash.to_string(),
            created_at: DateTime::parse_from_rfc3339(&now)?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&now)?.with_timezone(&Utc),
        })
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let query =
            "SELECT id, email, password_hash, created_at, updated_at FROM users WHERE email = ?1";

        let result = self
            .db
            .prepare(query)
            .bind(&[email.into()])?
            .first::<User>(None)
            .await?;

        Ok(result)
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<Option<User>> {
        let query =
            "SELECT id, email, password_hash, created_at, updated_at FROM users WHERE id = ?1";

        let result = self
            .db
            .prepare(query)
            .bind(&[id.into()])?
            .first::<User>(None)
            .await?;

        Ok(result)
    }

    // API Key operations
    pub async fn create_api_key(
        &self,
        user_id: &str,
        name: &str,
        key_hash: &str,
        permissions: &[String],
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiKey> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let permissions_json = serde_json::to_string(permissions)?;

        let query = "
            INSERT INTO api_keys (id, user_id, name, key_hash, permissions, created_at, expires_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ";

        let _result = self
            .db
            .prepare(query)
            .bind(&[
                id.clone().into(),
                user_id.into(),
                name.into(),
                key_hash.into(),
                permissions_json.into(),
                now.to_rfc3339().into(),
                expires_at
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default()
                    .into(),
            ])?
            .run()
            .await?;

        Ok(ApiKey {
            id,
            user_id: user_id.to_string(),
            name: name.to_string(),
            key_hash: key_hash.to_string(),
            permissions: permissions.to_vec(),
            created_at: now,
            expires_at,
            last_used_at: None,
        })
    }

    pub async fn get_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        let query = "SELECT id, user_id, name, key_hash, permissions, created_at, expires_at, last_used_at FROM api_keys WHERE key_hash = ?1";

        let result = self
            .db
            .prepare(query)
            .bind(&[key_hash.into()])?
            .first::<ApiKey>(None)
            .await?;

        Ok(result)
    }

    pub async fn list_api_keys_by_user(&self, user_id: &str) -> Result<Vec<ApiKey>> {
        let query = "SELECT id, user_id, name, key_hash, permissions, created_at, expires_at, last_used_at FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC";

        let result = self
            .db
            .prepare(query)
            .bind(&[user_id.into()])?
            .all()
            .await?;

        let api_keys = result.results::<ApiKey>()?;
        Ok(api_keys)
    }

    pub async fn delete_api_key(&self, id: &str, user_id: &str) -> Result<bool> {
        let query = "DELETE FROM api_keys WHERE id = ?1 AND user_id = ?2";

        let result = self
            .db
            .prepare(query)
            .bind(&[id.into(), user_id.into()])?
            .run()
            .await?;

        // For D1, we check if the statement was successful
        Ok(result.success())
    }

    // Session operations
    pub async fn create_session(
        &self,
        name: &str,
        user_id: Option<&str>,
        api_key_id: Option<&str>,
        host: Option<&str>,
    ) -> Result<Session> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let query = "
            INSERT INTO sessions (id, name, user_id, api_key_id, host, created_at, last_activity, status, metadata)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ";

        self.db
            .prepare(query)
            .bind(&[
                id.clone().into(),
                name.into(),
                user_id.unwrap_or_default().into(),
                api_key_id.unwrap_or_default().into(),
                host.unwrap_or_default().into(),
                now.to_rfc3339().into(),
                now.to_rfc3339().into(),
                SessionStatus::Active.as_str().into(),
                "{}".into(),
            ])?
            .run()
            .await?;

        Ok(Session {
            id,
            name: name.to_string(),
            user_id: user_id.map(|s| s.to_string()),
            api_key_id: api_key_id.map(|s| s.to_string()),
            host: host.map(|s| s.to_string()),
            created_at: now,
            last_activity: now,
            status: SessionStatus::Active,
            metadata: serde_json::json!({}),
        })
    }

    pub async fn get_session_by_name(&self, name: &str) -> Result<Option<Session>> {
        let query = "SELECT id, name, user_id, api_key_id, host, created_at, last_activity, status, metadata FROM sessions WHERE name = ?1";

        if let Some(result) = self
            .db
            .prepare(query)
            .bind(&[name.into()])?
            .first::<Session>(None)
            .await?
        {
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    pub async fn list_sessions_by_user(&self, user_id: &str) -> Result<Vec<Session>> {
        let query = "SELECT id, name, user_id, api_key_id, host, created_at, last_activity, status, metadata FROM sessions WHERE user_id = ?1 ORDER BY created_at DESC";

        let result = self
            .db
            .prepare(query)
            .bind(&[user_id.into()])?
            .all()
            .await?;

        let sessions = result.results::<Session>()?;
        Ok(sessions)
    }

    pub async fn close_session(&self, session_id: &str, user_id: &str) -> Result<bool> {
        let query = "UPDATE sessions SET status = 'closed' WHERE id = ?1 AND user_id = ?2";

        let result = self
            .db
            .prepare(query)
            .bind(&[session_id.into(), user_id.into()])?
            .run()
            .await?;

        Ok(result.success())
    }

    pub async fn update_session_activity(&self, session_id: &str) -> Result<()> {
        let query = "UPDATE sessions SET last_activity = ?1 WHERE id = ?2";

        let _result = self
            .db
            .prepare(query)
            .bind(&[Utc::now().to_rfc3339().into(), session_id.into()])?
            .run()
            .await?;

        Ok(())
    }

    pub async fn update_session_metadata(
        &self,
        session_id: &str,
        metadata: &serde_json::Value,
    ) -> Result<()> {
        let query = "UPDATE sessions SET metadata = ?1 WHERE id = ?2";

        let _result = self
            .db
            .prepare(query)
            .bind(&[metadata.to_string().into(), session_id.into()])?
            .run()
            .await?;

        Ok(())
    }

    pub async fn get_all_sessions(&self) -> Result<Vec<Session>> {
        let query = "SELECT * FROM sessions ORDER BY created_at DESC";

        let result = self.db.prepare(query).all().await?;

        let sessions = result.results::<Session>()?;
        Ok(sessions)
    }
}
