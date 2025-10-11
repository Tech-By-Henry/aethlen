pub mod models;
pub mod serializers;
pub mod urls;
pub mod views;

use std::sync::Arc;

use anyhow::Result;
use chrono::Duration as ChronoDuration;
use jsonwebtoken::{DecodingKey, EncodingKey};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};
use tokio::time::{interval, Duration};
use tracing::info;

#[derive(Clone)]
pub struct JwtCfg {
    /// Access token TTL (default 120s). Override with ACCESS_TTL_SECS.
    pub access_ttl: ChronoDuration,
    /// Refresh token TTL (default 1 day). Override with REFRESH_TTL_SECS.
    pub refresh_ttl: ChronoDuration,
    /// Cookie flags for refresh token cookie
    pub cookie_secure: bool,
    pub cookie_domain: Option<String>,
    pub cookie_name: String,
    /// Background janitor tick interval in seconds (default 3600 = 1h).
    pub janitor_interval_secs: u64,
    /// How long to keep revoked tokens before hard-delete (default 30 days).
    pub revoked_retention_secs: i64,
}

impl JwtCfg {
    pub fn from_env() -> Self {
        let access_secs = std::env::var("ACCESS_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120); // 2 minutes
        let refresh_secs = std::env::var("REFRESH_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(86_400); // 1 day
        let cookie_secure = std::env::var("COOKIE_SECURE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(false);
        let cookie_domain = std::env::var("COOKIE_DOMAIN").ok();
        let cookie_name = std::env::var("REFRESH_COOKIE_NAME").unwrap_or("aethlen_refresh".into());

        let janitor_interval_secs = std::env::var("JANITOR_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600); // 1 hour

        let revoked_retention_secs = std::env::var("REVOKED_RETENTION_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30 * 24 * 3600); // 30 days

        Self {
            access_ttl: ChronoDuration::seconds(access_secs),
            refresh_ttl: ChronoDuration::seconds(refresh_secs),
            cookie_secure,
            cookie_domain,
            cookie_name,
            janitor_interval_secs,
            revoked_retention_secs,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub jwt_enc: Arc<EncodingKey>,
    pub jwt_dec: Arc<DecodingKey>,
    pub jwt_cfg: JwtCfg,
}

/// Ensure DB schema is up-to-date (calls migration crate).
pub async fn ensure_schema(db: &DatabaseConnection) -> Result<()> {
    use migration::Migrator;
    use sea_orm_migration::migrator::MigratorTrait; // bring the trait into scope
    Migrator::up(db, None).await?;
    Ok(())
}

/// Spawn background janitor: clears expired and stale-revoked refresh tokens.
pub fn spawn_token_janitor(state: AppState) {
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(state.jwt_cfg.janitor_interval_secs));
        loop {
            tick.tick().await;

            // build backend-specific SQL using a configurable retention window
            let secs = state.jwt_cfg.revoked_retention_secs;
            let backend = state.db.get_database_backend();
            let sql = match backend {
                DatabaseBackend::Postgres => {
                    format!(
                        r#"
DELETE FROM refresh_tokens
WHERE expires_at < NOW()
   OR (revoked_at IS NOT NULL AND revoked_at < NOW() - INTERVAL '{} seconds');
"#,
                        secs
                    )
                }
                DatabaseBackend::MySql => {
                    format!(
                        r#"
DELETE FROM refresh_tokens
WHERE expires_at < NOW()
   OR (revoked_at IS NOT NULL AND revoked_at < DATE_SUB(NOW(), INTERVAL {} SECOND));
"#,
                        secs
                    )
                }
                DatabaseBackend::Sqlite => {
                    format!(
                        r#"
DELETE FROM refresh_tokens
WHERE expires_at < DATETIME('now')
   OR (revoked_at IS NOT NULL AND revoked_at < DATETIME('now', '-{} seconds'));
"#,
                        secs
                    )
                }
            };

            let _ = state.db.execute(Statement::from_string(backend, sql)).await;
            info!("refresh token janitor ran");
        }
    });
}
