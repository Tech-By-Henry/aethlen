use axum::{middleware, routing::get, Json, Router};
use dotenvy::dotenv;
use jsonwebtoken::{DecodingKey, EncodingKey};
use sea_orm::Database;
use std::{net::SocketAddr, sync::Arc};
use tracing::info;
use tracing_subscriber::EnvFilter;

use aethlen_core::{
    ensure_schema, spawn_token_janitor, AppState, JwtCfg,
    views::user_auth::auto_refresh_layer,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env (non-fatal if missing)
    dotenv().ok();

    // Logging: JSON if JSON_LOGS=true/1/yes/on, else pretty; default level = info
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json_logs = std::env::var("JSON_LOGS")
        .map(|v| {
            let v = v.to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(false);

    if json_logs {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .compact()
            .init();
    }

    // Config
    let db_url = std::env::var("DATABASE_URL")?;
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    // DB + schema
    let db = Database::connect(&db_url).await?;
    ensure_schema(&db).await?;

    // JWT cfg and keys
    let cfg = JwtCfg::from_env();
    let state = AppState {
        db,
        jwt_enc: Arc::new(EncodingKey::from_secret(jwt_secret.as_bytes())),
        jwt_dec: Arc::new(DecodingKey::from_secret(jwt_secret.as_bytes())),
        jwt_cfg: cfg,
    };

    // background cleanup
    spawn_token_janitor(state.clone());

    // Routes
    let public = aethlen_core::urls::public_routes();
    let protected = aethlen_core::urls::protected_routes()
        .layer(middleware::from_fn_with_state(state.clone(), auto_refresh_layer));

    let app = Router::new()
        .route("/healthz", get(|| async { Json(serde_json::json!({ "ok": true })) }))
        .merge(public)
        .merge(protected)
        .with_state(state);

    // Serve
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("listening on http://{}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
