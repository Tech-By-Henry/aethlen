use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Json, Router,
};
use dotenvy::dotenv;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Serialize)]
struct Health { ok: bool, service: &'static str }

#[derive(Deserialize)]
struct ChatReq {
    messages: serde_json::Value,
    system_profile: Option<String>,
    stream: Option<bool>,
    max_tokens: Option<u32>,
    temperature: Option<f32>,
}

#[derive(Serialize)]
struct ChatResp {
    text: String,
    model: &'static str,
    usage: serde_json::Value,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).compact().init();

    let port: u16 = std::env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(3000);

    let app = Router::new()
        .route("/healthz", get(|| async { Json(Health { ok: true, service: "aethlen-ai-core" }) }))
        .route("/v1/chat", post(chat_stub))
        .route("/v1/vision-chat", post(not_implemented))
        .route("/v1/stt", post(not_implemented))
        .route("/v1/tts", post(not_implemented))
        .route("/v1/ocr", post(not_implemented))
        .route("/v1/embeddings", post(not_implemented))
        .layer(DefaultBodyLimit::max(25 * 1024 * 1024));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("listening on http://{}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn chat_stub(Json(_req): Json<ChatReq>) -> Json<ChatResp> {
    Json(ChatResp {
        text: "Hi! I’m Aethlen. The AI engine is stubbed here — wiring providers is next.".into(),
        model: "stub",
        usage: serde_json::json!({"in_tokens": 0, "out_tokens": 0}),
    })
}

async fn not_implemented() -> (axum::http::StatusCode, Json<serde_json::Value>) {
    (axum::http::StatusCode::NOT_IMPLEMENTED, Json(serde_json::json!({
        "error": "not_implemented",
        "message": "Endpoint is stubbed. AI providers will be wired next."
    })))
}
