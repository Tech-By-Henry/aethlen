use axum::{Router, routing::get};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let json_logs = std::env::var("JSON_LOGS")
        .unwrap_or_else(|_| "false".into())
        .eq_ignore_ascii_case("true");
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if json_logs {
        tracing_subscriber::registry().with(env_filter).with(fmt::layer().json()).init();
    } else {
        tracing_subscriber::registry().with(env_filter).with(fmt::layer().without_time()).init();
    }

    // Base middleware stack (Django-like middlewares)
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    let stack = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(CompressionLayer::new());

    // Mount app routers (like including app urls.py)
    let app = Router::new()
        .route("/", get(|| async { "aethlen gateway alive" }))
        .nest("/api/core", iryx_core::urls::router())
        .nest("/api/ai",   iryx_ai::urls::router())
        .layer(stack);

    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    tracing::info!(%addr, "AETHLEN listening");

    // Axum 0.7 style
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
