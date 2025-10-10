use axum::{Router, routing::{get, post}};
use crate::views::{aethlen_health::health, aethlen_echo::echo};

pub fn router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/echo",   post(echo))
}
