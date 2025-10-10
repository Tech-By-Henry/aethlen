use axum::{Router, routing::{get, post}};
use crate::views::{iryx_health::health, iryx_echo::echo};

pub fn router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/echo",   post(echo))
}
