use axum::{Router, routing::post};
use crate::views::aethlen_rewrite::rewrite;

pub fn router() -> Router {
    Router::new()
        .route("/rewrite", post(rewrite))
}
