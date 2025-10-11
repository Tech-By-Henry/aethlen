use axum::{routing::{get, post}, Router};

use crate::{views::user_auth, AppState};

/// Routes that do NOT require auth (no middleware)
pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/auth/signup",  post(user_auth::signup))
        .route("/auth/login",   post(user_auth::login))
        .route("/auth/refresh", post(user_auth::refresh))
        .route("/auth/logout",  post(user_auth::logout))
}

/// Routes that DO require auth (middleware will be applied by the gateway)
pub fn protected_routes() -> Router<AppState> {
    Router::new()
        .route("/auth/me", get(user_auth::me))
}
