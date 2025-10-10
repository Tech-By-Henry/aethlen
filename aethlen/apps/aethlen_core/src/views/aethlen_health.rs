use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct Health {  // <-- make it public
    pub status: &'static str,
    pub app: &'static str,
}

pub async fn health() -> Json<Health> {
    Json(Health { status: "ok", app: "iryx_core" })
}
