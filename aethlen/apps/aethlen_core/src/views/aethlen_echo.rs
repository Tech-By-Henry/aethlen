use axum::Json;
use crate::serializers::aethlen_echo::{AethlenEchoIn, AethlenEchoOut};

pub async fn echo(Json(inp): Json<AethlenEchoIn>) -> Json<AethlenEchoOut> {
    Json(AethlenEchoOut { echoed: inp.message })
}
