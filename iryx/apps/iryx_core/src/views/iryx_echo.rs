use axum::Json;
use crate::serializers::iryx_echo::{IryxEchoIn, IryxEchoOut};

pub async fn echo(Json(inp): Json<IryxEchoIn>) -> Json<IryxEchoOut> {
    Json(IryxEchoOut { echoed: inp.message })
}
