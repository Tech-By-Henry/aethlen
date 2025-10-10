use axum::Json;
use crate::serializers::aethlen_rewrite::{AethlenRewriteIn, AethlenRewriteOut};

pub async fn rewrite(Json(inp): Json<AethlenRewriteIn>) -> Json<AethlenRewriteOut> {
    // Stub: later call Ollama; for now, uppercase to prove the flow
    Json(AethlenRewriteOut { text: inp.text.to_uppercase(), note: "aethlen_ai stub" })
}
