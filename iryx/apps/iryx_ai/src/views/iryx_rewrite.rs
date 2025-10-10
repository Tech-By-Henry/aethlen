use axum::Json;
use crate::serializers::iryx_rewrite::{IryxRewriteIn, IryxRewriteOut};

pub async fn rewrite(Json(inp): Json<IryxRewriteIn>) -> Json<IryxRewriteOut> {
    // Stub: later call Ollama; for now, uppercase to prove the flow
    Json(IryxRewriteOut { text: inp.text.to_uppercase(), note: "iryx_ai stub" })
}
