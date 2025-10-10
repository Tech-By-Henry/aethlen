use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct AethlenRewriteIn { pub text: String }

#[derive(Serialize)]
pub struct AethlenRewriteOut { pub text: String, pub note: &'static str }
