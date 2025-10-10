use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct IryxRewriteIn { pub text: String }

#[derive(Serialize)]
pub struct IryxRewriteOut { pub text: String, pub note: &'static str }
