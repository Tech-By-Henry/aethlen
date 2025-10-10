use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct IryxEchoIn { pub message: String }

#[derive(Serialize)]
pub struct IryxEchoOut { pub echoed: String }
