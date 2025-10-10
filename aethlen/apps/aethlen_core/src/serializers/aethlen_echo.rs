use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct AethlenEchoIn { pub message: String }

#[derive(Serialize)]
pub struct AethlenEchoOut { pub echoed: String }
