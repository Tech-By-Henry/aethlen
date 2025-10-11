use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct SignupReq {
    pub email: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginReq {
    pub identifier: String, // email or username
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserPublic {
    pub id: i64,
    pub email: String,
    pub username: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResp {
    pub user: UserPublic,
    /// short-lived access token (JWT)
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: i64,
    pub username: String,
    pub token_type: String, // "access" | "refresh"
    pub jti: Uuid,
    pub sid: Uuid,          // session id
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub aud: String,
}
