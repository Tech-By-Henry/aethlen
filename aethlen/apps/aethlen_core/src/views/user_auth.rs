use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use axum::http::Request;
use axum::body::Body;
use chrono::{Duration as ChronoDuration, Utc};
use cookie::{Cookie, SameSite};
use jsonwebtoken::{Algorithm, Header as JwtHeader, Validation};
use rand::rngs::OsRng;
use sea_orm::ActiveValue::NotSet;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, QueryFilter, Set, IntoActiveModel,
};
use uuid::Uuid;

use crate::models::refresh_token::{Column as RTCol, Entity as RT};
use crate::models::user::{self, Column as UserCol, Entity as User};
use crate::serializers::user_auth::{
    ApiError, AuthResp, Claims, LoginReq, SignupReq, UserPublic,
};
use crate::AppState;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm as ArgonAlgorithm, Argon2, Params, Version,
};

// ---------- handlers ----------
pub async fn signup(
    State(state): State<AppState>,
    Json(req): Json<SignupReq>,
) -> Result<(StatusCode, HeaderMap, Json<AuthResp>), (StatusCode, Json<ApiError>)> {
    if req.email.trim().is_empty() || req.username.trim().is_empty() || req.password.len() < 6 {
        return Err(bad("invalid input"));
    }

    if User::find()
        .filter(UserCol::Email.eq(&req.email))
        .one(&state.db)
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err(conflict("email already exists"));
    }
    if User::find()
        .filter(UserCol::Username.eq(&req.username))
        .one(&state.db)
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err(conflict("username already exists"));
    }

    let now = Utc::now();
    let hash = hash_password(&req.password).map_err(internal)?;

    let created = user::ActiveModel {
        id: NotSet,
        email: Set(req.email),
        username: Set(req.username),
        password_hash: Set(hash),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await
    .map_err(internal)?;

    let user = UserPublic {
        id: created.id,
        email: created.email.clone(),
        username: created.username.clone(),
        created_at: created.created_at.to_rfc3339(),
    };

    let sid = Uuid::new_v4();
    let access = issue_access_jwt(user.id, &user.username, &state, sid).map_err(internal)?;
    let (refresh, _) =
        issue_refresh_jwt_and_store(user.id, &user.username, &state, sid).await.map_err(internal)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        refresh_cookie(&state.jwt_cfg.cookie_name, &refresh, &state)
            .parse()
            .unwrap(),
    );

    Ok((StatusCode::CREATED, headers, Json(AuthResp { user, token: access })))
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginReq>,
) -> Result<(StatusCode, HeaderMap, Json<AuthResp>), (StatusCode, Json<ApiError>)> {
    let cond = Condition::any()
        .add(UserCol::Email.eq(&req.identifier))
        .add(UserCol::Username.eq(&req.identifier));

    let Some(found) = User::find()
        .filter(cond)
        .one(&state.db)
        .await
        .map_err(internal)?
    else {
        return Err(unauth("invalid credentials"));
    };

    if !verify_password(&found.password_hash, &req.password).map_err(internal)? {
        return Err(unauth("invalid credentials"));
    }

    let user = UserPublic {
        id: found.id,
        email: found.email.clone(),
        username: found.username.clone(),
        created_at: found.created_at.to_rfc3339(),
    };

    let sid = Uuid::new_v4();
    let access = issue_access_jwt(user.id, &user.username, &state, sid).map_err(internal)?;
    let (refresh, _) =
        issue_refresh_jwt_and_store(user.id, &user.username, &state, sid).await.map_err(internal)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        refresh_cookie(&state.jwt_cfg.cookie_name, &refresh, &state)
            .parse()
            .unwrap(),
    );

    Ok((StatusCode::OK, headers, Json(AuthResp { user, token: access })))
}

pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<UserPublic>), (StatusCode, Json<ApiError>)> {
    let claims = auth_from_header(&state, &headers)?;
    let Some(found) = User::find_by_id(claims.sub)
        .one(&state.db)
        .await
        .map_err(internal)?
    else {
        return Err(unauth("user not found"));
    };

    let user = UserPublic {
        id: found.id,
        email: found.email.clone(),
        username: found.username.clone(),
        created_at: found.created_at.to_rfc3339(),
    };
    Ok((StatusCode::OK, Json(user)))
}

pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, HeaderMap, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let name = &state.jwt_cfg.cookie_name;
    let refresh_token = cookie
        .split(';')
        .find_map(|kv| kv.trim().strip_prefix(&format!("{name}=")))
        .ok_or_else(|| unauth("missing refresh cookie"))?;

    // validate refresh
    let claims = decode_validated(refresh_token, &state).map_err(|_| unauth("invalid or expired refresh"))?;
    if claims.token_type != "refresh" {
        return Err(unauth("wrong token type"));
    }

    let r = RT::find()
        .filter(RTCol::Jti.eq(claims.jti))
        .one(&state.db)
        .await
        .map_err(internal)?
        .ok_or_else(|| unauth("refresh not found"))?;

    if r.revoked_at.is_some() || Utc::now() > r.expires_at {
        return Err(unauth("refresh revoked or expired"));
    }

    // rotate
    let access = issue_access_jwt(claims.sub, &claims.username, &state, claims.sid).map_err(internal)?;
    let (new_refresh, new_claims) =
        issue_refresh_jwt_and_store(claims.sub, &claims.username, &state, claims.sid)
            .await
            .map_err(internal)?;

    let mut am = r.into_active_model();
    am.replaced_by = Set(Some(new_claims.jti));
    am.revoked_at = Set(Some(Utc::now()));
    am.update(&state.db).await.map_err(internal)?;

    let mut out_headers = HeaderMap::new();
    out_headers.insert(
        header::SET_COOKIE,
        refresh_cookie(name, &new_refresh, &state).parse().unwrap(),
    );

    Ok((
        StatusCode::OK,
        out_headers,
        Json(serde_json::json!({ "access_token": access })),
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, HeaderMap, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    if let Some(refresh_token) = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
            raw.split(';')
                .find_map(|kv| kv.trim().strip_prefix(&format!("{}=", state.jwt_cfg.cookie_name)))
        })
    {
        if let Ok(claims) = decode_validated(refresh_token, &state) {
            if claims.token_type == "refresh" {
                if let Some(found) = RT::find()
                    .filter(RTCol::Jti.eq(claims.jti))
                    .one(&state.db)
                    .await
                    .map_err(internal)?
                {
                    let mut am = found.into_active_model();
                    am.revoked_at = Set(Some(Utc::now()));
                    let _ = am.update(&state.db).await;
                }
            }
        }
    }
    let mut out = HeaderMap::new();
    out.insert(
        header::SET_COOKIE,
        clear_refresh_cookie(&state.jwt_cfg.cookie_name, &state)
            .parse()
            .unwrap(),
    );
    Ok((StatusCode::OK, out, Json(serde_json::json!({"ok": true}))))
}

// ---------- middleware: auto-refresh access on expiry ----------
pub async fn auto_refresh_layer(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    // try current access
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let access_token = auth.and_then(|h| h.strip_prefix("Bearer "));

    let claims_result = match access_token {
        Some(t) => decode_validated(t, &state),
        None => Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        )),
    };

    match claims_result {
        Ok(c) => {
            // valid access; continue
            req.extensions_mut().insert(c);
            return next.run(req).await;
        }
        Err(err) => {
            // only attempt refresh if the access is expired
            if !matches!(err.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                return (StatusCode::UNAUTHORIZED, Json(ApiError { error: "invalid access token".into() })).into_response();
            }
        }
    }

    // try refresh cookie
    let cookies = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let name = &state.jwt_cfg.cookie_name;
    let Some(refresh_token) = cookies
        .split(';')
        .find_map(|kv| kv.trim().strip_prefix(&format!("{name}="))) else {
        return (StatusCode::UNAUTHORIZED, Json(ApiError { error: "session expired (no refresh)".into()})).into_response();
    };

    // validate & DB check
    let refresh_claims = match decode_validated(refresh_token, &state) {
        Ok(c) if c.token_type == "refresh" => c,
        _ => return (StatusCode::UNAUTHORIZED, Json(ApiError { error: "invalid refresh".into()})).into_response(),
    };

    if let Some(found) = RT::find()
        .filter(RTCol::Jti.eq(refresh_claims.jti))
        .one(&state.db)
        .await
        .ok()
        .flatten()
    {
        if found.revoked_at.is_some() || Utc::now() > found.expires_at {
            return (StatusCode::UNAUTHORIZED, Json(ApiError { error: "refresh revoked/expired".into()})).into_response();
        }
    } else {
        return (StatusCode::UNAUTHORIZED, Json(ApiError { error: "refresh missing".into()})).into_response();
    }

    // rotate & attach
    let access = match issue_access_jwt(
        refresh_claims.sub,
        &refresh_claims.username,
        &state,
        refresh_claims.sid,
    ) {
        Ok(t) => t,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let (new_refresh, new_claims) = match issue_refresh_jwt_and_store(
        refresh_claims.sub,
        &refresh_claims.username,
        &state,
        refresh_claims.sid,
    )
    .await
    {
        Ok(p) => p,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if let Some(old) = RT::find()
        .filter(RTCol::Jti.eq(refresh_claims.jti))
        .one(&state.db)
        .await
        .ok()
        .flatten()
    {
        let mut am = old.into_active_model();
        am.revoked_at = Set(Some(Utc::now()));
        am.replaced_by = Set(Some(new_claims.jti));
        let _ = am.update(&state.db).await;
    }

    // inject fresh access for downstream and set cookie on response
    let bearer = format!("Bearer {access}");
    req.headers_mut()
        .insert(header::AUTHORIZATION, HeaderValue::from_str(&bearer).unwrap());
    req.extensions_mut().insert(new_claims);

    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&refresh_cookie(name, &new_refresh, &state)).unwrap(),
    );
    resp.headers_mut()
        .insert("X-New-Access-Token", HeaderValue::from_str(&access).unwrap());
    resp
}

// ---------- password hashing ----------
fn hash_password(password: &str) -> Result<String, anyhow::Error> {
    // Argon2id with explicit params (stronger than defaults)
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(19456, 2, 1, None)?; // ~19MB mem, 2 iters (tune for prod)
    let argon = Argon2::new(ArgonAlgorithm::Argon2id, Version::V0x13, params);
    Ok(argon.hash_password(password.as_bytes(), &salt)?.to_string())
}

fn verify_password(phc: &str, password: &str) -> Result<bool, anyhow::Error> {
    let parsed = PasswordHash::new(phc)?;
    let params = Params::new(19456, 2, 1, None)?;
    let argon = Argon2::new(ArgonAlgorithm::Argon2id, Version::V0x13, params);
    Ok(argon
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

// ---------- jwt helpers ----------
fn base_claims(
    user_id: i64,
    username: &str,
    token_type: &str,
    ttl: ChronoDuration,
    sid: Uuid,
) -> Claims {
    let now = Utc::now();
    Claims {
        sub: user_id,
        username: username.to_string(),
        token_type: token_type.to_string(),
        jti: Uuid::new_v4(),
        sid,
        iat: now.timestamp(),
        exp: (now + ttl).timestamp(),
        iss: "aethlen".into(),
        aud: "aethlen-app".into(),
    }
}

fn issue_access_jwt(
    user_id: i64,
    username: &str,
    state: &AppState,
    sid: Uuid,
) -> Result<String, anyhow::Error> {
    let claims = base_claims(
        user_id,
        username,
        "access",
        state.jwt_cfg.access_ttl,
        sid,
    );
    Ok(jsonwebtoken::encode(
        &JwtHeader::new(Algorithm::HS256),
        &claims,
        &state.jwt_enc,
    )?)
}

async fn issue_refresh_jwt_and_store(
    user_id: i64,
    username: &str,
    state: &AppState,
    sid: Uuid,
) -> Result<(String, Claims), anyhow::Error> {
    use crate::models::refresh_token::ActiveModel as RTActive;

    let now = Utc::now();
    let claims = base_claims(
        user_id,
        username,
        "refresh",
        state.jwt_cfg.refresh_ttl,
        sid,
    );
    let token = jsonwebtoken::encode(&JwtHeader::new(Algorithm::HS256), &claims, &state.jwt_enc)?;

    let row = RTActive {
        id: NotSet,
        user_id: Set(user_id),
        jti: Set(claims.jti),
        session_id: Set(sid),
        issued_at: Set(now),
        expires_at: Set(chrono::DateTime::from_timestamp(claims.exp, 0).unwrap()),
        revoked_at: Set(None),
        replaced_by: Set(None),
        created_at: Set(now),
    };
    row.insert(&state.db).await?;
    Ok((token, claims))
}

fn decode_validated(
    token: &str,
    state: &AppState,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut v = Validation::new(Algorithm::HS256);
    v.validate_exp = true;
    v.set_audience(&["aethlen-app"]);
    v.set_issuer(&["aethlen"]);
    jsonwebtoken::decode::<Claims>(token, &state.jwt_dec, &v).map(|d| d.claims)
}

pub fn auth_from_header(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Claims, (StatusCode, Json<ApiError>)> {
    let Some(h) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return Err(unauth("missing bearer token"));
    };
    if !h.starts_with("Bearer ") {
        return Err(unauth("missing bearer token"));
    }
    let token = &h[7..];
    decode_validated(token, state)
        .map_err(|e| {
            if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                unauth("expired access token")
            } else {
                unauth("invalid or expired token")
            }
        })
}

// ---------- cookies ----------
fn refresh_cookie(name: &str, value: &str, state: &AppState) -> String {
    // cookie 0.18 API: build takes something Into<Cookie>
    let mut c = Cookie::build((name.to_string(), value.to_string()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::seconds(
            state.jwt_cfg.refresh_ttl.num_seconds(),
        ))
        .build();

    if state.jwt_cfg.cookie_secure {
        c.set_secure(true);
    }
    if let Some(ref d) = state.jwt_cfg.cookie_domain {
        c.set_domain(d.clone());
    }

    c.to_string()
}

fn clear_refresh_cookie(name: &str, state: &AppState) -> String {
    let mut c = Cookie::build((name.to_string(), "".to_string()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .expires(time::OffsetDateTime::UNIX_EPOCH)
        .build();
    if state.jwt_cfg.cookie_secure {
        c.set_secure(true);
    }
    if let Some(ref d) = state.jwt_cfg.cookie_domain {
        c.set_domain(d.clone());
    }
    c.to_string()
}

// ---------- small helpers ----------
fn bad(msg: &str) -> (StatusCode, Json<ApiError>) {
    (StatusCode::BAD_REQUEST, Json(ApiError { error: msg.into() }))
}
fn conflict(msg: &str) -> (StatusCode, Json<ApiError>) {
    (StatusCode::CONFLICT, Json(ApiError { error: msg.into() }))
}
fn unauth(msg: &str) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiError { error: msg.into() }),
    )
}
fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            error: e.to_string(),
        }),
    )
}
