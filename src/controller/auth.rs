use axum::{Extension, Router};
use axum::extract::{BodyStream, Json};
use axum::routing::{get, post};
use axum_core::response::{IntoResponse, Response};
use chrono::Utc;
use hyper;
use hyper::body;
use hyper::body::Body;
use hyper::http::{HeaderMap, HeaderValue};
use hyper::http::StatusCode;
use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror;

use crate::model::t_user::{query_t_user_by_name, TUser};
use crate::utils::g::{JWT_SECRET, RB_SESSION};

const BEARER: &str = "Bearer ";


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    sub: String,
    role: u8,
    exp: i64,
}

pub async fn create_jwt(uid: &str, role: u8, expire: i64) -> Result<String, AuthError> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(expire))
        .expect("invalid timestamp")
        .timestamp();

    let claims = Claims {
        sub: uid.to_owned(),
        role,
        exp: expiration,
    };
    let header = Header::new(Algorithm::HS512);
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET
        .as_ref()
        .read()
        .await.clone().as_ref()))
        .map(|jwt_str| BEARER.to_string() + &jwt_str)
        .map_err(|_| AuthError::TokenCreationError)
}

pub async fn verify_jwt(jwt_str: &String) -> Result<Claims, AuthError> {
    if !jwt_str.starts_with(BEARER) {
        return Err(AuthError::InvalidTokenError);
    }
    let jwt_str = jwt_str.trim_start_matches(BEARER)
        .to_owned();

    let decoded = decode::<Claims>(jwt_str.as_ref(),
                                   &DecodingKey::from_secret(JWT_SECRET.as_ref().read().await.clone().as_ref()),
                                   &Validation::new(Algorithm::HS512)).map_err(|_| AuthError::InvalidTokenError)?;
    Ok(decoded.claims.clone())
}


pub fn auth_routes() -> Router {
    Router::new()
        .route("/authorize", post(authorize))
        .route("/verify", get(verify))
        .layer(Extension(RB_SESSION.clone()))
}

async fn authorize(stream: BodyStream) -> Result<HeaderMap, AuthError> {
    let mut bytes_req: Vec<u8> = vec![];
    match body::to_bytes(Body::wrap_stream(stream)).await {
        Ok(v) => {
            bytes_req.extend_from_slice(v.to_vec().as_slice());
        }
        Err(e) => {
            // read body stream error
            warn!("Read body stream error: {}", e.to_string());
            return Err(AuthError::MissingCredentials);
        }
    }

    let req_str = match std::str::from_utf8(&bytes_req) {
        Ok(v) => v,
        Err(e) => {
            warn!("From vec to string error: {}", e.to_string());
            return Err(AuthError::MissingCredentials);
        }
    };

    let payload: AuthPayload = match serde_json::from_str(req_str) {
        Ok(v) => v,
        Err(e) => {
            warn!("payload from string error: {}", e.to_string());
            return Err(AuthError::MissingCredentials);
        }
    };

    // Check if the user sent the credentials
    if payload.username.is_empty() || payload.password.is_empty() {
        warn!("payload is empty");
        return Err(AuthError::WrongCredentials);
    }

    let res: Option<TUser> = match query_t_user_by_name(&payload.username).await {
        Ok(v) => v,
        Err(e) => {
            warn!("query_t_user_by_name error: {}", e.to_string());
            return Err(AuthError::RBatisQueryError);
        }
    };

    if res.is_none() {
        warn!("query_t_user_by_name returns none");
        return Err(AuthError::WrongCredentials);
    } else {
        let res = res.unwrap();

        // invalid password
        if res.password.unwrap() != payload.password {
            warn!("invalid password");
            return Err(AuthError::WrongCredentials);
        } else {
            let id = res.id.unwrap().to_string();
            let role = res.role.unwrap();

            let res = create_jwt(&id, role, 86400).await;
            return match res {
                Ok(v) => {
                    let mut headers = HeaderMap::new();

                    headers.insert(
                        hyper::http::header::AUTHORIZATION,
                        HeaderValue::from_str(v.as_str()).unwrap(),
                    );
                    Ok(headers)
                }
                Err(e) => {
                    warn!("create_jwt error: {}", e.to_string());
                    Err(e)
                }
            };
        }
    }
}

async fn verify(headers: HeaderMap) -> Result<Json<Claims>, AuthError> {
    let mut jwt_str = String::default();
    let mut jwt_found = false;

    if let Some(auth_token) = headers.get(hyper::http::header::AUTHORIZATION) {
        if let Ok(auth_token_str) = auth_token.to_str() {
            jwt_str = auth_token_str.to_string();
            jwt_found = true;
        }
    }
    if !jwt_found {
        // not found valid header
        warn!("not found valid header [authorization]");
        return Err(AuthError::NoAuthHeaderError);
    }

    let claim = match verify_jwt(&jwt_str).await {
        Ok(v) => v,
        Err(e) => {
            warn!("verify_jwt error: {}", e.to_string());
            return Err(e);
        }
    };

    if claim.exp < Utc::now().timestamp() {
        warn!("token is expired");
        return Err(AuthError::ExpirationToken);
    }

    Ok(axum::Json(claim))
}


#[derive(Debug, Deserialize)]
struct AuthPayload {
    username: String,
    password: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::RBatisQueryError => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AuthError::TokenCreationError => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AuthError::ExpirationToken => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::NoAuthHeaderError => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::InvalidTokenError => (StatusCode::BAD_REQUEST, self.to_string()),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("missing credentials")]
    MissingCredentials,
    #[error("wrong credentials")]
    WrongCredentials,
    #[error("rbatis query error")]
    RBatisQueryError,
    #[error("token creation error")]
    TokenCreationError,
    #[error("expiration token")]
    ExpirationToken,
    #[error("no auth header error")]
    NoAuthHeaderError,
    #[error("invalid token error")]
    InvalidTokenError,
}
