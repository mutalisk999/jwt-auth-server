use std::{env, fmt};
use std::sync::Arc;

use axum::{Extension, Json, Router};
use axum::extract::{BodyStream, Path};
use axum::routing::{get, post};
use axum_core::response::{IntoResponse, Response};

use bytes::Bytes;
use hyper::body;
use hyper::body::Body;
use hyper::http::{HeaderMap, HeaderValue};
use hyper::http::header::HeaderName;
use hyper::http::StatusCode;
use log::warn;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;

use chrono::Utc;
use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation};

use crate::utils::g::{RB_SESSION, JWT_SECRET};
use crate::model::t_user::{TUser, query_t_user_by_name};


const BEARER: &str = "Bearer ";

#[derive(Clone, PartialEq)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    pub fn from_str(role: &str) -> Role {
        match role {
            "Admin" => Role::Admin,
            _ => Role::User,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::User => write!(f, "User"),
            Role::Admin => write!(f, "Admin"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

pub async fn create_jwt(uid: &str, role: &Role, expire: i64) -> Result<String, JwtError> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(expire))
        .expect("invalid timestamp")
        .timestamp();

    let claims = Claims {
        sub: uid.to_owned(),
        role: role.to_string(),
        exp: expiration as usize,
    };
    let header = Header::new(Algorithm::HS512);
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET
        .as_ref()
        .read()
        .await.clone().as_ref()))
        .map(|jwt_str| BEARER.to_string() + &jwt_str)
        .map_err(|_| JwtError::JWTTokenCreationError)
}

pub async fn verify_jwt(jwt_str: &String) -> Result<Claims, JwtError> {
    if !jwt_str.starts_with(BEARER) {
        return Err(JwtError::InvalidAuthHeaderError);
    }
    let jwt_str = jwt_str.trim_start_matches(BEARER)
        .to_owned();

    let decoded = decode::<Claims>(jwt_str.as_ref(),
                                   &DecodingKey::from_secret(JWT_SECRET.as_ref().read().await.clone().as_ref()),
                                   &Validation::new(Algorithm::HS512)).map_err(|_| JwtError::JWTTokenError)?;
    Ok(decoded.claims.clone())
}

pub async fn check_authority(role: Role, jwt_str: &String) -> Result<Claims, JwtError> {
    let claim = match verify_jwt(jwt_str).await {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    if role == Role::Admin && Role::from_str(&claim.role) != Role::Admin {
        return Err(JwtError::NoPermissionError);
    }
    Ok(claim)
}

pub fn auth_routes() -> Router {
    Router::new()
        .route("/authorize", post(authorize))
        .route("/verify_authority", get(verify_authority))
        .layer(Extension(RB_SESSION.clone()))
}

async fn authorize(Json(payload): Json<AuthPayload>) -> Result<HeaderMap, AuthError> {
    // Check if the user sent the credentials
    if payload.username.is_empty() || payload.password.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    let res: Result<Option<TUser>, rbatis::core::Error> = query_t_user_by_name(&payload.username)
        .await;

    if res.is_err() {
        return Err(AuthError::RbatisQueryError);
    }
    let res = res.unwrap();

    if res.is_none() {
        return Err(AuthError::WrongCredentials);
    } else {
        let res = res.unwrap();

        // invalid password
        if res.password.unwrap() != payload.password {
            return Err(AuthError::WrongCredentials);
        } else {
            let id = res.id.unwrap().to_string();
            let role = res.id.unwrap();

            let res = if role == 0u64 {
                create_jwt(&id, &Role::Admin, 3600).await
            } else {
                create_jwt(&id, &Role::User, 3600).await
            };

            // create jwt fail
            if res.is_err() {
                Err(AuthError::TokenCreation)
            } else {
                let mut headers = HeaderMap::new();

                headers.insert(
                    HeaderName::from_static("Authorization"),
                    HeaderValue::from_str(res.unwrap().as_str()).unwrap(),
                );

                Ok(headers)
            }
        }
    }
}

async fn verify_authority(headers: HeaderMap) -> Result<(), AuthError> {
    Err(AuthError::WrongCredentials)
}


#[derive(Debug, Deserialize)]
struct AuthPayload {
    username: String,
    password: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::RbatisQueryError => (StatusCode::INTERNAL_SERVER_ERROR, "Rbatis query error"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

#[derive(Debug)]
enum AuthError {
    MissingCredentials,
    WrongCredentials,
    RbatisQueryError,
    TokenCreation,
    InvalidToken,
}

#[derive(Debug)]
pub enum JwtError {
    WrongCredentialsError,
    JWTTokenError,
    JWTTokenCreationError,
    NoAuthHeaderError,
    InvalidAuthHeaderError,
    NoPermissionError,
}