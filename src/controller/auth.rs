use axum::{Extension, Json, Router};
use axum::routing::{get, post};
use axum_core::response::{IntoResponse, Response};
use chrono::Utc;
use hyper::http::{HeaderMap, HeaderValue};
use hyper::http::header::HeaderName;
use hyper::http::StatusCode;
use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::model::t_user::{query_t_user_by_name, TUser};
use crate::utils::g::{JWT_SECRET, RB_SESSION};

const BEARER: &str = "Bearer ";
const AUTHORIZATION: &str = "AUTHORIZATION";


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

async fn authorize(Json(payload): Json<AuthPayload>) -> Result<HeaderMap, AuthError> {
    // Check if the user sent the credentials
    if payload.username.is_empty() || payload.password.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    let res: Result<Option<TUser>, rbatis::core::Error> = query_t_user_by_name(&payload.username)
        .await;

    if res.is_err() {
        return Err(AuthError::RBatisQueryError);
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
            let role = res.role.unwrap();

            let res = create_jwt(&id, role, 86400).await;
            match res {
                Ok(v) => {
                    let mut headers = HeaderMap::new();

                    headers.insert(
                        HeaderName::from_static(AUTHORIZATION),
                        HeaderValue::from_str(v.as_str()).unwrap(),
                    );

                    Ok(headers)
                }
                Err(e) => Err(e),
            }
        }
    }
}

async fn verify(headers: HeaderMap) -> Result<Json<Claims>, AuthError> {
    let mut jwt_str = String::default();
    let mut jwt_found = false;

    if let Some(auth_token) = headers.get(HeaderName::from_static(AUTHORIZATION)) {
        if let Ok(auth_token_str) = auth_token.to_str() {
            jwt_str = auth_token_str.to_string();
            jwt_found = true;
        }
    }
    if !jwt_found {
        // not found valid header
        return Err(AuthError::NoAuthHeaderError);
    }

    let claim = match verify_jwt(&jwt_str).await {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    if claim.exp < Utc::now().timestamp() {
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
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::RBatisQueryError => (StatusCode::INTERNAL_SERVER_ERROR, "RBatis query error"),
            AuthError::TokenCreationError => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidTokenError => (StatusCode::BAD_REQUEST, "Invalid token error"),
            AuthError::ExpirationToken => (StatusCode::UNAUTHORIZED, "Expiration token"),
            AuthError::NoAuthHeaderError => (StatusCode::BAD_REQUEST, "No auth header token error"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

#[derive(Debug)]
pub enum AuthError {
    MissingCredentials,
    WrongCredentials,
    RBatisQueryError,
    TokenCreationError,
    ExpirationToken,
    NoAuthHeaderError,
    InvalidTokenError,
}
