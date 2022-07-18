use std::env;
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


pub fn auth_routes() -> Router {
    Router::new()
}