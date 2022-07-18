use axum_core::response::IntoResponse;
use axum::Router;
use axum::error_handling::HandleErrorLayer;
use tower::{BoxError, ServiceBuilder};
use tokio::time::Duration;
use hyper::http::StatusCode;

use crate::controller::auth::auth_routes;

pub fn register_router() -> Router {
    // new web service router
    let r = Router::new()
        .nest("/auth", auth_routes())
        .layer(
            ServiceBuilder::new()
                // Handle errors from middleware
                .layer(HandleErrorLayer::new(handle_error))
                .load_shed()
                .concurrency_limit(1024)
                .timeout(Duration::from_secs(10))
                .into_inner(),
        );
    r
}

async fn handle_error(error: BoxError) -> impl IntoResponse {
    if error.is::<tower::timeout::error::Elapsed>() {
        return (StatusCode::REQUEST_TIMEOUT, String::from("request timed out"));
    }

    if error.is::<tower::load_shed::error::Overloaded>() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            String::from("service is overloaded, try again later"),
        );
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        String::from(format!("Unhandled internal error: {}", error)),
    )
}