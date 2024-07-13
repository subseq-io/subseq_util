pub mod email;
pub mod sessions;

use std::sync::Arc;

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::{AnyhowError, AuthRejectReason, RejectReason};
use crate::{oidc::IdentityProvider, tables::DbPool, ChannelRouter};

#[derive(Clone)]
pub struct AppState {
    pub db_pool: Arc<DbPool>,
    pub idp: Arc<IdentityProvider>,
    pub router: ChannelRouter,
    pub base_url: String,
}

impl IntoResponse for AnyhowError {
    fn into_response(self) -> Response {
        tracing::info!("AnyhowError: {:?}", self.error);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::to_string(&json!({"error": "An error occured"})).expect("valid json"),
        )
            .into_response()
    }
}

impl IntoResponse for RejectReason {
    fn into_response(self) -> Response {
        match self {
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": "An error occured"})).expect("valid json"),
            )
                .into_response(),
        }
    }
}

impl IntoResponse for AuthRejectReason {
    fn into_response(self) -> Response {
        match self {
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": "An error occured"})).expect("valid json"),
            )
                .into_response(),
        }
    }
}
