pub mod email;
pub mod sessions;

use std::sync::Arc;

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use uuid::Uuid;

use super::{AnyhowError, AuthRejectReason, RejectReason};
use crate::{oidc::IdentityProvider, tables::DbPool, ChannelRouter};

impl RejectReason {
    pub fn bad_request<S: Into<String>>(reason: S) -> Self {
        RejectReason::BadRequest {
            reason: reason.into(),
        }
    }

    pub fn conflict<S: Into<String>>(resource: S) -> Self {
        RejectReason::Conflict {
            resource: resource.into(),
        }
    }

    pub fn pool_error(err: bb8::RunError<diesel_async::pooled_connection::PoolError>) -> Self {
        RejectReason::DatabaseError {
            msg: format!("pool {}", err),
        }
    }
    pub fn database_error(err: diesel::result::Error) -> Self {
        RejectReason::DatabaseError {
            msg: format!("database {}", err),
        }
    }

    pub fn forbidden<S: Into<String>>(user_id: Uuid, reason: S) -> Self {
        RejectReason::Forbidden {
            user_id,
            reason: reason.into(),
        }
    }

    pub fn missing_env_key<S: Into<String>>(key: S) -> Self {
        RejectReason::MissingEnvKey { key: key.into() }
    }

    pub fn not_found<S: Into<String>>(resource: S) -> Self {
        RejectReason::NotFound {
            resource: resource.into(),
        }
    }

    pub fn session() -> Self {
        RejectReason::Session
    }
}

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
                serde_json::to_string(&json!({"error": "An error occured"}))
                    .expect("valid json"),
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
                serde_json::to_string(&json!({"error": "An error occured"}))
                    .expect("valid json"),
            )
                .into_response(),
        }
    }
}
