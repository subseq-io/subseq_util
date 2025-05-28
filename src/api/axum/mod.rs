pub mod email;
pub mod integrations;
pub mod sessions;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{json, Value};
use uuid::Uuid;

use super::{AnyhowError, AuthRejectReason, RejectReason};
use crate::{oidc::IdentityProvider, tables::DbPool, ChannelRouter, UserId};

pub trait Integration {
    fn name(&self) -> &'static str;
    fn create(
        &self,
        pool: Arc<DbPool>,
        user_id: UserId,
        data: Value,
    ) -> Pin<Box<dyn Future<Output = Result<Uuid, RejectReason>> + Send>>;
    fn get(
        &self,
        pool: Arc<DbPool>,
        user_id: UserId,
    ) -> Pin<Box<dyn Future<Output = Result<Value, RejectReason>> + Send>>;
}

#[derive(Clone)]
pub struct AppState {
    pub db_pool: Arc<DbPool>,
    pub priority_db_pool: Arc<DbPool>,
    pub idp: Arc<IdentityProvider>,
    pub router: ChannelRouter,
    pub base_url: String,
    pub admin_url: Option<String>,
    pub integrations: Vec<Arc<dyn Integration + Send + Sync>>,
}

impl IntoResponse for AnyhowError {
    fn into_response(self) -> Response {
        tracing::warn!("AnyhowError: {:?}", self.error);
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
        tracing::trace!("RejectReason: {:?}", self);
        match self {
            RejectReason::BadRequest { reason } => (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": reason})).expect("valid json"),
            )
                .into_response(),
            RejectReason::Conflict { resource } => (
                StatusCode::CONFLICT,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": resource})).expect("valid json"),
            )
                .into_response(),
            RejectReason::Forbidden { user_id, reason } => {
                tracing::info!("UserId: {}, Forbidden: {}", user_id, reason);
                (
                    StatusCode::FORBIDDEN,
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::to_string(&json!({"error": reason})).expect("valid json"),
                )
                    .into_response()
            }
            RejectReason::NotFound { resource } => (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": resource})).expect("valid json"),
            )
                .into_response(),
            RejectReason::Anyhow { error } => error.into_response(),
            _ => {
                tracing::error!("RejectReason: {:?}", self);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::to_string(&json!({"error": "An error occured"}))
                        .expect("valid json"),
                )
                    .into_response()
            }
        }
    }
}

impl IntoResponse for AuthRejectReason {
    fn into_response(self) -> Response {
        tracing::trace!("AuthRejectReason: {:?}", self);
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
