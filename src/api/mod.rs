use anyhow::{anyhow, Context, Result as AnyResult};
use email_address::EmailAddress;
use openidconnect::core::CoreIdTokenClaims;
use uuid::Uuid;

use crate::oidc::OidcToken;
use crate::tables::users::UserId;

#[cfg(feature = "axum")]
mod axum;

#[cfg(feature = "warp")]
mod warp;

#[derive(Debug)]
#[non_exhaustive]
pub enum AuthRejectReason {
    OidcError { msg: &'static str },
    CsrfMismatch,
    TokenTransferFailed { msg: String },
    InvalidCredentials,
    InvalidSessionToken { reason: String },
    NoSessionToken,
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AuthenticatedUser {
    pub(super) id: Uuid,

    pub(super) username: String,
    pub(super) email: String,
    pub(super) email_verified: bool,
    pub(super) given_name: Option<String>,
    pub(super) family_name: Option<String>,
}

pub trait ValidatesIdentity {
    fn validate_token(&self, token: &OidcToken) -> anyhow::Result<CoreIdTokenClaims>;
    fn refresh_token(
        &self,
        token: OidcToken,
    ) -> impl std::future::Future<Output = anyhow::Result<OidcToken>> + std::marker::Send;
}

impl AuthenticatedUser {
    pub async fn validate_session<S: ValidatesIdentity>(
        idp: &S,
        token: OidcToken,
    ) -> AnyResult<(Self, Option<OidcToken>)> {
        let (claims, token) = match idp.validate_token(&token) {
            Ok(claims) => (claims, None),
            Err(_) => {
                // Try to refresh
                tracing::trace!("Refresh happening");
                let token = idp.refresh_token(token).await.context("token refresh")?;
                tracing::trace!("Refresh complete");
                (
                    idp.validate_token(&token).context("validate_token")?,
                    Some(token),
                )
            }
        };
        tracing::trace!("Claims");
        let user_id =
            Uuid::parse_str(claims.subject().as_str()).context("UUID claims.subject()")?;
        let user_name = claims
            .preferred_username()
            .ok_or_else(|| anyhow!("No username in claims"))?
            .as_str();
        let user_email = claims
            .email()
            .map(|email| email.as_str())
            .or_else(|| {
                if EmailAddress::is_valid(user_name) {
                    Some(user_name)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("No email in claims"))?;
        let email_verified = claims.email_verified().unwrap_or(false);
        let given_name = claims
            .given_name()
            .and_then(|name| name.get(None).map(|name| name.to_string()));
        let family_name = claims
            .family_name()
            .and_then(|name| name.get(None).map(|name| name.to_string()));

        tracing::trace!("Token validated");
        Ok((
            Self {
                id: user_id,
                username: user_name.to_string(),
                email: user_email.to_string(),
                email_verified,
                given_name,
                family_name,
            },
            token,
        ))
    }

    pub fn id(&self) -> UserId {
        UserId(self.id)
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn email(&self) -> String {
        self.email.clone()
    }

    pub fn email_verified(&self) -> bool {
        self.email_verified
    }

    pub fn given_name(&self) -> Option<String> {
        self.given_name.clone()
    }

    pub fn family_name(&self) -> Option<String> {
        self.family_name.clone()
    }
}

#[cfg(any(feature = "warp", feature = "axum"))]
pub mod sessions {
    #[cfg(feature = "warp")]
    pub use super::warp::sessions::*;

    #[cfg(feature = "warp")]
    impl warp::reject::Reject for super::AuthRejectReason {}

    #[cfg(feature = "axum")]
    pub use super::axum::sessions::*;
}

#[cfg(feature = "warp")]
pub use self::sessions::authenticate;

#[cfg(any(feature = "warp", feature = "axum"))]
pub mod email {
    #[cfg(feature = "warp")]
    pub use super::warp::email::*;

    #[cfg(feature = "axum")]
    pub use super::axum::email::*;
}

#[derive(Debug)]
pub struct AnyhowError {
    pub error: anyhow::Error,
}

impl From<anyhow::Error> for AnyhowError {
    fn from(error: anyhow::Error) -> Self {
        Self { error }
    }
}

impl From<AnyhowError> for String {
    fn from(anyerr: AnyhowError) -> String {
        anyerr.error.to_string()
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum RejectReason {
    BadRequest { reason: String },
    Conflict { resource: String },
    DatabaseError { msg: String },
    Forbidden { user_id: UserId, reason: String },
    MissingEnvKey { key: String },
    NotFound { resource: String },
    Session,
}

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

    pub fn forbidden<S: Into<String>>(user_id: UserId, reason: S) -> Self {
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

#[cfg(feature = "axum")]
pub use axum::AppState;

#[cfg(feature = "warp")]
pub use warp::{handle_rejection, init_session_store, with_broadcast, with_db, with_string};
