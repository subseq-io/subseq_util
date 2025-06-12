use anyhow::{anyhow, Context, Result as AnyResult};
use email_address::EmailAddress;
use openidconnect::core::{CoreIdToken, CoreIdTokenClaims};
use openidconnect::ClaimsVerificationError;
use serde::Serialize;
use uuid::Uuid;

use crate::oidc::OidcToken;
use crate::tables::users::UserId;

#[cfg(feature = "axum")]
mod axum;

#[cfg(feature = "warp")]
mod warp;

#[derive(Clone, Debug)]
pub struct ActiveUser(pub UserId);

#[derive(Debug, Serialize)]
#[non_exhaustive]
pub enum AuthRejectReason {
    OidcError { msg: &'static str },
    CsrfMismatch,
    TokenTransferFailed { msg: String },
    InvalidCredentials,
    InvalidSessionToken { reason: String },
    NoSessionToken,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthenticatedUser {
    pub(super) id: Uuid,
    pub(super) authorization: CoreIdToken,
    pub(super) claims: CoreIdTokenClaims,
}

pub trait ValidatesIdentity {
    fn validate_bearer(&self, token: &str) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError>;
    fn validate_token(
        &self,
        token: &OidcToken,
    ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError>;
    fn refresh_token(
        &self,
        token: OidcToken,
    ) -> impl std::future::Future<Output = anyhow::Result<OidcToken>> + std::marker::Send;
}

impl AuthenticatedUser {
    pub async fn from_claims(token: CoreIdToken, claims: CoreIdTokenClaims) -> AnyResult<Self> {
        let user_id = Uuid::parse_str(claims.subject().as_str())
            .context("Failed to parse UUID from claims.subject()")?;

        // Must include username and email
        let user_name = claims
            .preferred_username()
            .ok_or_else(|| anyhow!("No username in claims"))?;
        claims
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
        Ok(Self {
            id: user_id,
            authorization: token,
            claims,
        })
    }

    pub async fn validate_session<S: ValidatesIdentity>(
        idp: &S,
        token: OidcToken,
    ) -> AnyResult<(Self, Option<OidcToken>)> {
        let (token, claims, refresh_token) = match idp.validate_token(&token) {
            Ok(result) => (result.0, result.1, None),
            Err(err) => {
                // Try to refresh
                tracing::trace!("Refresh happening: {:?}", err);
                match err {
                    ClaimsVerificationError::Expired(_) => {
                        let refresh_token = idp.refresh_token(token).await.context("token refresh")?;
                        tracing::trace!("Refresh complete");
                        let (token, claims) = idp.validate_token(&refresh_token).context("validate_token")?;
                        (token, claims, Some(refresh_token))
                    }
                    ClaimsVerificationError::InvalidAudience(other) => {
                        tracing::trace!("Invalid audience: {:?}", other);
                        return Err(anyhow!("Invalid audience: {}", other));
                    }
                    ClaimsVerificationError::InvalidAuthContext(other) => {
                        tracing::trace!("Invalid auth context: {:?}", other);
                        return Err(anyhow!("Invalid auth context: {}", other));
                    }
                    ClaimsVerificationError::InvalidAuthTime(other) => {
                        tracing::trace!("Invalid auth time: {:?}", other);
                        return Err(anyhow!("Invalid auth time: {}", other));
                    }
                    ClaimsVerificationError::InvalidIssuer(other) => {
                        tracing::trace!("Invalid issuer: {:?}", other);
                        return Err(anyhow!("Invalid issuer: {}", other));
                    }
                    ClaimsVerificationError::InvalidNonce(other) => {
                        tracing::trace!("Invalid nonce: {:?}", other);
                        return Err(anyhow!("Invalid nonce: {}", other));
                    }
                    ClaimsVerificationError::InvalidSubject(other) => {
                        tracing::trace!("Invalid subject: {:?}", other);
                        return Err(anyhow!("Invalid subject: {}", other));
                    }
                    ClaimsVerificationError::SignatureVerification(other) => {
                        tracing::trace!("Signature verification error: {:?}", other);
                        return Err(anyhow!("Signature verification error: {}", other));
                    }
                    ClaimsVerificationError::Unsupported(other) => {
                        tracing::trace!("Unsupported claims verification error: {:?}", other);
                        return Err(anyhow!("Unsupported claims verification error: {}", other));
                    }
                    _ => {
                        tracing::trace!("Other claims verification error");
                        return Err(anyhow!("Claims verification error"));
                    }
                }
            }
        };
        let auth_user = Self::from_claims(token, claims).await?;
        Ok((auth_user, refresh_token))
    }

    pub fn authorization(&self) -> &CoreIdToken {
        &self.authorization
    }

    pub fn id(&self) -> UserId {
        UserId(self.id)
    }

    pub fn username(&self) -> String {
        // Guaranteed by `from_claims` that preferred_username is present
        self.claims.preferred_username().unwrap().to_string()
    }

    pub fn email(&self) -> String {
        // Guaranteed by `from_claims` that email is present and valid
        let user_name = self.username();
        self.claims
            .email()
            .map(|email| email.as_str())
            .or_else(|| {
                if EmailAddress::is_valid(&user_name) {
                    Some(&user_name)
                } else {
                    None
                }
            })
            .expect("No email in claims or username is not a valid email")
            .to_string()
    }

    pub fn email_verified(&self) -> bool {
        self.claims.email_verified().unwrap_or(false)
    }

    pub fn given_name(&self) -> Option<String> {
        self.claims
            .given_name()
            .and_then(|name| name.get(None))
            .map(|name| name.to_string())
    }

    pub fn family_name(&self) -> Option<String> {
        self.claims
            .family_name()
            .and_then(|name| name.get(None))
            .map(|name| name.to_string())
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

#[cfg(feature = "axum")]
pub mod integrations {
    pub use super::axum::integrations::*;
    pub use super::axum::Integration;
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
    Auth { reason: AuthRejectReason },
    Anyhow { error: AnyhowError },
    BadRequest { reason: String },
    Conflict { resource: String },
    DatabaseError { msg: String },
    Forbidden { user_id: UserId, reason: String },
    MissingEnvKey { key: String },
    NotFound { resource: String },
    Session,
}

impl RejectReason {
    pub fn auth(reason: AuthRejectReason) -> Self {
        RejectReason::Auth { reason }
    }

    pub fn anyhow(error: anyhow::Error) -> Self {
        RejectReason::Anyhow {
            error: AnyhowError { error },
        }
    }

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

    pub fn pool_error(err: diesel_async::pooled_connection::deadpool::PoolError) -> Self {
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
