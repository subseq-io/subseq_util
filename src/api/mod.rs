use uuid::Uuid;

#[cfg(feature = "axum")]
mod axum;

#[cfg(feature = "warp")]
mod warp;

pub mod sessions {
    use anyhow::{anyhow, Context, Result as AnyResult};
    use email_address::EmailAddress;
    use openidconnect::core::CoreIdTokenClaims;
    use uuid::Uuid;

    use crate::oidc::OidcToken;

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
    #[cfg(feature = "warp")]
    impl warp::reject::Reject for AuthRejectReason {}

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

        pub fn id(&self) -> Uuid {
            self.id
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

    #[cfg(feature = "warp")]
    pub use super::warp::sessions::*;

    #[cfg(feature = "axum")]
    pub use super::axum::sessions::*;
}

#[cfg(feature = "warp")]
pub use self::sessions::authenticate;
pub use self::sessions::{AuthRejectReason, AuthenticatedUser, ValidatesIdentity};

pub mod email {
    use diesel_async::AsyncPgConnection;
    use email_address::EmailAddress;
    use tokio::sync::broadcast;

    use crate::email::{EmailTemplate, EmailTemplateBuilder, ScheduledEmail};
    use crate::tables::{UnverifiedEmailTable, UserTable};

    pub(crate) async fn send_verification_email<E, B, T, U>(
        conn: &mut AsyncPgConnection,
        base_url: &str,
        to_address: EmailAddress,
        builder: B,
        email_tx: broadcast::Sender<ScheduledEmail<T>>,
    ) -> anyhow::Result<()>
    where
        E: UnverifiedEmailTable,
        B: EmailTemplateBuilder<T, U>,
        T: EmailTemplate,
        U: UserTable,
    {
        let email_link = E::create(conn, &to_address, base_url).await?;
        let template = builder.unique_link(&email_link).build()?;
        let email = ScheduledEmail {
            to: to_address,
            template,
        };
        email_tx.send(email).ok();
        Ok(())
    }

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
    Forbidden { user_id: Uuid, reason: String },
    MissingEnvKey { key: String },
    NotFound { resource: String },
    Session,
}

#[cfg(feature = "axum")]
pub use axum::AppState;

#[cfg(feature = "warp")]
pub use warp::{handle_rejection, init_session_store, with_broadcast, with_db, with_string};
