use axum::{
    async_trait,
    extract::{FromRequestParts, Query, State},
    http::{header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use cookie::SameSite;
use openidconnect::{core::CoreIdTokenClaims, AuthorizationCode, Nonce, PkceCodeVerifier};
use serde::Deserialize;
use time::Duration;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer};
use urlencoding::decode;

use crate::oidc::OidcToken;

use super::{AppState, RejectReason};
use crate::api::{AuthRejectReason, AuthenticatedUser, ValidatesIdentity};

pub const AUTH_COOKIE: &str = "access_token";

impl AuthRejectReason {
    pub fn oidc_error(msg: &'static str) -> Self {
        AuthRejectReason::OidcError { msg }
    }

    pub fn csrf_mismatch() -> Self {
        AuthRejectReason::CsrfMismatch
    }

    pub fn token_transfer_failed<S: Into<String>>(msg: S) -> Self {
        AuthRejectReason::TokenTransferFailed { msg: msg.into() }
    }

    pub fn invalid_credentials() -> Self {
        AuthRejectReason::InvalidCredentials
    }

    pub fn invalid_session_token<S: Into<String>>(reason: S) -> Self {
        AuthRejectReason::InvalidSessionToken {
            reason: reason.into(),
        }
    }

    pub fn no_session_token() -> Self {
        AuthRejectReason::NoSessionToken
    }
}

fn split_bearer(header: Option<&str>) -> Option<OidcToken> {
    let (name, token) = header?.split_once(' ')?;
    if name == "Bearer" {
        parse_auth_cookie(&token).ok()
    } else {
        None
    }
}

impl ValidatesIdentity for AppState {
    fn validate_token(&self, token: &OidcToken) -> anyhow::Result<CoreIdTokenClaims> {
        self.idp.validate_token(token)
    }

    async fn refresh_token(&self, token: OidcToken) -> anyhow::Result<OidcToken> {
        self.idp.refresh(token).await
    }
}

pub struct AuthParts(pub CookieJar, pub AuthenticatedUser);

#[async_trait]
impl<S> FromRequestParts<S> for AuthParts
where
    S: Send + Sync + ValidatesIdentity,
{
    type Rejection = AuthRejectReason;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<AuthParts, Self::Rejection> {
        let authorization = &parts.headers.get(AUTHORIZATION);
        let cookies = CookieJar::from_headers(&parts.headers);

        // Get the token, preferring Bearer tokens first
        let token =
            if let Some(token) = split_bearer(authorization.and_then(|hv| hv.to_str().ok())) {
                Some(token)
            } else {
                let auth_cookie = cookies.get(AUTH_COOKIE);
                if let Some(auth_cookie) = auth_cookie {
                    Some(parse_auth_cookie(auth_cookie.value())?)
                } else {
                    None
                }
            }
            .ok_or_else(AuthRejectReason::no_session_token)?;

        let (auth_user, token) = AuthenticatedUser::validate_session(state, token)
            .await
            .map_err(|err| AuthRejectReason::invalid_session_token(err.to_string()))?;

        Ok(if let Some(reset_token) = token {
            tracing::trace!("Reset token");
            AuthParts(cookies.add(auth_cookie(reset_token)), auth_user)
        } else {
            AuthParts(cookies, auth_user)
        })
    }
}

#[derive(Deserialize)]
struct RedirectQuery {
    origin: Option<String>,
}

async fn login(
    session: Session,
    State(app): State<AppState>,
    Query(query): Query<RedirectQuery>,
) -> Result<impl IntoResponse, RejectReason> {
    let redirect_uri = query.origin.as_deref().unwrap_or("/");
    let (auth_url, csrf_token, verifier, nonce) = app.idp.login_oidc(vec![String::from("email")]);
    session
        .insert("csrf_token", csrf_token.secret().clone())
        .await
        .map_err(|_| RejectReason::Session)?;
    session
        .insert("pkce_verifier", verifier.secret().clone())
        .await
        .map_err(|_| RejectReason::Session)?;
    session
        .insert("nonce", nonce.secret().clone())
        .await
        .map_err(|_| RejectReason::Session)?;
    session
        .insert("redirect_uri", redirect_uri)
        .await
        .map_err(|_| RejectReason::Session)?;

    Ok(Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
struct AuthQuery {
    code: String,
    state: String,
}

async fn auth(
    session: Session,
    State(app): State<AppState>,
    jar: CookieJar,
    Query(query): Query<AuthQuery>,
) -> Result<(CookieJar, Response), AuthRejectReason> {
    let AuthQuery { code, state } = query;
    let code = AuthorizationCode::new(code);

    let csrf_token = match session.get::<String>("csrf_token").await {
        Ok(Some(csrf_token)) => csrf_token,
        Err(_) | Ok(None) => {
            tracing::warn!("Missing csrf token");
            return Ok((jar, Redirect::to("/auth/login").into_response()));
        }
    };

    let verifier = match session.get::<String>("pkce_verifier").await {
        Ok(Some(pkce_verifier)) => PkceCodeVerifier::new(pkce_verifier),
        Err(_) | Ok(None) => {
            tracing::warn!("Missing PKCE verifier");
            return Ok((jar, Redirect::to("/auth/login").into_response()));
        }
    };

    let nonce = match session.get::<String>("nonce").await {
        Ok(Some(nonce)) => Nonce::new(nonce),
        Err(_) | Ok(None) => {
            tracing::warn!("Missing nonce");
            return Ok((jar, Redirect::to("/auth/login").into_response()));
        }
    };

    let redirect_uri = match session.get::<String>("redirect_uri").await {
        Ok(Some(redirect_uri)) => decode(&redirect_uri)
            .map(|s| s.to_owned().to_string())
            .unwrap_or_else(|_| String::from("/")),
        Err(_) | Ok(None) => String::from("/"),
    };

    if state != csrf_token {
        tracing::warn!("CSRF token mismatch! This is a possible attack!");
        return Ok((jar, Redirect::to("auth/login").into_response()));
    }

    let token = match app.idp.token_oidc(code, verifier, nonce).await {
        Ok(token) => token,
        Err(err) => return Err(AuthRejectReason::token_transfer_failed(err.to_string())),
    };

    let redirect = format!(
        "<html><head><meta http-equiv=\"refresh\" content=\"0; URL='{}'\"/></head></html>",
        redirect_uri
    );
    Ok((
        jar.add(auth_cookie(token)),
        axum::response::Html(redirect).into_response(),
    ))
}

fn auth_cookie<'a>(token: OidcToken) -> Cookie<'a> {
    Cookie::build((
        AUTH_COOKIE,
        serde_json::to_string(&token).expect("serialize token"),
    ))
    .path("/")
    .http_only(true)
    .same_site(SameSite::Lax)
    .secure(true)
    .build()
}

fn parse_auth_cookie(cookie_str: &str) -> Result<OidcToken, AuthRejectReason> {
    serde_json::from_str(cookie_str)
        .map_err(|err| AuthRejectReason::invalid_session_token(format!("cookie: {}", err)))
}

async fn logout(
    session: Session,
    jar: CookieJar,
    State(app): State<AppState>,
) -> Result<impl IntoResponse, AuthRejectReason> {
    session
        .delete()
        .await
        .map_err(|_| AuthRejectReason::invalid_session_token("Invalid session"))?;
    let token = jar.get(AUTH_COOKIE);
    if let Some(token) = token {
        let oidc_token = parse_auth_cookie(token.to_string().as_str())?;
        let logout_url = app.idp.logout_oidc("/", &oidc_token);
        let uri = logout_url.as_str();
        Ok(Redirect::to(uri))
    } else {
        Err(AuthRejectReason::invalid_credentials())
    }
}

pub fn routes(app: AppState, store: MemoryStore) -> Router {
    let layer = SessionManagerLayer::new(store)
        .with_secure(false)
        .with_same_site(SameSite::Lax) // Ensure we send the cookie from the OAuth redirect.
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));
    Router::new()
        .route("/auth/login", get(login))
        .route("/auth", get(auth))
        .route("/auth/logout", get(logout))
        .layer(layer)
        .with_state(app)
}
