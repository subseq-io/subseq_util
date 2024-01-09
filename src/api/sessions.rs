use std::sync::Arc;

use cookie::{Cookie, SameSite};
use openidconnect::{AuthorizationCode, Nonce, PkceCodeVerifier};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warp::{filters::path::FullPath, Filter, Rejection, Reply};
use warp_sessions::{MemoryStore, SessionStore, SessionWithStore};

use crate::oidc::{IdentityProvider, OidcToken};

#[derive(Clone, Debug)]
pub struct AuthenticatedUser(Uuid);

#[derive(Clone, Debug)]
pub struct SessionToken(Vec<u8>);

impl AuthenticatedUser {
    pub fn validate_session(idp: Arc<IdentityProvider>, token: OidcToken) -> Option<Self> {
        let claims = idp.validate_token(&token).ok()?;
        let user_id = Uuid::parse_str(claims.subject().as_str()).ok()?;
        Some(Self(user_id))
    }

    pub fn id(&self) -> Uuid {
        self.0
    }
}

#[derive(Debug)]
pub struct SessionsError;
impl warp::reject::Reject for SessionsError {}

#[derive(Debug)]
pub struct UrlError;
impl warp::reject::Reject for UrlError {}

#[derive(Debug)]
pub struct OidcError {
    pub msg: &'static str,
}
impl warp::reject::Reject for OidcError {}

#[derive(Debug)]
pub struct CsrfMismatch;
impl warp::reject::Reject for CsrfMismatch {}

#[derive(Debug)]
pub struct TokenTransferFailed;
impl warp::reject::Reject for TokenTransferFailed {}

#[derive(Debug)]
pub struct InvalidCredentials;
impl warp::reject::Reject for InvalidCredentials {}

#[derive(Debug)]
pub struct InvalidSessionToken;
impl warp::reject::Reject for InvalidSessionToken {}

#[derive(Debug)]
pub struct NoSessionToken {}
impl warp::reject::Reject for NoSessionToken {}

pub const AUTH_COOKIE: &str = "access_token";

async fn login_handler(
    mut session: SessionWithStore<MemoryStore>,
    idp: Arc<IdentityProvider>,
) -> Result<(impl Reply, SessionWithStore<MemoryStore>), Rejection> {
    let (auth_url, csrf_token, verifier, nonce) = idp.login_oidc(vec![String::from("email")]);

    session
        .session
        .insert("csrf_token", csrf_token.secret().clone())
        .map_err(|_| warp::reject::custom(SessionsError {}))?;
    session
        .session
        .insert("pkce_verifier", verifier.secret().clone())
        .map_err(|_| warp::reject::custom(SessionsError {}))?;
    session
        .session
        .insert("nonce", nonce.secret().clone())
        .map_err(|_| warp::reject::custom(SessionsError {}))?;

    let uri: warp::http::Uri = auth_url
        .to_string()
        .try_into()
        .map_err(|_| warp::reject::custom(UrlError {}))?;
    let mut no_cache_headers = HeaderMap::new();
    no_cache_headers.append(
        "Cache-Control",
        HeaderValue::from_str("no-store, must-revalidate").expect("Invalid header value"),
    );
    no_cache_headers.append(
        "Expires",
        HeaderValue::from_str("0").expect("Invalid header value"),
    );

    let reply = warp::redirect(uri);
    let mut response = reply.into_response();
    let headers = response.headers_mut();
    headers.extend(no_cache_headers);
    Ok((response, session))
}

#[derive(Serialize, Deserialize)]
struct AuthQuery {
    code: String,
    state: String,
}

async fn auth_handler(
    query: AuthQuery,
    mut session: SessionWithStore<MemoryStore>,
    idp: Arc<IdentityProvider>,
) -> Result<(impl Reply, SessionWithStore<MemoryStore>), Rejection> {
    let AuthQuery { code, state } = query;
    let code = AuthorizationCode::new(code);

    let csrf_token = match session.session.get::<String>("csrf_token") {
        Some(csrf_token) => csrf_token,
        None => {
            return Err(warp::reject::custom(OidcError {
                msg: "Missing csrf token",
            }))
        }
    };

    let verifier = match session.session.get::<String>("pkce_verifier") {
        Some(pkce_verifier) => PkceCodeVerifier::new(pkce_verifier),
        None => {
            return Err(warp::reject::custom(OidcError {
                msg: "Missing pkce verifier",
            }))
        }
    };

    let nonce = match session.session.get::<String>("nonce") {
        Some(nonce) => Nonce::new(nonce),
        None => {
            return Err(warp::reject::custom(OidcError {
                msg: "Missing nonce",
            }))
        }
    };

    if state != csrf_token {
        tracing::warn!("CSRF token mismatch! This is a possible attack!");
        return Err(warp::reject::custom(CsrfMismatch {}));
    }

    let token = match idp.token_oidc(code, verifier, nonce).await {
        Ok(token) => token,
        Err(_) => return Err(warp::reject::custom(TokenTransferFailed {})),
    };

    let token_serialized = serde_json::to_string(&token).expect("Serialization error");
    let cookie = Cookie::build((AUTH_COOKIE, token_serialized.as_str()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true)
        .build();

    let cookie_content = cookie.to_string();
    let original_path = match session.session.get::<String>("redirect_path") {
        Some(path) => path,
        None => String::from("/"),
    };
    let redirect = format!(
        "<html><head><meta http-equiv=\"refresh\" content=\"0; URL='{}'\"/></head></html>",
        original_path
    );
    session.session.regenerate();
    Ok((
        warp::reply::with_header(warp::reply::html(redirect), "Set-Cookie", cookie_content),
        session,
    ))
}

fn parse_auth_cookie(cookie_str: &str) -> Result<OidcToken, Rejection> {
    serde_json::from_str(cookie_str).map_err(|_| warp::reject::custom(InvalidSessionToken))
}

pub fn authenticate(
    idp: Arc<IdentityProvider>,
    session: MemoryStore,
) -> impl Filter<Extract = (AuthenticatedUser,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::cookie::optional::<String>(AUTH_COOKIE))
        .and(warp::path::full())
        .and(warp_sessions::request::with_session(session.clone(), None))
        .and_then(
            move |token: Option<String>, path: FullPath, session: SessionWithStore<MemoryStore>| {
                let idp = idp.clone();
                async move {
                    let token = match token {
                        Some(tok) => tok,
                        // Send them over to the login form to get authenticated
                        None => {
                            let store = session.session_store;
                            let mut session = session.session;
                            session
                                .insert("redirect_path", path.as_str().to_string())
                                .expect("insert session failed");
                            store
                                .store_session(session)
                                .await
                                .expect("store session failed");

                            return Err(warp::reject::custom(NoSessionToken {}));
                        }
                    };

                    let token = parse_auth_cookie(&token)?;
                    AuthenticatedUser::validate_session(idp, token)
                        .ok_or_else(|| warp::reject::custom(InvalidSessionToken))
                }
            },
        )
}

pub fn with_idp(
    idp: Arc<IdentityProvider>,
) -> impl Filter<Extract = (Arc<IdentityProvider>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || idp.clone())
}

pub fn routes(
    session: MemoryStore,
    idp: Arc<IdentityProvider>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let login = warp::get()
        .and(warp::path("login"))
        .and(warp_sessions::request::with_session(session.clone(), None))
        .and(with_idp(idp.clone()))
        .and_then(login_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session);

    let auth = warp::get()
        .and(warp::query::<AuthQuery>())
        .and(warp_sessions::request::with_session(session.clone(), None))
        .and(with_idp(idp.clone()))
        .and_then(auth_handler)
        .untuple_one()
        .and_then(warp_sessions::reply::with_session);

    warp::path("auth").and(login.or(auth))
}
