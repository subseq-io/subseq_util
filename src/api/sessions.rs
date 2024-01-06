use std::sync::Arc;

use cookie::{Cookie, SameSite};
use openidconnect::{AuthorizationCode, Nonce, PkceCodeVerifier};
use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection, Reply};
use uuid::Uuid;
use warp_sessions::{SessionWithStore, MemoryStore};

use crate::oidc::{IdentityProvider, OidcToken};

#[derive(Clone, Debug)]
pub struct AuthenticatedUser (Uuid);

#[derive(Clone, Debug)]
pub struct SessionToken (Vec<u8>);

impl AuthenticatedUser {
    pub fn validate_session(idp: Arc<IdentityProvider>,
                            token: OidcToken) -> Option<Self> {
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
impl warp::reject::Reject for SessionsError{}

#[derive(Debug)]
pub struct UrlError;
impl warp::reject::Reject for UrlError{}

#[derive(Debug)]
pub struct OidcError;
impl warp::reject::Reject for OidcError{}

#[derive(Debug)]
pub struct CsrfMismatch;
impl warp::reject::Reject for CsrfMismatch{}

#[derive(Debug)]
pub struct TokenTransferFailed;
impl warp::reject::Reject for TokenTransferFailed{}

#[derive(Debug)]
pub struct InvalidCredentials;
impl warp::reject::Reject for InvalidCredentials{}

#[derive(Debug)]
pub struct InvalidSessionToken;
impl warp::reject::Reject for InvalidSessionToken {}

#[derive(Debug)]
pub struct NoSessionToken;
impl warp::reject::Reject for NoSessionToken {}


async fn login_handler(
    mut session: SessionWithStore<MemoryStore>,
    idp: Arc<IdentityProvider>,
) -> Result<impl Reply, Rejection> {
    let (auth_url, csrf_token, verifier, nonce) = idp.login_oidc(vec![String::from("email")]);
    session.session.insert("csrf_token", csrf_token.secret().clone())
        .map_err(|_| warp::reject::custom(SessionsError{}))?;
    session.session.insert("pkce_verifier", verifier.secret().clone())
        .map_err(|_| warp::reject::custom(SessionsError{}))?;
    session.session.insert("nonce", nonce.secret().clone())
        .map_err(|_| warp::reject::custom(SessionsError{}))?;

    let uri: warp::http::Uri = auth_url
        .to_string()
        .try_into()
        .map_err(|_| warp::reject::custom(UrlError{}))?;
    Ok(warp::redirect(uri))
}

#[derive(Serialize)]
pub struct Message {
    message: String,
    result: bool
}


#[derive(Serialize, Deserialize)]
struct AuthQuery {
    code: String,
    state: String
}

async fn auth_handler(
    query: AuthQuery,
    session: SessionWithStore<MemoryStore>,
    idp: Arc<IdentityProvider>) -> Result<impl Reply, Rejection>
{
    let AuthQuery{code, state} = query;
    let code = AuthorizationCode::new(code);

    let csrf_token = match session.session.get::<String>("csrf_token") {
        Some(csrf_token) => csrf_token,
        None => return Err(warp::reject::custom(OidcError{}))
    };

    let verifier = match session.session.get::<String>("pkce_verifier") {
        Some(pkce_verifier) => PkceCodeVerifier::new(pkce_verifier),
        None => return Err(warp::reject::custom(OidcError{}))
    };

    let nonce = match session.session.get::<String>("nonce") {
        Some(nonce) => Nonce::new(nonce),
        None => return Err(warp::reject::custom(OidcError{}))
    };

    if state != csrf_token {
        tracing::warn!("CSRF token mismatch! This is a possible attack!");
        return Err(warp::reject::custom(CsrfMismatch{}));
    }

    let token = match idp.token_oidc(code, verifier, nonce).await {
        Ok(token) => token,
        Err(_) => return Err(warp::reject::custom(TokenTransferFailed{}))
    };

    let token_serialized = serde_json::to_string(&token).expect("Serialization error");
    let cookie = Cookie::build(("access_token", token_serialized.as_str()))
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(true)
        .build();

    let response = Message{message: "User authenticated".to_string(),
                           result: true};

    Ok(warp::reply::with_header(warp::reply::json(&response),
                                "Set-Cookie",
                                cookie.to_string()))
}

fn parse_auth_cookie(cookie_str: &str) -> Result<OidcToken, Rejection> {
    let token: OidcToken = match Cookie::parse(cookie_str) {
        Ok(cookie) => {
            match serde_json::from_str(cookie.value()) {
                Ok(token) => token,
                Err(_) => {
                    return Err(warp::reject::custom(InvalidSessionToken));
                }
            }
        }
        Err(_) => {
            return Err(warp::reject::custom(InvalidSessionToken));
        }
    };
    Ok(token)
}

pub fn authenticate(idp: Arc<IdentityProvider>) -> 
        impl Filter<Extract = (AuthenticatedUser,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::cookie::optional("access_token"))
        .and_then(move |token: Option<String>| {
            let idp = idp.clone();
            async move {
                match token {
                    Some(cookie_str) => {
                        let token = parse_auth_cookie(&cookie_str)?;
                        AuthenticatedUser::validate_session(idp, token)
                            .ok_or_else(|| warp::reject::custom(InvalidSessionToken))
                    }
                    None => Err(warp::reject::custom(NoSessionToken)),
                }
            }
        })
}

pub fn with_idp(idp: Arc<IdentityProvider>) 
    -> impl Filter<Extract = (Arc<IdentityProvider>,),
                   Error = std::convert::Infallible> + Clone 
{
    warp::any().map(move || idp.clone())
}

pub fn with_session(session: SessionWithStore<MemoryStore>)
    -> impl Filter<Extract = (SessionWithStore<MemoryStore>,),
                   Error = std::convert::Infallible> + Clone 
{
    warp::any().map(move || session.clone())
}

pub fn routes(session: SessionWithStore<MemoryStore>,
              idp: Arc<IdentityProvider>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let login = warp::get()
        .and(warp::path("login"))
        .and(with_session(session.clone()))
        .and(with_idp(idp.clone()))
        .and_then(login_handler);

    let auth = warp::get()
        .and(warp::path("auth"))
        .and(warp::query::<AuthQuery>())
        .and(with_session(session.clone()))
        .and(with_idp(idp.clone()))
        .and_then(auth_handler);

    warp::path("session")
        .and(login.or(auth))
}
