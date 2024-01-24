use std::sync::Arc;

use cookie::{Cookie, SameSite};
use openidconnect::{AuthorizationCode, Nonce, PkceCodeVerifier};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warp::http::header::AUTHORIZATION;
use warp::{filters::path::FullPath, Filter, Rejection, Reply, reply::WithHeader};
use warp_sessions::{MemoryStore, SessionWithStore, WithSession};

use crate::oidc::{IdentityProvider, OidcToken};

#[derive(Clone, Debug)]
pub struct AuthenticatedUser(Uuid);

#[derive(Clone, Debug)]
pub struct SessionToken(Vec<u8>);

impl AuthenticatedUser {
    pub async fn validate_session(idp: Arc<IdentityProvider>, token: OidcToken) -> Option<(Self, Option<OidcToken>)> {
        let (claims, token) = match idp.validate_token(&token) {
            Ok(claims) => (claims, None),
            Err(_) => {
                // Try to refresh
                tracing::trace!("Refresh happening");
                let token = idp.refresh(token).await.ok()?;
                tracing::trace!("Refresh complete");
                (idp.validate_token(&token).ok()?, Some(token))
            }
        };
        tracing::trace!("Claims");
        let user_id = Uuid::parse_str(claims.subject().as_str()).ok()?;
        tracing::trace!("Token validated");
        Some((Self(user_id), token))
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

    session.session.insert("token", token).ok();

    let original_path = match session.session.get::<String>("redirect_path") {
        Some(path) => path,
        None => String::from("/"),
    };
    let redirect = format!(
        "<html><head><meta http-equiv=\"refresh\" content=\"0; URL='{}'\"/></head></html>",
        original_path
    );
    Ok((warp::reply::html(redirect), session))
}

fn parse_auth_cookie(cookie_str: &str) -> Result<OidcToken, Rejection> {
    serde_json::from_str(cookie_str).map_err(|_| warp::reject::custom(InvalidSessionToken))
}


pub async fn store_auth_cookie<T: Reply>(reply: T, session: SessionWithStore<MemoryStore>)
        -> Result<WithSession<WithHeader<T>>, Rejection>
{
    if !session.session.data_changed() {
        // Set this random header because there is a type problem otherwise
        let reply = warp::reply::with_header(reply, "Server", "Subseq");
        return WithSession::new(reply, session).await;
    }
    
    let token_serialized = match session.session.get_raw("token") {
        Some(token) => token,
        None => {
            // Set this random header because there is a type problem otherwise
            let reply = warp::reply::with_header(reply, "Server", "Subseq");
            return WithSession::new(reply, session).await;
        }
    };

    let cookie = Cookie::build((AUTH_COOKIE, token_serialized.as_str()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true)
        .build();

    let cookie_content = cookie.to_string();
    let reply = warp::reply::with_header(reply, "Set-Cookie", cookie_content);
    tracing::trace!("Cookie set");
    WithSession::new(reply, session).await
}


pub fn authenticate(
    idp: Option<Arc<IdentityProvider>>,
    session: MemoryStore,
) -> impl Filter<Extract = (AuthenticatedUser, SessionWithStore<MemoryStore>), Error = Rejection> + Clone {
    warp::any()
        .and(warp::cookie::optional::<String>(AUTH_COOKIE))
        .and(warp::header::optional::<String>(AUTHORIZATION.as_str()))
        .and(warp::path::full())
        .and(warp_sessions::request::with_session(session.clone(), None))
        .and_then(
            move |token: Option<String>, bearer: Option<String>, path: FullPath, mut session: SessionWithStore<MemoryStore>| {
                let idp = idp.clone();
                async move {
                    if let Some(idp) = idp {
                        // Prefer the bearer token
                        let token = match bearer {
                            Some(tok) if tok.starts_with("Bearer ") => {
                                let content = tok.trim_start_matches("Bearer ");
                                OidcToken::from_bearer(content)
                            }
                            _ => match token {
                                Some(tok) => Some(parse_auth_cookie(&tok)?),
                                None => None
                            }
                        };

                        match token {
                            Some(token) => {
                                let (auth_user, token) = AuthenticatedUser::validate_session(idp, token).await
                                    .ok_or_else(|| warp::reject::custom(InvalidSessionToken))?;
                                if let Some(token) = token {
                                    tracing::trace!("Reset token");
                                    let inner_session = &mut session.session;
                                    inner_session
                                        .insert("token", token).ok();
                                }
                                Ok((auth_user, session))
                            }
                            None => {
                                let inner_session = &mut session.session;
                                inner_session
                                    .insert("redirect_path", path.as_str().to_string()).ok();
                                Err(warp::reject::custom(NoSessionToken {}))
                            }
                        }
                    } else {
                        if let Some(token) = token {
                            let NoAuthToken { user_id } = serde_json::from_str(&token)
                                .map_err(|_| warp::reject::custom(InvalidSessionToken))?;
                            Ok((AuthenticatedUser(user_id), session))
                        } else {
                            Err(warp::reject::custom(NoSessionToken {}))
                        }
                    }
                }
            },
        )
        .untuple_one()

}

pub fn with_idp(
    idp: Arc<IdentityProvider>,
) -> impl Filter<Extract = (Arc<IdentityProvider>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || idp.clone())
}

async fn no_auth_login_handler() -> Result<impl Reply, Rejection> {
    let login_form = r#"
        <html>
            <body>
                <form action="/auth" method="post">
                    <label for="user_id">User ID</label>
                    <input type="text" id="user_id" name="user_id" required minlength="36" size="36" />
                    <input type="submit" value="Submit" />
                </form>
            </body>
        </html>
    "#;
    Ok(warp::reply::html(login_form))
}

#[derive(Deserialize)]
struct FormData {
    user_id: String
}

#[derive(Deserialize, Serialize)]
struct NoAuthToken {
    user_id: Uuid
}

async fn no_auth_form_handler(mut session: SessionWithStore<MemoryStore>, form: FormData)
    -> Result<(impl Reply, SessionWithStore<MemoryStore>), Rejection>
{
    let user_id = Uuid::parse_str(&form.user_id)
        .map_err(|_| warp::reject::custom(InvalidCredentials{}))?;
    let token = NoAuthToken{user_id};
    session.session.insert("token", token).ok();

    let original_path = match session.session.get::<String>("redirect_path") {
        Some(path) => path,
        None => String::from("/"),
    };
    let redirect = format!(
        "<html><head><meta http-equiv=\"refresh\" content=\"0; URL='{}'\"/></head></html>",
        original_path
    );
    Ok((warp::reply::html(redirect), session))
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
        .and_then(store_auth_cookie);
    warp::path("auth").and(login.or(auth))
}


pub fn no_auth_routes(
    session: MemoryStore,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let login = warp::get()
        .and(warp::path("login"))
        .and_then(no_auth_login_handler);
    let auth = warp::post()
        .and(warp_sessions::request::with_session(session.clone(), None))
        .and(warp::body::form())
        .and_then(no_auth_form_handler)
        .untuple_one()
        .and_then(store_auth_cookie);
    warp::path("auth").and(login.or(auth))
}
