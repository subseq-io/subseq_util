use std::convert::Infallible;
use std::sync::Arc;

use warp::{Filter, Reply};
use reqwest::header::{HeaderMap, HeaderValue};
use tokio::sync::broadcast;
use warp_sessions::MemoryStore;

pub mod sessions; 
pub mod users;

use self::sessions::CsrfMismatch;
pub use self::sessions::{
    AuthenticatedUser,
    InvalidSessionToken,
    NoSessionToken,
    OidcError,
    SessionsError,
    TokenTransferFailed,
    authenticate,
};

#[derive(Debug)]
pub struct ConflictError {}
impl warp::reject::Reject for ConflictError {}

#[derive(Debug)]
pub struct DatabaseError {}
impl warp::reject::Reject for DatabaseError {}

#[derive(Debug)]
pub struct NotFoundError {}
impl warp::reject::Reject for NotFoundError {}

#[derive(Debug)]
pub struct ParseError {}
impl warp::reject::Reject for ParseError {}

#[derive(Debug)]
pub struct InvalidConfigurationError {}
impl warp::reject::Reject for InvalidConfigurationError {}

use crate::tables::DbPool;
pub fn with_db(pool: Arc<DbPool>) -> impl Filter<Extract = (Arc<DbPool>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || pool.clone())
}

pub fn init_session_store() -> MemoryStore {
    MemoryStore::new()
}

pub fn with_broadcast<M: Send + Sync + Clone + 'static>(sender: broadcast::Sender<M>) -> 
        impl Filter<Extract = (broadcast::Sender<M>,), Error = Infallible> + Clone {
    warp::any().map(move || sender.clone())
}

pub async fn handle_rejection(err: warp::reject::Rejection) -> Result<Box<dyn warp::Reply>, std::convert::Infallible> {
    if let Some(_) = err.find::<NoSessionToken>() {
        let auth_path = warp::http::Uri::try_from("/auth/login").expect("uri failed");
        let mut no_cache_headers = HeaderMap::new();
        no_cache_headers.append("Cache-Control",
                                HeaderValue::from_str("no-store, must-revalidate")
                                .expect("Invalid header value"));
        no_cache_headers.append("Expires",
                                HeaderValue::from_str("0")
                                .expect("Invalid header value"));

        let reply = warp::redirect(auth_path);
        let mut response = reply.into_response();
        let headers = response.headers_mut();
        headers.extend(no_cache_headers);

        return Ok(Box::new(response));
    }

    if let Some(_) = err.find::<ConflictError>() {
        let json = warp::reply::json(&"Conflict: Resource already exists");
        let response = warp::reply::with_status(json, warp::http::StatusCode::CONFLICT);
        return Ok(Box::new(response));
    }
    if let Some(_) = err.find::<ParseError>() {
        let json = warp::reply::json(&"Invalid parameter, parsing failed");
        let response = warp::reply::with_status(json, warp::http::StatusCode::BAD_REQUEST);
        return Ok(Box::new(response));
    }
    if let Some(_) = err.find::<InvalidConfigurationError>() {
        let json = warp::reply::json(&"Invalid configuration provided, cannot complete request");
        let response = warp::reply::with_status(json, warp::http::StatusCode::BAD_REQUEST);
        return Ok(Box::new(response));
    }
    if let Some(_) = err.find::<NotFoundError>() {
        let json = warp::reply::json(&"Not Found: Resource does not exist");
        let response = warp::reply::with_status(json, warp::http::StatusCode::NOT_FOUND);
        return Ok(Box::new(response));
    }
    if let Some(_) = err.find::<InvalidSessionToken>() {
        let json = warp::reply::json(&"Unauthorized");
        let response = warp::reply::with_status(json, warp::http::StatusCode::UNAUTHORIZED);
        return Ok(Box::new(response));
    }
    if let Some(db_err) = err.find::<DatabaseError>() {
        tracing::error!("DB Error: {:?}", db_err);
        let json = warp::reply::json(&"Database Error");
        let response = warp::reply::with_status(json, warp::http::StatusCode::INTERNAL_SERVER_ERROR);
        return Ok(Box::new(response));
    }
    if let Some(err) = err.find::<OidcError>() {
        tracing::error!("OidcError: {}", err.msg);
        let json = warp::reply::json(&"OIDC Configuration Error");
        let response = warp::reply::with_status(json, warp::http::StatusCode::INTERNAL_SERVER_ERROR);
        return Ok(Box::new(response));
    }
    if let Some(_) = err.find::<CsrfMismatch>() {
        tracing::error!("CSRF Mismatch!");
        let json = warp::reply::json(&"OIDC Configuration Error");
        let response = warp::reply::with_status(json, warp::http::StatusCode::INTERNAL_SERVER_ERROR);
        return Ok(Box::new(response));
    }
    if let Some(_) = err.find::<TokenTransferFailed>() {
        tracing::error!("IdP is in down or degraded state!");
        let json = warp::reply::json(&"Error communicating with identity provider");
        let response = warp::reply::with_status(json, warp::http::StatusCode::INTERNAL_SERVER_ERROR);
        return Ok(Box::new(response));
    }

    tracing::error!("Unhandled Error: {:?}", err);
    let json = warp::reply::json(&"Unhandled error");
    Ok(Box::new(warp::reply::with_status(json, warp::http::StatusCode::INTERNAL_SERVER_ERROR)))
}
