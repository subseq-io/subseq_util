use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;
use warp::{Filter, Rejection, Reply};
use warp_sessions::{MemoryStore, SessionWithStore};

use super::*;
use crate::api::sessions::store_auth_cookie;
use crate::oidc::IdentityProvider;
use crate::router::Router;
use crate::tables::{DbPool, UserAccountType, UserTable};

#[derive(Deserialize)]
pub struct UserPayload {
    email: String,
}

pub async fn create_user_handler<U: UserTable>(
    payload: UserPayload,
    _auth_user: AuthenticatedUser,
    session: SessionWithStore<MemoryStore>,
    db_pool: Arc<DbPool>,
    sender: broadcast::Sender<U>,
) -> Result<(impl warp::Reply, SessionWithStore<MemoryStore>), warp::Rejection> {
    let mut conn = match db_pool.get() {
        Ok(conn) => conn,
        Err(err) => return Err(warp::reject::custom(DatabaseError::new(err.to_string()))),
    };
    let UserPayload { email } = payload;
    let user = match U::create(
        &mut conn,
        Uuid::new_v4(),
        &email,
        &email,
        UserAccountType::Unverified,
    ) {
        Ok(user) => user,
        Err(_) => return Err(warp::reject::custom(ConflictError {})),
    };
    sender.send(user.clone()).ok();
    Ok((warp::reply::json(&user), session))
}

pub async fn get_user_handler<U: UserTable>(
    user_id: Uuid,
    _auth_user: AuthenticatedUser,
    session: SessionWithStore<MemoryStore>,
    db_pool: Arc<DbPool>,
) -> Result<(impl warp::Reply, SessionWithStore<MemoryStore>), warp::Rejection> {
    let mut conn = match db_pool.get() {
        Ok(conn) => conn,
        Err(err) => return Err(warp::reject::custom(DatabaseError::new(err.to_string()))),
    };
    let user = match U::get(&mut conn, user_id) {
        Some(user) => user,
        None => return Err(warp::reject::custom(NotFoundError {})),
    };
    Ok((warp::reply::json(&user), session))
}

pub fn routes<U: UserTable + Send + Sync + 'static>(
    idp: Option<Arc<IdentityProvider>>,
    session: MemoryStore,
    pool: Arc<DbPool>,
    router: &mut Router,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let user_tx = router.announce();
    let create_user = warp::post()
        .and(warp::body::json())
        .and(authenticate(idp.clone(), session.clone()))
        .and(with_db(pool.clone()))
        .and(with_broadcast(user_tx))
        .and_then(create_user_handler::<U>)
        .untuple_one()
        .and_then(store_auth_cookie);

    let get_user = warp::get()
        .and(warp::path::param())
        .and(authenticate(idp.clone(), session.clone()))
        .and(with_db(pool.clone()))
        .and_then(get_user_handler::<U>)
        .untuple_one()
        .and_then(store_auth_cookie);

    warp::path("user").and(create_user.or(get_user))
}
