use std::str::FromStr;
use std::sync::Arc;

use email_address::EmailAddress;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::broadcast;
use warp::{http::StatusCode, Filter, Rejection, Reply};
use warp_sessions::{MemoryStore, SessionWithStore};

use super::with_db;
use crate::api::sessions::{store_auth_cookie, AuthenticatedUser};
use crate::api::{authenticate, with_broadcast, with_string, AnyhowError, RejectReason};
use crate::email::{EmailTemplate, EmailTemplateBuilder, ScheduledEmail};
use crate::oidc::IdentityProvider;
use crate::tables::{
    DbPool, EmailVerification, UnverifiedEmailTable, UserAccountType, UserIdTable, UserTable,
};

use crate::api::email::send_verification_email;

#[derive(Deserialize)]
struct VerifyQuery {
    id: String,
}

async fn verify_email_handler<E: UnverifiedEmailTable, U: UserTable, UIT: UserIdTable>(
    query: VerifyQuery,
    auth: AuthenticatedUser,
    session: SessionWithStore<MemoryStore>,
    db_pool: Arc<DbPool>,
) -> Result<(impl Reply, SessionWithStore<MemoryStore>), Rejection> {
    let mut conn = db_pool.get().await.map_err(RejectReason::pool_error)?;

    let user = U::get(&mut conn, auth.id())
        .await
        .ok_or_else(|| RejectReason::not_found(format!("UserTable {}", auth.id())))?;
    let verified = E::get_pending_verification(&mut conn, &query.id)
        .await
        .map_err(|_| RejectReason::not_found(format!("UnverifiedEmailTable {}", query.id)))?;
    let checked_verify = verified
        .inspect_pending_verification(&mut conn)
        .await
        .map_err(RejectReason::database_error)?;

    match checked_verify {
        EmailVerification::Accepted(email) => {
            if email.as_str() != user.email() {
                tracing::error!(
                    "User {} attempted to verify email {} but is logged in as {}",
                    user.id(),
                    email,
                    user.email()
                );
                return Ok((
                    warp::reply::with_status(
                        warp::reply::json(&json!({"message": "denied"})),
                        StatusCode::FORBIDDEN,
                    ),
                    session,
                ));
            }
            let mut user_id_account =
                UIT::get(&mut conn, user.id())
                    .await
                    .map_err(|_| RejectReason::NotFound {
                        resource: format!("UserIdAccount {}", user.id()),
                    })?;
            user_id_account
                .set_account_type(&mut conn, UserAccountType::Active)
                .await
                .map_err(RejectReason::database_error)?;

            Ok((
                warp::reply::with_status(
                    warp::reply::json(&json!({"message": "verified"})),
                    StatusCode::OK,
                ),
                session,
            ))
        }
        EmailVerification::Denied => Ok((
            warp::reply::with_status(
                warp::reply::json(&json!({"message": "denied"})),
                StatusCode::FORBIDDEN,
            ),
            session,
        )),
    }
}

async fn resend_email_handler<
    E: UnverifiedEmailTable,
    B: EmailTemplateBuilder<T, U>,
    T: EmailTemplate,
    U: UserTable,
>(
    auth: AuthenticatedUser,
    session: SessionWithStore<MemoryStore>,
    db_pool: Arc<DbPool>,
    email_tx: broadcast::Sender<ScheduledEmail<T>>,
    base_url: String,
) -> Result<(impl Reply, SessionWithStore<MemoryStore>), Rejection> {
    let mut conn = db_pool.get().await.map_err(RejectReason::pool_error)?;
    let user = U::get(&mut conn, auth.id())
        .await
        .ok_or_else(|| RejectReason::not_found(format!("UserTable {}", auth.id())))?;
    let builder = B::new(&mut conn, &user).await.map_err(AnyhowError::from)?;
    let email = EmailAddress::from_str(&user.email())
        .map_err(|_| RejectReason::bad_request(format!("Invalid user email: {}", user.email())))?;
    send_verification_email::<E, B, T, U>(&mut conn, &base_url, email, builder, email_tx)
        .await
        .map_err(AnyhowError::from)?;
    Ok((warp::reply::json(&json!({"message": "resent"})), session))
}

pub fn routes<
    E: UnverifiedEmailTable,
    B: EmailTemplateBuilder<T, U> + Clone + Sync + Send + 'static,
    T: EmailTemplate + Send + Sync,
    U: UserTable,
    EIT: UserIdTable,
>(
    idp: Option<Arc<IdentityProvider>>,
    session: MemoryStore,
    pool: Arc<DbPool>,
    base_url: String,
    email_tx: broadcast::Sender<ScheduledEmail<T>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let verify_email = warp::path!("email" / "verify")
        .and(warp::post())
        .and(warp::query::<VerifyQuery>())
        .and(authenticate(idp.clone(), session.clone()))
        .and(with_db(pool.clone()))
        .and_then(verify_email_handler::<E, U, EIT>)
        .untuple_one()
        .and_then(store_auth_cookie);

    let resend_email = warp::path!("email" / "verify")
        .and(warp::put())
        .and(authenticate(idp.clone(), session.clone()))
        .and(with_db(pool.clone()))
        .and(with_broadcast(email_tx.clone()))
        .and(with_string(base_url.clone()))
        .and_then(resend_email_handler::<E, B, T, U>)
        .untuple_one()
        .and_then(store_auth_cookie);

    return verify_email.or(resend_email);
}
