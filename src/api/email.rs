use std::str::FromStr;
use std::sync::Arc;

use diesel::prelude::*;
use email_address::EmailAddress;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::broadcast;
use warp::{http::StatusCode, Filter, Rejection, Reply};
use warp_sessions::{MemoryStore, SessionWithStore};

use crate::api::sessions::AuthenticatedUser;
use crate::email::{EmailTemplate, EmailTemplateBuilder, ScheduledEmail};
use crate::oidc::IdentityProvider;
use crate::tables::{DbPool, UnverifiedEmailTable, UserTable};
use crate::tables::{EmailVerification, UserAccountType, UserIdTable};

use super::sessions::store_auth_cookie;
use super::{authenticate, with_broadcast, with_db, with_string, AnyhowError, RejectReason};

fn send_verification_email<E, B, T, U>(
    conn: &mut PgConnection,
    base_url: &str,
    to_address: EmailAddress,
    builder: B,
    email_tx: broadcast::Sender<ScheduledEmail<T>>,
) -> Result<(), Rejection>
where
    E: UnverifiedEmailTable,
    B: EmailTemplateBuilder<T, U>,
    T: EmailTemplate,
    U: UserTable,
{
    let email_link =
        E::create(conn, &to_address, base_url).map_err(RejectReason::database_error)?;
    let template = builder
        .unique_link(&email_link)
        .build()
        .map_err(AnyhowError::from)?;
    let email = ScheduledEmail {
        to: to_address,
        template,
    };
    email_tx.send(email).ok();
    Ok(())
}

#[derive(Deserialize)]
struct VerifyQuery {
    id: String,
}

async fn verify_email_handler<U: UserTable, E: UnverifiedEmailTable, UIT: UserIdTable>(
    query: VerifyQuery,
    auth: AuthenticatedUser,
    session: SessionWithStore<MemoryStore>,
    db_pool: Arc<DbPool>,
) -> Result<(impl Reply, SessionWithStore<MemoryStore>), Rejection> {
    let mut conn = db_pool.get().map_err(RejectReason::pool_error)?;

    let user = U::get(&mut conn, auth.id())
        .ok_or_else(|| RejectReason::not_found(format!("UserTable {}", auth.id())))?;
    let verified = E::get_pending_verification(&mut conn, &query.id)
        .map_err(|_| RejectReason::not_found(format!("UnverifiedEmailTable {}", query.id)))?;
    let checked_verify = verified
        .inspect_pending_verification(&mut conn)
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
                UIT::get(&mut conn, user.id()).map_err(|_| RejectReason::NotFound {
                    resource: format!("UserIdAccount {}", user.id()),
                })?;
            user_id_account
                .set_account_type(&mut conn, UserAccountType::Active)
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
    U: UserTable,
    E: UnverifiedEmailTable,
    T: EmailTemplate,
    B: EmailTemplateBuilder<T, U>,
>(
    auth: AuthenticatedUser,
    session: SessionWithStore<MemoryStore>,
    db_pool: Arc<DbPool>,
    email_tx: broadcast::Sender<ScheduledEmail<T>>,
    base_url: String,
) -> Result<(impl Reply, SessionWithStore<MemoryStore>), Rejection> {
    let mut conn = db_pool.get().map_err(RejectReason::pool_error)?;
    let user = U::get(&mut conn, auth.id())
        .ok_or_else(|| RejectReason::not_found(format!("UserTable {}", auth.id())))?;
    let builder = B::new(&mut conn, &user)?;
    let email = EmailAddress::from_str(&user.email())
        .map_err(|_| RejectReason::bad_request(format!("Invalid user email: {}", user.email())))?;
    send_verification_email::<E, B, T, U>(&mut conn, &base_url, email, builder, email_tx)?;
    Ok((warp::reply::json(&json!({"message": "resent"})), session))
}

pub fn routes<
    U: UserTable,
    T: EmailTemplate + Send + Sync,
    B: EmailTemplateBuilder<T, U> + Clone + Sync + Send + 'static,
    E: UnverifiedEmailTable,
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
        .and_then(verify_email_handler::<U, E, EIT>)
        .untuple_one()
        .and_then(store_auth_cookie);

    let resend_email = warp::path!("email" / "verify")
        .and(warp::put())
        .and(authenticate(idp.clone(), session.clone()))
        .and(with_db(pool.clone()))
        .and(with_broadcast(email_tx.clone()))
        .and(with_string(base_url.clone()))
        .and_then(resend_email_handler::<U, E, T, B>)
        .untuple_one()
        .and_then(store_auth_cookie);

    return verify_email.or(resend_email);
}
