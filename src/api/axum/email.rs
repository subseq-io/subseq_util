use crate::{
    email::{EmailTemplate, EmailTemplateBuilder},
    tables::{EmailVerification, UnverifiedEmailTable, UserAccountType, UserIdTable, UserTable},
};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{post, put},
    Json, Router,
};
use email_address::EmailAddress;
use serde::Deserialize;
use serde_json::json;
use std::str::FromStr;

use super::{super::AuthenticatedUser, AnyhowError, AppState, RejectReason};
use crate::email::send_verification_email;

#[derive(Deserialize)]
struct VerifyQuery {
    id: String,
}

async fn verify_email_handler<E: UnverifiedEmailTable, U: UserTable, UIT: UserIdTable>(
    auth_user: AuthenticatedUser,
    Query(query): Query<VerifyQuery>,
    State(app): State<AppState>,
) -> Result<impl IntoResponse, RejectReason> {
    let mut conn = app.db_pool.get().await.map_err(RejectReason::pool_error)?;

    let user = U::get(&mut conn, auth_user.id())
        .await
        .ok_or_else(|| RejectReason::not_found(format!("UserTable {}", auth_user.id())))?;
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
                    StatusCode::FORBIDDEN,
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::to_string(&json!({"message": "denied"})).expect("valid json"),
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
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"message": "verified"})).expect("valid json"),
            ))
        }
        EmailVerification::Denied => Ok((
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::to_string(&json!({"message": "denied"})).expect("valid json"),
        )),
    }
}

async fn resend_email_handler<
    E: UnverifiedEmailTable,
    B: EmailTemplateBuilder<T, U>,
    T: EmailTemplate + Sync + 'static,
    U: UserTable,
>(
    auth_user: AuthenticatedUser,
    State(app): State<AppState>,
) -> Result<Response, RejectReason> {
    let mut conn = app.db_pool.get().await.map_err(RejectReason::pool_error)?;
    let user = U::get(&mut conn, auth_user.id())
        .await
        .ok_or_else(|| RejectReason::not_found(format!("UserTable {}", auth_user.id())))?;
    let builder = match B::new(&mut conn, &user).await {
        Ok(builder) => builder,
        Err(e) => return Ok(AnyhowError::from(e).into_response()),
    };
    let builder = builder.subject("Verify your email");  // TODO: Move to config, i18n
    let email = EmailAddress::from_str(&user.email())
        .map_err(|_| RejectReason::bad_request(format!("Invalid user email: {}", user.email())))?;
    let email_tx = app.router.announce();
    if let Err(anyerr) =
        send_verification_email::<E, B, T, U>(&mut conn, &app.base_url, email, builder, email_tx)
            .await
    {
        return Ok(AnyhowError::from(anyerr).into_response());
    }
    Ok(Json(&json!({"message": "resent"})).into_response())
}

pub fn routes<
    E: UnverifiedEmailTable + 'static,
    B: EmailTemplateBuilder<T, U> + Clone + Sync + Send + 'static,
    T: EmailTemplate + Send + Sync + 'static,
    U: UserTable + 'static,
    EIT: UserIdTable + 'static,
>() -> Router<AppState> {
    Router::new()
        .route("/email/verify", post(verify_email_handler::<E, U, EIT>))
        .route("/email/verify", put(resend_email_handler::<E, B, T, U>))
}
