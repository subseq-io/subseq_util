use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel_async::AsyncPgConnection;
use serde::Serialize;
use uuid::Uuid;

use crate::tables::UserAccountType;

pub trait AsyncUserTable: Sized + Clone {
    fn from_username(conn: &mut AsyncPgConnection, username: &str)
        -> impl std::future::Future<Output = Option<Self>> + Send;
    fn from_email(conn: &mut AsyncPgConnection, email: &str)
        -> impl std::future::Future<Output = Option<Self>> + Send;
    fn create(
        conn: &mut AsyncPgConnection,
        user_id: Uuid,
        email: &str,
        username: &str,
        account_type: UserAccountType,
    ) -> impl std::future::Future<Output = QueryResult<Self>> + Send;
    fn get(conn: &mut AsyncPgConnection, id: Uuid)
        -> impl std::future::Future<Output = Option<Self>> + Send;
    fn list(conn: &mut AsyncPgConnection, page: u32, page_size: u32)
        -> impl std::future::Future<Output = Vec<Self>> + Send;
}


#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! create_async_user_base {
    () => {
        #[derive(PartialEq, Queryable, Insertable, Clone, Debug, Serialize)]
        #[diesel(table_name = crate::schema::auth::metadata)]
        pub struct UserMetadata {
            pub user_id: Uuid,
            pub data: serde_json::Value,
        }

        #[derive(PartialEq, Queryable, Insertable, Clone, Debug, Serialize)]
        #[diesel(table_name = crate::schema::auth::portraits)]
        pub struct UserPortrait {
            pub user_id: Uuid,
            pub portrait: Vec<u8>,
        }

        #[derive(PartialEq, Queryable, Insertable, Clone, Debug, Serialize)]
        #[diesel(table_name = crate::schema::auth::user_id_accounts)]
        pub struct UserIdAccount {
            pub user_id: Uuid,
            pub username: String,
            pub account_type: Option<String>,
        }

        impl UserIdAccount {
            pub async fn create(
                conn: &mut AsyncPgConnection,
                user_id: Uuid,
                username: String,
                account_type: UserAccountType,
            ) -> QueryResult<Self> {
                let id = Self {
                    user_id,
                    username,
                    account_type: Some(account_type.to_string()),
                };
                diesel::insert_into(crate::schema::auth::user_id_accounts::table)
                    .values(&id)
                    .execute(conn)
                    .await?;
                Ok(id)
            }

            pub async fn get(conn: &mut AsyncPgConnection, user_id: Uuid) -> Option<Self> {
                use crate::schema::auth::user_id_accounts::dsl::user_id_accounts;
                user_id_accounts
                    .find(user_id)
                    .get_result::<UserIdAccount>(conn)
                    .await
                    .optional()
                    .ok()?
            }

            pub async fn set_account_type(
                &mut self,
                conn: &mut AsyncPgConnection,
                account_type: UserAccountType,
            ) -> QueryResult<()> {
                use crate::schema::auth::user_id_accounts::dsl::{
                    account_type as account_type_col, user_id_accounts,
                };
                self.account_type = Some(account_type.to_string());
                diesel::update(user_id_accounts.find(self.user_id))
                    .set(account_type_col.eq(account_type.to_string()))
                    .execute(conn)
                    .await?;
                Ok(())
            }
        }

        #[derive(Queryable, Insertable, Clone, Debug, Serialize, Deserialize)]
        #[diesel(table_name = crate::schema::auth::users)]
        pub struct User {
            pub id: Uuid,
            pub email: String,
            pub created: NaiveDateTime,
        }

        impl PartialEq for User {
            fn eq(&self, other: &Self) -> bool {
                self.id == other.id
                    && self.email == other.email
                    && self.created.and_utc().timestamp_micros()
                        == other.created.and_utc().timestamp_micros()
            }
        }

        impl UserTable for User {
            async fn from_username(conn: &mut AsyncPgConnection, username: &str) -> Option<Self> {
                use crate::schema::auth::user_id_accounts;
                use crate::schema::auth::users;
                let (_account, user): (UserIdAccount, User) = user_id_accounts::table
                    .inner_join(users::table.on(users::id.eq(user_id_accounts::user_id)))
                    .filter(user_id_accounts::username.eq(username))
                    .first(conn)
                    .await
                    .optional()
                    .ok()??;
                Some(user)
            }

            async fn from_email(conn: &mut AsyncPgConnection, email: &str) -> Option<Self> {
                use crate::schema::auth::users;
                let user: User = users::table
                    .filter(users::email.eq(email))
                    .first(conn)
                    .await
                    .optional()
                    .ok()??;
                Some(user)
            }

            async fn create(
                conn: &mut AsyncPgConnection,
                user_id: Uuid,
                email: &str,
                username: &str,
                account_type: UserAccountType,
            ) -> QueryResult<Self> {
                if !email_address::EmailAddress::is_valid(email) {
                    let kind = diesel::result::DatabaseErrorKind::CheckViolation;
                    let msg = Box::new(ValidationErrorMessage {
                        message: format!("Invalid email: {}", email),
                        column: "email".to_string(),
                        constraint_name: "email_restriction".to_string(),
                    });
                    return Err(diesel::result::Error::DatabaseError(kind, msg));
                }

                let user = User {
                    id: user_id,
                    email: email.to_owned(),
                    created: chrono::Utc::now().naive_utc(),
                };

                conn.transaction(async |transact| {
                    diesel::insert_into(crate::schema::auth::users::table)
                        .values(&user)
                        .execute(transact)
                        .await?;

                    let user_id_account = UserIdAccount {
                        user_id: user.id,
                        username: username.trim().to_ascii_lowercase(),
                        account_type: Some(account_type.to_string()),
                    };
                    diesel::insert_into(crate::schema::auth::user_id_accounts::table)
                        .values(&user_id_account)
                        .execute(transact)
                        .await?;
                    QueryResult::Ok(())
                })?;

                Ok(user)
            }

            async fn get(conn: &mut AsyncPgConnection, id: Uuid) -> Option<Self> {
                use crate::schema::auth::users::dsl::users;
                users
                    .find(id)
                    .get_result::<User>(conn)
                    .await
                    .optional()
                    .ok()?
                    .map(|user| user.into())
            }

            async fn list(conn: &mut AsyncPgConnection, page: u32, page_size: u32) -> Vec<Self> {
                use crate::schema::auth::users::dsl::users;
                let offset = page.saturating_sub(1) * page_size;
                match users
                    .limit(page_size as i64)
                    .offset(offset as i64)
                    .load::<User>(conn)
                    .await
                {
                    Ok(list) => list.into_iter().map(|user| user.into()).collect(),
                    Err(err) => {
                        tracing::warn!("DB List Query Failed: {:?}", err);
                        vec![]
                    }
                }
            }
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::async_tables::harness::async_list_tables;
    use crate::tables::harness::{to_pg_db_name, DbHarness};
    use crate::tables::ValidationErrorMessage;
    use chrono::NaiveDateTime;
    use function_name::named;
    use serde::{Deserialize, Serialize};

    create_async_user_base!();

    #[tokio::test]
    #[named]
    fn test_async_user_handle() {
        let db_name = to_pg_db_name(function_name!());
        let harness = DbHarness::new("localhost", "development", &db_name, None);
        let mut conn = harness.async_conn().await;

        for table_name in async_list_tables(&mut conn).await.expect("Tables not retrieved") {
            eprintln!("Table: {:?}", table_name);
        }

        let user = User::create(
            &mut conn,
            Uuid::new_v4(),
            "test-user@example.com",
            "test_user",
            UserAccountType::Active,
        )
        .await
        .expect("user");

        let user_expect = User::get(&mut conn, user.id)
            .await
            .expect("user2");
        assert_eq!(user, user_expect);
    }
}
