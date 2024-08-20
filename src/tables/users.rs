use std::fmt;
use std::str::FromStr;

use diesel::{
    backend::Backend,
    deserialize::{FromSql, FromSqlRow},
    expression::AsExpression,
    prelude::*,
    serialize::{Output, ToSql},
};
use diesel_async::AsyncPgConnection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, AsExpression, FromSqlRow,
)]
#[diesel(sql_type = diesel::sql_types::Uuid)]
pub struct UserId(pub Uuid);

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<DB> FromSql<diesel::sql_types::Uuid, DB> for UserId
where
    DB: Backend,
    Uuid: FromSql<diesel::sql_types::Uuid, DB>,
{
    fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
        let uuid = Uuid::from_sql(bytes)?;
        Ok(UserId(uuid))
    }
}

impl<DB> ToSql<diesel::sql_types::Uuid, DB> for UserId
where
    DB: Backend,
    Uuid: ToSql<diesel::sql_types::Uuid, DB>,
{
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> diesel::serialize::Result {
        self.0.to_sql(out)
    }
}

impl FromStr for UserId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(UserId(Uuid::parse_str(s)?))
    }
}

pub enum UserAccountType {
    Admin,
    Active,
    Unverified,
    Automated,
    Inactive,
    Imported, // Imported users are also inactive and unverified
    None,
}

#[allow(clippy::to_string_trait_impl)]
impl ToString for UserAccountType {
    fn to_string(&self) -> String {
        match self {
            Self::Admin => "admin".to_string(),
            Self::Active => "active".to_string(),
            Self::Unverified => "unverified".to_string(),
            Self::Automated => "automated".to_string(),
            Self::Inactive => "inactive".to_string(),
            Self::Imported => "imported".to_string(),
            Self::None => "none".to_string(),
        }
    }
}

impl UserAccountType {
    pub fn from_option(account_type: Option<String>) -> Self {
        match account_type {
            Some(account_type) => Self::from_str(&account_type),
            None => Self::None,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(account_type: &str) -> Self {
        match account_type.to_ascii_lowercase().as_str() {
            "admin" => Self::Admin,
            "active" => Self::Active,
            "unverified" => Self::Unverified,
            "automated" => Self::Automated,
            "inactive" => Self::Inactive,
            "imported" | "github" => Self::Imported, // Github was the previous name for imported
            _ => Self::None,
        }
    }
}

pub trait UserTable: Sized + Clone + Send {
    fn id(&self) -> UserId;
    fn email(&self) -> String;
    fn from_username(
        conn: &mut AsyncPgConnection,
        username: &str,
    ) -> impl std::future::Future<Output = Option<Self>> + Send;
    fn from_email(
        conn: &mut AsyncPgConnection,
        email: &str,
    ) -> impl std::future::Future<Output = Option<Self>> + Send;
    fn create(
        conn: &mut AsyncPgConnection,
        user_id: UserId,
        email: &str,
        username: &str,
        account_type: UserAccountType,
    ) -> impl std::future::Future<Output = QueryResult<Self>> + Send;
    fn get(
        conn: &mut AsyncPgConnection,
        id: UserId,
    ) -> impl std::future::Future<Output = Option<Self>> + Send;
    fn list(
        conn: &mut AsyncPgConnection,
        page: u32,
        page_size: u32,
    ) -> impl std::future::Future<Output = Vec<Self>> + Send;
}

pub trait UserIdTable: Sized + Send {
    fn get(
        conn: &mut AsyncPgConnection,
        user_id: UserId,
    ) -> impl std::future::Future<Output = QueryResult<Self>> + Send;
    fn set_account_type(
        &mut self,
        conn: &mut AsyncPgConnection,
        role: UserAccountType,
    ) -> impl std::future::Future<Output = QueryResult<()>> + Send;
}

#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! create_async_user_base {
    () => {
        use diesel_async::scoped_futures::ScopedFutureExt;
        use diesel_async::{AsyncConnection, RunQueryDsl};

        #[derive(PartialEq, Queryable, Insertable, Clone, Debug, Serialize)]
        #[diesel(table_name = crate::schema::auth::metadata)]
        pub struct UserMetadata {
            pub user_id: UserId,
            pub data: serde_json::Value,
        }

        #[derive(PartialEq, Queryable, Insertable, Clone, Debug, Serialize)]
        #[diesel(table_name = crate::schema::auth::portraits)]
        pub struct UserPortrait {
            pub user_id: UserId,
            pub portrait: Vec<u8>,
        }

        #[derive(PartialEq, Queryable, Insertable, Clone, Debug, Serialize)]
        #[diesel(table_name = crate::schema::auth::user_id_accounts)]
        pub struct UserIdAccount {
            pub user_id: UserId,
            pub username: String,
            pub account_type: Option<String>,
        }

        impl UserIdAccount {
            pub async fn create(
                conn: &mut AsyncPgConnection,
                user_id: UserId,
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
        }

        impl UserIdTable for UserIdAccount {
            async fn get(conn: &mut AsyncPgConnection, user_id: UserId) -> QueryResult<Self> {
                use crate::schema::auth::user_id_accounts::dsl::user_id_accounts;
                user_id_accounts
                    .find(user_id)
                    .get_result::<UserIdAccount>(conn)
                    .await
            }

            async fn set_account_type(
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
            pub id: UserId,
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
            fn id(&self) -> UserId {
                self.id
            }

            fn email(&self) -> String {
                self.email.clone()
            }

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
                user_id: UserId,
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

                let transaction_user = user.clone();
                conn.transaction(|transact| {
                    async move {
                        diesel::insert_into(crate::schema::auth::users::table)
                            .values(&transaction_user)
                            .execute(transact)
                            .await?;

                        let user_id_account = UserIdAccount {
                            user_id: transaction_user.id,
                            username: username.trim(),
                            account_type: Some(account_type.to_string()),
                        };
                        diesel::insert_into(crate::schema::auth::user_id_accounts::table)
                            .values(&user_id_account)
                            .execute(transact)
                            .await?;
                        QueryResult::Ok(())
                    }
                    .scope_boxed()
                })
                .await?;

                Ok(user)
            }

            async fn get(conn: &mut AsyncPgConnection, id: UserId) -> Option<Self> {
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
    use crate::tables::harness::list_tables;
    use crate::tables::harness::{to_pg_db_name, DbHarness};
    use crate::tables::ValidationErrorMessage;
    use chrono::NaiveDateTime;
    use function_name::named;
    use serde::{Deserialize, Serialize};

    create_async_user_base!();

    #[tokio::test]
    #[named]
    async fn test_async_user_handle() {
        let db_name = to_pg_db_name(function_name!());
        let harness = DbHarness::new("localhost", "development", &db_name, None).await;
        let mut conn = harness.conn().await;

        for table_name in list_tables(&mut conn).await.expect("Tables not retrieved") {
            eprintln!("Table: {:?}", table_name);
        }

        let user = User::create(
            &mut conn,
            UserId(Uuid::new_v4()),
            "test-user@example.com",
            "test_user",
            UserAccountType::Active,
        )
        .await
        .expect("user");

        let user_expect = User::get(&mut conn, user.id).await.expect("user2");
        assert_eq!(user, user_expect);
    }
}
