use diesel::prelude::*;
use serde::Serialize;
use uuid::Uuid;

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

pub trait UserTable: Sized + Serialize + Clone {
    fn from_username(conn: &mut PgConnection, username: &str) -> Option<Self>;
    fn from_email(conn: &mut PgConnection, email: &str) -> Option<Self>;
    fn create(
        conn: &mut PgConnection,
        user_id: Uuid,
        email: &str,
        username: &str,
        account_type: UserAccountType,
    ) -> QueryResult<Self>;
    fn get(conn: &mut PgConnection, id: Uuid) -> Option<Self>;
    fn list(conn: &mut PgConnection, page: u32, page_size: u32) -> Vec<Self>;
}

#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! create_user_base {
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
            pub fn create(
                conn: &mut PgConnection,
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
                    .execute(conn)?;
                Ok(id)
            }

            pub fn get(conn: &mut PgConnection, user_id: Uuid) -> Option<Self> {
                use crate::schema::auth::user_id_accounts::dsl::user_id_accounts;
                user_id_accounts
                    .find(user_id)
                    .get_result::<UserIdAccount>(conn)
                    .optional()
                    .ok()?
            }

            pub fn set_account_type(
                &mut self,
                conn: &mut PgConnection,
                account_type: UserAccountType,
            ) -> QueryResult<()> {
                use crate::schema::auth::user_id_accounts::dsl::{
                    account_type as account_type_col, user_id_accounts,
                };
                self.account_type = Some(account_type.to_string());
                diesel::update(user_id_accounts.find(self.user_id))
                    .set(account_type_col.eq(account_type.to_string()))
                    .execute(conn)?;
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
            fn from_username(conn: &mut PgConnection, username: &str) -> Option<Self> {
                use crate::schema::auth::user_id_accounts;
                use crate::schema::auth::users;
                let (_account, user): (UserIdAccount, User) = user_id_accounts::table
                    .inner_join(users::table.on(users::id.eq(user_id_accounts::user_id)))
                    .filter(user_id_accounts::username.eq(username))
                    .first(conn)
                    .optional()
                    .ok()??;
                Some(user)
            }

            fn from_email(conn: &mut PgConnection, email: &str) -> Option<Self> {
                use crate::schema::auth::users;
                let user: User = users::table
                    .filter(users::email.eq(email))
                    .first(conn)
                    .optional()
                    .ok()??;
                Some(user)
            }

            fn create(
                conn: &mut PgConnection,
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

                conn.transaction(|transact| {
                    diesel::insert_into(crate::schema::auth::users::table)
                        .values(&user)
                        .execute(transact)?;

                    let user_id_account = UserIdAccount {
                        user_id: user.id,
                        username: username.trim().to_ascii_lowercase(),
                        account_type: Some(account_type.to_string()),
                    };
                    diesel::insert_into(crate::schema::auth::user_id_accounts::table)
                        .values(&user_id_account)
                        .execute(transact)?;
                    QueryResult::Ok(())
                })?;

                Ok(user)
            }

            fn get(conn: &mut PgConnection, id: Uuid) -> Option<Self> {
                use crate::schema::auth::users::dsl::users;
                users
                    .find(id)
                    .get_result::<User>(conn)
                    .optional()
                    .ok()?
                    .map(|user| user.into())
            }

            fn list(conn: &mut PgConnection, page: u32, page_size: u32) -> Vec<Self> {
                use crate::schema::auth::users::dsl::users;
                let offset = page.saturating_sub(1) * page_size;
                match users
                    .limit(page_size as i64)
                    .offset(offset as i64)
                    .load::<User>(conn)
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
    use crate::tables::harness::{list_tables, to_pg_db_name, DbHarness};
    use crate::tables::ValidationErrorMessage;
    use chrono::NaiveDateTime;
    use function_name::named;
    use serde::{Deserialize, Serialize};

    create_user_base!();

    #[test]
    #[named]
    fn test_user_handle() {
        let db_name = to_pg_db_name(function_name!());
        let harness = DbHarness::new("localhost", "development", &db_name, None);
        let mut conn = harness.conn();

        for table_name in list_tables(&mut conn).expect("Tables not retrieved") {
            eprintln!("Table: {:?}", table_name);
        }

        let user = User::create(
            &mut conn,
            Uuid::new_v4(),
            "test-user@example.com",
            "test_user",
            UserAccountType::Active,
        )
        .expect("user");

        let user_expect = User::get(&mut conn, user.id).expect("user2");
        assert_eq!(user, user_expect);
    }
}
