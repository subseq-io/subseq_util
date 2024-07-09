use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel_async::AsyncPgConnection;
use email_address::EmailAddress;

use crate::tables::EmailVerification;

pub trait AsyncUnverifiedEmailTable: Sized + Clone + Send {
    fn create(
        conn: &mut AsyncPgConnection,
        email: &EmailAddress,
        base_url: &str,
    ) -> impl std::future::Future<Output = QueryResult<String>> + Send;
    fn get_pending_verification(
        conn: &mut AsyncPgConnection,
        verifier: &str,
    ) -> impl std::future::Future<Output = QueryResult<Self>> + Send;
    fn expires(&self) -> NaiveDateTime;
    fn is_valid(&self) -> bool {
        chrono::Utc::now().naive_utc() <= self.expires()
    }
    fn inspect_pending_verification(
        self,
        conn: &mut AsyncPgConnection,
    ) -> impl std::future::Future<Output = QueryResult<EmailVerification>> + Send;
}

#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! create_async_email_table {
    ($minutes:literal, $link_uri_fmt:tt) => {
        use diesel_async::{AsyncPgConnection, RunQueryDsl};
        const MINUTES_VERIFICATION_VALID: chrono::Duration = chrono::Duration::minutes($minutes);

        #[derive(PartialEq, Queryable, Insertable, Clone, Debug)]
        #[diesel(table_name = crate::schema::auth::pending_email_verifications)]
        pub struct PendingEmailVerification {
            id: String,
            email: String,
            created: NaiveDateTime,
            expires: NaiveDateTime,
        }

        impl AsyncUnverifiedEmailTable for PendingEmailVerification {
            async fn create(
                conn: &mut AsyncPgConnection,
                email: &EmailAddress,
                base_url: &str,
            ) -> QueryResult<String> {
                use crate::schema::auth::pending_email_verifications::dsl as pending;

                let now = chrono::Utc::now().naive_utc();
                let row = Self {
                    id: gen_rand_string(32),
                    email: email.to_string(),
                    created: now,
                    expires: now + MINUTES_VERIFICATION_VALID,
                };
                diesel::insert_into(pending::pending_email_verifications)
                    .values(&row)
                    .execute(conn)
                    .await?;
                Ok(format!($link_uri_fmt, base_url, row.id))
            }

            async fn get_pending_verification(
                conn: &mut AsyncPgConnection,
                verifier: &str,
            ) -> QueryResult<Self> {
                use crate::schema::auth::pending_email_verifications::dsl as pending;

                pending::pending_email_verifications
                    .filter(pending::id.eq(&verifier))
                    .first::<PendingEmailVerification>(conn)
                    .await
            }

            fn expires(&self) -> NaiveDateTime {
                self.expires
            }

            async fn inspect_pending_verification(
                self,
                conn: &mut AsyncPgConnection,
            ) -> QueryResult<EmailVerification> {
                use crate::schema::auth::pending_email_verifications::dsl as pending;

                Ok(if self.is_valid() {
                    diesel::delete(
                        pending::pending_email_verifications.filter(pending::id.eq(self.id)),
                    )
                    .execute(conn)
                    .await?;
                    EmailVerification::Accepted(
                        EmailAddress::from_str(&self.email).expect("valid email"),
                    )
                } else {
                    diesel::delete(
                        pending::pending_email_verifications.filter(pending::id.eq(self.id)),
                    )
                    .execute(conn)
                    .await?;
                    EmailVerification::Denied
                })
            }
        }
    };
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use email_address::EmailAddress;
    use function_name::named;
    use url::Url;

    use super::*;
    use crate::async_tables::harness::async_list_tables;
    use crate::tables::harness::{to_pg_db_name, DbHarness};
    use crate::tables::{gen_rand_string, EmailVerification};

    fn extract_token_from_uri(uri: &str) -> Option<String> {
        let url = Url::parse(uri).ok()?;
        let pairs = url.query_pairs();
        for (key, value) in pairs {
            if key == "token" {
                return Some(value.into_owned());
            }
        }
        None
    }

    create_async_email_table!(1, "{}app/verify_email?token={}");

    #[tokio::test]
    #[named]
    async fn test_async_email_verifier() {
        let db_name = to_pg_db_name(function_name!());
        let harness = DbHarness::new("localhost", "development", &db_name, None);
        let mut conn = harness.async_conn().await;

        for table_name in async_list_tables(&mut conn)
            .await
            .expect("Tables not retrieved")
        {
            eprintln!("Table: {:?}", table_name);
        }

        let email = EmailAddress::from_str("test@example.com").expect("valid email");
        let verifier = PendingEmailVerification::create(&mut conn, &email, "https://localhost/")
            .await
            .expect("created pending");
        assert!(verifier.starts_with("https://localhost/app/verify_email?token="));

        let token = extract_token_from_uri(&verifier).expect("token found");
        let fetched = PendingEmailVerification::get_pending_verification(&mut conn, &token)
            .await
            .expect("verifier should be found");

        assert!(fetched.is_valid());
        let accepted = fetched
            .inspect_pending_verification(&mut conn)
            .await
            .expect("delete success");

        match accepted {
            EmailVerification::Accepted(accepted_email) => assert_eq!(accepted_email, email),
            EmailVerification::Denied => panic!("verification should not be denied"),
        }
    }
}
