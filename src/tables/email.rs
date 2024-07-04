use chrono::NaiveDateTime;
use diesel::prelude::*;
use email_address::EmailAddress;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

pub fn gen_rand_string(num_bytes: usize) -> String {
    let random_bytes: Vec<u8> = (0..num_bytes).map(|_| thread_rng().gen::<u8>()).collect();
    let digest = Sha256::digest(random_bytes);
    base64::encode_config(digest, base64::URL_SAFE_NO_PAD)
}

pub enum EmailVerification {
    Accepted(EmailAddress),
    Denied,
}

pub trait UnverifiedEmailTable: Sized + Clone {
    fn create(conn: &mut PgConnection, email: &EmailAddress) -> QueryResult<String>;
    fn get_pending_verification(conn: &mut PgConnection, verifier: &str) -> QueryResult<Self>;
    fn expires(&self) -> NaiveDateTime;
    fn is_valid(&self) -> bool {
        chrono::Utc::now().naive_utc() <= self.expires()
    }
    fn inspect_pending_verification(
        self,
        conn: &mut PgConnection,
    ) -> QueryResult<EmailVerification>;
}

#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! create_email_table {
    ($minutes:literal) => {
        #[derive(PartialEq, Queryable, Insertable, Clone, Debug)]
        #[diesel(table_name = crate::schema::auth::pending_email_verifications)]
        pub struct PendingEmailVerification {
            id: String,
            email: String,
            created: NaiveDateTime,
            expires: NaiveDateTime,
        }

        const MINUTES_VERIFICATION_VALID: chrono::Duration = chrono::Duration::minutes($minutes);

        impl UnverifiedEmailTable for PendingEmailVerification {
            fn create(conn: &mut PgConnection, email: &EmailAddress) -> QueryResult<String> {
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
                    .execute(conn)?;
                Ok(row.id)
            }

            fn get_pending_verification(
                conn: &mut PgConnection,
                verifier: &str,
            ) -> QueryResult<Self> {
                use crate::schema::auth::pending_email_verifications::dsl as pending;

                pending::pending_email_verifications
                    .filter(pending::id.eq(&verifier))
                    .first::<PendingEmailVerification>(conn)
            }

            fn expires(&self) -> NaiveDateTime {
                self.expires
            }

            fn inspect_pending_verification(
                self,
                conn: &mut PgConnection,
            ) -> QueryResult<EmailVerification> {
                use crate::schema::auth::pending_email_verifications::dsl as pending;

                Ok(if self.is_valid() {
                    diesel::delete(
                        pending::pending_email_verifications.filter(pending::id.eq(self.id)),
                    )
                    .execute(conn)?;
                    EmailVerification::Accepted(
                        EmailAddress::from_str(&self.email).expect("valid email"),
                    )
                } else {
                    diesel::delete(
                        pending::pending_email_verifications.filter(pending::id.eq(self.id)),
                    )
                    .execute(conn)?;
                    EmailVerification::Denied
                })
            }
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tables::harness::{list_tables, to_pg_db_name, DbHarness};
    use email_address::EmailAddress;
    use function_name::named;
    use std::str::FromStr;

    create_email_table!(1);

    #[test]
    #[named]
    fn test_email_verifier() {
        let db_name = to_pg_db_name(function_name!());
        let harness = DbHarness::new("localhost", "development", &db_name, None);
        let mut conn = harness.conn();

        for table_name in list_tables(&mut conn).expect("Tables not retrieved") {
            eprintln!("Table: {:?}", table_name);
        }

        let email = EmailAddress::from_str("test@example.com").expect("valid email");
        let verifier =
            PendingEmailVerification::create(&mut conn, &email).expect("created pending");

        let fetched = PendingEmailVerification::get_pending_verification(&mut conn, &verifier)
            .expect("verifier should be found");

        assert!(fetched.is_valid());
        let accepted = fetched
            .inspect_pending_verification(&mut conn)
            .expect("delete success");

        match accepted {
            EmailVerification::Accepted(accepted_email) => assert_eq!(accepted_email, email),
            EmailVerification::Denied => panic!("verification should not be denied"),
        }
    }
}
