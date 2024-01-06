use std::env;
use std::time::Duration;

use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};

pub mod users;
pub use users::User;

pub struct PgVars {
    pub username: String,
    pub password: String,
    pub host: String,
    pub require_ssl: bool
}

impl PgVars {
    pub fn from_raw(username: &str, password: &str, host: &str, require_ssl: bool) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
            host: host.to_string(),
            require_ssl
        }
    }

    pub fn new(default_password: &str) -> Self {
        let username = env::var("PG_USERNAME").unwrap_or("postgres".to_string());
        let password = env::var("PG_PASSWORD").unwrap_or(default_password.to_string());
        let host = env::var("PG_HOST").unwrap_or("localhost".to_string());
        let require_ssl = match env::var("PG_SSL") { Ok(_) => true, Err(_) => false };

        if default_password == password {
            tracing::warn!(
                "App is running in development mode \
                 with the default database password."
            );
        }

        PgVars{username, password, host, require_ssl}
    }

    pub fn db_url(self, database: &str) -> String {
        let ssl_string = "?sslmode=require";
        format!("postgres://{}:{}@{}/{}{}",
                self.username,
                self.password,
                self.host,
                database,
                if self.require_ssl {ssl_string} else {""})
    }
}

pub type DbPool = Pool<ConnectionManager<PgConnection>>;
const DB_TIMEOUT: Duration = Duration::from_secs(3);

pub async fn establish_connection_pool(database_url: &str) -> DbPool {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool_async = tokio::task::spawn_blocking(|| Pool::builder().build(manager));
    match tokio::time::timeout(DB_TIMEOUT, pool_async).await {
        Ok(Ok(pool)) => pool.expect("Could not establish database connection"),
        Ok(Err(err)) => panic!("Database connection task failed: {:?}", err),
        Err(_) => panic!("Database connection timed out after {} secs", DB_TIMEOUT.as_secs())
    }
}

pub struct ValidationErrorMessage {
    pub message: String,
    pub column: String,
    pub constraint_name: String
}

impl diesel::result::DatabaseErrorInformation for ValidationErrorMessage {
    fn message(&self) -> &str {
        &self.message
    }
    fn details(&self) -> Option<&str> {
        None
    }
    fn hint(&self) -> Option<&str> {
        None
    }
    fn table_name(&self) -> Option<&str> {
        None
    }
    fn column_name(&self) -> Option<&str> {
        Some(&self.column)
    }
    fn constraint_name(&self) -> Option<&str> {
        Some(&self.constraint_name)
    }
    fn statement_position(&self) -> Option<i32> {
        None
    }
}
