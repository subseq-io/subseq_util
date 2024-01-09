use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use std::time::Duration;

pub mod users;
pub use users::User;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;
const DB_TIMEOUT: Duration = Duration::from_secs(3);

pub async fn establish_connection_pool(database_url: &str) -> DbPool {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool_async = tokio::task::spawn_blocking(|| Pool::builder().build(manager));
    match tokio::time::timeout(DB_TIMEOUT, pool_async).await {
        Ok(Ok(pool)) => pool.expect("Could not establish database connection"),
        Ok(Err(err)) => panic!("Database connection task failed: {:?}", err),
        Err(_) => panic!(
            "Database connection timed out after {} secs",
            DB_TIMEOUT.as_secs()
        ),
    }
}

pub struct ValidationErrorMessage {
    pub message: String,
    pub column: String,
    pub constraint_name: String,
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
