pub mod email;
pub mod users;

use diesel::{ConnectionError, ConnectionResult};
use diesel_async::pooled_connection::{AsyncDieselConnectionManager, ManagerConfig, bb8::Pool};
use diesel_async::AsyncPgConnection;
use futures_util::future::{BoxFuture, FutureExt};
use tokio::time::Duration;

use crate::get_cert_pool;
pub use crate::async_tables::email::AsyncUnverifiedEmailTable;
pub use crate::async_tables::users::{AsyncUserIdTable, AsyncUserTable};
pub use crate::tables::{gen_rand_string, EmailVerification};

pub type DbPool = Pool<AsyncPgConnection>;
const DB_TIMEOUT: Duration = Duration::from_secs(3);

fn establish_secure_connection(config: &str) -> BoxFuture<ConnectionResult<AsyncPgConnection>> {
    let fut = async move {
        // We first set up the way we want rustls to work.
        let rustls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_certs())
            .with_no_client_auth();
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(rustls_config);
        let (client, conn) = tokio_postgres::connect(config, tls)
            .await
            .map_err(|e| ConnectionError::BadConnection(e.to_string()))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                if cfg!(feature = "abort-on-connection-error") {
                    eprintln!("Database connection error: {}", e);
                    std::process::abort();
                } else {
                    tracing::error!("Database connection error: {}", e);
                }
            }
        });
        AsyncPgConnection::try_from(client).await
    };
    fut.boxed()
}

fn root_certs() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs().expect("Certs not loadable!");
    roots.add_parsable_certificates(certs);
    let certs = get_cert_pool().map(|pool| pool.certs().clone()).unwrap_or_default();
    roots.add_parsable_certificates(certs);
    roots
}

pub async fn establish_connection_pool(db_url: &str, secure: bool) -> anyhow::Result<DbPool> {
    let mut config = ManagerConfig::default();
    if secure {
        config.custom_setup = Box::new(establish_secure_connection);
    }
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new_with_config(db_url, config);

    let pool_async = Pool::builder().build(manager);
    match tokio::time::timeout(DB_TIMEOUT, pool_async).await {
        Ok(Ok(pool)) => {
            let conn = pool.get().await?; // Verify the connection succeeded
            drop(conn);
            Ok(pool)
        }
        Ok(Err(err)) => panic!("Database connection task failed: {:?}", err),
        Err(_) => panic!(
            "Database connection timed out after {} secs",
            DB_TIMEOUT.as_secs()
        ),
    }
}

#[macro_export]
macro_rules! setup_table_crud {
    ($struct_name:ident, $table:path) => {
        impl $struct_name {
            pub fn list(conn: &mut PgConnection, page: u32, page_size: u32) -> Vec<Self> {
                let offset = page.saturating_sub(1) * page_size;
                match $table
                    .limit(page_size as i64)
                    .offset(offset as i64)
                    .load::<Self>(conn)
                {
                    Ok(list) => list,
                    Err(err) => {
                        tracing::warn!("DB List Query Failed: {:?}", err);
                        vec![]
                    }
                }
            }

            pub fn get(conn: &mut PgConnection, id: Uuid) -> Option<Self> {
                $table.find(id).get_result::<Self>(conn).optional().ok()?
            }
        }
    };
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

pub mod harness {
    use crate::tables::harness::DbHarness;
    use diesel::{sql_query, QueryResult, QueryableByName};
    use diesel_async::{AsyncPgConnection, RunQueryDsl};

    pub async fn async_list_tables(connection: &mut AsyncPgConnection) -> QueryResult<Vec<String>> {
        #[derive(QueryableByName)]
        struct Table {
            #[diesel(sql_type = diesel::sql_types::Text)]
            tablename: String,
        }
        sql_query("SELECT tablename FROM pg_tables WHERE schemaname = 'auth'")
            .load::<Table>(connection)
            .await
            .map(|tables| tables.into_iter().map(|t| t.tablename).collect())
    }

    impl DbHarness {
        pub async fn async_conn(&self) -> AsyncPgConnection {
            use diesel_async::AsyncConnection;
            let url = self.db_conf.db_url(self.db_name.as_str());
            AsyncPgConnection::establish(&url)
                .await
                .expect("Cannot establish database connection")
        }
    }
}
