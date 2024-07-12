pub mod email;
pub mod users;

use diesel::{ConnectionError, ConnectionResult};
use diesel_async::pooled_connection::{bb8::Pool, AsyncDieselConnectionManager, ManagerConfig};
use diesel_async::AsyncPgConnection;
use futures_util::future::{BoxFuture, FutureExt};
use tokio::time::Duration;

use crate::get_cert_pool;
pub use crate::tables::email::{gen_rand_string, EmailVerification, UnverifiedEmailTable};
pub use crate::tables::users::{UserAccountType, UserIdTable, UserTable};

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
    let certs = get_cert_pool()
        .map(|pool| pool.der_certs().clone())
        .unwrap_or_default();
    roots.add_parsable_certificates(certs);
    roots
}

pub async fn establish_connection_pool(db_url: &str, secure: bool) -> anyhow::Result<DbPool> {
    let mut config = ManagerConfig::default();
    if secure {
        config.custom_setup = Box::new(establish_secure_connection);
    }
    let manager =
        AsyncDieselConnectionManager::<AsyncPgConnection>::new_with_config(db_url, config);

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
            pub async fn list(
                conn: &mut AsyncPgConnection,
                page: u32,
                page_size: u32,
            ) -> Vec<Self> {
                let offset = page.saturating_sub(1) * page_size;
                match $table
                    .limit(page_size as i64)
                    .offset(offset as i64)
                    .load::<Self>(conn)
                    .await
                {
                    Ok(list) => list,
                    Err(err) => {
                        tracing::warn!("DB List Query Failed: {:?}", err);
                        vec![]
                    }
                }
            }

            pub async fn get(conn: &mut AsyncPgConnection, id: Uuid) -> Option<Self> {
                $table
                    .find(id)
                    .get_result::<Self>(conn)
                    .await
                    .optional()
                    .ok()?
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
    use crate::server::DatabaseConfig;
    use diesel::migration::MigrationSource;
    use diesel::prelude::*;
    use diesel::{pg::Pg, sql_query};
    use diesel_async::async_connection_wrapper::AsyncConnectionWrapper;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    pub const AUTH_MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/");

    pub fn to_pg_db_name(name: &str) -> String {
        let mut db_name = String::new();

        // Ensure the name starts with an underscore if it doesn't start with a letter
        if name
            .chars()
            .next()
            .map_or(true, |c| !c.is_ascii_alphabetic())
        {
            db_name.push('_');
        }

        // Convert function name to lowercase and replace invalid characters
        for ch in name.chars() {
            if ch.is_ascii_alphanumeric() {
                db_name.push(ch.to_ascii_lowercase());
            } else {
                db_name.push('_');
            }
        }

        // Truncate if length exceeds 63 characters
        let max_length = 63;
        if db_name.len() > max_length {
            db_name.truncate(max_length);
        }

        db_name
    }

    pub async fn list_tables(connection: &mut AsyncPgConnection) -> QueryResult<Vec<String>> {
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

    fn run_migrations(
        url: &str,
        server_migrations: Option<EmbeddedMigrations>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let mut connection = AsyncConnectionWrapper::<AsyncPgConnection>::establish(&url)?;
        for mig in
            <EmbeddedMigrations as MigrationSource<Pg>>::migrations(&AUTH_MIGRATIONS).unwrap()
        {
            eprintln!("migration: {}", mig.name());
        }
        connection.run_pending_migrations(AUTH_MIGRATIONS)?;
        if let Some(server_migrations) = server_migrations {
            for mig in
                <EmbeddedMigrations as MigrationSource<Pg>>::migrations(&server_migrations).unwrap()
            {
                eprintln!("migration: {}", mig.name());
            }
            connection.run_pending_migrations(server_migrations)?;
        }
        Ok(())
    }

    pub struct DbHarness {
        pub(crate) db_conf: DatabaseConfig,
        pub(crate) db_name: String,
    }

    impl Drop for DbHarness {
        fn drop(&mut self) {
            let url = self.db_conf.db_url("postgres");
            let db_name = self.db_name.clone();

            tokio::task::spawn(async move {
                let mut conn = AsyncPgConnection::establish(&url)
                    .await
                    .expect("Cannot establish database connection");

                let disconnect_users = format!(
                    "SELECT pg_terminate_backend(pid)
                                               FROM pg_stat_activity
                                               WHERE datname = '{}';",
                    db_name
                );
                if diesel::sql_query(disconnect_users)
                    .execute(&mut conn)
                    .await
                    .is_err()
                {
                    eprintln!("Failed to drop database {}", db_name);
                    return;
                }

                eprintln!("Drop database: {}", db_name);
                let drop_db = format!("DROP DATABASE {}", db_name);
                if diesel::sql_query(drop_db).execute(&mut conn).await.is_err() {
                    eprintln!("Failed to drop database {}", db_name);
                }
            });
        }
    }

    impl DbHarness {
        pub async fn new(
            host: &str,
            password: &str,
            database: &str,
            server_migrations: Option<EmbeddedMigrations>,
        ) -> Self {
            let db_conf = DatabaseConfig {
                username: "postgres".to_string(),
                password: Some(password.to_string()),
                host: host.to_string(),
                port: 5432,
                require_ssl: false,
            };
            let url = db_conf.db_url("postgres");
            let database = format!("dbharness_{}", database);
            eprintln!("Connecting to url: {}", url);
            let mut conn = AsyncPgConnection::establish(&url)
                .await
                .expect("Cannot establish database connection");
            let drop_db = diesel::sql_query(format!("DROP DATABASE IF EXISTS {}", database));
            drop_db
                .execute(&mut conn)
                .await
                .unwrap_or_else(|_| panic!("Creating {} failed", database));
            eprintln!("Creating database: {}", database);
            let query = diesel::sql_query(format!("CREATE DATABASE {}", database));
            query
                .execute(&mut conn)
                .await
                .unwrap_or_else(|_| panic!("Creating {} failed", database));
            let url = db_conf.db_url(&database);

            eprintln!("Connecting to url: {}", url);
            run_migrations(&url, server_migrations).expect("Migrations failed");

            Self {
                db_conf,
                db_name: database,
            }
        }

        pub async fn conn(&self) -> AsyncPgConnection {
            use diesel_async::AsyncConnection;
            let url = self.db_conf.db_url(self.db_name.as_str());
            AsyncPgConnection::establish(&url)
                .await
                .expect("Cannot establish database connection")
        }
    }
}
