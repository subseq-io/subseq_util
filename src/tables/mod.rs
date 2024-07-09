use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use std::time::Duration;

pub mod email;
pub mod users;
pub use email::{gen_rand_string, EmailVerification, UnverifiedEmailTable};
pub use users::{UserAccountType, UserIdTable, UserTable};

pub type DbPool = Pool<ConnectionManager<PgConnection>>;
const DB_TIMEOUT: Duration = Duration::from_secs(3);

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

pub mod harness {
    use crate::server::DatabaseConfig;
    use diesel::migration::MigrationSource;
    use diesel::pg::Pg;
    use diesel::pg::PgConnection;
    use diesel::prelude::*;
    use diesel::sql_query;
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

    pub fn list_tables(connection: &mut PgConnection) -> QueryResult<Vec<String>> {
        #[derive(QueryableByName)]
        struct Table {
            #[diesel(sql_type = diesel::sql_types::Text)]
            tablename: String,
        }
        sql_query("SELECT tablename FROM pg_tables WHERE schemaname = 'auth'")
            .load::<Table>(connection)
            .map(|tables| tables.into_iter().map(|t| t.tablename).collect())
    }

    fn run_migrations(
        connection: &mut impl MigrationHarness<Pg>,
        server_migrations: Option<EmbeddedMigrations>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
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
            let mut conn =
                PgConnection::establish(&url).expect("Cannot establish database connection");

            let disconnect_users = format!(
                "SELECT pg_terminate_backend(pid)
                                           FROM pg_stat_activity
                                           WHERE datname = '{}';",
                self.db_name
            );
            if diesel::sql_query(disconnect_users)
                .execute(&mut conn)
                .is_err()
            {
                eprintln!("Failed to drop database {}", self.db_name);
                return;
            }

            eprintln!("Drop database: {}", self.db_name);
            let drop_db = format!("DROP DATABASE {}", self.db_name);
            if diesel::sql_query(drop_db).execute(&mut conn).is_err() {
                eprintln!("Failed to drop database {}", self.db_name);
            }
        }
    }

    impl DbHarness {
        pub fn new(
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
            let mut conn =
                PgConnection::establish(&url).expect("Cannot establish database connection");
            let drop_db = diesel::sql_query(format!("DROP DATABASE IF EXISTS {}", database));
            drop_db
                .execute(&mut conn)
                .unwrap_or_else(|_| panic!("Creating {} failed", database));
            eprintln!("Creating database: {}", database);
            let query = diesel::sql_query(format!("CREATE DATABASE {}", database));
            query
                .execute(&mut conn)
                .unwrap_or_else(|_| panic!("Creating {} failed", database));
            let url = db_conf.db_url(&database);
            eprintln!("Connecting to url: {}", url);
            let mut db_conn =
                PgConnection::establish(&url).expect("Cannot establish database connection");
            run_migrations(&mut db_conn, server_migrations).expect("Migrations failed");

            Self {
                db_conf,
                db_name: database,
            }
        }

        pub fn conn(&self) -> PgConnection {
            let url = self.db_conf.db_url(self.db_name.as_str());
            PgConnection::establish(&url).expect("Cannot establish database connection")
        }
    }
}
