pub mod email;
pub mod users;

pub use crate::tables::{gen_rand_string, EmailVerification};
pub use email::AsyncUnverifiedEmailTable;

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
