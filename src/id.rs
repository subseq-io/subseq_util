#[macro_export]
macro_rules! uuid_type {
    ($name:ident) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            Serialize,
            Deserialize,
            Default,
            AsExpression,
            FromSqlRow,
        )]
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub struct $name(pub Uuid);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl<DB> FromSql<diesel::sql_types::Uuid, DB> for $name
        where
            DB: Backend,
            Uuid: FromSql<diesel::sql_types::Uuid, DB>,
        {
            fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
                Uuid::from_sql(bytes).map($name)
            }
        }

        impl<DB> ToSql<diesel::sql_types::Uuid, DB> for $name
        where
            DB: Backend,
            Uuid: ToSql<diesel::sql_types::Uuid, DB>,
        {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> diesel::serialize::Result {
                self.0.to_sql(out)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::from_str(s).map($name)
            }
        }
    };
}
