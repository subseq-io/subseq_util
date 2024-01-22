// @generated automatically by Diesel CLI.

pub mod auth {
    diesel::table! {
        auth.metadata (user_id) {
            user_id -> Uuid,
            #[sql_name = "metadata"]
            data -> Jsonb,
        }
    }

    diesel::table! {
        auth.portraits (user_id) {
            user_id -> Uuid,
            portrait -> Bytea,
        }
    }

    diesel::table! {
        auth.user_id_accounts (user_id, username) {
            user_id -> Uuid,
            username -> Varchar,
            #[max_length = 10]
            account_type -> Nullable<Varchar>,
        }
    }

    diesel::table! {
        auth.users (id) {
            id -> Uuid,
            email -> Varchar,
            created -> Timestamp,
        }
    }

    diesel::joinable!(metadata -> users (user_id));
    diesel::joinable!(portraits -> users (user_id));
    diesel::joinable!(user_id_accounts -> users (user_id));

    diesel::allow_tables_to_appear_in_same_query!(
        metadata,
        portraits,
        user_id_accounts,
        users,
    );
}
