pub mod auth {
    diesel::table! {
        auth.user_id_accounts (user_id, username) {
            user_id -> Uuid,
            username -> Varchar,
        }
    }

    diesel::table! {
        auth.users (id) {
            id -> Uuid,
            email -> Varchar,
            created -> Timestamp,
        }
    }
    diesel::joinable!(user_id_accounts -> users (user_id));

    diesel::allow_tables_to_appear_in_same_query!(user_id_accounts, users,);
}
