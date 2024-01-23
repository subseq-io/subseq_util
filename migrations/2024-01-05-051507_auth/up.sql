CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE auth.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR NOT NULL UNIQUE,
    created TIMESTAMP NOT NULL
);

CREATE TABLE auth.user_id_accounts (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id),
    username VARCHAR NOT NULL UNIQUE
);
