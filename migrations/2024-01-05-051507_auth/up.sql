CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE auth.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR NOT NULL UNIQUE,
    created TIMESTAMP NOT NULL
);

CREATE TABLE auth.user_id_accounts (
    user_id UUID NOT NULL REFERENCES users(id),
    username VARCHAR NOT NULL UNIQUE,
    PRIMARY KEY (user_id, username)
);

INSERT INTO auth.users (id, email, created) VALUES (
    '00000000-0000-0000-0000-000000000000'::uuid,
    'support@subseq.io',
    NOW()
);
