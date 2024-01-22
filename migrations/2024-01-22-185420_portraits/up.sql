CREATE TABLE auth.portraits (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id),
    portrait BYTEA NOT NULL
);

CREATE TABLE auth.metadata (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id),
    metadata JSONB NOT NULL
);
