CREATE TABLE auth.pending_email_verifications (
    id VARCHAR(128) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    created TIMESTAMP NOT NULL,
    expires TIMESTAMP NOT NULL
)
