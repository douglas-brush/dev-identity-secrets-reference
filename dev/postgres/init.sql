-- PostgreSQL initialization for Vault dynamic credentials demo.
-- This runs once when the container is first created.

-- ── Vault admin user ────────────────────────────────────────────────
-- Vault uses this account to create/revoke dynamic credentials.
-- In production, this would be provisioned by IaC with minimal grants.
CREATE USER vault_admin WITH PASSWORD 'vault_admin_password' CREATEROLE;

-- Grant vault_admin the ability to manage roles and table access
GRANT ALL PRIVILEGES ON DATABASE demo TO vault_admin;
GRANT ALL PRIVILEGES ON SCHEMA public TO vault_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO vault_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO vault_admin;

-- ── Sample application tables ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(255) NOT NULL UNIQUE,
    email       VARCHAR(255) NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash    VARCHAR(64)  NOT NULL,
    name        VARCHAR(255) NOT NULL,
    scopes      TEXT[]       DEFAULT '{}',
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    actor       VARCHAR(255) NOT NULL,
    action      VARCHAR(100) NOT NULL,
    resource    VARCHAR(255),
    detail      JSONB,
    ip_address  INET,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_actor ON audit_log(actor);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);

-- ── Seed data ───────────────────────────────────────────────────────
INSERT INTO users (username, email) VALUES
    ('alice',   'alice@example.com'),
    ('bob',     'bob@example.com'),
    ('ci-bot',  'ci@example.com');

INSERT INTO api_keys (user_id, key_hash, name, scopes) VALUES
    (1, 'sha256-placeholder-alice-key', 'alice-dev-key',  ARRAY['read', 'write']),
    (2, 'sha256-placeholder-bob-key',   'bob-readonly',   ARRAY['read']),
    (3, 'sha256-placeholder-ci-key',    'ci-deploy-key',  ARRAY['deploy']);

INSERT INTO audit_log (actor, action, resource, detail) VALUES
    ('system', 'database_init', 'demo', '{"message": "Local dev environment initialized"}');

-- ── Grant table access to vault_admin so dynamic roles inherit it ──
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vault_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vault_admin;
