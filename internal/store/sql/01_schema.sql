-- =============================================================================
-- target-service schema bootstrap
-- Schema: target
-- Idempotent: every statement is safe to re-run.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS target AUTHORIZATION "target-service-user";
ALTER USER "target-service-user" SET SEARCH_PATH TO target;
SET search_path TO target;

-- ---------------------------------------------------------------------------
-- targets
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS targets (
    id                BIGSERIAL PRIMARY KEY,
    uid               UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    user_id           BIGINT NOT NULL,
    kind              TEXT NOT NULL,                        -- 'domain'|'url'|'ip'|'cidr'
    value             TEXT NOT NULL,                        -- normalized host / CIDR
    registrable_domain TEXT,                               -- eTLD+1 for domain/url kinds
    status            TEXT NOT NULL DEFAULT 'unverified',  -- 'unverified'|'verifying'|'verified'|'revoked'
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_targets_user_id ON targets(user_id);
CREATE INDEX IF NOT EXISTS idx_targets_status  ON targets(status);

-- ---------------------------------------------------------------------------
-- authorizations
-- Proof-of-control record. An intrusive scan requires a current, non-expired
-- row with verified_at IS NOT NULL.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authorizations (
    id           BIGSERIAL PRIMARY KEY,
    uid          UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    target_id    BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    method       TEXT NOT NULL,   -- 'dns_txt'|'http_file'|'meta_tag'|'email'|'ip_registry'
    token        TEXT NOT NULL,   -- issued challenge token
    scope_kind   TEXT NOT NULL,   -- 'registrable_domain'|'ip_range'
    scope_value  TEXT NOT NULL,   -- e.g. 'example.com' or '203.0.113.0/24'
    verified_at  TIMESTAMPTZ,     -- set when verification succeeded
    expires_at   TIMESTAMPTZ,     -- re-verify before this date
    attested_by  BIGINT,          -- user who attested ownership (ToS record)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_authorizations_target_id ON authorizations(target_id);
CREATE INDEX IF NOT EXISTS idx_authorizations_token     ON authorizations(token);

-- ---------------------------------------------------------------------------
-- assets
-- Discovered subdomains/IPs/ports/services — authoritative inventory.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets (
    id              BIGSERIAL PRIMARY KEY,
    uid             UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    target_id       BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_type      TEXT NOT NULL,   -- 'subdomain'|'ip'|'port'|'service'|'endpoint'
    value           TEXT NOT NULL,
    parent_asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL,
    scope_class     TEXT NOT NULL DEFAULT 'unknown',  -- 'in_scope'|'out_of_scope'|'shared_infra'|'unknown'
    metadata        JSONB,
    discovered_by   TEXT,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_id, asset_type, value)
);

CREATE INDEX IF NOT EXISTS idx_assets_target_id   ON assets(target_id);
CREATE INDEX IF NOT EXISTS idx_assets_scope_class ON assets(scope_class);
