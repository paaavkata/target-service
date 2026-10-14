-- =============================================================================
-- 04 — bug-bounty authorization mode (plans/17-scanner-coverage-gaps.md §10)
-- Schema: target
-- Idempotent: every statement is safe to re-run. Applied after 03 (files run in
-- alphabetical order, each in its own Exec, so the search_path is set again).
--
-- Structured, machine-readable bug-bounty program policy — a SECOND
-- authorization mode alongside client mode. The scope gate (scope_service.go)
-- resolves the governing program for a program-mode authorization and enforces
-- per-job scope / automation / prohibited-technique rules from these tables.
-- =============================================================================
SET search_path TO target;

-- ---------------------------------------------------------------------------
-- bugbounty_programs
-- One row per synced program policy. Unique on (platform, handle).
-- raw_policy keeps the source payload for audit; the typed columns are what the
-- gate reads. stale_after_seconds is the per-program staleness window (0 ⇒ the
-- service default); synced_at older than that window ⇒ the gate refuses to run.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bugbounty_programs (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform             TEXT NOT NULL,                       -- 'hackerone'|'bugcrowd'|...
    handle               TEXT NOT NULL,                       -- program slug/handle on the platform
    name                 TEXT NOT NULL DEFAULT '',
    policy_url           TEXT NOT NULL DEFAULT '',
    automation_allowed   BOOLEAN NOT NULL DEFAULT FALSE,      -- default-deny: automation must be explicitly permitted
    rate_limit_rps       INT,                                 -- nullable; NULL ⇒ no stated limit
    prohibited_techniques TEXT[] NOT NULL DEFAULT '{}',       -- normalized technique tokens the program forbids
    safe_harbor          BOOLEAN NOT NULL DEFAULT FALSE,
    raw_policy           JSONB,
    synced_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale_after_seconds  INT NOT NULL DEFAULT 604800,         -- 7 days; 0 ⇒ service default
    status               TEXT NOT NULL DEFAULT 'active',      -- 'active'|'paused'
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (platform, handle)
);

-- ---------------------------------------------------------------------------
-- program_assets
-- Per-asset scope. in_scope=true ⇒ included, false ⇒ explicitly excluded.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS program_assets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    program_id  UUID NOT NULL REFERENCES bugbounty_programs(id) ON DELETE CASCADE,
    asset_type  TEXT NOT NULL,   -- 'domain'|'wildcard'|'url'|'ip'|'cidr'|'other'
    identifier  TEXT NOT NULL,   -- e.g. 'example.com', '*.example.com', '203.0.113.0/24'
    in_scope    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_program_assets_program_scope ON program_assets(program_id, in_scope);
CREATE INDEX IF NOT EXISTS idx_program_assets_identifier    ON program_assets(identifier);
