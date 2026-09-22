-- =============================================================================
-- 02 — admin panel: program targets (plans/10-ADMIN-PANEL.md §3)
-- Schema: target
-- Idempotent: every statement is safe to re-run. Applied after 01_schema.sql
-- (files run in alphabetical order, each in its own Exec, so the search_path
-- is set again here).
-- =============================================================================
SET search_path TO target;

ALTER TABLE targets        ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'customer'; -- 'customer'|'program'
ALTER TABLE targets        ADD COLUMN IF NOT EXISTS label  TEXT;
ALTER TABLE authorizations ADD COLUMN IF NOT EXISTS evidence JSONB;
CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);
CREATE INDEX IF NOT EXISTS idx_targets_source ON targets(source);
