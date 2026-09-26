-- =============================================================================
-- keycloak_uid: Keycloak `sub` UUID of the owning user (task 01 phase 2,
-- additive). user_id stays the key for reads/authorization (it is
-- deriveUserID(sub), the gateway's FNV-1a-64 bridge). keycloak_uid is
-- dual-written from the gateway's X-User-Uid when the caller is the row owner
-- (NULL otherwise) and backfilled from Keycloak by an operator. Idempotent.
--
-- DOWN (manual; this repo's runner re-applies every file on start, so also
-- delete this file before rolling back):
--   SET search_path TO target;
--   DROP INDEX IF EXISTS idx_targets_keycloak_uid;
--   ALTER TABLE targets DROP COLUMN IF EXISTS keycloak_uid;
-- =============================================================================
SET search_path TO target;

ALTER TABLE targets ADD COLUMN IF NOT EXISTS keycloak_uid UUID;
CREATE INDEX IF NOT EXISTS idx_targets_keycloak_uid ON targets (keycloak_uid);
