-- 0052_change_ledger.sql — the change ledger's provenance columns (Iris plan
-- N-D1, docs/architecture/iris-natural-language-platform.md §5 Phase D).
--
-- dem_change_events (migration 0044) answered "what changed, of which type, for
-- which app or site, since when". The questions Iris has to answer next are
-- "WHO changed it", "what else did they change", "what changed on THIS device"
-- and "only the ones the config backup saw" — and none of those could be asked
-- of the database: the actor and the object lived only inside `data`, so a
-- filter on them ran in Go AFTER the row limit, which answers a different
-- question from the one asked (a busy tenant's limit is spent on rows that do
-- not match, and "nothing changed" comes back while the answer sits one page
-- down). This migration gives every filterable field a typed column.
--
--   source_system  the producer that recorded the change: `config_capture`
--                  (a configuration backup that found a NEW version),
--                  `correlix_audit` (an allowed mutation made through this
--                  platform), `ledger` (posted to /api/dem/changes; also every
--                  row that predates this migration).
--   actor          the SOURCE identity, verbatim, as the producer saw it.
--   actor_type     user | service | automation | system | unknown (closed).
--   actor_id       the Correlix canonical identity when the identity store
--                  knows the source actor, otherwise the source identity
--                  verbatim — never a guess (N-D4).
--   actor_display  a human label for the actor when one is known.
--   object / object_kind  WHAT was changed (a device id, a resource …).
--   ticket_ref     the change ticket the producer attached, if any.
--   automation     true when no human made the change directly.
--   detected_at    when Correlix LEARNED of the change. event_at stays when it
--                  HAPPENED; the gap between them is diagnostic (a capture sweep
--                  finds a change up to one interval after it was made).
--
-- RETENTION: the ledger is now bounded by AGE, not by a per-tenant row count.
-- Rows whose event_at is older than 180 days are deleted by the store itself,
-- inside the writing tenant's WithTenant transaction, so the FORCE-RLS policy
-- scopes every delete to that one tenant (internal/dem/experience
-- ChangeRetention). A row cap evicted the OLDEST rows of the busiest tenant
-- first, which made "what changed on this device last quarter" depend on how
-- chatty some other producer had been this week.
--
-- RLS: unchanged — 0044's tenant_iso FORCE policy covers every column of the
-- table, including these.
--
-- Additive and idempotent — safe to apply forward. Rollback:
-- rollback/0052_change_ledger.down.sql.

ALTER TABLE dem_change_events ADD COLUMN IF NOT EXISTS source_system TEXT NOT NULL DEFAULT 'ledger';
ALTER TABLE dem_change_events ADD COLUMN IF NOT EXISTS actor         TEXT NOT NULL DEFAULT '';
ALTER TABLE dem_change_events ADD COLUMN IF NOT EXISTS actor_type    TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE dem_change_events ADD COLUMN IF NOT EXISTS actor_id      TEXT NOT NULL DEFAULT '';
ALTER TABLE dem_change_events ADD COLUMN IF NOT EXISTS actor_display TEXT NOT NULL DEFAULT '';
ALTER TABLE dem_change_events ADD COLUMN IF NOT EXISTS object        TEXT NOT NULL DEFAULT '';
ALTER TABLE dem_change_events ADD COLUMN IF NOT EXISTS object_kind   TEXT NOT NULL DEFAULT '';
ALTER TABLE dem_change_events ADD COLUMN IF NOT EXISTS ticket_ref    TEXT NOT NULL DEFAULT '';
ALTER TABLE dem_change_events ADD COLUMN IF NOT EXISTS automation    BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE dem_change_events ADD COLUMN IF NOT EXISTS detected_at   TIMESTAMPTZ;

-- The closed actor vocabulary is CHECKed here as well as in the store: the
-- store is the first line, the database is the line that still holds if a
-- future writer bypasses it.
ALTER TABLE dem_change_events DROP CONSTRAINT IF EXISTS dem_change_events_actor_type_check;
ALTER TABLE dem_change_events ADD CONSTRAINT dem_change_events_actor_type_check
    CHECK (actor_type IN ('user','service','automation','system','unknown'));

-- Backfill the rows written before this migration from their own `data`, with
-- exactly the defaults the store applies on read (experience.ChangeEvent
-- applyDefaults): the source identity is kept verbatim as actor_id, and the
-- actor type is `unknown` because nothing recorded it. The predicate makes the
-- statement idempotent: a row that already carries its object is never touched
-- again.
--
-- WHY set_config IS HERE (0050 is the precedent and has the long form):
-- dem_change_events is FORCE ROW LEVEL SECURITY and the migrator connects as the
-- non-superuser role that owns it, so the tenant_iso policy applies to this
-- UPDATE too. With no app.tenant_id the policy matches nothing (fresh
-- connection) or only the blank-tenant rows (a pooled connection whose GUC
-- reverted to ''), and the backfill would "succeed" while converting none or
-- part of the estate. '*' is the platform scope, and the third argument `true`
-- makes it LOCAL to this migration's transaction.
SELECT set_config('app.tenant_id', '*', true);

UPDATE dem_change_events
   SET actor       = COALESCE(data->>'actor', ''),
       actor_id    = COALESCE(data->>'actor', ''),
       object      = COALESCE(data->>'object', ''),
       object_kind = COALESCE(data->>'object_kind', ''),
       detected_at = COALESCE(NULLIF(data->'provenance'->>'observed_at', '')::timestamptz, event_at)
 WHERE object = '' AND data->>'object' IS NOT NULL;

-- "What changed on this device / this resource" — one tenant, one object,
-- newest first.
CREATE INDEX IF NOT EXISTS dem_change_events_object_idx
    ON dem_change_events (tenant_id, object, event_at DESC);

-- config_backup_versions (migration 0038): the capture TRIGGER is stored on the
-- version row, so the ledger's actor for a configuration change can be traced
-- back to the capture that produced it after the audit trail has rotated.
-- `scheduled`, `manual` or `manual:<principal id>`; '' on rows written before
-- this migration (their trigger was never recorded anywhere but the audit log).
ALTER TABLE config_backup_versions ADD COLUMN IF NOT EXISTS capture_trigger TEXT NOT NULL DEFAULT '';
