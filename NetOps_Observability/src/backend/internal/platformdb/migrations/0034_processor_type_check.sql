-- 0034_processor_type_check.sql — let the ENGINE own the processor-type enum.
--
-- BUG THIS FIXES (found in the 2026-07-31 code review): migration 0032 pinned
--   rule_type IN ('redact_field','redact_pattern','drop_field','set_field')
-- in a CHECK constraint. The framework (0033) added `mask` and `drop_event`,
-- and the API + UI advertise them — but on the POSTGRES backend creating one
-- violated the constraint and returned an opaque 500. The file backend (dev)
-- accepted them, so this was a textbook works-in-dev / breaks-in-production
-- split. The pg isolation test only exercised drop_field, so nothing caught it.
--
-- Fix: drop the CHECK rather than restate the list. `Rule.Validate` +
-- the action registry are already the single source of truth for which types
-- exist (adding one is a Register call); a duplicated enum in SQL can only
-- drift out of date exactly the way it just did. `lane` keeps its CHECK: lanes
-- are a fixed property of the ingest topology, not an extension point.
--
-- Idempotent; the constraint name is Postgres's default for 0032's inline CHECK.

ALTER TABLE pipeline_processors
    DROP CONSTRAINT IF EXISTS pipeline_processors_rule_type_check;
