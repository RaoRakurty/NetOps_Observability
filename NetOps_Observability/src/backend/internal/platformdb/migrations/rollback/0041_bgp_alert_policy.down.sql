-- Rollback for 0041_bgp_alert_policy.sql.
--
-- NOTE for the operator: dropping this table removes every tenant's DECLARED
-- alert intent (expected origins, upstream sets, thresholds). The watchlist
-- evaluator then falls back to a LEARNED origin baseline and runs no route-leak
-- heuristic at all — it keeps working, but it alerts on less, and it will not
-- say that it used to know more. Export the rows first if the intent is a
-- version rollback rather than a feature removal.
DROP TABLE IF EXISTS bgp_alert_policy;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0041_bgp_alert_policy.sql';
