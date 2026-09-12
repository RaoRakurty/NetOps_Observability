-- Rollback for 0045_tac_templates.sql. Drops the per-tenant TAC command
-- templates. Correlix's own default templates are generated from the authored
-- plans and are unaffected — after this rollback the review step still shows
-- every command before collect and still lets an operator edit the list; only
-- SAVING a set survives it.
DROP TABLE IF EXISTS tac_templates;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0045_tac_templates.sql';
