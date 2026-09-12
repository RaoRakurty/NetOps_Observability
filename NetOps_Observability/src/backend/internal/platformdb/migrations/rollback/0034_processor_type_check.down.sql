-- Rollback for 0034_processor_type_check.sql. Restores the 0032 enum, which
-- only accepts the four original types — any mask/drop_event processors must be
-- removed first or the constraint will not validate.
ALTER TABLE pipeline_processors
    ADD CONSTRAINT pipeline_processors_rule_type_check
    CHECK (rule_type IN ('redact_field','redact_pattern','drop_field','set_field'));

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0034_processor_type_check.sql';
