-- Rollback for 0049_user_identities.sql.
--
-- NOTE for the operator: this removes EVERY canonical identity in the
-- deployment. After it, no account has an issuer/subject, so the api's
-- identity-aware login paths resolve nothing: local sign-in has no per-tenant
-- namespace to look a username up in, federated sign-in finds no tuple, and the
-- boot-time enforce check (users.VerifyIdentityInvariants) refuses to start
-- because every local account is missing its identity row. Roll back ONLY as part
-- of rolling the api back to a release that predates tracker 300.
--
-- It also drops the migration epoch (identity_migration). If 0049/0050 are later
-- re-applied, the epoch becomes the RE-APPLY time, and every account created in
-- between is then "pre-migration" as far as the bounded §2.6 lazy bind is
-- concerned — a wider adoption window than the original migration had. Export
-- both tables first if the intent is a version rollback rather than a feature
-- removal.
DROP TABLE IF EXISTS user_identities;
DROP TABLE IF EXISTS identity_migration;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0049_user_identities.sql';
