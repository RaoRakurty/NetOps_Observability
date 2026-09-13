-- Rollback for 0051_user_identity_state.sql.
--
-- NOTE for the operator, in the order it matters:
--
-- 1. Every account loses its EXPLICIT migration state. The api then infers the
--    two-state answer again ("holds a tuple" = bound, "does not" = unresolved),
--    which is what the release before this one did — so an `ambiguous` flag, the
--    one state that cannot be inferred, is LOST. Export
--    `user_identity_state` first if the intent is a version rollback rather than a
--    feature removal: the accounts a human still has to remediate are recorded
--    nowhere else.
--
-- 2. The DETERMINISTICALLY backfilled LDAP/TACACS+ identities are deleted, because
--    restoring 0049's narrower CHECK would otherwise fail against them (ADD
--    CONSTRAINT validates existing rows). This is SAFE in a way that deleting an
--    'asserted' row would not be: those tuples are a pure function of the door's
--    configuration and the account's login name, so re-applying 0051 (or the boot
--    backfill) reproduces exactly the same rows for exactly the same accounts.
--    Between the two, those accounts are `identity_status: unresolved` and their
--    sign-in provisions a fresh account — so roll back the api in the same window,
--    do not leave the schema behind a running new api.
--
-- 3. `directory_dn` is dropped. It is a profile attribute (the DN the directory
--    returned), never a key, so nothing resolves differently without it.
DELETE FROM user_identities WHERE provenance IN ('backfilled-ldap', 'backfilled-tacacs');

ALTER TABLE user_identities DROP CONSTRAINT IF EXISTS user_identities_provenance_check;
ALTER TABLE user_identities ADD CONSTRAINT user_identities_provenance_check
    CHECK (provenance IN ('asserted', 'backfilled-local', 'legacy-lazy-bound'));

ALTER TABLE user_identities DROP COLUMN IF EXISTS directory_dn;

DROP TABLE IF EXISTS user_identity_state;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0051_user_identity_state.sql';
