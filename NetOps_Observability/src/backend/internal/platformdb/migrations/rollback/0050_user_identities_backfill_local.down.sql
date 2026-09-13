-- Rollback for 0050_user_identities_backfill_local.sql.
--
-- It deletes ONLY the rows this migration created — provenance =
-- 'backfilled-local'. Rows written by a door ('asserted') and rows adopted by the
-- bounded §2.6 lazy bind ('legacy-lazy-bound') are other code's facts and are
-- left alone; deleting them would silently re-provision those principals as new
-- accounts at their next sign-in, with fresh roles.
--
-- The migration EPOCH (identity_migration) is deliberately NOT deleted. It is
-- write-once on purpose: if a re-apply could move it forward, the §2.6 adoption
-- window would widen to every account created since. Keeping the original epoch
-- means a re-apply of 0050 is exactly as safe as the first apply. 0049's rollback
-- is where the epoch goes, together with the table it belongs to.
--
-- NOTE for the operator: after this, every LOCAL account is `identity_status:
-- pending` and the boot-time enforce check (users.VerifyIdentityInvariants)
-- refuses to start the api. Re-apply 0050 (it is idempotent) or roll 0049 back as
-- well.
DELETE FROM user_identities WHERE provenance = 'backfilled-local';

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0050_user_identities_backfill_local.sql';
