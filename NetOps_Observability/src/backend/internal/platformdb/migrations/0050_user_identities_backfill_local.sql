-- 0050_user_identities_backfill_local.sql — the BACKFILL step of tracker 300
-- (design §3). It gives every existing LOCAL account its canonical identity and
-- stamps the migration epoch. It is the FIRST migration in this schema to carry
-- data rather than DDL, and the two comments below are why it is written the way
-- it is.
--
-- 1. LOCAL ROWS ONLY. A local account's issuer and subject ARE derivable offline
--    with certainty: the issuer is the literal 'local' namespace and the subject
--    is the account's own lower(username), which is exactly what `users.id`
--    already holds. A FEDERATED row is the opposite case — it carries no issuer
--    and no subject, the value cannot be reconstructed from anything on disk, and
--    the owner's rule 6 forbids guessing. Those rows are therefore left with NO
--    identity row: they surface as `identity_status: pending`, and they are bound
--    only by the bounded §2.6 rule at their next login (the same door, the same
--    legacy username, before this epoch, not local, not disabled, not already
--    bound) or by an operator. This migration NEVER merges on a username or an
--    email.
--
-- 2. WHY set_config IS HERE. `users` and `user_identities` are FORCE ROW LEVEL
--    SECURITY and the api connects as a NON-superuser role that owns them, so RLS
--    applies to the migrator too. The migration connection has no app.tenant_id
--    set, so current_setting('app.tenant_id', true) is NULL on a fresh connection
--    and the tenant_iso policy denies. That is fail-closed and correct for the
--    request path, but it would make this backfill silently insert NOTHING.
--    Worse, a POOLED connection that has already served one WithTenant
--    transaction reads the GUC back as the empty string once the transaction-local
--    value reverts (a custom-GUC placeholder's session default is ''), so the
--    policy then matches exactly the blank-tenant rows — and the backfill inserts
--    SOME of the estate. A migration that "succeeds" while converting part of the
--    estate is the worst outcome available; proven by removing this line and
--    watching internal/users' idempotency test report 1 identity instead of 2.
--    The platform-owner scope ('*') is the same scope the store's own boot-time
--    normalisation runs under (users.PGStore.migrateLocalAuthSource), set with the
--    third argument `true` so it is LOCAL TO THIS TRANSACTION and reverts on
--    commit.
--
-- IDEMPOTENT by construction: ON CONFLICT DO NOTHING on both the PK
-- (tenant_id, issuer, subject) and UNIQUE (user_id), so re-applying inserts
-- nothing and changes nothing. Applying it twice is a proven no-op
-- (internal/users migration-idempotency test).

SELECT set_config('app.tenant_id', '*', true);

INSERT INTO user_identities
    (tenant_id, issuer, subject, user_id, protocol, connection_id, subject_kind, provenance)
SELECT u.tenant_id, 'local', u.id, u.id, 'local', '', '', 'backfilled-local'
  FROM users u
 WHERE COALESCE(u.data->>'auth_source', '') IN ('', 'local')
   AND u.id <> ''
ON CONFLICT DO NOTHING;

-- The epoch (design §2.6 condition 3). Write-once: a second apply must not move
-- it forward, because that would widen the lazy-bind window to every account
-- created since the first apply.
INSERT INTO identity_migration (singleton) VALUES (TRUE)
ON CONFLICT DO NOTHING;
