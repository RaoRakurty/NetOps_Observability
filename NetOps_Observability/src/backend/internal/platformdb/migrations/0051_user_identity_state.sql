-- 0051_user_identity_state.sql — the EXPLICIT migration state of every account,
-- plus the two schema changes the deterministic backfill needs (tracker 300,
-- owner Decision 2, 2026-09-13).
--
-- WHY THIS MIGRATION EXISTS. 0049/0050 namespaced every LOCAL account and left
-- every FEDERATED one waiting for a future login to repair it one at a time. The
-- owner VETOED that as the migration model:
--
--   "Use deterministic migration/backfill for identities whose current provenance
--    can be established. … Do not leave all existing identities un-namespaced and
--    rely on future logins to repair them one at a time. … A constrained lazy
--    migration MAY exist only for legacy records whose issuer/source/subject
--    provenance cannot safely be reconstructed offline. For those cases: place
--    them in an explicit legacy/unresolved state or namespace … Add migration
--    metrics showing: deterministically migrated / legacy/unresolved /
--    ambiguous/manual remediation."
--
-- So this migration adds the three things that decision needs and 0049 did not
-- have:
--
-- 1. `user_identity_state` — the state is STORED, not inferred from "does a row
--    exist in user_identities". An operator asking "what is waiting for me?" gets
--    the same answer whatever code last looked at the account, and `ambiguous`
--    (the derivation collided; never merge, never guess) becomes expressible at
--    all. `since` answers "for how long".
--
-- 2. Two more provenance values — `backfilled-ldap` / `backfilled-tacacs`. For
--    those two doors the provenance CAN be established offline: the issuer is the
--    configured directory's host:port and the subject is the login name the
--    directory authenticated. They are recorded distinctly from
--    `backfilled-local` and from `legacy-lazy-bound` so the metrics can separate
--    "deterministically migrated" from "repaired by a login".
--
-- 3. `user_identities.directory_dn` — the LDAP DN demoted from KEY to PROFILE
--    attribute. Keying on the DN (the original §2.3) both re-namespaced an
--    account whenever a person moved OU and made every legacy LDAP row
--    un-backfillable offline, since the DN is not stored anywhere on the row. The
--    login name is what the directory authenticated and it is stable, so it is
--    the subject; the DN is kept beside it because it is what an operator
--    correlates with the directory.
--
-- `users` is DELIBERATELY UNTOUCHED: no column added, no data rewritten. The
-- state lives in its own table with its own FORCE-RLS tenant_iso policy (§3a rule
-- 4: the storage layer enforces isolation), and it disappears with the account it
-- describes via ON DELETE CASCADE.
--
-- IDEMPOTENT by construction: IF NOT EXISTS, DROP CONSTRAINT IF EXISTS before
-- ADD, and ON CONFLICT DO NOTHING on the seed. Re-applying changes nothing.

-- 1. The DN becomes a profile attribute.
ALTER TABLE user_identities ADD COLUMN IF NOT EXISTS directory_dn TEXT NOT NULL DEFAULT '';

-- 2. The provenance vocabulary grows by the two DETERMINISTIC backfills. Dropped
--    and re-added rather than edited: a CHECK constraint has no ALTER form, and
--    the name is the one Postgres gave the column check in 0049.
ALTER TABLE user_identities DROP CONSTRAINT IF EXISTS user_identities_provenance_check;
ALTER TABLE user_identities ADD CONSTRAINT user_identities_provenance_check
    CHECK (provenance IN ('asserted', 'backfilled-local', 'backfilled-ldap',
                          'backfilled-tacacs', 'legacy-lazy-bound'));

-- 3. The explicit state.
CREATE TABLE IF NOT EXISTS user_identity_state (
    user_id   TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL DEFAULT '',
    state     TEXT NOT NULL CHECK (state IN ('bound', 'unresolved', 'ambiguous')),
    -- The closed reason vocabulary lives in Go (internal/users/identity.go) rather
    -- than in a CHECK: a new reason must not require a migration to be reportable,
    -- and an unrecognised one degrades to "listed for an operator", not to a failed
    -- write. '' is correct for `bound`.
    reason    TEXT NOT NULL DEFAULT '',
    since     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The admin surface lists by state (?identity=unresolved|ambiguous), so that is
-- the one access path worth an index.
CREATE INDEX IF NOT EXISTS user_identity_state_state_idx ON user_identity_state (state);

ALTER TABLE user_identity_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_identity_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON user_identity_state;
CREATE POLICY tenant_iso ON user_identity_state
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

-- 4. Seed the state of the estate as it stands. `set_config` for the same reason
--    0050 needs it: both tables are FORCE ROW LEVEL SECURITY and the migrator
--    connects as the non-superuser role that owns them, so without the
--    platform-owner scope this INSERT would silently convert only the blank-tenant
--    rows (transaction-local: it reverts on commit).
--
--    An account that holds a tuple is `bound`. One that does not is `unresolved`
--    with reason `pending-backfill`: this migration does NOT derive identities —
--    the issuer of an LDAP/TACACS+ account is the DOOR's configuration, which only
--    the api knows, so the derivation is the boot backfill's job
--    (internal/users.BackfillIdentities) and it runs immediately after this and
--    refines every one of these rows in the same boot.
SELECT set_config('app.tenant_id', '*', true);

INSERT INTO user_identity_state (user_id, tenant_id, state, reason)
SELECT u.id, u.tenant_id,
       CASE WHEN i.user_id IS NOT NULL THEN 'bound' ELSE 'unresolved' END,
       CASE WHEN i.user_id IS NOT NULL THEN '' ELSE 'pending-backfill' END
  FROM users u
  LEFT JOIN user_identities i ON i.user_id = u.id
 WHERE u.id <> ''
ON CONFLICT (user_id) DO NOTHING;
