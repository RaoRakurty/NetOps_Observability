-- 0049_user_identities.sql — the CANONICAL IDENTITY of a principal
-- (tracker 300, docs/design/IDENTITY_NAMESPACING_2026-09-13.md §2.2; owner
-- decision 2026-09-13). EXPAND step: additive, idempotent, and readable by the
-- previous api release, which simply never queries it.
--
-- WHAT THIS TABLE IS FOR. Before it, `users.id` was lower(username) and the
-- username was the SOLE, GLOBAL, case-insensitive identity key. Every door wrote
-- into that one key: the OIDC callback derived a username from
-- preferred_username/email/sub and threw the verified `iss` and `sub` away, LDAP
-- threw the DN away, TACACS+ had nothing else. So identity WAS username-based
-- auto-linking across whatever happened to assert it: two different directories
-- handing out the same login name landed on ONE account, and no tenant could own
-- its own `admin`.
--
-- The owner's binding rules (design §0): canonical identity is
-- tenant_id + issuer + subject; the uniqueness is enforced AT THE DATABASE, not
-- only in code; local auth is its own issuer namespace; and there is NO email- or
-- username-based auto-linking across issuers, ever.
--
-- WHY UNIQUE (user_id) IS THE IMPORTANT LINE. It is the database-level form of
-- "no auto-linking": a second identity cannot be attached to an existing account
-- by ANY code path, including one nobody has written yet. A future explicit
-- linking ceremony (SSO design §15, deferred) would have to relax it
-- deliberately, in its own migration, under review — which is exactly the
-- property we want.
--
-- SUBJECT SEMANTICS (design §2.3), recorded here because the column cannot say
-- it: local = lower(trim(username)); OIDC/bearer = the verified `sub` VERBATIM
-- (the spec makes it case-sensitive, so folding it could fuse two principals);
-- LDAP = lower(DN) when the directory returned one, else lower(login name), with
-- which one recorded in `subject_kind` so a later DN-vs-login policy change is
-- visible rather than silent; TACACS+ = lower(login name). preferred_username and
-- email are PROFILE attributes refreshed on login and are never keys.
--
-- provenance is the audit trail rule 6 demands: 'asserted' (a door verified this
-- tuple), 'backfilled-local' (migration 0050 derived it offline from a LOCAL
-- account, which is the only case where offline derivation is certain), or
-- 'legacy-lazy-bound' (the single bounded §2.6 exception: a pre-migration
-- federated account adopted once, by the same door that created it). Nothing is
-- ever guessed, and an ambiguous legacy row stays PENDING — no identity row —
-- for an operator to remediate.
--
-- RLS: tenant_iso, FORCE, with the SAME policy text as `users` (the
-- app.tenant_id GUC that migration 0013 standardised). An identity is a fact
-- about one customer's principal, so the platform-owner scope ('*') is the only
-- way to read across tenants — which is what login needs before any tenant
-- context exists, and is why the store's resolve paths run at '*' and authorize
-- afterwards.

CREATE TABLE IF NOT EXISTS user_identities (
    tenant_id     TEXT NOT NULL DEFAULT '',
    issuer        TEXT NOT NULL CHECK (issuer <> ''),
    subject       TEXT NOT NULL CHECK (subject <> ''),
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    protocol      TEXT NOT NULL CHECK (protocol <> ''),   -- local | oidc | saml | ldap | tacacs
    connection_id TEXT NOT NULL DEFAULT '',               -- ssoidp alias ("" = platform/legacy global)
    subject_kind  TEXT NOT NULL DEFAULT ''                -- dn | login | '' (LDAP only)
        CHECK (subject_kind IN ('', 'dn', 'login')),
    provenance    TEXT NOT NULL
        CHECK (provenance IN ('asserted', 'backfilled-local', 'legacy-lazy-bound')),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, issuer, subject),   -- rule 2, enforced at the DB
    UNIQUE (user_id)                            -- rule 4: exactly ONE identity per user
);

-- The PK already covers (tenant_id, issuer, subject); this index serves the
-- reverse direction (given an account, what is its identity) and the UNBOUND
-- lookup by (issuer, subject) that the single platform LDAP/TACACS+/bearer
-- configuration needs.
CREATE INDEX IF NOT EXISTS user_identities_user_idx ON user_identities (user_id);
CREATE INDEX IF NOT EXISTS user_identities_issuer_subject_idx ON user_identities (issuer, subject);

ALTER TABLE user_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_identities FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON user_identities;
CREATE POLICY tenant_iso ON user_identities
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

-- The MIGRATION EPOCH (design §2.6 condition 3). A pre-migration federated
-- account may be adopted by the bounded lazy bind; an account created AFTER the
-- migration never may, because it was created by code that already records its
-- identity. The row is written ONCE, by 0050, with ON CONFLICT DO NOTHING: if a
-- re-run could move the epoch forward it would silently widen the adoption
-- window to every account created since, which is precisely the kind of
-- "idempotent" that is not.
--
-- The schema is created here (expand) and the row is written in 0050 (backfill),
-- so the two steps stay separable. No tenant_id and therefore no RLS: this is
-- platform-global plumbing, one row for the whole deployment, and it holds no
-- customer data — the same shape as schema_migrations.
CREATE TABLE IF NOT EXISTS identity_migration (
    singleton  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
