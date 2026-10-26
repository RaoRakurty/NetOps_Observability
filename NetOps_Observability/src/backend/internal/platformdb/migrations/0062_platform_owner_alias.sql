-- 0062_platform_owner_alias.sql — the Provider scope reads the platform's own
-- rows in BOTH spellings (tracker 365).
--
-- The platform realm has two spellings of one owner (internal/owner): '' (rows
-- written for untagged / discovered infrastructure, and by system writers that
-- never resolved an owner) and 'global' (what the Provider scope stamps). Until
-- 365 the platform owner only ever read these tables cross-tenant ('*'), so the
-- split was invisible. Selecting "Provider" now scopes the session to 'global'
-- (non-cross), and tenant_iso alone would hide every '' row from it: the
-- Provider's own incidents, seams, topology and config history would vanish.
--
-- WHAT THIS ADDS: one PERMISSIVE policy, platform_alias, OR'd with tenant_iso
-- (PostgreSQL combines permissive policies with OR). It admits exactly one
-- extra pair: session scope 'global' AND row tenant_id ''. Nothing else moves:
--   * a tenant scope ('t_…') matches neither clause — it still sees only its own
--     rows (tenant_iso), never a '' or 'global' row;
--   * '*' (cross-tenant) already sees everything through tenant_iso;
--   * WITH CHECK is the same predicate, so a 'global' session may write a ''
--     row (it is its own) but can never file a row under a real tenant.
--
-- EXPLICIT ALLOWLIST — data tables only, each verified to carry tenant_id and a
-- tenant_iso policy (the DO block refuses to run otherwise). The lab audit
-- (2026-10-25) found '' platform rows in incidents, incident_events, seams,
-- seam_groups, topology_nodes, config_backup_versions, config_drift_state and
-- metering_daily; topology_edges travels with topology_nodes (one writer), and
-- saved_objects matches the app-layer saved-object rule (rbac ResSaved compares
-- by owner).
--
-- NEVER on an identity or credential table — users, user_identities,
-- user_identity_state, api_keys, snmp_credentials, sessions, contact points,
-- integration credentials, tenants. There a '' row is the platform owner's own
-- account class, and aliasing it into the Provider TENANT would let a
-- non-owner admin bound to Provider reach the platform owner's account: a
-- privilege escalation, not a convenience. platform_alias_test (pgintegration)
-- pins that a '' users row stays invisible under 'global'.
--
-- Idempotent (DROP POLICY IF EXISTS first). Rollback:
-- rollback/0062_platform_owner_alias.down.sql.
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'incidents',
        'incident_events',
        'seams',
        'seam_groups',
        'topology_nodes',
        'topology_edges',
        'config_backup_versions',
        'config_drift_state',
        'metering_daily',
        'saved_objects'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = t AND column_name = 'tenant_id'
        ) THEN
            RAISE EXCEPTION '0062: % has no tenant_id column — refusing to alias it', t;
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE schemaname = 'public' AND tablename = t AND policyname = 'tenant_iso'
        ) THEN
            RAISE EXCEPTION '0062: % has no tenant_iso policy — refusing to alias it', t;
        END IF;
        EXECUTE format('DROP POLICY IF EXISTS platform_alias ON public.%I', t);
        EXECUTE format(
            'CREATE POLICY platform_alias ON public.%I AS PERMISSIVE '
            || 'USING (current_setting(''app.tenant_id'', true) = ''global'' AND tenant_id = '''') '
            || 'WITH CHECK (current_setting(''app.tenant_id'', true) = ''global'' AND tenant_id = '''')',
            t);
    END LOOP;
END $$;
