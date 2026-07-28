-- 0013_rls_guc_rename.sql — rename the RLS session GUC app.current_tenant →
-- app.tenant_id (opaque-identity Phase 2, docs/design/tenant-id-migration-inventory.md).
--
-- The GUC ALREADY carries the canonical opaque tenant id (what principalTenant
-- returns), NOT the slug — so this is a CLARITY rename, not a semantic change. The
-- '*' platform-owner sentinel and the per-table tenant_id predicate are unchanged.
--
-- Every tenant_iso policy is recreated dynamically (one pass over pg_policies) so
-- this stays correct no matter which prior migrations created which policies — and
-- it skips a table whose tenant_iso policy doesn't exist yet (e.g. an optional
-- table from a not-yet-applied migration). Runs in this migration's own
-- transaction, so it is all-or-nothing: a partial rewrite can never leave the GUC
-- name split across tables (which would fail CLOSED — zero rows — never leak).
--
-- The application's withTenant (db.go) sets app.tenant_id from this migration on;
-- both ship in the same binary, so policy GUC and set_config name can't drift
-- across a deploy.

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT tablename
        FROM pg_policies
        WHERE schemaname = 'public' AND policyname = 'tenant_iso'
    LOOP
        EXECUTE format('DROP POLICY tenant_iso ON public.%I', r.tablename);
        EXECUTE format(
            'CREATE POLICY tenant_iso ON public.%I '
            || 'USING (current_setting(''app.tenant_id'', true) = ''*'' '
            || '    OR tenant_id = current_setting(''app.tenant_id'', true)) '
            || 'WITH CHECK (current_setting(''app.tenant_id'', true) = ''*'' '
            || '    OR tenant_id = current_setting(''app.tenant_id'', true))',
            r.tablename);
    END LOOP;
END $$;
