-- 0021_incident_policy_single_enabled.sql — at most ONE enabled auto-ticketing
-- policy per (tenant, external system), enforced by the DATABASE.
--
-- Why (live incident 2026-07-10): a tenant held two enabled policies (a leftover
-- permissive validation policy + the operator's confirmed-only policy) and the
-- runtime resolver returned the first enabled row — the permissive policy
-- silently governed and flooded a real ServiceNow PDI with suspected-verdict
-- incidents. The HTTP write path now rejects a second enable with 409, but that
-- is check-then-write; this partial unique index closes the race and any
-- non-API write path for good.
--
-- The migration runner wraps this file in one transaction; SET LOCAL is
-- required because these tables are FORCE-RLS and the migration connection
-- carries no app.tenant_id — without '*' the dedupe UPDATE would silently
-- match zero rows and the index build would then fail on existing duplicates.
SET LOCAL app.tenant_id = '*';

-- Resolve pre-existing duplicates DETERMINISTICALLY, never destructively:
-- within each (tenant_id, external_system) scope keep the most recently
-- updated enabled policy (tie → highest id) and disable the rest. Nothing is
-- deleted; every demoted row keeps its configuration and shows the change in
-- updated_at. Deliberate choice over failing the migration: an install must
-- come up unattended, and "most recently updated wins" matches what the
-- operator last expressed intent about.
WITH ranked AS (
    SELECT tenant_id, id,
           row_number() OVER (PARTITION BY tenant_id, external_system
                              ORDER BY updated_at DESC, id DESC) AS rn
      FROM incident_policies
     WHERE enabled
)
UPDATE incident_policies p
   SET enabled = false, updated_at = now()
  FROM ranked r
 WHERE p.tenant_id = r.tenant_id AND p.id = r.id AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS incident_policies_one_enabled
    ON incident_policies (tenant_id, external_system)
 WHERE enabled;
