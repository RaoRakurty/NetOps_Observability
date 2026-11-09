-- 0065_iris_source_authority.sql — configurable source authority (tracker 337
-- N-F6, docs/architecture/iris-natural-language-platform.md §4.2.1).
--
-- One row per tenant: the order in which Iris believes the sources that report
-- the same device (controller, discovered, declared, manual). No row = the
-- platform default (owner 2026-11-09: controller-observed > SNMP-discovered >
-- manually entered), which lives in code, not here.
--
-- The order must be a PERMUTATION of the four classes — exactly four entries,
-- every class present (both containments), so no duplicate and nothing else —
-- enforced by the database too, so a row written around the application still
-- cannot hold an undefined order.
--
-- ISOLATION: FORCE-RLS tenant_iso.
--
-- Rollback: rollback/0065_iris_source_authority.down.sql.

CREATE TABLE IF NOT EXISTS iris_source_authority (
    tenant_id    TEXT PRIMARY KEY CHECK (tenant_id <> ''),
    source_order TEXT[] NOT NULL CHECK (
        cardinality(source_order) = 4
        AND source_order <@ ARRAY['controller', 'discovered', 'declared', 'manual']::text[]
        AND ARRAY['controller', 'discovered', 'declared', 'manual']::text[] <@ source_order),
    updated_by   TEXT NOT NULL CHECK (updated_by <> '' AND octet_length(updated_by) <= 256),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE iris_source_authority ENABLE ROW LEVEL SECURITY;
ALTER TABLE iris_source_authority FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON iris_source_authority;
CREATE POLICY tenant_iso ON iris_source_authority
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
