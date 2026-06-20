-- 0012_topology.sql — Persistent topology graph (#77). Until now the topology
-- canvas recomputed an ephemeral projection from Redis (FetchTopologyLinks) +
-- inventory on every request, so it had no MEMORY: ids weren't stable across
-- requests, adjacencies that stopped being observed simply vanished, and there
-- was nowhere to anchor an RCA overlay. These two tables give the graph a
-- persistent spine: a background reconciler (single writer) folds the live
-- observed set in, preserving first_seen, advancing last_seen, and marking
-- last-not-observed rows STALE (kept, not deleted — honesty: "was here, not seen
-- now" beats a silent disappearance). The canonical structural fields live in
-- typed columns; the lossless record is carried in JSONB `data` (same pattern as
-- saved_objects), so a reader never has to reconstruct a row from columns.
--
-- Tenant-isolated like every other tenant table: tenant_id is denormalized onto
-- both tables (an edge's tenant = its source device's tenant) and guarded by the
-- tenant_iso FORCE-RLS policy, so a scoped reader can never see another tenant's
-- topology. '' is the global/platform-owned namespace (untagged discovery).

CREATE TABLE IF NOT EXISTS topology_nodes (
    tenant_id   TEXT NOT NULL DEFAULT '',
    id          TEXT NOT NULL,                       -- stable node id (= device id)
    label       TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL DEFAULT 'unresolved',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale       BOOLEAN NOT NULL DEFAULT false,
    data        JSONB NOT NULL DEFAULT '{}'::jsonb,  -- lossless topology.NodeRecord
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS topology_nodes_tenant_idx ON topology_nodes (tenant_id);

CREATE TABLE IF NOT EXISTS topology_edges (
    tenant_id   TEXT NOT NULL DEFAULT '',
    id          TEXT NOT NULL,                       -- stable, deterministic edge id
    source      TEXT NOT NULL DEFAULT '',
    target      TEXT NOT NULL DEFAULT '',
    protocol    TEXT NOT NULL DEFAULT '',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale       BOOLEAN NOT NULL DEFAULT false,
    data        JSONB NOT NULL DEFAULT '{}'::jsonb,  -- lossless topology.EdgeRecord
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS topology_edges_tenant_idx ON topology_edges (tenant_id);

-- RLS: tenant_iso on both ('*' = platform cross-tenant; FORCE so even the table
-- owner is bound). Identical predicate to every other tenant table.
ALTER TABLE topology_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE topology_nodes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON topology_nodes;
CREATE POLICY tenant_iso ON topology_nodes
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE topology_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE topology_edges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON topology_edges;
CREATE POLICY tenant_iso ON topology_edges
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
