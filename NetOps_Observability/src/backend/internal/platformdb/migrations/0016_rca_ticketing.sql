-- 0016_rca_ticketing.sql — RCA-driven auto-ticketing data model (#78). The
-- correlation engine produces ONE RCA correlation object per incident; this
-- feature opens/updates ONE external ticket from that object (never one ticket
-- per raw alert). These four tables are the persistent spine:
--
--   incident_policies      — WHEN to ticket (per tenant, per external system).
--   correlix_ticket_links  — the RCA object ↔ external ticket binding (the dedupe
--                            anchor: one row per (tenant, corr_object, system)).
--   ticket_outbox          — reliable async actions so ticketing NEVER blocks
--                            correlation (SKIP LOCKED worker, retry, dead_letter).
--   ticket_audit_log       — every action, for the compliance trail.
--
-- The ServiceNow CONNECTION (instance_url, creds, field mapping) is NOT added
-- here — it reuses the existing integration control plane (integration_configs /
-- itsm_config); P2 extends that, keeping this migration to the net-new ticketing
-- tables only.
--
-- Tenant-isolated like every other tenant table: tenant_id is denormalized onto
-- all four and guarded by the tenant_iso FORCE-RLS policy on the app.tenant_id
-- GUC (the post-0013 name). '' is the global/platform-owned namespace. Tickets
-- are wired to corr_object_id, never raw alert ids.

-- ── incident_policies — ticket-worthiness rules ──────────────────────────────
CREATE TABLE IF NOT EXISTS incident_policies (
    tenant_id                   TEXT NOT NULL DEFAULT '',
    id                          TEXT NOT NULL,
    name                        TEXT NOT NULL DEFAULT '',
    external_system             TEXT NOT NULL DEFAULT 'servicenow',
    enabled                     BOOLEAN NOT NULL DEFAULT true,
    min_verdict                 TEXT NOT NULL DEFAULT 'suspected',  -- suspected | confirmed
    require_customer_facing     BOOLEAN NOT NULL DEFAULT true,
    allow_probe_only            BOOLEAN NOT NULL DEFAULT false,
    allow_internal_monitoring   BOOLEAN NOT NULL DEFAULT false,
    suspected_requires_critical BOOLEAN NOT NULL DEFAULT true,
    require_persistence_seconds INTEGER NOT NULL DEFAULT 0,
    suppress_flapping_seconds   INTEGER NOT NULL DEFAULT 0,
    assignment_group            TEXT NOT NULL DEFAULT '',
    default_impact              INTEGER NOT NULL DEFAULT 2,
    default_urgency             INTEGER NOT NULL DEFAULT 2,
    filters                     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS incident_policies_tenant_idx ON incident_policies (tenant_id);

-- ── correlix_ticket_links — RCA object ↔ external ticket ─────────────────────
-- One row per (tenant, corr_object, external_system): the dedupe anchor that
-- guarantees we never open a second active ticket for the same RCA object.
CREATE TABLE IF NOT EXISTS correlix_ticket_links (
    tenant_id         TEXT NOT NULL DEFAULT '',
    corr_object_id    TEXT NOT NULL,
    external_system   TEXT NOT NULL DEFAULT 'servicenow',
    instance_url      TEXT NOT NULL DEFAULT '',
    ticket_number     TEXT NOT NULL DEFAULT '',
    sys_id            TEXT NOT NULL DEFAULT '',
    dedupe_key        TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'pending',  -- pending|open|updated|resolved|failed
    last_verdict      TEXT NOT NULL DEFAULT '',
    last_confidence   DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_payload_hash TEXT NOT NULL DEFAULT '',
    last_synced_at    TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, corr_object_id, external_system)
);
CREATE INDEX IF NOT EXISTS correlix_ticket_links_tenant_idx ON correlix_ticket_links (tenant_id);

-- ── ticket_outbox — reliable async actions (never blocks correlation) ────────
CREATE TABLE IF NOT EXISTS ticket_outbox (
    tenant_id       TEXT NOT NULL DEFAULT '',
    id              TEXT NOT NULL,
    corr_object_id  TEXT NOT NULL,
    external_system TEXT NOT NULL DEFAULT 'servicenow',
    action          TEXT NOT NULL,  -- create|update|add_work_note|resolve|reopen
    idempotency_key TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending|sent|failed|retrying|dead_letter
    retry_count     INTEGER NOT NULL DEFAULT 0,
    max_retries     INTEGER NOT NULL DEFAULT 8,
    next_retry_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);
-- idempotency_key embeds the tenant + corr_object + action(+hash), so it is
-- globally unique by construction — a UNIQUE index makes the at-most-once
-- guarantee a hard constraint the worker can ON CONFLICT DO NOTHING against.
CREATE UNIQUE INDEX IF NOT EXISTS ticket_outbox_idem_idx ON ticket_outbox (idempotency_key);
-- The SKIP LOCKED worker polls due work by (status, next_retry_at).
CREATE INDEX IF NOT EXISTS ticket_outbox_due_idx ON ticket_outbox (status, next_retry_at);

-- ── ticket_audit_log — compliance trail of every action ──────────────────────
CREATE TABLE IF NOT EXISTS ticket_audit_log (
    tenant_id       TEXT NOT NULL DEFAULT '',
    id              TEXT NOT NULL,
    corr_object_id  TEXT NOT NULL DEFAULT '',
    external_system TEXT NOT NULL DEFAULT 'servicenow',
    action          TEXT NOT NULL DEFAULT '',
    actor           TEXT NOT NULL DEFAULT 'system',  -- system | user:<id>
    old_status      TEXT NOT NULL DEFAULT '',
    new_status      TEXT NOT NULL DEFAULT '',
    payload_hash    TEXT NOT NULL DEFAULT '',
    result          TEXT NOT NULL DEFAULT '',
    error           TEXT NOT NULL DEFAULT '',
    at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS ticket_audit_corr_idx ON ticket_audit_log (tenant_id, corr_object_id, at);

-- ── RLS: tenant_iso on all four (identical predicate to every other tenant
-- table; '*' = platform cross-tenant; FORCE so even the table owner is bound) ──
ALTER TABLE incident_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON incident_policies;
CREATE POLICY tenant_iso ON incident_policies
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE correlix_ticket_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlix_ticket_links FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON correlix_ticket_links;
CREATE POLICY tenant_iso ON correlix_ticket_links
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE ticket_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON ticket_outbox;
CREATE POLICY tenant_iso ON ticket_outbox
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE ticket_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket_audit_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON ticket_audit_log;
CREATE POLICY tenant_iso ON ticket_audit_log
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
