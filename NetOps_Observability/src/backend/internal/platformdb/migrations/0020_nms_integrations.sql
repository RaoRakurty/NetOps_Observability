-- 0020_nms_integrations.sql — NMS / vendor-controller integration framework
-- (design docs/design/nms-integration-framework.md, P1 storage).
--
-- Config + controller STATE (relational, slow-moving) for the vendor-controller
-- intelligence framework. The other two signal classes do NOT live here:
-- controller_metric rides VictoriaMetrics (the metric-events lane) and
-- controller_event rides the ClickHouse/Redpanda evidence path — only the
-- current-state snapshot (§3.2, with flap history) is relational.
--
-- Credentials store NO plaintext: integration_credentials_metadata records only
-- which secret fields are set + the Vault reference; the ciphertext lives in the
-- existing envelope Vault (per-tenant DEK), same as SNMP creds.
--
-- Every table is tenant-isolated by the tenant_iso FORCE-RLS policy (identical
-- predicate to every other tenant table; '' = platform/untagged, '*' =
-- cross-tenant reader). Lossless record rides in JSONB `data`. All idempotent.

-- 1. Integration instances (one per configured vendor controller per tenant).
CREATE TABLE IF NOT EXISTS integrations (
    tenant_id       TEXT NOT NULL,
    integration_id  TEXT NOT NULL,
    vendor          TEXT NOT NULL,   -- meraki | catalyst_center | vmanage | ndfc | versa_director | versa_concerto | prime | generic
    product         TEXT NOT NULL DEFAULT '',
    display_name    TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    base_url        TEXT NOT NULL DEFAULT '',
    auth_type       TEXT NOT NULL DEFAULT '', -- api_key | token | session | basic | oauth
    poll_interval_s INTEGER NOT NULL DEFAULT 300,
    data_sources    TEXT[] NOT NULL DEFAULT '{}', -- alarms|inventory|topology|audit|tunnel_status|health_scores|metrics|state
    data            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, integration_id)
);
CREATE INDEX IF NOT EXISTS integrations_vendor_idx ON integrations (tenant_id, vendor);

-- 2. Credential metadata — references only, NEVER plaintext secrets.
CREATE TABLE IF NOT EXISTS integration_credentials_metadata (
    tenant_id      TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    vault_ref      TEXT NOT NULL DEFAULT '', -- path/handle into the envelope Vault
    fields_set     TEXT[] NOT NULL DEFAULT '{}', -- which secret fields are populated (api_key, password, client_secret, …)
    rotated_at     TIMESTAMPTZ,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, integration_id)
);

-- 3. Poll checkpoints (resume cursor per integration+stream).
CREATE TABLE IF NOT EXISTS connector_checkpoints (
    tenant_id        TEXT NOT NULL,
    integration_id   TEXT NOT NULL,
    stream           TEXT NOT NULL,   -- alarms | events | inventory | tunnels | ...
    last_event_time  TIMESTAMPTZ,
    last_seq         BIGINT NOT NULL DEFAULT 0,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, integration_id, stream)
);

-- 4. Connector health (latest snapshot).
CREATE TABLE IF NOT EXISTS connector_health (
    tenant_id        TEXT NOT NULL,
    integration_id   TEXT NOT NULL,
    healthy          BOOLEAN NOT NULL DEFAULT FALSE,
    last_success     TIMESTAMPTZ,
    last_error       TEXT NOT NULL DEFAULT '',
    last_error_at    TIMESTAMPTZ,
    events_ingested  BIGINT NOT NULL DEFAULT 0,
    error_rate       DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, integration_id)
);

-- 5. Connector run history (bounded; one row per poll/backfill run).
CREATE TABLE IF NOT EXISTS connector_run_history (
    tenant_id      TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    run_id         TEXT NOT NULL,
    started_at     TIMESTAMPTZ NOT NULL,
    finished_at    TIMESTAMPTZ,
    status         TEXT NOT NULL DEFAULT 'running', -- running | ok | error
    events         BIGINT NOT NULL DEFAULT 0,
    error          TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, integration_id, run_id)
);
CREATE INDEX IF NOT EXISTS run_history_recent_idx ON connector_run_history (tenant_id, integration_id, started_at DESC);

-- 6. Controller state (current snapshot with flap history — §3.2).
CREATE TABLE IF NOT EXISTS controller_state_current (
    tenant_id      TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    entity_key     TEXT NOT NULL,   -- normalized entity id (device/tunnel/peer/interface/…)
    state_kind     TEXT NOT NULL,   -- bfd | omp | control_conn | tunnel | bgp | reachability | intf_oper | deploy | fabric_node
    current_state  TEXT NOT NULL,
    previous_state TEXT NOT NULL DEFAULT '',
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    flap_count     BIGINT NOT NULL DEFAULT 0,
    device_id      TEXT NOT NULL DEFAULT '',
    site_id        TEXT NOT NULL DEFAULT '',
    data           JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, integration_id, entity_key, state_kind)
);
CREATE INDEX IF NOT EXISTS controller_state_kind_idx ON controller_state_current (tenant_id, state_kind, current_state);

-- RLS: tenant_iso on all six (identical predicate to every other tenant table;
-- FORCE so even the table owner is bound). '*' = platform cross-tenant reader.
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'integrations','integration_credentials_metadata','connector_checkpoints',
        'connector_health','connector_run_history','controller_state_current'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_iso ON %I', t);
        EXECUTE format($f$CREATE POLICY tenant_iso ON %I
            USING (current_setting('app.tenant_id', true) = '*'
                OR tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (current_setting('app.tenant_id', true) = '*'
                OR tenant_id = current_setting('app.tenant_id', true))$f$, t);
    END LOOP;
END $$;
