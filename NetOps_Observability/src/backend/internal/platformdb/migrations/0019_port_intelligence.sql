-- 0019_port_intelligence.sql — Port Intelligence / physical-layer observability
-- (#94, design docs/design/port-intelligence.md, P2 storage).
--
-- Seven relational "current-state" models for the SP/DC optics workbench. The
-- CARDINALITY LAW (owner): identity fields that would blow up a TSDB label set
-- — serials, part numbers, panel/circuit ids, path components — live HERE in
-- relational storage; rapidly-changing numerics (RX/TX power, BER, temps) live
-- in the time-series plane, keyed by the stable (device, port) pair only. So
-- these tables hold the slow-moving inventory + latest-snapshot rows; the fast
-- numerics are referenced, not duplicated.
--
-- Each row carries the canonical typed columns for filtering/joins; the lossless
-- record rides in JSONB `data` (same pattern as topology_nodes / saved_objects)
-- so a reader never reconstructs a row from columns and a new field never needs
-- a migration. Every table is tenant-isolated by the tenant_iso FORCE-RLS
-- policy (identical predicate to every other tenant table; '' = platform/
-- untagged discovery, '*' = cross-tenant reader). All idempotent.

-- 1. Physical port inventory (current snapshot).
CREATE TABLE IF NOT EXISTS port_inventory_current (
    tenant_id     TEXT NOT NULL DEFAULT '',
    device_id     TEXT NOT NULL,
    port_id       TEXT NOT NULL,                     -- stable: device_id + ifName
    if_index      BIGINT NOT NULL DEFAULT 0,
    if_name       TEXT NOT NULL DEFAULT '',
    if_alias      TEXT NOT NULL DEFAULT '',
    admin_status  TEXT NOT NULL DEFAULT '',          -- up | down | testing
    oper_status   TEXT NOT NULL DEFAULT '',
    speed_bps     BIGINT NOT NULL DEFAULT 0,         -- ifHighSpeed * 1e6
    role          TEXT NOT NULL DEFAULT '',          -- access | fabric | wan | handoff | …
    seam          TEXT NOT NULL DEFAULT '',          -- DIA | SDWAN | VPN | DX | CLOUD_BACKBONE | ''
    lag_id        TEXT NOT NULL DEFAULT '',
    parent_port   TEXT NOT NULL DEFAULT '',          -- breakout parent ('' = physical)
    breakout_group TEXT NOT NULL DEFAULT '',
    last_change   TIMESTAMPTZ,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale         BOOLEAN NOT NULL DEFAULT false,
    data          JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, device_id, port_id)
);
CREATE INDEX IF NOT EXISTS port_inventory_tenant_idx ON port_inventory_current (tenant_id);
CREATE INDEX IF NOT EXISTS port_inventory_device_idx ON port_inventory_current (tenant_id, device_id);

-- 2. Transceiver inventory (identity — the high-cardinality fields that must
--    NEVER be TSDB labels: serial/part/rev).
CREATE TABLE IF NOT EXISTS transceiver_inventory_current (
    tenant_id       TEXT NOT NULL DEFAULT '',
    device_id       TEXT NOT NULL,
    port_id         TEXT NOT NULL,
    present         BOOLEAN NOT NULL DEFAULT false,
    form_factor     TEXT NOT NULL DEFAULT '',        -- SFP28 | QSFP-DD | OSFP | …
    module_type     TEXT NOT NULL DEFAULT '',
    media_type      TEXT NOT NULL DEFAULT '',        -- copper | multimode_fiber | singlemode_fiber | dac | aoc | coherent | unknown
    optic_pmd       TEXT NOT NULL DEFAULT '',        -- SR4 | LR4 | DR4 | ZR | …
    connector_type  TEXT NOT NULL DEFAULT '',        -- LC | MPO-12 | RJ45 | …
    vendor_name     TEXT NOT NULL DEFAULT '',
    vendor_oui      TEXT NOT NULL DEFAULT '',
    part_number     TEXT NOT NULL DEFAULT '',
    serial_number   TEXT NOT NULL DEFAULT '',
    revision        TEXT NOT NULL DEFAULT '',
    firmware        TEXT NOT NULL DEFAULT '',
    wavelength_nm   DOUBLE PRECISION NOT NULL DEFAULT 0,
    reach_m         BIGINT NOT NULL DEFAULT 0,
    lane_count      INT NOT NULL DEFAULT 0,
    supported_status TEXT NOT NULL DEFAULT 'unknown', -- supported | third_party | unsupported | unknown
    cmis_version    TEXT NOT NULL DEFAULT '',
    inserted_at     TIMESTAMPTZ,
    last_changed_at TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    data            JSONB NOT NULL DEFAULT '{}'::jsonb,  -- full CMIS/EEPROM-derived record (raw EEPROM suppressed from APIs)
    PRIMARY KEY (tenant_id, device_id, port_id)
);
CREATE INDEX IF NOT EXISTS transceiver_inv_tenant_idx ON transceiver_inventory_current (tenant_id);
CREATE INDEX IF NOT EXISTS transceiver_inv_serial_idx ON transceiver_inventory_current (tenant_id, serial_number);

-- 3. Per-lane current snapshot (latest values; time-series carries the history).
CREATE TABLE IF NOT EXISTS port_lane_current (
    tenant_id       TEXT NOT NULL DEFAULT '',
    device_id       TEXT NOT NULL,
    port_id         TEXT NOT NULL,
    lane_id         INT NOT NULL,
    lane_state      TEXT NOT NULL DEFAULT '',
    lock_status     TEXT NOT NULL DEFAULT '',
    alarm_status    TEXT NOT NULL DEFAULT '',
    rx_power_dbm    DOUBLE PRECISION,
    tx_power_dbm    DOUBLE PRECISION,
    tx_bias_ma      DOUBLE PRECISION,
    temperature_c   DOUBLE PRECISION,
    pre_fec_ber     DOUBLE PRECISION,
    post_fec_ber    DOUBLE PRECISION,
    snr             DOUBLE PRECISION,
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    data            JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, device_id, port_id, lane_id)
);
CREATE INDEX IF NOT EXISTS port_lane_tenant_idx ON port_lane_current (tenant_id);
CREATE INDEX IF NOT EXISTS port_lane_port_idx ON port_lane_current (tenant_id, device_id, port_id);

-- 4. Fiber-path inventory (panel/cassette/jumper/circuit — pure relational,
--    the physical documentation spine the MPO/fiber signatures ground against).
CREATE TABLE IF NOT EXISTS fiber_path_inventory (
    tenant_id       TEXT NOT NULL DEFAULT '',
    path_id         TEXT NOT NULL,
    a_device_id     TEXT NOT NULL DEFAULT '',
    a_port_id       TEXT NOT NULL DEFAULT '',
    z_device_id     TEXT NOT NULL DEFAULT '',
    z_port_id       TEXT NOT NULL DEFAULT '',
    circuit_id      TEXT NOT NULL DEFAULT '',
    provider        TEXT NOT NULL DEFAULT '',
    polarity_method TEXT NOT NULL DEFAULT '',        -- A | B | C
    connector_gender TEXT NOT NULL DEFAULT '',
    panel_id        TEXT NOT NULL DEFAULT '',
    cassette_id     TEXT NOT NULL DEFAULT '',
    jumper_id       TEXT NOT NULL DEFAULT '',
    mux_demux_id    TEXT NOT NULL DEFAULT '',
    amplifier_id    TEXT NOT NULL DEFAULT '',
    budget_db       DOUBLE PRECISION NOT NULL DEFAULT 0,
    rack_id         TEXT NOT NULL DEFAULT '',
    row_id          TEXT NOT NULL DEFAULT '',
    site            TEXT NOT NULL DEFAULT '',
    data            JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, path_id)
);
CREATE INDEX IF NOT EXISTS fiber_path_tenant_idx ON fiber_path_inventory (tenant_id);
CREATE INDEX IF NOT EXISTS fiber_path_circuit_idx ON fiber_path_inventory (tenant_id, circuit_id);

-- 5. Neighbor (LLDP-discovered) current, for cross-connect/label-drift grounding.
CREATE TABLE IF NOT EXISTS port_neighbor_current (
    tenant_id           TEXT NOT NULL DEFAULT '',
    device_id           TEXT NOT NULL,
    port_id             TEXT NOT NULL,
    remote_system_name  TEXT NOT NULL DEFAULT '',
    remote_port_id      TEXT NOT NULL DEFAULT '',
    remote_port_desc    TEXT NOT NULL DEFAULT '',
    neighbor_device_id  TEXT NOT NULL DEFAULT '',
    topology_edge_id    TEXT NOT NULL DEFAULT '',
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    data                JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, device_id, port_id)
);
CREATE INDEX IF NOT EXISTS port_neighbor_tenant_idx ON port_neighbor_current (tenant_id);

-- 6. Port event log (insert/remove/link/threshold — from syslog/traps).
CREATE TABLE IF NOT EXISTS port_event_log (
    tenant_id    TEXT NOT NULL DEFAULT '',
    id           BIGSERIAL,
    device_id    TEXT NOT NULL DEFAULT '',
    port_id      TEXT NOT NULL DEFAULT '',
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type   TEXT NOT NULL DEFAULT '',           -- insert | remove | link_up | link_down | threshold | fault
    severity     TEXT NOT NULL DEFAULT '',
    summary      TEXT NOT NULL DEFAULT '',
    data         JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS port_event_tenant_idx ON port_event_log (tenant_id);
CREATE INDEX IF NOT EXISTS port_event_port_idx ON port_event_log (tenant_id, device_id, port_id, ts DESC);

-- 7. Port health (current) — the deterministic scorer's output (P4) + dominant
--    issue + matched signature reference for the RCA-Evidence drawer section.
CREATE TABLE IF NOT EXISTS port_health_current (
    tenant_id           TEXT NOT NULL DEFAULT '',
    device_id           TEXT NOT NULL,
    port_id             TEXT NOT NULL,
    health_score        INT NOT NULL DEFAULT 100,    -- 0-100 (100 = clean)
    health_state        TEXT NOT NULL DEFAULT 'ok',  -- ok | watch | degraded | critical
    dominant_issue      TEXT NOT NULL DEFAULT '',
    matched_signature   TEXT NOT NULL DEFAULT '',    -- sig.ent.spdc.* id
    correlation_id      TEXT NOT NULL DEFAULT '',    -- linked RCA object, if attached
    next_check          TEXT NOT NULL DEFAULT '',
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    data                JSONB NOT NULL DEFAULT '{}'::jsonb,  -- per-dimension score contributions
    PRIMARY KEY (tenant_id, device_id, port_id)
);
CREATE INDEX IF NOT EXISTS port_health_tenant_idx ON port_health_current (tenant_id);
CREATE INDEX IF NOT EXISTS port_health_state_idx ON port_health_current (tenant_id, health_state);

-- RLS: tenant_iso on all seven (identical predicate to every other tenant table;
-- FORCE so even the table owner is bound). '*' = platform cross-tenant reader.
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'port_inventory_current','transceiver_inventory_current','port_lane_current',
        'fiber_path_inventory','port_neighbor_current','port_event_log','port_health_current'
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
