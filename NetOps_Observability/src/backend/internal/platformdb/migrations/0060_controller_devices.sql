-- 0060_controller_devices.sql — controller-sourced inventory (owner
-- 2026-10-19; src/backend/nms/inventory.go).
--
-- One row per device a controller integration reports (vManage edges today;
-- Meraki, Catalyst Center, NDFC, Versa and Prime plug in later), keyed by the
-- controller's own key for it. The discovery source turns these rows into the
-- tenant's inventory devices.
--
-- ISOLATION: FORCE-RLS tenant_iso, the same predicate as every other tenant
-- table. tenant_id is the INTEGRATION's owner, stamped by the runtime; writes
-- run tenant-scoped, so WITH CHECK refuses a row filed under another tenant.
--
-- PRUNING: a complete snapshot marks the rows it no longer lists absent
-- (absent_since); they are deleted after a grace period, so one bad poll never
-- removes a device. An empty or incomplete snapshot deletes nothing.
CREATE TABLE IF NOT EXISTS controller_devices (
    tenant_id      TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    device_key     TEXT NOT NULL,
    key_kind       TEXT NOT NULL,
    source_system  TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL DEFAULT '',
    mgmt_addr      TEXT NOT NULL DEFAULT '',
    serial         TEXT NOT NULL DEFAULT '',
    vendor         TEXT NOT NULL DEFAULT '',
    model          TEXT NOT NULL DEFAULT '',
    os             TEXT NOT NULL DEFAULT '',
    os_version     TEXT NOT NULL DEFAULT '',
    site_id        TEXT NOT NULL DEFAULT '',
    site_name      TEXT NOT NULL DEFAULT '',
    role           TEXT NOT NULL DEFAULT '',
    managed        BOOLEAN NOT NULL DEFAULT FALSE,
    reachable      TEXT NOT NULL DEFAULT '',
    aliases        JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    absent_since   TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, integration_id, device_key)
);
CREATE INDEX IF NOT EXISTS controller_devices_integration_idx ON controller_devices (tenant_id, integration_id);

ALTER TABLE controller_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE controller_devices FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON controller_devices;
CREATE POLICY tenant_iso ON controller_devices
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
