-- 0063_discovered_devices.sql — SNMP-discovered inventory survives a restart
-- (tracker 366; src/backend/internal/discovery/found_store_pg.go).
--
-- WHY. A device the SNMP subnet sweep found lived only in the scanner's memory
-- (SNMPSource.found). After an outage plus an api restart, every device that
-- was not answering at boot vanished from the inventory: its id, its tenant
-- attribution in device_tenant.csv and its topology node all went, and a
-- controller twin with a different id took its place — so the history and the
-- alerts of that device stopped lining up with anything. One row per device the
-- sweep has found lets the scanner start from what it knew, and age a device
-- out on evidence (missed sweeps, then a stale period) instead of on a reboot.
--
-- The scanner is the only writer. A device is never deleted for missing sweeps
-- alone: three missed sweeps mark it stale (stale_since), and only a device
-- stale for seven days is removed, and only by a sweep in which at least one
-- device answered (an all-silent sweep is an outage, not evidence).
--
-- ISOLATION: FORCE-RLS tenant_iso, the same predicate as every other tenant
-- table (0060). Discovered infrastructure is platform-scoped ('') until an
-- operator assigns it; writes run tenant-scoped per tenant group, so WITH CHECK
-- refuses a row filed under another tenant.
--
-- data is reserved for forward-compatible per-device fields; the scanner writes
-- back what it read, so a newer binary's fields survive an older one's rewrite.
CREATE TABLE IF NOT EXISTS discovered_devices (
    tenant_id      TEXT NOT NULL,
    source         TEXT NOT NULL,
    address        TEXT NOT NULL,
    device_id      TEXT NOT NULL,
    name           TEXT NOT NULL DEFAULT '',
    vendor         TEXT NOT NULL DEFAULT '',
    os             TEXT NOT NULL DEFAULT '',
    credential_ref TEXT NOT NULL DEFAULT '',
    first_found    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_answered  TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale_since    TIMESTAMPTZ,
    data           JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, source, address)
);

ALTER TABLE discovered_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovered_devices FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON discovered_devices;
CREATE POLICY tenant_iso ON discovered_devices
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
