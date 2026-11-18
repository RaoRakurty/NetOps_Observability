-- 0079_device_baselines.sql — before/after change baselines for one device
-- (Iris change assistance, 2026-11-18). An operator asks Iris to take a
-- baseline of a device before a change; afterwards Iris compares a fresh read
-- against it: interfaces, routing neighbours, routing-table size, software
-- version and overlay sessions — what came back and what did not.
--
-- A baseline is read with the read-only state battery; nothing here changes a
-- device. The body is the devbaseline.Snapshot JSON (bounded lists, device
-- strings clamped), ≤ 256 KiB, enforced here and at the API.
--
-- Retention: the newest 10 baselines per device are kept; older ones are
-- deleted in the same transaction that inserts a new one.
--
-- RLS: tenant_iso, FORCE — 0036/0059/0071 are the template; the API reads and
-- writes exclusively through WithTenant so the policy always has its GUC. The
-- owning tenant is derived from the device the server resolved under the
-- caller's scope, never from a request field.
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS device_baselines (
    tenant_id  TEXT NOT NULL DEFAULT '',
    id         UUID NOT NULL,
    device_id  TEXT NOT NULL CHECK (char_length(device_id) BETWEEN 1 AND 128),
    taken_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    taken_by   TEXT NOT NULL DEFAULT '' CHECK (char_length(taken_by) <= 128),
    label      TEXT NOT NULL DEFAULT '' CHECK (char_length(label) <= 80),
    body       JSONB NOT NULL CHECK (octet_length(body::text) <= 262144),
    PRIMARY KEY (tenant_id, id)
);

-- A device's baselines, newest first (Latest, List and the retention trim).
CREATE INDEX IF NOT EXISTS device_baselines_device_idx
    ON device_baselines (tenant_id, device_id, taken_at DESC);

ALTER TABLE device_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_baselines FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON device_baselines;
CREATE POLICY tenant_iso ON device_baselines
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
