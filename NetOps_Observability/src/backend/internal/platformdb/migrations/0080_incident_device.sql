-- 0080_incident_device.sql — WHERE an incident is: the device it fired on
-- (tracker 438).
--
-- An alert-born incident used to drop the firing alert's device id, so
-- Operations → Incidents could not name the device the way Problems and Active
-- Alerts do (owner, 2026-11-22: device names on every operational list).
--
-- Stamped SERVER-SIDE only, from the firing alert (ingestAlertIncident). The
-- manual POST /api/incidents body never carries it (unknown fields are
-- refused). The first non-empty value wins on a dedup fold, so the column never
-- flips between devices. '' = no device (stack, Digital Experience, manual).
--
-- RLS: `incidents` already carries tenant_iso FORCE; a new column is covered by
-- the same row policy. Additive and idempotent.

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS device_id TEXT NOT NULL DEFAULT ''
    CHECK (char_length(device_id) <= 256);
