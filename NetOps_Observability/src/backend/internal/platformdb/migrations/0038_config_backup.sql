-- 0038_config_backup.sql — the relational half of the Config Backup & Drift
-- module (P3-CFG, docs/design/CONFIG_BACKUP_AND_DRIFT_DESIGN_2026-08-25.md).
--
-- WHAT IS *NOT* IN HERE IS THE POINT: no configuration text. A device's
-- running-config is a secret store (SNMP communities, key material, password
-- hashes), so the config bytes live SEALED under the owning tenant's DEK in the
-- blob store (0700 directory, 0600 blobs) and Postgres holds only the metadata
-- needed to index, order, diff and prune them — device, tenant, content address,
-- capture time, size, blob reference, status. A dumped database, a stray backup
-- or an RLS bug therefore yields an INVENTORY of versions, never a single
-- configuration line (CLAUDE.md §8, design §2).
--
-- config_backup_versions — one row per captured version.
--   version_sha   sha256 of the NORMALIZED config: the content address, the
--                 storage key and the drift comparator in one. An unchanged
--                 capture re-stamps captured_at on the existing row instead of
--                 minting a new version, which is what keeps storage flat for a
--                 fleet that is not changing (design §3).
--   blob_ref      the sealed blob's path inside the blob store, relative to its
--                 root. It is validated for containment on every read — a row is
--                 untrusted input the moment anything else can write to it.
--   status/error_text  a FAILED capture is stored too: "we could not reach this
--                 device" is information the badge must show, and keeping only
--                 successes would render an unreachable device as merely stale.
--   golden        the optional known-good baseline, at most one per device
--                 (enforced by the partial unique index below). Retention never
--                 prunes it — it is the reference every drift verdict is made
--                 against.
--   drift_state / lines_added / lines_removed  the verdict internal/configdrift
--                 reached for this capture, stamped back onto the row so the
--                 versions timeline renders without a second query.
--
-- config_drift_state — one row per device: the inventory sync badge.
--   state         in_sync | changed | drifted | unknown. `unknown` covers BOTH
--                 "never captured" and "last capture failed" (last_error tells
--                 them apart) and is deliberately never rendered green: an
--                 unassessed device must not look like a clean one.
--
-- RLS: tenant_iso, FORCE, on both tables — migration 0011/0031/0036/0037 is the
-- template. Every read and write goes through WithTenant so the policy always
-- has its GUC. Additive and idempotent: safe to apply forward.

CREATE TABLE IF NOT EXISTS config_backup_versions (
    tenant_id     TEXT        NOT NULL DEFAULT '',
    device_id     TEXT        NOT NULL,
    version_sha   TEXT        NOT NULL,
    captured_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    size_bytes    BIGINT      NOT NULL DEFAULT 0,
    blob_ref      TEXT        NOT NULL DEFAULT '',
    vendor        TEXT        NOT NULL DEFAULT '',
    status        TEXT        NOT NULL DEFAULT 'ok',
    error_text    TEXT        NOT NULL DEFAULT '',
    golden        BOOLEAN     NOT NULL DEFAULT FALSE,
    drift_state   TEXT        NOT NULL DEFAULT 'unknown',
    lines_added   INTEGER     NOT NULL DEFAULT 0,
    lines_removed INTEGER     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, device_id, version_sha)
);

-- The versions list is always "one device, newest first".
CREATE INDEX IF NOT EXISTS config_backup_versions_device_idx
    ON config_backup_versions (tenant_id, device_id, captured_at DESC);

-- At most one golden baseline per device. A second one would make "the" golden
-- ambiguous and every drift verdict non-deterministic.
CREATE UNIQUE INDEX IF NOT EXISTS config_backup_versions_golden_idx
    ON config_backup_versions (tenant_id, device_id) WHERE golden;

CREATE TABLE IF NOT EXISTS config_drift_state (
    tenant_id       TEXT        NOT NULL DEFAULT '',
    device_id       TEXT        NOT NULL,
    state           TEXT        NOT NULL DEFAULT 'unknown',
    last_sha        TEXT        NOT NULL DEFAULT '',
    golden_sha      TEXT        NOT NULL DEFAULT '',
    lines_added     INTEGER     NOT NULL DEFAULT 0,
    lines_removed   INTEGER     NOT NULL DEFAULT 0,
    last_error      TEXT        NOT NULL DEFAULT '',
    last_capture_at TIMESTAMPTZ,
    changed_at      TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, device_id)
);

-- The bulk badge query is "my devices in state X, ordered by device id".
CREATE INDEX IF NOT EXISTS config_drift_state_state_idx
    ON config_drift_state (tenant_id, state, device_id);

ALTER TABLE config_backup_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE config_backup_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON config_backup_versions;
CREATE POLICY tenant_iso ON config_backup_versions
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE config_drift_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE config_drift_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON config_drift_state;
CREATE POLICY tenant_iso ON config_drift_state
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
