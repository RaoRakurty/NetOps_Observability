-- 0030_wireless_inventory.sql — Wireless canonical inventory (tracker #128,
-- design docs/Wireslessdesign.md §7, owner-approved 2026-07-26).
--
-- Wireless Phase 1: the vendor-neutral canonical model, no telemetry. Seven
-- tables mirror the report's entity schema exactly. Conventions are the
-- topology_nodes pattern (0012): typed columns for what is queried, a lossless
-- JSONB `data` record, first_seen/last_seen/stale honesty (a row that stops
-- being observed is MARKED, never silently deleted), and the tenant_iso
-- FORCE-RLS policy on every table.
--
-- Identity rules (enforced in Go, wireless/identity.go — deterministic, never
-- name-based):
--   ap_id        = sha256(tenant|vendor|serial)   (mac_base fallback; NEVER name)
--   radio_id     = ap_id|slot                     (slot, not band — dual-5GHz)
--   wlan_id      = sha256(tenant|controller|profile)  (profile is controller-scoped)
--   ssid_id      = sha256(tenant|ssid_name)       (an SSID is NOT controller-scoped)
--   bssid        = the broadcast MAC itself       (unique per radio × WLAN)
--
-- SSID / WLAN / BSSID are SEPARATE identities by design (report §9): the SSID
-- is a broadcast name (not unique, not owned), the WLAN is a controller-scoped
-- config profile, the BSSID is the only precise "where was this client".
--
-- The logical/physical split (report §11): wireless_controllers is the LOGICAL
-- control domain APs join (a cluster, a cloud dashboard, or 'controllerless');
-- wireless_controller_members are the PHYSICAL boxes. A member failover
-- changes member_state — never an AP's controller binding.
--
-- ROLLBACK: migrations/rollback/0030_wireless_inventory.down.sql

CREATE TABLE IF NOT EXISTS wireless_controllers (
    tenant_id          TEXT NOT NULL DEFAULT '',
    controller_id      TEXT NOT NULL,                     -- deterministic (identity.go)
    name               TEXT NOT NULL DEFAULT '',
    vendor             TEXT NOT NULL DEFAULT '',
    model              TEXT NOT NULL DEFAULT '',
    os_version         TEXT NOT NULL DEFAULT '',
    kind               TEXT NOT NULL DEFAULT 'controller' -- controller | gateway (report §11: same shape, one discriminator)
                       CHECK (kind IN ('controller','gateway')),
    cluster_role       TEXT NOT NULL DEFAULT 'standalone'
                       CHECK (cluster_role IN ('standalone','ha_pair','n_plus_1','cloud_managed','controllerless')),
    management_address TEXT NOT NULL DEFAULT '',
    forwarding_default TEXT NOT NULL DEFAULT 'unknown'    -- central | local | mixed | unknown
                       CHECK (forwarding_default IN ('central','local','mixed','unknown')),
    -- Honest visibility (the seam model's rule: 'full' is earned, never assumed).
    -- cloud_managed controllers default to 'partial' — the members are opaque.
    visibility         TEXT NOT NULL DEFAULT 'partial'
                       CHECK (visibility IN ('full','partial','blind')),
    first_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale              BOOLEAN NOT NULL DEFAULT false,
    data               JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, controller_id)
);

CREATE TABLE IF NOT EXISTS wireless_controller_members (
    tenant_id       TEXT NOT NULL DEFAULT '',
    member_id       TEXT NOT NULL,
    controller_id   TEXT NOT NULL,                        -- logical parent
    name            TEXT NOT NULL DEFAULT '',
    serial          TEXT NOT NULL DEFAULT '',
    member_state    TEXT NOT NULL DEFAULT 'active'
                    CHECK (member_state IN ('active','standby','member','failed','maintenance')),
    redundancy_role TEXT NOT NULL DEFAULT 'primary'
                    CHECK (redundancy_role IN ('primary','secondary','tertiary')),
    ap_capacity     INTEGER NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale           BOOLEAN NOT NULL DEFAULT false,
    data            JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, member_id)
);
CREATE INDEX IF NOT EXISTS wireless_members_controller_idx
    ON wireless_controller_members (tenant_id, controller_id);

CREATE TABLE IF NOT EXISTS access_points (
    tenant_id         TEXT NOT NULL DEFAULT '',
    ap_id             TEXT NOT NULL,                      -- deterministic (identity.go — never the name)
    name              TEXT NOT NULL DEFAULT '',           -- display only; renames must not fork identity
    mac_base          TEXT NOT NULL DEFAULT '',
    serial            TEXT NOT NULL DEFAULT '',
    model             TEXT NOT NULL DEFAULT '',
    vendor            TEXT NOT NULL DEFAULT '',
    controller_ref    TEXT NOT NULL DEFAULT '',           -- LOGICAL controller (never a member)
    site_id           TEXT NOT NULL DEFAULT '',
    floor_ref         TEXT NOT NULL DEFAULT '',
    x                 REAL NOT NULL DEFAULT 0,
    y                 REAL NOT NULL DEFAULT 0,
    -- The AP uplink — the rank-1 structural join between the wireless domain and
    -- the LAN (report §6): the same switch:port appears as an ordinary interface
    -- entity, so wireless↔LAN edges ground on resource identity with no new code.
    uplink_switch_ref TEXT NOT NULL DEFAULT '',
    uplink_port_ref   TEXT NOT NULL DEFAULT '',
    poe_class         TEXT NOT NULL DEFAULT '',
    poe_draw_w        REAL NOT NULL DEFAULT 0,
    mgmt_address      TEXT NOT NULL DEFAULT '',
    mgmt_vlan         INTEGER NOT NULL DEFAULT 0,
    forwarding_mode   TEXT NOT NULL DEFAULT 'unknown'     -- central | local | mixed | unknown
                      CHECK (forwarding_mode IN ('central','local','mixed','unknown')),
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale             BOOLEAN NOT NULL DEFAULT false,
    data              JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, ap_id)
);
CREATE INDEX IF NOT EXISTS access_points_controller_idx
    ON access_points (tenant_id, controller_ref);

CREATE TABLE IF NOT EXISTS ap_radios (
    tenant_id         TEXT NOT NULL DEFAULT '',
    radio_id          TEXT NOT NULL,                      -- ap_id|slot
    ap_id             TEXT NOT NULL,
    slot              INTEGER NOT NULL DEFAULT 0,         -- identity axis (band is ambiguous: dual-5GHz)
    band              TEXT NOT NULL DEFAULT '',            -- 2.4GHz | 5GHz | 6GHz (display/query, not identity)
    channel           INTEGER NOT NULL DEFAULT 0,
    channel_width_mhz INTEGER NOT NULL DEFAULT 0,
    tx_power_dbm      REAL NOT NULL DEFAULT 0,
    tx_power_max_dbm  REAL NOT NULL DEFAULT 0,
    admin_state       TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (admin_state IN ('enabled','disabled','unknown')),
    oper_state        TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (oper_state IN ('up','down','unknown')),
    generation        TEXT NOT NULL DEFAULT '',            -- wifi5 | wifi6 | wifi6e | wifi7 | ''
    mlo_capable       BOOLEAN NOT NULL DEFAULT false,      -- Wi-Fi 7 MLO (report §10)
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale             BOOLEAN NOT NULL DEFAULT false,
    data              JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, radio_id)
);
CREATE INDEX IF NOT EXISTS ap_radios_ap_idx ON ap_radios (tenant_id, ap_id);

CREATE TABLE IF NOT EXISTS ssids (
    tenant_id  TEXT NOT NULL DEFAULT '',
    ssid_id    TEXT NOT NULL,                             -- sha256(tenant|ssid_name)
    ssid_name  TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale      BOOLEAN NOT NULL DEFAULT false,
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, ssid_id)
);

CREATE TABLE IF NOT EXISTS wlans (
    tenant_id           TEXT NOT NULL DEFAULT '',
    wlan_id             TEXT NOT NULL,                    -- sha256(tenant|controller|profile)
    profile_name        TEXT NOT NULL DEFAULT '',
    ssid_ref            TEXT NOT NULL DEFAULT '',          -- → ssids.ssid_id
    controller_ref      TEXT NOT NULL DEFAULT '',
    security_mode       TEXT NOT NULL DEFAULT 'unknown',   -- wpa2_psk | wpa2_enterprise | wpa3_sae | owe | open | ...
    auth_method         TEXT NOT NULL DEFAULT 'unknown',   -- dot1x | psk | sae | owe | open | mac_auth | portal
    aaa_ref             TEXT NOT NULL DEFAULT '',          -- AAA/RADIUS service ref (SESSION_AUTHENTICATED_BY edge)
    vlan_or_pool        TEXT NOT NULL DEFAULT '',
    -- Forwarding is a WLAN property, not a controller property (report §15:
    -- mixed forwarding is a per-WLAN split on one controller).
    forwarding_mode     TEXT NOT NULL DEFAULT 'unknown'
                        CHECK (forwarding_mode IN ('central','local','mixed','unknown')),
    band_policy         TEXT NOT NULL DEFAULT '',
    -- Roaming domain: populated ONLY when the controller exposes one (mobility
    -- group / cluster). NULL/'' = roam analysis abstains — NEVER inferred from
    -- SSID equality (report §9.2).
    mobility_domain_ref TEXT NOT NULL DEFAULT '',
    enabled             BOOLEAN NOT NULL DEFAULT true,
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale               BOOLEAN NOT NULL DEFAULT false,
    data                JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, wlan_id)
);
CREATE INDEX IF NOT EXISTS wlans_ssid_idx ON wlans (tenant_id, ssid_ref);

CREATE TABLE IF NOT EXISTS bssids (
    tenant_id  TEXT NOT NULL DEFAULT '',
    bssid      TEXT NOT NULL,                             -- the broadcast MAC — its own identity
    radio_ref  TEXT NOT NULL DEFAULT '',                  -- → ap_radios.radio_id
    wlan_ref   TEXT NOT NULL DEFAULT '',                  -- → wlans.wlan_id
    ap_ref     TEXT NOT NULL DEFAULT '',                  -- → access_points.ap_id (denormalized for lookup)
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale      BOOLEAN NOT NULL DEFAULT false,
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, bssid)
);
CREATE INDEX IF NOT EXISTS bssids_ap_idx ON bssids (tenant_id, ap_ref);

-- RLS: tenant_iso on all seven ('*' = platform cross-tenant; FORCE so even the
-- table owner is bound). Identical predicate to every other tenant table.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['wireless_controllers','wireless_controller_members',
                           'access_points','ap_radios','ssids','wlans','bssids'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_iso ON %I', t);
    EXECUTE format($p$CREATE POLICY tenant_iso ON %I
        USING (current_setting('app.tenant_id', true) = '*'
            OR tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (current_setting('app.tenant_id', true) = '*'
            OR tenant_id = current_setting('app.tenant_id', true))$p$, t);
  END LOOP;
END $$;
