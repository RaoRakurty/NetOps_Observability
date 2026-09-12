-- 0010_seam_inventory.sql — Canonical seam inventory (#67 build ⑤, #68 §4/§4.1).
-- Seams are OWNERSHIP TRANSITIONS in packet-forwarding responsibility (owner
-- spec, 2026-06-11): five canonical types, each instance an entity the
-- correlation engine grounds edges against (corr_edges.grounding_kind='seam').
-- Postgres owns this because it is lifecycle/catalog state (suggest → confirm →
-- active workflow, owner edits) — the CH↔PG ownership split from the #67 freeze.
--
-- The bootstrap engine (seam_bootstrap.go) auto-suggests instances from
-- telemetry; suggestions are idempotent and rejections are PERMANENT memory:
-- both are enforced by one mechanism, the partial-unique suggestion_key index
-- (a rejected row keeps its key, so the same evidence can never re-raise it).

CREATE TABLE IF NOT EXISTS seams (
    seam_id        TEXT NOT NULL,                    -- deterministic for suggestions (sm-<hash>), free-form for manual
    tenant_id      TEXT NOT NULL DEFAULT '',
    seam_type      TEXT NOT NULL
                   CHECK (seam_type IN ('DX','VPN','SDWAN','DIA','CLOUD_BACKBONE')),
    state          TEXT NOT NULL DEFAULT 'suggested'
                   CHECK (state IN ('suggested','confirmed','active','rejected','retired')),
    display_name   TEXT NOT NULL DEFAULT '',
    endpoints      JSONB NOT NULL DEFAULT '{}'::jsonb,  -- {on_prem, cloud, provider, ...}
    control_plane_owner TEXT NOT NULL DEFAULT 'enterprise'
                   CHECK (control_plane_owner IN ('enterprise','isp','cloud','sdwan_controller')),
    visibility     TEXT NOT NULL DEFAULT 'partial'      -- honest default; 'full' is earned, never assumed
                   CHECK (visibility IN ('full','partial','blind')),
    probe_strategy JSONB NOT NULL DEFAULT '[]'::jsonb,  -- ["stamp","icmp","http_synthetic"]
    -- Provenance: which rule raised it, on what evidence, how confident.
    -- Manual rows carry suggested_by='manual' and an empty suggestion_key.
    suggested_by   TEXT NOT NULL DEFAULT 'manual',
    evidence       JSONB NOT NULL DEFAULT '{}'::jsonb,
    confidence     REAL NOT NULL DEFAULT 0,
    suggestion_key TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by     TEXT NOT NULL DEFAULT 'system',
    PRIMARY KEY (tenant_id, seam_id)
);

-- Idempotent suggest + permanent rejection memory (§4.1 "rejected suggestions
-- are remembered and never re-raised"): INSERT … ON CONFLICT DO NOTHING here.
CREATE UNIQUE INDEX IF NOT EXISTS seams_suggestion_key_idx
    ON seams (tenant_id, suggestion_key) WHERE suggestion_key <> '';
CREATE INDEX IF NOT EXISTS seams_tenant_state_idx
    ON seams (tenant_id, state, seam_type);

ALTER TABLE seams ENABLE ROW LEVEL SECURITY;
ALTER TABLE seams FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON seams;
CREATE POLICY tenant_iso ON seams
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

-- Redundancy groups (#68 §4, owner direction): topology variation lives in the
-- INSTANCE, never the type — a dual-homed DX is still seam_type DX; what varies
-- is fault/impact semantics. Members reference seams (incl. cross-type fallback
-- members, e.g. a VPN backing a DX). Correlation runs member-level (fault) and
-- group-level (impact) so "circuit down, group held" can verdict as
-- redundancy-loss rather than outage. Same suggest→confirm lifecycle.
CREATE TABLE IF NOT EXISTS seam_groups (
    group_id        TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    seam_type       TEXT NOT NULL                     -- the group's primary type
                    CHECK (seam_type IN ('DX','VPN','SDWAN','DIA','CLOUD_BACKBONE')),
    redundancy_model TEXT NOT NULL DEFAULT 'single'
                    CHECK (redundancy_model IN ('single','active_active','active_standby','hybrid_fallback')),
    state           TEXT NOT NULL DEFAULT 'suggested'
                    CHECK (state IN ('suggested','confirmed','active','rejected','retired')),
    display_name    TEXT NOT NULL DEFAULT '',
    members         JSONB NOT NULL DEFAULT '[]'::jsonb,  -- [{member_id, role, seam_type}]
    suggested_by    TEXT NOT NULL DEFAULT 'manual',
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
    confidence      REAL NOT NULL DEFAULT 0,
    suggestion_key  TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by      TEXT NOT NULL DEFAULT 'system',
    PRIMARY KEY (tenant_id, group_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS seam_groups_suggestion_key_idx
    ON seam_groups (tenant_id, suggestion_key) WHERE suggestion_key <> '';
CREATE INDEX IF NOT EXISTS seam_groups_tenant_state_idx
    ON seam_groups (tenant_id, state);

ALTER TABLE seam_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE seam_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON seam_groups;
CREATE POLICY tenant_iso ON seam_groups
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));
