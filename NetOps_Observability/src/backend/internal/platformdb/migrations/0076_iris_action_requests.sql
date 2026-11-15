-- 0076_iris_action_requests.sql — Iris's approval gate for writes (tracker 337
-- N-I4, design 15). One row per write Iris PROPOSED: what it would send (the
-- exact payload), who it was proposed for, what was checked, who decided, and
-- what happened.
--
-- WHAT CAN BE HERE: exactly two kinds, both product/ticket writes — a note on
-- the incident's ITSM ticket and Iris's finding saved to investigation memory.
-- A device write is not a kind (the CHECK below) and its payload is not a type
-- in the code. Device writes stay structurally prohibited (owner 2026-09-05).
--
-- TWO PEOPLE: the person Iris answered (proposed_by) may withdraw a request but
-- never approve it — the CHECK refuses an executing / executed / failed row
-- whose decider is the proposer, even when the application is bypassed.
--
-- RLS: tenant_iso, FORCE — the API reads and writes exclusively through
-- WithTenant so the policy always has its GUC.
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS iris_action_requests (
    tenant_id       TEXT NOT NULL,
    id              UUID NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('itsm_note','investigation_note')),
    status          TEXT NOT NULL CHECK (status IN ('proposed','dry_run','executing','executed','failed','rejected','expired')),
    policy          TEXT NOT NULL CHECK (policy IN ('allow','deny','require_approval','dry_run_only')),
    proposed_by     TEXT NOT NULL CHECK (char_length(proposed_by) BETWEEN 1 AND 256),
    proposed_via    TEXT NOT NULL DEFAULT 'iris' CHECK (proposed_via = 'iris'),
    decision_id     TEXT NOT NULL DEFAULT '' CHECK (char_length(decision_id) <= 64),
    correlation_id  TEXT NOT NULL CHECK (char_length(correlation_id) BETWEEN 1 AND 128),
    citations       JSONB NOT NULL DEFAULT '[]'::jsonb,
    payload         JSONB NOT NULL,
    summary         TEXT NOT NULL CHECK (char_length(summary) <= 300),
    preview         TEXT NOT NULL CHECK (char_length(preview) <= 4300),
    dry_run         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    decided_by      TEXT NOT NULL DEFAULT '' CHECK (char_length(decided_by) <= 256),
    decided_at      TIMESTAMPTZ,
    reason          TEXT NOT NULL DEFAULT '' CHECK (char_length(reason) <= 500),
    executed_at     TIMESTAMPTZ,
    result          JSONB,
    PRIMARY KEY (tenant_id, id),
    -- A write runs only after a DIFFERENT person decided it.
    CONSTRAINT iris_action_two_people CHECK (
        status NOT IN ('executing','executed','failed') OR (decided_by <> '' AND decided_by <> proposed_by)),
    -- A write runs only when the policy required approval (never on a dry run).
    CONSTRAINT iris_action_policy_status CHECK (
        status NOT IN ('executing','executed','failed') OR policy = 'require_approval'),
    CONSTRAINT iris_action_dry_run CHECK (status <> 'dry_run' OR policy = 'dry_run_only'),
    -- A declined request says why.
    CONSTRAINT iris_action_reject_reason CHECK (status <> 'rejected' OR reason <> ''),
    CONSTRAINT iris_action_expiry CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS iris_action_requests_created_idx
    ON iris_action_requests (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS iris_action_requests_open_idx
    ON iris_action_requests (tenant_id, status) WHERE status = 'proposed';

ALTER TABLE iris_action_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE iris_action_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON iris_action_requests;
CREATE POLICY tenant_iso ON iris_action_requests
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
