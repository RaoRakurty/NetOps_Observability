-- 0073_iris_learning_proposals.sql — Iris's controlled learning loop (tracker
-- 337 N-F5). What operators already told Correlix (how incidents were fixed,
-- which entity an answer should have meant, which questions Iris could not
-- answer) becomes a PROPOSED update a person decides.
--
-- NOTHING ACTIVATES FROM HERE. A row is a suggestion with its sources. Adopting
-- one hands it to the store it targets, under that store's own rules: a
-- Network context version (0058: a second person approves, CHECK
-- approver_sub <> author_sub), a tenant runbook draft (0066: cases + a second
-- person), or an alias, which has no review of its own — so for an alias THIS
-- table refuses an approval by the person who adopted it (the CHECK below).
--
-- PRIVACY: `draft` holds the text that would reach a prompt once approved; it
-- is built from closed vocabularies and server-derived names only. `evidence`
-- may quote an operator's RCA resolution note for the REVIEWER; that quote never
-- enters `draft` and is never sent to an AI provider.
--
-- RLS: tenant_iso, FORCE — the API reads and writes exclusively through
-- WithTenant so the policy always has its GUC.
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS iris_learning_proposals (
    tenant_id       TEXT NOT NULL,
    id              UUID NOT NULL,
    target          TEXT NOT NULL CHECK (target IN ('org_context','runbook','alias')),
    generator       TEXT NOT NULL CHECK (generator IN ('resolution_pattern','entity_correction','miss_cluster')),
    subject         TEXT NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 300),
    title           TEXT NOT NULL CHECK (char_length(title) <= 300),
    why             TEXT NOT NULL CHECK (char_length(why) <= 1000),
    draft           JSONB NOT NULL,
    evidence        JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_count  INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
    state           TEXT NOT NULL CHECK (state IN ('proposed','adopted','applied','dismissed')),
    adopted_by      TEXT NOT NULL DEFAULT '',
    adopted_at      TIMESTAMPTZ,
    decided_by      TEXT NOT NULL DEFAULT '',
    decided_at      TIMESTAMPTZ,
    reason          TEXT NOT NULL DEFAULT '' CHECK (char_length(reason) <= 500),
    target_id       TEXT NOT NULL DEFAULT '' CHECK (char_length(target_id) <= 200),
    target_version  INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, generator, subject),
    -- An adopted / applied proposal names who adopted it.
    CONSTRAINT iris_learning_adopted_by CHECK (state IN ('proposed','dismissed') OR adopted_by <> ''),
    -- The two-person rule for aliases, which have no review of their own.
    CONSTRAINT iris_learning_alias_two_people CHECK (
        NOT (target = 'alias' AND state = 'applied') OR (decided_by <> '' AND decided_by <> adopted_by)),
    -- A dismissal says why.
    CONSTRAINT iris_learning_dismiss_reason CHECK (state <> 'dismissed' OR reason <> '')
);

CREATE INDEX IF NOT EXISTS iris_learning_proposals_updated_idx
    ON iris_learning_proposals (tenant_id, updated_at DESC);

ALTER TABLE iris_learning_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE iris_learning_proposals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON iris_learning_proposals;
CREATE POLICY tenant_iso ON iris_learning_proposals
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
