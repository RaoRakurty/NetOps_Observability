-- 0066_tenant_runbooks.sql — tenant runbooks and MOPs (tracker 337 N-F2, design
-- D7, docs/architecture/iris-natural-language-platform.md).
--
-- A customer's own troubleshooting method, written in the same dialect as the
-- compiled skills and proven by the same case harness (internal/tenantrunbook).
-- The version lifecycle is the Org Context Store's (0058) and is enforced the
-- same way: one document, numbered versions, at most one ACTIVE.
--
-- TWO PEOPLE, enforced here as well as in the store:
--   * approver_sub <> author_sub (CHECK) — nobody approves their own text;
--   * an active / superseded / retired version must carry an approver.
-- PROVEN: a version may not go pending → active unless its cases passed
-- (trigger), no active row may exist without harness_passed (CHECK: this is the
-- rollback path, which INSERTs its new version), and a submitted version's
-- harness result is frozen, so a statement cannot claim the proof in the same
-- breath as the approval. Whether the proof is still CURRENT (fingerprint) is the
-- store's check: the database does not know what the current fingerprint is.
-- A MOP is never executed, so it stores harness_passed = true, fingerprint 'n/a'.
-- HISTORY IS NOT REWRITTEN: once a version leaves 'draft' its text, hash, author,
-- approver and number are frozen, only the legal state moves are allowed, and
-- only a draft can be deleted. Rollback is a NEW version.
--
-- BOUNDS: the text sizes here (CHECKs); 30 runbooks per tenant, 50 versions per
-- runbook, 40 cases per runbook and 20 links per runbook in the store.
--
-- SEARCH: name + when_to_use_text only. The method's body is not indexed.
-- when_to_use_text follows the ACTIVE version while there is one, so an
-- unapproved edit cannot change what an approved runbook is found by.
--
-- ISOLATION: FORCE-RLS tenant_iso on all three tables.
--
-- Rollback: rollback/0066_tenant_runbooks.down.sql.

CREATE TABLE IF NOT EXISTS tenant_runbooks (
    tenant_id        TEXT NOT NULL,
    id               UUID NOT NULL,
    name             TEXT NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,47}$'),
    kind             TEXT NOT NULL CHECK (kind IN ('investigative', 'mop')),
    when_to_use_text TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    search           TSVECTOR GENERATED ALWAYS AS
                         (to_tsvector('simple', name || ' ' || coalesce(when_to_use_text, ''))) STORED,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS tenant_runbooks_search ON tenant_runbooks USING GIN (search);

CREATE TABLE IF NOT EXISTS tenant_runbook_versions (
    tenant_id           TEXT NOT NULL,
    runbook_id          UUID NOT NULL,
    version             INTEGER NOT NULL CHECK (version >= 1),
    skill_md            TEXT NOT NULL CHECK (octet_length(skill_md) BETWEEN 1 AND 16384),
    cases_yaml          TEXT NOT NULL DEFAULT '' CHECK (octet_length(cases_yaml) <= 32768),
    body_sha256         TEXT NOT NULL CHECK (body_sha256 ~ '^[0-9a-f]{64}$'),
    state               TEXT NOT NULL CHECK (state IN ('draft', 'pending', 'active', 'superseded', 'rejected', 'retired')),
    author_sub          TEXT NOT NULL CHECK (author_sub <> ''),
    approver_sub        TEXT,
    activated_by        TEXT NOT NULL DEFAULT '',
    decided_by          TEXT NOT NULL DEFAULT '',
    restored_from       INTEGER,
    reason              TEXT NOT NULL DEFAULT '' CHECK (octet_length(reason) <= 500),
    harness_passed      BOOLEAN NOT NULL DEFAULT false,
    harness_fingerprint TEXT NOT NULL DEFAULT '',
    harness_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at          TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, runbook_id, version),
    FOREIGN KEY (tenant_id, runbook_id) REFERENCES tenant_runbooks (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT tenant_runbook_two_people CHECK (approver_sub IS NULL OR approver_sub <> author_sub),
    CONSTRAINT tenant_runbook_approved_states CHECK (state IN ('draft', 'pending', 'rejected') OR approver_sub IS NOT NULL),
    CONSTRAINT tenant_runbook_active_proven CHECK (state <> 'active' OR harness_passed)
);

-- At most one active version, and one open (draft/pending) version, per runbook.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_runbook_one_active
    ON tenant_runbook_versions (tenant_id, runbook_id) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS tenant_runbook_one_open
    ON tenant_runbook_versions (tenant_id, runbook_id) WHERE state IN ('draft', 'pending');

CREATE OR REPLACE FUNCTION tenant_runbook_versions_guard() RETURNS trigger
    LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.state <> 'draft' THEN
            RAISE EXCEPTION 'tenant_runbook_versions: only a draft can be deleted' USING ERRCODE = '42501';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.tenant_id <> OLD.tenant_id OR NEW.runbook_id <> OLD.runbook_id OR NEW.version <> OLD.version
       OR NEW.author_sub <> OLD.author_sub OR NEW.restored_from IS DISTINCT FROM OLD.restored_from
       OR (NEW.created_at <> OLD.created_at AND OLD.state <> 'draft') THEN
        RAISE EXCEPTION 'tenant_runbook_versions: identity of a version is immutable' USING ERRCODE = '42501';
    END IF;
    IF OLD.state <> 'draft' AND (NEW.skill_md <> OLD.skill_md OR NEW.cases_yaml <> OLD.cases_yaml
       OR NEW.body_sha256 <> OLD.body_sha256) THEN
        RAISE EXCEPTION 'tenant_runbook_versions: text is frozen once submitted' USING ERRCODE = '42501';
    END IF;
    IF OLD.approver_sub IS NOT NULL AND NEW.approver_sub IS DISTINCT FROM OLD.approver_sub THEN
        RAISE EXCEPTION 'tenant_runbook_versions: approver is immutable' USING ERRCODE = '42501';
    END IF;
    IF NEW.state <> OLD.state AND NOT (
           (OLD.state = 'draft'   AND NEW.state = 'pending')
        OR (OLD.state = 'pending' AND NEW.state IN ('draft', 'active', 'rejected'))
        OR (OLD.state = 'active'  AND NEW.state IN ('superseded', 'retired'))) THEN
        RAISE EXCEPTION 'tenant_runbook_versions: % -> % is not a legal move', OLD.state, NEW.state USING ERRCODE = '42501';
    END IF;
    IF OLD.state IN ('superseded', 'rejected', 'retired') THEN
        RAISE EXCEPTION 'tenant_runbook_versions: a closed version cannot change' USING ERRCODE = '42501';
    END IF;
    -- The two rules 0058 does not have. A submitted version's result only moves
    -- when it goes back to draft (a withdrawal clears it for the next submit).
    IF OLD.state <> 'draft' AND NEW.state <> 'draft' AND (NEW.harness_passed <> OLD.harness_passed
       OR NEW.harness_fingerprint <> OLD.harness_fingerprint OR NEW.harness_at IS DISTINCT FROM OLD.harness_at) THEN
        RAISE EXCEPTION 'tenant_runbook_versions: the harness result is frozen once submitted' USING ERRCODE = '42501';
    END IF;
    IF OLD.state = 'pending' AND NEW.state = 'active' AND NOT NEW.harness_passed THEN
        RAISE EXCEPTION 'tenant_runbook_versions: a version whose cases have not passed cannot become active' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS tenant_runbook_versions_guard ON tenant_runbook_versions;
CREATE TRIGGER tenant_runbook_versions_guard
    BEFORE UPDATE OR DELETE ON tenant_runbook_versions
    FOR EACH ROW EXECUTE FUNCTION tenant_runbook_versions_guard();

CREATE TABLE IF NOT EXISTS tenant_runbook_links (
    tenant_id  TEXT NOT NULL,
    runbook_id UUID NOT NULL,
    link_type  TEXT NOT NULL CHECK (link_type IN ('alert', 'signature', 'entity', 'incident')),
    link_key   TEXT NOT NULL CHECK (octet_length(link_key) BETWEEN 1 AND 128),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, runbook_id, link_type, link_key),
    FOREIGN KEY (tenant_id, runbook_id) REFERENCES tenant_runbooks (tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS tenant_runbook_links_by_key
    ON tenant_runbook_links (tenant_id, link_type, link_key);

ALTER TABLE tenant_runbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_runbooks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON tenant_runbooks;
CREATE POLICY tenant_iso ON tenant_runbooks
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE tenant_runbook_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_runbook_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON tenant_runbook_versions;
CREATE POLICY tenant_iso ON tenant_runbook_versions
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE tenant_runbook_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_runbook_links FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON tenant_runbook_links;
CREATE POLICY tenant_iso ON tenant_runbook_links
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
