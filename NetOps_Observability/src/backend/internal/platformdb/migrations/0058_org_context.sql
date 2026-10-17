-- 0058_org_context.sql — the Org Context Store (tracker 337 N-F1, design D6,
-- docs/architecture/iris-natural-language-platform.md §4.1.6).
--
-- Short, typed facts a customer writes about its own network, read by Iris
-- before every answer (internal/orgcontext). One document per (scope, kind,
-- key); numbered versions; at most one ACTIVE version per document, and only
-- the active version ever reaches a prompt.
--
-- TWO PEOPLE, enforced here as well as in the store:
--   * approver_sub <> author_sub (CHECK) — nobody approves their own text;
--   * an active / superseded / retired version must carry an approver.
-- HISTORY IS NOT REWRITTEN: once a version leaves 'draft' its body, hash,
-- author, approver and number are frozen, only the legal state moves are
-- allowed, and only a draft can be deleted (trigger below). Rollback is a NEW
-- version that copies an earlier approved one.
--
-- BOUNDS: body ≤ 2000 bytes, key ≤ 80 bytes (CHECKs); 50 documents per tenant
-- and 200 versions per document are enforced by the store.
--
-- ISOLATION: FORCE-RLS tenant_iso on both tables.
--
-- Rollback: rollback/0058_org_context.down.sql.

CREATE TABLE IF NOT EXISTS org_context_docs (
    tenant_id   TEXT NOT NULL,
    id          UUID NOT NULL,
    scope       TEXT NOT NULL CHECK (scope = 'tenant' OR scope ~ '^site:[a-z0-9._:-]{1,120}$'),
    kind        TEXT NOT NULL CHECK (kind IN ('naming_convention', 'escalation_contact', 'topology_note',
                    'maintenance_window', 'known_false_positive', 'criticality', 'carrier_relationship',
                    'address_convention', 'terminology')),
    key         TEXT NOT NULL CHECK (octet_length(key) BETWEEN 1 AND 80),
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, scope, kind, key)
);

CREATE TABLE IF NOT EXISTS org_context_versions (
    tenant_id     TEXT NOT NULL,
    doc_id        UUID NOT NULL,
    version       INTEGER NOT NULL CHECK (version >= 1),
    body          TEXT NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 2000),
    body_sha256   TEXT NOT NULL CHECK (body_sha256 ~ '^[0-9a-f]{64}$'),
    state         TEXT NOT NULL CHECK (state IN ('draft', 'pending', 'active', 'superseded', 'rejected', 'retired')),
    author_sub    TEXT NOT NULL CHECK (author_sub <> ''),
    approver_sub  TEXT,
    activated_by  TEXT NOT NULL DEFAULT '',
    decided_by    TEXT NOT NULL DEFAULT '',
    restored_from INTEGER,
    reason        TEXT NOT NULL DEFAULT '' CHECK (octet_length(reason) <= 500),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at    TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, doc_id, version),
    FOREIGN KEY (tenant_id, doc_id) REFERENCES org_context_docs (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT org_context_two_people CHECK (approver_sub IS NULL OR approver_sub <> author_sub),
    CONSTRAINT org_context_approved_states CHECK (state IN ('draft', 'pending', 'rejected') OR approver_sub IS NOT NULL)
);

-- At most one active version, and one open (draft/pending) version, per document.
CREATE UNIQUE INDEX IF NOT EXISTS org_context_one_active
    ON org_context_versions (tenant_id, doc_id) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS org_context_one_open
    ON org_context_versions (tenant_id, doc_id) WHERE state IN ('draft', 'pending');

CREATE OR REPLACE FUNCTION org_context_versions_guard() RETURNS trigger
    LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.state <> 'draft' THEN
            RAISE EXCEPTION 'org_context_versions: only a draft can be deleted' USING ERRCODE = '42501';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.tenant_id <> OLD.tenant_id OR NEW.doc_id <> OLD.doc_id OR NEW.version <> OLD.version
       OR NEW.author_sub <> OLD.author_sub OR NEW.restored_from IS DISTINCT FROM OLD.restored_from
       OR (NEW.created_at <> OLD.created_at AND OLD.state <> 'draft') THEN
        RAISE EXCEPTION 'org_context_versions: identity of a version is immutable' USING ERRCODE = '42501';
    END IF;
    IF OLD.state <> 'draft' AND (NEW.body <> OLD.body OR NEW.body_sha256 <> OLD.body_sha256) THEN
        RAISE EXCEPTION 'org_context_versions: text is frozen once submitted' USING ERRCODE = '42501';
    END IF;
    IF OLD.approver_sub IS NOT NULL AND NEW.approver_sub IS DISTINCT FROM OLD.approver_sub THEN
        RAISE EXCEPTION 'org_context_versions: approver is immutable' USING ERRCODE = '42501';
    END IF;
    IF NEW.state <> OLD.state AND NOT (
           (OLD.state = 'draft'   AND NEW.state = 'pending')
        OR (OLD.state = 'pending' AND NEW.state IN ('draft', 'active', 'rejected'))
        OR (OLD.state = 'active'  AND NEW.state IN ('superseded', 'retired'))) THEN
        RAISE EXCEPTION 'org_context_versions: % -> % is not a legal move', OLD.state, NEW.state USING ERRCODE = '42501';
    END IF;
    IF OLD.state IN ('superseded', 'rejected', 'retired') THEN
        RAISE EXCEPTION 'org_context_versions: a closed version cannot change' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS org_context_versions_guard ON org_context_versions;
CREATE TRIGGER org_context_versions_guard
    BEFORE UPDATE OR DELETE ON org_context_versions
    FOR EACH ROW EXECUTE FUNCTION org_context_versions_guard();

ALTER TABLE org_context_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_context_docs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON org_context_docs;
CREATE POLICY tenant_iso ON org_context_docs
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE org_context_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_context_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON org_context_versions;
CREATE POLICY tenant_iso ON org_context_versions
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
