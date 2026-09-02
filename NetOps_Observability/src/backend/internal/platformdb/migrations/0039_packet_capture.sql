-- 0039_packet_capture.sql — the relational half of the Packet Capture module
-- (docs/design/PACKET_CAPTURE_DESIGN_2026-08-25.md).
--
-- WHAT IS *NOT* IN HERE IS THE POINT, and it matters more here than it did for
-- config backup (migration 0038). A PCAP is the DATA PLANE: real payload, real
-- credentials, real PII. The capture bytes therefore live SEALED under the
-- owning tenant's DEK in the blob store (0700 directory, 0600 blobs, AAD bound
-- to tenant|device|capture) and Postgres holds only the metadata needed to
-- list, order, audit and prune them. A dumped database, a stray backup or an
-- RLS bug yields an INVENTORY of captures, never a single packet
-- (CLAUDE.md §8, design "Secure storage").
--
-- pcap_captures — one row per capture.
--   capture_id   a 32-hex id minted by the platform. It is NEVER caller input:
--                it becomes a blob path and an on-device file name, so a
--                caller-supplied id would be a path-traversal and a command
--                injection in one.
--   iface        the interface the capture ran on, already validated against
--                the module's strict interface grammar.
--   filter_expr  the CANONICAL re-rendered capture filter (or ''). It is the
--                string the module built from validated tokens, never the
--                operator's bytes echoed back.
--   duration_s / max_packets  the bounds the capture actually ran with. They
--                are stored because "how wide was this capture" is an audit
--                question, and the answer must survive the request.
--   expires_at   the hard stop. A row whose status is still 'running' past
--                this instant is a capture whose runtime died; the one-per-
--                device gate treats it as finished rather than wedging the
--                device forever.
--   status       running | stored | failed. A FAILED capture is stored too:
--                "we tried and could not reach the device" is information the
--                operator needs, and keeping only successes would render an
--                unreachable device as merely idle.
--   blob_ref     the sealed blob's path inside the capture store, relative to
--                its root. It is validated for containment on every read — a
--                row is untrusted input the moment anything else can write it.
--   remote_path  the on-device file, kept ONLY so a cleanup retry knows what to
--                delete. It is never rendered to a client.
--   actor        who started the capture. A capture is never anonymous
--                (design: "Ticketed + audited ... No capture is anonymous").
--
-- RLS: tenant_iso, FORCE — migration 0011/0031/0036/0037/0038 is the template.
-- Every read and write goes through WithTenant so the policy always has its
-- GUC. Additive and idempotent: safe to apply forward.

CREATE TABLE IF NOT EXISTS pcap_captures (
    tenant_id   TEXT        NOT NULL DEFAULT '',
    device_id   TEXT        NOT NULL,
    capture_id  TEXT        NOT NULL,
    iface       TEXT        NOT NULL DEFAULT '',
    filter_expr TEXT        NOT NULL DEFAULT '',
    duration_s  INTEGER     NOT NULL DEFAULT 0,
    max_packets INTEGER     NOT NULL DEFAULT 0,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at    TIMESTAMPTZ,
    status      TEXT        NOT NULL DEFAULT 'running',
    packets     INTEGER     NOT NULL DEFAULT 0,
    bytes       BIGINT      NOT NULL DEFAULT 0,
    error_text  TEXT        NOT NULL DEFAULT '',
    blob_ref    TEXT        NOT NULL DEFAULT '',
    actor       TEXT        NOT NULL DEFAULT '',
    remote_path TEXT        NOT NULL DEFAULT '',
    platform    TEXT        NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, device_id, capture_id)
);

-- The listing is always "one device, newest first".
CREATE INDEX IF NOT EXISTS pcap_captures_device_idx
    ON pcap_captures (tenant_id, device_id, started_at DESC);

-- The one-capture-per-device gate reads "is anything running on this device".
CREATE INDEX IF NOT EXISTS pcap_captures_active_idx
    ON pcap_captures (tenant_id, device_id) WHERE status = 'running';

ALTER TABLE pcap_captures ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcap_captures FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON pcap_captures;
CREATE POLICY tenant_iso ON pcap_captures
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
