-- 0061_controller_session_identity.sql — controller sessions keep the identity
-- the topology and the correlation engine need (NMS-first plan T4a, 2026-10-25).
--
-- A BFD session row recorded only the reporting device and an opaque entity
-- key, so nothing downstream could say WHICH tunnel it was, which end it ran
-- to, or over which transports. Those now persist with the state:
--   tunnel_id    canonical id both ends share (nms/sdwan_tunnel.go)
--   peer_id      the far end's native key (system-ip)
--   local_color  this end's transport colour
--   remote_color the far end's transport colour
-- Rows written before this migration keep '' and are re-filled by the next
-- poll of the session (every poll rewrites the row).
--
-- ISOLATION: the table already carries FORCE-RLS tenant_iso (0020). New
-- columns inherit it; the writer now runs tenant-scoped (nms/store.go
-- UpsertStates), so WITH CHECK refuses a row filed under another tenant.
ALTER TABLE controller_state_current ADD COLUMN IF NOT EXISTS tunnel_id    TEXT NOT NULL DEFAULT '';
ALTER TABLE controller_state_current ADD COLUMN IF NOT EXISTS peer_id      TEXT NOT NULL DEFAULT '';
ALTER TABLE controller_state_current ADD COLUMN IF NOT EXISTS local_color  TEXT NOT NULL DEFAULT '';
ALTER TABLE controller_state_current ADD COLUMN IF NOT EXISTS remote_color TEXT NOT NULL DEFAULT '';

-- The topology projection reads one tenant's sessions by kind; the partial
-- index keeps that read bounded to path rows.
CREATE INDEX IF NOT EXISTS controller_state_tunnel_idx
    ON controller_state_current (tenant_id, state_kind, last_seen DESC)
    WHERE tunnel_id <> '';
