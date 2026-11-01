-- Rollback for 0061_controller_session_identity.sql. The columns mirror what
-- the controller reports on every poll: dropping them loses nothing that the
-- next poll does not rewrite (the topology shows no controller tunnels until
-- the forward migration is re-applied).
DROP INDEX IF EXISTS controller_state_tunnel_idx;
ALTER TABLE controller_state_current DROP COLUMN IF EXISTS remote_color;
ALTER TABLE controller_state_current DROP COLUMN IF EXISTS local_color;
ALTER TABLE controller_state_current DROP COLUMN IF EXISTS peer_id;
ALTER TABLE controller_state_current DROP COLUMN IF EXISTS tunnel_id;

-- The migrator never removes a schema_migrations row: without this delete a
-- re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0061_controller_session_identity.sql';
