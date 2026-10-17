-- Rollback for 0059_incident_fingerprints.sql. Fingerprints are derived data:
-- dropping them only means they are recomputed on demand.
DROP TABLE IF EXISTS incident_fingerprints;

-- The migrator never removes a schema_migrations row: without this delete a
-- re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0059_incident_fingerprints.sql';
