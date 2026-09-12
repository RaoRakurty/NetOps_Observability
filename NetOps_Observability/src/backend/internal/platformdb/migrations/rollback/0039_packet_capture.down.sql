-- Rollback for 0039_packet_capture.sql.
--
-- NOTE for the operator: dropping this table removes the INDEX of packet
-- captures, not the sealed blobs themselves — those live on the platform volume
-- under PCAP_DIR and become unreferenced. Because a PCAP is customer payload,
-- deleting that directory is the more urgent half of a rollback, not an
-- afterthought: delete it separately if the intent is to remove the captures.
DROP TABLE IF EXISTS pcap_captures;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0039_packet_capture.sql';
