-- Rollback for 0039_packet_capture.sql.
--
-- NOTE for the operator: dropping this table removes the INDEX of packet
-- captures, not the sealed blobs themselves — those live on the platform volume
-- under PCAP_DIR and become unreferenced. Because a PCAP is customer payload,
-- deleting that directory is the more urgent half of a rollback, not an
-- afterthought: delete it separately if the intent is to remove the captures.
DROP TABLE IF EXISTS pcap_captures;
