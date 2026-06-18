// topologyFactTypes.ts — the RAW evidence layer of the Correlix topology contract.
//
// Architecture rule (PDF §1, §7): the frontend NEVER consumes raw LLDP/CDP/SNMP/
// BGP-LS rows. Those are modelled here as immutable TopologyFacts — subject /
// predicate / object triples carrying their own source, confidence, time-validity
// and a raw reference back to the ingest record. The resolved TopologyView
// (topologyTypes.ts) is built FROM facts; every node and edge keeps the EvidenceRefs
// that justify it, so the UI can always answer "why does this link exist?".
//
// Nothing in this file imports a renderer. It is pure domain.

/** Where a fact came from. Confidence guidance per source lives in topologyHealth. */
export type TopologySource =
  | "lldp"
  | "cdp"
  | "snmp"
  | "bgp_ls"
  | "isis_lsdb"
  | "ospf_lsdb"
  | "netbox"
  | "cloud_api"
  | "k8s_api"
  | "flow"
  | "trace"
  | "syslog"
  | "metric"
  | "manual";

/**
 * A single normalized observation about the network. Immutable; superseded by
 * newer facts rather than mutated. (PDF §7.1)
 */
export type TopologyFact = {
  fact_id: string;
  tenant_id: string;
  source: TopologySource;
  /** RDF-ish triple: e.g. subject="leaf1" predicate="connected_to" object="spine1". */
  subject: string;
  predicate: string;
  object: string;
  source_device?: string;
  source_interface?: string;
  target_device?: string;
  target_interface?: string;
  /** ISO-8601. When the underlying telemetry observed this. */
  observed_at: string;
  /** ISO-8601. After this the fact is stale (source TTL exceeded). */
  expires_at?: string;
  /** 0..1 — how much we trust this single observation. */
  confidence: number;
  /** Opaque pointer back to the ingest record (OpenSearch doc id, CH row, etc.). */
  raw_ref: string;
  attributes: Record<string, unknown>;
};

/**
 * A reference, carried on a node/edge/group, to the evidence that justifies it.
 * Drives the Evidence panel and the "missing evidence is explicit" rule. (PDF §7.3)
 */
export type EvidenceRef = {
  source: TopologySource;
  /** 0..1 confidence contributed by this evidence. */
  confidence: number;
  observed_at: string;
  /** Pointer to the raw fact / ingest record. */
  raw_ref: string;
  /** One-line human summary, e.g. "bidirectional LLDP leaf1 Eth1/1 ↔ spine1 Eth1/11". */
  summary: string;
  /** True when an RCA correlation actually used this evidence. */
  used_by_rca?: boolean;
  /** Why a present fact was discounted (e.g. "one-way only", "stale > TTL"). */
  ignored_reason?: string;
  /** What we'd EXPECT but don't have (e.g. "no reverse LLDP from spine1"). */
  missing_evidence_if_any?: string;
};
