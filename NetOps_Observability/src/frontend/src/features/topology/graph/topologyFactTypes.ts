// topologyFactTypes.ts — the RAW evidence layer of the Correlix topology contract.
//
// Architecture rule (skill: topology-fact-model.md): the frontend NEVER consumes raw
// LLDP/CDP/SNMP/BGP-LS rows. Those are modelled here as immutable TopologyFacts —
// subject/predicate/object triples carrying source, confidence, time-validity and a
// raw reference. The resolved TopologyView (topologyTypes.ts) is built FROM facts.
//
// Nothing in this file imports a renderer. Pure domain.

/** Where a fact came from (skill topology-context.md source list). */
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

/** A single normalized observation. Immutable; superseded, not mutated. */
export type TopologyFact = {
  fact_id: string;
  source: TopologySource;
  subject: string;
  predicate: string;
  object: string;
  source_device?: string;
  source_interface?: string;
  target_device?: string;
  target_interface?: string;
  observed_at: string;
  expires_at?: string;
  confidence: number;
  raw_ref: string;
  attributes?: Record<string, unknown>;
};

/**
 * Evidence reference carried on a node/edge. CANONICAL fields per the skill
 * contract example are `source` + `confidence` (+ optional `detail`); everything
 * else is DERIVED ENRICHMENT the UI computes (drawer summaries, RCA flags). These
 * are adapter/display fields — not part of the wire contract.
 */
export type EvidenceRef = {
  // ── canonical (skill topology-contract.json) ──
  source: TopologySource;
  confidence: number;
  detail?: string;
  // ── derived / UI enrichment (allowed; not canonical API) ──
  summary?: string;
  observed_at?: string;
  raw_ref?: string;
  used_by_rca?: boolean;
  ignored_reason?: string;
  missing_evidence_if_any?: string;
};
