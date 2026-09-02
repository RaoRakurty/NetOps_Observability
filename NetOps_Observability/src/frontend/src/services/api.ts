// Minimal typed API client. Paths are relative — nginx (or Vite dev
// proxy) routes /api and /admin to the Go backend.

// Port Intelligence workbench row (#94) — flattened port+transceiver+health.
export type PortRow = {
  device: string;
  port_id: string;
  port_name: string;
  if_alias?: string;
  admin_status: string;
  oper_status: string;
  speed_bps: number;
  role?: string;
  seam?: string;
  lag_id?: string;
  breakout_group_id?: string;
  form_factor?: string;
  media_type?: string;
  vendor_name?: string;
  part_number?: string;
  serial_number?: string;
  supported_status?: string;
  health: number;
  health_state: string;
  dominant_issue?: string;
  matched_signature?: string;
  last_change?: string;
};

export type Device = {
  id: string;
  name: string;
  address: string;
  vendor?: string;
  model?: string;
  os?: string;
  type?: string; // router|switch|firewall|load-balancer|ap|wlc|cloud-gw|generic (SNMP-inferred)
  preferred_protocol?: string;
  credential_ref?: string;
  labels?: Record<string, string>;
  source: string;
  last_seen: string;
};

// Subnet discovery scan scope (platform-owner; GET is redacted — the probe
// community is write-only).
export type DiscoveryConfig = {
  enabled: boolean;
  ranges: string[];
  community_set: boolean;
  allow_non_private: boolean;
  interval_sec: number;
};
export type DiscoveryConfigInput = {
  enabled: boolean;
  ranges: string[];
  community?: string; // comma-separated priority list; blank preserves the stored secret
  allow_non_private?: boolean;
  interval_sec?: number;
};
export type DiscoveryConfigEnvelope = {
  config: DiscoveryConfig;
  limits?: { max_hosts: number; max_ranges: number };
  stats?: { last_poll?: string; last_error?: string; devices?: number };
};

export type CollectorStatus = {
  kind?: string; // "protocol" | "discovery"
  name: string;
  enabled: boolean;
  healthy: boolean;
  last_tick?: string;
  last_error?: string;
  targets: number;
  reachable?: number;
  last_poll_ms?: number;
};

export type Alert = {
  id: string;
  rule: string;
  severity: string;
  device_id?: string;
  summary: string;
  description?: string;
  labels?: Record<string, string>;
  fired_at: string;
  resolved_at?: string | null;
};

export type Rule = {
  name: string;
  expr: string;
  for: number;
  severity: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
};

// Alert episode — repeated firings of the same (resource, signal, state)
// folded into one row with first/last/count, flap detection and triage state.
export type EpisodeNote = { at: string; by: string; text: string };
export type AlertEpisode = {
  id: string;
  tenant_id?: string;
  resource?: string; // device id; absent = platform/stack-level
  signal: string; // monitor rule name
  state: string; // severity facet (critical | warning | …)
  summary?: string;
  status: "active" | "cleared" | "closed";
  first_seen: string;
  last_seen: string;
  count: number;
  flapping?: boolean;
  flip_count?: number;
  acknowledged_by?: string;
  acknowledged_at?: string;
  assigned_to?: string;
  assigned_by?: string;
  muted?: boolean;
  muted_by?: string;
  snoozed_until?: string;
  snoozed_by?: string;
  notes?: EpisodeNote[];
};
// Maintenance windows (item 121). Exactly one shape per window: one-shot
// (starts_at + ends_at) or recurring (schedule, optionally bounded by until).
// Empty scope lists match everything of that dimension.
export type MaintenanceWindowSchedule = {
  tz?: string;
  weekdays?: string[]; // mon..sun; empty = daily
  start_hour: number;
  start_minute: number;
  duration_minutes: number;
};
export type MaintenanceWindowInput = {
  name: string;
  description?: string;
  device_ids?: string[];
  sites?: string[];
  rules?: string[];
  starts_at?: string;
  ends_at?: string;
  schedule?: MaintenanceWindowSchedule;
  until?: string;
  enabled?: boolean;
};
export type MaintenanceWindow = MaintenanceWindowInput & {
  id: string;
  tenant_id?: string;
  enabled: boolean;
  created_by?: string;
  created_at: string;
  updated_at: string;
};

// Pipeline Processors — structured processors compiled to the ingest runtime.
// Never free-form VRL; custom regex is accepted but server-validated (RE2).
export type ProcessorLane = "applogs" | "syslog" | "snmptrap" | "cloudlogs" | "flows";
export type ProcessorRuleType =
  | "redact_field" | "redact_pattern" | "redact_keys" | "mask" | "hash" | "tag"
  | "drop_field" | "set_field" | "drop_event" | "seal";
export type ProcessorMatchOp = "equals" | "contains" | "prefix" | "regex" | "attribute";
export type ProcessorMatch = { field: string; op: ProcessorMatchOp; value: string };
export type ProcessorRuleInput = {
  name?: string;
  lane: ProcessorLane;
  type: ProcessorRuleType;
  field: string;
  pattern?: string;       // managed-rule id, literal text, or RE2 pattern
  pattern_kind?: "builtin" | "literal" | "regex";
  value?: string;         // set_field
  replacement?: string;   // redact/mask token, e.g. "[EMAIL]"
  keep_last?: number;     // mask: retained tail length
  keys?: string[];        // redact_keys: field NAMES to redact
  data_type?: string;     // seal: semantic type bound INTO the token (card, email, ssn)
  match?: ProcessorMatch;
  description?: string;
  order?: number;
  enabled?: boolean;
};
export type ProcessorRule = ProcessorRuleInput & {
  id: string;
  tenant_id?: string;
  enabled: boolean;
  order: number;
  version: number;
  source?: "custom" | "managed";
  managed_rule_id?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
};
export type ManagedRule = {
  id: string; name: string; category: string; description: string;
  // A detector is EITHER content-scoped (pattern) or key-scoped (keys).
  pattern: string; keys?: string[]; version: number; replacement: string;
  checksum?: string; default_field?: string;
};
export type ProcessorPlugin = {
  type: string; label: string; edge_capable: boolean; targets_field?: boolean;
};
export type SealPreset = {
  data_type: string; label: string; keep_last: number; hint: string;
};
export type ProcessorCatalog = {
  actions: ProcessorPlugin[];
  matchers: ProcessorPlugin[];
  managed_rules: ManagedRule[];
  lanes: ProcessorLane[];
  // Sealing is the one action that can be registered but UNAVAILABLE (it needs
  // key custody), so the wizard disables it with a reason rather than offering
  // a choice that fails on save.
  seal_available?: boolean;
  seal_presets?: SealPreset[];
};
export type ProcessorApplied = {
  rule_id: string; processor: string; type: string; field?: string;
  description?: string; managed_rule?: string;
};
export type ProcessorPreview = {
  original: Record<string, unknown>;
  event: Record<string, unknown>;
  applied: ProcessorApplied[];
  dropped: boolean;
};
export type ProcessorVersion = {
  processor_id: string; version: number; config: ProcessorRule;
  changed_by?: string; change_kind: string; created_at: string;
};

export type AlertEpisodeList = {
  episodes: AlertEpisode[];
  total: number;
  truncated: boolean;
  close_window_seconds?: number;
  flap_flips?: number;
  flap_window_seconds?: number;
};

export type MetricTile = {
  title: string;
  value: string;
  trend?: string;
};

export type Health = {
  status: string;
  version: string;
  uptime: string;
  // Fleet/collector detail is platform-owner-only (SR-009) — absent for
  // scoped tenants, so these are optional.
  discovery?: Record<string, unknown>;
  collectors?: Record<string, boolean>;
  alerts?: Record<string, unknown>;
};

// ---------- Automation: NetBox source-of-truth config ----------
// GET shape is redacted: `token_set` reflects whether a token is stored; the
// token itself is never returned. On save, send `token` only to change it.
export type NetboxConfig = {
  enabled: boolean;
  url: string;
  interval_sec: number;
  token_set: boolean;
  managed: boolean; // bundled internal NetBox — URL/token auto-wired
  token?: string; // write-only
  // Sync direction: "write" = devices → NetBox only (default; NetBox never read
  // back, no duplicates), "read" = NetBox → platform (intent SoT), "both",
  // "none" = automatic device sync off (NetBox available, but no auto push/pull).
  direction?: "write" | "read" | "both" | "none";
};

// Result of the device→NetBox write-through reconciler.
export type NetboxSyncStatus = {
  enabled: boolean;
  last_run?: string;
  last_error?: string;
  created: number; // devices created in NetBox on the last run
  present: number; // devices already in NetBox (left untouched)
};

// ---------- Platform stack health (platform-owner only) ----------

export type StackComponent = {
  name: string;
  category: string;
  status: "up" | "degraded" | "down";
  latency_ms: number;
  detail?: string;
};
export type StackHealth = {
  overall: "healthy" | "degraded" | "down";
  up: number;
  degraded: number;
  down: number;
  components: StackComponent[];
  subsystems: Record<string, unknown>;
};

// ---------- SNMP profiles (vendor OID/metric library) ----------

export type SnmpMetric = {
  name: string;
  oid: string;
  type: string;
  unit?: string;
  mib?: string;
  category?: string;
  description?: string;
};
export type SnmpProfile = {
  id: string;
  vendor: string;
  description?: string;
  category: string;
  sysobjectid_prefix?: string;
  builtin: boolean;
  metrics: SnmpMetric[];
};

// ---------- Notification channels ----------

export type SmtpConfig = {
  enabled: boolean;
  host: string;
  port: number;
  from: string;
  user: string;
  pass?: string; // write-only on PUT
  pass_set?: boolean; // read-only on GET
  to: string;
  security: string; // starttls | tls | none
  min_severity: string;
};
export type TwilioConfig = {
  enabled: boolean;
  account_sid: string;
  auth_token?: string;
  token_set?: boolean;
  from: string;
  to: string;
  min_severity: string;
};
export type NtfyConfig = {
  enabled: boolean;
  server: string;
  topic: string;
  token?: string;
  token_set?: boolean;
  min_severity: string;
};

export type SlackConfig = {
  enabled: boolean;
  webhook_url?: string; // write-only on PUT
  webhook_set?: boolean; // read-only on GET
  min_severity: string;
};

export type PagerDutyConfig = {
  enabled: boolean;
  routing_key?: string; // write-only on PUT
  routing_set?: boolean; // read-only on GET
  min_severity: string;
};

// Microsoft Teams — an Incoming Webhook URL embeds a bearer token, so the WHOLE
// URL is the secret and is redacted exactly the way Slack's is: GET returns
// `webhook_set`, PUT accepts `webhook_url`, and a PUT that omits it preserves
// the stored value.
export type TeamsConfig = {
  enabled: boolean;
  webhook_url?: string; // write-only on PUT
  webhook_set?: boolean; // read-only on GET
  min_severity: string;
};

// Amazon SNS — SMS to E.164 numbers and/or publish to a topic ARN. There is no
// write-only secret here on purpose: the AWS access/secret key pair lives in
// the deployment environment and is never stored or returned by the API. The
// only thing the surface ever says about it is `credentials_set`.
export type SNSConfig = {
  enabled: boolean;
  topic_arn: string;
  region: string;
  phone_numbers: string; // comma-separated E.164 list
  min_severity: string;
  scope: string; // "all" | "platform"
  credentials_set?: boolean; // read-only on GET — env credential presence
};

// ---------- Audit trail (tenant-scoped) ----------

export type AuditEvent = {
  id: string;
  time: string;
  actor: string;
  tenant?: string;
  cross?: boolean;
  method: string;
  path: string;
  status: number;
  decision: "allow" | "deny" | "error";
  remote?: string;
  // Action-specific context for sensitive operations (an unseal's outcome,
  // stated reason, data type and ciphertext fingerprint). Never the value.
  detail?: Record<string, unknown>;
};

// ---------- OpenSearch ------------

export type OSHit = {
  _index: string;
  _id: string;
  _source: Record<string, any>;
};
// Sampling disclosure the backend injects on sampled stores (today: the flows
// signal, whose OpenSearch index holds the router's 1:50 sample — ClickHouse
// keeps the canonical flow store). Present ⇒ counts/totals are estimates.
export type LogSampling = { rate: number; note?: string };

export type OSResponse = {
  took?: number;
  hits: {
    total?: { value: number };
    hits: OSHit[];
  };
  sampling?: LogSampling;
};

export type LogSearchOpts = {
  query: string;
  from?: string;
  to?: string;
  size?: number;
  signal?: "applogs" | "syslog" | "snmptrap" | "flows" | "cloud" | "";
  // Paging offset ("Load more"); server-clamped to the engine's result window.
  offset?: number;
};

// Retention floor for the caller's visible log store: exact doc count + oldest
// timestamp ("logs go back to <date>, N days"). Tenant-scoped server-side.
// `sampling` present (flows) ⇒ `total` counts a 1:N sample, not the stream.
export type LogRetention = { signal: string; total: number; oldest: string | null; days: number; sampling?: LogSampling };

export type ExportFmt = "csv" | "json" | "ndjson" | "xlsx";

export type LogExportOpts = {
  format: ExportFmt;
  query?: string;
  from?: string;
  to?: string;
  signal?: "applogs" | "syslog" | "snmptrap" | "flows" | "cloud" | "";
  mode?: "sync" | "async" | "auto";
};

export type ExportStatus = {
  id: string;
  status: string;
  format?: string;
  size_bytes?: number;
  download_url?: string;
  error?: string;
};

export type Incident = {
  id: string;
  tenant_id: string;
  title: string;
  description?: string;
  severity: string;
  status: string;
  source_type: string;
  source_id?: string;
  owner?: string;
  occurrences: number;
  created_at: string;
  updated_at: string;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at?: string;
  external_ticket_id?: string;
  external_url?: string;
  external_system?: string;
  sync_status: string;
  last_synced_at?: string;
  notified_via?: string[]; // recorded notification deliveries (#103 UX-1)
};

export type IncidentEvent = {
  id: string;
  incident_id: string;
  event_type: string;
  payload?: Record<string, unknown>;
  actor: string;
  created_at: string;
};

// TimelineEntry — one item in the merged incident timeline: a lifecycle event
// (kind="lifecycle") or an ITSM sync event (kind="sync"). The discriminator says
// which fields are populated; `at` is the unified sort key.
export type TimelineEntry = {
  kind: "lifecycle" | "sync";
  at: string;
  id: string;
  // lifecycle
  event_type?: string;
  actor?: string;
  payload?: Record<string, unknown>;
  // sync
  provider?: string;
  direction?: string;
  type?: string;
  external_id?: string;
  status?: string;
  reason?: string;
  correlation_id?: string;
};

export type ExportPolicy = {
  rate_per_min: number;
  max_rows: number;
  max_bytes: number;
  max_runtime_seconds: number;
  max_range_hours: number;
  link_ttl_seconds: number;
  sync_max_rows: number;
};

// ---------- ClickHouse rows (passthrough) ----------

export type ClickHouseResponse<T = Record<string, any>> = {
  meta?: { name: string; type: string }[];
  data: T[];
  rows?: number;
  // /api/flows/geo only: false when the GeoIP dictionary has no data yet
  // (operator hasn't run scripts/geoip-prepare.py). Absent = enabled.
  geo_enabled?: boolean;
};

// NetFlow dashboard filter-bar selection. All optional; only set keys are sent.
export type FlowFilters = {
  src?: string; // initiator (source) IP
  dst?: string; // responder (destination) IP
  device?: string; // exporter / sampler IP
  in_if?: string; // ingress interface (SNMP ifIndex)
  out_if?: string; // egress interface
};

// flowQS serializes flow filters (and optional direction) into a query-string
// suffix (leading "&"), skipping empty values. Returns "" when nothing is set.
function flowQS(filters?: FlowFilters, direction = ""): string {
  const p: string[] = [];
  if (filters) {
    for (const [k, v] of Object.entries(filters)) {
      if (v) p.push(`${k}=${encodeURIComponent(v)}`);
    }
  }
  if (direction) p.push(`direction=${encodeURIComponent(direction)}`);
  return p.length ? `&${p.join("&")}` : "";
}

export type CorrObject = {
  correlation_id: string;
  version: number;
  state: string;
  window_start: string;
  window_end: string;
  trigger_signal?: string;
  top_hypothesis: string;
  top_confidence: number;
  verdict_tier: string;
  hypotheses?: string;        // ranking + embedded grounding context (JSON)
  evidence_missing: string;   // JSON array of named shortfalls
  affected: string;           // JSON {devices, paths, interfaces, ...}
  app_impact?: string;        // #81 P5: JSON {apps:[{app,band,state,sources,evidence_score,...}], evidence_missing?}
  signal_count: number;
  node_count: number;
  engine_version: string;
  topology_version?: string;
  catalog_version: string;
  created_at: string;
  // Triage enrichment (list endpoint) — for left-table badges.
  edge_count?: number | string;
  grounding?: string;          // "seam" | "topo" | "seam+topo" | "none"
  plane_count?: number | string;
  owner?: string;              // verdict owner (netops/isp/…)
  debug_excluded?: number;     // 0/1
  low_authority?: number;      // 0/1
  chaos_fixture?: string;      // non-empty = named intentional storm source (#101)
  ticket_status?: TicketStatus; // #78: external ticket state for this RCA object
};

// External ticket state for one RCA correlation object (#78). state is
// not_created | pending | open | updated | resolved | failed; url is a ready
// deep-link into the external system when a ticket exists.
export type TicketStatus = {
  state: string;
  system?: string;
  ticket_number?: string;
  sys_id?: string;
  instance_url?: string;
  last_verdict?: string;
  last_synced_at?: string | null;
  url?: string;
};
export type TicketAuditEntry = {
  action: string;
  actor: string;
  old_status?: string;
  new_status?: string;
  result: string;
  error?: string;
  at: string;
};
export type CorrelationTickets = {
  status: TicketStatus;
  pagerduty?: TicketStatus | null;   // legacy key (older backends)
  destinations?: TicketStatus[];     // #103 UX: every destination this RCA was filed to
  audit: TicketAuditEntry[];
};
// One tenant ticket link for the "Notified via" join (#103 UX-1): a TicketStatus
// plus the correlation it belongs to.
export type TicketLinkRow = TicketStatus & { corr_object_id: string };

// ---- RCA operator verdict feedback (Project 2 P7) --------------------------
// The record an operator writes after reading a correlation case: "the engine
// got this right / wrong / partly right", and when it was wrong, WHICH claim
// was wrong. Append-only — a revision adds a row, it never edits one. Mirrors
// src/backend/rcafeedback/feedback.go; write = alerts:write, read =
// infrastructure:read.
export type RcaVerdict = "correct" | "wrong" | "partial";
export type RcaWrongPart = "cause" | "owner" | "affected" | "evidence" | "recovery";
export type RcaFeedback = {
  id: string;
  tenant_id: string;
  correlation_id: string;
  verdict: RcaVerdict;
  wrong_part?: RcaWrongPart;
  reason?: string;
  /** The object version the operator actually judged; absent = not stated. */
  correlation_version?: number;
  top_hypothesis?: string;
  verdict_tier?: string;
  created_by: string;
  created_at: string;
};
export type RcaFeedbackList = { correlation_id: string; feedback: RcaFeedback[]; count: number };
/** The write body. No tenant field: the owner is stamped from the resolved object. */
export type RcaFeedbackCreate = {
  verdict: RcaVerdict;
  wrong_part?: RcaWrongPart;
  reason?: string;
  correlation_version?: number;
};
/** One engine template's tally. false_positive_rate is NULL for an empty sample —
 *  "nobody has judged this yet" is never rendered as a 0% false-positive rate. */
export type RcaFeedbackTemplateCounts = {
  template: string;
  correct: number; wrong: number; partial: number; n: number;
  false_positive_rate: number | null;
};
export type RcaFeedbackSummary = {
  days: number;
  since: string;
  n: number;
  counts: { correct: number; wrong: number; partial: number };
  false_positive_rate: number | null;
  by_template: RcaFeedbackTemplateCounts[];
};

// Active Verification (RCA spec item 8): one normalized read-only check result
// and the latest run per case. Statuses: pass | fail | unreachable | skipped.
export type VerificationCheckResult = {
  check: string;
  device_id: string;
  device_name?: string;
  target: string;
  method: string; // tcp | snmp | ssh
  status: "pass" | "fail" | "unreachable" | "skipped";
  observed?: string;
  command?: string; // the exact allowlisted read-only command executed
  ts: string;
  duration_ms: number;
  corroborates_kinds?: string[];
  refutes_kinds?: string[];
};
export type VerificationRun = {
  run_id: string;
  correlation_id: string;
  trigger: "manual" | "auto";
  actor: string;
  started_at: string;
  finished_at?: string;
  status: "running" | "completed";
  devices: string[];
  results?: VerificationCheckResult[];
};
export type VerificationStatus = {
  enabled: boolean; // global feature AND this tenant's opt-in
  run: VerificationRun | null;
};

// Incident policy (#78) — decides when an RCA object opens an external ticket.
export type IncidentPolicy = {
  id: string;
  tenant_id?: string;
  name: string;
  external_system: string; // "servicenow"
  enabled: boolean;
  min_verdict: string;     // "suspected" | "confirmed"
  require_customer_facing: boolean;
  allow_probe_only: boolean;
  allow_internal_monitoring: boolean;
  suspected_requires_critical: boolean;
  require_persistence_seconds: number;
  suppress_flapping_seconds: number;
  assignment_group?: string;
  default_impact: number;  // 1..4
  default_urgency: number; // 1..4
  // Per-verdict priority mapping — 0 = automatic (confirmed+critical → 1/1,
  // confirmed → urgency 1, suspected uses the defaults above).
  impact_confirmed_critical?: number;
  urgency_confirmed_critical?: number;
  impact_confirmed?: number;
  urgency_confirmed?: number;
};
export type IncidentPolicyTestFacts = {
  verdict: string;
  peak_severity?: string;
  internal?: boolean;
  probe_only?: boolean;
  low_authority_probe?: boolean;
  has_affected_entity?: boolean;
  persistence_seconds?: number;
};
export type TicketPolicyDecision = {
  create: boolean;
  reason: string;
  // Which exact saved policy produced this dry-run verdict…
  policy_id?: string;
  policy_name?: string;
  policy_enabled?: boolean;
  policy_updated_at?: string;
  // …and whether that policy is what the runtime would ACTUALLY apply.
  runtime_state?: "active" | "shadowed" | "held" | "opted_out";
  runtime_policy_id?: string;
  runtime_policy_name?: string;
};

// RCA path overlay (#77) — UI-ready path + annotations for a correlation object
// (GET /api/correlations/{id}/rca-path-view; backend rca_path_view.go).
export type RcaPathNode = { id: string; type: string; kind: string; label: string; role?: string; status?: string };
export type RcaPathEdge = { id: string; source: string; target: string; type: string; state: string; label?: string };
export type RcaAnnotation = {
  target_type: string; target_id: string; status: string; verdict: string; confidence: number;
  owner: string; visibility: string; reason: string; evidence_refs: string[]; missing_evidence: string[];
};
// C4 causal-layer stack — the RCA Layer-Stack panel's data (engine-owned taxonomy,
// passed through verbatim; backend rca_path_view.go parseLayerCoverage).
export type RcaLayer = {
  layer: string;          // device | physical | link | network | transport | service | application
  osi: string;            // "L1".."L7" | "device" | ""
  observed: boolean;
  kinds: string[];
  entities: string[];
  peak_severity: string;  // crit | high | warn | info | ""
};
export type RcaLayerCoverage = {
  layers: RcaLayer[];     // full bottom-up ladder, always seven, device→application
  root_layer: string;     // lowest observed = most root-ward cause ("" if none mapped)
  impact_layer: string;   // highest observed = the impact
  unmapped_kinds: string[];
};
export type RcaPathView = {
  corr_object_id: string; verdict: string; confidence: number; internal: boolean;
  title: string; summary: string; recommended_action: string;
  path: { source: string; destination: string; nodes: RcaPathNode[]; edges: RcaPathEdge[] };
  annotations: RcaAnnotation[];
  evidence_summary: Record<string, unknown>; missing_evidence_summary: string[];
  layer_coverage?: RcaLayerCoverage;
};

// ── Path-causality RCA P3 (design §5) — the discovered typed SRC→DST path + the
// named on-path cause, as decoded server-side (rca_path_attribution.go). This is a
// PURE render contract: the engine already made the causal decision + applied the
// honesty caps; the UI only draws it. Absent when no on-path cause was attributed.
export type RcaOnPathDevice = {
  address?: string; role: string; label?: string;
  segment_index: number; segment_type?: string; upstream_rank: number; ambiguous: boolean;
};
export type RcaAttributedFault = {
  device: RcaOnPathDevice; kind: string; modality?: string; headline?: string;
};
export type RcaDiscountedFault = { identity: string; kind: string; reason: string };
export type RcaPathKeyDevice = {
  address?: string; role: string; label?: string; confidence?: string;
  // Discovery-driven device role (backend classifier, roles.go): access_switch |
  // distribution_switch | core_router | firewall | load_balancer | wan_edge |
  // carrier_hop | dc_wan_edge | dc_leaf | dc_spine | cloud_edge | unknown.
  // Absent when discovery couldn't classify — never guessed.
  device_role?: string;
  role_confidence?: string; // strong | medium | weak (words, never percentages)
};
export type RcaTypedSegment = {
  index: number; segment_type: string; boundary?: string; provider?: string; confidence?: string;
  key_devices?: RcaPathKeyDevice[]; unknown_hops?: number[]; ambiguous: boolean; reason?: string;
  // Cloud attachment flavor when the backend derived one (dia | direct_connect |
  // expressroute | ipsec_vpn). Absent = not derivable; the UI must not guess.
  attachment?: string;
};
export type RcaPathHead = { query_name?: string; resolved_address?: string };
export type RcaTypedPath = {
  src?: string; dst?: string; ambiguous: boolean;
  head?: RcaPathHead | null; segments?: RcaTypedSegment[]; notes?: string[];
};
export type RcaPathAttribution = {
  src?: string; dst?: string; headline?: string;
  attributed?: RcaAttributedFault | null;
  explained_away?: RcaAttributedFault[];
  discounted?: RcaDiscountedFault[];
  verdict_tier: string; baseline_verdict_tier: string;
  confidence_lifted: boolean; capped: boolean; cap_reason?: string;
  on_path_device_count: number; path?: RcaTypedPath | null;
};
// The RCA report JSON — we type the path-causality slice the P3 render reads and
// the recovery/lifecycle slice the embedded-investigation verification loop reads;
// the report carries much more (rca_report.go), left loose for other consumers.
export type RcaRecoveryScope = { state: string; at?: string; basis: string };
export type RcaReportStatesLite = {
  incident?: string;   // active | recovering | recovered | no_longer_observed | closed | merged | superseded
  lifecycle?: string;
  recovery?: string;   // explicitly_confirmed | component_only | failed_validation | inferred | not_observed
  recovery_basis?: string;
  recovery_component?: RcaRecoveryScope;
  recovery_service?: RcaRecoveryScope;
  monitoring?: string; // not_started | active | completed
  [k: string]: unknown;
};
export type RcaReportTimesLite = {
  first_observed?: string; last_anomalous?: string;
  recovered_at?: string; recovered_captured?: boolean;
  component_recovered_at?: string; monitoring_until?: string;
  [k: string]: unknown;
};
export type RcaPromotionStatus = {
  promoted: boolean;
  basis: "auto" | "manual" | "not_promoted";
  reason: string;
  criteria?: Array<{ name: string; met: boolean; detail: string }>;
  manual?: { promoted_by: string; promoted_at: string; note?: string };
};

// #113 point 3 — thrown when the server refuses the RCA DOCUMENT because the
// candidate is not a promoted real outage (the JSON/workspace tier stays open).
export class RcaNotPromotedError extends Error {
  constructor(public reason: string) {
    super(reason);
    this.name = "RcaNotPromotedError";
  }
}

export type RcaReportJson = {
  path_attribution?: RcaPathAttribution | null;
  states?: RcaReportStatesLite;
  times?: RcaReportTimesLite;
  promotion?: RcaPromotionStatus;
  [k: string]: unknown;
};

// #113 — the management RCA library: promoted real outages only. Rows are
// projections of the BUILT server report (never re-derived client-side).
export type RcaLibraryReport = {
  correlation_id: string;
  display_id: string;
  report_type: string;
  title: string;
  at_a_glance: {
    where: string; where_basis?: string; what: string;
    owners_label: string; owners: string[]; owners_reason?: string;
  };
  states: { incident: string; analysis: string; impact: string };
  times: { start: string; end: string; duration_ms: number };
  promotion: RcaPromotionStatus;
  validation: boolean;
};
export type RcaLibraryResponse = {
  reports: RcaLibraryReport[];
  // no silent caps: how many candidates were evaluated, whether the prefilter
  // page was full (older promoted outages may exist beyond it), and the window.
  evaluated: number;
  truncated: boolean;
  window_days: number;
};

// Manual incident lifecycle events (#84 P1d / #7 investigation close): the
// caller-tenant's operator-entered timestamps for one correlation object.
export type TimeEventRow = {
  id: string; correlation_id: string; event_type: string; event_time: string;
  timestamp_source: string; confidence: number; source_system: string;
  note?: string; created_at: string; created_by: string;
};

// Front page (#69) — scope health score, unified event feed, RCA coverage stats.
export type HealthContribution = {
  signal_class: string; entity: string; badness: number; points: number; reason: string; timestamp?: string;
};
export type HealthScoreResp = {
  scope: string; id?: string; score: number | null; band: string; confidence: string;
  coverage_status: string; signal_classes_live: string[]; contributions: HealthContribution[];
  stale_inputs: string[]; updated_at: string;
};
export type FeedItem = {
  signal_id: string; ts: string; source: string; kind: string; severity: string;
  entity_type: string; entity_id: string; site: string; title: string; correlation_id: string | null;
  // attrs is decoded server-side when it is valid JSON (actor/provider/region
  // for change events); a malformed blob passes through as its raw string.
  attrs?: Record<string, unknown> | string;
};
// `total` is the TRUE window count (real COUNT over the same filters; -1 =
// unknown); next_cursor is set only when a full page was returned.
export type EventsFeedResp = { items: FeedItem[]; next_cursor: string; total?: number; facets: Record<string, Record<string, number>> };
export type CorrStats = {
  open: number; open_confirmed: number; open_suspected: number; open_undetermined: number;
  actionable_pct: number; confirmed_7d_pct: number; total_window: number; signatures_matched: number; window_days: number;
};
// True tenant-scoped window counts for the Correlations page (never the capped
// list length): total objects, split by verdict tier and by state.
export type CorrSummary = {
  // total/tier/closed EXCLUDE state='merged' engine tombstones (#111); merged
  // is the separately disclosed duplicate count (don't-hide).
  total: number; confirmed: number; suspected: number; undetermined: number;
  open: number; closed: number; merged: number; window_seconds: number;
};
// #80 — recurring undetermined gap-shapes (which signature to write/strengthen next).
export type UndeterminedGap = { clause: string; count: number };
export type UndeterminedCluster = {
  fingerprint: string; label: string;
  nearest_signatures: string[]; top_gaps: UndeterminedGap[]; entity_types: string[];
  count: number; last_seen?: string; examples: string[]; avg_signals: number;
};
export type UndeterminedFeed = { window: string; total_undetermined: number; clusters: UndeterminedCluster[] };
export type ForecastRow = {
  device: string; interface: string; current_util_pct: number; slope_per_day_pct: number;
  days_to_90: number; status: "saturated" | "trending" | "stable" | "building_baseline"; history_days: number;
};
export type ForecastResp = { class: string; interfaces: ForecastRow[]; count: number; min_days: number };

// Path Behavior Health (docs/design/path-behavior-health.md). Numbers AND
// explanation: the UI shows state/confidence/ranges/reason/owner/evidence/baseline.
export type PathHealthItem = {
  path_id: string;
  agent: string;
  dst: string;
  health_state: "healthy" | "watch" | "degraded" | "severe";
  score: number;
  confidence: "low" | "medium_low" | "medium" | "high";
  severities: Record<string, number | null>; // latency/jitter/loss/route; null = not measured
  baseline_source: string;
  reason: string;
  likely_fault_domain: string;
  evidence: string[];
  current: { latency_p95_5m: number; jitter_p95_5m: number; loss_pct_5m: number };
  baseline: {
    source: string; source_label: string; window: string; sample_count: number;
    latency_p50: number; latency_p99: number; jitter_p50: number; jitter_p99: number;
  };
};
export type PathHealthResponse = { paths: PathHealthItem[]; count: number };

export type CorrEdge = {
  from_node: string;
  to_node: string;
  grounding_kind: string;
  grounding_ref: string;
  weight: number;
  w_temporal: number;
  w_topo: number;
  w_reinforce: number;
  direction_conf: number;
  direction_basis: string;
};

export type CorrReplay = {
  correlation_id: string;
  stored_version: number;
  engine_pin_match: boolean;
  catalog_pin_match: boolean;
  clean: boolean;
  differences: string[];
};

// RCA Time Intelligence (Incident Time Decomposition). Mirrors timeintel_api.go.
export type TimeMetric = {
  metric_name: "ttd" | "ttc" | "tti" | "tte" | "tta" | "ttm" | "ttr_recovery" | "ttr_resolution";
  complete: boolean;
  started_at?: string;
  ended_at?: string;
  duration_ms: number;
  start_event_type: string;
  end_event_type: string;
  confidence: number;
  is_inferred: boolean;
  blocked_by?: string;
  missing_event?: string;
  calculation_version: string;
};
export type TimeIntelLifecycleRow = {
  event_type: string;
  at: string;
  timestamp_source: "observed" | "inferred" | "user_entered" | "itsm" | "synthetic" | "imported";
  confidence: number;
};
export type Bottleneck =
  | "resolved" | "detection" | "correlation" | "root_isolation" | "owner_assignment"
  | "evidence_bundle" | "ticket_creation" | "acknowledgement" | "provider_repair"
  | "mitigation" | "recovery" | "closure" | "workflow_not_connected" | "unknown";
export type TimeIntel = {
  correlation_id: string;
  verdict_tier: string;
  owner?: string;
  owner_domain: string;
  owner_label: string;
  seam_type?: string;
  root_domain?: string;
  confidence_label: string; // Evidence-backed | Candidate | Insufficient evidence
  evidence_missing: boolean;
  lifecycle: TimeIntelLifecycleRow[];
  metrics: TimeMetric[];
  current_bottleneck: Bottleneck;
  bottleneck_message: string;
  workflow_connected: boolean;
  calculation_version: string;
};

// Reliability rollups (Operational Recovery Scorecard).
export type MetricStat = { incident_count: number; p50_ms: number; p90_ms: number; p95_ms: number; mean_ms: number };
export type ReliabilityRollup = {
  incident_count: number;
  metrics: Record<string, MetricStat>;
  top_time_loss_phase: string;
  repeat_incident_rate: number;
  mtbf_ms: number;
};
export type OwnerDomainStat = {
  domain: string; incident_count: number; mtti_p90_ms: number;
  recovery_p90_ms: number; repeat_incident_rate: number; top_delay_driver: string;
};
export type ReliabilityRollupResp = {
  window_seconds: number; rollup: ReliabilityRollup; by_owner_domain: OwnerDomainStat[];
  mttf_ms: number; mttf_asset_count: number; capped: boolean; scan_cap: number; include_internal: boolean;
  // #84 tail: rollups read persisted phase-metric snapshots; "live_scan" only on
  // cold start before the first backfill pass.
  source?: "snapshots" | "live_scan";
};
export type ReliabilityTrendBucket = {
  bucket_start: string; incident_count: number;
  metrics: Record<string, MetricStat>; repeat_incident_rate: number; mtbf_ms: number;
};
export type ReliabilityTrendsResp = { window_seconds: number; bucket_seconds: number; buckets: ReliabilityTrendBucket[] };
export type ChronicOffender = { group_key: string; incident_count: number; mtbf_ms: number; last_seen: string; owner_domain: string };
export type ReliabilityQuery = { owner?: string; provider?: string; device?: string; severity?: string; signature?: string; include_internal?: boolean };
function reliabilityQS(f: ReliabilityQuery): string {
  const parts = (["owner", "provider", "device", "severity", "signature"] as const)
    .filter((k) => f[k]).map((k) => `&${k}=${encodeURIComponent(String(f[k]))}`);
  if (f.include_internal) parts.push("&include_internal=true");
  return parts.join("");
}

// One evidence link: a signal's role w.r.t. an edge or hypothesis.
export type CorrEvidence = {
  signal_id: string;
  subject_kind: string;   // edge | hypothesis
  subject_id: string;
  role: string;           // supports | contradicts | discriminates
  note: string;
};

// One signal in an object's window slice (corr_signals_archive) enriched with
// its evidence role(s). The timing fields (ts = onset, onset_uncertainty_s,
// clock_quality) and attached flag drive the RCA timeline.
export type CorrSignal = {
  signal_id: string;
  ts: string;
  ingest_ts?: string;
  source: string;
  kind: string;
  observer_type: string;
  observer_id?: string;
  collection_path: string;
  modality_class: string;
  clock_quality: string;
  entity_type: string;
  entity_id: string;
  entity_tokens?: string[];
  severity: string;
  value: number;
  baseline?: number;
  deviation?: number;
  metric_name: string;
  attrs?: string;
  onset_uncertainty_s: number;
  phase: string;
  clear_ts: string;
  attached: boolean;
  is_trigger: boolean;
  evidence: CorrEvidence[] | null;
  // Linkage to the object's causal graph, DERIVED at read time from graph
  // membership (the engine records evidence only at edge level). Explains, per
  // signal, whether/why it was linked — the core of the honest RCA story.
  link_status: "attached" | "recovery" | "unlinked" | "malformed";
  link_role: string;   // supporting | contradicting | discriminating (attached only)
  link_reason: string;
  linked_edges: CorrLinkedEdge[] | null;
  // Probe authority model (Step 3) — set for active_probe signals.
  probe_scope?: string;        // customer_path | service_dependency | internal_self_probe | synthetic_lab_probe | unknown
  probe_authority?: string;    // high | medium | low | debug_only
  classification_source?: string; // registry | inferred | unknown
};

// One grounded edge a signal's episode sits on (peer node + how it's grounded).
export type CorrLinkedEdge = {
  peer: string;
  grounding_kind: string;   // seam | topo
  grounding_ref: string;
  weight: number;
  direction_basis: string;
};

export type CorrTimeline = {
  correlation_id: string;
  version: number;
  window_start: string;
  window_end: string;
  trigger_signal: string;
  verdict_tier: string;
  top_hypothesis: string;
  top_confidence: number;
  evidence_missing: string; // JSON array
  signals: CorrSignal[];
  evidence: CorrEvidence[];
  edges: CorrEdge[];
  counts: {
    total: number;
    attached: number;
    unattached: number;
    recovery: number;
    unlinked: number;
    attached_observers: number;
    by_modality: Record<string, number>;
    attached_by_modality: Record<string, number>;
    by_role: Record<string, number>;
    by_grounding: Record<string, number>;
    by_status: Record<string, number>;
  };
};

// A grounding seam (ownership-transition boundary) — joins to edge grounding_ref.
export type Seam = {
  seam_id: string;
  seam_type?: string;
  state?: string;
  display_name?: string;
  endpoints?: Record<string, string>;
  control_plane_owner: string;  // enterprise | isp | cloud | sdwan_controller
  visibility: string;           // full | partial | blind
};

export type Finding = {
  ts: string;
  id: string;
  kind: string;
  severity: string;
  score: number;
  device: string;
  component: string;
  summary: string;
  description: string;
};

// Overlay tunnel (IPsec / SD-WAN / GRE) — one current row per tunnel, served
// from netops.tunnels. Numeric fields may arrive as JSON strings from
// ClickHouse (UInt64), so coerce with Number() at the call site.
// Per-WAN-interface row (GET /api/wan/interfaces) — one WAN (or WAN-connected)
// interface, with live util/status, its DERIVED measurement target (no hub/spoke)
// and the SLA resolved through the 5-tier source ranking. Has* flags distinguish a
// real 0 from "no data".
export type WanTargetKind = "direct_peer" | "next_hop" | "anchor" | "";
export type WanInterfaceRow = {
  device: string;
  interface: string;
  address: string;
  site?: string;
  connected_to_wan?: boolean; // Spine-style: connected to a WAN device, not on one
  in_bps: number;
  out_bps: number;
  util_pct: number;
  has_util: boolean;
  oper_up: boolean;
  has_oper: boolean;
  spark?: number[]; // live throughput history (bits/sec, oldest→newest) for the in-row moving graph
  target?: string; // dst host measured to
  target_kind?: WanTargetKind; // how the target was derived
  target_label?: string; // customer-facing target description
  remote_device?: string;
  remote_if?: string;
  has_target: boolean;
  latency_ms: number;
  jitter_ms: number;
  loss_pct: number;
  qoe: number;
  availability_pct: number;
  has_latency: boolean;
  has_jitter: boolean;
  has_loss: boolean;
  has_qoe: boolean;
  has_availability: boolean;
  source?: string;
  source_label?: string;
  tier?: number; // 1..5 (1 = closest to user experience)
  tier_label?: string; // e.g. "Active path probe"
};

// Platform DNS + NTP system settings.
export type SystemNetworkConfig = {
  dns_servers: string[];
  search_domains?: string[];
  ntp_servers: string[];
  updated_by?: string;
  updated_at?: string;
};
export type NTPResult = {
  server: string;
  reachable: boolean;
  stratum?: number;
  offset_ms?: number;
  rtt_ms?: number;
  error?: string;
};
export type BackupConfig = {
  remote_url: string;
  push_command?: string;
  schedule_enabled: boolean;
  schedule_cron?: string;
  updated_by?: string;
  updated_at?: string;
};
export type FullBackupRun = {
  status: string;
  ended: string;
  size_bytes: number;
  duration_seconds: number;
  failures: number;
  artifact?: string;
};
export type BackupStatus = {
  remote_configured: boolean;
  schedule_enabled: boolean;
  os_snapshot_repo_ok: boolean;
  os_last_snapshot_age_hours?: number;
  os_snapshot_detail: string;
  on_host_only_warning: boolean;
  last_drill_result?: string;
  last_drill_at?: string;
  full_backup?: FullBackupRun;
};
export type BackupConfigAndStatus = { config: BackupConfig; status: BackupStatus };
// #150: thin truthful view over the OpenSearch netops-daily SM policy.
export type SnapshotRun = { status: string; time?: string; duration_seconds?: number };
export type SnapshotPolicy = {
  enabled: boolean;
  schedule_cron: string;
  retention_max_count: number;
  retention_max_age_days: number; // 0 = no age limit (count-only retention)
  last_run?: SnapshotRun;
  next_run?: string;
  detail?: string;
};
export type SnapshotPolicyUpdate = {
  enabled?: boolean;
  schedule_cron?: string;
  retention_max_count?: number;
  retention_max_age_days?: number; // 0 clears the age condition
};
export type SystemNetworkStatus = {
  dns: { servers: string[]; test_host: string; resolved?: string[]; ok: boolean; error?: string };
  ntp: { results: NTPResult[]; ok: boolean; offset_ms: number };
};

// One resolved app name from POST /api/appid/resolve/batch (#81 P3G). `source`
// is the winning provenance (cloud_tag | ngfw_app_id | operator | ip_catalog |
// …) — surfaced as the tooltip on the UI's app-name chip.
export type AppIdBatchVerdict = {
  app: string;
  source: string;
  confidence: number;
};

export type Tunnel = {
  ts: string;
  id: string;
  type: string; // ipsec | sdwan | gre
  local_device: string;
  local_addr: string;
  remote_device: string;
  remote_addr: string;
  status: string; // up | down
  latency_ms: number;
  jitter_ms: number;
  loss_pct: number;
  qoe: number;
  uptime_s: number;
};

// ---------- Vulnerability Management (#13) ----------

export type VulnFinding = {
  device_id: string;
  device_name: string;
  vendor: string;
  product: string;
  version: string;
  cve: string;
  severity: string; // critical | high | medium | low | ""
  cvss: number;
  kev: boolean; // CISA Known Exploited Vulnerabilities
  published: string;
  summary: string;
};

export type VulnUnassessed = {
  device_id: string;
  device_name: string;
  vendor?: string;
  reason: string;
};

export type VulnsResponse = {
  vuln_enabled: boolean;
  feed?: { entries: number; kev_entries: number; updated_at: string };
  summary?: {
    devices: number;
    assessed: number;
    affected: number;
    findings: number;
    critical: number;
    kev: number;
  };
  findings?: VulnFinding[];
  unassessed?: VulnUnassessed[];
};

// ---------- Compliance Monitoring (build-order #14) ----------

export type ComplianceFinding = {
  check: string;
  title: string;
  class: "drift" | "policy";
  severity: "high" | "medium" | "low";
  framework: string;
  device_id: string;
  device_name: string;
  observed?: string;
  intended?: string;
  detail?: string;
};

export type ComplianceCheck = {
  id: string;
  title: string;
  class: "drift" | "policy";
  framework: string;
  active: boolean;
  reason?: string;
  findings: number;
};

export type ComplianceGap = {
  device_id: string;
  device_name: string;
  reason: string;
};

export type ComplianceResponse = {
  compliance_enabled: boolean;
  sot?: { configured: boolean; provider?: string };
  summary?: {
    devices: number;
    affected: number;
    compliant: number;
    findings: number;
    drift: number;
    policy: number;
    high: number;
    checks_active: number;
    checks_total: number;
  };
  checks?: ComplianceCheck[];
  findings?: ComplianceFinding[];
  gaps?: ComplianceGap[];
};

// ---------- Copilot ----------

export type CopilotMessage = { role: "user" | "assistant" | "system"; content: string };

export type AnthropicChatResponse = {
  id: string;
  type: string;
  role: "assistant";
  content: { type: "text"; text: string }[];
  model: string;
  stop_reason: string;
};
export type OpenAIChatResponse = {
  id: string;
  choices: { message: { role: string; content: string }; finish_reason: string }[];
  model: string;
};
// One retrieved documentation section returned with a chat answer — rendered
// as a "From the docs" link that opens the Help drawer at that page+section.
export type CopilotDocRef = { id: string; label: string; href: string };
// One governed lookup the agent loop ran for this answer (customer-facing label).
export type ChatLookup = { tool: string; label: string; items: number; error?: boolean };
// One evidence citation from an agent-loop lookup — href deep-links into the app.
export type ChatCitation = { id: string; kind: string; label: string; href: string };
// The backend now normalizes every provider (ChatGPT/Gemini/Copilot) to a single
// shape: { provider, text, doc_refs } — plus, when the agent loop investigated,
// lookups/citations/truncated. The old provider-native shapes are kept for
// backward-compatible parsing.
export type NormalizedChatResponse = {
  provider: string;
  text: string;
  doc_refs?: CopilotDocRef[];
  lookups?: ChatLookup[];
  investigated?: number;
  citations?: ChatCitation[];
  truncated?: boolean;
  // Provider-down fallback: the grounded engine answered (evidence-only) and
  // the UI shows a slim disclosure banner.
  fallback?: "provider_unavailable";
  grounded?: AiAnswer;
};
export type CopilotChatResponse = NormalizedChatResponse | AnthropicChatResponse | OpenAIChatResponse;

// Runtime assistant config (admin). The API key stays server-side and is never
// returned — GET reports key_present instead of the secret.
export type CopilotConfig = {
  provider: string; // "anthropic" | "openai"
  model: string;
  system?: string;
  feature_enabled?: boolean;
  key_present?: boolean;
  key_source?: "env" | "stored" | "none";
  providers?: string[];
  model_suggestions?: Record<string, string[]>;
};

// Per-workspace (tenant) AI settings — a tenant admin's own view. The key is
// write-only; entitlement fields are read-only here (platform-controlled).
export type AITenantConfig = {
  provider: string;
  model: string;
  key_present: boolean;
  no_platform_key: boolean;
  assistant_enabled: boolean;
  investigations_enabled: boolean;
  platform_key_available: boolean;
  providers?: string[];
  model_suggestions?: Record<string, string[]>;
};

export type AITenantRow = {
  tenant_id: string;
  name: string;
  assistant_enabled: boolean;
  investigations_enabled: boolean;
  key_present: boolean;
  no_platform_key: boolean;
  max_calls: number; // 0 = platform default
  daily_tokens: number; // 0 = platform default
};

export const TOKEN_KEY = "netops_token";
export const REFRESH_KEY = "netops_refresh";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(t: string | null): void {
  if (t === null) localStorage.removeItem(TOKEN_KEY);
  else localStorage.setItem(TOKEN_KEY, t);
}
// LANDING_PENDING_KEY marks a FRESH login so the app applies the configured default
// landing on the next authenticated load (a reload of a specific page does NOT set
// it, so deep-links/reloads keep their page). Cleared once the landing is applied.
export const LANDING_PENDING_KEY = "netops_landing_pending";
export function markFreshLogin(): void {
  try { sessionStorage.setItem(LANDING_PENDING_KEY, "1"); } catch { /* sessionStorage unavailable */ }
}
export function getRefresh(): string | null {
  return localStorage.getItem(REFRESH_KEY);
}
export function setRefresh(t: string | null): void {
  if (t === null) localStorage.removeItem(REFRESH_KEY);
  else localStorage.setItem(REFRESH_KEY, t);
}

// sweepScopedUIState clears per-user/per-scope client state that must never
// survive a session boundary on a shared browser (§3a): the FrontPage
// KPI-history family (netops.fp.kpihist*) and the active-scope selection.
// Called on EVERY session edge — logout, the 401 clear path, and each
// successful login BEFORE the new session's first render — so the previous
// principal's counts can never seed the next principal's sparklines (M21).
export function sweepScopedUIState(): void {
  try {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (k && k.startsWith("netops.fp.kpihist")) localStorage.removeItem(k);
    }
    localStorage.removeItem(ACTIVE_SCOPE_KEY);
  } catch { /* ignore storage errors */ }
}

// clearSession = tokens + scoped UI state, in one place. logout() and the 401
// refresh-failure path MUST both go through here: the 401 path used to drop
// only the tokens, leaving the kpihist family behind for the next user (M21).
export function clearSession(): void {
  setToken(null);
  setRefresh(null);
  sweepScopedUIState();
}

// sessionTenantKey — a storage-key discriminator derived from the SIGNED
// session token's claims (tenant id, falling back to the subject for the
// cross-tenant platform owner). Decode-only, no verification: the server
// enforces authz; this only namespaces client-side UI state per principal so
// two tenants on a shared browser never share a localStorage key (M21).
export function sessionTenantKey(): string {
  const t = getToken();
  if (!t) return "";
  try {
    const seg = t.split(".")[1] ?? "";
    const b64 = seg.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const c = JSON.parse(atob(pad)) as { tenant?: string; sub?: string };
    return c.tenant || (c.sub ? `u.${c.sub}` : "");
  } catch {
    return "";
  }
}

// (Removed the "view as tenant" switcher. Per-tenant data privacy is now a tenant
// config — "hide from global view" — enforced server-side, not a client view mode.)

// SSO_STATE_KEY holds the browser-side login-CSRF nonce (M20). ssoLoginUrl()
// mints it into sessionStorage right before the full-page redirect to
// /api/auth/sso/login; captureSSORedirect() consumes it (single-use) when the
// callback hands the session back via the URL fragment. sessionStorage on
// purpose: per-tab, survives the redirect round-trip, and an attacker's page
// cannot write it — so a fragment DELIVERED to a victim who never started an
// SSO login (login-CSRF / session fixation) is refused.
export const SSO_STATE_KEY = "netops.ssoState";

function newSSOState(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// SSO_PENDING_COOKIE is the JS-readable, single-use fallback nonce the backend
// sets ONLY on bookmark / IdP-initiated logins (Okta dashboard tile → the full
// page navigates straight to /api/auth/sso/login, so ssoLoginUrl() never ran to
// arm SSO_STATE_KEY). captureSSORedirect() reads and clears it and requires it
// to equal the `state` echoed in the callback fragment, so the token is still
// bound to a browser that actually hit /sso/login. Kept in sync with
// oidc.go's ssoPendingCookie.
const SSO_PENDING_COOKIE = "netops_sso_pending";

// takeSSOPendingCookie reads the bookmark-login fallback nonce and clears it
// (single-use), matching the backend cookie's Path=/. Returns null when absent.
function takeSSOPendingCookie(): string | null {
  let val: string | null = null;
  try {
    const pref = SSO_PENDING_COOKIE + "=";
    for (const part of document.cookie.split(";")) {
      const c = part.trim();
      if (c.startsWith(pref)) {
        val = decodeURIComponent(c.slice(pref.length));
        break;
      }
    }
    if (val) {
      document.cookie = SSO_PENDING_COOKIE + "=; Path=/; Max-Age=0; SameSite=Lax";
    }
  } catch { /* document.cookie unavailable -> null -> fail closed */ }
  return val || null;
}

// captureSSORedirect inspects the URL fragment the SSO callback redirects to
// (#token=…&refresh=…&sso=1, or #sso_error=…) and, on success, stores the
// session and clears the fragment. Call once at startup before rendering.
// Returns an error string when the SSO round-trip failed, else null.
//
// M20 (login-CSRF / session fixation): the fragment used to be accepted
// unconditionally — any page that navigated this browser to
// app/#token=<attacker's own session> silently signed the victim into the
// attacker's account (and overwrote a real session). Now the token is accepted
// only when THIS tab initiated the SSO login (pending SSO_STATE_KEY nonce,
// consumed single-use), and — once the backend echoes the nonce back in the
// fragment as `state` — only when it round-tripped unchanged. Fail closed:
// no pending nonce, or a mismatched echo, drops the fragment and stores nothing.
export function captureSSORedirect(): string | null {
  const hash = window.location.hash.replace(/^#/, "");
  if (!hash.includes("token=") && !hash.includes("sso_error=")) return null;
  const p = new URLSearchParams(hash);
  const clear = () => history.replaceState(null, "", window.location.pathname + window.location.search);
  // The nonce is single-use: take it out of storage no matter how we exit.
  let pending: string | null = null;
  try {
    pending = sessionStorage.getItem(SSO_STATE_KEY);
    sessionStorage.removeItem(SSO_STATE_KEY);
  } catch { /* sessionStorage unavailable -> pending stays null -> fail closed */ }
  const err = p.get("sso_error");
  if (err) {
    clear();
    return err;
  }
  const token = p.get("token");
  const refresh = p.get("refresh");
  // Bookmark / IdP-initiated login (Okta dashboard tile): ssoLoginUrl() never
  // ran, so SSO_STATE_KEY is empty. Fall back to the single-use cookie the
  // backend set on /sso/login. An attacker who delivers a #token= fragment to a
  // victim who never hit /sso/login has neither the sessionStorage nonce nor the
  // cookie, so this still fails closed.
  let fromCookie = false;
  if (!pending) {
    const c = takeSSOPendingCookie();
    if (c) {
      pending = c;
      fromCookie = true;
    }
  }
  if (!pending) {
    // Token fragment with no matching login started from this tab: forged or
    // replayed. Drop it (and never overwrite an existing session with it).
    clear();
    return "SSO sign-in was not started from this browser tab — please sign in again.";
  }
  const echoed = p.get("state");
  // Bookmark path: the backend ALWAYS echoes the cookie value as `state`, so
  // require an exact match. SP-initiated path is unchanged (lenient if the
  // backend echoed nothing, exact match when it did).
  const echoMismatch = fromCookie
    ? echoed !== pending
    : (echoed !== null && echoed !== pending);
  if (echoMismatch) {
    clear();
    return "SSO state mismatch — please sign in again.";
  }
  if (token) {
    sweepScopedUIState(); // previous principal's UI state must not leak in (M21)
    setToken(token);
    setRefresh(refresh);
    markFreshLogin();
    clear();
  }
  return null;
}

// When a refresh is rejected because the server-side SESSION ended (idle /
// absolute / revoked), the backend returns a machine code. We stash it so the
// Login screen can explain WHY the user landed there ("signed out due to
// inactivity"), then the normal clear-and-redirect flow takes over. We never
// retry refresh on these — the session is gone, not the access token.
const SESSION_END_KEY = "netops.sessionEnd";
function setSessionEndCode(code: string) {
  try { sessionStorage.setItem(SESSION_END_KEY, code); } catch { /* ignore */ }
}
export function takeSessionEndMessage(): string | null {
  let code: string | null = null;
  try {
    code = sessionStorage.getItem(SESSION_END_KEY);
    if (code) sessionStorage.removeItem(SESSION_END_KEY);
  } catch { /* ignore */ }
  if (!code) return null;
  switch (code) {
    case "SESSION_IDLE_TIMEOUT": return "You were signed out due to inactivity.";
    case "SESSION_ABSOLUTE_TIMEOUT": return "Your session reached its time limit — please sign in again.";
    case "SESSION_REVOKED": return "Your session was ended — please sign in again.";
    default: return "Your session has expired — please sign in again.";
  }
}

// Single-flight refresh: many requests can 401 at once; only one /refresh runs.
let refreshInFlight: Promise<boolean> | null = null;
async function doRefresh(rt: string): Promise<boolean> {
  try {
    const res = await fetch("/api/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: rt }),
    });
    if (!res.ok) {
      // Surface a session-end reason (idle/absolute/revoked) for the Login screen.
      try {
        const err = await res.json();
        if (err && typeof err.code === "string" && err.code.startsWith("SESSION_")) {
          setSessionEndCode(err.code);
        }
      } catch { /* non-JSON error body — ignore */ }
      return false;
    }
    const data = await res.json();
    setToken(data.token);
    setRefresh(data.refresh_token);
    return true;
  } catch {
    return false;
  }
}
function tryRefresh(): Promise<boolean> {
  const rt = getRefresh();
  if (!rt) return Promise.resolve(false);
  if (!refreshInFlight) {
    refreshInFlight = doRefresh(rt).finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

type AuthListener = (signedIn: boolean) => void;
const authListeners = new Set<AuthListener>();
export function onAuthChange(fn: AuthListener): () => void {
  authListeners.add(fn);
  return () => authListeners.delete(fn);
}
function fireAuthChange(signedIn: boolean) {
  for (const fn of authListeners) fn(signedIn);
}

// ---- Active scope (the top-bar Org|Region|Tenant selector) ----------------
// The selected tenant is carried on EVERY API call as X-Acting-Tenant; the
// backend's withActingTenant narrows the caller to that scope IFF it is one the
// principal is bound to (it can only narrow, never widen — server-validated).
// Empty = the caller's default view (home tenant, or cross for the platform
// owner). Persisted so a returning multi-scope user lands where they left off.
const ACTIVE_SCOPE_KEY = "netops.activeScope";
export function getActiveScope(): string {
  try { return localStorage.getItem(ACTIVE_SCOPE_KEY) || ""; } catch { return ""; }
}
export function setActiveScope(tenantId: string) {
  try {
    if (tenantId) localStorage.setItem(ACTIVE_SCOPE_KEY, tenantId);
    else localStorage.removeItem(ACTIVE_SCOPE_KEY);
  } catch { /* ignore storage errors */ }
}


/**
 * Serializes the shared security-finding filter set. Undefined/empty values are
 * DROPPED rather than sent blank, so an unset filter never narrows the server's
 * query by accident; `current` is sent explicitly (true|false) because the
 * current-vs-history toggle is a real, user-visible choice, not a default.
 */
export function secFindingParams(q: SecFindingQuery): string {
  const p = new URLSearchParams();
  if (q.cursor) p.set("cursor", q.cursor);
  if (q.limit !== undefined) p.set("limit", String(q.limit));
  if (q.severity) p.set("severity", q.severity);
  if (q.status) p.set("status", q.status);
  if (q.seam) p.set("seam", q.seam);
  if (q.framework) p.set("framework", q.framework);
  if (q.device) p.set("device", q.device);
  if (q.q) p.set("q", q.q);
  if (q.since) p.set("since", q.since);
  if (q.until) p.set("until", q.until);
  if (q.current !== undefined) p.set("current", q.current ? "true" : "false");
  return p.toString();
}

async function request<T>(path: string, init?: RequestInit, retried = false): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const scope = getActiveScope();
  if (scope && !headers["X-Acting-Tenant"]) headers["X-Acting-Tenant"] = scope;

  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    // Access token expired? Trade the refresh token for a fresh one and retry
    // the original request exactly once. Skip for the auth endpoints themselves.
    const isAuthEndpoint = path.startsWith("/api/auth/login") || path.startsWith("/api/auth/refresh");
    if (!retried && !isAuthEndpoint && getRefresh()) {
      if (await tryRefresh()) return request<T>(path, init, true);
    }
    // Refresh unavailable/failed — clear and notify so App swaps to Login.
    // clearSession (not bare setToken/setRefresh): this path must sweep the
    // same per-scope UI state logout sweeps, or the kpihist family survives
    // an expired session on a shared browser (M21).
    if (token || getRefresh()) {
      clearSession();
      fireAuthChange(false);
    }
    const text = await res.text().catch(() => "");
    throw new Error(`401 Unauthorized: ${text || "please sign in"}`);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// ---- auth types ----
export type AuthUser = {
  username: string;
  role: string;
  tenant_id?: string;
  // platform_admin = the cross-tenant platform owner. Gates infra-stack
  // monitoring + platform-wide admin in the UI. Mirrors the backend rule.
  platform_admin?: boolean;
  grafana_enabled?: boolean;
  // org_id = the organization the caller belongs to (its tenant's org; Global
  // for the platform owner).
  org_id?: string;
  // PBAC: the scopes the principal may act in — feeds the top-bar scope selector.
  // all_tenants=true ⇒ platform owner (reaches every tenant).
  accessible_tenants?: string[];
  all_tenants?: boolean;
  org_admin_of?: string[];
  // auth_source = how the account authenticates: local | oidc | saml | ldap |
  // tacacs. Only local accounts can change their password in-app (federated
  // passwords live at the IdP). Empty/undefined = legacy local account.
  auth_source?: string;
  last_login_at?: string;
  // Administratively-configured default landing route (tenant default → platform
  // default). The SPA applies it on a fresh open if it resolves to an accessible leaf.
  default_landing?: string;
};
export type LoginResponse = { token: string; refresh_token?: string; expires_in?: number; user: AuthUser };

// downloadResponse turns a fetch Response body into a browser file download.
async function downloadResponse(res: Response, filename: string): Promise<void> {
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export interface CloudIngestionSource {
  source_type: string;
  status: string;
  volume?: number;
  last_seen_iso?: string;
  capability?: "available" | "planned";
  // Poller-reported error context (Wave 2 #4): when status is
  // permission_denied/misconfigured, what failed and since when.
  detail?: string;
  since_iso?: string;
}

// Provenance of each inventory source file, measured by the backend from the
// live-poller collection stamp (cloud/provider.go ConnectorInfo). Drives the
// data-mode badge: "live" only when the poller actually wrote the inventory.
export interface CloudConnectorInfo {
  provider: string;
  account_id: string;
  kind: "live" | "fixture";
  collected_at?: string;
  resource_count: number;
}

// Live per-app health/traffic enrichment served alongside the app inventory —
// measured from provider status checks, probe outcomes and flow bytes.
export interface CloudAppLive {
  health?: string;
  health_basis?: string;
  traffic_bytes?: number;
}

// ---- Cloud Connectors (onboarding wizard, backlog Wave 1 #3) ----
// Trust-metadata projections of the done 7-step connector API — NEVER a secret.
// Mirrors src/backend/cloud_connectors_handlers.go + cloudconn/*.go.
// CloudProvider is an OPEN token (Wave 5 #17 extensibility): the provider set
// comes from the backend registry via /api/cloud/providers, and the frontend
// resolves display metadata through pages/appobs/providers.tsx — so a newly
// registered provider needs no type edit here. "aws" | "azure" | "gcp" today.
export type CloudProvider = string;
export type CloudAuthMethod =
  | "workload_identity_federation"
  | "cloud_role"
  | "certificate"
  | "client_secret"
  | "static_key"
  | "admin_password";
// Connector lifecycle (cloudconn/connection.go). "" only pre-create.
export type CloudLifecycleState =
  | "DRAFT" | "DEPLOYING" | "VALIDATING" | "ACTIVE" | "DEGRADED"
  | "REAUTHORIZATION_REQUIRED" | "DISABLED" | "REVOKED" | "DELETING" | "";

export interface CloudScope {
  type: string;                 // account|subscription|project|region|vpc|…
  ref: string;                  // provider-native id
  display?: string;
  regions?: string[];
  discovered?: boolean;
}
export interface CloudCapability {
  key: string; title: string; apis: string[]; permissions: string[];
  read_only: boolean; data_collected: string; rca_value: string;
}
export interface CloudCapabilityPack {
  id: string; version: string; provider: CloudProvider; title: string;
  summary: string; read_only: boolean; capabilities: CloudCapability[];
}
export interface CloudProviderMethod {
  method: CloudAuthMethod; rank: number;
  federated: boolean; legacy: boolean; recommended: boolean;
}
export interface CloudProviderCatalogEntry {
  provider: CloudProvider;
  display_name?: string;
  short_label?: string;
  setup_doc_key?: string;
  has_flow_logs?: boolean;
  has_health_lane?: boolean;
  methods: CloudProviderMethod[];
  scope_types: string[];
  org_scope_types?: string[];   // org-level anchor kinds (Wave 5 #17)
  member_scope_type?: string;   // what org enumeration yields
  capability_packs: CloudCapabilityPack[];
}
// Org-level (multi-account) enrollment anchor — non-secret deployment metadata.
export interface CloudOrgScope {
  type: string;           // org | ou | mgmt_group | folder
  ref: string;            // org / management-group / folder id
  role_template?: string; // member-account role name (default correlix-observer)
}
export interface CloudConnHealth { state: string; detail?: string; checked?: string; }
export interface CloudConnFinding {
  severity: "error" | "warning" | "info";
  code: string; message: string; remediation?: string;
}
export interface CloudConnValidation { ok: boolean; findings: CloudConnFinding[] | null; }
export interface CloudConnIdentity {
  role_arn?: string; external_id?: string; azure_tenant_id?: string; client_id?: string;
  audience?: string; issuer?: string; federated_subject?: string; cert_thumbprint?: string;
  project_number?: string; workload_pool?: string; workload_provider?: string;
  service_account?: string; has_legacy_secret: boolean; legacy_key_hint?: string;
  org?: CloudOrgScope | null;
}
export interface CloudConnectorView {
  id: string; provider: CloudProvider; display_name: string;
  auth_method: CloudAuthMethod | ""; auth_federated: boolean; auth_legacy: boolean;
  capability_pack: string; state: CloudLifecycleState; collecting: boolean;
  identity: CloudConnIdentity; scopes: CloudScope[] | null;
  identity_health: CloudConnHealth; telemetry_health: CloudConnHealth;
  last_validation: CloudConnValidation; version: number;
  created_at: string; updated_at: string;
}
export interface CloudSetupArtifact { kind: string; title: string; format: string; content: string; }
export interface CloudSetupBundle {
  provider: CloudProvider; method: CloudAuthMethod; summary: string;
  steps: string[]; artifacts: CloudSetupArtifact[];
}
// The live validate result: pure config findings + the LIVE trust-proof marker
// ("ok" | "deferred" | "failed") from the Identity Broker exchange.
export interface CloudConnValidateResult {
  connector: CloudConnectorView;
  validation: CloudConnValidation;
  live_check: "ok" | "deferred" | "failed" | string;
}
// The identity-trust fields the operator supplies on the auth step. The TENANT and
// the ExternalId are NEVER set here — the backend stamps the owner from the token
// and mints the ExternalId itself (confused-deputy protection).
export interface CloudAuthInput {
  method: CloudAuthMethod;
  role_arn?: string;
  azure_tenant_id?: string; client_id?: string; audience?: string;
  issuer?: string; federated_subject?: string; cert_thumbprint?: string;
  project_number?: string; workload_pool?: string; workload_provider?: string;
  service_account?: string;
}

const ccnPath = (id: string, action = ""): string =>
  `/api/cloud/connectors/${encodeURIComponent(id)}${action ? "/" + action : ""}`;


// ---- BGP Operations (item 10, 2026-08-25) ----------------------------------
export type BgpWatchEntry = { resource: string; kind: "prefix" | "asn"; note: string; added_by: string; created_at: string };
export type BgpRoutingStatus = {
  announced?: boolean;
  last_seen?: { origin?: string; prefix?: string; time?: string };
  visibility?: {
    v4?: { total_ris_peers?: number; ris_peers_seeing?: number };
    v6?: { total_ris_peers?: number; ris_peers_seeing?: number };
  };
  observed_neighbours?: number;
};
export type BgpRpki = { status?: string; validating_roas?: { origin?: string; prefix?: string; max_length?: number; validity?: string }[] };
export type BgpPaths = { rrcs?: { rrc?: string; location?: string; peers?: { asn_origin?: string; as_path?: string; last_updated?: string }[] }[] };
export type BgpStatusResp = {
  resource: string; kind: "prefix" | "asn";
  routing_status?: BgpRoutingStatus; routing_status_error?: string;
  rpki?: BgpRpki; rpki_origin?: string; rpki_error?: string;
  paths?: BgpPaths; paths_error?: string;
};
export type BgpUpdatesResp = {
  resource: string;
  updates: { updates?: { type?: string; timestamp?: string; attrs?: { path?: number[]; source_id?: string } }[]; nr_updates?: number };
};

// ---- Telemetry coverage / parser stats (parser programme A6) ---------------
// Three endpoints, exactly as contracted — nothing invented beyond them.
//   GET  /api/admin/parser/stats                          (platform admin only)
//   GET  /api/telemetry/unrecognized?days&limit&lane      (tenant-scoped)
//   POST /api/telemetry/unrecognized/{template_id}/propose(tenant, alerts:write)
// The propose call returns a DRAFT catalog row generated deterministically from
// the template — there is NO model in this path, and the UI applies nothing.
export type ParserLane = "syslog" | "trap" | "port";
export type ParserFidelity = "code" | "doc_claimed" | "lab_validated" | "live_validated";

export type ParserRuleStat = {
  rule_id: string;
  lane: ParserLane;
  kind: string;
  fidelity: ParserFidelity;
  hits: number;
  shadow: boolean;
};

export type ParserStats = {
  parser_rev: string;
  rules_hash: string;
  generated_at: string;
  // null = no admitted lines in the window yet. NEVER coerce it to 0 — "no data"
  // and "0% promoted" are different facts (honest-empty rule).
  promotion_rate: number | null;
  window_lines: number;
  prefilter: { passed: number; rejected: number };
  generic_fallback: { syslog: number; trap: number };
  rules: ParserRuleStat[];
};

export type UnrecognizedItem = {
  template_id: string;
  // Masked template text with <*> wildcards. Rendered as ESCAPED text in a mono
  // cell — never as markup (§15 LLM02 applies to any untrusted string).
  template: string;
  count: number;
  devices: number;
  severity_max: number;
  first_seen: string;
  last_seen: string;
  sample: string;
  appname?: string;
  mnemonic?: string;
};

export type UnrecognizedPage = {
  generated_at: string;
  days: number;
  items: UnrecognizedItem[];
  total: number;
  // Honest state carried by the backend, e.g. "mining not yet run" or
  // "no unrecognized lines in window". Rendered verbatim, never swallowed.
  note?: string;
};

export type CatalogProposal = {
  proposal_id: string;
  status: "drafted";
  catalog_row: string; // YAML text — shown read-only, copied, never executed
  fixture: string;
};

export type UnrecognizedQuery = { days?: number; limit?: number; lane?: "syslog" | "trap" };

/** Query string for the unrecognized-shapes endpoint. Only the three contracted
 *  params are ever sent; everything goes through URLSearchParams. */
export function unrecognizedParams(q: UnrecognizedQuery = {}): string {
  const p = new URLSearchParams();
  if (q.days !== undefined) p.set("days", String(q.days));
  if (q.limit !== undefined) p.set("limit", String(q.limit));
  if (q.lane) p.set("lane", q.lane);
  return p.toString();
}

export const api = {
  // ---- BGP Operations (item 10) ----
  bgpWatchlist: () => request<{ watchlist: BgpWatchEntry[] }>("/api/bgp/watchlist"),
  bgpWatchAdd: (resource: string, note = "") =>
    request<{ ok: boolean; resource: string; kind: string }>("/api/bgp/watchlist", {
      method: "POST", body: JSON.stringify({ resource, note }),
    }),
  bgpWatchDelete: (resource: string) =>
    request<{ ok: boolean }>(`/api/bgp/watchlist?resource=${encodeURIComponent(resource)}`, { method: "DELETE" }),
  bgpStatus: (resource: string) =>
    request<BgpStatusResp>(`/api/bgp/resource?resource=${encodeURIComponent(resource)}&view=status`),
  bgpUpdates: (resource: string, hours = 8) =>
    request<BgpUpdatesResp>(`/api/bgp/resource?resource=${encodeURIComponent(resource)}&view=updates&hours=${hours}`),
  bgpWhois: (resource: string) =>
    request<{ resource: string; rdap: unknown }>(`/api/bgp/resource?resource=${encodeURIComponent(resource)}&view=whois`),

  // ---- tenant display preferences (Wave 4 #11: time display, per-tenant) ----
  getDisplaySettings: () =>
    request<{ tenant_id: string; time_display: "local" | "utc" }>("/api/settings/display"),
  setDisplaySettings: (timeDisplay: "local" | "utc") =>
    request<{ tenant_id: string; time_display: "local" | "utc" }>("/api/settings/display", {
      method: "PUT", body: JSON.stringify({ time_display: timeDisplay }),
    }),

  // ---- tenant governance settings (Wave 4 #11: real Settings editors) ----
  // Required tags — the per-tenant list that drives missingTags + the coverage
  // compliance report. PUT is admin-gated + audited server-side.
  getRequiredTags: () => request<RequiredTagsSettings>("/api/settings/required-tags"),
  setRequiredTags: (tags: string[]) =>
    request<RequiredTagsSettings>("/api/settings/required-tags", {
      method: "PUT", body: JSON.stringify({ required_tags: tags }),
    }),
  resetRequiredTags: () =>
    request<RequiredTagsSettings>("/api/settings/required-tags", {
      method: "PUT", body: JSON.stringify({ reset: true }),
    }),
  // RCA window — the tenant's default read window (hours) for the cloud
  // signal/RCA surfaces when a view names none. Server clamps to 1..168.
  getRcaWindow: () => request<RcaWindowSettings>("/api/settings/rca-window"),
  setRcaWindow: (hours: number) =>
    request<RcaWindowSettings>("/api/settings/rca-window", {
      method: "PUT", body: JSON.stringify({ rca_window_hours: hours }),
    }),
  resetRcaWindow: () =>
    request<RcaWindowSettings>("/api/settings/rca-window", {
      method: "PUT", body: JSON.stringify({ reset: true }),
    }),
  // Attribution precedence — tenant ordering of the resolver's precedence
  // classes (must be a permutation of the server's known classes).
  getAttributionPrecedence: () =>
    request<AttributionPrecedenceSettings>("/api/settings/attribution-precedence"),
  setAttributionPrecedence: (order: string[]) =>
    request<AttributionPrecedenceSettings>("/api/settings/attribution-precedence", {
      method: "PUT", body: JSON.stringify({ attribution_precedence: order }),
    }),
  resetAttributionPrecedence: () =>
    request<AttributionPrecedenceSettings>("/api/settings/attribution-precedence", {
      method: "PUT", body: JSON.stringify({ reset: true }),
    }),
  // Seam-ownership registry (#113) — owner class → the tenant's actual
  // responsible party, joined into RCA ownership + ticket assignment.
  getSeamOwners: () => request<SeamOwnersSettings>("/api/settings/seam-owners"),
  setSeamOwners: (owners: Record<string, SeamOwnerEntry>) =>
    request<SeamOwnersSettings>("/api/settings/seam-owners", {
      method: "PUT", body: JSON.stringify({ seam_owners: owners }),
    }),
  resetSeamOwners: () =>
    request<SeamOwnersSettings>("/api/settings/seam-owners", {
      method: "PUT", body: JSON.stringify({ reset: true }),
    }),
  // Recent governance-settings changes (who/when/what) — admin-gated,
  // scoped server-side to the caller's audit visibility.
  getGovernanceAudit: (limit = 50) =>
    request<{ events: GovernanceAuditEvent[]; count: number }>(
      `/api/settings/governance-audit?limit=${limit}`),

  // ---- auth ----
  // Returns { mfaRequired:false } on success (session set), or
  // { mfaRequired:true, mfaToken } when the account has MFA — complete via mfaLogin,
  // or { mustChangePassword:true } when the account's Security Settings withhold
  // the session until the password is reset (F-68: password expiry /
  // reset-on-first-login). In that last case there is NO token in the response —
  // falling through to setToken(undefined) would leave the SPA believing it was
  // signed in with an empty credential.
  login: async (username: string, password: string): Promise<{
    mfaRequired: boolean; mfaToken?: string;
    mustChangePassword?: boolean; message?: string;
  }> => {
    const r = await request<LoginResponse & {
      mfa_required?: boolean; mfa_token?: string;
      must_change_password?: boolean; reason?: string; message?: string;
    }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    if (r.mfa_required && r.mfa_token) return { mfaRequired: true, mfaToken: r.mfa_token };
    if (r.must_change_password) {
      return { mfaRequired: false, mustChangePassword: true, message: r.message };
    }
    sweepScopedUIState(); // previous principal's UI state must not leak in (M21)
    setToken(r.token);
    setRefresh(r.refresh_token ?? null);
    markFreshLogin();
    fireAuthChange(true);
    return { mfaRequired: false };
  },
  // Complete the login MFA challenge with the one-time code → issues the session.
  mfaLogin: async (mfaToken: string, code: string) => {
    const r = await request<LoginResponse>("/api/auth/mfa/login", {
      method: "POST",
      body: JSON.stringify({ mfa_token: mfaToken, code }),
    });
    sweepScopedUIState(); // previous principal's UI state must not leak in (M21)
    setToken(r.token);
    setRefresh(r.refresh_token ?? null);
    markFreshLogin();
    fireAuthChange(true);
    return r;
  },
  // MFA self-service (authed).
  mfaStatus: () => request<{ enabled: boolean; pending: boolean; local: boolean }>("/api/auth/mfa/status"),
  mfaSetup: () => request<{ secret: string; uri: string }>("/api/auth/mfa/setup", { method: "POST" }),
  mfaActivate: (code: string) => request<{ enabled: boolean }>("/api/auth/mfa/activate", { method: "POST", body: JSON.stringify({ code }) }),
  mfaDisable: (code: string) => request<{ enabled: boolean }>("/api/auth/mfa/disable", { method: "POST", body: JSON.stringify({ code }) }),
  // Admin recovery: clear a user's MFA (lost device).
  adminResetMfa: (username: string) => request<{ enabled: boolean }>("/api/users/mfa-reset", { method: "POST", body: JSON.stringify({ username }) }),
  logout: async () => {
    const rt = getRefresh();
    if (rt) {
      // Best-effort server-side revoke of the refresh token.
      await fetch("/api/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: rt }),
      }).catch(() => {});
    }
    // Tokens + per-scope UI state (kpihist family, active scope) in one sweep —
    // shared with the 401 clear path so the two can never drift apart (M21).
    clearSession();
    fireAuthChange(false);
  },
  // SSO (OIDC/SAML/LDAP via Keycloak). Config is public; the login flow is a
  // full-page redirect (the browser must follow 302s to the IdP and back).
  ssoConfig: () => request<SSOConfig>("/api/auth/sso/config"),
  // ssoLoginUrl mints the browser-side login-CSRF nonce (M20) and carries it as
  // `fe_state` — the backend should thread it through its SSO transaction and
  // echo it back in the callback fragment as `state` (captureSSORedirect
  // verifies the round-trip). Until the backend echoes it, the nonce still
  // proves "this tab started an SSO login", which is what blocks a delivered
  // fragment. Call ONLY when actually navigating (it arms the nonce).
  ssoLoginUrl: (idp?: string) => {
    const st = newSSOState();
    try { sessionStorage.setItem(SSO_STATE_KEY, st); } catch { /* fail closed at capture */ }
    const qs = new URLSearchParams();
    if (idp) qs.set("idp", idp);
    qs.set("fe_state", st);
    return `/api/auth/sso/login?${qs.toString()}`;
  },

  // Auth-method discovery for the login page (which sign-in options are enabled).
  authMethods: () => request<AuthMethods>("/api/auth/methods"),

  // Direct (native) LDAP / TACACS+ logins — same session-issuing contract as login().
  ldapLogin: async (username: string, password: string) => {
    const r = await request<LoginResponse>("/api/auth/ldap/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    sweepScopedUIState(); // previous principal's UI state must not leak in (M21)
    setToken(r.token);
    setRefresh(r.refresh_token ?? null);
    markFreshLogin();
    fireAuthChange(true);
    return r;
  },
  tacacsLogin: async (username: string, password: string) => {
    const r = await request<LoginResponse>("/api/auth/tacacs/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    sweepScopedUIState(); // previous principal's UI state must not leak in (M21)
    setToken(r.token);
    setRefresh(r.refresh_token ?? null);
    markFreshLogin();
    fireAuthChange(true);
    return r;
  },

  // SSO/OIDC admin config (admin-gated; the client secret is write-only on the
  // server). GET/PUT return the redacted config plus whether the provider is ready.
  oidcConfig: () => request<{ config: OidcConfig; ready: boolean }>("/api/auth/oidc/config"),
  saveOidcConfig: (cfg: Partial<OidcConfig> & { client_secret?: string }) =>
    request<{ config: OidcConfig; ready: boolean }>("/api/auth/oidc/config", { method: "PUT", body: JSON.stringify(cfg) }),

  // GUI-configurable SSO — Keycloak-brokered identity providers (platform-admin
  // gated). The client secret is write-only (GET returns client_secret_set);
  // PUT reports whether the change was applied to Keycloak plus any warnings
  // (e.g. Keycloak unreachable → saved but not applied).
  ssoIdps: () => request<SsoIdpListResponse>("/api/auth/sso/idp"),
  saveSsoIdp: (idp: SsoIdP) =>
    request<SsoIdpSaveResponse>(`/api/auth/sso/idp/${encodeURIComponent(idp.alias)}`, { method: "PUT", body: JSON.stringify(idp) }),
  deleteSsoIdp: (alias: string) =>
    request<void>(`/api/auth/sso/idp/${encodeURIComponent(alias)}`, { method: "DELETE" }),
  testSsoIdp: (alias: string) =>
    request<SsoIdpTestResult>(`/api/auth/sso/idp/${encodeURIComponent(alias)}/test`, { method: "POST" }),

  // Native-provider admin config (admin-gated; secrets are write-only on the server).
  ldapConfig: () => request<{ config: LdapConfig }>("/api/auth/ldap/config"),
  saveLdapConfig: (cfg: Partial<LdapConfig> & { bind_password?: string }) =>
    request<{ config: LdapConfig }>("/api/auth/ldap/config", { method: "PUT", body: JSON.stringify(cfg) }),
  testLdap: (username?: string, password?: string) =>
    request<AuthTestResult>("/api/auth/ldap/test", { method: "POST", body: JSON.stringify({ username, password }) }),
  tacacsConfig: () => request<{ config: TacacsConfig }>("/api/auth/tacacs/config"),
  saveTacacsConfig: (cfg: Partial<TacacsConfig> & { secret?: string }) =>
    request<{ config: TacacsConfig }>("/api/auth/tacacs/config", { method: "PUT", body: JSON.stringify(cfg) }),
  testTacacs: (username?: string, password?: string) =>
    request<AuthTestResult>("/api/auth/tacacs/test", { method: "POST", body: JSON.stringify({ username, password }) }),

  // Token policy (access/refresh lifetimes) — admin-gated, clamped server-side.
  tokenPolicy: () => request<TokenPolicy>("/api/auth/token-policy"),
  saveTokenPolicy: (p: { access_ttl_seconds: number; refresh_ttl_seconds: number }) =>
    request<TokenPolicy>("/api/auth/token-policy", { method: "PUT", body: JSON.stringify(p) }),

  me: () => request<AuthUser>("/api/auth/me"),
  // username is supplied only by the unauthenticated login-window flow; omit it
  // when already signed in (the server takes the account from the token).
  changePassword: (current_password: string, new_password: string, username?: string) =>
    request<{ status: string }>("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify(username ? { username, current_password, new_password } : { current_password, new_password }),
    }),

  // The caller's resolved password rules (Security Policy #24) — advisory; the
  // server re-validates authoritatively on change.
  passwordPolicy: () =>
    request<{ min_length: number; complexity_classes: number }>("/api/auth/password-policy"),

  health: () => request<Health>("/api/health"),
  stackHealth: () => request<StackHealth>("/api/stack/health"),
  audit: (limit = 200) => request<AuditEvent[]>(`/api/audit?limit=${limit}`),

  // Notification channels (UI-configurable; secrets write-only). _set booleans
  // tell the form whether a secret is stored without revealing it.
  smtpConfig: () => request<SmtpConfig>("/api/notify/smtp"),
  saveSmtpConfig: (c: Partial<SmtpConfig>) => request<SmtpConfig>("/api/notify/smtp", { method: "PUT", body: JSON.stringify(c) }),
  testSmtp: () => request<{ status: string }>("/api/notify/smtp/test", { method: "POST" }),
  twilioConfig: () => request<TwilioConfig>("/api/notify/twilio"),
  saveTwilioConfig: (c: Partial<TwilioConfig>) => request<TwilioConfig>("/api/notify/twilio", { method: "PUT", body: JSON.stringify(c) }),
  testTwilio: () => request<{ status: string }>("/api/notify/twilio/test", { method: "POST" }),
  ntfyConfig: () => request<NtfyConfig>("/api/notify/ntfy"),
  saveNtfyConfig: (c: Partial<NtfyConfig>) => request<NtfyConfig>("/api/notify/ntfy", { method: "PUT", body: JSON.stringify(c) }),
  testNtfy: () => request<{ status: string }>("/api/notify/ntfy/test", { method: "POST" }),
  slackConfig: () => request<SlackConfig>("/api/notify/slack"),
  saveSlackConfig: (c: Partial<SlackConfig>) => request<SlackConfig>("/api/notify/slack", { method: "PUT", body: JSON.stringify(c) }),
  testSlack: () => request<{ status: string }>("/api/notify/slack/test", { method: "POST" }),
  pagerDutyConfig: () => request<PagerDutyConfig>("/api/notify/pagerduty"),
  savePagerDutyConfig: (c: Partial<PagerDutyConfig>) => request<PagerDutyConfig>("/api/notify/pagerduty", { method: "PUT", body: JSON.stringify(c) }),
  testPagerDuty: () => request<{ status: string }>("/api/notify/pagerduty/test", { method: "POST" }),
  // Teams + SNS (G10). Same platform-gated GET/PUT/test shape as the five
  // above; a PUT that omits `webhook_url` keeps the stored Teams secret.
  notifyTeams: () => request<TeamsConfig>("/api/notify/teams"),
  notifyTeamsUpdate: (c: Partial<TeamsConfig>) => request<TeamsConfig>("/api/notify/teams", { method: "PUT", body: JSON.stringify(c) }),
  notifyTeamsTest: () => request<{ status: string }>("/api/notify/teams/test", { method: "POST" }),
  notifySNS: () => request<SNSConfig>("/api/notify/sns"),
  notifySNSUpdate: (c: Partial<SNSConfig>) => request<SNSConfig>("/api/notify/sns", { method: "PUT", body: JSON.stringify(c) }),
  notifySNSTest: () => request<{ status: string }>("/api/notify/sns/test", { method: "POST" }),

  // Contact points — reusable, tenant-scoped delivery audiences (email group /
  // slack / webhook) referenced by reports. Managed in the Notifications section.
  contactPoints: () => request<ContactPoint[]>("/api/notify/contact-points"),
  saveContactPoint: (c: Partial<ContactPoint>) =>
    c.id
      ? request<ContactPoint>(`/api/notify/contact-points/${encodeURIComponent(c.id)}`, { method: "PUT", body: JSON.stringify(c) })
      : request<ContactPoint>("/api/notify/contact-points", { method: "POST", body: JSON.stringify(c) }),
  deleteContactPoint: (id: string) => request<void>(`/api/notify/contact-points/${encodeURIComponent(id)}`, { method: "DELETE" }),
  snmpProfiles: () => request<SnmpProfile[]>("/api/snmp/profiles"),
  addSnmpProfileMetrics: (id: string, metrics: SnmpMetric[]) =>
    request<SnmpProfile>(`/api/snmp/profiles/${encodeURIComponent(id)}/metrics`, {
      method: "POST",
      body: JSON.stringify(metrics),
    }),
  upsertSnmpProfile: (p: Partial<SnmpProfile>) =>
    request<SnmpProfile>("/api/snmp/profiles", { method: "POST", body: JSON.stringify(p) }),
  deleteSnmpProfile: (id: string) =>
    request<void>(`/api/snmp/profiles/${encodeURIComponent(id)}`, { method: "DELETE" }),
  devices: () => request<Device[]>("/api/devices"),

  // Port Intelligence (#94) — the interfaces/ports/optics workbench.
  portInterfaces: (qs = "") => request<{ interfaces: PortRow[]; total: number; limit: number; offset: number }>(`/api/infrastructure/interfaces${qs ? "?" + qs : ""}`),
  portInterfaceDetail: (id: string) => request<PortRow>(`/api/infrastructure/interfaces/${encodeURIComponent(id)}`),
  portSummary: () => request<{ total_ports: number; by_state: Record<string, number>; rca_attached: number }>("/api/infrastructure/port-summary"),
  portModuleTypes: () => request<{ module_families: string[]; media_types: string[]; supported_status: string[]; detection_methods: string[] }>("/api/infrastructure/module-types"),
  portFilterOptions: () => request<Record<string, string[]>>("/api/infrastructure/port-filter-options"),
  portSignatures: () => request<{ signatures: { id: string; name: string; seams: string }[] }>("/api/infrastructure/port-signatures"),
  upsertDevice: (d: Partial<Device>) =>
    request<Device>("/api/devices", { method: "POST", body: JSON.stringify(d) }),
  deleteDevice: (id: string) =>
    request<void>(`/api/devices/${encodeURIComponent(id)}`, { method: "DELETE" }),
  collectors: () => request<CollectorStatus[]>("/api/collectors"),
  discoveryConfig: () => request<DiscoveryConfigEnvelope>("/api/discovery/config"),
  saveDiscoveryConfig: (c: DiscoveryConfigInput) =>
    request<DiscoveryConfigEnvelope>("/api/discovery/config", { method: "PUT", body: JSON.stringify(c) }),
  alerts: () => request<Alert[]>("/api/alerts"),
  // Alert episodes: grouped firings + triage. Actor is always the signed-in
  // principal (stamped server-side); mute/snooze pause notifications only.
  alertEpisodes: (status: "open" | "active" | "cleared" | "closed" | "all" = "open") =>
    request<AlertEpisodeList>(`/api/alerts/episodes?status=${encodeURIComponent(status)}`),
  episodeAck: (id: string, acknowledged: boolean) =>
    request<AlertEpisode>(`/api/alerts/episodes/${encodeURIComponent(id)}/ack`, { method: "POST", body: JSON.stringify({ acknowledged }) }),
  episodeAssign: (id: string, assignee: string) =>
    request<AlertEpisode>(`/api/alerts/episodes/${encodeURIComponent(id)}/assign`, { method: "POST", body: JSON.stringify({ assignee }) }),
  episodeMute: (id: string, muted: boolean) =>
    request<AlertEpisode>(`/api/alerts/episodes/${encodeURIComponent(id)}/mute`, { method: "POST", body: JSON.stringify({ muted }) }),
  episodeSnooze: (id: string, until: string) =>
    request<AlertEpisode>(`/api/alerts/episodes/${encodeURIComponent(id)}/snooze`, { method: "POST", body: JSON.stringify({ until }) }),
  episodeNote: (id: string, text: string) =>
    request<AlertEpisode>(`/api/alerts/episodes/${encodeURIComponent(id)}/notes`, { method: "POST", body: JSON.stringify({ text }) }),
  // Maintenance windows (item 121): declared planned-work periods. A covering
  // window pauses alert NOTIFICATIONS only (same honesty rule as mute/snooze)
  // and stamps reliability rollups as planned maintenance.
  maintenanceWindows: () =>
    request<{ windows: MaintenanceWindow[]; count: number }>("/api/alerts/maintenance-windows"),
  maintenanceWindowCreate: (body: MaintenanceWindowInput) =>
    request<MaintenanceWindow>("/api/alerts/maintenance-windows", { method: "POST", body: JSON.stringify(body) }),
  maintenanceWindowUpdate: (id: string, body: MaintenanceWindowInput) =>
    request<MaintenanceWindow>(`/api/alerts/maintenance-windows/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(body) }),
  maintenanceWindowDelete: (id: string) =>
    request<{ deleted: string }>(`/api/alerts/maintenance-windows/${encodeURIComponent(id)}`, { method: "DELETE" }),
  // Pipeline processors (item 121): structured per-tenant redact/drop/set rules
  // compiled into the ingest router. Admin-gated server-side.
  processorRules: () =>
    request<{ rules: ProcessorRule[]; count: number }>("/api/pipeline/processors"),
  processorRuleCreate: (body: ProcessorRuleInput) =>
    request<ProcessorRule>("/api/pipeline/processors", { method: "POST", body: JSON.stringify(body) }),
  processorRuleUpdate: (id: string, body: ProcessorRuleInput) =>
    request<ProcessorRule>(`/api/pipeline/processors/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(body) }),
  processorRuleDelete: (id: string) =>
    request<{ deleted: string }>(`/api/pipeline/processors/${encodeURIComponent(id)}`, { method: "DELETE" }),
  // `draft` previews an UNSAVED processor alongside the saved chain, so the
  // wizard can show the effect of the rule being written.
  processorPreview: (lane: string, event: Record<string, unknown>, draft?: ProcessorRuleInput) =>
    request<ProcessorPreview>("/api/pipeline/processors/preview", {
      method: "POST", body: JSON.stringify({ lane, event, processor: draft }),
    }),
  // The engine describes itself: registered actions/matchers + the managed-rule
  // catalog. The wizard renders from this, so a newly-registered plugin shows up
  // with no frontend change.
  processorCatalog: () => request<ProcessorCatalog>("/api/pipeline/processors/catalog"),
  processorClone: (body: { managed_rule_id: string; lane: string; field: string; order?: number }) =>
    request<ProcessorRule>("/api/pipeline/processors/clone", { method: "POST", body: JSON.stringify(body) }),
  // Reveal one sealed value. Requires sensitive_data:admin; every call is
  // audited server-side, including the refusals — `reason` is what the audit
  // trail shows a compliance reviewer, so the UI always asks for it.
  processorUnseal: (body: { value: string; reason: string; processor_id?: string; field?: string; data_type?: string }) =>
    request<{ value: string; field?: string; data_type?: string; processor_id?: string; key_version?: number }>(
      "/api/pipeline/processors/unseal", { method: "POST", body: JSON.stringify(body) }),
  // The compliance view: who revealed sensitive data, when, and why. Filtered
  // SERVER-side to reveal events — a client-side filter over a capped page
  // would render empty whenever reveals sit below the newest rows, and a
  // compliance surface that says "nobody read anything" when someone did is
  // the one failure this must not have.
  sealAccessAudit: (limit = 200) =>
    request<AuditEvent[]>(`/api/pipeline/processors/unseal/audit?limit=${limit}`),
  // Advance this tenant's sealing key. Values already sealed keep opening —
  // each names the version that sealed it.
  sealRotate: () =>
    request<{ key_version: number; note: string }>(
      "/api/pipeline/processors/seal/rotate", { method: "POST", body: "{}" }),
  processorVersions: (id: string) =>
    request<{ versions: ProcessorVersion[]; count: number }>(
      `/api/pipeline/processors/${encodeURIComponent(id)}/versions`),
  processorRollback: (id: string, version: number) =>
    request<ProcessorRule>(`/api/pipeline/processors/${encodeURIComponent(id)}/versions/${version}`, { method: "POST" }),
  rules: () => request<Rule[]>("/api/rules"),
  addRule: (r: Rule) =>
    request<Rule>("/api/rules", { method: "POST", body: JSON.stringify(r) }),
  // Only operator-created rules (labels.origin === "ui") are deletable; the
  // built-in rules-file set 404s by design.
  deleteRule: (name: string) =>
    request<void>(`/api/rules?name=${encodeURIComponent(name)}`, { method: "DELETE" }),
  credentials: () => request<Record<string, boolean>>("/api/credentials"),
  // Feature availability for any authenticated user. Distinct from credentials()
  // (platform-owner only): a non-admin asking "should I render the SSH button?"
  // must not depend on an endpoint they are not allowed to read, or a 403 shows
  // up as "the feature does not exist".
  features: () => request<Record<string, boolean>>("/api/features"),
  // Topology Operating Canvas: resolved, renderer-agnostic TopologyView for a
  // workflow mode. Typed `unknown` to keep services/api.ts decoupled from the
  // feature's contract types; the topology API client casts + normalizes it.
  topologyView: (mode: string, params?: { src?: string; dst?: string }) => {
    const qs = new URLSearchParams({ mode });
    if (params?.src) qs.set("src", params.src);
    if (params?.dst) qs.set("dst", params.dst);
    return request<unknown>(`/api/topology/view?${qs.toString()}`);
  },
  // Persistent topology graph (#77): the reconciler-maintained graph with stable
  // ids + first_seen/last_seen/stale + a coverage summary (vs the per-mode live
  // projection of topologyView). Renderer-agnostic TopologyView shape + coverage.
  topologyGraph: () => request<unknown>("/api/topology/graph"),
  // In-cloud NETWORK topology (VPC/VNet → subnets → route tables → gateways/NVAs),
  // discovered from the provider APIs and mapped to the same renderer-agnostic
  // TopologyView the canvas consumes. Tenant-scoped server-side.
  topologyCloud: () => request<unknown>("/api/topology/cloud"),
  refreshDiscovery: () =>
    request<{ status: string }>("/api/discovery/refresh", { method: "POST" }),

  // Automation → Source of Truth: NetBox discovery config (platform-owner).
  // GET is redacted (token_set bool, never the token); PUT preserves the stored
  // token when `token` is left blank.
  netboxConfig: () =>
    request<{ config: NetboxConfig }>("/api/automation/netbox"),
  saveNetboxConfig: (c: Partial<NetboxConfig>) =>
    request<{ config: NetboxConfig }>("/api/automation/netbox", { method: "PUT", body: JSON.stringify(c) }),
  // Device → NetBox write-through (push discovered devices INTO NetBox as SoT).
  netboxSyncStatus: () => request<NetboxSyncStatus>("/api/automation/netbox/sync"),
  netboxSyncNow: () => request<NetboxSyncStatus>("/api/automation/netbox/sync", { method: "POST" }),

  // Dashboard tile data — same shape /api/events emits via
  // { type: "metric_update", data: <tile> }.
  metricTiles: () =>
    request<MetricTile[]>("/api/metrics"),

  // Logs (OpenSearch)
  searchLogs: (opts: LogSearchOpts) =>
    request<OSResponse>("/api/logs/search", {
      method: "POST",
      body: JSON.stringify(opts),
    }),
  logIndices: () => request<Record<string, any>[]>("/api/logs/indices"),
  // Retention floor: how far back the caller's visible log store goes + exact
  // total stored (tenant-scoped server-side; owner directive: DON'T HIDE).
  logsRetention: (signal = "") =>
    request<LogRetention>(`/api/logs/retention${signal ? `?signal=${encodeURIComponent(signal)}` : ""}`),

  // Flows (ClickHouse). `type` filters by source family (netflow|ipfix|sflow);
  // empty = all sources. `filters` narrows by the dashboard filter bar
  // (src/dst IP, exporter device IP, ingress/egress interface); `direction=bi`
  // folds A↔B conversations into one row.
  topTalkers: (sinceSeconds = 3600, limit = 20, type = "", filters?: FlowFilters, direction = "") =>
    request<ClickHouseResponse>(
      `/api/flows/top?since=${sinceSeconds}s&limit=${limit}${type ? `&type=${type}` : ""}${flowQS(filters, direction)}`,
    ),
  // Generic top-N by a single allowlisted dimension (device | in_if | out_if |
  // src_addr | dst_addr | src_as | dst_as | src_port | dst_port | proto).
  flowsTopN: (by: string, sinceSeconds = 3600, limit = 20, type = "", filters?: FlowFilters) =>
    request<ClickHouseResponse>(
      `/api/flows/topn?by=${by}&since=${sinceSeconds}s&limit=${limit}${type ? `&type=${type}` : ""}${flowQS(filters)}`,
    ),
  // Flow fan-out for threat detection: per-source distinct dst hosts/ports
  // (scan signal). sort=hosts (horizontal) | ports (vertical).
  flowsFanout: (sort: "hosts" | "ports" = "hosts", sinceSeconds = 3600, limit = 15, type = "", filters?: FlowFilters) =>
    request<ClickHouseResponse>(
      `/api/flows/fanout?sort=${sort}&since=${sinceSeconds}s&limit=${limit}${type ? `&type=${type}` : ""}${flowQS(filters)}`,
    ),
  // Batch app-name resolution (#81 P3G): visible IPs → {ip: {app, source,
  // confidence}} through the unified resolver. Unresolved IPs are OMITTED from
  // the response. Callers should go through services/appNames.ts (debounce +
  // TTL cache) rather than calling this directly.
  appIdResolveBatch: (keys: string[]) =>
    request<Record<string, AppIdBatchVerdict>>("/api/appid/resolve/batch", {
      method: "POST",
      body: JSON.stringify({ keys }),
    }),
  // Traffic by country of the initiator (dim=src) or responder (dim=dst),
  // resolved through the server's GeoIP dictionary. Rows: {country, bytes_total,
  // packets_total, flows}; country "" = private/unmatched. The generous default
  // limit returns the full country distribution (≤ ~250) so callers can compute
  // exact shares. geo_enabled=false ⇒ dictionary not provisioned yet.
  flowsGeo: (dim: "src" | "dst", sinceSeconds = 3600, type = "", filters?: FlowFilters) =>
    request<ClickHouseResponse>(
      `/api/flows/geo?dim=${dim}&since=${sinceSeconds}s${type ? `&type=${type}` : ""}${flowQS(filters)}`,
    ),
  // TCP traffic by tcp_flags combination (tcpControlBits bitmask); the UI
  // decodes bits to SYN/ACK/FIN/RST… names. Rows: {tcp_flags, bytes_total,
  // packets_total, flows}.
  flowsFlags: (sinceSeconds = 3600, limit = 20, type = "", filters?: FlowFilters) =>
    request<ClickHouseResponse>(
      `/api/flows/flags?since=${sinceSeconds}s&limit=${limit}${type ? `&type=${type}` : ""}${flowQS(filters)}`,
    ),
  flowsByProto: (sinceSeconds = 3600, type = "", filters?: FlowFilters) =>
    request<ClickHouseResponse>(
      `/api/flows/by-proto?since=${sinceSeconds}s${type ? `&type=${type}` : ""}${flowQS(filters)}`,
    ),
  flowsByType: (sinceSeconds = 3600) =>
    request<ClickHouseResponse>(`/api/flows/by-type?since=${sinceSeconds}s`),
  // Active-measurement path topology (traceroute).
  probePaths: () => request<ProbePath[]>("/api/probe/paths"),
  // LLDP-discovered topology adjacencies (tenant-scoped, deduped). Empty when the
  // LLDP collector is off — the topology then falls back to tier inference.
  topologyLinks: () => request<{ links: TopoLink[]; count: number; source: string }>("/api/topology/links"),
  // Device Geomap — sites (SoT intent) + per-site device health.
  geomap: () => request<GeomapResponse>("/api/geomap"),
  deviceLocations: () => request<{ devices: DeviceLocationRow[] }>("/api/devices/locations"),
  deviceLocation: (id: string) =>
    request<{ set: boolean; sot_site?: string; location?: { site?: string; lat: number; lng: number } }>(
      `/api/devices/${encodeURIComponent(id)}/location`),
  setDeviceLocation: (id: string, body: { site: string; lat: number; lng: number }) =>
    request<{ ok: boolean }>(`/api/devices/${encodeURIComponent(id)}/location`, { method: "PUT", body: JSON.stringify(body) }),
  clearDeviceLocation: (id: string) =>
    request<{ ok: boolean }>(`/api/devices/${encodeURIComponent(id)}/location`, { method: "DELETE" }),

  // One-time WebSocket ticket for the device SSH terminal. The session JWT
  // rides THIS request's Authorization header (a normal authenticated call);
  // the returned ticket is opaque, single-use, ~30s, and bound to this device —
  // it is the ONLY credential that goes into the WebSocket URL, so a logged
  // request line yields nothing reusable. Never put getToken() in a WS URL.
  deviceSSHTicket: (id: string) =>
    request<{ ticket: string; expires_in_seconds: number }>(
      `/api/devices/${encodeURIComponent(id)}/ssh-ticket`, { method: "POST" }),

  // Operator device→site binding (the internal SoT provider's editable intent):
  // assign a device to a DECLARED site by slug; coords resolve live from the site.
  deviceSite: (id: string) =>
    request<{ site: string }>(`/api/devices/${encodeURIComponent(id)}/site`),
  setDeviceSite: (id: string, site: string) =>
    request<{ ok: boolean; site: string }>(`/api/devices/${encodeURIComponent(id)}/site`, { method: "PUT", body: JSON.stringify({ site }) }),
  clearDeviceSite: (id: string) =>
    request<{ ok: boolean }>(`/api/devices/${encodeURIComponent(id)}/site`, { method: "DELETE" }),

  // Internal Source-of-Truth sites (the default SoT provider). `active` reports
  // which provider currently answers ("internal" | "netbox").
  sites: () => request<SitesResponse>("/api/sites"),
  saveSite: (body: SiteInput) =>
    request<SiteRow>("/api/sites", { method: "POST", body: JSON.stringify(body) }),
  updateSite: (slug: string, body: SiteInput) =>
    request<SiteRow>(`/api/sites/${encodeURIComponent(slug)}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteSite: (slug: string) =>
    request<{ ok: boolean }>(`/api/sites/${encodeURIComponent(slug)}`, { method: "DELETE" }),

  // External SoT import — one-way file seed of sites / device→site into the
  // internal SoT. dry_run (default true) returns a plan; dry_run:false applies.
  importSot: (body: { kind: "sites" | "device_sites"; format: "csv" | "json" | "geojson"; data: string; dry_run?: boolean; overwrite?: boolean }) =>
    request<ImportResult>("/api/sot/import", { method: "POST", body: JSON.stringify(body) }),
  flowsTimeseries: (sinceSeconds = 3600, stepSeconds = 60, type = "", filters?: FlowFilters) =>
    request<ClickHouseResponse>(
      `/api/flows/timeseries?since=${sinceSeconds}s&step=${stepSeconds}s${type ? `&type=${type}` : ""}${flowQS(filters)}`,
    ),
  tunnels: (limit = 200, status?: string) => {
    const p = new URLSearchParams({ limit: String(limit) });
    if (status) p.set("status", status);
    return request<ClickHouseResponse<Tunnel>>(`/api/tunnels?${p}`);
  },
  wanInterfaces: () => request<{ interfaces: WanInterfaceRow[] }>(`/api/wan/interfaces`),

  // System network settings (platform admin) — DNS resolvers + NTP servers.
  systemNetwork: () => request<SystemNetworkConfig>(`/api/system/network`),
  setSystemNetwork: (cfg: SystemNetworkConfig) =>
    request<SystemNetworkConfig>(`/api/system/network`, { method: "PUT", body: JSON.stringify(cfg) }),
  backupConfig: () => request<BackupConfigAndStatus>(`/api/system/backup`),
  setBackupConfig: (cfg: BackupConfig) =>
    request<BackupConfigAndStatus>(`/api/system/backup`, { method: "PUT", body: JSON.stringify(cfg) }),
  snapshotPolicy: () => request<SnapshotPolicy>(`/api/system/backup/snapshots`),
  setSnapshotPolicy: (upd: SnapshotPolicyUpdate) =>
    request<SnapshotPolicy>(`/api/system/backup/snapshots`, { method: "PUT", body: JSON.stringify(upd) }),
  testSystemNetwork: (host?: string) =>
    request<SystemNetworkStatus>(`/api/system/network/test${host ? `?host=${encodeURIComponent(host)}` : ""}`, { method: "POST" }),
  findings: (limit = 100, severity?: string) => {
    const p = new URLSearchParams({ limit: String(limit) });
    if (severity) p.set("severity", severity);
    return request<ClickHouseResponse<Finding>>(`/api/findings?${p}`);
  },
  // Correlation Engine v2 objects (read-only inspector). `cursor` is the house
  // keyset cursor — the response's next_cursor (set only when a full page was
  // returned) fetches the next page of the same window.
  correlations: (limit = 100, sinceSeconds = 86400, state?: string, tier?: string, cursor?: string) => {
    const p = new URLSearchParams({ limit: String(limit), since: `${sinceSeconds}s` });
    if (state) p.set("state", state);
    if (tier) p.set("tier", tier);
    if (cursor) p.set("cursor", cursor);
    return request<ClickHouseResponse<CorrObject> & { next_cursor?: string }>(`/api/correlations?${p}`);
  },
  // True window counts behind the Correlations stat chips — real COUNTs, never
  // the capped list length (owner directive: DON'T HIDE).
  correlationsSummary: (sinceSeconds = 86400, state?: string) => {
    const p = new URLSearchParams({ since: `${sinceSeconds}s` });
    if (state) p.set("state", state);
    return request<CorrSummary>(`/api/correlations/summary?${p}`);
  },
  correlationDetail: (id: string) =>
    request<{ object: CorrObject; edges: CorrEdge[] }>(`/api/correlations/${encodeURIComponent(id)}`),
  // RCA path overlay (#77): UI-ready path + per-target overlay annotations for a
  // correlation object — drives the canvas Investigate-mode RCA overlay.
  rcaPathView: (id: string) =>
    request<RcaPathView>(`/api/correlations/${encodeURIComponent(id)}/rca-path-view`),
  correlationReplay: (id: string) =>
    request<CorrReplay>(`/api/correlations/${encodeURIComponent(id)}/replay`),
  // Canonical server-side RCA report (owner directive 2026-07-12). PDF via the
  // backend's controlled renderer (no browser print chrome); when the PDF
  // sidecar is off, falls back to the server-rendered HTML in a new tab.
  // Returns which format was delivered.
  downloadRcaReport: async (id: string, displayId: string): Promise<"pdf" | "html"> => {
    const token = getToken();
    const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
    const scope = getActiveScope();
    if (scope) headers["X-Acting-Tenant"] = scope;
    const base = `/api/correlations/${encodeURIComponent(id)}/rca-report`;
    const pdf = await fetch(`${base}?format=pdf`, { headers });
    if (pdf.ok) {
      await downloadResponse(pdf, `incident-report-${displayId || id.slice(0, 8)}.pdf`);
      return "pdf";
    }
    if (pdf.status === 403) {
      // #113 point 3 — RCA promotion gate: the candidate is not a promoted real
      // outage; surface the policy reason so the caller can offer manual promote.
      const j = await pdf.json().catch(() => null) as { error?: string } | null;
      throw new RcaNotPromotedError(j?.error || "This candidate is not promoted to an RCA document.");
    }
    const html = await fetch(`${base}?format=html`, { headers });
    if (!html.ok) throw new Error(`report render failed (${html.status})`);
    const blob = await html.blob();
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    return "html";
  },
  // Canonical server-side RCA report as JSON (same endpoint the PDF/HTML render
  // from). The path-causality P3 render reads `path_attribution` off this; the
  // read is tenant-scoped + permission-gated identically to every correlation read.
  rcaReportJson: (id: string) =>
    request<RcaReportJson>(`/api/correlations/${encodeURIComponent(id)}/rca-report?format=json`),
  // #113 — the management RCA library: promoted outages only (auto + manual).
  rcaLibrary: (days = 30) =>
    request<RcaLibraryResponse>(`/api/correlations/rca-reports?days=${encodeURIComponent(days)}`),
  // #113 point 3 — manual RCA promotion (audited, write-gated server-side).
  // Candidates and RCA documents are different tiers: only a promoted case
  // renders the html/pdf document.
  promoteRca: (id: string, note?: string) =>
    request<{ manually_promoted: boolean }>(`/api/correlations/${encodeURIComponent(id)}/rca-promotion`, {
      method: "POST", body: JSON.stringify(note ? { note } : {}),
    }),
  unpromoteRca: (id: string) =>
    request<{ manually_promoted: boolean }>(`/api/correlations/${encodeURIComponent(id)}/rca-promotion`, { method: "DELETE" }),
  // Full window signal slice (attached + concurrent-unattached) for the RCA timeline.
  correlationTimeline: (id: string) =>
    request<CorrTimeline>(`/api/correlations/${encodeURIComponent(id)}/timeline`),
  // RCA Time Intelligence — incident time decomposition (phases + time-loss driver).
  correlationTimeMetrics: (id: string) =>
    request<TimeIntel>(`/api/correlations/${encodeURIComponent(id)}/time-metrics`),
  // Manual lifecycle events for one investigation (tenant-scoped; the embedded
  // drawer reads WHO closed it + the recorded verification state at close).
  correlationTimeEvents: (id: string) =>
    request<{ events: TimeEventRow[] }>(`/api/correlations/${encodeURIComponent(id)}/time-events`),
  // Record a manual lifecycle event. For a close, `verification` is the
  // allowlisted recovery-verification state — the server composes the labeled
  // note and audits the actor; an override can never be recorded silently.
  correlationTimeEventSet: (id: string, body: {
    event_type: string; event_time: string; note?: string; verification?: string;
  }) =>
    request<TimeEventRow>(`/api/correlations/${encodeURIComponent(id)}/time-events`,
      { method: "POST", body: JSON.stringify(body) }),
  // RCA auto-ticketing (#78): the external ticket link + audit history for one
  // RCA object, and operator-initiated create / sync (enqueued to the outbox).
  correlationTickets: (id: string) =>
    request<CorrelationTickets>(`/api/correlations/${encodeURIComponent(id)}/tickets`),
  // All of the caller-tenant's ticket links (#103 UX-1) — the RCA candidate
  // list joins these by correlation id for the "Notified via" column.
  ticketLinks: () => request<{ links: TicketLinkRow[] }>(`/api/tickets/links`),
  correlationTicketCreate: (id: string) =>
    request<{ enqueued: string; corr_object_id: string; system: string }>(
      `/api/correlations/${encodeURIComponent(id)}/ticket`, { method: "POST", body: "{}" }),
  correlationTicketSync: (id: string) =>
    request<{ enqueued: string; corr_object_id: string; system: string }>(
      `/api/correlations/${encodeURIComponent(id)}/ticket/sync`, { method: "POST", body: "{}" }),
  // RCA operator verdict feedback (Project 2 P7). The list is newest-first as
  // the server orders it; the create appends (never overwrites) and returns 201
  // with the stored record. Summary is the windowed false-positive rate for the
  // caller's scope — days is clamped 1..365 server-side.
  correlationFeedback: (id: string) =>
    request<RcaFeedbackList>(`/api/correlations/${encodeURIComponent(id)}/feedback`),
  correlationFeedbackCreate: (id: string, body: RcaFeedbackCreate) =>
    request<RcaFeedback>(`/api/correlations/${encodeURIComponent(id)}/feedback`,
      { method: "POST", body: JSON.stringify(body) }),
  rcaFeedbackSummary: (days = 30) =>
    request<RcaFeedbackSummary>(`/api/correlations/feedback/summary?days=${encodeURIComponent(String(days))}`),
  // Active Verification (RCA spec item 8): latest run for a case + manual
  // "Verify now". 404 = feature dormant or case not visible to this tenant.
  verificationStatus: (id: string) =>
    request<VerificationStatus>(`/api/correlations/${encodeURIComponent(id)}/verify`),
  verificationRun: (id: string) =>
    request<{ run_id: string; status: string; devices: string[] }>(
      `/api/correlations/${encodeURIComponent(id)}/verify`, { method: "POST", body: "{}" }),
  // Incident-policy CRUD + pure simulator (#78). Per-tenant: the backend scopes
  // by the caller and stamps the owner from the token.
  incidentPolicies: () => request<{ policies: IncidentPolicy[] }>("/api/incident-policies"),
  incidentPolicyCreate: (p: Partial<IncidentPolicy>) =>
    request<IncidentPolicy>("/api/incident-policies", { method: "POST", body: JSON.stringify(p) }),
  incidentPolicyUpdate: (id: string, p: Partial<IncidentPolicy>) =>
    request<IncidentPolicy>(`/api/incident-policies/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(p) }),
  incidentPolicyDelete: (id: string) =>
    request<{ deleted: boolean }>(`/api/incident-policies/${encodeURIComponent(id)}`, { method: "DELETE" }),
  incidentPolicyTest: (id: string, facts: IncidentPolicyTestFacts) =>
    request<TicketPolicyDecision>(`/api/incident-policies/${encodeURIComponent(id)}/test`, { method: "POST", body: JSON.stringify(facts) }),
  // Reliability rollups (Operational Recovery Scorecard).
  reliabilityRollups: (sinceSeconds = 2592000, f: ReliabilityQuery = {}) =>
    request<ReliabilityRollupResp>(`/api/reliability/rollups?since=${sinceSeconds}${reliabilityQS(f)}`),
  reliabilityTrends: (sinceSeconds = 2592000, bucketSeconds = 604800, f: ReliabilityQuery = {}) =>
    request<ReliabilityTrendsResp>(`/api/reliability/trends?since=${sinceSeconds}&bucket=${bucketSeconds}${reliabilityQS(f)}`),
  reliabilityChronicOffenders: (sinceSeconds = 2592000, top = 10, f: ReliabilityQuery = {}) =>
    request<{ offenders: ChronicOffender[] }>(`/api/reliability/chronic-offenders?since=${sinceSeconds}&top=${top}${reliabilityQS(f)}`),
  // Active grounding seams (owner/visibility) — joined to edge grounding_ref in
  // the seam-aware graph. 501 on the file backend → caller degrades gracefully.
  seams: (state = "active") =>
    request<Seam[]>(`/api/seams?state=${encodeURIComponent(state)}`),
  // Front page (#69)
  healthScore: (scope = "global", id?: string) => {
    const p = new URLSearchParams({ scope });
    if (id) p.set("id", id);
    return request<HealthScoreResp>(`/api/health/score?${p}`);
  },
  eventsFeed: (params: Record<string, string> = {}) =>
    request<EventsFeedResp>(`/api/events/feed?${new URLSearchParams(params)}`),
  correlationsStats: (sinceSeconds = 604800) =>
    request<CorrStats>(`/api/correlations/stats?since=${sinceSeconds}s`),
  // #80 signature-governance: recurring undetermined gap-shapes ranked by frequency.
  undeterminedFrequency: (sinceSeconds = 604800, top = 20) =>
    request<UndeterminedFeed>(`/api/correlations/undetermined-frequency?since=${sinceSeconds}s&top=${top}`),
  metricsForecast: (days = 28) => request<ForecastResp>(`/api/metrics/forecast?days=${days}`),
  // Path Behavior Health — adaptive baseline-relative path scoring (worst-first).
  pathsHealth: () => request<PathHealthResponse>(`/api/paths/health`),
  vulns: (limit = 500) => request<VulnsResponse>(`/api/vulns?limit=${limit}`),
  compliance: (limit = 500) => request<ComplianceResponse>(`/api/compliance?limit=${limit}`),

  // Copilot
  copilotChat: (messages: CopilotMessage[], system?: string) =>
    request<CopilotChatResponse>("/api/copilot/chat", {
      method: "POST",
      body: JSON.stringify({ messages, system }),
    }),

  // Iris AI — application-aware assistant. Ask a question (optionally with a
  // context id like the open RCA's correlation_id); returns a grounded, cited
  // answer in a typed answer-mode schema. Read-only (FEATURE_AI gated server-side).
  aiAsk: (question: string, context?: Record<string, string>) =>
    request<AiAnswer>("/api/ai/ask", {
      method: "POST",
      body: JSON.stringify({ question, context }),
    }),
  // Slash-command registry (the "/" menu) — single source of truth on the server.
  aiCommands: () => request<{ commands: AiCommand[] }>("/api/ai/commands"),
  // Answer feedback (thumbs up/down) — privacy-safe (rating + intent only). 204.
  aiFeedback: (rating: "up" | "down", intent?: string, conversationId?: string) =>
    request<void>("/api/ai/feedback", {
      method: "POST",
      body: JSON.stringify({ rating, intent, conversation_id: conversationId }),
    }),
  // (Re)issue the embedded-console gate cookie for the current session so a raw
  // iframe (/netbox, /search) carries a fresh, correctly-pathed cookie. 204.
  ensureConsoleGate: () => request<void>("/api/auth/console-gate", { method: "POST" }),

  // Runtime assistant config (admin): provider/model picker. Key never returned.
  copilotConfig: () => request<CopilotConfig>("/api/copilot/config"),
  setCopilotConfig: (cfg: { provider: string; model: string; system?: string; key?: string }) =>
    request<CopilotConfig>("/api/copilot/config", {
      method: "PUT",
      body: JSON.stringify(cfg),
    }),
  // Per-workspace AI settings (tenant admin): own provider key + platform-service
  // opt-out. 403 for non-admins, 400 for the platform owner (who uses the above).
  aiTenantConfig: () => request<AITenantConfig>("/api/ai/tenant-config"),
  setAITenantConfig: (cfg: { provider: string; model: string; key?: string; no_platform_key: boolean; clear_key?: boolean }) =>
    request<AITenantConfig>("/api/ai/tenant-config", { method: "PUT", body: JSON.stringify(cfg) }),
  // Per-tenant AI access (platform owner): who gets the assistant/investigations.
  aiTenants: () => request<{ tenants: AITenantRow[] | null; tools_feature: boolean; defaults?: { max_calls: number; daily_tokens: number } }>("/api/ai/tenants"),
  setAITenantAccess: (id: string, body: { assistant_enabled: boolean; investigations_enabled: boolean; max_calls?: number; daily_tokens?: number }) =>
    request<AITenantRow>(`/api/ai/tenants/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(body) }),

  // Native metrics (Prometheus-compatible API via the Go proxy).
  metricNames: () => request<PromNamesResponse>("/api/metrics/names"),
  metricsQueryRange: (query: string, startSec: number, endSec: number, stepSec: number) => {
    const p = new URLSearchParams({
      query,
      start: String(startSec),
      end: String(endSec),
      step: String(stepSec),
    });
    return request<PromRangeResponse>(`/api/metrics/query_range?${p.toString()}`);
  },
  // Instant PromQL evaluation — the New Monitor wizard uses it to preview which
  // series a condition would fire on right now.
  metricsQuery: (query: string) =>
    request<PromInstantResponse>(`/api/metrics/query?${new URLSearchParams({ query })}`),

  // Cloud metric charts (Wave 5 #14): tenant-scoped, bounded series for the
  // resource drawer / App Detail. The backend refuses ids outside the caller's
  // inventory (404) and builds the PromQL itself — no raw query surface here.
  cloudMetricSeries: (resources: string[], metric: string, windowMinutes: number) => {
    const p = new URLSearchParams({ metric, window_minutes: String(windowMinutes) });
    for (const r of resources) p.append("resource", r);
    return request<CloudMetricSeriesResponse>(`/api/cloud/metrics/series?${p.toString()}`);
  },

  // Per-tenant SLOs / error budgets (Wave 5 #14 slice 2). GET returns defs +
  // MEASURED status (absent data = "not measurable", never a fake 100%);
  // PUT replaces the tenant's list (admin-gated, tenant stamped server-side).
  cloudSlos: () => request<CloudSloResponse>("/api/cloud/slos"),
  setCloudSlos: (slos: CloudSloDef[]) =>
    request<CloudSloResponse>("/api/cloud/slos", { method: "PUT", body: JSON.stringify({ slos }) }),
  resetCloudSlos: () =>
    request<CloudSloResponse>("/api/cloud/slos", { method: "PUT", body: JSON.stringify({ reset: true }) }),

  // Per-tenant cloud monitors (Wave 5 #14 slice 3): threshold/anomaly rules on
  // the closed cloud-metric catalog, evaluated by the backend's bounded loop.
  cloudMonitors: () =>
    request<{ monitors: CloudMonitorRow[]; count: number; max_monitors: number }>("/api/cloud/monitors"),
  createCloudMonitor: (m: CloudMonitorInput) =>
    request<CloudMonitorRow>("/api/cloud/monitors", { method: "POST", body: JSON.stringify(m) }),
  updateCloudMonitor: (id: string, m: CloudMonitorInput) =>
    request<CloudMonitorRow>(`/api/cloud/monitors/${encodeURIComponent(id)}`, {
      method: "PUT", body: JSON.stringify(m),
    }),
  deleteCloudMonitor: (id: string) =>
    request<{ deleted: string }>(`/api/cloud/monitors/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // Saved objects (searches / dashboards / reports) — Postgres-swappable
  // file-backed store on the API.
  listSaved: (type?: string) =>
    request<SavedObject[]>(`/api/saved${type ? `?type=${encodeURIComponent(type)}` : ""}`),
  createSaved: (type: SavedType, name: string, body: unknown) =>
    request<SavedObject>("/api/saved", {
      method: "POST",
      body: JSON.stringify({ type, name, body }),
    }),
  deleteSaved: (id: string) => request<void>(`/api/saved/${id}`, { method: "DELETE" }),

  // Global omni-search — resolves a free-text query to jump targets
  // (devices, alerts, saved objects) plus a raw log-search handoff.
  globalSearch: (q: string) =>
    request<GlobalSearchResponse>(`/api/search/global?q=${encodeURIComponent(q)}`),
  // Unified search (Wave 6 #20) — typed, tenant-scoped, bounded results across
  // devices · cloud resources · services · accounts · correlation cases
  // (P-XXXXXX), each carrying its permanent deep-link href.
  unifiedSearch: (q: string) =>
    request<UnifiedSearchResponse>(`/api/search?q=${encodeURIComponent(q)}`),
  // Permanent per-resource read (Wave 6 #20) behind #/resource/cloud/{id}.
  // A cross-tenant or unknown id is an indistinguishable 404.
  cloudResource: (id: string) =>
    request<CloudResourceDetailResponse>(`/api/cloud/resources/${encodeURIComponent(id)}`),

  // Reports — saved objects (type=report) delivered on a schedule by the
  // server-side scheduler via the notify dispatcher.
  reportRuns: () => request<Record<string, ReportRun>>("/api/reports/runs"),
  // The notify channels actually configured, so "Send now" offers only real
  // delivery destinations.
  reportChannels: () => request<string[]>("/api/reports/channels"),
  // Deliver a report now. channels optionally restricts this one send to named
  // notify channels; omitted/empty => all configured channels.
  runReport: (id: string, channels?: string[]) =>
    request<ReportRun & { execution_id?: string }>("/api/reports/run", {
      method: "POST",
      body: JSON.stringify(channels && channels.length ? { id, channels } : { id }),
    }),
  // Edit an existing report (or any saved object).
  updateSaved: (id: string, name: string, body: unknown) =>
    request<SavedObject>(`/api/saved/${id}`, { method: "PUT", body: JSON.stringify({ name, body }) }),
  // Async pipeline (Postgres backend): per-report execution history + detail.
  reportExecutions: (scheduleId?: string, opts?: { limit?: number; before?: string }) => {
    const p = new URLSearchParams();
    if (scheduleId) p.set("schedule_id", scheduleId);
    if (opts?.limit) p.set("limit", String(opts.limit));
    if (opts?.before) p.set("before", opts.before);
    const qs = p.toString();
    return request<ReportExecution[]>(`/api/reports/executions${qs ? `?${qs}` : ""}`);
  },
  reportExecution: (id: string) => request<ReportExecutionDetail>(`/api/reports/executions/${encodeURIComponent(id)}`),
  // Live preview — renders a report's HTML on demand without scheduling/delivering.
  reportPreview: async (name: string, body: ReportBody, format: ReportFormat = "html"): Promise<string> => {
    const token = getToken();
    const res = await fetch(`/api/reports/preview?format=${encodeURIComponent(format)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ name, body }),
    });
    if (!res.ok) throw new Error(`${res.status}: ${await res.text().catch(() => "")}`);
    return res.text();
  },
  // Fetch a stored artifact (auth-protected) and trigger a browser download.
  downloadArtifact: async (execId: string, format: ReportFormat): Promise<void> => {
    const token = getToken();
    const res = await fetch(`/api/reports/executions/${encodeURIComponent(execId)}/artifact?format=${encodeURIComponent(format)}`, {
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    });
    if (!res.ok) throw new Error(`${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  // ----- Logs export -----
  // Mode A: render the rows already loaded in the browser (selected/page) to one
  // file. Excel reuses the server OOXML renderer; csv/json/ndjson share the
  // server encoders so every format matches Mode B byte-for-byte.
  exportLogRows: async (format: ExportFmt, columns: string[], rows: string[][], filename = "logs-export"): Promise<void> => {
    const token = getToken();
    const res = await fetch("/api/logs/export/rows", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ format, columns, rows, filename }),
    });
    if (!res.ok) throw new Error(`Export failed: ${res.status} ${await res.text().catch(() => "")}`);
    await downloadResponse(res, `${filename}.${format}`);
  },

  // Mode B: export the ENTIRE result set. Small sets stream straight back (file
  // download, returns {}); large sets enqueue an async job and return
  // { executionId } to poll via exportStatus → exported download_url.
  exportLogQuery: async (opts: LogExportOpts): Promise<{ executionId?: string; matched?: number }> => {
    const token = getToken();
    const params = new URLSearchParams();
    params.set("format", opts.format);
    if (opts.query) params.set("query", opts.query);
    if (opts.from) params.set("from", opts.from);
    if (opts.to) params.set("to", opts.to);
    if (opts.signal) params.set("signal", opts.signal);
    if (opts.mode) params.set("mode", opts.mode);
    const res = await fetch(`/api/logs/export?${params.toString()}`, {
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    });
    if (res.status === 202) {
      const body = await res.json();
      return { executionId: body.execution_id, matched: body.matched };
    }
    if (!res.ok) throw new Error(`Export failed: ${res.status} ${await res.text().catch(() => "")}`);
    await downloadResponse(res, `logs-export.${opts.format}`);
    return {};
  },

  exportStatus: (id: string) => request<ExportStatus>(`/api/exports/${encodeURIComponent(id)}`),

  // ----- Incidents -----
  listIncidents: (opts: { status?: string; severity?: string; limit?: number } = {}) => {
    const p = new URLSearchParams();
    if (opts.status) p.set("status", opts.status);
    if (opts.severity) p.set("severity", opts.severity);
    if (opts.limit) p.set("limit", String(opts.limit));
    const qs = p.toString();
    return request<Incident[]>(`/api/incidents${qs ? `?${qs}` : ""}`);
  },
  getIncident: (id: string) =>
    request<{ incident: Incident; events: IncidentEvent[] }>(`/api/incidents/${encodeURIComponent(id)}`),
  getIncidentTimeline: (id: string) =>
    request<{ incident: Incident; timeline: TimelineEntry[] }>(`/api/incidents/${encodeURIComponent(id)}/timeline`),
  incidentAction: (id: string, action: "ack" | "resolve" | "investigate" | "close" | "reopen" | "note" | "assign" | "promote", body: { note?: string; owner?: string } = {}) =>
    request<Incident>(`/api/incidents/${encodeURIComponent(id)}/${action}`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // ----- Export limits (runtime policy; platform-owner only to change) -----
  exportPolicy: () => request<ExportPolicy>("/api/exports/policy"),
  saveExportPolicy: (p: ExportPolicy) =>
    request<ExportPolicy>("/api/exports/policy", { method: "PUT", body: JSON.stringify(p) }),

  // ----- Identity & access (admin) -----
  permissions: () => request<{ role: string; permissions: Record<string, number> }>("/api/auth/permissions"),

  listUsers: () => request<AdminUser[]>("/api/users"),
  createUser: (u: Partial<AdminUser> & { password?: string }) =>
    request<AdminUser>("/api/users", { method: "POST", body: JSON.stringify(u) }),
  updateUser: (username: string, patch: Partial<AdminUser> & { password?: string }) =>
    request<AdminUser>(`/api/users/${encodeURIComponent(username)}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteUser: (username: string) =>
    request<void>(`/api/users/${encodeURIComponent(username)}`, { method: "DELETE" }),

  listRoles: () => request<{ modules: string[]; roles: Role[] }>("/api/roles"),
  saveRole: (r: Role) =>
    r.id
      ? request<Role>(`/api/roles/${encodeURIComponent(r.id)}`, { method: "PUT", body: JSON.stringify(r) })
      : request<Role>("/api/roles", { method: "POST", body: JSON.stringify(r) }),
  deleteRole: (id: string) => request<void>(`/api/roles/${encodeURIComponent(id)}`, { method: "DELETE" }),

  listTenants: () => request<Tenant[]>("/api/tenants"),
  createTenant: (name: string, note?: string, operatorRestricted?: boolean, orgId?: string, region?: string) =>
    request<Tenant>("/api/tenants", { method: "POST", body: JSON.stringify({ name, note, operator_restricted: !!operatorRestricted, org_id: orgId || "", region: region || "" }) }),
  setTenantRegion: (id: string, region: string) =>
    request<Tenant>(`/api/tenants/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ region }) }),
  regionTopology: () => request<RegionTopologyResponse>("/api/regions/topology"),
  // Destructive: requires the exact tenant name echoed back (server-enforced) and
  // refuses a non-empty tenant unless force=true.
  deleteTenant: (id: string, confirm: string, force = false) =>
    request<void>(`/api/tenants/${encodeURIComponent(id)}?confirm=${encodeURIComponent(confirm)}${force ? "&force=true" : ""}`, { method: "DELETE" }),
  // Compliance: toggle whether the platform operator may view this tenant's telemetry.
  setTenantOperatorRestricted: (id: string, restricted: boolean) =>
    request<Tenant>(`/api/tenants/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ operator_restricted: restricted }) }),
  // Lifecycle: suspend (block sign-in) or reactivate a tenant.
  setTenantStatus: (id: string, status: "active" | "suspended") =>
    request<Tenant>(`/api/tenants/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  // Admin-configurable default landing route for this tenant ("" = inherit the
  // platform default = the global tenant's value). Set on the global tenant to
  // define the platform-wide default.
  setTenantLanding: (id: string, defaultLanding: string) =>
    request<Tenant>(`/api/tenants/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ default_landing: defaultLanding }) }),
  // Operator one-step onboard: create an org + its first tenant (+optional SSO) in
  // one audited call (platform-owner only). Slugs optional (derived from names).
  onboardCustomer: (req: {
    org_name: string; org_slug?: string; home_region?: string; sso_connection?: string;
    tenant_name: string; tenant_slug?: string; isolation_mode?: string; operator_restricted?: boolean;
  }) => request<{ org: Org; tenant: Tenant }>("/api/onboard", { method: "POST", body: JSON.stringify(req) }),

  // ---------- Organizations (the account layer above tenants) ----------
  listOrgs: () => request<Org[]>("/api/orgs"),
  listRegions: () => request<Region[]>("/api/regions"),
  createOrg: (name: string, opts: { note?: string; homeRegion?: string; ssoConnection?: string } = {}) =>
    request<Org>("/api/orgs", { method: "POST", body: JSON.stringify({ name, note: opts.note || "", home_region: opts.homeRegion || "", sso_connection: opts.ssoConnection || "" }) }),
  updateOrg: (id: string, patch: { note?: string; home_region?: string; sso_connection?: string }) =>
    request<Org>(`/api/orgs/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(patch) }),
  // Refused (409) if the org still owns tenants; the Global org is permanent.
  deleteOrg: (id: string) =>
    request<void>(`/api/orgs/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ---------- Role bindings (PBAC: principal → role → scope) ----------
  listBindings: (principal?: string) =>
    request<RoleBinding[]>(`/api/bindings${principal ? `?principal=${encodeURIComponent(principal)}` : ""}`),
  grantBinding: (b: { principal_id: string; role_id: string; scope_id: string; effect?: string; expires_at?: string; reason?: string }) =>
    request<RoleBinding>("/api/bindings", { method: "POST", body: JSON.stringify(b) }),
  revokeBinding: (id: string) =>
    request<void>(`/api/bindings/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ---------- Accessible scopes (the top-bar Org|Region|Tenant selector) ----
  myScopes: () => request<{ scopes: ScopeDetail[]; all_tenants: boolean }>("/api/scopes"),

  // ---------- Security Settings (scope-wide password/lockout/session rules) ----
  getSecuritySettings: (scope = "provider") => request<SecuritySettings>(`/api/security-settings?scope=${encodeURIComponent(scope)}`),
  saveSecuritySettings: (scope: string, s: SecuritySettings) =>
    request<SecuritySettings>(`/api/security-settings?scope=${encodeURIComponent(scope)}`, { method: "PUT", body: JSON.stringify(s) }),

  // ---------- Transport Security posture (SEC-021.1, read-only) ------------
  // Platform owner → the full path inventory + validator findings; tenant
  // admin → its device lanes only. 403 below administration:admin; 503 when
  // the inventory is unavailable (the caller renders the error message).
  transportPosture: () => request<TransportPosture>("/api/security/transport-posture"),
  // Platform-admin-only HTML posture report, returned as a Blob the caller
  // turns into a browser download (same hand-built-headers blob idiom as
  // downloadRcaReport: bearer token + acting-tenant scope).
  exportTransportPosture: async (): Promise<Blob> => {
    const token = getToken();
    const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
    const scope = getActiveScope();
    if (scope) headers["X-Acting-Tenant"] = scope;
    const res = await fetch("/api/security/transport-posture/export?format=html", { headers });
    if (!res.ok) throw new Error(`Export failed: ${res.status} ${await res.text().catch(() => "")}`);
    return res.blob();
  },

  // ---------- Security CTEM (P3-T8) ---------------------------------------
  // Every call below is tenant-scoped SERVER-side from the bearer token (§3a);
  // the client never sends a tenant, and a foreign id answers 404. Filters are
  // URL-encoded through URLSearchParams — no string concatenation, no injection
  // surface. Only the endpoints in the T8 contract exist here; nothing extra.
  securityFindings: (query: SecFindingQuery = {}) =>
    request<SecFindingsPage>(`/api/security/findings?${secFindingParams(query)}`),
  securityFinding: (id: string) =>
    request<SecFinding>(`/api/security/findings/${encodeURIComponent(id)}`),
  securityFindingFacets: (query: SecFindingQuery = {}) =>
    request<SecFacets>(`/api/security/findings/facets?${secFindingParams(query)}`),
  securityFindingTrend: (query: SecFindingQuery = {}, bucket = "1d") =>
    request<SecTrend>(`/api/security/findings/trend?${secFindingParams({ ...query, cursor: undefined, limit: undefined })}&bucket=${encodeURIComponent(bucket)}`),
  securityPosture: () => request<SecPosture>("/api/security/posture"),
  // Exposure Stories are correlation objects filtered to the security evidence
  // class — the SAME RCA shape, so the workspace components are reused as-is.
  securityExposureStories: (limit = 20) =>
    request<CorrObject[]>(`/api/security/exposure-stories?limit=${encodeURIComponent(String(limit))}`),
  securityExposureStory: (correlationId: string) =>
    request<{ object: CorrObject; edges: CorrEdge[] }>(
      `/api/security/exposure-stories/${encodeURIComponent(correlationId)}`),
  securityRules: () => request<SecRule[]>("/api/security/rules"),
  // Admin-gated server-side. The body carries enablement ONLY — fidelity,
  // family, MITRE tags and seam-awareness are server-owned facts, so echoing
  // them back would let a client claim properties it does not own.
  securityRulesUpdate: (updates: SecRuleToggle[]) =>
    request<SecRule[]>("/api/security/rules", {
      method: "PUT",
      body: JSON.stringify(updates.map((u) => ({ rule_id: u.rule_id, enabled: u.enabled }))),
    }),
  securityViews: () => request<SecSavedView[]>("/api/security/views"),
  securityViewCreate: (name: string, filters: SecFindingQuery) =>
    request<SecSavedView>("/api/security/views", {
      method: "POST", body: JSON.stringify({ name, filters }),
    }),
  securityViewDelete: (id: string) =>
    request<void>(`/api/security/views/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ---------- Sessions (admin: live session listing + revocation) ----------
  listSessions: (user?: string) =>
    request<AdminSession[]>(`/api/sessions${user ? `?user=${encodeURIComponent(user)}` : ""}`),
  revokeSession: (id: string) =>
    request<void>(`/api/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ---------- Access Explorer (L3: "what can X access, and why?") ----------
  explainAccess: (principal?: string) =>
    request<AccessExplanation>(`/api/access/explain${principal ? `?principal=${encodeURIComponent(principal)}` : ""}`),

  // ---------- Break-glass (time-boxed, audited operator elevation) ----------
  listBreakGlass: () => request<RoleBinding[]>("/api/breakglass"),
  openBreakGlass: (tenantId: string, reason: string, durationMinutes = 60) =>
    request<RoleBinding>("/api/breakglass", { method: "POST", body: JSON.stringify({ tenant_id: tenantId, reason, duration_minutes: durationMinutes }) }),
  endBreakGlass: (id: string) =>
    request<void>(`/api/breakglass/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // Self-describing API + ITSM connector status.
  openapi: () => request<OpenAPISpec>("/api/openapi.json"),
  itsmServiceNow: () => request<ServiceNowStatus>("/api/itsm/servicenow"),
  itsmJira: () => request<JiraStatus>("/api/itsm/jira"),
  itsmConfig: () => request<ItsmConfig>("/api/notify/itsm"),
  saveItsmPagerDutyRCA: (c: { enabled: boolean; routing_key?: string }) =>
    request<ItsmConfig>("/api/itsm/pagerduty-rca", { method: "PUT", body: JSON.stringify(c) }),
  saveItsmSlackRCA: (c: { enabled: boolean; webhook_url?: string }) =>
    request<ItsmConfig>("/api/itsm/slack-rca", { method: "PUT", body: JSON.stringify(c) }),
  saveItsmConfig: (c: ItsmConfigInput) =>
    request<ItsmConfig>("/api/notify/itsm", { method: "PUT", body: JSON.stringify(c) }),

  // Integration Platform — bidirectional-sync config (one entry per provider).
  // The webhook signing secret is write-only: omit/blank it on PUT to keep stored.
  integrations: () => request<IntegrationsResponse>("/api/integrations"),
  saveIntegration: (
    provider: string,
    body: Partial<{ enabled: boolean; sync_mode: string; webhook_enabled: boolean; webhook_secret: string; state_map: Record<string, string> }>,
  ) => request<IntegrationConfig>("/api/integrations/" + provider, { method: "PUT", body: JSON.stringify(body) }),

  // NMS vendor-controller integrations (#95) — controller-intelligence
  // ingestion. Credentials are WRITE-ONLY: responses carry set field names
  // only. All routes 404 while FEATURE_NMS_INTEGRATIONS is off (dormant).
  nmsConnectors: () => request<{ connectors: NmsConnector[] }>("/api/nms/connectors"),
  nmsIntegrations: () => request<{ integrations: NmsIntegration[] }>("/api/nms/integrations"),
  // Wireless canonical inventory (#128): read-only, tenant-scoped.
  wirelessControllers: () => request<WirelessController[]>("/api/wireless/controllers"),
  wirelessAPs: () => request<WirelessAP[]>("/api/wireless/aps"),
  wirelessWLANs: () => request<WirelessWLAN[]>("/api/wireless/wlans"),
  createNmsIntegration: (body: NmsIntegrationInput) =>
    request<NmsIntegration>("/api/nms/integrations", { method: "POST", body: JSON.stringify(body) }),
  updateNmsIntegration: (id: string, body: Partial<NmsIntegrationInput>) =>
    request<NmsIntegration>("/api/nms/integrations/" + id, { method: "PUT", body: JSON.stringify(body) }),
  deleteNmsIntegration: (id: string) =>
    request<{ deleted: boolean }>("/api/nms/integrations/" + id, { method: "DELETE" }),
  testNmsIntegration: (id: string) =>
    request<{ ok: boolean; error?: string }>("/api/nms/integrations/" + id + "/test", { method: "POST" }),
  pollNmsIntegration: (id: string) =>
    request<NmsPollResult>("/api/nms/integrations/" + id + "/poll", { method: "POST" }),
  nmsHealth: (id: string) => request<NmsHealth>("/api/nms/integrations/" + id + "/health"),
  nmsStates: (id: string) => request<{ states: NmsStateRow[] }>("/api/nms/integrations/" + id + "/states"),

  listApiKeys: () => request<ApiKey[]>("/api/apikeys"),
  createApiKey: (req: CreateApiKeyRequest) =>
    request<{ key: ApiKey; secret: string }>("/api/apikeys", {
      method: "POST",
      body: JSON.stringify(req),
    }),
  revokeApiKey: (id: string) => request<void>(`/api/apikeys/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // GraphQL — single typed endpoint; powers the in-app explorer.
  graphql: (query: string, variables?: Record<string, unknown>) =>
    request<{ data?: Record<string, unknown>; errors?: unknown }>("/api/graphql", {
      method: "POST",
      body: JSON.stringify({ query, variables }),
    }),

  // ----- SNMP credential profiles -----
  snmpOptions: () => request<SNMPOptions>("/api/snmp/options"),
  listSnmpCreds: () => request<SNMPCredential[]>("/api/snmp/credentials"),
  saveSnmpCred: (c: SNMPCredential) =>
    c.id
      ? request<SNMPCredential>(`/api/snmp/credentials/${encodeURIComponent(c.id)}`, { method: "PUT", body: JSON.stringify(c) })
      : request<SNMPCredential>("/api/snmp/credentials", { method: "POST", body: JSON.stringify(c) }),
  deleteSnmpCred: (id: string) => request<void>(`/api/snmp/credentials/${encodeURIComponent(id)}`, { method: "DELETE" }),
  // SNMP config generator — returns the device CLI block + provisions the
  // matching profile (secrets shown once). Platform-admin only.
  generateSnmpConfig: (body: { vendor: string; version: string; mgmt_subnet?: string; mask?: string; skip_profile?: boolean }) =>
    request<SnmpGenResult>("/api/onboard/snmp-config", { method: "POST", body: JSON.stringify(body) }),

  // ----- Security Policy (#24) — NIST-aligned controls resolved through the
  // System→Tenant→Role→User hierarchy. Admin-gated; system/global = platform
  // owner. The catalog is the source of truth for what's configurable; documents
  // only carry per-scope overrides; effective is the deterministic resolution.
  policyCatalog: () => request<PolicyCatalog>("/api/policy/catalog"),
  policyEffective: (sub: PolicySubject = {}) => {
    const p = new URLSearchParams();
    if (sub.tenant) p.set("tenant", sub.tenant);
    if (sub.role) p.set("role", sub.role);
    if (sub.user) p.set("user", sub.user);
    const qs = p.toString();
    return request<{ subject: PolicySubject; resolved: PolicyResolved[] }>(`/api/policy/effective${qs ? `?${qs}` : ""}`);
  },
  policyDocuments: () => request<{ documents: PolicyDocument[] }>("/api/policy/documents"),
  policyDocument: (scope: PolicyScope, selector = "", tenant = "") => {
    const p = new URLSearchParams({ scope });
    if (selector) p.set("selector", selector);
    if (tenant) p.set("tenant", tenant);
    return request<{ document: PolicyDocument; found: boolean }>(`/api/policy/document?${p}`);
  },
  setPolicyOverride: (ref: PolicyRef, key: string, value: PolicyValue, locked = false) => {
    const p = new URLSearchParams({ scope: ref.scope });
    if (ref.selector) p.set("selector", ref.selector);
    if (ref.tenant) p.set("tenant", ref.tenant);
    return request<{ resolved: PolicyResolved }>(`/api/policy/document?${p}`, {
      method: "PUT",
      body: JSON.stringify({ key, value, locked }),
    });
  },
  clearPolicyOverride: (ref: PolicyRef, key: string, prune = true) => {
    const p = new URLSearchParams({ scope: ref.scope, key });
    if (ref.selector) p.set("selector", ref.selector);
    if (ref.tenant) p.set("tenant", ref.tenant);
    if (prune) p.set("prune", "true");
    return request<void>(`/api/policy/document?${p}`, { method: "DELETE" });
  },
  validatePolicyOverride: (ref: PolicyRef, key: string, value: PolicyValue, locked = false) =>
    request<{ ok: boolean; error?: string }>("/api/policy/validate", {
      method: "POST",
      body: JSON.stringify({ scope: ref.scope, selector: ref.selector ?? "", tenant: ref.tenant ?? "", key, value, locked }),
    }),

  // ----- Cloud App Observability (#81 P3A) -----
  // The IDENTITY surfaces are live from the cloud inventory; health/change/flow
  // telemetry arrive in later phases (UI shows those as "not measured"). Shapes
  // mirror src/backend/cloud/{model,derive}.go.
  cloudResources: (q?: CloudResourceQuery) => request<{ resources: CloudResourceRow[]; console_urls?: Record<string, string>; connectors?: CloudConnectorInfo[]; count: number; required_tags?: string[] }>(`/api/cloud/resources${cloudResourceQS(q)}`),
  cloudApps: () => request<{ apps: CloudAppRow[]; count: number; live?: Record<string, CloudAppLive> }>("/api/cloud/apps"),
  cloudIdentityMap: () => request<{ mappings: CloudIdentityMappingRow[]; count: number }>("/api/cloud/identity-map"),
  cloudCoverage: () => request<{ coverage: CloudCoverageReport; top_unknown: CloudResourceRow[]; required_tags?: string[]; tag_compliance?: CloudTagCompliance }>("/api/cloud/attribution/coverage"),
  // Business services + manual resource→service assignment (2026-07 review #5:
  // these endpoints shipped with the Azure optional-tags epic but had NO UI —
  // the untagged remediation queue dead-ended at the provider console). The
  // assignment is the operator-authoritative override layer: it wins over tag /
  // graph inference on the Resources surface (backend overlayManualMappings).
  cloudBusinessServices: () =>
    request<{ business_services: BusinessServiceRow[]; count: number }>("/api/cloud/business-services"),
  cloudCreateBusinessService: (body: BusinessServiceInput) =>
    request<BusinessServiceRow>("/api/cloud/business-services", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  cloudUpdateBusinessService: (id: string, body: BusinessServiceInput) =>
    request<{ updated: string }>(`/api/cloud/business-services/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  cloudDeleteBusinessService: (id: string) =>
    request<{ deleted: string }>(`/api/cloud/business-services/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  // The resource→service override ledger (catalog UI shows per-service counts).
  cloudResourceMappings: () =>
    request<{ resource_mappings: ResourceMappingRow[]; count: number }>("/api/cloud/resource-mappings"),
  cloudAssignResources: (body: { business_service_id?: string; service_name?: string; resource_ids: string[] }) =>
    request<{ assigned: number }>("/api/cloud/resource-mappings", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  // Resource ids are ARM ids / ARNs / GCP paths — slashes are load-bearing path
  // segments the backend reads back out of the URL. Encode per-segment so a "/"
  // survives while every other reserved char is escaped.
  cloudClearResourceMapping: (resourceId: string) =>
    request<{ cleared: string }>(
      `/api/cloud/resource-mappings/${resourceId.split("/").map(encodeURIComponent).join("/")}`,
      { method: "DELETE" },
    ),
  // Per-source ingestion status, MEASURED from what actually landed (signals,
  // active seams, inventory) — not a hard-coded assumption.
  cloudIngestion: () => request<{
    sources: CloudIngestionSource[];
    // per-provider matrices (audit Azure P0-7): keyed "aws" | "azure" | … —
    // GCP appears automatically once connected. A provider row is only
    // credited with signals that carry that provider's own attribution.
    providers?: Record<string, CloudIngestionSource[]>;
    generated_at: string;
  }>("/api/cloud/ingestion"),
  // #81 P3G — the REAL engine-formed cloud RCA object(s) for an app (corr_objects),
  // tenant-scoped. Empty data[] when the app has no active RCA (unknown stays first-class).
  cloudAppRca: (app: string) => request<ClickHouseResponse<CloudAppRcaRow>>(`/api/cloud/app-rca?app=${encodeURIComponent(app)}`),
  // #81 P3H — the REAL cloud health / change / evidence surfaces (corr_signals +
  // the cloud correlation objects), tenant-scoped and bounded to a 24h window.
  // Empty lists when nothing landed — the UI shows its honest empty state.
  cloudHealth: (app?: string, limit?: number, windowHours?: number, extra?: CloudSignalPage) =>
    request<{ signals: CloudHealthSignalRow[]; count: number; window_hours: number; next_cursor?: string }>(`/api/cloud/health${cloudQS(app, limit, windowHours, extra)}`),
  cloudChanges: (app?: string, limit?: number, windowHours?: number, extra?: CloudSignalPage) =>
    request<{ changes: CloudChangeRow[]; count: number; window_hours: number; next_cursor?: string }>(`/api/cloud/changes${cloudQS(app, limit, windowHours, extra)}`),
  // Change→incident correlation (Wave 4 #12): the change events recorded in the
  // onset-anchored window on ONE investigation's own affected resources/apps.
  cloudInvestigationChanges: (id: string) =>
    request<{
      changes: (CloudChangeRow & { offset_seconds: number })[]; count: number;
      onset: string; basis: "affected_scope" | "no_affected_resources" | "onset_unknown";
      lookback_hours: number;
    }>(`/api/cloud/investigations/${encodeURIComponent(id)}/changes`),
  cloudEvidence: (app?: string, limit?: number, windowHours?: number, extra?: CloudSignalPage) =>
    request<{
      objects: CloudRcaObjectRow[]; evidence: CloudEvidenceRow[];
      // count = the TRUE ledger size; returned = this page; open_object_count =
      // a dedicated COUNT of open investigations (audit D-P1-7 / D-P2-13).
      count: number; returned?: number; open_object_count?: number;
      objects_truncated?: boolean; window_hours: number; next_cursor?: string;
    }>(`/api/cloud/evidence${cloudQS(app, limit, windowHours, extra)}`),
  // Wave 5 #16 — security-relevant rollups from the fidelity lanes (WAF blocks /
  // LB-plane 5xx / DNS failures), tenant-scoped and bounded. lane_counts backs
  // the surface's per-lane coverage note.
  cloudSecurity: (app?: string, limit?: number, windowHours?: number) =>
    request<{
      findings: CloudSecurityFindingRow[]; count: number; window_hours: number;
      lane_counts: Record<string, number>;
    }>(`/api/cloud/security${cloudQS(app, limit, windowHours)}`),
  // Wave 5 #16 — provider-declared incidents/maintenance (AWS Health lane);
  // one row per event, latest observation. Empty = the provider reported
  // nothing (or the lane needs an AWS support plan — see ingestion status).
  cloudProviderEvents: (windowHours?: number, limit?: number) =>
    request<{ events: CloudProviderEventRow[]; count: number; window_hours: number }>(
      `/api/cloud/provider-events${cloudQS(undefined, limit, windowHours)}`),
  // Wave 5 #16 — hybrid-seam telemetry: latest measured state per seam
  // endpoint (#105 lanes). Empty = the seam lanes have observed nothing in the
  // window (the UI renders "awaiting telemetry", never a green guess).
  cloudSeamTelemetry: (windowHours?: number, limit?: number) =>
    request<{ seams: CloudSeamTelemetryRow[]; count: number; window_hours: number }>(
      `/api/cloud/seam-telemetry${cloudQS(undefined, limit, windowHours)}`),

  // ---- Cloud Connectors: the done 7-step onboarding API (Wave 1 #3) ----
  // Every call is tenant-scoped server-side (owner from the token, never the body).
  // The provider catalog needs only infrastructure:read; the create/mutate/validate/
  // activate calls need infrastructure:write.
  cloudProviderCatalog: () =>
    request<{ providers: CloudProviderCatalogEntry[] }>("/api/cloud/providers"),
  cloudConnectors: () =>
    request<{ connectors: CloudConnectorView[] }>("/api/cloud/connectors"),
  cloudCreateConnector: (provider: CloudProvider, displayName: string) =>
    request<CloudConnectorView>("/api/cloud/connectors", {
      method: "POST",
      body: JSON.stringify({ provider, display_name: displayName }),
    }),
  cloudConnector: (id: string) => request<CloudConnectorView>(ccnPath(id)),
  cloudDeleteConnector: (id: string) =>
    request<{ deleted: string }>(ccnPath(id), { method: "DELETE" }),
  cloudConnectorAuth: (id: string, body: CloudAuthInput) =>
    request<CloudConnectorView>(ccnPath(id, "auth"), { method: "POST", body: JSON.stringify(body) }),
  cloudConnectorCapabilities: (id: string, capabilityPack: string) =>
    request<CloudConnectorView>(ccnPath(id, "capabilities"), {
      method: "POST",
      body: JSON.stringify({ capability_pack: capabilityPack }),
    }),
  cloudConnectorScopes: (id: string, scopes: CloudScope[]) =>
    request<CloudConnectorView>(ccnPath(id, "scopes"), { method: "POST", body: JSON.stringify({ scopes }) }),
  // Org-level (multi-account) anchor — {type:""} clears back to single-account.
  cloudConnectorOrg: (id: string, org: { type: string; ref?: string; role_template?: string }) =>
    request<CloudConnectorView>(ccnPath(id, "org"), { method: "POST", body: JSON.stringify(org) }),
  cloudConnectorSetup: (id: string) => request<CloudSetupBundle>(ccnPath(id, "setup")),
  // The HONEST trust proof: config validation + a LIVE broker credential exchange.
  cloudConnectorValidate: (id: string) =>
    request<CloudConnValidateResult>(ccnPath(id, "validate"), { method: "POST" }),
  cloudConnectorActivate: (id: string) =>
    request<CloudConnectorView>(ccnPath(id, "activate"), { method: "POST" }),
  // Legacy-only: encrypt-and-store a reusable secret (federated methods never call this).
  cloudConnectorSecret: (id: string, body: { kind: string; key_hint: string; secret: string }) =>
    request<CloudConnectorView>(ccnPath(id, "secret"), { method: "POST", body: JSON.stringify(body) }),

  // ---------- Telemetry coverage (parser programme A6) ---------------------
  // Platform-admin only; a 403 is a legitimate answer for a tenant admin and the
  // page renders it as a "platform-admin only" card, not as a failure.
  parserStats: () => request<ParserStats>("/api/admin/parser/stats"),
  // Tenant-scoped SERVER-side from the bearer token (§3a) — the client never
  // sends a tenant.
  unrecognizedTemplates: (q: UnrecognizedQuery = {}) => {
    const qs = unrecognizedParams(q);
    return request<UnrecognizedPage>(`/api/telemetry/unrecognized${qs ? `?${qs}` : ""}`);
  },
  // Drafts a catalog row from one template. Requires alerts:write; applies
  // NOTHING — the row is landed by a human through a pull request.
  proposeCatalogRow: (templateId: string) =>
    request<CatalogProposal>(
      `/api/telemetry/unrecognized/${encodeURIComponent(templateId)}/propose`,
      { method: "POST" },
    ),
};


// shared query string for the cloud signal surfaces (optional app + limit).
function cloudQS(app?: string, limit?: number, windowHours?: number, extra?: CloudSignalPage): string {
  const p = new URLSearchParams();
  if (app) p.set("app", app);
  if (limit) p.set("limit", String(limit));
  // Real time-range (Wave 2 #5): the backend clamps to 1..168h and reports the
  // honored value back in window_hours. Only sent when it differs from the 24h
  // default, so existing callers keep byte-identical requests.
  if (windowHours && windowHours !== 24) p.set("window_hours", String(windowHours));
  // Scale-out (Wave 3 #10): server-side search + keyset cursor. Both optional
  // and omitted when empty, so existing callers keep byte-identical requests.
  if (extra?.q) p.set("q", extra.q);
  if (extra?.cursor) p.set("cursor", extra.cursor);
  const qs = p.toString();
  return qs ? `?${qs}` : "";
}

// Wave 3 #10 — the shared paging/search params of the three signal surfaces.
export type CloudSignalPage = { q?: string; cursor?: string };

// Wave 5 #16 — wire rows of the security / provider-event / seam-telemetry reads
// (shapes mirror src/backend/cloud_security.go).
export interface CloudSecurityFindingRow {
  time: string;
  lane: "waf" | "lb" | "dns" | "other";
  signal: string;
  app: string;
  resource: string;
  source: string; // provider (aws|azure|gcp) or "cloud"
  severity: string;
  count: number;
  detail: string;
}

export interface CloudProviderEventRow {
  time: string;
  provider: string;
  service: string;
  region: string;
  category: string; // issue | scheduledChange | accountNotification
  status: string;   // the provider's own lifecycle status
  summary: string;
  severity: string;
}

export interface CloudSeamTelemetryRow {
  seam_id: string;
  state: "up" | "down" | "degraded" | "unknown";
  kind: string;
  severity: string;
  last_seen: string;
  events: number;
  provider: string;
  evidence_class: string;
}

// The relative export path for a signal surface (?format=csv|json) — the SAME
// query the table read uses (tenant scope enforced server-side), so an export
// can never show more than the table could. Fetched with the auth header by
// downloadCloudExport (a bare <a href> would arrive tokenless and 401).
export function cloudSignalExportPath(
  surface: "health" | "changes" | "evidence", format: "csv" | "json",
  app?: string, windowHours?: number, extra?: CloudSignalPage,
): string {
  const base = cloudQS(app, undefined, windowHours, extra);
  return `/api/cloud/${surface}${base ? base + "&" : "?"}format=${format}`;
}

// Multi-value server-side scope filters for /api/cloud/resources (Wave 2 #5 —
// each value list is comma-joined; OR within a dimension, AND across).
export interface CloudResourceQuery {
  providers?: string[];
  accounts?: string[];
  regions?: string[];
}

function cloudResourceQS(q?: CloudResourceQuery): string {
  if (!q) return "";
  const p = new URLSearchParams();
  if (q.providers?.length) p.set("provider", q.providers.join(","));
  if (q.accounts?.length) p.set("account", q.accounts.join(","));
  if (q.regions?.length) p.set("region", q.regions.join(","));
  const qs = p.toString();
  return qs ? `?${qs}` : "";
}

// Rows the backend already shapes for the UI tables (src/backend/cloud_signals.go).
export type CloudHealthSignalRow = {
  time: string; app: string; resource: string; signal: string; state: string;
  metric: string; current: string; baseline: string; severity: string; source: string;
  // Provider-declared cause of a health STATE event (Azure reasonType). Absent
  // for metric anomalies, which carry metric/current/baseline instead.
  reason?: string;
};
// Provider-native identity + server-built console deep-links for a row — the
// id an engineer pastes into the AWS/Azure console, one click away from the
// operator sentence (backend cloudEvidenceRef, cloud_console.go).
export type CloudRefWire = {
  provider?: string; resource_id?: string; account?: string; region?: string;
  log_ref?: string; signal_id?: string; console_url?: string; log_url?: string;
};
export type CloudChangeRow = {
  time: string; app: string; resource: string; change_type: string; actor: string;
  source: string; confidence: string; related_symptoms: string[];
  cloud_ref?: CloudRefWire;
};
export type CloudEvidenceRow = {
  time: string; category: string; signal_type: string; app: string; resource: string;
  source: string; confidence: string; reason: string; grounded: boolean;
  rca_group: string; evidence_ref: string; cloud_ref?: CloudRefWire;
};
export type CloudRcaObjectRow = {
  correlation_id: string; verdict_tier: string; confidence: number; top_hypothesis: string;
  signal_count: number; state: string; window_start: string; apps: string[];
};

export type CloudAppRcaRow = {
  correlation_id: string;
  verdict_tier: string;
  confidence: number;
  top_hypothesis: string;
  signal_count: number;
  state: string;
  window_start: string;
  created_at: string;
  affected: string;
  sources: string[];
  observer_count?: number;
  observers?: string[];
  plane_count?: number;
  cross_plane: number | boolean;
};

// ----- Security Policy types (mirror src/backend/policy/model.go JSON) -----
export type PolicyScope = "system" | "tenant" | "role" | "user";
export type PolicyDomain = "authentication" | "password" | "session" | "account_lifecycle";
export type PolicyKind = "bool" | "int" | "duration" | "enum" | "list";
export type PolicyHarden = "" | "higher" | "lower";

export type PolicyValue = {
  kind: PolicyKind;
  bool?: boolean;
  num?: number; // int count OR duration seconds
  str?: string; // enum selection
  list?: string[]; // list members
};
export type PolicyConstraint = {
  min?: number;
  max?: number;
  unit?: string; // "characters" | "attempts" | "seconds" | "days" | "minutes" | "hours" …
  enum?: string[];
};
export type PolicySetting = {
  key: string;
  domain: PolicyDomain;
  label: string;
  description: string;
  kind: PolicyKind;
  default: PolicyValue;
  constraint: PolicyConstraint;
  tier: "basic" | "advanced";
  nist: string[];
  lockable: boolean;
  harden: PolicyHarden;
  rationale: string;
};
export type PolicyCatalogDomain = { domain: PolicyDomain; settings: PolicySetting[] };
export type PolicyCatalog = { scopes: PolicyScope[]; domains: PolicyCatalogDomain[] };

export type PolicyTrailStep = {
  scope: PolicyScope;
  selector?: string;
  value: PolicyValue;
  locked?: boolean;
  applied: boolean;
  note?: string;
};
export type PolicyResolved = {
  key: string;
  domain: PolicyDomain;
  value: PolicyValue;
  source?: PolicyScope; // empty => from_default
  from_default: boolean;
  locked?: boolean;
  locked_at?: PolicyScope;
  trail?: PolicyTrailStep[];
};
export type PolicyOverride = { value: PolicyValue; locked?: boolean };
export type PolicyDocument = {
  scope: PolicyScope;
  selector: string;
  tenant?: string;
  overrides: Record<string, PolicyOverride>;
  updated_at?: string;
  updated_by?: string;
};
export type PolicySubject = { tenant?: string; role?: string; user?: string };
export type PolicyRef = { scope: PolicyScope; selector?: string; tenant?: string };

export type SNMPOptions = {
  versions: string[];
  security_levels: string[];
  auth_protocols: string[];
  priv_protocols: string[];
};
// Secrets (community/auth_key/priv_key) are write-only: sent on save, never
// returned. has_* booleans report whether one is stored.
export type SnmpGenResult = {
  vendor: string;
  version: string;
  templated: boolean;
  profile_id: string;
  device_config: string;
  community?: string;
  security_name?: string;
  auth_key?: string;
  priv_key?: string;
};

export type SNMPCredential = {
  id?: string;
  name: string;
  version: string; // v1 | v2c | v3
  port?: number;
  timeout_ms?: number;
  retries?: number;
  community?: string;
  has_community?: boolean;
  security_name?: string;
  security_level?: string;
  auth_protocol?: string;
  auth_key?: string;
  has_auth_key?: boolean;
  priv_protocol?: string;
  priv_key?: string;
  has_priv_key?: boolean;
  context?: string;
  created_at?: string;
};

// ----- Identity & access types -----
export type AdminUser = {
  username: string;
  role: string;
  email?: string;
  display_name?: string;
  tenant_id?: string;
  status?: string;
  auth_source?: string;
  mfa_enabled?: boolean;
  created_at?: string;
  last_login_at?: string;
};
export type Role = {
  id?: string;
  name: string;
  builtin?: boolean;
  description?: string;
  permissions: Record<string, number>; // module -> 0..3
};
export type Tenant = {
  id: string;
  name: string;
  slug: string;
  note?: string;
  org_id?: string; // the organization this tenant belongs to (blank = Global)
  region?: string; // data-residency region (blank = inherit org home_region)
  operator_restricted?: boolean; // compliance: operator may NOT view this tenant's telemetry
  status?: "active" | "suspended"; // lifecycle: a suspended tenant's users cannot sign in
  default_landing?: string; // admin-configured landing route ("" = inherit platform default)
  created_at?: string;
};
export type DataPlane = { region: string; local: boolean; clickhouse?: string; opensearch?: string; victoria_metrics?: string; kafka?: string };
export type RegionTopologyRow = { id: string; label: string; data_plane: DataPlane; tenants: number; orgs: number };
export type RegionTopologyResponse = { control_plane: { orgs: number; tenants: number; users: number }; regions: RegionTopologyRow[] };
export type Org = {
  id: string;
  name: string;
  slug: string;
  note?: string;
  home_region: string; // data-residency region id
  sso_connection?: string; // bound identity-provider connection (optional)
  created_at?: string;
};
export type Region = { id: string; label: string };
export type ScopeDetail = { tenant_id: string; tenant_name: string; org_id: string; org_name: string; region: string };
export type SecuritySettings = {
  scope: string;
  min_password_length: number;
  require_uppercase: boolean; require_lowercase: boolean; require_number: boolean; require_special: boolean;
  password_expire_enabled: boolean; password_expire_days: number; password_history: boolean;
  reset_on_first_login: boolean;
  login_attempts_allowed: number; unlock_time_seconds: number;
  account_validity_days: number; account_inactivity_days: number;
  concurrent_login: string;
  // Session lifecycle (per scope). idle is operator-facing; absolute is a hidden
  // standard default. enforce_* gate each at /api/auth/refresh.
  idle_timeout_minutes: number; absolute_timeout_minutes: number;
  enforce_idle_timeout: boolean; enforce_absolute_timeout: boolean;
};
export type AdminSession = {
  id: string; user_id: string; display_name?: string; tenant_id?: string;
  created_at: string; last_activity_at: string; last_refresh_at: string;
  issued_ip?: string; user_agent_hash?: string; status: string;
  idle_timeout_sec: number; absolute_timeout_sec: number;
};
// ----- Transport Security posture (SEC-021.1, read-only) -----
// Live probe observations for one transport path. `probe_ok` with a
// `cert_not_after` means a certificate was presented and parsed.
export interface PostureObserved {
  probe_ok: boolean;
  cert_not_after?: string;
  last_checked?: string;
}
// A declared, owner-accepted deviation from the target tier.
export interface PostureException { owner: string; accepted: string; reason: string }
// One transport path (edge) in the posture inventory.
export interface PostureRow {
  edge: string;
  source: string;
  destination: string;
  channel: string;
  protocol: string;
  port?: number;
  trust_domain: string;
  owning_epic: string;
  current_tier: string;
  declared_tier: string;
  target_tier: string;
  identity?: string;
  observed?: PostureObserved | null;
  drift?: string;
  exception?: PostureException | null;
  exception_age_days?: number;
}
export interface TransportValidatorFinding {
  rule: string;
  control: string;
  component: string;
  source: string;
  observed: string;
  required: string;
  remedy: string;
  severity: string;
}
export interface TransportValidator {
  profile: string;
  findings: TransportValidatorFinding[];
  fatal: number;
  warn: number;
  info: number;
}
// scope:"platform" carries rows + validator; scope:"tenant" carries
// device_lanes + device_count (the tenant never sees platform-internal paths).
export interface TransportPosture {
  scope: "platform" | "tenant";
  generated: string;
  rows?: PostureRow[];
  validator?: TransportValidator;
  device_lanes?: PostureRow[];
  device_count?: number;
}

export type GrantReason = { role_id: string; scope_id: string; effect: string; granted_by?: string; reason?: string; break_glass?: boolean; expires_at?: string };
export type TenantReach = { tenant_id: string; tenant_name: string; org_id: string; org_name: string; granted_by: GrantReason[] };
export type AccessExplanation = { principal: string; all_tenants: boolean; org_admin_of: string[] | null; bindings: RoleBinding[] | null; reaches: TenantReach[] | null };
export type RoleBinding = {
  id: string;
  principal_id: string;
  role_id: string;
  scope_type: string;
  scope_id: string;
  effect: string; // allow | deny
  expires_at?: string;
  granted_by?: string;
  reason?: string;
  granted_at?: string;
};
export type ApiKey = {
  id: string;
  tenant_id: string;
  label: string;
  prefix: string;
  scopes: string[];
  rate_limit_per_min: number; // effective per-minute cap (0 = unlimited)
  use_count: number; // lifetime authenticated calls
  window_used: number; // calls counted in the current minute
  created_by: string;
  created_at: string;
  last_used_at?: string;
  revoked_at?: string;
  // Client metadata
  grant_types?: string[];
  client_uri?: string;
  logo_uri?: string;
  contacts?: string[];
  contact_phone?: string;
  source_cidrs?: string[];
  client_expires_at?: string;
  secret_expires_at?: string;
};

// CreateApiKeyRequest is the registration payload for minting a new key.
// Only `label` is mandatory; everything else is optional metadata.
export type CreateApiKeyRequest = {
  label: string;
  scopes: string[];
  rate_limit_per_min?: number;
  tenant_id?: string;
  grant_types?: string[];
  client_uri?: string;
  logo_uri?: string;
  contacts?: string[];
  contact_phone?: string;
  source_cidrs?: string[];
  client_expires_at?: string;
  secret_expires_at?: string;
};

export type ReportKind =
  | "alerts_summary"
  | "device_inventory"
  | "health_summary"
  | "wan_utilization"
  | "security_threats"
  | "device_utilization"
  | "latency_jitter_sla";
export type ReportBody = {
  kind: ReportKind;
  interval_minutes: number;
  severity: string;
  enabled: boolean;
  description?: string;
  // Optional delivery-channel restriction (email, slack, pagerduty, sns, twilio…).
  // Empty/undefined => all configured channels.
  channels?: string[];
  // Reusable contact points (by id) this report is delivered to. Email-type
  // points are resolved to addresses and emailed directly.
  contact_points?: string[];
  // How contact-point delivery carries the report: "body" emails the rendered
  // report; "link" emails a secure link (rolling out). Default "body".
  delivery_mode?: "body" | "link";
  // Calendar+timezone schedule (async backend). Supersedes interval_minutes when set.
  schedule?: Recurrence;
  // Output formats to render: html (always), xlsx, pdf. Empty => html only.
  formats?: ReportFormat[];
};

export type ReportFormat = "html" | "xlsx" | "pdf";
export type Weekday = "" | "sun" | "mon" | "tue" | "wed" | "thu" | "fri" | "sat";
export type Recurrence = {
  tz: string; // IANA, e.g. "America/Chicago"; "" => UTC
  hour: number; // 0..23
  minute: number; // 0..59
  weekday?: Weekday; // set => weekly
  dom?: number; // 1..31 => monthly (takes precedence over weekday)
};

export type ArtifactRef = {
  format: ReportFormat;
  content_type: string;
  size_bytes: number;
  sha256: string;
  summary: string;
  key: string;
};
export type DeliveryStatus = {
  channel: string;
  recipient: string;
  ok: boolean;
  attempt: number;
  error?: string;
  at: string;
};
export type ExecEvent = { phase: string; at: string; note?: string };
export type ReportExecution = {
  id: string;
  tenant_id?: string;
  schedule_id: string;
  job_id?: string;
  fire_time: string;
  started_at?: string;
  completed_at?: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  artifacts?: ArtifactRef[];
  delivery_status?: DeliveryStatus[];
  error?: string;
};
export type ReportExecutionDetail = ReportExecution & { events?: ExecEvent[] };

export type ContactPointType = "email" | "slack" | "webhook";
export type ContactPoint = {
  id: string;
  tenant_id?: string;
  name: string;
  type: ContactPointType;
  email?: string[];
  target?: string;
  enabled: boolean;
};
export type ReportRun = {
  last_run?: string;
  next_run?: string;
  status?: string;
  detail?: string;
};

export type GlobalResultKind = "device" | "alert" | "saved" | "logs";
export type GlobalResult = {
  kind: GlobalResultKind;
  id: string;
  title: string;
  sub: string;
  route: string;
};
export type GlobalSearchResponse = { query: string; results: GlobalResult[] };

// Unified search (Wave 6 #20): typed results with a permanent deep-link href
// (hash route without the leading "#/"). The id is the canonical opaque id.
export type SearchHitKind = "device" | "resource" | "app" | "account" | "case";
export type SearchHit = {
  kind: SearchHitKind;
  id: string;
  label: string;
  sublabel?: string;
  href: string;
};
export type UnifiedSearchResponse = { query: string; results: SearchHit[] };

// Single-resource read behind the permanent #/resource/cloud/{id} page.
// Live fields are present only when actually measured — absence is honest.
export type CloudResourceDetailResponse = {
  resource: CloudResourceRow;
  health?: string;
  health_basis?: string;
  traffic_bytes?: number;
  cpu_pct?: number;
  console_url?: string;
};

export type SavedType = "saved_search" | "dashboard" | "report";
export type SavedObject = {
  id: string;
  type: SavedType;
  name: string;
  owner: string;
  body: any;
  created_at: string;
  updated_at: string;
};

// ----- SSO / API / ITSM -----
export type SSOProvider = { id: string; name: string; kind: "oidc" | "saml" | "ldap" | "tacacs" };
export type SSOConfig = { enabled: boolean; providers: SSOProvider[] };

// OIDC/SSO provider config (admin-gated). The client secret is write-only: the
// server returns client_secret_set instead of the value, and a PUT that omits
// client_secret preserves the stored one.
export type OidcConfig = {
  enabled: boolean;
  issuer: string;
  client_id: string;
  client_secret_set: boolean;
  scopes: string;
  redirect_url: string;
  post_login_url: string;
  default_role: string;
  default_tenant: string;
  admin_roles: string;
  operator_roles: string;
  providers: string;
  require_mfa?: boolean; // reject SSO sign-ins the IdP didn't MFA (amr/acr)
  mfa_acr?: string; // optional csv of acr values that count as MFA
};

// Keycloak-brokered identity providers (GUI-configurable SSO). One record per
// upstream IdP (SAML or OIDC) registered in the Keycloak realm. The client
// secret is write-only: GET redacts it to client_secret_set. role_mappings is
// an ORDERED array — first match wins, so the UI must preserve row order.
export type SsoIdpAttrMapping = { idp_attr: string; user_attr: string };
export type SsoIdpRoleMapping = { value: string; role: string };
export type SsoIdP = {
  alias: string;
  display_name: string;
  protocol: "saml" | "oidc";
  enabled: boolean;
  // SAML: point at metadata by URL, or paste/upload the XML; optionally pin the
  // IdP signing certificate (drives the client-side expiry banner).
  metadata_url?: string;
  metadata_xml?: string;
  signing_cert_pem?: string;
  // OIDC: discovery + client credentials.
  discovery_url?: string;
  client_id?: string;
  client_secret?: string; // write-only; never returned by GET
  client_secret_set?: boolean; // GET only — whether a secret is stored
  groups_attr: string;
  attr_mappings: SsoIdpAttrMapping[];
  role_mappings: SsoIdpRoleMapping[];
};
export type SsoIdpListResponse = {
  idps: SsoIdP[];
  keycloak: { reachable: boolean; realm: string; detail?: string };
};
export type SsoIdpSaveResponse = { idp: SsoIdP; applied: boolean; warnings: string[] };
export type SsoIdpTestCheck = { name: string; ok: boolean; detail: string };
export type SsoIdpTestResult = { ok: boolean; checks: SsoIdpTestCheck[]; cert_not_after?: string };

// Native (non-Keycloak) auth providers, configured at runtime via the admin UI.
export type LdapRoleMapping = { group: string; role: string };
export type LdapConfig = {
  enabled: boolean;
  host: string;
  port: number;
  use_tls: boolean;
  start_tls: boolean;
  bind_dn: string;
  bind_password_set: boolean;
  base_dn: string;
  user_filter: string;
  group_base_dn: string;
  group_filter: string;
  role_mappings: LdapRoleMapping[];
  default_role: string;
  default_tenant: string;
  insecure_skip_verify: boolean;
};
export type TacacsConfig = {
  enabled: boolean;
  host: string;
  port: number;
  secret_set: boolean;
  timeout_seconds: number;
  default_role: string;
  default_tenant: string;
};
export type AuthTestResult = {
  ok: boolean;
  stage: string;
  message: string;
  resolved_dn?: string;
  groups?: string[];
  assigned_role?: string;
};
export type TokenPolicy = {
  access_ttl_seconds: number;
  refresh_ttl_seconds: number;
  bounds: {
    access_min_seconds: number; access_max_seconds: number; access_recommended_seconds: number;
    refresh_min_seconds: number; refresh_max_seconds: number; refresh_recommended_seconds: number;
  };
};
export type AuthMethods = {
  local: boolean;
  ldap: { enabled: boolean; name: string };
  tacacs: { enabled: boolean; name: string };
  sso: { enabled: boolean; providers: SSOProvider[] };
};

export type OpenAPIOperation = { tags?: string[]; summary?: string };
export type OpenAPISpec = {
  openapi: string;
  info: { title: string; version: string; description?: string };
  paths: Record<string, Record<string, OpenAPIOperation>>;
};

export type ServiceNowTicket = {
  fingerprint: string;
  number: string;
  sys_id: string;
  severity: string;
  device?: string;
  summary?: string;
  opened_at: string;
  state: string;
};
export type ServiceNowStatus = {
  enabled: boolean;
  configured: boolean;
  threshold?: string;
  auto_close?: boolean;
  open?: ServiceNowTicket[];
  open_count?: number;
};

export type JiraTicket = {
  fingerprint: string;
  key: string;
  issue_id: string;
  severity: string;
  device?: string;
  summary?: string;
  opened_at: string;
  state: string;
};
export type JiraStatus = {
  enabled: boolean;
  configured: boolean;
  project?: string;
  threshold?: string;
  auto_close?: boolean;
  open?: JiraTicket[];
  open_count?: number;
};

// ITSM connector config (admin-editable). GET returns has_password/has_token +
// configured flags (secrets are write-only and never returned); PUT sends the
// secret only when (re)setting it — leave blank to keep the stored one.
export type ItsmServiceNowConfig = {
  enabled: boolean;
  instance_url: string;
  user: string;
  has_password?: boolean;
  password?: string;
  min_severity: string;
  assignment_group: string;
  configured?: boolean;
};
export type ItsmJiraConfig = {
  enabled: boolean;
  base_url: string;
  email: string;
  has_token?: boolean;
  api_token?: string;
  project_key: string;
  issue_type: string;
  min_severity: string;
  resolve_transition: string;
  configured?: boolean;
};
// ITSM Integration Platform — bidirectional-sync config. One entry per provider
// (servicenow | jira | pagerduty | slack). The webhook signing secret is
// write-only: GET reports webhook_secret_set instead of the value, and a PUT
// that omits webhook_secret preserves the stored one. webhook_url is only
// present once a token exists; prepend window.location.origin to get the full
// URL to paste into the provider.
export type IntegrationConfig = {
  provider: string; // servicenow | jira | pagerduty | slack
  enabled: boolean;
  sync_mode: "outbound" | "bidirectional";
  webhook_enabled: boolean;
  webhook_secret_set: boolean;
  webhook_url?: string; // path only, present when a token exists
  state_map: Record<string, string> | null; // {<external>: <internal>}
};
// inbound_enabled mirrors the server's FEATURE_ITSM_INBOUND flag — inbound
// state changes are recorded regardless but only drive incident state when true.
export type IntegrationsResponse = { integrations: IntegrationConfig[]; inbound_enabled: boolean };

// ── NMS vendor-controller integrations (#95) ─────────────────────────────────

// Wireless canonical inventory (#128) — mirrors src/backend/wireless/model.go
// JSON tags (the read-only /api/wireless/* surface).
export type WirelessRadio = {
  radio_id: string;
  ap_id: string;
  slot: number;
  band?: string;
  channel?: number;
  admin_state?: string;
  oper_state?: string;
  generation?: string;
  mlo_capable?: boolean;
};

export type WirelessAP = {
  ap_id: string;
  name: string;
  mac_base?: string;
  serial?: string;
  model?: string;
  vendor?: string;
  controller_ref?: string;
  site_id?: string;
  uplink_switch_ref?: string;
  uplink_port_ref?: string;
  mgmt_address?: string;
  forwarding_mode?: string;
  radios?: WirelessRadio[];
  first_seen?: string;
  last_seen?: string;
  stale?: boolean;
};

export type WirelessControllerMember = {
  member_id: string;
  controller_id: string;
  name: string;
  member_state: string;
  redundancy_role: string;
};

export type WirelessController = {
  controller_id: string;
  name: string;
  vendor: string;
  model?: string;
  kind?: string;
  cluster_role: string;
  management_address?: string;
  forwarding_default?: string;
  visibility?: string;
  members?: WirelessControllerMember[];
  first_seen?: string;
  last_seen?: string;
  stale?: boolean;
};

export type WirelessWLAN = {
  wlan_id: string;
  profile_name: string;
  ssid_name: string;
  ssid_ref?: string;
  controller_ref?: string;
  security_mode?: string;
  auth_method?: string;
  forwarding_mode?: string;
  mobility_domain_ref?: string;
  enabled: boolean;
  stale?: boolean;
};

export type NmsConnector = {
  vendor: string;
  product: string;
  supportedAuth: string[];
  preferredAuth: string;
  webhook: boolean;
  poll: boolean;
  streams: string[];
  defaultPollS: number;
};

export type NmsIntegration = {
  id: string;
  vendor: string;
  product?: string;
  displayName: string;
  enabled: boolean;
  baseUrl: string;
  authType?: string;
  pollIntervalS: number;
  streams?: string[];
  tlsSkipVerify?: boolean;
  webhookUrl?: string;
  credentialFieldsSet?: string[];
  createdAt?: string;
  updatedAt?: string;
};

export type NmsIntegrationInput = {
  vendor: string;
  displayName: string;
  enabled?: boolean;
  baseUrl: string;
  authType?: string;
  pollIntervalS?: number;
  streams?: string[];
  tlsSkipVerify?: boolean;
  // Write-only: encrypted at rest, never returned.
  credentials?: Record<string, string>;
};

export type NmsPollResult = { status: string; events: number; durationMs: number; error?: string };

export type NmsRun = { runId: string; started: string; finished: string; status: string; events: number; error?: string };

export type NmsHealth = {
  healthy: boolean;
  lastSuccess?: string;
  lastError?: string;
  lastErrorAt?: string;
  eventsIngested: number;
  errorRate: number;
  updatedAt?: string;
  runs?: NmsRun[];
};

export type NmsStateRow = {
  entityKey: string;
  stateKind: string;
  currentState: string;
  previousState: string;
  firstSeen: string;
  lastSeen: string;
  flapCount: number;
  deviceId: string;
  siteId: string;
};

export type ItsmPagerDutyRCA = { enabled: boolean; has_routing_key?: boolean; configured?: boolean };
export type ItsmSlackRCA = { enabled: boolean; has_webhook?: boolean; configured?: boolean };
export type ItsmConfig = { servicenow: ItsmServiceNowConfig; jira: ItsmJiraConfig; pagerduty?: ItsmPagerDutyRCA; slack?: ItsmSlackRCA };
export type ItsmConfigInput = {
  servicenow: Omit<ItsmServiceNowConfig, "has_password" | "configured">;
  jira: Omit<ItsmJiraConfig, "has_token" | "configured">;
};

export type PromNamesResponse = { status: string; data: string[] };
export type PromSeries = { metric: Record<string, string>; values: [number, string][] };

// Active-measurement (traceroute) path topology — from /api/probe/paths.
// `via` is set in priority/auto mode: the fallback method (e.g. "tcp") that
// filled this hop when the primary method (icmp) got no reply.
// rtt_ms/loss_pct are optional: a hop with no reply, or a prober that doesn't
// measure per-hop loss, omits them (the UI must null-check, not assume present).
export type ProbeHop = { ttl: number; ip: string; host?: string; rtt_ms?: number; loss_pct?: number; via?: string };
// A destination can be traced by more than one method (icmp + tcp); they often
// diverge, so each (dst, method) is a distinct ProbePath.
export type ProbePath = { dst: string; method?: string; hops: ProbeHop[]; reached: boolean; changed: boolean; ts: string };

// A normalized topology adjacency. source_protocol is one (or a "+"-joined set
// when independently confirmed) of lldp | cdp | bgp_ls. For bgp_ls links igp
// carries the IGP origin (isis-l1/l2, ospfv2/v3) and area the IGP area — these
// drive the Logical (IGP) topology sub-view.
export type TopoLink = {
  source: string; target: string; source_name: string; target_name: string;
  local_port: string; remote_port: string; source_protocol: string;
  igp?: string; area?: string;
  resolved: boolean; bidirectional: boolean; last_observed_at: number;
};
// Device Geomap — NetBox DCIM sites (lat/lng intent data) joined with inventory health.
export type DeviceLocationRow = {
  id: string; name: string; vendor?: string; site?: string;
  lat?: number; lng?: number; source: "sot" | "manual" | "none";
};

export type GeoSite = {
  name: string; slug: string; status?: string;
  lat: number; lng: number; has_coords: boolean;
  devices: number; up: number; down: number;
};
export type GeomapResponse = {
  geo_enabled: boolean; reason?: string; error?: string;
  sites?: GeoSite[]; placed?: number; unplaced?: number;
};

// Internal SoT sites (the default provider's editable data).
export type SiteRow = {
  slug: string; name: string; status?: string;
  lat: number; lng: number; has_coords: boolean;
  owner?: string; // operator-declared ownership intent (team / on-call / BU)
  updated_by?: string; updated_at?: string;
};
export type SitesResponse = { sites: SiteRow[]; active: "internal" | "netbox" | string };
export type SiteInput = { slug?: string; name: string; status?: string; owner?: string; lat?: number; lng?: number };

// External SoT import plan/result (POST /api/sot/import).
export type ImportRowResult = { line: number; key: string; action: string; detail?: string };
export type ImportResult = { kind: string; dry_run: boolean; summary: Record<string, number>; rows: ImportRowResult[] };
export type PromRangeResponse = {
  status: string;
  data?: { resultType: string; result: PromSeries[] };
  error?: string;
};

// Cloud metric charts (Wave 5 #14) — GET /api/cloud/metrics/series. Points are
// [unix_seconds, value] (Prometheus convention; the chart multiplies by 1000).
// An empty points array is an HONEST "nothing ingested", never a flatline.
export type CloudMetricPoint = [number, number];
export type CloudMetricSeriesEntry = {
  resource_id: string;
  resource_name?: string;
  points: CloudMetricPoint[];
};
export type CloudMetricCatalogEntry = { name: string; label: string; unit: string };
export type CloudMetricSeriesResponse = {
  metric: string;
  label: string;
  unit: string; // percent | bytes | count
  window_minutes: number;
  step_seconds: number;
  start: number;
  end: number;
  series: CloudMetricSeriesEntry[];
  catalog: CloudMetricCatalogEntry[];
};

// Per-tenant SLOs (Wave 5 #14 slice 2) — /api/cloud/slos shapes
// (src/backend/cloud_slo.go). status is computed at read time; measurable=false
// carries a basis naming exactly what is missing.
export type CloudSloDef = {
  app_name: string;
  target_pct: number;
  window_days: number;
  description?: string;
};
export type CloudSloStatus = {
  measurable: boolean;
  actual_pct?: number;
  budget_pct: number;
  budget_remaining_pct?: number;
  burn_ratio?: number;
  resources_total: number;
  resources_reporting: number;
  basis: string;
};
export type CloudSloRow = CloudSloDef & { status?: CloudSloStatus };
export type CloudSloResponse = {
  tenant_id: string;
  slos: CloudSloRow[];
  count: number;
  max_slos: number;
};

// Per-tenant cloud monitors (Wave 5 #14 slice 3) — /api/cloud/monitors shapes
// (src/backend/cloud_monitors.go). last_* fields are evaluator-written.
export type CloudMonitorMode = "threshold" | "anomaly";
export type CloudMonitorState =
  | "never_evaluated" | "ok" | "firing" | "no_data" | "error" | "disabled";
export type CloudMonitorInput = {
  name: string;
  metric: string;
  resource_id?: string; // "" = every cloud resource in the tenant inventory
  mode: CloudMonitorMode;
  condition?: "above" | "below"; // threshold mode only
  threshold?: number;            // threshold mode only
  enabled: boolean;
};
export type CloudMonitorRow = CloudMonitorInput & {
  id: string;
  tenant_id: string;
  created_at?: string;
  updated_at?: string;
  last_state: CloudMonitorState;
  last_value?: number;
  last_reason?: string;
  last_eval_at?: string;
};

// Instant query — one sample per matching series.
export type PromInstantSeries = { metric: Record<string, string>; value: [number, string] };
export type PromInstantResponse = {
  status: string;
  data?: { resultType: string; result: PromInstantSeries[] };
  error?: string;
};

// ---------- Cloud App Observability (#81 P3) ----------
// Backend cloud.* JSON shapes (src/backend/cloud/model.go + derive.go). The App
// Observability UI maps these into its view types (pages/appobs/types.ts) — see
// pages/appobs/api.ts. Confidence/source string values match the UI enums 1:1.
export type CloudConfidence = "confirmed" | "strong" | "suspected" | "weak" | "unknown";
export type CloudSource =
  | "cloud_tag" | "cloud_graph" | "operator_catalog" | "firewall_appid"
  | "domain" | "ip_catalog" | "unknown";

export type CloudResourceRow = {
  tenant_id: string;
  cloud_provider: string; // aws | azure | gcp | ""
  account_id: string;
  region: string;
  zone?: string;
  resource_id: string;
  resource_arn_or_uri?: string;
  resource_type: string; // e.g. "AWS::ElasticLoadBalancingV2::LoadBalancer"
  resource_name?: string;
  private_ips?: string[];
  public_ips?: string[];
  network_interface_ids?: string[];
  tags?: Record<string, string>;
  power_state?: string; // provider lifecycle: running | stopped | deallocated…
  owner?: string;
  env?: string;
  app_id?: string;
  app_name?: string;
  discovered_at: string;
  last_seen_at: string;
  source: CloudSource;
  confidence: CloudConfidence;
};

export type CloudAppRow = {
  app_id: string;
  app_name: string;
  owner: string;
  env: string;
  cloud_provider: string;
  account_id: string;
  region: string;
  confidence: CloudConfidence;
  source: CloudSource;
  resources: number;
};

export type CloudCoverageReport = {
  confirmed_tag: number;
  strong_graph: number;
  firewall_appid: number;
  suspected_domain_ip: number;
  unknown: number;
  total: number;
};

// Per-tenant required-tags governance setting (Wave 4 #11 slice 1).
export type RequiredTagsSettings = {
  tenant_id: string;
  required_tags: string[];
  is_default: boolean;
  default_tags: string[];
};

// Per-tenant RCA/signal read-window default (Wave 4 #11 slice 2).
export type RcaWindowSettings = {
  tenant_id: string;
  rca_window_hours: number;
  is_default: boolean;
  default_hours: number;
  max_hours: number;
};

// Per-tenant attribution-precedence ordering (Wave 4 #11 slice 3).
export type AttributionPrecedenceSettings = {
  tenant_id: string;
  attribution_precedence: string[];
  is_default: boolean;
  default_precedence: string[];
};

// Per-tenant seam-ownership registry (#113 slice 2): owner CLASS (isp /
// carrier / cloud_provider / …) → the tenant's actual responsible party.
export type SeamOwnerEntry = { name: string; contact?: string };
export type SeamOwnersSettings = {
  tenant_id: string;
  seam_owners: Record<string, SeamOwnerEntry>;
  is_default: boolean;
  classes: string[];
};

// One governance-settings audit event (backend AuditEvent, filtered to the
// settings actions by /api/settings/governance-audit).
export type GovernanceAuditEvent = {
  id: string;
  time: string;
  actor: string;
  tenant?: string;
  method: string;
  path: string;
  status: number;
  decision: string;
  detail?: Record<string, unknown>;
};

// Required-tag compliance over the tenant's inventory (coverage response).
export type CloudTagCompliance = {
  required_tags: string[];
  total: number;
  fully_tagged: number;
  missing_by_tag: Record<string, number>;
};

// A named business service (backend business_service_store.go BusinessService).
export type BusinessServiceRow = {
  business_service_id: string;
  tenant_id: string;
  name: string;
  description: string;
  criticality: string; // critical | high | normal | low | ""
  owner: string;       // accountable team/person label ("" = unset)
  runbook_url: string; // https-only operational runbook link ("" = unset)
  created_by: string;
  created_at: string;
  updated_at: string;
};

// The editable catalog fields (the id/tenant/audit stamps are server-owned).
export type BusinessServiceInput = {
  name: string;
  description?: string;
  criticality?: string;
  owner?: string;
  runbook_url?: string;
};

// One resource_id → service binding (backend ResourceMapping).
export type ResourceMappingRow = {
  tenant_id: string;
  resource_id: string;
  business_service_id?: string;
  service_name: string;
  source: string;
  confidence: string;
  basis: string;
  is_manual_override: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
};

export type CloudIdentityMappingRow = {
  tenant_id: string;
  match_key_type: string;
  match_key: string;
  app_id: string;
  app_name: string;
  owner?: string;
  env?: string;
  resource_id?: string;
  source: CloudSource;
  confidence: CloudConfidence;
  attribution_reason: string;
  updated_at: string;
};

// ── Security CTEM (P3-T8) ─────────────────────────────────────────────────
// The read model behind the Security section. Every shape here mirrors the
// backend contract 1:1 (src/backend/internal/secfindings/finding.go for the
// finding itself) — the client INVENTS nothing. All of it is tenant-scoped by
// the bearer token server-side (§3a): the UI never asks for, and must never
// assume it can see, another tenant's rows; a foreign id answers 404 and is
// rendered as "not found", never as an empty-but-clean state.

/** Subject of a finding — the device or host it concerns (Resource in Go). */
export type SecResource = {
  uid?: string;
  name?: string;
  hostname?: string;
  ip?: string;
  type?: string;      // host | network-device | container
  platform?: string;  // e.g. "Cisco IOS-XE 17.9"
};

/** By-reference, version-pinned pointer to the raw artifact a verdict came from. */
export type SecEvidenceRef = {
  locator: string;
  kind?: string;            // oval-result | ch-row | config-line | os-doc | arf
  ruleset_version?: string;
  digest?: string;
};

/** Optional seam attribution — set only on seam-aware exposure findings. */
export type SecSeamContext = {
  seam_id?: string;
  seam_type?: string;       // e.g. "ISP", "internet", "mgmt"
  internet_facing?: boolean;
};

/**
 * One normalized security finding: one subject × one evaluated rule, with an
 * OCSF-normalized verdict. `status_id` is 1=Pass 2=Warning 3=Fail
 * 4=NotApplicable 5=Error — 4/5 are NOT a pass, which is why the UI renders
 * them as "unassessed", never green.
 *
 * `id`, `time`, `scan_id` and `native_id` are the read-API additions on top of
 * the stored document (tenant_id is never serialized to a client).
 */
export type SecFinding = {
  id: string;               // OpenSearch doc id
  native_id: string;        // stable provider identity (current-verdict collapse key)
  scan_id?: string;         // read-API alias of scan_uid
  scan_uid?: string;
  uid?: string;
  time: string;
  source?: string;
  evidence_class?: string;  // posture | exposure | signal (threat lane) …
  status?: string;
  status_id: number;
  standards?: string[];
  control?: string;
  control_title?: string;
  category_name?: string;
  severity?: string;        // critical | high | medium | low | info
  resource: SecResource;
  observed?: string;
  intended?: string;
  status_detail?: string;
  remediation?: string;
  evidence_ref?: SecEvidenceRef;
  raw_rule_id?: string;
  seam?: SecSeamContext;
};

/** GET /api/security/findings — one cursor page. */
export type SecFindingsPage = {
  items: SecFinding[];
  next_cursor: string | null;
  total: number;
};

/** The filter set every findings-family endpoint accepts (all optional). */
export type SecFindingQuery = {
  cursor?: string;
  limit?: number;
  severity?: string;
  status?: string;
  seam?: string;
  framework?: string;
  device?: string;
  q?: string;
  since?: string;
  until?: string;
  /** true = latest verdict per native_id ("current"); false = full history. */
  current?: boolean;
};

/** GET /api/security/findings/facets — counts for the same filter set. */
export type SecFacets = {
  severity: { crit: number; high: number; medium: number; low: number; info: number };
  status: { pass: number; warn: number; fail: number };
  seam: Record<string, number>;
  framework: Record<string, number>;
  evidence_class: Record<string, number>;
};

/** GET /api/security/findings/trend — one bucket per period. */
export type SecTrendBucket = { t: string; fail: number; warn: number; pass: number };
export type SecTrend = { buckets: SecTrendBucket[] };

/**
 * GET /api/security/posture — the CTEM funnel + assessment coverage.
 * `coverage.unassessed` is rendered honestly (an unassessed asset is UNKNOWN,
 * never "clear"); the funnel numbers are counts, never percentages of a total
 * the API did not state.
 */
export type SecPosture = {
  funnel: {
    scope: number;       // assets in scope
    discover: number;    // current findings
    prioritize: number;  // high or critical
    validate: number;    // validated
    mobilize: number;    // has an owner
  };
  coverage: { assessed_assets: number; total_assets: number; unassessed: number };
  last_scan: { scan_id: string; time: string };
};

/** GET/PUT /api/security/rules — the detection/hardening rule inventory. */
export type SecRule = {
  rule_id: string;
  family: string;
  enabled: boolean;
  fidelity: string;
  mitre?: string[];
  seam_aware: boolean;
};
/** PUT body — enablement only; the server owns every other field. */
export type SecRuleToggle = { rule_id: string; enabled: boolean };

/** GET/POST/DELETE /api/security/views — a named, saved filter set. */
export type SecSavedView = {
  id: string;
  name: string;
  filters: SecFindingQuery;
};

// ── Iris AI ───────────────────────────────────────────────────────────────
export type AiCitation = { id: string; kind: string; label: string; href: string };
export type AiProblemExplanation = {
  problem_id: string;
  title: string;
  verdict: string;
  confidence: string;
  summary: string;
  root_cause_hypothesis: string;
  timeline: string[];
  supporting_evidence: string[];
  contradicting_evidence: string[];
  missing_evidence: string[];
  recommended_owner: string;
  itsm_note: string;
  why_first?: string[]; // "why this is the top incident" (spec §4)
};
export type AiNavEntry = { feature: string; ui_route: string; required_permission: string; explanation: string; related_module: string };
// Normalized, labeled incident counts (spec §6) — one definition per number.
export type AiIncidentCounts = {
  active_correlation_groups: number;
  confirmed_count: number;
  suspected_count: number;
  candidate_count: number;
  undetermined_count: number;
  actionable_incidents_count: number;
  low_evidence_watch_items_count: number;
  capped?: boolean;
};
// P4 module-aware answer schema (flow analytics, telemetry, …): a focused,
// evidence-grounded read of ONE module's governed tools, with a model headline.
export type AiModuleHealth = {
  module: string;
  display_name: string;
  headline: string;
  items: string[];
  notes: string[];
};
export type AiCurrentState = {
  summary: string;
  title?: string;
  counts?: AiIncidentCounts;
  active_incidents: string[];
  confirmed: number;
  suspected: number;
  undetermined: number;
  impacted_entities: string[];
  recommended_focus: string[];
  focus_reason?: string;
  watch_note?: string;
  actionable_count?: number;
  confidence_notes: string[];
  missing_data: string[];
  // Focus status/confidence label the RECOMMENDED-FOCUS incident only (spec §2/§3)
  // — rendered inside the focus section, never as the whole card's status.
  focus_status?: string;
  focus_confidence?: string;
  suspected_incidents?: string[]; // "Active suspected incidents" section (spec §5/§6)
  why_first?: string[]; // reasons the focus leads (spec §4/§5)
  counts_legend?: string[]; // explains the count categories (spec §6)
};
export type AiCommand = {
  command: string;
  aliases?: string[];
  label: string;
  description: string;
  intent: string;
  risk_level: string;
  requires_context?: boolean;
};
export type AiAnswer = {
  mode: string;
  intent: string;
  modules: string[];
  text: string;
  problem?: AiProblemExplanation;
  current_state?: AiCurrentState;
  module?: AiModuleHealth;
  navigation?: AiNavEntry[];
  citations: AiCitation[];
  disclaimers: string[];
  provider?: string;
  // Universal Response-Quality fields (rendered as badges + sections).
  status?: string;
  confidence_label?: string;
  recommended_owner?: string;
  next_actions?: string[];
  missing_evidence?: string[];
  mode_badges?: string[];
  evidence_only?: boolean;
  provider_note?: string; // single small provider-fallback footer (spec §1)
  title?: string; // card heading (spec §2)
  counts?: AiIncidentCounts; // normalized counts (spec §6)
};
