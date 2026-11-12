# src/correlation — the correlation engine, as it actually works

**Why this file exists (owner, 2026-10-24):** the correlation engine is the product's
original purpose. Its design is default knowledge for anyone writing code or approving
designs ANYWHERE in this repo. Every feature (a connector, a UI change, an ops fix) is
judged by what it gives the engine: signals, entities, topology, contrast, timing and
ownership. A change to the engine is framed as a change to one named stage below. Never
propose as new something this file says already exists.

Verified against the code on 2026-10-24 (main 646c40e2); singleton rule, clause
fields and ENGINE_SEMVER re-verified 2026-11-09 (tracker 385). **If the code and this file
disagree, the code wins: fix this file in the same change.**
Abbreviations: **E** engine.py · **M** main.py · **S** signals.py · **SC** scoring.py ·
**V** verdicts.py · **C** catalog.py · **CF** confirmability.py · **R** replay.py.
Go paths are under `src/backend/`. `[lead]` = read from the code, not yet proven by a test.

**One sentence.** Kafka lane records become canonical `Signal`s. Signals are grouped
per tenant into an event-time window. Groups of signals are joined ONLY by a ranked
relationship ("grounding"). Connected components become versioned correlation objects.
Each object is scored against a declarative signature catalog (the *rank*: competing
hypotheses) and, separately, graded by an evidence-independence gate (the *verdict*).
Objects are persisted to ClickHouse and are replayable. The core is PURE: no IO, no
clock, no randomness, no dependence on dict order (E:4-19, SC:7-9, V:7-9).

## 1. Inputs — [1] normalize (S), [2] episodes (episodes.py)

**Signal** (S:736-766): `tenant_id`, `ts` (must be timezone-aware), `source`
(S:129-161), `kind`, `observer`, `modality_class` (S:173-196), `entity_type` /
`entity_id`, `severity` (info|warn|high|crit), `native_id`, `entity_tokens`, `site`,
`path_id`, `metric_name`, `value` / `baseline` / `deviation`, `attrs`.
- `observer` carries `observer_id`, `observer_type`, `collection_path` and
  `clock_quality` (S:578-605).
- Parser provenance `{rule_id, parser_rev, rules_hash, fidelity}` rides in **attrs**,
  never in identity. `fidelity` is an attrs key, not a field (S:388-391).
- `signal_id = uuid5(SIGNAL_NS, source|native_id|ts)` (S:35, S:831). SIGNAL_NS is fixed
  forever.

Construction gates send the record to a `DeadLetter` (S:572) when:
- observer / kind / entity is missing;
- `ts` is naive;
- an entity token carries a tenant/org/global/all/ssid/wlan prefix (S:776-791).

Size caps (S:37, S:52-55): strings 256/128/512, tokens ≤32, attrs ≤4 KiB.

| topic | handler | source / modality | observer · collection_path |
|---|---|---|---|
| netops.metrics | handle_metric M:12389 | metric / device_telemetry; CUSUM episodes `if_/bgp_/igp_state_/device_resource_/cloud_resource_anomaly` | device id · `snmp_poll` |
| netops.syslog | handle_syslog M:13190 | syslog / control_plane or device_telemetry per rule (parser_rules.py) | event hostname · direct |
| netops.snmptrap | handle_snmptrap M:12728 | trap / control_plane (CPU/memory threshold rows: device_telemetry, the modality of the episode they land beside) | device · direct |
| netops.probes (+DEM) | handle_probe M:12661 | probe / active_probe; authority classified M:12597 | vantage |
| netops.flows | handle_flow M:13346 | flow / passive_flow; CUSUM → `flow_volume_anomaly` | sampler · `flow_export` |
| netops.controller_events | M:12796 → controller_events.py:120 | controller / **management_plane** | `<source_system>:<integration_id>` · `via_controller` (no instance suffix) |
| cloud · app.edge · verification · app identities · wireless | M:12995 · 13088 · 12817 · 13048 · 12841/12920 | cloud (via_cloud_api) · app-edge · active_verification · APP_IDENTITY (enrichment only, never a node, E:471-474) | — |
| netops.security · netops.bgp | handle_evidence_event M:13120 | evidence classes (S:1092-1150) | platform evaluator |

**SNMP allowlist.** `rcaMetricFamilies` names 17 metrics; everything else stays in
VictoriaMetrics only (`collectors/metric_events.go:75-108`).

**Vendor packs (tracker 387, 2026-11-09).** `telemetry-catalog/vendor-packs/*.yaml` is
one file per vendor: body and envelope grammars, a severity map, rule rows and fixtures.
`syslog_packs.py` is the engine's executor and names no vendor; the same rows compile into
the aggregator's Stage B (`scripts/gen-syslog-packs.py`), so the two cannot disagree.
`syslog_severity_num` also reads the severity a pack grammar finds in the message.
`syslog_alarm_num` is what the screen and the generic net act on: when a pack grammar
matched and the severity is past its `alarm_floor`, it returns None, so reading a severity
never opens an object by itself (owner D3). A line withheld that way with err or worse in
its own text, that no typed or `known_benign` row took, is counted
(`corr_syslog_high_severity_no_signal_total{path}`, PR 14), since a rise is a fault nobody
has a rule for; the count decides nothing. The hash covers the packs: `rules_hash(RULES,
PACK_DIGEST)`. The VRL's `cx_inventory_vendor` comes from the registry row (PR 12, vendor
from discovery through the vendor profiles); an inventory vendor narrows the grammars in
both executors, and `vendor_source` records `inventory` or `format`. Pack rows sit behind the vendor-neutral
rules and ahead of the generic net. A `known_benign` row counts the line
(`corr_parser_known_benign_total`), emits nothing and ends the walk; unlike a shadow row it
is a decision, not a candidate. Stage [1] only: no template, gate or constant moved, so
ENGINE_SEMVER does not move.

**Syslog framing (tracker 387 PR 10, 2026-11-09).** Until then syslog-ng reset PRI to 13 for
every vendor and read RFC 5424 with its legacy parser, so `ev.severity` was always `notice`
and the generic net was silent by accident. It is now the device's real severity, and the
message is clean, with the `%FAC-N-MNEMONIC` at its start (`syslog-ng/core.conf` p_frame).
Three things changed at stage [1] because of it, nothing else:
- `syslog_severity_num` also reads the mnemonic digit at the START of the message
  (`_BODY_SEV_RE`), where the tag used to carry it. Text later in a line is the sender's and
  states nothing.
- `syslog.generic.device_alarm` opens alone only on emerg/alert/crit: err arrives as `warn`,
  below `severity_open_floor`, and joins a component if one grounds to it (owner D3). The
  trap net keeps err → high: traps were never suppressed, so nothing changed there.
- `syslog.link.state_change`: a `%LINEPROTO-*-UPDOWN` down line from a sender with no process
  tag (`appname` `unknown`, IOS-format) is `warn`, because IOS logs the same line after a
  fault and after a `shutdown`; the first line of the pair says which. `%LINK-3-UPDOWN` opens,
  and `%LINK-5-CHANGED` emits nothing. EOS logs a tag and only the protocol line, so it stays
  `high`. No typed row reads PRI.
`.facility` no longer carries the PRI facility (that is `syslog_facility`): `local` is a screen
literal, and a fleet on local7 would have passed every line through the prefilter.
`ev.timestamp` is the device's own time when it can be believed. An RFC 3164 time has no zone
or year: within `SYSLOG_CLOCK_SKEW_TOLERANCE_S` it stands, which keeps sub-second order; past it
the aggregator replaces it with the edge's receive time (`ts_source=edge_receive`, the claim in
`device_timestamp`, `clock_skew_s` stamped), so a device logging local time still correlates. A
frame with `Z` or an offset keeps its timestamp whatever it says, because it can truly be old:
re-stamping would fabricate freshness, as `buffer_signal` already reasons, which clamps the
future and counts the past. So a wrong clock with a stated zone does not correlate, and
`clock_skew_signal` reports it.

**Admission gates.**
- Metric lane: an event older than −120 s / +3600 s is dropped (M:925-926, M:12426).
- Other lanes (`buffer_signal`): a ts more than 120 s in the future is clamped; a ts
  more than 1 h old is counted, not dropped (M:1947-1961).
- `debug_only` and `internal_self_probe` probes are persisted but never enter the
  window (M:1910-1920).
- Tenant check: `verified_tenant` (M:660) refuses a claim that contradicts the registry;
  "" becomes "global". On the registry-anchored lanes (syslog, snmptrap, flows) an
  identity the registry does not know is refused (`identity_unattributable`).
  The registry (`device_tenant.csv`, `telemetry_enrichment.go`) has one row per
  inventory device **id**, **name** and **address**. `identity` and `tenant_id` are the
  first two columns and are read by position; the inventory facts after them
  (`device_id, vendor, model, site, role`, PR 12) are never read here. The id row matters: traps and
  metrics carry the id, e.g. the SNMP scan id `vedge-20-1e95f00f`. Before
  2026-10-25 the id row was missing and those traps were quarantined. An identity
  claimed by two tenants is left out by the writer and dropped by the reader
  (`_tenant_registry`).
  The controller lane calls `verified_tenant` too (since 2026-10-24, unanchored: a
  claim the registry contradicts is quarantined; `handle_controller_event`).

**Trap meaning is data (tracker 387, 2026-11-09).** The Go receiver stamps
`event_state` (raise|clear|point), `severity_native_text/_code` and typed values from
`collectors/mibs/packs/*.json`, so no vendor name is in its code. The `trap.sdwan.*`,
`trap.bfd.*` and `trap.resource.*` rows read those fields. Owner rule "ingestion is
not incident creation" and D3: a row emits `crit` only for a raise the vendor calls
critical; everything else is `warn`, below the open floor, and can still join a
component. `controller_*` and resource recoveries arrive as `<kind>_clear`;
interface and BGP keep the device lane's `state=up` convention (tracker 380). A BFD
trap binds `<tloc pair>` without the controller's `@instance`, so it meets vManage's
report through the device token (rank 7), not as one node.

**BGP transition semantics (tracker 387, 2026-11-10).** Owner rule: only an ESTABLISHED
session going down is a session failure. The receiver decodes the peer from the row index
(gen_index.py writes each column's INDEX clause into the OID index; IOS-XE's bare
cbgpPeer2 index is a pack `tables` row), groups one transition's ~6 reports
(`transition_id`, `transition_seq`, `occurrence_count`) and stamps
`bgp.transition_class` (session_lost | session_up | never_established | progressing |
unknown), filling a report's missing prior state from the same transition or the peer's
last state (`bgp.prev_state_basis`). Stage [1] (`trap_control_signal`): a
`bgp_adjacency_change` down whose transition is never_established or progressing (the
trap's own fsm_from/fsm_to first, then the receiver's class) emits NO signal and is counted
(`corr_trap_bgp_not_session_failure_total{class}`); "unknown" or no class leaves the rule's
reading as it was. The lab's idle <-> active neighbour used to open a `high` singleton per
transition. Dedup of the six reports stays `trap_collapse.TransitionCollapser` (main.py).
Both sides pin the classifier to `collectors/testdata/bgp_transition_classes.json`. No
template, gate or constant moved: ENGINE_SEMVER does not move.

**A device's interface rows outlive its polls.** `interface_ips` and `ifindex` in
`entity_resolver.json` are each device's LAST-KNOWN rows, so `device_for_ip` still
recovers a trap sent from an interface address by a device that has stopped answering.
The retention is on the collector side (`collectors/if_rows_retention.go`; the wire
format is unchanged): a completed walk replaces the rows, and they go when the device
leaves the inventory or changes tenant, or 7 days after its last completed walk. An
address two devices claimed at once stays claimed by both, so it stays ambiguous.
Gauge: `collector_if_rows_retained_devices`.
**The controller feeds the same rows (tracker 387 PR 13a).** vManage's per-device interface
list (ifindex, addresses, VPN, description) reaches `interface_ips` and `ifindex` through the
api's interface bridge (`if_bridge.go`, `internal/ifbridge`), keyed by the inventory device
the controller's key resolves to OWNER-STRICTLY (never by address). VPN ≥ 65528 and
loopback/link-local addresses are skipped at the source; SNMP and NMS rows for one device
merge (same port canonically → the SNMP spelling; disagreement → the newer reading); NMS rows
outlive their polls for the same 7 days. The wire format is unchanged, so stage [1] reads
them like SNMP rows. Gauge: `netops_nms_iface_bridge_rows{source,outcome}`.

**Trap attribution (tracker 387 PR 13c', 2026-11-10).** The Go receiver names the
device by management address, then an interface address exactly one device reports
(`nms.InventoryIndex.DeviceForAddress`; VPN ≥ 65528 loopbacks and shared addresses
name nobody), then sysName, then v1 agent-addr, each rung only with the device's
credential proven, and stamps `attribution_basis` (`mgmt_ip|interface_ip|sysname|
agent_addr|none`). Stage [1]: `handle_snmptrap`'s `device_for_ip(host)` recovery runs
ONLY for a record without that field (an older receiver); a stamped `none` is a refusal
and stays unattributed (`ingest.traps_recanon_declined`). The receiver also stamps
`interface`/`ifindex`/`interface_basis`; `_trap_interface` still reads the varbinds.

**Raw evidence is durable.** `corr_signals` is written BEFORE the aggregation plane and
the window filters (e.g. M:8157-8161).
- Aggregation plane: aggregation.py:30. OFF in the image (M:2138), ON in compose.

**Episodes** (episodes.py:37-56).
- Two-sided CUSUM: H=4σ, K=0.5σ, at least 20 baseline samples; clears after 3 samples
  with |z|<1σ.
- Severity from peak z: <5 warn, ≥5 high, ≥8 crit (producers.py:77-82).
- Syslog, trap and controller records are point signals.
- Cumulative counters (octets/errors/discards/fcs, BGP FSM transitions) become a
  per-second rate per (tenant, entity, metric, collection_path) BEFORE the detector
  (tracker 379, counter_rate.py; kill switch `CORR_COUNTER_RATES=0`).
- **Series admission (P6 PR-C2, flag `CORR_SERIES_ADMISSION`, default OFF,
  2026-11-07).** One metric series per device across SNMP + controller (owner,
  NMS_DEVICE_IDENTITY §8); the CUSUM key stays (tenant, entity_id, metric). ON, on the
  metric lane only: (1) one sample per (series, `CORR_SERIES_BUCKET_S`=60 s bucket)
  across DIFFERENT collection paths — first arrival owns the bucket, a later sample
  from another path for that or an earlier bucket is dropped and counted
  (`EpisodeDetector.cross_source_dropped` → ingest `series_cross_source_dropped`,
  `corr_series_cross_source_dropped_total`); a path's own samples always pass; state
  in `_SeriesState` (MAX_SERIES LRU); (2) an RCA-family sample whose declared `unit`
  contradicts `series_admission.SERIES_SEMANTICS` (pinned by parsing Go
  `rcaMetricFamilies`, vManage realtime units and the gNMI shaper) is refused before
  the counter-rate stage and counted (`series_unit_rejected`); (3) `EpisodeEvent.sources`
  → `attrs["series_sources"]`; several sources → observer path =
  `verdicts.conservative_collection_path` and the witness sits in EVERY source's
  authority bucket (§5). OFF byte-identical (test_series_admission_p6.py).
- **Stage [1] identity canonicalisation (P6 PR-D blocks 2026-11-08, PR-E wiring;
  flag `CORR_IDENTITY_CANON`, default OFF, REQUIRES E1 `CORR_ORIGIN_OBSERVER` AND
  `CORR_SERIES_ADMISSION` — requested without both it stays off, logs an error at
  start-up, gauge `corr_identity_canon_enabled 0`; ENGINE_SEMVER unchanged until the
  default-ON PR).** One box / session / port reaches the engine under a different
  spelling per lane (syslog hostname or management IP vs inventory id; `Gi1` vs
  `GigabitEthernet1`; the controller's peer rewritten to an inventory id), so the
  evidence never met. `canon.py` (pure): `canon_iface_key` (table-free port key, a
  superset of Go `canonIface`, drift-tested; digit-only names → an ifIndex marker),
  `canonical_peer`, `canonicalize_detailed(sig, resolver)` (D1 syslog BGP host →
  `<device>:<peer>`, also for the A4 `bgp_session_not_established` check derived from
  it; D2 host → device id; D4 `<device>:<port key>`; D5 controller peer → its
  address), `canonicalize_series` (the metric-lane key; digits are an ifIndex only
  when the source declares `index`). Rewrites `entity_id` + the raw device token only,
  never `native_id`/`signal_id`; stamps `attrs["canon"]={raw,basis}` on a rewrite
  only; abstains (keeps the raw spelling) on unknown/ambiguous/generic/conflicting
  identities; refuses a resolver not scoped to the signal's tenant.
  `entity_resolver.identity_resolver_for` is the TENANT-ONLY resolver (never ∪ global;
  collision-dropping (device, key) → ifName index); `main.cached_identity_resolver_for`
  memoizes it per (tenant, file mtime), caching only tenants the file holds.
  **Seams (ON):** event lanes (syslog, trap, controller, proactive) in `buffer_signal`
  AFTER `canon_tenant`, BEFORE the E1 origin stamp, and so AFTER every lane's
  `agg_admit` (the aggregation plane keeps raw keys: INVARIANTS §10a); the metric lane
  in `handle_metric` after `verified_tenant`, before the counter-rate state, the
  episode detector, A4 and the z-score. `corr_signals` keeps the RAW entity (written
  before the window); the window, the archive slice and therefore objects and replay
  carry the canonical one — replay never comes through `buffer_signal`, so it is
  flag-independent. Counted `corr_identity_canon_total{lane,axis,outcome}` (closed
  labels; axis `signal` = one per call) + /healthz `ingest.identity_canon_<outcome>`.
  OFF: canonicalize is never called, byte-identical (test_canon_identity_p6.py,
  test_identity_canon_isolation.py, test_identity_canon_wiring_p6e.py,
  test_source_parity_e7.py `KNOWN_DIVERGENCES` / `_ON`).

**Partitioning.** Producers key by tenant (murmur2); every topic has the same partition
count, so replica k owns partition k of every topic (scale-correlation.md:9-22).

## 2. Window → objects — [3] window (M), [5] components (E)

**Window.**
- Per-replica deque, maxlen 50k, deduplicated by signal_id (M:1363, M:1975).
- Storm mode evicts the lowest severity first (M:1982-2003).
- Per-tenant horizon = watermark − **516.5 s**: reach 396.5 s (E:157-240) + lateness
  120 s (M:2105-2117).
  **Evidence later than that relative to the tenant stream never correlates.**

**Epoch.** A per-tenant frozen context (M:4045, M:4104-4145).
- Cohorts of 5000 signals (1000 in storm mode).
- `run_window` runs per tenant (M:7570). Only pairs with a cohort endpoint are scored;
  earlier edges are carried forward (E:1441-1462, E:3598).
- A window must be single-tenant; a mixed one raises ValueError (E:1312).

**Nodes and components.**
- Nodes = signals grouped by `entity_type:entity_id:kind`; `*_clear` kinds and
  APP_IDENTITY are skipped (E:466-494).
- Components = connected by admitted edges (E:3169), plus a tenant-scoped fold across
  grounded seams (E:3305, E:3635).

**Singleton rule** (E:3651-3668).
- A component with no edge and peak severity < `severity_open_floor`="high" (E:104)
  opens NO object.
- Any component with ≥1 edge opens one.
- **Admin link change (tracker 385).** A no-edge `link_state_change` node whose every
  signal at or above the floor is `link_cause=admin` also opens none
  (`_admin_change_only`): an operator's shutdown is a change. Fail-closed: one
  opening-severity signal with fault/unknown/no cause opens. Severity is NOT lowered at
  the parser (storm eviction is severity-ordered). The evidence stays in the window and
  `corr_signals`, so a grounded fault later folds it in. Counted:
  `corr_admin_link_change_singletons_total`.

**Identity** `cid = uuid5(corrobj|tenant|earliest node key|onset_ms)` (E:3752).
- A cid that overlaps an open object adopts that object's id: entity Jaccard ≥0.4 +
  window overlap, or a seam bridge, same tenant (E:4321-4345).
- A new version is written only when `material_hash` moves (E:2803-2813) or on the
  900 s heartbeat (M:7800-7884).

**Lifecycle**, per epoch (M:7076-7343):
1. merge: stale overlapping objects merge (`merged_into`);
2. quiesce: unseen for 900 s → closed;
3. cap: 5000 open objects (least recently seen force-closed).

States are `open|closed|merged` only; there is no "stable" (init.sql:442).

**Storm mode.**
- Entered at buffer ≥90% or oldest pending ≥120 s; exits at ≤45% (M:1220-1269).
- In storm mode: smaller cohorts, severity-ordered persistence, node dedup that leaves
  the verdict unchanged (E:3413-3452), and a single per-tenant noise object for
  below-floor singletons (E:3823-3873).
- Declared in the snapshot and replayed (R:115-120).

## 3. Graph — [4] grounding gate (E:511), [5] graph builder (E:1338)

**Ranked relationship ladder** (E:676-760):
1. same structural identity / device containment
2. seam membership (structural ids)
3. path hop or L2/L3 adjacency (LLDP/CDP/BGP-LS)
4. app→endpoint binding
5. flow/NAT stitch
6. INFERRED route/policy
7. CANDIDATE shared token

- Ranks 1–5 can be authoritative; 6–7 never are (E:528-532).
- A token shared by more than 64 nodes never grounds (E:596).
- **An ungrounded pair is a gap hint, never an edge** (E:1513).

**Edge weight** = `min(exp(-gap/τ300)·w_topo·w_r, 1)`, admitted at ≥0.3; gap = 0 when
the activity intervals overlap (E:1525-1560).
- `w_topo`: containment .9, path .9, seam .8, adjacency .65, inferred/candidate .5.
- Stale topology caps `w_topo` at .4.
- A cross-modality pair gets ×1.25 (E:86-104).

**Direction** (E:835-870): three votes — onset order, layer prior (layers.py), and
topology up/down (DirectedTopology: traceroute > netflow > SPF, M:4122).
- 2 agreeing votes → `direction_conf` 0.8; any conflict → 0.
- **Direction is stored and replayed but NEVER changes confidence.**

**Topology inputs** are the files the Go API writes under `/data/enrichment/` (M:1313):
`seams`, `topology_links`, `path_graph`, `cloud_dependency`, `routing_direction`,
`probe_paths`, `entity_resolver` (`topology_links_enrichment.go`).
- Scoped to the tenant ∪ global (M:4118).
- Stale after 180 s: `w_topo` is capped and the staleness is declared (M:1219, M:6924).

**`graph_support` is a hook that is ALWAYS 1.0**: `score_template(t, ev)` passes it no
graph (SC:14-19, 266, 1018).

## 4. Scoring — [6] (SC): competing hypotheses, already built

**Catalog.** Built-in templates only; PG/tenant overrides are not wired (M:1357,
M:1420). 151 templates, 105 enabled. The version hash changes on any edit (C:382-397).

**Template** (C:257-303):
- `requires` clauses: kind `a|b`, optional `entity_type` / `min_deviation` /
  `optional`; at least one mandatory.
- Clause `attrs` (every pair equal; absent key fails) and `attrs_not` (no pair equal;
  absent key passes), over the closed `signals.CLAUSE_ATTR_KEYS`, read through
  `clause_attr` by the scorer AND the rank_memo projection (tracker 385). They only make
  a clause stricter, so the kind index, structure gate and confirmability stay kind-only
  supersets. A verification witness goes through the same predicate.
- Clause `anchor` (required clauses only): while no signal satisfies it, `rank` omits the
  template from that ranking altogether. Rows tie-break by id, so even a zero row would
  displace visible competitors and the nearest-template checklist.
- `discriminators{absent, else_prefer, attested}`. `attested` (a structure class) narrows
  one: it fires only when the evidence also attests that structure (SD-WAN controller
  fan-in, 2026-11-11).
- `required_modalities`.
- `requires_structure` (device_tier / redundancy_group / overlay_encap / transit_path /
  controller_fan_in).
- `allow_root_cause_confirmed`.
- `verdict{owner, layer, first_steps}`.
- Narration: `seams`, `operator_phrase`, `manager_phrase`, `blast_radius`,
  `false_positives`, `causal_chain`.
- Declared but read nowhere: `within_s`, `applies_when`, `direction_expect` [lead].

**`rank()`** (SC:973):
0. An unattested `anchor` removes the template from this ranking.
1. The kind index scores unreachable templates analytically (SC:451-484).
2. The **structure gate** refuses templates whose structure the evidence does not
   attest (SC:736-818).
3. Coverage = satisfied required / required, + 0.05 per optional clause, capped at
   +0.1.
4. A discriminator `absent` hit (or a healthy active-verification refute) multiplies by
   **×0.2** and force-lists the `else_prefer` competitor (SC:300-351).
5. **confidence_rank = coverage × penalty**: a heuristic rank, not a probability.
6. Sort by (−confidence, −#satisfied, id). Show **TOP_K=4** plus forced and
   contradicted competitors.
7. **Top < CONFIDENCE_FLOOR 0.3 → `undetermined`**, with `evidence_missing` from the 2
   nearest templates. No forced root cause, ever (SC:1050-1086).

After rank:
- ties are broken by seam affinity (E:3254-3302);
- memoized: `rank_memo` L1 across epochs, keyed (tenant, catalog_version, signal
  projections) (rank_memo.py:968); `ComponentMemo` L2 within an epoch (E:3455).

## 5. Verdicts — [7] (V + engine caps). Rank ⟂ verdict.

**The gate runs over the TOP template's matched signals only** (SC:353).

**Witness** = observer_id + modality + authority bucket + probe authority + fate
(V:79-195).
- `direct` / `via_aggregator` = transport, no bucket.
- `via_controller[:i]` / `via_cloud_api[:i]` = authority buckets.
- Any other path → `unknown:<path>` (V:176-186).

**Independent** = different observer AND different authority AND no shared fate (agent
host / egress / seam+target+schedule) (V:105-115).
- **E1 origin observer (flag `CORR_ORIGIN_OBSERVER`, default OFF, 2026-11-01):** two
  witnesses whose `attrs["origin_device"]` is the same device are never independent —
  one box's own state seen through two lanes (its trap + the controller relaying it;
  its syslog by hostname + its SNMP episode by id) is one observation. Downgrade-only.
  `buffer_signal` stamps the origin (metric/trap/syslog/flow observer, or the device a
  controller event reports about) canonicalised through the TENANT's resolver
  (`EntityResolver.canonical_device`: id, name or address → id; ambiguous → kept
  verbatim), so the archive and replay carry it. With `CORR_IDENTITY_CANON` on, the
  origin is resolved by the same TENANT-ONLY resolver that canonicalised the entity
  (P6 OD2): a global row spelled like the tenant's box would otherwise drop the
  name/address from the legacy tenant ∪ global resolver and give one node two
  origins. `Witness.origin` is "" with the flag
  off and the rank_memo projection appends it only under the flag, so OFF is
  byte-identical (test_origin_observer_e1.py). Plan:
  docs/design/NMS_DEVICE_IDENTITY_2026-11-01.md §7a/§7b.
- **P6 PR-C2 multi-source series (flag `CORR_SERIES_ADMISSION`, default OFF):** an
  episode fed by several collection paths (`attrs["series_sources"]`) gets
  `Witness.series_authorities` = every source's bucket (incl. `unknown:snmp_poll`);
  sharing ANY bucket blocks independence and joins the fate group. Naming one path
  alone would not be downgrade-only (via_controller would lift it out of the shared
  snmp_poll bucket). Projected into the rank_memo key only under the flag.
- **E5c config-change family (flag `CORR_CONFIG_CHANGE_FAMILY`, default OFF, REQUIRES
  E1, 2026-11-02):** a change reaches the engine as `device_config_change` (the box),
  `controller_policy_change` (a controller) or `config_change`. ON: stage [6]
  `builtin_catalog()` applies `catalog.apply_config_change_family` — change-induced
  requires `[any change kind (device), a fault from any source]` (a lone push is half
  coverage, no longer 1.0), and every optional `device_config_change` clause widens to
  the family; stage [7] `score_template` keeps a family hit from an OPTIONAL clause out
  of `assess` (context, never a confirming plane). Requested without E1 it stays off
  and logs an error; gauge `corr_config_change_family_enabled`. OFF catalog version is
  unchanged (test_config_change_family_e5.py).
  An admin link change (tracker 385) does not need this flag: the unflagged sibling
  `sig.ent.access.admin-link-change-induced` scores `link_cause=admin` as the change half
  (`[admin link change (anchor), a fault that is not itself admin]`), and contradicts
  `local-link-fault` and `lastmile-circuit-flap` (×0.2, tag
  `link_state_change[link_cause=admin]`). `apply_config_change_family` leaves it alone.
  The engine does not order change against fault: a shutdown done as remediation reads the
  same way, so the template discloses that under `false_positives`. It is capped at suspected (`allow_root_cause_confirmed=false`): a shutdown causes its own traffic drop, and the engine does not order change against fault.

**Trusted:**
- non-probe evidence: yes;
- probes: only at HIGH/MEDIUM authority — `CORR_TRUSTED_PROBE_OBSERVERS` is empty by
  default, so probes are LOW and **never confirm** (M:12563, M:12640);
- active_verification: only when the method is ssh or snmp;
- DEBUG_ONLY: excluded.

**CONFIRMED** ⇔ ≥2 modalities AND ≥2 observers AND a trusted, cross-modality,
independent pair AND every required modality met by a trusted witness (V:367-387).
- Otherwise SUSPECTED, with reasons.
- UNDETERMINED only when there is no admissible evidence, or the rank is below the floor.
- management_plane and security are each their own plane: either alone caps at
  suspected.

**Downgrade-only caps** (`_cap_verdict` never upgrades, E:3188-3204):
- physical `allow_root_cause_confirmed=false` (SC:359);
- A7 fidelity — a doc_claimed signal can't be in the confirming pair; flag
  `CORR_FIDELITY_WEIGHTING`, default OFF (S:441, SC:385);
- non-live `data_class` (E:3722);
- **no authoritative (rank 1–5) edge in the component** (E:3735);
- unknown path hops → `evidence_missing` (E:3745).

`confidence_label` (confirmed / likely / suspected) comes from the gate and the clause
outcomes, never from the number (SC:215-226).

**confirmability.py is a static CI audit, not a runtime check.** It computes the best
verdict each template can reach with today's producers (CF:314-375). The ratchet
`confirmability_baseline.json` never drops (test_confirmability.py:120).

## 6. Outputs — [8] persist (M:5792)

**Planes.** Decision plane (`corr_objects` + `corr_current`) first, then the Evidence
plane (`corr_edges`, `corr_evidence`, `corr_signals_archive` slice) through a bounded
priority queue (evidence_plane.py).
- `corr_current` = ReplacingMergeTree(created_at) (init.sql:497).
- `corr_signals` TTL 30 d (init.sql:351); the others are profile-driven (default 90 d,
  `corr_retention.go`).

**Row and blob.**
- Row: `to_object_row` (E:2859); `top_confidence` = top hypothesis rank.
- Hypotheses blob = {ranking, grounding_context, seams, gap hints, degradation,
  orientations, adjacency, path_graph, provenance} (E:2653-2762).
- Persisted copies are capped at 1 MiB; content_hash is unaffected (E:1771).
- Outside every hash: `layer_coverage`, `app_impact`, `attribution`. Path attribution
  never touches the verdict (E:2894, E:3539).

**Narration** per hypothesis (SC:196-253): phrases, blast radius, false positives,
seams, causal chain, owner, first_steps.
Owner ∈ netops | carrier | cloud_provider | app_team | colo_provider | isp |
sdwan_vendor (C:132).

**Consumers:**
- API: `corr_current FINAL` under `chTenantScope` (correlations.go).
- **RCA auto-promotion needs CONFIRMED** + confirmed impact + ≥2 min; manual promotion
  is audited (internal/rca/rca_promotion_model.go:45-99).
- Iris speaks `operator_phrase`.
- TAC classify weights template ids (internal/tac/classify.go).

## 7. Sacred invariants + how to change the engine safely

**Replay determinism.** Byte-identical snapshots for the same inputs.
- `engine_version = ENGINE_SEMVER + EngineConfig hash` (E:62, E:118-127). Replay reports
  a pin mismatch, never substitutes (R:4-24).
- **The constants in SC:55-59 (floor, TOP_K, penalty), V:74-75 and episodes.py:37-43
  are NOT in the hash: bump ENGINE_SEMVER when you change them.**
- Any blob or hash change re-versions every open object once.

**Rules that never relax:**
- no ungrounded edge;
- no forced root cause;
- tier from the gate, never the rank;
- never relax the structure gate for throughput;
- "still analyzing" over an unsupported cause;
- suppression never drops raw evidence (INVARIANTS.md:389-392).

**New flags** must be byte-identical when OFF (as A7, storm mode and the aggregation
plane are). Prove it with fixtures.

**§3a.** Every in-memory structure is keyed by tenant:
- single-tenant windows;
- tenant-guarded merge and continuation;
- tenant in the rank_memo key;
- tenant-scoped seams, adjacency and paths;
- ClickHouse `tenant_iso_corr_*` row policies.

**Gate.** `cd src/correlation && python -m pytest`, plus `ruff check .`,
`bandit -r main.py -ll`, `mypy main.py` (correlation-ci.yml).

**Must stay green:** test_engine, test_fixtures, test_golden_wire*, test_replay*,
test_engine_complexity, test_confirmability, test_coverage, test_p2_rank_memo,
test_p3_equivalence, test_fidelity_weighting_a7, test_no_module_global_leakage.

**New lane:** follow data-contract §6, KIND_MODALITY and the coverage gate. If scoring
reads a new attrs key, add it to the rank_memo projection (rank_memo.py:935-965).

**Ranking changes** measure specificity, FP rate, unsupported-cause rate and accuracy.
The rig gate is `scripts/scale-miniladder.py` t-storm-2.5k (INVARIANTS.md §10).

## 8. NMS-only (owner decision 2026-10-24: the NMS integration may be the ONLY source)

- **Every controller of every vendor is ONE authority bucket** (`via_controller`, no
  instance; controller_events.py:158, V:182). So controller-only evidence is suspected at
  most, and thirty different edges' own BFD observations relayed by vManage count as one
  witness.
  Decided direction: count each edge's own observation as its own witness, so structural
  fan-in with contrast (many sites converging on one element while their other sessions
  stay up) can confirm. Two integrations of one controller stay ONE witness.
  Plan: docs/design/NMS_FIRST_PLAN_2026-10-24.md (T2).
- **SD-WAN controller fan-in (2026-11-11, ENGINE_SEMVER 3.4.0).** Stage [6] structure
  class `controller_fan_in`: >=2 DISTINCT edges, counted per lane (`source`: one box is
  spelled three ways across syslog/trap/controller until `CORR_IDENTITY_CANON`), report
  losing their control connection to the SAME controller (`signals.controller_peer`:
  syslog/trap `peer`, else `correlation_hints.controller_peer_id`, else `peer_id`;
  `CONTROL_LOSS_KINDS`). It admits `sig.ent.wan-edge.sdwan-controller-unreachable`
  (anchored, capped at suspected: the fan-in says the sessions died, not that the
  controller rather than a shared path to it failed), whose note names the controller,
  and fires a structure-conditioned discriminator that rules out the edge-local
  `sdwan-control-connection-loss` (now matchable: its mandatory kind was the
  producer-less `sdwan_control_down`). Stage [1]: the syslog control-connection rows emit
  the controller as a token (trap rows already did); vManage events read
  `peer-system-ip` + `peer-type` (nms/vmanage_events.go). **Fleet-scale limit:** the
  edges meet ONLY on that rank-7 token, and a token on more than `CORR_TOKEN_HUB_CAP` = 64
  NODES never grounds — about 32 edges when each reports through two lanes (one node per
  spelling while `CORR_IDENTITY_CANON` is off). Past it there is no controller verdict at
  all: syslog/trap control-loss rows are `warn`, below the open floor, so control loss
  alone opens NOTHING (measured: 64 nodes → one controller object, 65 → zero); an edge
  whose own BFD loss grounds to it, or a vManage-relayed (`high`) row, opens its OWN
  edge-local object instead — N symptoms again. Tracker: export controller↔edge
  control-session rows into `topology_links` (rank 3). **Transport look-alike, fail
  closed:** an edge id that lost controllers of ≥2 distinct peer types (vSmart AND
  vManage/vBond — its own transport failed) is not counted toward any fan-in; when that is
  every edge, nothing is attested and the edge-local reading is not demoted. A catalog
  load refuses a discriminator whose `absent` clause overlaps the template's mandatory
  clause unless it is narrowed (`attested`, `attrs`/`attrs_not`, `min_deviation`). The
  rank-memo projection carries `(source, peer, peer_type)` for control-loss kinds only.
  No exporter-silence signal exists: a fully silent exporter never reaches the CUSUM.
- **Tunnel identity (T0, 2026-10-25).** A BFD transition carries `tunnel_id` =
  the sorted TLOC pair `<ipA>/<colA>|<ipB>/<colB>` (nms/sdwan_tunnel.go) plus `peer_id`;
  controller_events.py binds PATH kinds to `<tunnel_id>@<controller_instance>` when
  the `tunnel_scheme=tloc_pair` hint is present. Both ends of one session are now ONE
  node (rank-1 shared identity). The `@instance` scope keeps two overlays that reuse
  system-ips apart. Older records without the hint bind as before.
- **Recoveries are clears.** An SD-WAN transition back to a good state, and a cleared
  vManage alarm, arrive as `<kind>_clear` at info. They bind to the fault's entity and
  build_nodes skips them. Before T0 they were fault-kind evidence that kept a recovered
  tunnel's node alive.
- **Canonical kinds from controllers (E2a, 2026-11-01).** vManage alarms (keyed on the
  release's `rule_name_display`, all 99 rules of 20.6 mapped or explicitly unclassified —
  nms/vmanage_kinds.go) and device events now arrive as the kinds the templates use:
  `link_state_change` (bound `<device>:<ifname>`, INTERFACE), `bgp_adjacency_change` /
  `ospf_adjacency_change` (`<device>:<peer>`), `device_restart`, `transceiver_unsupported`,
  plus the existing BFD / control-connection kinds; `*_Up` rules and recovered states are
  `<kind>_clear`. Until then every BGP / OSPF / interface / reboot alarm was
  `controller_alarm`, a kind no template consumes. Still management_plane (a relayed
  observation names the hypothesis; it does not confirm alone). Real 20.6 alarms carry the
  device in `devices[].system-ip`; before E2a the connector read a top-level field and every
  alarm reached the engine with no device (testdata/vmanage_20.6, recorded on the lab).
- **Controller metrics on the metric lane (E3, 2026-11-02).** vManage's real-time
  per-device interface and system APIs (nms/vmanage_realtime.go; streams
  `interface_realtime`, `system_realtime`, defaults) emit the SNMP canonical families
  (`device_if_oper_status` … `device_cpu_percent`, `device_mem_percent`, IF-MIB values,
  cumulative counters, Mbps) labelled `device` + `ifName`. They go to VictoriaMetrics AND,
  via the bus bridge, to `netops.metrics` with the integration's `tenant_id` and
  `collection_path: via_controller` (nms_scheduler.go nmsEmitMetricEvents) — the
  aggregator's metrics HTTP lane resets tenant_id from the registry, where a
  controller-only device has no row. The metric lane is not registry-anchored, so the
  claim stands; via_controller puts the episode in the controller authority bucket.
  The aggregation streams (`interfaces`, `system`: 10-min buckets, 30–60 min late)
  remain context only.
- `controller_instance` (`ci-<hash>`, basis `host`) rides in attrs: context for T2's
  witness rule. The observer and the verdict are unchanged.
- **Controller topology (T4b/T4c, 2026-10-25).** The api draws the SD-WAN overlay from
  the integration's stored BFD sessions (internal/ctloverlay), and exports
  tunnel↔endpoint rows (`proto: sdwan_bfd`, `a` = `<tunnel_id>@<controller_instance>`,
  `b` = endpoint inventory id, tenant never `""`) into topology_links.json.
  `Node.adjacency_key()` (E) lets the rank-3 adjacency rung look a tunnel node up by its
  own id, so a tunnel incident grounds to its edge devices AUTHORITATIVELY instead of
  through a rank-7 token (no "no authoritative edge" cap). Device↔device overlay rows are
  deliberately not exported: on a full mesh they would weld the fabric (#99 class).
  ENGINE_SEMVER 3.2.0 (3.3.0 since tracker 385, 3.4.0 since the controller fan-in); byte-identical when no tunnel rows exist. The verdict tier still
  stays suspected for controller-only evidence until T2 changes the witness rule.
- Controller evidence later than 516.5 s behind the watermark never correlates. vManage
  statistics are 30–60 min late, so they are context only, never live corroboration.
- Observer ids are lane-local strings (SNMP device id, syslog hostname
  producers.py:1388). If they differ for one box, the gate over-counts it as two
  independent witnesses — proven by test_origin_observer_e1.py; closed by the E1
  origin-observer rule when `CORR_ORIGIN_OBSERVER` is on (§5).
- **NMS-only identity (P6 PR-E, `CORR_IDENTITY_CANON`, §1).** The controller's
  device id is the inventory id already (nms/identity.go), so stage [1] leaves
  controller device kinds alone (a `device or site` binding is never read as a
  hostname); it puts a session's peer back to the address nms/identity.go kept in
  `correlation_hints.controller_peer_id` (D5), so the controller's report and the
  router's own trap are ONE node (E7 `controller_peer_is_inventory_id` heals ON), and
  canonicalises controller port spellings (E2a `<device>:<ifname>`, E3 realtime
  `ifName` on the metric lane) onto the SNMP port key. A controller-only device the
  inventory does not know keeps its id verbatim. The witness rule is unchanged: still
  one `via_controller` bucket, and E1 keeps the device's own lanes one witness.
