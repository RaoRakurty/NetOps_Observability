# src/correlation — the correlation engine, as it actually works

**Why this file exists (owner, 2026-10-24):** the correlation engine is the product's
original purpose. Its design is default knowledge for anyone writing code or approving
designs ANYWHERE in this repo. Every feature (a connector, a UI change, an ops fix) is
judged by what it gives the engine: signals, entities, topology, contrast, timing and
ownership. A change to the engine is framed as a change to one named stage below. Never
propose as new something this file says already exists.

Verified against the code on 2026-10-24 (main 646c40e2). **If the code and this file
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
| netops.snmptrap | handle_snmptrap M:12728 | trap / control_plane | device · direct |
| netops.probes (+DEM) | handle_probe M:12661 | probe / active_probe; authority classified M:12597 | vantage |
| netops.flows | handle_flow M:13346 | flow / passive_flow; CUSUM → `flow_volume_anomaly` | sampler · `flow_export` |
| netops.controller_events | M:12796 → controller_events.py:120 | controller / **management_plane** | `<source_system>:<integration_id>` · `via_controller` (no instance suffix) |
| cloud · app.edge · verification · app identities · wireless | M:12995 · 13088 · 12817 · 13048 · 12841/12920 | cloud (via_cloud_api) · app-edge · active_verification · APP_IDENTITY (enrichment only, never a node, E:471-474) | — |
| netops.security · netops.bgp | handle_evidence_event M:13120 | evidence classes (S:1092-1150) | platform evaluator |

**SNMP allowlist.** `rcaMetricFamilies` names 17 metrics; everything else stays in
VictoriaMetrics only (`collectors/metric_events.go:75-108`).

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
  inventory device **id**, **name** and **address**. The id row matters: traps and
  metrics carry the id, e.g. the SNMP scan id `vedge-20-1e95f00f`. Before
  2026-10-25 the id row was missing and those traps were quarantined. An identity
  claimed by two tenants is left out by the writer and dropped by the reader
  (`_tenant_registry`).
  **[lead] The controller lane does NOT call `verified_tenant`; it trusts the tenant in
  the payload** (M:12796-12814).

**Raw evidence is durable.** `corr_signals` is written BEFORE the aggregation plane and
the window filters (e.g. M:8157-8161).
- Aggregation plane: aggregation.py:30. OFF in the image (M:2138), ON in compose.

**Episodes** (episodes.py:37-56).
- Two-sided CUSUM: H=4σ, K=0.5σ, at least 20 baseline samples; clears after 3 samples
  with |z|<1σ.
- Severity from peak z: <5 warn, ≥5 high, ≥8 crit (producers.py:77-82).
- Syslog, trap and controller records are point signals.

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
M:1420). 149 templates, 103 enabled. The version hash changes on any edit (C:382-397).

**Template** (C:257-303):
- `requires` clauses: kind `a|b`, optional `entity_type` / `min_deviation` /
  `optional`; at least one mandatory.
- `discriminators{absent, else_prefer}`.
- `required_modalities`.
- `requires_structure` (device_tier / redundancy_group / overlay_encap / transit_path).
- `allow_root_cause_confirmed`.
- `verdict{owner, layer, first_steps}`.
- Narration: `seams`, `operator_phrase`, `manager_phrase`, `blast_radius`,
  `false_positives`, `causal_chain`.
- Declared but read nowhere: `within_s`, `applies_when`, `direction_expect` [lead].

**`rank()`** (SC:973):
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
- No controller topology: adjacency comes only from LLDP/CDP/BGP-LS. Controller PATH
  events ground only through rank-7 tokens, which triggers the "no authoritative edge"
  cap [lead] (plan T0/T4).
- Controller evidence later than 516.5 s behind the watermark never correlates. vManage
  statistics are 30–60 min late, so they are context only, never live corroboration.
- Observer ids are lane-local strings (SNMP device id M:12451, syslog hostname
  producers.py:1388). If they differ for one box, the gate over-counts it as two
  independent witnesses [lead].
