# Correlation Engine v2 — Persistent Causal Correlation Objects

Status: **DESIGN — awaiting sign-off** · Owner: correlation service (`src/correlation/`)
Related: `docs/design/front-page.md` (consumer), failure-signature catalog (rule base,
user-authored), tracker #53 (unified event feed — shares the normalized-signal spine),
memory `netops-frontpage-rca-direction`.

---

## 0. Objective and differentiator

Today the correlation service is a **real-time anomaly annotator**: z-score per
(device, metric), each crossing emitted as an isolated finding row in ClickHouse.
Findings have no relationship to each other, no lifetime, no causal claim, and no
replay. That is exactly what every incumbent ships, and it is the ceiling we
committed to break.

v2 produces **Correlation Objects**: persistent, versioned, queryable causal graphs
of incidents. Each object explains *what changed, when it started, what co-occurred,
what likely caused what (ranked, with confidence), and which infrastructure paths
were involved* — and can be deterministically reconstructed from stored inputs.

Hard constraints (what we are NOT building):

- ❌ dashboard-side correlation (query-time joins pretending to be insight)
- ❌ ad-hoc ML inference at query time
- ❌ single-event root-cause guesses that collapse alternatives
- ✔ time-windowed causal graph builder, incremental over the object's lifetime
- ✔ persistent, versioned correlation store (append-only history)
- ✔ replayable incident reconstruction (same inputs + same engine version ⇒ same object)
- ✔ multiple competing hypotheses maintained and re-scored, never silently collapsed

Honesty rule (house style): confidence values are **calibrated heuristic ranks, not
probabilities**. The API labels them `confidence_rank`; UI copy says "correlation
strength" / "evidence coverage", never "probability the cause is X".

---

## 1. Position in the stack

```
                       ┌─────────────────────────────── Go API ───────────────────────────────┐
                       │  alerts engine · topology/discovery · SoT/compliance · authz (RLS)   │
                       └───────────────┬───────────────────────────────▲──────────────────────┘
                                       │ POST events                   │ GET /api/correlations*
                                       ▼ (Vector http_server,          │ (tenant-scoped proxy,
                              snmptrap pattern)                        │  same backend_client TLS)
 syslog-ng ─┐                          │                               │
 goflow2 ───┤→ Vector agg → Redpanda ──┼── netops.flows ──┐    ┌───────┴───────┐
 telegraf ──┘                          └── netops.events ─┤    │  Correlation  │
 prober (STAMP/ICMP/HTTP) → netops.metrics ───────────────┼──▶ │  Engine v2    │
 gNMI ────────────────────→ netops.metrics ───────────────┘    │  (Python,     │
                                                               │  src/correlation)
                                                               └───┬───────┬───┘
                                                 ClickHouse ◀──────┘       └──────▶ Postgres
                                                 (signals, objects,               (active registry,
                                                  edges, evidence —                RLS, ops lifecycle,
                                                  append-only, replay)             hypothesis templates)
```

Component responsibilities:

| Component | Responsibility |
|---|---|
| **Vector / Redpanda** (exists) | Transport. No correlation logic. New topic `netops.events` for alert-state transitions + topology/discovery/SoT-drift events pushed by the Go API via the existing Vector `http_server` pattern (same as snmptrap :8688). |
| **Normalizer** (new, in engine) | Every consumed record → one `Signal` in the canonical schema (§2.1). Stamps tenant via the existing `device_tenant.csv` enrichment. Assigns event-time, source watermark. |
| **Episode detector** (evolves existing z-score) | Turns continuous metric streams into bounded **anomaly episodes** (onset/clear with CUSUM-style hysteresis, §4.1). Discrete signals (alerts, topology changes) pass through as point episodes. |
| **Window manager** (new) | Sliding co-occurrence windows 30 s / 5 m / 1 h per tenant; watermark + allowed-lateness; storm-mode degradation (§8). |
| **Graph builder** (new) | Maintains the live correlation graph per open object: nodes = episodes, edges = weighted co-occurrence with direction (§4.2–4.4). |
| **Hypothesis scorer** (new) | Evaluates declarative hypothesis templates (failure-signature catalog) over each object's graph; maintains ranked top-K (§4.5). |
| **Persistence** (new) | Versioned snapshots to ClickHouse (append-only), active-state registry to Postgres (RLS). Idempotent writes keyed (correlation_id, version). |
| **Go API** | Public query surface `/api/correlations*` (authz, tenant scoping — engine itself trusts nothing, Go re-checks); pushes alert/topology events onto the bus; WebSocket hub emits object updates to the UI. |

Topology input: the engine pulls the topology graph + path/segment inventory from the
Go API on an interval (same `backend_client` mTLS seam in reverse — engine→API GET,
already how it reads enrichment). Each pull is versioned (`topology_version` = hash);
graphs embed the version they scored against (§8 staleness).

---

## 2. Canonical objects and storage design

### 2.1 Normalized signal (the spine — shared with #53's event feed)

One schema for everything the engine sees. ClickHouse table `corr_signals`:

```sql
CREATE TABLE corr_signals (
    tenant_id      LowCardinality(String),          -- '' = platform/global
    signal_id      UUID,                            -- deterministic: UUIDv5(source, native_id, ts)
    ts             DateTime64(3),                   -- event time (source clock)
    ingest_ts      DateTime64(3),                   -- engine receipt (skew/lateness analysis)
    source         Enum8('flow'=1,'probe'=2,'metric'=3,'alert'=4,
                         'topology'=5,'syslog'=6,'sot_drift'=7),
    kind           LowCardinality(String),          -- e.g. probe_loss, if_errors, bgp_peer_down
    entity_type    Enum8('device'=1,'interface'=2,'path'=3,'segment'=4,
                         'site'=5,'service'=6,'prefix'=7),
    entity_id      String,                          -- canonical id within type
    entity_tokens  Array(String),                   -- dedup identity aliases (same chain as discovery)
    site           LowCardinality(String),
    path_id        LowCardinality(Nullable(String)),
    service_id     Nullable(String),                -- NULLABLE from day one (Phase-2 catalog fills it)
    severity       Enum8('info'=0,'warn'=1,'high'=2,'crit'=3),
    metric_name    LowCardinality(String),
    value          Float64,
    baseline       Float64,                         -- rolling mean at scoring time
    deviation      Float64,                         -- z-score (signed)
    attrs          String                           -- JSON, bounded 4 KiB, schema-checked per kind
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (tenant_id, ts, source, entity_type, entity_id)
TTL toDateTime(ts) + INTERVAL 30 DAY;
```

Notes:
- `signal_id` is **deterministic** (UUIDv5 over source+native id+event time) so reprocessing
  the same input produces the same ids — the foundation of replay and idempotency.
- Raw stores stay as they are (flows in `netops.flows` CH tables, metrics in VM, logs in OS).
  `corr_signals` holds only what crossed the engine's attention threshold (anomalous
  episodes + discrete events), not the firehose — bounded by design.
- This table IS the #53 unified event feed's backing store; the Events Explorer reads
  it directly. One spine, two consumers.

### 2.2 Correlation object (versioned snapshots)

ClickHouse `corr_objects` — append-only; every material change writes version N+1:

```sql
CREATE TABLE corr_objects (
    tenant_id        LowCardinality(String),
    correlation_id   UUID,
    version          UInt32,                        -- monotonic per object
    state            Enum8('open'=1,'closed'=2,'merged'=3),
    window_start     DateTime64(3),
    window_end       DateTime64(3),                 -- advances while open
    trigger_signal   UUID,                          -- first episode that opened the object
    top_hypothesis   String,                        -- template id, e.g. 'sig.wan_congestion'
    top_confidence   Float32,                       -- 0..1 heuristic rank (NOT probability)
    hypotheses       String,                        -- JSON: ranked top-K [{id, confidence, coverage, contradicted}]
    affected         String,                        -- JSON: {devices[], interfaces[], sites[], paths[], services[]}
    signal_count     UInt32,
    node_count       UInt16,
    engine_version   LowCardinality(String),        -- semver + config hash → replay contract
    topology_version LowCardinality(String),
    merged_into      Nullable(UUID),
    created_at       DateTime64(3)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(window_start)
ORDER BY (tenant_id, correlation_id, version);
-- "latest" = argMax(version) view:
CREATE VIEW corr_objects_latest AS
SELECT * FROM corr_objects
ORDER BY tenant_id, correlation_id, version DESC
LIMIT 1 BY tenant_id, correlation_id;
```

### 2.3 Graph edges + evidence

```sql
CREATE TABLE corr_edges (
    tenant_id       LowCardinality(String),
    correlation_id  UUID,
    version         UInt32,                         -- edges written per snapshot version
    from_node       String,                         -- episode key: entity_type:entity_id:kind
    to_node         String,
    weight          Float32,                        -- combined w (§4.2)
    w_temporal      Float32,
    w_topo          Float32,
    w_reinforce     Float32,
    direction_conf  Float32,                        -- 0 = undirected co-occurrence
    direction_basis String                          -- 'onset_order'|'topo_updown'|'layer_prior'|'mixed'
) ENGINE = MergeTree
PARTITION BY toYYYYMM(now())
ORDER BY (tenant_id, correlation_id, version, from_node, to_node);

CREATE TABLE corr_evidence (
    tenant_id       LowCardinality(String),
    correlation_id  UUID,
    version         UInt32,
    subject_kind    Enum8('edge'=1,'hypothesis'=2),
    subject_id      String,                         -- edge key or template id
    signal_id       UUID,
    role            Enum8('supports'=1,'contradicts'=2,'discriminates'=3),
    note            String                          -- human-readable "why": rendered in UI evidence log
) ENGINE = MergeTree
ORDER BY (tenant_id, correlation_id, version, subject_kind, subject_id);
```

Every edge and every hypothesis score is **explainable by construction**: the evidence
rows are written in the same transaction batch as the snapshot, with a human-readable
`note` ("probe_loss onset 09:43:02 on segment dallas-edge→equinix-pop precedes
teams_latency onset 09:44:40 by 98 s; topology: segment is upstream of site dallas").

### 2.4 Postgres — active registry + templates (RLS, transactional)

```sql
-- migrations/000X_correlation_engine.sql  (RLS like every other tenant table)
CREATE TABLE corr_active (
    correlation_id  UUID PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('open','closed','merged')),
    opened_at       TIMESTAMPTZ NOT NULL,
    last_update     TIMESTAMPTZ NOT NULL,
    current_version INT NOT NULL,
    quiesce_after   TIMESTAMPTZ NOT NULL,           -- close timer
    ack_by          TEXT,                            -- ops lifecycle (ack/assign), UI-driven
    incident_id     TEXT                             -- link once promoted to an incident
);
CREATE TABLE corr_hypothesis_templates (             -- the failure-signature catalog, AS DATA
    id              TEXT PRIMARY KEY,                -- 'sig.wan_congestion'
    tenant_id       TEXT NOT NULL DEFAULT '',        -- '' = built-in/platform; tenants may add their own
    version         INT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    spec            JSONB NOT NULL                   -- declarative predicate, §4.5
);
```

Postgres is the **small, transactional, mutable** side (claiming, ack, close timers —
`FOR UPDATE SKIP LOCKED`, the same pattern as the report queue). ClickHouse is the
**large, append-only, replayable** side. Neither duplicates the other's job.

---

## 3. Streaming pipeline

```
Redpanda (netops.flows | netops.metrics | netops.events | netops.syslog)
   │  aiokafka consumer group "correlation-v2" (manual commit, §8 crash recovery)
   ▼
[1] Normalize  → Signal (deterministic signal_id, tenant stamp, event-time)
   ▼
[2] Episode detection  → metric streams: CUSUM onset/clear; discrete events: point episodes
   ▼          (only episodes proceed; sub-threshold samples just update baselines)
[3] Window manager  → per-tenant sliding windows 30s/5m/1h, watermark = min(source watermarks) − lateness
   ▼
[4] Object router  → episode joins an OPEN object if it scores ≥ ATTACH_FLOOR against
   │                 the object's graph (temporal×topo, §4.2); else if severity ≥ open
   │                 threshold, opens a NEW object; else parked in candidate pool
   ▼                 (candidate pool re-evaluated each window slide; merge check §8)
[5] Graph update  → add node, recompute affected edges only (incremental, not full rebuild)
   ▼
[6] Hypothesis re-score  → evaluate templates whose trigger-kinds intersect the new node
   ▼
[7] Persist  → if material change (Δtop-hypothesis, Δstate, new node, ≥N new edges):
   │           snapshot version++ → CH batch (object + edges + evidence) + PG registry update
   ▼
[8] Emit  → Go API webhook → WebSocket hub topic "correlations" → UI live update;
            optional alert-engine feedback (an object reaching confidence ≥ T can raise
            a meta-alert "correlated incident", which dedups its member alerts)
```

Windows are **event-time** with per-source watermarks; late signals within the
lateness budget (default 120 s) are inserted retroactively and trigger re-score of
any object whose window covers them. Later than that → appended to the evidence log
flagged `late`, never silently dropped.

---

## 4. Correlation logic

### 4.1 Episode detection (replaces "every z-crossing is a finding")

The current per-(device,metric) rolling window stays, but crossings now open an
**episode** with hysteresis instead of emitting isolated findings:

- onset: CUSUM accumulator over signed deviation crosses `h` (default 4σ cumulative)
  → `onset_ts` recorded **with uncertainty ±half the metric's sampling interval**.
  Onset is what matters for causal ordering — NOT the alert's firing time (alert
  evaluation delay would systematically lie about order).
- clear: deviation back inside 1σ for `clear_hold` (default 3 intervals).
- episode carries: peak deviation, integral (area = magnitude×duration), onset
  uncertainty. Discrete signals (BGP peer down, alert fired, SoT drift, config
  change) are point episodes with onset = event ts, uncertainty = source skew bound.

### 4.2 Edge weight — temporal × topological × reinforcement

For episodes A, B (onset times tA ≤ tB):

```
w_temporal(A,B) = exp(−(tB − tA) / τ)          τ = 60 s (30s window) / 300 s (5m) / 1800 s (1h)
w_topo(A,B)     = max over relation:
                    same interface            1.00
                    same device               0.85
                    L2/L3 adjacent device     0.65
                    same path (segment overlap = Jaccard of segment sets, scaled 0.3–0.8)
                    same site                 0.40
                    same ASN / provider       0.30
                    no known relation         0.05   (never exactly 0 — unknown ≠ unrelated,
                                                      but ATTACH_FLOOR usually excludes these)
w_reinforce     = 1 + 0.25 × (distinct source types on {A,B} − 1)
                  (flow + probe + alert agreeing is worth more than three alerts)

weight = clamp01( w_temporal × w_topo × w_reinforce )
edge kept iff weight ≥ EDGE_FLOOR (0.15); episode attaches to an object iff its best
edge against the object ≥ ATTACH_FLOOR (0.30).
```

All constants live in engine config, are part of the **config hash** in
`engine_version`, and get re-fit later from labeled history (Phase-4 calibration) —
deterministic first, learned second.

**Seam-relative correlation (owner spec, 2026-06-11):** `path`/`segment` entities
are instances of the five **canonical ownership-transition seams**
(`cloud-ingestion.md` §4: DX, VPN, SDWAN, DIA, CLOUD_BACKBONE). Correlation is
computed *relative to seams*: episodes on opposite sides of a seam crossing get the
seam itself as the candidate boundary node, and a seam's `control_plane_owner`
(enterprise/isp/cloud/sdwan_controller) feeds the hypothesis verdict's `owner` field
directly — causality localizing *at* a seam is what makes "open carrier ticket" vs
"our edge" assignable. A seam's `visibility` (full/partial/blind) caps the
direction confidence claimable across it (blind seams never get onset-order votes
from inferred interior state, only from bracketing probes).

### 4.3 Causal direction inference

Directed edge A→B claimed only when at least two of three agree (else edge stays
undirected co-occurrence, `direction_conf = 0`):

1. **Onset order** — `tA + uA < tB − uB` (uncertainty intervals must NOT overlap).
   Strength scales with gap/uncertainty ratio.
2. **Topology up/downstream** — A on an entity upstream of B's entity along the
   traffic direction of an involved path (WAN edge upstream of branch users; the
   underlay segment upstream of the overlay tunnel riding it).
3. **Layer prior** — OSI causality: L1 errors → L2 → L3 reroute → L4 retrans/session
   → tunnel/overlay → DNS/TLS → L7 latency. Each `kind` maps to a layer; lower-layer
   onset directs toward higher-layer. (This prior is exactly what the failure-signature
   catalog encodes from practitioner knowledge.)

`direction_conf = weighted agreement`, `direction_basis` records which signals agreed —
auditable, shown in the evidence log.

### 4.4 Graph maintenance

- Node cap per object: 200 (top-weighted kept, evictions logged to evidence as
  `note='evicted: weight below floor at cap'` — no silent truncation).
- Incremental: a new node only scores edges against existing nodes sharing an entity
  relation (topology index lookup) or within the temporal window — O(candidates), not O(n²).
- Two open objects sharing ≥ J% affected-entity overlap (default 40%) AND overlapping
  windows → **merge**: older `correlation_id` wins, younger gets terminal snapshot
  `state='merged', merged_into=elder`. Deterministic rule; merge event in both evidence logs.

### 4.5 Hypothesis templates — the failure-signature catalog as the rule base

Templates are **declarative data** (PG `corr_hypothesis_templates.spec`), not code:

```jsonc
{
  "id": "sig.wan_congestion",
  "title": "WAN edge congestion",
  "layer": "L3/L4",
  "requires": [                       // evidence coverage: fraction satisfied drives score
    {"kind": "if_util_high",   "entity_type": "interface", "role": "wan_edge"},
    {"kind": "probe_loss",     "entity_type": "segment",   "min_deviation": 3.0},
    {"kind": "qos_drops|if_discards", "entity_type": "interface", "optional": true}
  ],
  "discriminators": [                 // the look-alike killers — practitioner gold
    {"not": {"kind": "bgp_path_change", "within": "10m"},
     "else_prefer": "sig.routing_instability"},
    {"not": {"kind": "if_errors", "min_deviation": 3.0},
     "else_prefer": "sig.physical_degradation"}
  ],
  "direction_expect": "interface → path → service",
  "verdict": {
    "owner": "netops",                // netops | carrier | cloud_provider | app_team
    "first_steps": ["Check QoS queue drops per class on the WAN edge",
                    "Compare utilization vs CIR on the affected circuit",
                    "Verify no recent traffic-shift (routing change, new top-talker)"]
  }
}
```

Scoring per open object:

```
coverage      = satisfied required clauses / total required        (optional clauses add ≤ 0.1 bonus)
graph_support = mean weight of edges connecting the satisfying episodes
contradiction = any discriminator's "not" clause violated → score ×0.2 AND the
                else_prefer template is force-evaluated (competing hypotheses by construction)
confidence_rank = coverage × graph_support × direction_agreement
```

Top-K (default 4) kept **always** — ranked list, never a single answer. Rank flips
require min-dwell 2 evaluation cycles (no flapping headline). Every satisfied/violated
clause writes a `corr_evidence` row with role `supports`/`contradicts`/`discriminates`.

Built-in starter set ships with the engine (wan_congestion, routing_instability,
physical_degradation, dns_impairment, cloud_region_degradation, tunnel_mtu_blackhole);
the user-authored catalog replaces/extends these — same schema, hot-reloaded from PG,
versioned. **The engine's quality scales with the catalog, by design.**

---

## 5. API design

Engine-internal (FastAPI, mTLS via the existing tlsconfig seam, never exposed raw):

```
POST /internal/signal-ingest        # non-bus producers (Go API alert/topology pushes
                                    # if Vector hop is down); schema-validated; idempotent
GET  /internal/healthz              # consumer lag, watermark age, open-object count
```

Public, on the Go API (authz + tenant scoping enforced there — zero-trust toward the
engine; Go re-derives tenant from the principal, never from the engine response):

```
GET /api/correlations?from=&to=&state=&entity=&service=&min_confidence=
        → corr_objects_latest page (tenant-filtered in the CH predicate, RLS pattern)
GET /api/correlations/active
        → PG corr_active join latest snapshot (the NOC "needs attention" feed)
GET /api/correlations/{id}                      [?version=N]
        → one snapshot (default latest): object + hypotheses + affected + evidence summary
GET /api/correlations/{id}/graph                [?version=N]
        → nodes + corr_edges + per-edge evidence notes (the UI causal-graph view)
GET /api/correlations/{id}/timeline
        → version history: how hypotheses/graph evolved over the object's life
POST /api/correlations/{id}/ack | /close        # ops lifecycle → PG registry (audited)
GET /api/correlations/{id}/replay   (admin)
        → re-runs the engine pure-function over corr_signals[window] at the snapshot's
          engine_version; returns diff vs stored object (drift = bug or config change)
```

WebSocket: existing event hub gains topic `correlations` (object opened / version++ /
closed / merged) — powers the front page's live "Top Active Issues".

---

## 6. Example lifecycle (the Dallas mockup scenario, step by step)

1. `09:42:10` Telegraf/gNMI util sample → z-deviation on `dallas-edge:Gi0/1 if_util`
   accumulates; CUSUM crosses → **episode E1** (onset 09:42:04 ± 15 s). Severity high
   → **object C-7f3a opens**, version 1: one node, zero edges, hypotheses: none ≥ floor.
2. `09:43:20` STAMP probe segment `dallas-edge→equinix-pop` loss 4.2% → **E2**
   (onset 09:43:02 ± 5 s). Router: best edge vs C-7f3a = w_t(58 s, τ=300)≈0.82 ×
   w_topo(interface on segment's path = 0.8) × reinforce(metric+probe = 1.25) = **0.82**
   ≥ ATTACH → joins. Direction: onset order ✓ (gap 58 s ≫ uncertainties) + topo
   upstream ✓ + layer prior (L2/util → path) ✓ → **E1→E2, direction_conf 0.9**.
   Version 2 persisted: `sig.wan_congestion` coverage 2/2 required (util + probe loss),
   no contradictions yet → confidence_rank 0.66, rank 1.
3. `09:44:40` Teams latency SLO alert (netops.events) → **E3** on service `teams`
   (attached via path overlap; service_id present because attribution Phase 2 — in
   Phase 1 the same signal arrives entity_type=path). Edges E2→E3 (onset+topo+layer).
   `09:45:55` VPN degradation alert → **E4**, same pattern. Version 3–4.
4. `09:46:00` scheduled topology pull: **no BGP path change** in window → discriminator
   `not bgp_path_change` **passes**; `sig.routing_instability` force-evaluated anyway,
   scores 0.18 (coverage 1/3) — kept as rank-2 competing hypothesis, shown as such.
5. Object stabilizes: rank-1 `sig.wan_congestion` 0.74, affected = {dallas-edge,
   Gi0/1, segment dallas→equinix, services teams+vpn}, verdict owner=netops,
   first_steps rendered on the front page's Recommended Actions. Meta-alert raised;
   member alerts deduped under it.
6. `10:31` all episodes cleared ≥ quiesce window (15 m) → **closed**, terminal
   version 9. Object queryable forever; `?replay` reproduces it bit-for-bit from
   `corr_signals`; the front page's "What changed" renders version timeline.

---

## 7. Multi-tenancy & zero trust

- Every signal, object, edge, evidence row carries `tenant_id`; engine state
  (windows, candidate pools, objects) is partitioned per tenant — **episodes never
  correlate across tenants**. Platform/global ('') correlates only infra-stack signals
  (strict-tenancy model).
- Engine validates every consumed record against per-kind schemas (malformed →
  dead-letter topic `netops.events.dlq` + counter, never a crash).
- Go API is the only public surface; it enforces authz/RLS exactly as for findings
  today. OperatorRestricted tenants: their correlation objects are hidden from the
  platform operator on every endpoint (same enforcement point as flows/findings).
- LLM note: if Opsis later summarizes objects, it receives the rendered evidence log
  (already sanitized, no secrets by construction) — §15 OWASP rules apply unchanged.

## 8. Failure modes and handling

| Failure | Handling |
|---|---|
| **Late / out-of-order signals** | Event-time windows + per-source watermark; lateness ≤ 120 s → retroactive insert + re-score; later → evidence row flagged `late`, object NOT rewritten (append-only honesty). |
| **Clock skew across sources** | Per-source skew estimate (ingest_ts − ts EWMA) widens that source's onset uncertainty; direction inference refuses onset-order votes when uncertainty intervals overlap — degrades to undirected, never guesses. |
| **Alert storm / signal flood** | Bounded per-tenant queues; storm mode at threshold: collapse episodes by entity prefix, coarsen to the 5 m window only, log `storm_mode` in every snapshot produced under it (scores are marked degraded). Backpressure to Kafka (pause/resume), never OOM. |
| **Topology stale/unavailable** | Snapshots embed `topology_version`; staleness > 2 pull intervals → w_topo capped at 0.4 + evidence note; engine keeps running on temporal+reinforcement (degraded, declared). |
| **Engine crash / restart** | Manual offset commit AFTER snapshot persist; on boot: reload open objects from PG + latest CH snapshots, resume from committed offsets. Versioned idempotent writes ⇒ at-least-once delivery is safe (duplicate snapshot = same (id,version) content, deduped at read by version). |
| **Hypothesis flapping** | Min-dwell 2 cycles before rank-1 flip; full ranked history preserved in version timeline (a flip is itself diagnostic signal). |
| **Cardinality explosion** | Node cap 200/object with logged evictions; candidate pool TTL = window span; per-tenant open-object cap (default 50, breach raises a platform alert — that's an incident in itself). |
| **Split-brain objects** | Deterministic merge rule (§4.4); merge recorded in both evidence logs; API redirects merged ids to the survivor. |
| **False merges** | Merge requires entity-overlap ≥ 40% AND window overlap AND combined graph diameter ≤ 6 — three independent brakes; merges are versioned and visible, never silent. |
| **Replay drift** | `engine_version` = code semver + config hash; replay compares stored vs recomputed and reports diff — CI gains a golden-incident replay test (lab-generated scenarios as fixtures). |

## 9. Phasing (aligns with the front-page MVP cut)

- **P1 (with front-page Phase 1):** normalizer + `corr_signals` (this IS #53's spine) +
  episode detection + 5 m window + graph builder + built-in template set + CH/PG
  persistence + `/api/correlations*` + WS emit. Infra-only (service_id null).
  Existing `/findings` API kept, backed by episodes (compat view).
- **P2 (with service catalog):** service dimension joins the graph (attribution
  stream); path/segment entities from probe placement; hypothesis templates gain
  service-scoped clauses.
- **P3:** user's failure-signature catalog loaded as templates (the differentiator
  moment); per-signature lab replay fixtures; meta-alert dedup feedback loop.
- **P4:** weight calibration from labeled history; cross-domain (cloud-log) signals
  as new sources — schema already admits them (`source` enum extension).

Out of scope here: UI views (front-page doc), cloud-log collectors (own lane),
ML-learned causal discovery (post-calibration research, only on top of the
deterministic core — never replacing it).
