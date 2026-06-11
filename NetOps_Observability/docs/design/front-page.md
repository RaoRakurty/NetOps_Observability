# Front Page — Triage-First Landing + Service Semantics Layer

Status: **DESIGN — awaiting sign-off** · Surfaces: React SPA + Go API · Tracker #69
Related: `correlation-engine.md` (#67 — supplies Top Issues / What-Changed / Recommended
Actions), `cloud-ingestion.md` (#68 — cloud seam panels), `rca-market-research.md`
(market/algorithm evidence behind these choices), memory `netops-frontpage-rca-direction`.

---

## 0. Objective and strategy

The current default route is the Overview panel board — a *status* page (gauges,
counts, top talkers). Useful, but it answers "what is the state of things", not the
NOC's actual opening question: **"is anything broken, who does it hurt, what changed,
and what do I do first?"** Every incumbent ships the status page; the triage page on
top of causal correlation objects is the white space we committed to.

Framing (owner, endorsed): the **truth streams — events, flows, probes, topology —
ARE the system**. The service catalog is a *semantic lens* on top of them. The
platform must be fully valuable with **zero services configured** (infra-only mode),
and every service-shaped panel must degrade to an honest INACTIVE state, never a
fake one. "Event + flow + probe correlation system with optional service semantics
layer."

Strategy is explicitly **not market parity**. The four differentiators this page
makes visible:

1. on-prem ↔ cloud ↔ underlay **seam** coverage incl. colo/POP middle mile (#68),
2. **causal, topology-grounded RCA** vs time-window statistics (#67),
3. **prescriptive L1–L7 fault direction** (failure-signature catalog → verdict +
   first steps + owner),
4. self-hosted multi-tenant.

House honesty rules apply throughout: no probabilities (confidence = heuristic
rank), no silently-empty panels (INACTIVE ≠ zero), no score without explanation.

## 1. Information architecture changes

| Change | Detail |
|---|---|
| **New default route** | `#/dashboards/home` → the Front Page (this doc). Set as the post-login landing for every role. |
| **Overview board demotes** | Current `#/dashboards/board` stays fully intact, renamed **"My Dashboard"** — the user-customizable panel board (registry in `pages/panels.tsx`, localStorage layout). Nothing removed. |
| **Command Center unchanged** | Stays the incident *drill-target*: Front Page rows link into it (and into `/api/correlations/{id}` views). The Front Page is "what needs attention"; Command Center is "work the incident". |
| **Events Explorer** | New leaf under Monitoring (`events` exists as stub): the #53 unified feed UI, reading the `corr_signals` spine (§5). |
| **Fixed layout** | The Front Page is **not** user-rearrangeable (it is an opinionated triage instrument; My Dashboard is the customizable one). Panels auto-hide rows that are INACTIVE-by-configuration only when the whole row is inactive — otherwise they render their inactive state (visible honesty beats layout purity). |

## 2. Service model — the semantic lens (Phase 2)

Three objects, deliberately split (owner decision 2026-06-11): identity is stable,
selection evolves, operations attach.

```sql
-- Postgres, RLS like every tenant table (migrations/000X_service_catalog.sql)
CREATE TABLE services (
    service_id   UUID PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    name         TEXT NOT NULL,            -- "Teams", "SAP", "Branch VPN"
    criticality  TEXT NOT NULL DEFAULT 'normal'
                 CHECK (criticality IN ('critical','high','normal','low')),
    description  TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at  TIMESTAMPTZ                -- never hard-delete: attribution history refers to it
);

CREATE TABLE service_selectors (            -- versioned, append-only
    service_id      UUID NOT NULL REFERENCES services(service_id),
    version         INT  NOT NULL,          -- monotonic per service
    effective_from  TIMESTAMPTZ NOT NULL,   -- attribution uses the version active at flow time
    spec            JSONB NOT NULL,         -- {dst_prefixes[], ports[], protocols[], remote_asns[], domains[], tags[]}
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (service_id, version)
);

CREATE TABLE service_bindings (             -- operational attachments
    binding_id   UUID PRIMARY KEY,
    service_id   UUID NOT NULL REFERENCES services(service_id),
    kind         TEXT NOT NULL CHECK (kind IN ('probe','path','seam')),
    ref          TEXT NOT NULL,             -- probe assignment id / path_id / seam_id
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

- **`services`** — stable identity. Renames don't break history; archive, never delete.
- **`service_selectors`** — the dynamic grouping rule, **versioned with
  `effective_from`**. Selector edits NEVER silently rewrite history: rows attributed
  under v3 stay v3 (deterministic, replayable — same rule as #67's snapshots).
  Reclassifying the past is an **explicit backfill job** (§3.3), audited.
- **`service_bindings`** — what we *operate* for the service: which probes watch it,
  which paths/seams carry it. Drives probe assignments (§7) and the cloud Layer-3
  admission policy (#68 §2 — same selector objects, one source of truth).

API (Go, tenant-scoped, RLS): `GET/POST /api/services`,
`GET/POST /api/services/{id}/selectors` (POST = new version),
`GET/POST/DELETE /api/services/{id}/bindings`.

## 3. Flow→service attribution pipeline

Decision (owner): attribution is **materialized at insert time in ClickHouse**, not
query-time joins and not Vector enrichment (reload/versioning semantics in Vector
are murky; CH dictionaries are explicit and versioned).

### 3.1 Mechanism

```
PG service_selectors ──(Go API flattens active versions)──▶ CH svc_selector_rules
                                                                  │ (dictionary source)
netops.flows insert ──▶ MV mv_flow_attribution ──(dict lookups)──▶ svc_flow_rollup_1m
```

- The Go API **flattens** the active selector set into `netops.svc_selector_rules`
  (one row per prefix/port/ASN predicate, carrying `service_id` + `selector_version`)
  on every selector change — same publish pattern as `device_tenant.csv` enrichment.
  Two CH dictionaries over it: `svc_by_prefix` (`ip_trie` layout) and `svc_by_port`
  (flat), TTL-refreshed + explicitly reloaded by the API after publish.
- A **materialized view** on the flows table computes attribution per inserted row
  and writes a 1-minute **rollup** (panels need aggregates, not raw flows):

```sql
CREATE TABLE svc_flow_rollup_1m (
    tenant_id        LowCardinality(String),
    ts               DateTime,                       -- minute bucket
    service_id       Nullable(UUID),                 -- NULL until catalog matches (Phase 2)
    selector_version UInt32,                         -- 0 = heuristic attribution
    app_label        LowCardinality(String),         -- Phase-1 built-in heuristics ('' = unknown)
    direction        Enum8('in'=1,'out'=2),
    site             LowCardinality(String),
    seam_id          LowCardinality(String),         -- '' until #68 seam inventory lands
    bytes            UInt64, packets UInt64, flows UInt64
) ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (tenant_id, ts, service_id, app_label, direction, site, seam_id)
TTL ts + INTERVAL 90 DAY;
```

### 3.2 No schema churn later (Phase-1 rule)

`service_id` (NULLABLE) + `selector_version` + `seam_id` exist **from day one**, even
though Phase 1 fills only `app_label` from built-in heuristics (well-known
ports/prefixes → "dns", "https", "ipsec", "ms-teams"…). When the catalog ships, the
same table gains real attribution with zero migration; heuristic rows remain
distinguishable (`selector_version = 0`).

### 3.3 Backfill (explicit, never implicit)

`POST /api/services/{id}/selectors/{v}/backfill?from=&to=` — an audited admin job
that re-attributes a past window under a new selector version by inserting
*corrective rollup rows* (negative+positive deltas in SummingMergeTree). Default off;
history is truth, reclassification is an intentional act.

## 4. Health score — normalized, weighted, explainable

There is no health score in the product today (verified). The score is worth
shipping only with all three properties; a bare 0–100 is noise the NOC learns to
ignore (and the research is blunt about opaque scores — see
`rca-market-research.md`).

### 4.1 Per-signal normalization → badness b ∈ [0,1]

| Signal class | Normalization | Rationale |
|---|---|---|
| latency (probe rtt/owd) | **percentile distance**: `b = clamp01((v − p50) / (p99 − p50))`, quantiles from a rolling 28d window per (target, hour-of-week) | "is 80 ms bad?" depends on the path; distance from *its own* distribution is comparable across paths |
| jitter (pdv) | same percentile distance | same |
| loss | **log-scale**: `b = ln(1 + v/0.1) / ln(1 + 100/0.1)` (v in %) | loss is non-linear in user pain: 1% ≈ disaster for voice; linear scaling would hide it (1% → b≈0.35, 5% → b≈0.57, 50% → b≈0.9) |
| interface utilization | hinge: `0` below 70 %, linear 70→95 %, `1` above | utilization is only bad near saturation |
| errors/discards rate | percentile distance vs own 28d baseline | error floors differ wildly per media type |
| availability | binary: down=1, flapping(≥3 transitions/h)=0.6 | non-negotiable signal |
| active correlation objects touching the scope | `b = top_confidence` of the worst object | the engine's judgment feeds the score, not raw alert counts (alert counts double-count what correlation already deduped) |

### 4.2 Aggregation

Per scope (global / site / device / service):

```
blend  = max( Σ wᵢ·bᵢ / Σ wᵢ ,  0.8 × max(bᵢ) )
score  = round( 100 × (1 − blend) )
```

Default weights (per-tenant configurable, part of the score config hash):
availability 3.0 · loss 2.5 · correlation 2.0 · latency 1.5 · errors 1.5 ·
jitter 1.0 · utilization 1.0.

The `max` floor stops averaging from hiding a catastrophe (one dead site inside 50
healthy devices). When the floor binds, the explanation says so explicitly
("floored by: probe loss dallas→equinix").

**Coverage honesty:** if fewer than 2 signal classes are live for a scope, the score
is **INSUFFICIENT TELEMETRY** (rendered as `—` + coverage chips), never a hollow 100.
Each score carries `coverage: {class: live|inactive}` so the UI can show *what the
score is based on*.

### 4.3 Explainability contract (the part incumbents skip)

```
GET /api/health/score?scope=site|device|service|global&id=...
→ {
    "scope": "site", "id": "dallas", "score": 72,
    "floored_by": null,
    "coverage": {"availability":"live","loss":"live","latency":"live",
                 "errors":"live","utilization":"live","jitter":"inactive",
                 "correlation":"live"},
    "contributions": [                         // sorted by points, sums to 100 − score
      {"signal":"probe_loss","entity":"segment dallas→equinix-pop",
       "badness":0.57,"weight":2.5,"points":18,
       "evidence":"/api/correlations/c-7f3a"},
      {"signal":"if_util","entity":"dallas-edge:Gi0/1","badness":0.62,
       "weight":1.0,"points":7,"evidence":null},
      ...
    ],
    "config_hash": "w-default-v1"              // weights/windows versioned like engine config
  }
```

Computed in the Go API on demand (VM quantile queries + alerts + `corr_objects_latest`),
30 s cache per (tenant, scope, id). UI: every score chip expands to its
contributions; "72 because…" is one click, always.

## 5. Unified event feed (#53's UI half)

The backing store **is** `corr_signals` (#67 §2.1) — one spine, two consumers (the
correlation engine and this feed). No second event table.

```
GET /api/events/feed?from=&to=&source=&kind=&severity=&entity_type=&entity=&site=&q=&cursor=
→ { items: [FeedItem], next_cursor, facets: {source:{flow:12,...}, severity:{...}, kind:{...}} }

FeedItem (render contract, stable):
{ signal_id, ts, source, kind, severity, entity_type, entity_id, site,
  title,                        // server-rendered one-liner: "BGP peer 10.0.0.1 down on dallas-edge"
  correlation_id | null,        // attached episodes link to their object
  attrs }                       // bounded JSON, per-kind schema
```

Live tail: WebSocket hub topic `events` (hub exists; topic added alongside #67's
`correlations`). The Events Explorer leaf renders feed + facets + a severity-banded
timeline; "what changed" on the Front Page is this same API pre-filtered to
discrete change kinds (`topology`, `sot_drift`, `alert` state transitions, config
change when sourced).

## 6. Panel → API contract

Layout (desktop, 12-col; mockup refined). Every panel declares: API, phase, and its
honest INACTIVE condition. *No panel ever renders synthetic/demo data.*

```
┌────────────────────────── 1 Health strip (global + per-site scores) ───────────────────────┐
├───────────── 2 Top Active Issues (corr objects) ───────────┬─── 3 Recommended Actions ─────┤
├───────────── 4 What changed (feed: change kinds) ──────────┼─── 5 RCA coverage stat ───────┤
├──── 6 Service health (P3) ───┬─── 7 Hot paths/seams ───────┼─── 8 Impact (P4) ─────────────┤
├──── 9 Topology impact map ──────────────────┬── 10 Capacity outlook (P2) ──────────────────┤
└──── 11 App↔net correlation strip (P3/P4) ───┴──────────────────────────────────────────────┘
```

| # | Panel | API | Phase | INACTIVE when / shows |
|---|---|---|---|---|
| 1 | **Health strip** — global score + per-site chips, each expandable to contributions | `GET /api/health/score?scope=global` + `scope=site` (batch) | **P1** (infra-only) | < 2 signal classes per scope → "insufficient telemetry" + coverage chips + onboarding link |
| 2 | **Top Active Issues** — open correlation objects: headline hypothesis, confidence band, affected entities, age, ack state | `GET /api/correlations/active` + WS `correlations` | **P1** | engine not running → "Correlation engine offline" (stack health link). Zero objects → "No active correlated issues" + last-closed link (a *good* empty) |
| 3 | **Recommended Actions** — rank-1 hypothesis verdict: owner badge (netops/carrier/cloud/app) + first 3 steps | same payload as 2 (`hypotheses[0].verdict`) | **P1** (built-in templates; real value at P3 catalog) | no object ≥ confidence floor → "No action suggested — investigating signals" listing top ungrounded/low-rank episodes |
| 4 | **What changed** — last-N discrete changes: topology deltas, SoT drift, alert transitions, config/deploy events | `GET /api/events/feed?kind=change-classes` | **P1** | feed empty AND sources inactive → onboarding hints (per-source) |
| 5 | **RCA coverage** — % of open objects with rank-1 ≥ 0.5; 7-day % of incidents closed with a confirmed hypothesis; signature-catalog size | `GET /api/correlations/stats` (new, cheap CH aggregates) | **P1** | engine offline → INACTIVE. Honest by construction: low % is *displayed*, that's the point |
| 6 | **Service health** — per-service score chips sorted worst-first, traffic sparkline from rollup | `/api/health/score?scope=service` + `GET /api/flows/services` (rollup query) | **P3** | catalog empty → "No services defined — the platform is fully functional without them" + define-service CTA |
| 7 | **Hot paths / seams** — worst probe segments + seam instances: rtt/jitter/loss vs baseline, path-change flags | `GET /api/probe/paths` + `probe_*` metrics via `/api/metrics/query_range`; seam dimension when #68 lands | **P1** (paths) → seams at CI-P2 | no probes configured → synthetics/STAMP onboarding hint (`EmptyHint` kind exists) |
| 8 | **Impact** — users/sites affected by open objects; cost-weighted when configured | corr `affected` × operator-entered site/user/cost data (P4 business layer) | **P4** | until business data entered → INACTIVE "configure site users/cost to light this up" (never guesses) |
| 9 | **Topology impact map** — existing topology graph with corr-object overlay (affected nodes pulse by severity) | `GET /api/regions/topology` + `affected` sets from 2 | **P1** | topology empty → discovery onboarding |
| 10 | **Capacity outlook** — days-to-90 % per WAN interface (28d linear + seasonal-naive trend), worst-first | `GET /api/metrics/forecast?class=wan_util` (new, computed in Go over VM range data) | **P2** | < 14d history per interface → "building baseline (N days left)" |
| 11 | **App↔net correlation strip** — service episodes joined to network-layer causes (the cross-domain seam story) | `GET /api/correlations?entity_type=service` once service signals exist | **P3/P4** | until then → INACTIVE explaining the dependency (catalog + cloud tiers) |

Dropped from the mockup: **TCP retransmits** (no source: lab exporters don't fill
`tcpControlBits` reliably and we refuse derived fakes — revisit if eBPF/mirroring
lands post-#68).

New API surface this doc owns: `/api/health/score`, `/api/events/feed`,
`/api/correlations/stats`, `/api/metrics/forecast`, `/api/flows/services`,
`/api/services*` (§2). Everything else exists or is owned by #67.

## 7. Probe placement (foundational, not an afterthought)

Differential measurement is the only honest way to disambiguate segments we don't
own (site→edge vs edge→ISP vs edge→cloud brackets the leased line / middle mile —
#68 seam table drives *what* to bracket).

- **v1 rule (Phase 1, static):** 1 probe per site, 1 per cloud region (when T2
  lands), 1 per SaaS target group. Configured via bindings (§2) or env
  (`STAMP_TARGETS`/`SYNTHETIC_*` today).
- **Vantage-point agent (new deliverable, with #68 CI-P1):** the existing
  `PROBER_ONLY` sidecar promoted to a deployable agent — static Go binary,
  registers to the platform over outbound mTLS (per-tenant ingest URL), receives
  probe assignments from service/seam bindings, ships results. The #68 cloud
  collector **is** this agent grown up; same hard constraint applies (deterministic
  executor, zero local judgment).

## 8. Phasing (the MVP cut, binding)

| Phase | Ships | Front-page effect |
|---|---|---|
| **P1 — must ship** | `corr_signals` spine + engine P1 (#67) · attribution rollup w/ heuristics + NULLABLE service_id (§3.2) · STAMP+ICMP+HTTP probes (exist) · health score infra-only (§4) · events feed (§5) · **new landing page** with panels 1,2,3,4,5,7,9 live | the visible win: triage page on causal objects, zero services needed |
| **P2 — unlock** | service catalog v1 (§2, 3-way model) · attribution gains catalog dimension · probe bindings · capacity forecast (panel 10) | service chips appear; INACTIVE states start converting |
| **P3 — differentiation** | user's failure-signature catalog loads (#67 P3) · service health + per-service hot paths + site×service heatmap (Explorer view) · panel 6, 11 | Recommended Actions become practitioner-grade; the selling point lands |
| **P4 — vision** | causality graph UI · cross-domain (cloud-log #68 T1/T2 signals) · business-impact layer (panel 8) · score/weight calibration | the full white-space story |

Failure-signature engine is **not parked at P4**: built-in infra signatures run from
P1; the user-authored catalog (in progress, owner) swaps in at P3 — same schema,
data not code.

## 9. Build order (P1, follow-along granularity)

1. `corr_signals` + engine P1 land first (#67 — separate lane, same milestone),
   **including the seam bootstrap engine** (cloud-ingestion.md §4.1): the grounding
   inventory is a P1 deliverable, not a follow-up.
2. `svc_flow_rollup_1m` + heuristic MV + `/api/flows/services` (no UI yet).
3. `/api/health/score` (global+site+device) + unit tests for every normalization
   curve (§4.1 table is the test spec).
4. `/api/events/feed` over `corr_signals` + WS `events` topic.
5. `/api/correlations/stats`, `/api/metrics/forecast` stubs→real.
6. Front Page route + panels 1/2/3/4/5/7/9 + INACTIVE machinery
   (extend `EmptyHint` with per-panel inactive reasons) + nav rename
   (`board` → "My Dashboard", new default `home`).
7. Golden walkthrough: replay the Dallas scenario (#67 §6) end-to-end in the lab;
   the Front Page must tell that story unaided — that's the acceptance test.

Out of scope here: Events Explorer full UI (follows the feed API), service catalog
UI (P2), signature-catalog authoring UI (P3 — catalog arrives as data first).
