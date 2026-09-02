# Correlix Resource Sizing — Design (v2, for owner review)

Status: **DRAFT v2 — awaiting owner approval** (2026-07-11)
v2 incorporates the owner's refined specification (evidence discipline,
coefficient provenance, storage/I-O as first-class dimensions, explicit
overcommit policy, tenant-governance separation, benchmark plan, A/B/C
decision framework, revised maturity taxonomy).

---

## 0. v2 changelog (what the refined spec changed)

| # | Enhancement in refined spec | Where addressed |
|---|---|---|
| 1 | Evidence discipline: file:line + confidence + fact/vendor/inference/unknown separation | §1 (audit restated with classes), §5 (per-rule provenance), §13 (unknowns) |
| 2 | Never invent coefficients; label every rule's evidence class; provisional ≠ certified | §4.2, §5 provenance column, plan-output warnings |
| 3 | Storage capacity / throughput / IOPS / temp-merge space are first-class; a memory-adequate plan with inadequate storage is INVALID | §4.4, §6 validation set |
| 4 | Requests vs hard limits + explicit approved overcommit policy (not a blanket no-oversubscription rule) | §4.3 |
| 5 | CLICKHOUSE_MEM_LIMIT end-to-end trace + verdict on the 5g change | §2 (full trace, evidence-classed) |
| 6 | Revised maturity taxonomy (0 universal … 5 auto-resize) | §1.3 — verdict changes to **Level 1** |
| 7 | Outcome A/B/C decision with 3-option comparison table | §3 |
| 8 | Multi-tenancy / noisy-neighbor governance separated from deployment sizing | §9 |
| 9 | Benchmark & calibration plan with coefficient metadata | §10 |
| 10 | Alert semantics: CHQueryMemoryKilled must not fire without query-kill evidence; no renames without dependency review; per-alert runbook fields | §8 |
| 11 | Failure-mode sizing (downstream outage → buffer growth in Vector/syslog-ng/goflow2) | §4.2 driver map, §10 scenario, test 24 |
| 12 | Unit normalization (GiB/g/bytes), plan rollback, 26 test scenarios | §7, §11 |
| 13 | Rollout plan (flags, canary, migration, success criteria) | §12 |
| 14 | Verify versions before version-specific settings; OpenSearch ≠ Elasticsearch assumptions | §5 notes, §13 unknowns |

Spec items **moot by repository evidence** (unchanged from v1, re-verified):
Redpanda & Redis are removed (#97 — patterns applied to Apache Kafka & Valkey);
no Kubernetes/Helm/Terraform/Ansible/CI deployment path exists (Compose only;
K8s an explicit deferred TODO in the compose banner); Telegraf exists behind the
off-by-default `legacy` profile.

---

## 1. Phase-1 audit summary (evidence-classed)

Full agent transcripts underlie these; each line carries its class:
**[FACT]** = observed in repo (file:line), **[VENDOR]** = vendor-documented,
**[INF]** = engineering inference, **[UNK]** = unknown, needs measurement.
Confidence high unless noted.

- **[FACT]** All ~30 compose services carry env-overridable lab defaults
  (`docker-compose.yml`, e.g. `${CLICKHOUSE_MEM_LIMIT:-4g}` :610,
  `${OS_MEM_LIMIT:-3g}` :390). Banner :28-35 declares them "LAB-SIZED
  PLACEHOLDERS… PROD must re-tune".
- **[FACT]** Neither installer writes any `*_MEM_LIMIT`/`*_CPU_LIMIT`/heap var
  (grep = 0 in `scripts/install.py`, `scripts/install-correlix.sh`). No
  capacity calculation exists anywhere.
- **[FACT]** `install-correlix.sh` detects host CPU/RAM/disk but uses them only
  as pass/fail floors (:133-192: die <2 vCPU / <6 GB RAM / <20 GB disk).
- **[FACT]** Default-profile mem_limit caps sum ≈ 16.1 GiB (17.1 with the live
  5g override) on the 16 GiB lab host — unvalidated overcommit; no
  requests/reservation layer exists (no `mem_reservation` anywhere).
- **[FACT]** Go services set no GOMEMLIMIT/GOGC (repo grep = 0). **[VENDOR]**
  Go GC therefore targets heap growth against host RAM, blind to the cgroup.
  (**[FACT]** Go toolchain 1.26 per go.mod/Dockerfile (raised 1.25.13 → 1.26.8,
  2026-09-02); **[VENDOR, verify in P3]**
  Go ≥1.25 sets GOMAXPROCS cgroup-aware natively; GOMEMLIMIT still manual.)
- **[FACT]** ClickHouse per-query caps are absolute constants
  (`query-spill.xml:19-29` 2 GiB hard / 1.5 GiB spill;
  `workload-profiles.xml:28-36` 1–2 GiB) with comments saying they must be
  re-scaled manually at prod sizing. No `max_concurrent_queries` set anywhere.
- **[FACT]** No repo config asserts CH server-memory behavior (no
  max_server_memory_usage / ratio / cgroup settings in any mounted XML).
- **[FACT]** Postgres runs stock alpine defaults (no conf/command overrides;
  only `netops-app-role.sql` is mounted). Valkey `--maxmemory 96mb` hard-coded
  under a 128m cap with deliberate `noeviction` (compose :82-86). OpenSearch
  heap `-Xms/-Xmx ${OPENSEARCH_HEAP:-1g}` under 3g cap (:397). Kafka heap
  `-Xmx512m` hard-coded under 1g (:180). VictoriaMetrics sets no memory flag
  (:455-469) — **[VENDOR]** defaults to `-memory.allowedPercent=60` of
  cgroup-visible memory (v1.101 is cgroup-aware).
- **[FACT]** Vector aggregator+router have no buffer/batch config (defaults).
  Correlation service: single uvicorn worker, fixed 50k-signal window deque
  (`main.py:430`). Reporting workers are in-process goroutines in the API
  (`report_pipeline.go:73` REPORT_WORKERS=4).
- **[FACT]** No sizing tests exist. Docs: one 3-row host table
  (`DEPLOY_LINUX.md:6-16`).
- **[FACT]** Alerting: host memory/disk/CPU live (node-exporter); CH
  app-level memory alert live; container-pressure/OOM rules exist but are
  cadvisor-blind (containerd store, documented rules.yaml:664-666); no host
  OOM-killer alert; no OpenSearch heap alert.

### 1.2 Existing mechanisms (rule 7: extend, don't duplicate)

**[FACT]** The repo's canonical configuration generator is `install.py`
(generates `.env`, migrates it in place, owns `COMPOSE_PROFILES`), plus
`install-correlix.sh` for customer bundles (host gates, add-ons) and
`preflight.sh` (compose↔installer parity). The proven profile pattern is
`CORR_RETENTION_PROFILE` (presets + per-knob env overrides + safety floor —
`corr_retention.go:54-94`). **The planner extends this system** — a module the
existing installers call — not a parallel subsystem.

### 1.3 Maturity verdict (revised taxonomy)

Under the v2 taxonomy Correlix is **Level 1 — operator-configurable static
values**: every value is env-overridable (so not Level 0), but no capacity
calculation of any kind exists (host detection is validation-only). Nothing
reaches Level 2. Target: **Level 3** (workload-aware deployment sizing), with
Level 4 (telemetry-driven recommendations) as a later additive phase and
Level 5 explicitly out of scope.

---

## 2. CLICKHOUSE_MEM_LIMIT: the complete trace and the 5g verdict

**Definition → runtime path [FACT, high confidence]:**

1. Defined in exactly one place: `docker-compose.yml:610`
   `mem_limit: ${CLICKHOUSE_MEM_LIMIT:-4g}`. Not referenced by install.py, any
   entrypoint, or any ClickHouse XML.
2. Compose v2 maps `mem_limit` → the container cgroup-v2 `memory.max`.
   So the variable controls **Docker container memory — one layer, nothing else.**
3. The live value `5g` sits in `deployment/docker/.env:183` — a manual operator
   edit (2026-07-11 incident response), not installer output.

**Indirect internal effect [VENDOR, medium confidence until asserted]:**
ClickHouse 24.8 stock config ships `max_server_memory_usage_to_ram_ratio=0.9`
and reads cgroup-visible memory, so the internal server ceiling follows the
container limit (~4.5 GiB at 5g). The repo does not assert or pin this —
vendor GitHub issues (#62788 et al.) document cgroup-detection failures in
some container environments. The observed effective ceiling of 3.6 GiB at 4g
(= 0.9 × 4g) **is itself repo-side evidence the coupling worked here**.

**Not affected by the change [FACT]:** all per-query caps
(hot_ui 1 GiB, background/default 2 GiB, spill thresholds 1.5 GiB) — absolute
constants, unchanged at any container size.

**Verdict:** the 5g change was a **correct tactical mitigation** (relieved a
real total-memory ceiling; recoverable, reversible) and **a container-memory
change whose internal effect rides an unasserted vendor default** — i.e.
*incompletely wired by design standards*: the coupling works but is implicit,
unpinned, and undocumented in-repo. It is **not** a sizing solution: it
remains a universal manual constant, per-query caps didn't scale, and nothing
prevents the same incident at the next workload increment.
**[UNK]** The attribution of the 4.19 GiB transients to #101 background jobs
was timing-based inference only (~30-min cadence match). It has NOT been
proven against `system.metric_log`/`system.query_log`/merge activity — carried
into the benchmark plan (§10) as measurement item M1.

**Alert follow-up:** yesterday's re-key to
`ClickHouseErrorMetric_MEMORY_LIMIT_EXCEEDED` fixed the false-fire (no
exceptions → no alert). Remaining semantic gap per refined spec: the metric
counts **all** thrown MEMORY_LIMIT_EXCEEDED (query or background context), so
the name `CHQueryMemoryKilled` still overclaims "query killed". §8 proposes
the rename + a proactive pressure alert — executed only with the required
dependency review (dashboards, tests, docs, notification routing).

---

## 3. Decision: Outcome A / B / C

| Option | Description | Effort | Migration risk | Operational benefit | Long-term maintainability |
|---|---|---|---|---|---|
| Minimal | Fix proven defects only (GOMEMLIMIT, CH ratio asserted, CH query caps env-scaled, Postgres conf, alert semantics) | ~2 days | very low | Removes whole-host assumptions; sizing still manual per customer | Poor — every customer install remains hand-tuned env editing |
| Incremental | Minimal + document a manual sizing worksheet per profile | ~3 days | low | Operators get guidance; still manual, error-prone, unvalidated aggregates | Medium — worksheet drifts from reality |
| **Canonical planner (selected)** | One calculation module extending the existing installer system; generated plans; aggregate + storage validation; legacy overrides preserved | ~2 wks phased | low (fresh installs only until `--replan`) | Per-customer generated sizing, refuse-to-fit, explainable plans | Good — single model, tests, calibration path |

**Why C is justified by evidence (spec's own criteria):** no equivalent
mechanism exists [FACT §1.2 — install.py generates config but computes
nothing]; per-customer sizing today requires manual `.env` edits [FACT];
aggregate capacity is never validated [FACT — 16.1 GiB caps on a 16 GiB
host]; internal limits don't derive safely from boundaries [FACT — Go, CH
query caps, Postgres]. Docker/K8s conflict doesn't apply (no K8s). The
planner is implemented **as an extension of the existing installer system**
(rule 7), not a parallel mechanism — `scripts/resource_planner.py`, called by
both installers, sole owner of sizing math. Minimal's defect fixes are all
*contained within* C's P3 phase, so C strictly includes A.

---

## 4. Target architecture

### 4.1 The chain (owner's model, adopted)

```
Host / VM capacity  (detected; cgroup-visible when containerized)
  → OS + runtime + platform reserve
  → Correlix allocatable capacity
  → workload + deployment topology
  → per-component CPU / memory / storage / I-O budgets
  → container requests (mem_reservation) and hard boundaries (mem_limit)
  → application-internal limits and concurrency controls
  → runtime telemetry, alerts, resize recommendations
```

Computed at install and explicit resize/upgrade only. No continuous limit
mutation. Planner: `scripts/resource_planner.py`, stdlib-only Python 3,
pure calculation + thin I/O; both installers call it; emits
`.env` managed block + `resource-plan.json` + `resource-plan.txt`
(+ future `values.resources.generated.yaml` from the same JSON when K8s
arrives). Precedence:

```
built-in safe minimums < named profile < workload-derived plan
  < customer override file < emergency operator override (hand-set var
    outside the managed block — detected, honored, warned)
```

### 4.2 Workload drivers → component map (with provenance discipline)

Every coefficient in the planner lives in ONE table; each entry carries an
**evidence class** from the spec's taxonomy (`vendor-required`,
`vendor-recommended`, `repository-existing`, `benchmark-derived`,
`telemetry-derived`, `conservative-provisional`, `unknown-measurement-required`)
plus source citation, date, and applicable range. **v1 ships with most scaling
coefficients classed `conservative-provisional` and the plan output prints
that warning verbatim** — nothing is presented as production-certified until
§10 calibration upgrades its class. Driver map (inputs → affected components):

- devices/interfaces/series & churn → VictoriaMetrics, gnmic, api
- flows/s + record size + retention → goflow2, Kafka, Vector, ClickHouse (+disk)
- syslog EPS + event size + retention → syslog-ng, Vector, Kafka, OpenSearch (+disk)
- probes/min + vantage count → prober, VictoriaMetrics
- concurrent users + analytical queries + dashboards → api, ClickHouse, OpenSearch, VictoriaMetrics, Postgres
- tenants + report/scheduled-job concurrency → api (REPORT_WORKERS), Postgres, ClickHouse, gotenberg
- correlation background workload (EPS-derived) → correlation, ClickHouse
- HA/replication → validated input; v1 errors on `high_availability: true` (single-node product) [FACT]
- **failure modes**: downstream-outage buffer growth affects Vector/syslog-ng/goflow2/Kafka
  (today: default in-memory buffers [FACT]) — v1 sizes their steady-state
  containers with an outage allowance term and flags disk-buffer adoption as a
  P5 decision informed by benchmark scenario B10.

### 4.3 Requests, limits, and the explicit overcommit policy

New in v2 (replaces v1's blanket "no oversubscription"):

- Planner emits **both** `mem_reservation` (request-equivalent) and
  `mem_limit` (hard boundary) per service — compose supports both today.
- Invariants: `Σ mem_reservation ≤ allocatable` (guaranteed capacity), and
  `Σ mem_limit ≤ allocatable × overcommit_factor` where `overcommit_factor`
  is an explicit, printed policy knob (default 1.0 for stateful engines'
  sub-budget, up to 1.3 across burst-capable stateless services;
  class: conservative-provisional). CPU: Σ cpus ≤ cores × cpu_overcommit
  (default 1.5; CPU is compressible).
- Component minimums are never silently reduced (refusal instead), exactly per
  spec.

### 4.4 Storage and I/O as first-class dimensions

A plan is INVALID unless storage validates:

- Persistent estimate = Σ per-store retained-state terms: CH
  (flows/s × avg record bytes × compression × days + syslog + corr state),
  OpenSearch (EPS × event bytes × replication × days, ISM-aligned),
  VictoriaMetrics (series × bytes/sample × samples/s × days), PG, Kafka
  (`BUS_RETENTION_BYTES` [FACT: 512 MiB default]). Compression ratios:
  class conservative-provisional until calibrated (§10 measures real
  bytes/record from the lab CH/OS stores).
- Temporary/merge space: CH merges + OpenSearch segment merges need transient
  headroom (vendor-recommended allowances; verified against deployed versions).
- Validated against detected free disk minus a free-space reserve; refusal
  message includes retention-reduction options (spec's corrective-action list).
- Throughput/IOPS: inputs accepted (`storage.type/iops/throughput`), default
  `unknown` → plan prints an explicit "storage capability undeclared —
  validate ingest rate ≥ X requires ~Y sustained IOPS" advisory rather than
  fake validation (class: unknown-measurement-required). Fd limits: existing
  ulimits retained [FACT: opensearch, clickhouse]; planner asserts them for
  new scales.

### 4.5 Named profiles

`demo | small | medium | large | custom` (spec naming), each = defaults for
workload inputs + reserves, VCSA-style bounds documented; auto-selected from
detected host when unspecified; always refinable by explicit workload inputs.
(Alignment of names with GTM/licensing tiers = open owner decision.)

---

## 5. Per-component internal limits (provenance-labeled)

| Component | Internal knob(s) | Rule | Evidence class + source |
|---|---|---|---|
| ClickHouse 24.8 [FACT: compose :605] | `max_server_memory_usage_to_ram_ratio` **asserted** in new `memory.xml` | 0.9 × container | vendor-recommended (CH docs; also matches current implicit behavior = repository-existing) |
| | per-query caps → env-driven | hot_ui / background / spill as ratios of container with floors at today's values | repository-existing (today's constants) + conservative-provisional (the ratios) |
| | `max_concurrent_queries` | from concurrency input | vendor-recommended |
| OpenSearch 2.16 [FACT: :386] | `OPENSEARCH_HEAP` | 50% of container, cap 31g, Xms=Xmx | vendor-recommended (OpenSearch docs — verified against OS 2.16 docs, not ES, in P3) |
| Kafka 4.1 [FACT: :146] | `KAFKA_HEAP` (parameterize :180) | min(6g, 50%); remainder = page cache | vendor-recommended (Confluent/Kafka ops docs) |
| VictoriaMetrics v1.101 [FACT: :452] | `-memory.allowedPercent` asserted | 60 (cache budget — NOT total-process budget; container limit remains the backstop for query overhead) | vendor-recommended (VM docs; also current implicit default) |
| PostgreSQL 16 [FACT: :56] | shared_buffers / effective_cache_size / work_mem / maintenance_work_mem / max_connections | pgtune-family formulas; work_mem sized against realistic concurrent operations (NOT max_connections × work_mem); connections from measured pool sizes (api pool 25 [FACT: config.yaml:16] + correlation + reserve) | vendor-recommended (PG wiki/pgtune) + repository-existing (pool sizes) |
| Valkey 8 [FACT: :81] | `--maxmemory` parameterized | 75% of container; **policy stays `noeviction`** — role audited as durable app state [FACT: compose :83 comment], eviction would be data loss | vendor-recommended (ratio) + repository-existing (policy) |
| Go services (api, prober, mocks, goflow2) | `GOMEMLIMIT` env (soft runtime target, not a hard cap — spec 3.7) | 90% of container; GOGC default; GOMAXPROCS: verify Go 1.25 cgroup-awareness in P3 | vendor-recommended (Go runtime guidance/automemlimit convention); env-only, stdlib constraint intact |
| correlation (Python 3.12) | `CORR_WINDOW_BUFFER` (new env), worker count stays 1 (asyncio) | buffer from EPS & memory term; floor 50k (today) | repository-existing (deque bound) + conservative-provisional (scaling) |
| Vector 0.40 ×2 | container sizing v1; buffer/batch config P5 after benchmark B10 | — | unknown-measurement-required |
| syslog-ng, gnmic, nginx, frontend, grafana, osd, exporters | container limits only, tier-stepped | — | conservative-provisional |

---

## 6. Aggregate validation set (planner hard checks)

1. Σ reservations ≤ allocatable memory; Σ limits ≤ allocatable × overcommit policy.
2. Every internal limit < its container limit at its declared ratio.
3. Floors respected or refuse (never silent shrink).
4. Persistent storage estimate ≤ free disk − reserve; temp/merge headroom present.
5. Declared IOPS/throughput ≥ estimate when declared; advisory when unknown.
6. CPU Σ ≤ cores × cpu_overcommit; per-service CPU floors.
7. Minimum supported host (profile floors) — else refusal with contributors +
   corrective actions (increase host / reduce retention / reduce concurrency /
   dedicated-node option), exactly per spec format.
8. Unit discipline: all internal math in bytes; inputs parsed from
   GiB/GB/g/m/k forms, normalized, echoed back normalized in the plan.

---

## 7. Backward compatibility & rollback

- Managed `.env` block (`# BEGIN/END correlix-resource-plan`); hand-set vars
  outside it are emergency overrides: honored, deprecation-warned with the
  spec's message format (observed semantics + generated recommendation +
  headroom note). `CLICKHOUSE_MEM_LIMIT=5g` becomes the worked example.
- Existing installs: zero behavior change until explicit `--replan`.
- Rollback: previous block saved (`.env.plan.bak-<ts>`) + prior
  `resource-plan.json` retained; `--rollback-plan` restores; `--replan`
  refuses to shrink below 7-day observed p99 per-container usage when
  telemetry is available (measure-then-resize).

---

## 8. Alerting (with dependency-review discipline)

Keep: host memory/disk/CPU (live), CH `MEMORY_LIMIT_EXCEEDED` exception alert
(fixed 2026-07-11), container-pressure/OOM rules (cadvisor-blind, documented,
light up when the containerd-store issue resolves).

Add / change (each with condition, source, thresholds, duration, runbook,
pressure-vs-failure class in docs):

| Alert | Class | Note |
|---|---|---|
| HostOOMKillerFired (`node_vmstat_oom_kill`) | platform failure | closes the uncovered class-5 gap |
| CHMemoryPressureSustained (MemoryTracking/limit > 0.85 for 10m) | capacity pressure | proactive, replaces what the old false-firing alert was accidentally doing |
| **Rename** `CHQueryMemoryKilled` → `CHMemoryLimitExceeded` | app failure | current metric counts all thrown MEMORY_LIMIT_EXCEEDED (query OR background) — name overclaims. Rename ships ONLY with the spec-required dependency review: dashboards, tests, docs, notification routing, ServiceNow/PD rules. Query-kill *attribution* = runbook step (`ch-query-budget-check.sh` + system.query_log). |
| CH merge/mutation backlog, ingestion lag (Kafka consumer lag), queue growth (Vector) | capacity pressure | P5, sources exist (CH metrics :9363, Kafka JMX absent → lag via CH-side freshness [INF], scope in P5) |
| OpenSearch JVM heap pressure | capacity pressure | deferred — needs an exporter; circuit breakers are the in-process net meanwhile [documented gap] |

---

## 9. Multi-tenancy: governance ≠ deployment sizing

Per spec, kept strictly separate from the planner. Current state [FACT]:
per-tenant CH partitioning + write-amp rollups (#101), API-key rate limit
(env), CH workload profiles (hot_ui/background) — service-level, not
per-tenant quotas. The planner takes `tenants` only as a capacity input.
Per-tenant ingestion quotas / query concurrency / CH per-tenant memory /
retention / report concurrency = a separate roadmap lane (candidate tracker
item), with its own design; nothing in this work implements or blocks it.

---

## 10. Benchmark & calibration plan

Purpose: raise coefficient classes from conservative-provisional →
benchmark-derived/telemetry-derived. Anchor 0 = the live lab (known workload:
~13 devices, ~1.1k flows/s tgen, real EPS; measured docker stats + CH/OS/VM
on-disk bytes per retained day). Then scripted scenarios (tgen + flowgen +
seed tooling, all in-repo): demo, small-prod, flow-heavy, log-heavy,
metrics-heavy (series churn), query-heavy (concurrent analytics), multi-tenant,
reporting-heavy, **B10 downstream-outage buffer growth** (stop OpenSearch/CH,
watch Vector/Kafka/syslog-ng memory & loss behavior), merge-heavy CH
(mutation storm), storage-latency degradation (M1: attribute the 4.19 GiB CH
transients via system.metric_log/part_log — settle the #101 inference).
Measured per scenario: p50/p95/p99 container RSS, app-tracked memory, CPU,
disk + temp usage, IOPS/throughput, query latency, ingestion lag, merge
backlog/part counts, queue depth, OOM events. Coefficients stored with test
version, dataset, hardware, component versions, date, confidence, safety
factor, applicable range (spec format) in a `calibration/` fixture the
planner's table cites.

---

## 11. Testing (26 scenarios, all mapped)

`scripts/tests/test_resource_planner.py` (stdlib unittest) + golden files
(plan JSON + generated env block per fixture) + `docker compose config`
rendering check in preflight. Scenarios 1–26 per spec §12: demo/small/flow/
log/metrics/query/multi-tenant/HA inputs, host-too-small, insufficient
storage, unknown-IOPS advisory, legacy CLICKHOUSE_MEM_LIMIT, customer + 
emergency overrides, Σ requests ≤ budget, Σ limits ≤ overcommit policy,
internal<container, single-model output consistency, determinism,
invalid/negative/overflow/malformed units, missing inputs, cgroup-limited
host, cgroup v1/v2 detection, outage-buffer-growth sizing term, plan
rollback, unit normalization (GB vs GiB vs g). Existing suites (Go backend,
correlation pytest, preflight) run before/after every phase; results reported
with actual commands (rule 9).

---

## 12. Rollout plan

- P1 planner+tests (no runtime change) → P2 install.py integration behind
  `--plan-resources` flag (opt-in first release, default-on the next) →
  P3 compose plumbing for internal limits (defaults preserve today's exact
  values; lab soak ≥48h) → P4 customer-bundle integration (refuse-to-fit UX)
  → P5 alerts + benchmark tooling + docs.
- Canary = the lab host itself, then the VM bundle test (.123).
- Migration: existing customers unaffected until `--replan`; upgrade notes in
  UPGRADE.md; every phase reversible (plan rollback + git revert; P3 env
  defaults equal current constants so unset == today).
- Success criteria: acceptance list in the spec, plus: lab replan reproduces
  ≈ current lab consumption (calibration sanity), zero regression in existing
  suites, refusal messages actionable.

## 13. Known unknowns (measurement required)

- M1: true cause of the CH 4.19 GiB transients (timing-correlated with #101,
  unproven).
- Real bytes/flow-record and bytes/log-event after compression (lab-measurable).
- VM series count & churn at customer scale; CH merge temp-space factor at
  flow-heavy scale; Vector/Kafka behavior under sustained downstream outage
  (B10); Go 1.25 GOMAXPROCS cgroup behavior (P3 verification); CH cgroup
  detection reliability in target environments (why we assert, not assume);
  OpenSearch 2.16 auto-heap behavior vs explicit env (P3 verification against
  OS 2.16 docs).
