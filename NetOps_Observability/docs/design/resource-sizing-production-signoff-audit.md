# Resource Sizing (#102) — Production-Signoff Audit

Date: 2026-07-11 (evening). Read-only Phase-1 validation of the 10 signoff
concerns; every runtime observation below was actually executed against the
live lab stack. Classes: **[FACT]** repo, **[RT]** runtime observation,
**[VENDOR]** vendor behavior, **[INF]** inference.

## Validation matrix

| # | Concern | Classification | Evidence (file / runtime) | Risk | Action |
|---|---|---|---|---|---|
| 1 | KAFKA_HEAP semantics | **confirmed correct** (+1 dead-config nit) | [FACT] compose: `KAFKA_HEAP_OPTS: "-Xmx${KAFKA_HEAP:-512m}…"` on `apache/kafka:4.1.1`; planner emits KAFKA_HEAP=min(6g,50%). [RT] kafka PID-1 cmdline shows `-Xmx555m` = 50% of its plan-bumped 1109m limit — variable provably reaches the JVM broker. **Redpanda does not exist in the deployment** (#97 removal); grep found only comments + one dead fallback `KAFKA_BOOTSTRAP=…"redpanda:9092"` in `src/correlation/main.py:88` (compose always overrides; dead but misleading). | none / cosmetic | Fix dead fallback → `kafka:9092`; no rename (variable correctly named for an actual Apache Kafka JVM) |
| 2 | OpenSearch live JVM | **confirmed correct** (runtime-verified) | [FACT] OS 2.16.0; heap via `OPENSEARCH_JAVA_OPTS: -Xms/-Xmx ${OPENSEARCH_HEAP}` (explicit env overrides 2.x auto-heap — deliberate: plan-owned). [RT] env `-Xms1887m -Xmx1887m`; live `_nodes/jvm heap_max=1979711488` (1.84 GiB); container limit 3957325824 (3.69 GiB) → heap exactly 50%, Xms==Xmx, 1.85 GiB non-heap/page-cache headroom. 50% = vendor-recommended policy (documented as such, not benchmark-derived). | none | none |
| 3 | CH 0.9 ratio | **confirmed correct as policy; provisional as calibration** | [FACT] asserted in `clickhouse/memory.xml` via `from_env=CH_MEM_RATIO`; env default 0.9. [RT] `system.server_settings` ratio=0.9; `CGroupMemoryTotal`=5.20 GiB == container mem_limit 5584715776 → **applies to cgroup-visible memory, not host** (host=15.6 GiB). Observed graze at prior ceiling (4.52 vs 4.50) with zero query kills → tracked+untracked stayed within container (no OOMKill, restarts=0). Configurable: `CH_MEM_RATIO` is a recognized emergency-override var. | low | Document policy class + override knob (docs); calibration = M1 (§10), open |
| 4 | CH concurrency "50" | **confirmed correct** (not universal) | [FACT] setting = `max_concurrent_queries` (server-wide total, incl. background-profile queries), planner-derived: `max(50, 30+10×concurrent_analytical_queries)` — demo(aq=2)→50, customer example(aq=8)→110; test_06 proves variation. [RT] live value 50. Memory-demand invariant: satisfied by *rejection/spill*, not by concurrency×per-query≤budget — per-query caps (hot_ui 1g/bg 2g) + spill thresholds + the asserted server ceiling mean excess demand fails a query (recoverable) rather than the server. [INF] conservative-provisional coefficient like the rest. | low | Document invariant rationale; no formula change (rule 9) |
| 5 | Container/cgroup OOM detection | **confirmed defect (gap)** | [FACT] `ContainerOOMKilled` rule exists (`rules.yaml`) but its source (cadvisor `container_oom_events_total`) is dark under docker's containerd image store — a container OOM-kill today triggers NEITHER `CHMemoryLimitExceeded` (app-level) NOR `HostOOMKillerFired` (host may not OOM). Docker-only deployment (no K8s). Available signal without cadvisor: `docker inspect .State.OOMKilled` + RestartCount — and the external stack-watchdog cron is the established liveness authority. | **medium** | **Fix: extend `scripts/stack-watchdog.sh`** to detect OOMKilled/restart-spikes per container and push ntfy (distinct message class) |
| 6 | PostgreSQL budget | **partially correct → hardened** | [FACT] 256MB/5MB/100 (lab first-apply) = shared_buffers/work_mem/max_connections. Formula: SB=25%, work_mem=(mem−SB)/(3×conns) with conns=50 "realistic concurrent ops" (api pool 25 [config.yaml:16] + correlation + reserve), server max_connections=2×conns. NOT naïve max_conns×work_mem — the ×3 divisor models multiple sort/hash ops per query. [RT] live: SB 274MB, wm 5MB, maint 68MB, ECS 822MB, max_conn 100, parallel workers 8 (stock), autovacuum 3 (stock) — all under the 1097m container. Gap: overrides/legacy pins of PG_* vars can silently break `SB+3×conns×wm ≤ limit`. | low | Add planner warning when pinned PG values violate the budget identity; document assumptions |
| 7 | Host vs cgroup detection | **confirmed correct** (tests extended) | [FACT] `detect_host`: min(MemTotal, finite cgroup) via v2 `memory.max` then v1 `memory.limit_in_bytes`; "max" sentinel ignored; explicit `--memory` override wins (scenario B/C = test 22/23). v1 numeric sentinel (2^63-ish) > MemTotal → min() neutralizes it. Malformed/missing → except-pass → host value. | low | Add tests: v1 numeric sentinel, malformed file, tiny limit |
| 8 | Rollback | **confirmed defect** (live-proven) | [RT] executed A→B→rollback: B correctly REFUSED (custom 15k flows on 16 GiB — refuse-to-fit works through the installer, .env hash unchanged); rollback failed: backup written to `.env.env.plan.bak` (Path(".env").suffix=="" → with_suffix misfire) while `--rollback-plan` reads `.env.plan.bak`. Also resource-plan.{json,txt} not covered by rollback. | **medium** | Fix: single canonical backup path helper in the planner used by both sides; back up + restore plan artifacts; re-run live test |
| 9 | Valkey/Redis naming | **confirmed correct** (doc line added) | [RT] `server_name:valkey` (redis_version 7.2.4 compat string), maxmemory 100663296 (96 MiB) < 128 MiB limit, `noeviction` (durable app state — correct role), RDB save 60/1, no replication. [FACT] service/env named `redis`/`REDIS_MAXMEMORY` = deliberate compatibility naming. | none | Add the compatibility sentence to docs; NO rename |
| 10 | Maturity level | **Level 3 confirmed** | Workload inputs genuinely driving allocations: devices, interfaces, series, flows/s, EPS, users, analytical concurrency, tenants, retention (terms in `workload_terms()`/`storage_estimate()`; goldens differ demo↔flow-heavy). Telemetry = monitoring only + shrink-guard on replan; no recommendations engine → **not** Level 4; no automated resizing → not Level 5. Previous: Level 1. | — | none |

## Runtime checks executed (commands in session transcript)
kafka /proc/1/cmdline; OS `_nodes/jvm` + env + inspect; CH system.server_settings
+ CGroupMemoryTotal + inspect + OOM state; PG pg_settings/SHOW; valkey INFO/CONFIG GET;
rollback A→B→rollback sequence; planner-vs-.env diff.

## Not recommended (explicitly)
- Renaming KAFKA_HEAP (it correctly sizes an actual Apache Kafka JVM).
- Renaming REDIS_MAXMEMORY (stable compatibility name; documented instead).
- Changing the 0.9 ratio or the concurrency formula absent M1/benchmark data
  (rule 9: no changes to working defaults for generic-guidance conformity).
- Adding a cadvisor replacement exporter (watchdog extension is the
  repo-idiomatic container-OOM sentinel until upstream cadvisor supports the
  containerd store).

## Implementation plan (Phase 2)
F1 rollback: canonical `plan_backup_paths()` in planner; install.py uses it for
backup+restore of .env AND resource-plan.{json,txt}; live re-test.
F2 watchdog: per-container OOMKilled/restart-burst detection + ntfy class.
F3 planner: PG budget-identity warning when pins/overrides violate it.
F4 correlation: dead `redpanda:9092` fallback → `kafka:9092`.
F5 docs: Valkey compatibility line; CH ratio policy/override note.
F6 tests: cgroup sentinel/malformed; backup-path helper; PG violation warning.
