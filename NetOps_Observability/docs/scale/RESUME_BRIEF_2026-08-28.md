# Resume brief — correlation scale/optimization work (2026-08-28)

Paste-in state so a fresh session continues exactly here. Authority order:
`docs/TRACKER.md` + `docs/audit/INVARIANTS.md`, then this brief, then the dated
design/verdict docs referenced below.

## Where we are (one paragraph)
The correlation engine's storm **collapse is FIXED** and it survives 2.5K devices
losslessly, but it can't **complete** correlation in budget on one 4-core shard.
All 6 market-benchmark P0s are implemented + deployed. A deep-research synthesis
concluded the next move is a **control/data-plane split** (fast verdict / async
evidence graph), with a cheap **cohort-touch gate** as the highest-ROI first step.
The immediate open question the owner was about to answer: *spec P1 (the
cohort-touch gate) as an implementation-ready design?*

## Done + committed this session (newest first)
- `c75a1cee` docs: **storm-plane separation research synthesis** (the plan below).
  Artifact: https://claude.ai/code/artifact/f720c036-b86e-417d-bf91-62d0866e8c9a
- `b2a3e156` docs: storm-mode 2.5K verdict — completion is scale-out-bound.
- `51575407` feat: **storm mode** (last benchmark P0) — DEPLOYED. Deterministic,
  gated, replay-safe. BUT barely fires at 2.5K (detector watches the SIGNAL queue;
  the bottleneck is the OBJECT-reconciliation queue) — does NOT fix completion.
- `fa4857a5` feat: **P0 boundedness pass** — DEPLOYED. Paged child-row emit.
  Collapse fixed: worst loop stall **108s→10.7s, 0 restarts**, lossless.
- `e520a0b7` feat: protocoldiag HTTP API (Project 3) — committed, gate-clean,
  **NOT deployed**. `dee57f18` security findings store decision (Project 2, OpenSearch).
  `05f82ceb` IRIS roadmap. Topology frontend fix `e2625421` **NOT deployed**.
- Verdict docs: `docs/scale/SCALE_2P5K_POSTFIX_VERDICT_2026-08-28.md`,
  `STORM_MODE_2P5K_VERDICT_2026-08-28.md`, `ENGINE_DECISION_2026-08-28.md`,
  `docs/design/CORRELATION_STORM_MODE_DESIGN_2026-08-28.md`,
  `docs/design/STORM_PLANE_SEPARATION_RESEARCH_2026-08-28.md`.
- Scale-findings artifact (honest end-state): https://claude.ai/code/artifact/9ed6863e-6c93-4a7d-8574-37c117a05757

## Empirical state (2.5K, 2500 devices @ ~1000 eps, 2 replicas)
- PASS: preflight, onboard, burst, drain (transport), **accounting (lossless
  900,001==900,001, 2500/2500)**, **stability (10.7s stall, 0 restarts)**,
  sharding correctness (12 co-partition tests).
- FAIL: **correlation_completion** (~15.6K–24.6K objects pending = single-shard
  reconciliation THROUGHPUT ceiling → scale-out, not tuning); memflat
  (inconclusive: working-set-while-churning vs leak — needs longer-settle
  re-measure); cleanup (non-product OS-purge artifact).
- **time-to-first-useful-RCA: NOT measured** — the metric the whole plane design
  optimizes and the honest reframing of completion. Measure it first.
- **2-worker ≥1.6× scale-out: HARDWARE-BLOCKED** (4 cores total; two workers
  contend). Needs 8 cores / 2 nodes.

## THE PLAN (from the research synthesis — do these in order)
- **P0** Measure **time-to-first-useful-RCA** + causal-amplification ratio (raw
  eps ÷ verdict-changes) on the current engine. Cheap, no new hardware.
- **P1 (START HERE)** **Cohort-touch gate**: skip re-rank/re-hash/re-materialize
  for components not in `_cohort_keys` this cohort (reuse `OPEN_OBJECTS[cid]
  ["snapshot"]`); + memoize the frozen `ObjectSnapshot` (content_hash/
  hypotheses_blob recomputed 2–4× per persist — free win); + hoist the O(open)
  find_merges/quiesce/cap passes to epoch cadence (not per-cohort ×20). Pure
  in-engine, low risk, largest single saving. Determinism: does NOT move
  `content_hash` bytes (skips work on unchanged objects). Opus builds; Fable
  verifies byte-identical against golden-wire/replay/166/162/168.
- **P2** Control/data-plane split: control plane (=FIB) emits verdict from
  cohort-touched components; data plane (=RIB) materializes full evidence graph
  ASYNC as a Kafka-log-derived materialized view, version-keyed deltas,
  replayable. Kappa constraint: ONE computation at two completeness levels, not
  two code paths. Determinism linchpin: convert every wall-clock/arrival-order
  decision into a **content-addressed quantum**.
- **P3** Backplane dedup tier + SRE criticality shedding (storm mode's correct
  home — front tier, not a per-object flag; prefer backpressure to dropping).
- **P4** Re-measure time-to-useful-RCA; then the 8-core/2-node scale-out proof.

## Engine hot spots (code refs for P1)
`src/correlation/main.py`: `_engine_cycle_inner` (~3615), reconciliation
hash/damp (3834-3866), `_persist_snapshot` (3422), `_emit_child_rows` (3373),
drain loop (4031-4044, `CORR_ENGINE_DRAIN_COHORTS=20`), `_cohort_keys` (3663),
merge/quiesce/cap (3889-3930). `src/correlation/engine.py`: `run_window`
component/rank/materialize loop (2603-2760), `content_hash` (1999),
`material_hash` (2014), `hypotheses_blob` (1975+). `scoring.py`: `rank` (489).

## Operational gotchas (READ before running a scale test)
- Deploy actions (`docker compose up -d`) and bulk deletes get **classifier-
  blocked** — need owner approval in-session.
- Harness: `python3 scripts/scale-miniladder.py --profile t-nominal-2.5k
  --devices 2500 --eps 1000 --run-dir <dir>`. Preflight refuses if baseline
  correlation lag > 5000 (needs an idle stack). A harness FAIL LINE in the
  console does NOT mean the process exited — it keeps running; do NOT launch a
  second run concurrently (they collide on the 198.18/15 device space).
- Failed runs leave `mlx-*` device residue that blocks the next onboard. Clear
  via `scratchpad/clear_mlx_residue.py` (API delete; the device-list endpoint
  caps at 2500/page so loop until VERIFY=0). `drain_then_run.sh` self-paces the
  drain+retry as ONE tracked job.
- The box is degraded under load: broker admin API (`kafka-consumer-groups.sh`)
  and `/metrics` refuse/hang; trust the harness's own `settled_group` lag read.
- Harness robustness gap to file: cleanup doesn't run on mid-run failure (leaves
  residue); preflight gives no drain-ETA. Nice-to-have fix.
- Redeploy after any engine change: rebuild `correlation` image + `up -d
  --no-deps --scale correlation=2 correlation`; verify a code marker in BOTH
  replicas (`grep -c` a new symbol in /app/*.py). Current live = fa4857a5+51575407.

## UPDATE (2026-08-28 evening) — P0 measured, P1 built, 2.5K A/B running
- Owner memo `/var/tmp/Correlix-Bottleneck-Modified.md` is now the programme
  authority: planes are **Aggregation / Decision / Evidence** (never "data plane"),
  "priority-aware materialization" (never "shedding"), P0-measure-first order.
- **P0 DONE:** `scripts/scale-rca-latency.py` → `docs/scale/RCA_LATENCY_BASELINE_2026-08-28.md`.
  TTUR on run `08281519gjez` is ~100 % queueing latency (T1 p95 5,135 s; T3−T1 = 0 s),
  churn healthy (max 2), versions→material changes 30.6:1. Tracker 177.
- **P1 BUILT + Fable-verified, NOT committed:** spec `docs/design/COHORT_TOUCH_GATE_P1_2026-08-28.md`
  (§10 = implementation notes). engine.py/main.py + `test_cohort_touch_gate_p1.py`
  (18 tests) + `bench_cohort_touch_gate.py`; `test_loop_blocking.py` hardened; mypy
  narrowing in storm-aggregate block. Suite 1591 green, ruff+mypy clean. Tracker 176.
- **2.5K A/B:** `docs/scale/RUN_PLAN_P1_2P5K_AB_2026-08-28.md` executed by an Opus
  operator (correlation-only rebuild/redeploy, flags default ON) → verdict
  `docs/scale/P1_2P5K_VERDICT_2026-08-28.md`. Compare to OLD leg `08281519gjez`.
- New gap: replay `_diff` ignores edge direction (tracker 178).
- **OWNER DECISION (2026-08-28): no more hardware.** Success = engine efficiency +
  TTUR SLOs on the existing 4-core box. The 8-core/2-node scale-out proof (P4/P5
  in the plans above and in the research synthesis) is DROPPED — do not propose it.
- Next after the verdict: owner verifies → commit P1 → P2 Decision/Evidence split
  spec (versioned RCA Verdict Record; ONE computation, two completeness levels).

## Standing rules (unchanged)
Fable = architecture/design/research/grading + delegates ALL coding/testing to
Opus subagents. Verify subagent work (read-then-verify, full gate incl. -race/
staticcheck/gosec — gate tools in /home/rao/go/bin, NOT on subagent PATH).
Exceed industry baselines. Three-project priority: 1) Scale (HIGH), 2) Security
CTEM, 3) Troubleshooting. `/code-review ultra` is owner-triggered.

## UPDATE (2026-08-28 late) — P1 verdict in, P2 spec'd, harness hardened
- **P1 A/B leg `p1-on-08281911` was signal-interrupted after `drain`** (no gate
  verdict, 2,500 `mlx-08281911zaz6-*` devices left). Engine still converged on
  its own (pending 0 ≈21:15, closes until 21:27). Verdict reconstructed from
  `corr_objects` with the clean-scope SQL (per-incident `min(window_start)` in
  the leg's burst window, **storm-aggregate cid `bb1e46d6…` excluded — it is
  tenant-constant and shared by both legs**): `docs/scale/P1_2P5K_VERDICT_2026-08-28.md`
  + `P1_2P5K_EQUIVALENCE_2026-08-28.md`. Result: versions −30 %, T1 p99 −32 %,
  T6 p95 −29 %, churn preserved, equivalence 100 % on owner/tier/confidence;
  merges 11→378 all predicate-valid. Completion still ~106 min (budget 45).
  Residue: undetermined +112 unexplained; storm-mode activation 100 % vs 93.5 %.
- **P2 spec: `docs/design/DECISION_EVIDENCE_SPLIT_P2_2026-08-28.md`** (tracker 179).
  Key measured lead: in the 65-min load epoch 61 % of component evaluations were
  untouched first-sight components ranked anyway (memo is intra-epoch) →
  cross-epoch content-addressed decision memo + epoch wall-time budget are steps
  1–2; VVR table, async Evidence queue, priority ordering are 3–5. `rank()` takes
  no clock, so the cross-epoch key is sound.
- **Tracker 178 shipped** (`replay.EDGE_COMPARISON_SCHEMA=2`, direction drift
  compared; `test_replay_direction_178.py`). Row deleted.
- **Harness hardened** (`scripts/scale-miniladder.py`): `InterruptGuard`
  (SIGINT/SIGTERM/SIGHUP; signals during cleanup ignored with a message, 3rd
  aborts loudly with `RESIDUE LEFT`), durable `purge_devices` (page-loop +
  re-list until verified zero), `--cleanup-only [mlx-prefix]` (refuses other
  prefixes / unreachable stack, `--dry-run`), preflight drain ETA. Root cause of
  the residue: `except Exception` around cleanup couldn't catch the second
  `KeyboardInterrupt`; SIGHUP unhandled. 31 tests.
- **To do before the next scale run:** `python3 scripts/scale-miniladder.py
  --cleanup-only mlx-` (bulk delete → owner approval in-session), then re-run the
  A/B to the completion gate with `CORR_PROFILE_STAGES=1` on the correlation env.

## UPDATE (2026-08-29 early) — P2 steps 0–2 committed, residue cleared
- P2 steps 0–1 `d78971ef` (caches + epoch budget, bench −35.7 %), step 2 (rank
  memo, bench a further −26 %; offline rank calls −77 %, hit rate 63 %/95.6 % by
  epoch). All byte-neutral, mutant-verified, suite 1828 green. **NOT deployed** —
  live replicas still run the P1-only image from 2026-08-28 19:11.
- Residue: devices 0 (verified), OpenSearch `mlx-` docs 0 (10.2 M purged via
  async task; harness OS purge now async+count-verified `42d04cc0`).
- NEXT (needs owner in-session for the deploy): rebuild `correlation` image →
  `up -d --no-deps --scale correlation=2 correlation` with
  `CORR_PROFILE_STAGES=1` → verify `rank_memo` marker in BOTH replicas → run
  `scale-miniladder.py --profile t-nominal-2.5k --devices 2500 --eps 1000` TO THE
  COMPLETION GATE (do not interrupt; harness now survives SIGHUP) → clean-scope
  TTUR compare vs OLD `08281519gjez` and P1 `p1-on-08281911` (exclude aggregate
  cid `bb1e46d6…`). Then decide step 3 (VVR) / step 4 (Evidence queue).
- `test_loop_yield_resilience::test_reconciliation_loop_yields_under_single_tenant_storm`
  is CPU-contention-flaky when another suite runs on the box (passes 3/3 alone).

## UPDATE (2026-08-29 03:xx) — first P2 live run was HOLLOW; two harness blind spots fixed
- Run `p2-s012-08290116` (P2 steps 0–2 + `compose.profile.yml`) reported
  `correlation_completion PASS in 14 s` — FALSE: with `CORR_PROFILE_STAGES=1`
  every window was rejected (`int('')` on the str field `dea93c20` added to the
  profiler work_sink), all cohorts discarded, 0 objects persisted. Fixed (commit
  after a077ab07): accounting never raises, observability moved out of the
  reject path (counted `corr_engine_profiler_errors_total`), real rejections
  counted `corr_engine_windows_rejected_total` + `corr_signals_dropped_total{reason=window_rejected}`
  with traceback; harness gate FAILs on rejections and on HOLLOW completion
  (cohorts advanced, `corr_versions{persisted}` did not); harness metric parser
  no longer collapses labelled series (it had been reading `damped` as `persisted`).
- Second attempt `p2-s012b-08290322` collided with the host CRON 1K run
  (daily 03:17 UTC `t-nominal`, Sun 04:17 `s1`; `data/miniladder/cron.log`) —
  onboard FAIL (devices absorbed by dedupe). Interrupted cleanly, residue 0.
  Do not start a manual run that overlaps 03:17–~04:30 UTC.
- NEXT: redeploy the fixed image (profiler overlay is safe again) after the cron
  run finishes, then the 2.5K run to the gate.

## UPDATE (2026-08-29 06:00) — P2 steps 0–2 measured live (4th attempt)
Verdict `docs/scale/P2_STEPS012_2P5K_VERDICT_2026-08-29.md`: T1 p95 −38 % vs P1
(2,980 s), incidents +23 %, 0 rejections; completion FAIL (21.6K pending at the
gate, 18.9K signals expired unevaluated); run_window is now 104 s TOTAL — the
persist path is the whole cohort cost (~1,000 s per 5,000-signal cohort);
epoch budget ⇒ 1 cohort/epoch ⇒ merges regressed 378→11. Harness hardening this
night: `c19dcc7d` (profiler-safe accounting, rejection/hollow gate clauses,
label-aware parser), `b29d34ea` (namespace preflight, run lock, shadow purge),
API-retry + measured OS-purge budget (in build). Cron 1K canary DISABLED
(crontab commented; backup in the session scratchpad). Tracker 181 = API
shadow-row defect. NEXT: step 4 (async Evidence queue, verdict row first) + 4a
(lifecycle cadence over last K cohorts) → redeploy → 2.5K run → TTUR re-measure
against 2,980 s.

## UPDATE (2026-08-29 09:00) — P2 step 4 measured live; 3 gauge-found defects in build
`docs/scale/P2_STEP4_2P5K_VERDICT_2026-08-29.md` + `P2_STEP4_EQUIVALENCE_…`: T1 p95
2,401 s (−19 % vs steps 0–2, −58 % vs OLD), completion FAIL but pending 4,055
(from 21.6K), T7 measurable (p95 1,055 s). Defects: Evidence consumer hold leak
(`held` True at idle → consumer ran only when the queue was full), 4a regression
(stale set emptied → merges 0; fix = widen survivors only), rank-memo estimator
1.62× over-charge (fixed `a75b73f8`, 96 MiB ≈ 2.9–5k entries). memflat ×1.45
attribution with the Evidence plane on in progress. NEXT: land the hold/4a/stall
fix → rebuild → redeploy (profiler overlay) → `scale-miniladder.py --profile
t-nominal-2.5k --devices 2500 --eps 1000 --run-dir /var/tmp/scale-runs/p2-s04b-…`
→ clean-scope TTUR vs 2,401 s; then damping.

## UPDATE (2026-08-29 10:30) — FIRST 2.5K COMPLETION PASS
Run `p2-s04b-08290858` (image 7ba42389: generational Evidence hold, 4a fixed,
archive offload): correlation_completion PASS 2,515 s / 2,711, T1 p95 2,208 s
(−57 % vs OLD). Verdict `docs/scale/P2_STEP4B_2P5K_VERDICT_2026-08-29.md`.
NOT clean: accounting FAIL (901 signals silently dropped — corr_signals batch
insert outside the retry contract, fix in build), memflat FAIL on ClickHouse
(part churn from per-version Evidence inserts — batching design in progress),
injector 870k/900k. Committed but NOT deployed: e318ace2 (queue 2000 / 64 MiB,
calibrated estimator). NEXT: land both fixes → redeploy → one run for a clean
all-phase PASS → damping.

## UPDATE (2026-08-29 12:00) — committed, NOT deployed; deploy recipe for the clean-pass run
Committed since the PASS run: `e318ace2` (Evidence queue 2000 / 64 MiB, calibrated
estimator), `c4b11690` (ClickHouse merge/memory budget: server settings need a
**ClickHouse restart**; per-table ALTERs run at **api boot** — rebuild api),
`8e623e38` (harness: producer hardening = the 901-event accounting FAIL was the
harness's own producer; burst shortfall FAILs; ClickHouse memflat clauses;
end_offset all partitions). In build: Evidence write batching + Decision-write
offload (`main.py`/`evidence_plane.py`).
Deploy order for the next run (owner approval in-session): build api +
correlation → `up -d --no-deps api` → restart clickhouse (verify
`system.server_settings` background_pool_size=6, max_server_memory_usage
4,096 MiB, part_log exists) → `up -d --no-deps --force-recreate --scale
correlation=2 correlation` with `compose.profile.yml` → verify 0 rejections
→ `scale-miniladder.py --profile t-nominal-2.5k --devices 2500 --eps 1000
--run-dir /var/tmp/scale-runs/p2-s05-…` → expect ALL phases PASS.

## UPDATE (2026-08-29 13:00) — CLEAN-ish PASS: completion 1,986 s, accounting exact
`docs/scale/P2_STEP5_2P5K_VERDICT_2026-08-29.md`. Deployed: fbb4a740 image
(batching + offload), ClickHouse budget (needed a hotfix 865ef7dd: pool
thresholds — server crash-looped on sanityCheck), harness 8e623e38. T1 p95
1,947 s (−66 % vs OLD); T7−T1 p95 4 s. memflat FAIL = harness bugs (CH clause
query; correlation anchor) — fix in build. P2 is functionally complete. NEXT:
damping → rank-memo compact form → P3.

## UPDATE (2026-08-29 15:00) — post-P2 lever wave deployed; run p2-s06 in flight
Deployed (image 46934f3f + api c703db56): compact rank memo (bd6ff86c, 1.2 KiB/
entry), heartbeat touch-only + 6 h keepalive and ingest prefilter (46934f3f),
corr_objects ZSTD(3) codec (applied; daily-partition migration parked —
corr_edges copy timed out fire-and-forget, fix in build; corr_objects over the
4 GiB gate). Harness: memflat clauses honest (67f359a8), t-storm-2.5k profile
with ground truth (a8bb6077, tracker 183). P3 step 0 showed t-nominal has ~0 %
aggregation opportunity — P3 deferred behind damping/prefilter; size it on
t-storm. Docs/alerts re-derived (616cd7b6). NEXT: verdict for p2-s06 (all
phases expected PASS with honest memflat) → first t-storm-2.5k run (TTUR + T4
scoring contract) → P4 write-up.

## UPDATE (2026-08-29 16:30) — s06 measured; ClickHouse system logs fixed; twin is the fault harness of record
- Run p2-s06: completion PASS 2,439 s, accounting exact; compact memo works
  (66 %/0 evictions); prefilter + heartbeat touch = no live gain on t-nominal;
  TTUR within noise (+8 %, arrival-timing incident count). Verdict pending the
  harness memflat rescore (v2 clause: error_log delta + p99).
- ClickHouse: the 4.4 GiB peak was system.metric_log merging itself (997
  columns, Wide+Horizontal band); `03995ecb` makes all six system logs
  merge-safe via <settings>; ClickHouse restarted (21 s), tables recreated,
  legacy `*_log_0` dropped. `CORR_REPARTITION` default is now `check` (api
  logs one CHECK line per table; corr_objects 50 GiB and corr_signals_archive
  172 GiB uncompressed are over the 4 GiB gate).
- Digital twin (scripts/lab/twin, tracker 152, not running) is the labelled
  fault harness of record; the enterprise-outage chain (link/OSPF/BGP churn/
  STP/MAC-move) is being added there + t-storm ground truth made scorable by
  `twin.py score`.
- Next build of api: pass GIT_SHA=$(git rev-parse HEAD) (watchdog flags it).

## UPDATE (2026-08-29 18:30) — storm profile live; P3 = GO
- `t-storm-2.5k` run `storm-s01-08291633`: completion PASS 2,171 s, accounting
  exact, BUT stability FAIL (115 s loop stall = Evidence batch flush of the storm
  aggregate member, tracker 185 — consumer ejected, 65k evictions) and memflat
  FAIL on 2 ClickHouse refusals (api `WITH picked` query reads 4M rows, fix in
  build). T1 p95 1,376 s; 5,889 incidents; confirmed tier 0 (to read with the
  twin scorer output `twin-score.log`).
- StormShape ladder (`29686b0c`): offline step-0 says aggregation is worth
  0/36/56/74 % of engine signals at 2/10/25/50 % storm share → **P3 GO** (spec
  §6b, tracker 182). Build after 185 lands; A/B on t-storm-10/25.
- Scoring a miniladder run: `ln -s <run-dir> /var/tmp/scale-runs/x-<runid>`
  then `twin.py --run-root /var/tmp/scale-runs score --runid <runid>` (global
  option before the subcommand; takes >10 min at 345 stories — run detached).

## UPDATE (2026-08-29 19:00) — storm stall fixed (not deployed), backfill worker fixed (deployed)
- `675966cd`: offload gates sized by signal count (storm aggregate = 922 nodes /
  0 edges / 95k signals); row-capped Evidence blocks. Residuals (batcher lock,
  GC policy) in build. Correlation NOT yet redeployed with it.
- `0af9c896` (api, DEPLOYED with GIT_SHA): time-intel backfill bounded — it had
  been failing every pass; tracker 186 for the watermark redesign.
- Storm run storm-s01 scored by `twin.py` (result in `twin-score.log`, pending).
- NEXT: residuals land → rebuild/redeploy correlation → clean `t-storm-2.5k`
  (stability + memflat PASS expected) → P3 build (spec §7 steps 1–4) → A/B on
  t-storm-10/25 → P4 write-up.

## UPDATE (2026-08-29 19:35) — residuals landed + deployed; clean storm re-run; P3 build started
- Correlation image = HEAD (675966cd + batcher-lock/GC residuals). Run
  `storm-s02-08291929` (t-storm-2.5k) in flight — expect stability + memflat PASS.
- P3 steps 1–2 (aggregation.py, ingest wiring behind the flag, default OFF)
  in build; steps 3–4 (archive/replay representation, equivalence suite,
  live A/B on t-storm-10/25) follow.
- Twin scorer: unbounded per-story SELECTs (329 in an hour) — being bounded;
  storm-s01 accuracy not yet scored.

## UPDATE (2026-08-29 20:30) — storm re-run 8/9 PASS; P3 steps 1–2 built
- `storm-s02-08291929` (`STORM_S02_2P5K_VERDICT_2026-08-29.md`): completion
  118 s, accounting exact, memflat PASS 9/9, stability FAIL on ONE 35 s stall
  (epoch lifecycle pass: find_merges over the 20-cohort survivor window on the
  loop thread; instrumentation + token index + offload in build). s01's counts
  were inflated by Kafka redelivery after its ejections — s02 is the honest
  storm baseline (2,754 incidents, T1 p95 1,054 s, confirmed 0).
- P3 steps 1–2 built, uncommitted (waiting for the concurrent main.py lifecycle
  fix): `aggregation.py` (AggKey ≡ K3, all memo-§17 classes, lateness rule),
  `agg_admit` wiring behind the default-OFF flag, `--agg-ab` bench: engine
  forwarded == plan K3 exactly at 2/10/25 %. Steps 3–4 next (archive/replay
  fields + equivalence suite + live A/B on t-storm-10/25).
- Twin scorer bounding in build; storm-s01/s02 accuracy not yet scored.

## UPDATE (2026-08-29 21:30) — where to pick up
- P4 draft: `docs/scale/P4_PROGRAMME_WRITEUP_2026-08-29.md` (tables + honest SLO
  statement; §7 lists the two remaining steps).
- Uncommitted in the main tree (two builders): P3 steps 1–2 (`aggregation.py`,
  `test_aggregation_p3.py`, `main.py` ingest wiring, bench `--agg-ab`) and the
  lifecycle-pass instrumentation/bound (main.py/engine.py, tracker 185 part 2).
  Commit both when the lifecycle builder reports, then rebuild/redeploy
  correlation and run `t-storm-2.5k` once more (expect 9/9).
- P3 step 3 (representation + equivalence suite) being prepared in a worktree
  as a patch (`scratchpad/p3_step3.patch`); step 4 = live A/B on
  `t-storm-10-2.5k` / `t-storm-25-2.5k` with `CORR_AGGREGATION_PLANE` OFF vs ON.
- Accuracy scoring: 46 s per run now; storm-s01 93.0 %, storm-s02 93.3 %;
  misses = tracker 187 (blocked on parser gaps 184).

## UPDATE (2026-08-29 22:30) — P3 A/B wave ready
- Committed: `12074157` (P3 steps 1–3 + lifecycle index fix), `d4f6e345` +
  `eeea904e` (compose.agg.yml, run plan with validated TTUR SQL). Correlation
  redeployed at HEAD; `storm-s03-08292148` in flight (expect 9/9 → closes 185).
- Run the wave per `RUN_PLAN_P3_AB_2026-08-29.md` (L1 t-storm-10 OFF, L2
  t-storm-25 OFF, redeploy +compose.agg.yml, L3/L4 ON, L5 t-storm-2.5k ON,
  redeploy back). Driver `scripts/scale-ab-driver.sh` in build (resumable,
  refuses the 03:10–04:40 UTC window). Decision rule in the plan §6.

## UPDATE (2026-08-29 22:50) — A/B wave running unattended
`scripts/scale-ab-driver.py` started (detached; log `/var/tmp/scale-runs/
ab-driver.log`, state `ab-state.json`, resumable with `--from Lx`). It waits for
storm-s03's lock, then runs L1..L5 with the arm switch and restore. Expect the
wave to take ~8–9 h (5 legs × ~1.5 h + redeploys). Read each leg's `ab-leg.json`,
`ttur.tsv`, `accuracy-report.md`, `metrics-final.txt`; fill the comparison table
in `RUN_PLAN_P3_AB_2026-08-29.md` §5 and apply the §6 decision rule; then
update `P4_PROGRAMME_WRITEUP_2026-08-29.md` tables.

## UPDATE (2026-08-29 23:00) — storm-s03 7/9; two fixes queued BEHIND the A/B wave
- `STORM_S03_2P5K_VERDICT_2026-08-29.md`: completion 104 s, merge index fix
  confirmed; remaining: quiesce/reconcile-tail ~26 s stall (tracker 185 part
  3) and one `findings` row lost on a transport error (tracker 188). Both fixes
  are in build; DO NOT deploy them until the A/B wave (L1–L5) has finished —
  both arms must run on the same image (`12074157`).
- After the wave: commit both fixes, rebuild/redeploy correlation, one more
  `t-storm-2.5k` for 9/9, then finalise the P4 tables.
- 22:49 (driver clock): wave RUNNING from L1 after fixing the arm probe
  (`dd051f53`: mTLS :8443, never :8094). Follow `/var/tmp/scale-runs/ab-driver.log`.

## UPDATE 2026-08-30 00:40Z — L1 collected; both engine fixes committed (not deployed)
- L1 `t-storm-10-2.5k` OFF: PASS 9/9, 94,942 engine signals, T1 p95 2,763 s, accuracy 903/1005 — recorded in RUN_PLAN_P3_AB §1. L2 `t-storm-25-2.5k` OFF running since 00:14Z.
- `2852ad6f` = tracker 188 (findings retry-safe) + 185 part 3 (26 s was wall time over ~400 closes, not a block; sync-only spans, per-object yield, 60 s session timeout). Gate 2496/79. **Do not deploy until the wave's restore step has run** — both arms on image `12074157`. Post-wave: rebuild correlation with GIT_SHA, apply the findings ALTER if api is not rebuilt, final `t-storm-2.5k`, fill §5, decide §6.
- `fc0d8b23` driver OSError handlers reviewed; `d759836d` tracker 189 filed.

## UPDATE 2026-08-30 03:20Z — session handoff mid-wave
- L2 (`t-storm-25` OFF) INCOMPLETE — recorded in RUN_PLAN §1 (`81f9e876`). L3 (`t-storm-10` ON, dir `agg-10-on-0830*`) reached pending 0 at ~03:10Z, in stability grace; L4/L5 ON follow, then the driver restores OFF.
- Image parity VERIFIED: single `netops-correlation` image `000e7bc3…` built 21:46Z (before the OFF switch); both arm switches are `up --force-recreate` with no build.
- Fresh-session pickup: `tail -f /var/tmp/scale-runs/ab-driver.log` (grep `VERDICT|=====|arm reads|restore|ABORT`); per leg read `<run-dir>/ab-leg.json` (`ttur.row`, `metrics[*].corr_agg_*`, `phases`) + `twin-score.log` accuracy line; fill RUN_PLAN §1 rows and §5 table; apply §6. Then redeploy `2852ad6f` (rebuild correlation with GIT_SHA), findings ALTER if api not rebuilt, final `t-storm-2.5k`, P4 write-up.

## UPDATE 2026-08-30 03:45Z — HANDOFF: wave paused before L4, relaunch needed
- L3 (`t-storm-10` ON) PASS 9/9: signals 76,680 vs L1 94,942 (−19.2 %), T1 p95 1,985 vs 2,763 s (−28 %), accuracy flat (899 vs 903). Rows L1–L3 in RUN_PLAN_P3_AB §1 (`413c6b44`).
- Driver STOPPED at its stale 03:10–04:40 UTC canary guard (canary is gone from crontab, owner-approved). Stack: idle, arm ON (`CORR_AGGREGATION_PLANE=1` on both replicas, image `000e7bc3…`, residue 0). **Relaunch (owner runs it):**
  `cd NetOps_Observability && setsid nohup python3 scripts/scale-ab-driver.py --from L4 --ignore-cron-window >> /var/tmp/scale-runs/ab-driver.launcher.log 2>&1 < /dev/null &`
  Remaining: L4 `t-storm-25` ON (decides the rule — OFF was INCOMPLETE), L5 `t-storm-2.5k` ON (neutrality guard), then the driver restores OFF.
- Then: fill RUN_PLAN §5 table + apply §6; redeploy `2852ad6f` (rebuild correlation with GIT_SHA), findings ALTER if api not rebuilt; final `t-storm-2.5k` 9/9; finalise P4_PROGRAMME_WRITEUP.

## UPDATE 2026-08-30 07:50Z — PROGRAMME CLOSED
- **Wave done.** All five A/B legs collected and graded; verdict
  `docs/scale/P3_AB_2P5K_VERDICT_2026-08-29.md`: **`CORR_AGGREGATION_PLANE` stays
  OFF by default** (criterion 2 MET with −41 % signals / −28 % T1 p95 at the 10 %
  rung and INCOMPLETE→PASS 192 s at 25 %; criteria 1 and 3 FAIL at the 2 %
  neutrality guard). Driver restored the OFF arm.
- **`2852ad6f` deployed** 06:26Z — image `netops-correlation` `34d113a3a8bb`,
  both replicas `--force-recreate`d fresh, findings dedup-window ALTER applied,
  arm OFF verified on both (`corr_agg_enabled 0`).
- **storm-s04 (`/var/tmp/scale-runs/storm-s04-08300637`, runid `08300637l2bv`):
  PASS 9/9** — the first clean storm sweep. Completion 144 s, drain 1,384 s,
  accounting exact (900,001 == 900,001 + 0 DLQ), memflat 79.5 % of cap ×0.961
  FLAT, stability 0/0/0 restarts, residue 0. TTUR (re-queried same-session with
  s02/s03): **T1 p95 832 s** vs 1,055 / 1,203. Accuracy **326/345 = 94.49 %**
  (best recorded). Verdict `docs/scale/STORM_S04_2P5K_VERDICT_2026-08-30.md`.
- **Tracker 188 CLOSED (row deleted)** — and the fault path was exercised LIVE:
  three `netops.findings` transport failures during the run, all retried under
  the dedup token and RECOVERED on attempt 2, 0 rows lost.
- **Tracker 185 rewritten as a residual** — the ~30 s stall did NOT shrink:
  `corr_sync_stretch_max_ms` **27,844 ms at `reconcile.find_continuation`** =
  92.9 % of the 29,974 ms stall, a genuinely BLOCKED stretch (16 overruns of the
  500 ms budget). `lifecycle.quiesce` is exonerated (26.5 s WALL, 0 overruns).
  It stopped ejecting the consumer only because the same commit widened the
  session timeout 30 s → 60 s. Fix = chunk-and-yield/offload that site.
- **P4 write-up finalised** (`docs/scale/P4_PROGRAMME_WRITEUP_2026-08-29.md`):
  §3 carries s03 + s04 with same-session re-queried p95s, §5 replaces the ladder
  projection with the measured A/B, §7 lists what is actually left, and a new §8
  puts **three SLO options** to the owner (A: completion+lossless as the gate
  with T1 p95 as an indicator — available today; B: per-identity-class relative
  to burst end — needs a classifier on the OFF path; C: A/B with the plane ON at
  storm rungs — needs the matched fresh-container pair first).
- **What's open:** (1) the owner's SLO decision — nothing more to measure;
  (2) optional matched fresh-container P3 pair (the OFF half is storm-s04, so
  only one ON leg is needed, ~1.5 h, owner go-ahead required);
  (3) tracker 185 residual; (4) trackers 186 / 187 / 189, outside P4.
- **Stack state:** idle, arm OFF, image `34d113a3a8bb`, residue 0, run lock free.

## UPDATE 2026-08-30 16:18Z — SLO Option A ratified
- **Decision (owner, in session):** storm-time SLO = **Option A** of
  `P4_PROGRAMME_WRITEUP_2026-08-29.md` §8 — completion within 45 min of burst end,
  lossless (0 DLQ), within memory caps, accuracy ≥ 93 %; T1 p95 published as a
  tracked indicator, NOT a gate. **B not pursued** (its class classifier exists
  only inside the aggregation plane; it becomes a refinement of C if C lands).
  **C stays a candidate**, contingent on the matched fresh-container OFF/ON
  `t-storm-2.5k` pair — **not yet approved to run**.
- **P4 measurement side is CLOSED.** Nothing left to measure; what remains is
  execution.
- **Pickup order:** (1) matched pair — ONLY on owner approval (needs two
  force-recreate arm switches; storm-s04 is the OFF half, so one ON leg);
  (2) tracker 185 residual fix, then ONE confirming `t-storm-2.5k` after the pair;
  (3) tracker 190 — raise/re-derive the harness stability gate, stale at
  30,000 ms against the now-60 s session timeout (s04 PASSed by 26 ms).

## UPDATE 2026-08-30 18:30Z — matched OFF/ON pair RUN and GRADED; the accuracy metric is the defect
- **The pair ran** (owner-approved, `RUN_PLAN_P3_PAIR_2026-08-30.md`). Both legs on
  the live image `34d113a3a8bb` / `2852ad6f`, one session, fresh containers per
  leg (counters LEG-SCOPED, no subtraction), arm verified on BOTH replicas at
  every switch. Driver restored the shipping default — **arm OFF, verified
  `corr_agg_enabled 0.0` on both replicas at 18:29:58Z.** Stack idle, residue 0.
  - **P1 OFF** `/var/tmp/scale-runs/pair-2p5k-off-08301624` (`083016240km5`) —
    **6/9**: `memflat` FAIL (corr-3 carrier 1,093 MiB = 85.4 % of cap),
    `stability` FAIL (stall 32,446 ms), `cleanup` FAIL (OS purge stalled, cleared
    to a verified 0 before P2). Completion 223 s, accounting exact. TTUR
    81 / **902** / 1,312 s, tlast95 2,374, inc 1,632, sigs 86,624. Accuracy
    **325/345 = 94.20 %**.
  - **P2 ON** `/var/tmp/scale-runs/pair-2p5k-on-08301732` (`083017321c8x`) —
    **8/9**: `stability` FAIL only; **`memflat` and `cleanup` both FAIL→PASS**
    (corr-4 carrier 1,068 MiB = 83.4 % of cap). Completion 195 s, accounting
    exact. Plane exact: observed 54,767 = forwarded 49,910 + suppressed 4,857
    (**8.87 %**); `contradiction` / `new_vantage` / `new_modality` all **0**.
    TTUR 81 / **830** / 1,295 s, tlast95 2,265, inc 1,532, sigs 76,036. Accuracy
    **319/345 = 92.46 %**.
- **§7 outcome (`docs/scale/P3_PAIR_2P5K_VERDICT_2026-08-30.md`): criterion 3
  PASSES, criterion 2 already MET, criterion 1 fails on the ACCURACY CLAUSE
  ALONE.** Every TTUR clause passed against **both** OFF points for the first
  time — T1 p95 **−7.98 %** vs P1 and **−0.24 %** vs storm-s04, p50 0.00 %,
  p99 −1.30 %, tlast95 −4.59 % — and the OFF-vs-OFF spread tightened
  **13.11 % → 8.07 %**. Accuracy −1.74 pp vs a −1.00 pp floor. Per §7's
  disposition the **plane stays OFF by default**.
- **THE FINDING: the 6-story gap is a twin-scorer defect, proven 60/60, not the
  plane.** `scorer.py:664` decides `affected_includes` against ONE object
  (`max` over tied-tier objects → the **lowest correlation UUID**, list sorted at
  `:432`). All 65 FAILs across the three legs are that one clause missing exactly
  `{cause_entity.device}`. The engine names the cause in **105 of 105** tied
  stories on all three legs; under the union reading **every leg scores
  345/345**. Instrument noise: expected 93.04 %, 1σ 0.71 pp — **wider than the
  rule's ±1 pp floor and centred on the ratified SLO's 93 % clause.** Filed
  **tracker 191**.
- **Tracker 187's premise is falsified** by the same measurement (it says the
  engine omits the cause; it does not) and its evidence came from this scorer.
  Re-derive it after 191. 187 is High and blocked on 184 on that premise.
- **Pickup order (revised):**
  1. **Tracker 191** — the scorer fix (union over the already-fetched `objects`
     + a deterministic tie-break + a unit test), then **re-score P1 / P2 / s04
     from the still-resident `corr_objects`** (~45 s each, NO rig time) and
     re-apply §7 criterion 1. If it confirms the counterfactual, criteria 1+2+3
     all hold and the rule's own text says default ON — take that decision on the
     re-scored numbers, never on the counterfactual.
  2. **Do NOT buy more legs for the accuracy question.** ≈3 legs/arm to resolve
     the 6-story gap, ≈92 legs/arm to establish equivalence within the 0.29 pp
     OFF-vs-OFF spread. The one-line fix answers it exactly.
  3. Tracker 185 residual (`reconcile.find_continuation`) — **note an
     uncommitted, unbuilt, undeployed WIP for it sits in the working tree**
     (`src/correlation/engine.py`, +147/−17: `SeamView.membership_values`,
     `ObjectSnapshot.identity_refs`). It was NOT in either leg's image.
  4. Tracker 190 — the stale 30,000 ms stability gate. All three legs recorded
     **0 CommitFailed / 0 UnknownMember / 0 restarts / 0 rebalances**; the only
     discriminator was 32,446 / 30,468 / 29,974 ms against 30,000. The gate
     produced two FAILs and one PASS-by-26-ms out of three identically clean runs.
  5. Then tracker 187 (re-derived), 186, 189.
- **Unmeasured, and stated:** the plane's `contradiction` / `new_vantage` /
  `new_modality` classes have never fired — the harness stamps `observer_id` from
  the event's own device (`main.py:8814`) and `entity_id` is that device or its
  child, so every `AggKey` has exactly one possible observer and one modality.
  Exercising them needs a workload with a second independent vantage per entity
  (harness work, adjacent to tracker 183).

## UPDATE 2026-08-30 21:40Z — FINAL. PROGRAMME CLOSED; the plane ships ON

**This is the last update to this brief.** The P4 storm-time optimisation
programme is closed on both sides — nothing left to measure, nothing left to
execute. Close-out: `docs/scale/STORM_S05_S06_CLOSEOUT_2026-08-30.md`.

**What closed it, in order:**
1. **Tracker 185 CLOSED** (`0bfdce1c`) — `reconcile.find_continuation`'s seam
   bridge rescanned the whole probe per candidate; now cached + per-inventory,
   Jaccard without a union set. Fixture **13,787 ms → 46.8 ms (294×)**; live
   `corr_sync_stretch_max_ms` **443.5 ms** (s05) / **401.1 ms** (s06) with **0**
   overruns and the worst site moved to `lifecycle.merge_index`. Worst in-window
   loop stall 29,974 ms (s04) → **4,122 / 4,450 ms**.
2. **Tracker 191 CLOSED** (`06450430`) — scorer v2 (`affected_includes` over the
   union of touching objects; deterministic `_best_object`). Confirmed on LIVE
   runs: s05 and s06 both `scorer_version: 2`, both **345/345 = 100.00 %**, zero
   template FAILs.
3. **§7 re-graded on v2** (`P3_PAIR_2P5K_VERDICT_2026-08-30.md` §8) — criterion 1
   now **PASS** (TTUR all within ±10 %, accuracy Δ **0.00 pp**), criterion 2 MET
   (−41.0 % signals at the 10 % rung, re-scored accuracy Δ −0.20 pp), criterion 3
   PASS. The rule's own text: default ON.
4. **Flip executed and committed** — `a9d9a10c`, deployed **20:31Z**.
5. **`storm-s05` (OFF control) and `storm-s06` (ON, shipped default) both
   `t-storm-2.5k` PASS 9/9.**

**Deployed state (as of this update):**
- Image `netops-correlation` **`c3f627581082`**, code **`0bfdce1c`**.
- `CORR_AGGREGATION_PLANE` **ON by default** via
  `deployment/docker/docker-compose.yml:1201`
  (`${CORR_AGGREGATION_PLANE:-1}`). **Image default stays OFF**
  (`src/correlation/main.py`) so the A/B overlay contract holds; fallback is
  `CORR_AGGREGATION_PLANE=0` in `deployment/docker/.env`.
- Both replicas verified: env `=1`, `corr_agg_enabled 1`.
- Committed as `a9d9a10c`.
- Stack idle, residue 0, run lock free.

**s05 vs s06 headline** (full table in the close-out doc): completion 95 → 124 s;
T1 p95 866 → **816 s** (−5.8 %); T-last p95 2,196 → **2,001 s** (−8.9 %); engine
`sigs` 85,837 → **82,359** (−4.05 %); accuracy 345/345 both; memflat 83.2 % →
**82.7 %** of cap, FLAT both; accounting exact both; 0/0/0/0 on stability both.
Plane on s06: observed **54,767** = forwarded **49,913** + suppressed **4,854**
(**8.86 %**), keys 32,243 / identities 27,280, zero capacity evictions, zero
`beyond_lateness`. The prefilter stream is digit-identical across the two legs.

**Open items — the whole list, in pickup order:**
1. **187** (Med) — cause device dropped from `affected` when the object CLOSES.
   3–5 `bgp_peer_flap` stories per 1,005-story leg, same story ids on both arms.
   **The honest remaining accuracy defect**; scorer v2's union is over objects,
   not versions, so it does not catch it. Decide whether a final `affected` may
   shrink below its own history; if not, fix the close path.
2. **190** (Low, was Med) — harness `stability` gate still hard-coded 30,000 ms
   against a live 60 s session timeout. With worst in-window stalls now ~4 s it
   no longer bites; still wrong, still worth re-deriving from the live value.
3. **192** (Med, NEW) — un-instrumented ~9–14 s loop block on the cleanup/re-key
   path. `corr_loop_lag_max_ms` **9,134.9 ms** (s05, block located at 20:11:54Z
   during cleanup) / **13,881.1 ms** (s06), both OUTSIDE the stability window,
   no `sync_span` site attributed. Needs a `sync_span` + a bound in the
   `0bfdce1c` style.
4. **189** (Med) — retry contract for six more correlation-written tables.
5. **186** (High) — time-intelligence backfill `created_at` watermark (97 % of
   objects never get a snapshot).
6. **193** (Low, NEW) — no `.dockerignore` at the repo root; eight services build
   with `context: ../..` over a 16 GB tree. Benign today (narrow `COPY`s):
   wasted transfer, cache-busting, latent leak risk.

**Unmeasured, and stated:** the plane's `contradiction` / `new_vantage` /
`new_modality` classes have never fired on any leg — the harness gives every
entity one observer and one modality. The shipped ON configuration's behaviour
under multi-vantage telemetry is unmeasured (harness work, adjacent to 183).
Also unchanged: the harness's `producer_key=tenant` single-key partitioning
means every storm leg measures ONE replica's behaviour.
