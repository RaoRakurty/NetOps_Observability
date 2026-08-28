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

## Standing rules (unchanged)
Fable = architecture/design/research/grading + delegates ALL coding/testing to
Opus subagents. Verify subagent work (read-then-verify, full gate incl. -race/
staticcheck/gosec — gate tools in /home/rao/go/bin, NOT on subagent PATH).
Exceed industry baselines. Three-project priority: 1) Scale (HIGH), 2) Security
CTEM, 3) Troubleshooting. `/code-review ultra` is owner-triggered.
