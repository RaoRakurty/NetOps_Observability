# Run plan — P1 cohort-touch gate, 2.5K A/B (2026-08-28)

Owner-approved in-session ("I would like to finally see the results of 2.5K storm").
Fable wrote this plan; an Opus subagent executes it; Fable grades. Compare against
the OLD leg that already exists in ClickHouse: run **`08281519gjez`** (storm mode,
pre-P1; TTUR baseline in `docs/scale/RCA_LATENCY_BASELINE_2026-08-28.md`).

## Preconditions (Fable, before handing over)
1. P1 diff verified: full `src/correlation` suite green, ruff/bandit/mypy clean,
   hash-function bodies unchanged, tests T1–T10 present.
2. Nothing committed yet (owner verifies before commit); the image is built from
   the working tree — that is intentional for the A/B.

## Steps (Opus)
1. **Idle check.** `curl -s localhost:8000/…` is not needed — read each replica's
   `/metrics` via the harness's `corr_completion_state()` path or `docker exec`:
   `corr_engine_pending` must be ~0 on both replicas and consumer lag < 5000
   (preflight refuses otherwise). If pending is draining, WAIT (self-paced, no
   second harness process).
2. **Residue.** Count devices named `mlx-*` via the API (harness `api()` +
   token login pattern; device list pages cap at 2500 — loop). Delete any
   (`Harness.cleanup()` logic, ~line 2332) and verify 0 remain. Do NOT touch
   non-`mlx-` devices. Do NOT purge OpenSearch/ClickHouse (not needed; the P0
   script scopes by device prefix).
3. **Build + deploy ONLY the correlation service.**
   `cd deployment/docker && docker compose build correlation && docker compose up -d
   --no-deps --scale correlation=2 correlation`. Verify in BOTH replicas:
   `docker exec <c> grep -c ComponentMemo /app/engine.py` ≥ 1 and
   `grep -c CORR_COHORT_TOUCH_GATE /app/main.py` ≥ 1; both healthy; env flags
   unset ⇒ defaults ON (record `docker exec <c> env | grep CORR_`).
4. **Run NEW leg.** `python3 scripts/scale-miniladder.py --profile t-nominal-2.5k
   --devices 2500 --eps 1000 --run-dir /var/tmp/scale-runs/p1-on-$(date -u +%m%d%H%M)`
   as ONE tracked background job; a FAIL line does not mean it exited — wait for
   the process. Expect ~15 min burst + up to 45 min drain/completion budget.
   Never start a second harness concurrently.
5. **Collect.** From the run dir: phase verdicts (preflight/onboard/burst/drain/
   accounting/stability/correlation_completion/memflat/cleanup) + evidence JSON.
   From both replicas' `/metrics` at end: `corr_cohort_components_*`,
   `corr_snapshot_digest*`, `corr_lifecycle_passes_total`,
   `corr_open_objects_epoch_peak`, `corr_versions{outcome=…}`, epoch/cohort
   totals, loop-lag max, restarts (0 required). Then
   `python3 scripts/scale-rca-latency.py --device-prefix mlx-<runid>- --json
   /var/tmp/rca-p1-on.json` and the extended-curve variant.
6. **Report** `docs/scale/P1_2P5K_VERDICT_2026-08-28.md`: OLD (08281519gjez) vs NEW
   table — accounting (must remain lossless N==N, 2500/2500), restarts, worst
   stall, completion (pending curve, completed_at or INCOMPLETE), cohorts/sec,
   versions persisted/damped, touch ratio, memo-hit ratio, digest cached ratio,
   TTUR T1/T2/T3/T4/T6 p50/p95, churn, versions→material-change ratio. State
   every caveat (loaded box, run-to-run variance seen between 082812437a77 and
   08281519gjez). No magnitude claims beyond what was measured.
7. Optional if time and owner asks: OFF leg (`CORR_COHORT_TOUCH_GATE=0
   CORR_LIFECYCLE_EPOCH_CADENCE=0` in the compose env, redeploy, rerun) for a
   same-image, same-night control.

## Hard rules
No commits. No deletes outside `mlx-*` devices. No changes to engine/harness
during the run. If the run fails mid-way, run cleanup, record the failure, stop.
