# Release qualification — rerunning CORRELIX REFERENCE CAPACITY V1

**One command reruns the V1 qualification on a candidate build and grades every
clause with a single three-valued verdict.** The profile it grades against is
frozen: [`docs/scale/CORRELIX_REFERENCE_CAPACITY_V1.md`](../scale/CORRELIX_REFERENCE_CAPACITY_V1.md).
The baseline it diffs against is the leg of record, `storm-s11`, extracted into
[`docs/scale/baselines/storm-s11.v1.json`](../scale/baselines/storm-s11.v1.json).

Tool: `scripts/release-qualify.py` (tracker 203).

---

## The command

```bash
cd NetOps_Observability
python3 scripts/release-qualify.py
```

It prints one line last:

```
QUALIFICATION PASS|FAIL|INVALID run <runid> candidate <corr-image>/<api-image> baseline storm-s11
```

and exits **0 = PASS**, **1 = FAIL**, **2 = INVALID / environment refusal /
usage error**.

Useful variants:

```bash
# See exactly what would run, plus the live environment reading. Touches nothing.
python3 scripts/release-qualify.py --dry-run

# Re-grade a leg that already finished (no leg is run, no stack is touched
# beyond a read-only candidate capture).
python3 scripts/release-qualify.py --skip-leg /var/tmp/scale-runs/storm-s12-XXXXXXXX

# Regenerate the machine-readable baseline from a finished run dir.
python3 scripts/release-qualify.py --extract-baseline /var/tmp/scale-runs/storm-s11-09012138
```

Flags: `--run-dir` (default `/var/tmp/scale-runs/qualify-<UTC stamp>`),
`--baseline PATH`, `--max-load1` (default 6.0), `--allow-unquiet`, `--dry-run`,
`--extract-baseline RUN_DIR`, `--skip-leg RUN_DIR`, `--project`, `--env-file`,
`--tenant`.

There is deliberately **no workload/seed/gate/cap/scorer flag**. See
[A semantic change needs a V2 profile](#a-semantic-change-needs-a-v2-profile).

---

## Prerequisites

| requirement | why | where it is checked |
|---|---|---|
| **≥ 10 GiB free** on the root filesystem AND on the docker data root | V1 §8(e). `storm-s10` started at 10.8 GiB, crossed OpenSearch's flood-stage watermark mid-burst and the router's OS sink discarded 291,296 syslog evidence docs (tracker 209/210) | `environment` stage, and again in the harness's own preflight |
| **Quiet host**: load1 ≤ `--max-load1` (6.0), no concurrent CI suites or builds | V1 §8(e). `storm-s11` launched at 2.9; `storm-s10` ran at 16–38 and was excluded from qualification | same |
| **The candidate build is deployed** (`docker compose up -d` with the images under test) | the qualification grades what is RUNNING, not what is committed. The `candidate` stage records both, including whether the tree is dirty | `candidate` stage |
| **Exactly 2 correlation replicas** (`--scale correlation=2`) | V1 §2: one carrier + one idle under the single-tenant workload | `candidate` stage (INVALID otherwise) |
| **Aggregation plane ON** | V1 §7 qualifies the plane at the ~2 % storm share. It is ON by default in the shipped compose (`${CORR_AGGREGATION_PLANE:-1}`); `CORR_AGGREGATION_PLANE=0` in `.env` turns it off | `candidate` stage records the resolved arm |
| **Clean `mlx-` namespace, idle bus** | a leftover fleet makes the API's dedupe absorb this run's creates | harness `preflight` phase |
| ~1 hour of exclusive rig time | the leg is 15 min of burst plus drain, completion, memflat settle and cleanup | — |

---

## What each stage grades

| stage | V1 clause | what makes it PASS |
|---|---|---|
| `environment` | §8(e) | ≥ 10 GiB free on every relevant filesystem, load1 within bound. **Refuses before anything else runs.** |
| `pins` | §3 | `tests/test_storm_scenario_profile.py` + `tests/test_workload_profiles.py` green — the scenario digest and the profile-registry digest have not moved. A red pin stops the run **before** the hour-long leg: a moved scenario re-bases every recorded number. |
| `candidate` | — | the deployed build is captured: each correlation replica's image id + `started_at`, the api image id + OCI revision + build time, `git rev-parse HEAD` + dirty flag, the resolved `CORR_AGGREGATION_PLANE`. Also takes the **PRE-run `/metrics` scrape** so §7 can be asserted on a delta. Written to `candidate.json`. |
| `leg` | §8(a) | `scale-miniladder.py --profile t-storm-2.5k --devices 2500 --eps 1000` runs and **all nine harness gates PASS** (preflight, onboard, burst, drain, correlation_completion, accounting, memflat, stability, cleanup). Those nine carry the SLO's completion, losslessness, memory and replica-stability clauses. |
| `accuracy` | §4 + §5 | the twin scorer reports `scorer_version: 2` and accuracy ≥ **0.93**. A number from any other scorer is not a V1 accuracy number. |
| `aggregation` | §7 | per replica **and** summed: Δobserved == Σ Δforwarded{class} + Δsuppressed, **exactly**. |
| `ttur` | §8(b) | the clean-scope SQL runs and a row comes back. **T1 p50/p95/p99 are PUBLISHED, NEVER GATED** (§4). T1 = *time to first correlated version*, an engineering lifecycle metric — it is **not** TTUR proper (tracker 205). |
| `rebalance` | §8(d) | **SKIPPED today.** The 155/199 disturbance clauses are a separate arc (`docs/scale/OWNERSHIP_155_VALIDATION_2026-08-31.md`) and `scripts/lab/twin/ownership_runner.py` has no CLI. §8(d) itself requires only "no unexpected replica ejection or restart", which the harness `stability` gate already grades and which the `leg` stage carries. |
| `baseline` | — | every gated clause that PASSes on `storm-s11` also PASSes on the candidate. Informational numbers are printed, never gated. |
| `verdict` | — | overall PASS only if **every non-SKIPPED stage is PASS**. |

### The three-valued verdict

| value | meaning |
|---|---|
| **PASS** | the clause was measured and met. |
| **FAIL** | the clause was measured and missed. Overall FAIL, exit 1. |
| **SKIPPED** | the clause was **not measured**, with the reason recorded. It never fails the run and it never counts as evidence. This is the honest third value that keeps "we did not measure it" distinct from "it passed". |
| **INVALID** | the measurement itself cannot be trusted — an unquiet host, a replica that restarted mid-run so its counter delta is not a delta, a missing harness phase. Overall INVALID, exit 2: never a PASS, never a FAIL. |

`--allow-unquiet` downgrades the §8(e) refusal to a recorded **WARN** and sets
`qualification_grade: false` in `qualification.json`. Use it for exploratory
re-grades; **a result with `qualification_grade: false` is not V1 qualification
evidence** and must not be quoted as one.

### Informational, never gated

`qualification.md` carries a table of engine completion seconds, T1
p50/p95/p99, per-container memory ratio and % of cap, accuracy, suppressed
share and `corr_signals` rows, against the same numbers from `storm-s11`. A
regression ≥ 10 % is flagged `REGRESSION (informational)` — **reported, not
gated**. V1 says so explicitly for T1 p95; completion and memory follow the same
rule because the actual gates are the harness's own clauses, already graded in
`leg`.

---

## Where the artifacts land

Everything goes into `--run-dir` (default `/var/tmp/scale-runs/qualify-<stamp>`):

| file | what it is |
|---|---|
| `qualification.json` | the machine-readable record: verdict, `qualification_grade`, candidate identity, and every stage as `{stage, status, evidence, at}` |
| `qualification.md` | the human report: stage table, informational-delta table, the published T1 line |
| `candidate.json` | the deployed build's identity + the PRE-run counter capture |
| `leg.log` | the harness's streamed output |

The leg's own artifacts stay in the leg's run dir (which is the qualification
run dir on a full run): `report.{json,md}`, `accuracy-report.{json,md}`,
`twin-score.log`, `metrics-final.txt`, `ttur.tsv`, `ttur-scope.json`,
`ground-truth.json`, `lag-curve.json`, `correlation-completion.json`,
`burst-chunks.json` (V1 §9).

---

## Re-grading a finished leg

```bash
python3 scripts/release-qualify.py \
  --skip-leg /var/tmp/scale-runs/storm-s12-XXXXXXXX \
  --run-dir  /var/tmp/scale-runs/qualify-regrade
```

This grades an existing run dir without running anything. Two honest
consequences, both stated in the record:

- **`aggregation` reports SKIPPED (no pre-run capture).** The plane's counters
  are cumulative since container start; without a PRE-run scrape there is no
  per-leg delta. The baseline's cumulative numbers are shown for display only
  and grade nothing. (This is exactly the caveat `storm-s11` had to carry; a
  full run removes it by capturing the pre-run counters itself.)
- **`accuracy` and `ttur` reuse the leg's own artifacts** rather than
  re-scoring or re-querying. The leg's cleanup phase purged its ClickHouse
  corpus, so a fresh scorer pass or T1 query would measure an empty store, not
  the leg.

Re-grading `storm-s11` this way reproduces its scorecard exactly: 9/9 harness
gates, 345/345 on scorer v2, T1 p50 80 s / p95 876 s / p99 1,363 s.

---

## Regenerating the baseline

```bash
python3 scripts/release-qualify.py --extract-baseline /var/tmp/scale-runs/storm-s11-09012138
```

`docs/scale/baselines/storm-s11.v1.json` is **generated, never hand-typed** —
every number in it is read out of the leg's own `report.json`,
`accuracy-report.json`, `metrics-final.txt` and `ttur.tsv`, so it cannot drift
from the run it claims to describe. The extractor is re-runnable and
byte-stable (sorted keys, fixed indent).

Two things it says out loud rather than smoothing over:

- `aggregation.scope: "cumulative_s10_s11"` — s11's correlation containers were
  not recreated between `storm-s10` and `storm-s11`, so those `*_total` values
  span both legs. `per_leg_observed_expected: 54767` records the deterministic
  per-leg count from V1 §7 beside them.
- `images.api.image: null` — no harness records the api container id in the run
  dir, so a historical leg's api image is not recoverable from it (V1 §9 quotes
  it from the deploy record). A qualification run records its own candidate's
  api image in `candidate.json`.

**Designating a new baseline is a decision, not a side effect.** Extract to a
new file (`storm-sNN.v1.json`) and point `--baseline` at it; do not overwrite
`storm-s11.v1.json` unless the owner has re-designated the leg of record.

---

## A semantic change needs a V2 profile

V1's versioning rule (owner, 2026-09-01, binding): any **semantic** change — a
different workload shape, seed, digest, device count, rate, cap, gate clause,
scorer semantics, SLO wording or aggregation-plane configuration — requires a
**new versioned profile** (`CORRELIX_REFERENCE_CAPACITY_V2.md`), never a silent
modification of V1.

That is why `release-qualify.py` launches the leg with the profile and nothing
else: **the harness defaults ARE the V1 gates.** Adding a tuning flag would
silently re-base the qualification, and the resulting number would not be
comparable to the baseline it is printed beside. If you need different
semantics, write V2, extract a V2 baseline from a V2 leg, and grade against
those.

The one thing that is *not* a semantic change: the harness's preflight
disk-headroom + host-quiet gate (tracker 210, `--min-free-gib` / `--max-load1` /
`--allow-unquiet`). It refuses **before** a leg starts and grades nothing, so
any leg that runs is evaluated exactly as it was before.

---

## Related

- `docs/scale/CORRELIX_REFERENCE_CAPACITY_V1.md` — the frozen profile (the authority)
- `docs/scale/GA_GATE_TESTS.md` — where this lane sits among the gates
- `docs/scale/OWNERSHIP_155_VALIDATION_2026-08-31.md` — the rebalance arc this tool skips
- `docs/scale/PROJECT1_DONE_2026-09-01.md` — how `storm-s09`/`storm-s11` were graded by hand
