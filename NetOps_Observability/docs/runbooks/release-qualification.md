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
python3 scripts/release-qualify.py     # or: make release-qualify
```

It prints one line last:

```
QUALIFICATION PASS|FAIL|INVALID run <runid> candidate <corr-image>/<api-image> baseline storm-s11
```

and exits **0 = PASS**, **1 = FAIL**, **2 = INVALID / environment refusal /
usage error**.

Useful variants:

```bash
# Prove the SUITE's own logic — no stack, no rig, no .env. This is what CI runs.
python3 scripts/release-qualify.py --self-test

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
`--self-test`, `--extract-baseline RUN_DIR`, `--skip-leg RUN_DIR`, `--project`,
`--env-file`, `--tenant`.

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
| `qualification.md` | the human report: dated header, stage table, **the gated-clause table against the V1 reference** (clause · V1 reference · this candidate · REGRESSION), informational-delta table, the published T1 line |
| `candidate.json` | the deployed build's identity + the PRE-run counter capture |
| `leg.log` | the harness's streamed output |

The leg's own artifacts stay in the leg's run dir (which is the qualification
run dir on a full run): `report.{json,md}`, `accuracy-report.{json,md}`,
`twin-score.log`, `metrics-final.txt`, `ttur.tsv`, `ttur-scope.json`,
`ground-truth.json`, `lag-curve.json`, `correlation-completion.json`,
`burst-chunks.json` (V1 §9).

---

## Proving the suite without the rig — `--self-test`

A qualification leg costs an hour of exclusive, owner-gated rig time. Between
legs there is nothing to tell a change that broke *this grader* from one that
did not — so the suite proves itself instead:

```bash
python3 scripts/release-qualify.py --self-test     # seconds, exit 0 / 1 / 2
make release-qualify-selftest                      # the same thing, discoverable
```

It re-grades the **checked-in `storm-s11` leg fixture** (`tests/fixtures/storm-s11/`
— the same leg the shipped baseline was extracted from) through the real stage
methods, and then re-grades **mutated copies** of it, asserting both directions:

| direction | what is asserted |
|---|---|
| the leg of record grades right | the shipped `storm-s11.v1.json` is byte-identical to a fresh extraction of the fixture (the baseline is generated, never hand-typed); 9/9 harness gates PASS; 345/345 on scorer v2; `aggregation` and `rebalance` report **SKIPPED with a reason**; T1 is published, not gated; no gated regression; verdict PASS; a dated `qualification.{json,md}` is written with the gated-clause table |
| every mutation is CAUGHT | a regressed harness gate fails the leg *and* the baseline diff *and* the verdict · accuracy below 0.93 FAILs · a perfect score on **scorer v1** still FAILs · a missing accuracy FAILs (never a silent zero) · aggregation that does not close FAILs · a replica that restarted mid-run is **INVALID**, not a false PASS · too little disk / an unquiet host / an unreadable filesystem all refuse · `SKIPPED` never fails and never counts · one FAIL fails · `INVALID` beats FAIL · an all-SKIPPED run is INVALID · the leg is launched with the frozen V1 parameters and nothing else |

Properties that make it CI-safe: it touches no stack, needs no `.env` (which is
generated at install and gitignored), issues no docker command beyond the
stubbed `inspect` the baseline extractor asks for — any other command is a
self-test **failure**, not a fallback — and writes only into a temporary
directory it removes.

**It is not qualification evidence.** It measures a fixture, not a build, and
prints no qualification verdict. Only a real leg on a quiet rig qualifies a
build.

CI runs it as part of `pytest tests/` (`tests/test_release_qualify.py`), which
also asserts the self-test is **not vacuous**: with a deliberately broken
grader wired in, the self-test must fail.

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

## Harness clause changes since the `storm-s11` baseline

A rerun compares a candidate against a leg graded by an earlier harness, so any
change to a harness *gate* is recorded here rather than discovered in a diff.

| date | clause | change | effect on the baseline |
|---|---|---|---|
| 2026-09-06 (tracker 202) | `onboard` creation-rate verdict | was `last-window rate ≥ 0.6 × FIRST-window rate`; now **an absolute end-rate floor** (`--onboard-end-rate-floor`, default 15/s) **plus a decay reading taken on the run's body** (`--linearity-floor` × the rate over everything *after* the first window). `last_over_first` is still recorded, flagged `last_over_first_is_advisory`, and gates nothing. | **none.** `storm-s11`'s own numbers (first 39.03/s, last 29.14/s, 89.31 s wall) PASS under both clauses, asserted against the checked-in fixture by `tests/test_miniladder_onboard_rate_gate.py`. |

Why that one changed: the last-window rate is a stable property of the device
store (30.5 / 28.6 / 26.1 / 25.2 / 24.8 /s across the five clean legs) while the
first-window rate swings 27.7 → 44.5 /s with api process age and tombstone-store
state, so the ratio graded how fast a run *started*. On `storm-s09` the
tracker-175 compaction improved the start to 44.5/s and the clause FAILED the
leg at 0.56 for exactly that improvement — 2,500/2,500 devices created, 0
failures, 103 s of a 467 s budget. A faster start must never fail a gate. The
purpose of the clause (catching a super-linear O(N²) per-device-persistence
collapse) is kept by two readings a fast start cannot move.

**This is a harness-artifact fix, not a re-basing of a V1 SLO.** V1 §8(a) item 2
("2,500 devices created via the API, identity-verified") is unchanged, no V1
number moves, and the leg of record grades identically. If the owner reads the
harness gate itself as V1-frozen semantics, the V2 route below applies and this
row is the change it would carry.

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
- `docs/RELEASE_CHECKLIST.md` §3.1 — where the release gate calls this runbook
