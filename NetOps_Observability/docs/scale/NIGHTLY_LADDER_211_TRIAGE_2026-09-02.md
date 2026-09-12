# Tracker 211 — `scale-miniladder-nightly` RED: triage record (2026-09-02)

Project 2 phase P0 (`docs/projects/02-GAP-REPORT-2026-09-02.md` §3a). Read-only
diagnosis; evidence from `gh run view --json headSha`, the runs' `report.json`
evidence blocks, and `/var/tmp/scale-runs/storm-s11-09012138/report.json`.

## Verdict: harness-calibration artifact (b) on a stale snapshot, plus drain-in-progress sampling (c). Not a leak.

**1. The nightly was not testing HEAD.** Every run from 2026-08-23 to
2026-09-01 executed commit `f74a0e0c` (2026-08-22 03:20 UTC) because the
remote default branch sat there until the 291-commit push on 2026-09-01
evening — after the last scheduled run fired (07:53 UTC). That snapshot
predates both the 2026-08-29 memflat rework (`67f359a8`: pending-zero anchor,
`CORR_MEM_SETTLE_S`, `_memflat_judge_correlation` — absent from the snapshot's
harness, confirmed by `git show f74a0e0c:…/scale-miniladder.py`) and the
ultra-review fix wave (`7096e207`, evidence-consumer deadlock).

**2. The same commit passed once and failed nine times.** `netops-correlation-1`
across the ten `f74a0e0c` runs: warm (docker-stats RSS at input stop) ranged
**157–250 MiB** (spread 93 MiB), end ranged **245–288 MiB** (spread 43 MiB).
The end state is the stable quantity; the *denominator* of the ratio wandered.
The last PASS (2026-08-25) cleared by 0.024 (×1.276 vs ×1.3). A ratio clause
whose base jitters by 93 MiB on a ~180 MiB working set cannot discriminate a
leak.

**3. The post-burst delta is a constant, not a proportion.** s11's carrier
(2,500 devices): `rss_at_input_stop` 985.2 MiB → `rss_end` 1,055.8 MiB =
**+70.5 MiB (×1.072 unjudged)**; against the pending-zero anchor +11 MiB
(×1.011, FLAT). The nightly's delta band is 70–113 MiB at 200 devices. Every
retained structure in `src/correlation/main.py` is a fixed-`maxlen` deque
bounded by signal count (`CORR_WINDOW_BUFFER`), not device count.
Counterfactual: s11's own 70.5 MiB delta on the nightly's 180 MiB base would
FAIL the nightly clause (×1.39); the nightly's worst 113 MiB on s11's base
PASSES (×1.114). The clause measured base size.

**4. Two of the three cited runs sampled `end` mid-drain** (pending 19,295 /
16,800 with `oldest_pending_age` pinned at 30 s) — exactly the false-fail the
08-29 rework eliminated ("a working set that grows while a queue drains is the
queue, not a leak").

**Completion failures** (7 of 10 snapshot runs): transport drain PASSED (lag to
baseline in 59–72 s) while the engine froze with a static pending count —
the signature of the evidence-consumer deadlock fixed in `7096e207`. Plausible,
unproven until a post-fix-wave nightly runs.

## What would refute this
The current harness at 200 devices showing `rss_at_pending_zero → rss_end`
climbing past ×1.3 after the full settle (s11's equivalent segment: +11 MiB).

## Actions
1. **Dispatched 2026-09-02**: `gh workflow run scale-miniladder-nightly.yml
   --ref feat/observability-platform` on `88ee2947` (fix wave + reworked
   harness). Result recorded below when it lands.
2. If memflat still fails on the reworked harness: add
   `--mem-abs-floor-mib` (default **64** — the ratified V1 jitter floor,
   unchanged) and set **128** only in the nightly workflow. V1 §6 semantics
   and the s09/s11 verdicts are numerically untouched (carrier judged delta 11
   MiB, ratio 1.011). Never widen `--mem-factor`.
3. Not before V2: a ratio ∧ %-of-cap pair for the correlation judge.

## Result of action 1
**Run 33574967600 on `88ee2947` (fix wave + reworked harness): SUCCESS**, first
green scheduled-lane result since 2026-08-25 and the first ever on the
pending-zero-anchored memflat judge. The lane was red because it was frozen on
a stale snapshot; no harness floor change (action 2) is needed. Row 211 closes
on this evidence; the standing guard is the lane itself, now tracking HEAD.
