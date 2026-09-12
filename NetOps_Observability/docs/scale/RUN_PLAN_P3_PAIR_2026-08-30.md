# Run plan — matched fresh-container OFF/ON pair at `t-storm-2.5k` (2026-08-30)

**Purpose.** Settle criteria **1 (neutrality guard)** and **3 (no new gate
FAIL)** of `RUN_PLAN_P3_AB_2026-08-29.md` §7 with every confound the P3 wave
carried removed. This is the follow-up recommended in
`P3_AB_2P5K_VERDICT_2026-08-29.md` §3.6 and approved by the owner. Criterion 2
is already **MET** (10 % rung, −41.0 % signals); nothing here re-tests it.

The confounds §3.6 lists and how this pair removes them: both legs run on the
**same image, same session, same day**; both start on **freshly
`--force-recreate`d correlation containers**, so `memflat` and every `*_total`
measure ONE leg; the deployed image already carries `2852ad6f`, so the
`stability` ejections and the tracker-188 `accounting` FAIL that dominated L5's
comparison are out of the picture (storm-s04 proved that live: 0/0/0, exact).

## 1. The two legs

| leg | profile | arm | run dir | result |
|---|---|---|---|---|
| **P1** | `t-storm-2.5k` | **OFF** | `pair-2p5k-off-08301624` (runid `083016240km5`) | **6/9** — `memflat` FAIL (carrier **corr-3** 489 → 1,014 → **1,093 MiB** end = **85.4 %** of its 1,280 MiB cap, FLAT ×1.078), `stability` FAIL (worst loop stall **32,446 ms** vs the stale 30,000 ms gate — 0 CommitFailed / 0 UnknownMember / 0 restarts / 0 rebalances, tracker 190), `cleanup` FAIL (OpenSearch purge stalled at 736,001 docs; cleared to a **verified 0** by the driver's `--cleanup-only` pass before P2). PASS: preflight · onboard 0.78 · burst 900,000/900,000 · drain **1,423 s** (peak lag 441,799) · **completion 223 s** · accounting **exact** (900,001 == 900,001 + 0 DLQ + 0 rejections, 2,500/2,500 devices, `corr_signals` 54,001 rows). TTUR (own `ttur.tsv`, §5.3 clean scope): inc **1,632** · versions 10,554 · vpi 6.47 · sigs **86,624** · T1 p50/p95/p99 **81 / 902 / 1,312 s** · T1 max 1,807 · T-last p95 2,374 · merged 191 · undet 0. Twin accuracy **325/345 = 94.20 %** (detection 100 %, specificity 100 %; `upstream_link_failure` 14/20, `enterprise_outage` 1/15, other three templates 310/310) |
| **P2** | `t-storm-2.5k` | **ON** (`compose.agg.yml`) | `pair-2p5k-on-08301732` (runid `083017321c8x`) | **8/9** — `stability` FAIL only (worst loop stall **30,468 ms**, same stale gate, again **0/0/0/0**); **`memflat` and `cleanup` both FAIL → PASS** (carrier **corr-4** 626 → 1,012 → **1,068 MiB** = **83.4 %** of cap, FLAT ×1.055; residue 0). PASS: preflight · onboard 0.66 · burst 900,000/900,000 · drain **1,340 s** (peak lag 418,128) · **completion 195 s** · accounting **exact** (`corr_signals` 54,022 rows). Plane, leg-scoped and **exact**: observed **54,767** = forwarded **49,910** (`first` 41,921 · `state_transition` 3,223 · `recovery` 4,713 · `count_threshold` 23 · `repeat` 30 · `contradiction`/`new_vantage`/`new_modality` **0**) + suppressed **4,857** = **8.87 %**; evicted `expired` 18,254 / `ident_expired` 97 / capacity 0. TTUR: inc **1,532** · versions 9,094 · vpi 5.94 · sigs **76,036** · T1 p50/p95/p99 **81 / 830 / 1,295 s** · T1 max 1,734 · T-last p95 2,265 · merged 147 · undet 0. Twin accuracy **319/345 = 92.46 %** (`upstream_link_failure` **8/20**, `enterprise_outage` 1/15, other three 310/310) |

**Outcome — `P3_PAIR_2P5K_VERDICT_2026-08-30.md`.** Criterion 1 **FAILS on the
accuracy clause ONLY**: every TTUR clause passes against **both** OFF points for
the first time (T1 p95 **−7.98 %** vs P1, **−0.24 %** vs s04, against an
OFF-vs-OFF spread that has tightened from 13.11 % to **8.07 %**), while accuracy
is **−1.74 pp** against a −1.00 pp floor. Criterion 3 **PASSES** (0 PASS→FAIL;
`memflat` and `cleanup` FAIL→PASS; `stability` pre-existing on both).
Criterion 2 was already MET and is not re-tested. **The plane stays OFF by
default** per §7's disposition — but the 6-story accuracy gap is proven
(60/60 exact reproduction) to be a **twin-scorer defect**, not an engine or plane
result: `scorer.py:664` decides `affected_includes` from one arbitrarily-chosen
object among tied-tier objects, and the choice is the **lowest correlation
UUID**. Under the union reading all three legs score **345/345**. Filed as
**tracker 191**; re-score (no new legs) before re-applying criterion 1.

Both on the LIVE image `netops-correlation` **`34d113a3a8bb`**, code
**`2852ad6f`** — the image `storm-s04` ran on. 2,500 devices, 1,000 eps, 15 min
burst, the driver's own gates per leg (cron window, idle+lock, residue 0,
ClickHouse, 2 healthy replicas, arm read from BOTH replicas' env AND
`corr_agg_enabled`). **Fresh containers before EVERY leg** — including P1, whose
arm does not change. **Restore to arm OFF** (the deployed default) after P2.

## 2. What to compare

1. **P2 vs P1** — the matched pair. This is the primary comparison and the only
   one with no cross-session confound.
2. **P2 vs `storm-s04`** (same image, OFF, run `08300637l2bv`: T1 p95 **832 s**,
   accuracy **94.49 %**, completion **144 s**) — a second OFF point on the same
   image, for corroboration only.
3. **P1 vs `storm-s04`** — the **OFF-vs-OFF spread on the post-`2852ad6f`
   image**. The rule's ±10 % threshold is judged against this: the pre-fix
   spread was **13.11 %** (wider than the threshold itself), and whether it
   tightened is exactly what a third OFF point at this rung buys.

Report every TTUR figure from the driver's own `ttur.tsv` (clean scope,
storm-aggregate cid excluded), re-queried in the same session for both legs, and
both legs twin-scored — the driver does all of this per leg.

## 3. Decision rule

**`RUN_PLAN_P3_AB_2026-08-29.md` §7, criteria 1 and 3, unchanged and not
restated here** (and the §5.3 clean-scope SQL is the driver's `ttur_sql()` — do
not re-derive it). In one line: criterion 1 = T1 p95 within **±10 %** with T1
p50 / T-last p95 as cross-checks and accuracy **≥ OFF − 1 pp**; criterion 3 = no
phase that PASSed on P1 FAILs on P2, a persisting pre-existing FAIL named but
not counted. If both hold, criteria 1+2+3 hold and the rule says default ON.
Read every delta against the P1-vs-s04 spread measured above, not against the
old 13.11 %.

## 4. Launch

```
setsid nohup python3 scripts/scale-ab-driver.py \
  --legs P1:t-storm-2.5k:off:pair-2p5k-off,P2:t-storm-2.5k:on:pair-2p5k-on \
  --fresh-containers \
  --state-file /var/tmp/scale-runs/ab-pair-state.json \
  --log-file /var/tmp/scale-runs/ab-pair-driver.log \
  --ignore-cron-window \
  >> /var/tmp/scale-runs/ab-pair-driver.launcher.log 2>&1 < /dev/null &
```

Run from the repo root. `--state-file` is **not optional**: the default
`ab-state.json` holds the six-leg wave, and the driver refuses a state file
recorded for a different leg table. The restore leg needs no flag (it is on by
default; `--no-restore-arm` would disable it).

Resumable: re-running the same command re-attaches to a live leg, re-collects a
leg that ran but was not collected, and skips a leg that is complete AND
collected. `--from P2` starts at P2 deliberately.

## 5. Hard rules

No engine, harness or image change between P1 and P2 — a redeploy of anything
but the correlation replicas' arm invalidates the pair. No commits during the
wave. No deletes outside `mlx-*` devices. If a leg fails mid-way: record the
failure and its evidence and stop; do not re-run it into the same table row.

## 6. Resolved leg table (`--dry-run`, 2026-08-30)

```
PLAN — 2 leg(s), state /var/tmp/scale-runs/ab-pair-state.json
  resolved leg table (2 leg(s), source --legs, --fresh-containers):
    P1     profile t-storm-2.5k       arm OFF run dir /var/tmp/scale-runs/pair-2p5k-off-<MMDDHHMM>
    P2     profile t-storm-2.5k       arm ON  run dir /var/tmp/scale-runs/pair-2p5k-on-<MMDDHHMM>
  now 2026-08-30T16:21Z — cron window 03:10-04:40 UTC: outside [--ignore-cron-window given]

[RUN ] P1  profile t-storm-2.5k  arm OFF  state=not run collected=False
       arm     : ensure OFF and force-recreate ALWAYS (--fresh-containers), so this leg starts on cold containers:
                 docker compose -f docker-compose.yml ... -f compose.profile.yml up -d --no-deps --force-recreate --scale correlation=2 correlation
       verify  : CORR_AGGREGATION_PLANE + corr_agg_enabled == 0 on BOTH replicas (mTLS /metrics on each replica's own ip:8443)
       run     : setsid nohup python3 scripts/scale-miniladder.py --profile t-storm-2.5k --devices 2500 --eps 1000 --run-dir /var/tmp/scale-runs/pair-2p5k-off-<MMDDHHMM>
       counters: LEG-SCOPED (fresh containers) — metrics-final.txt needs no subtraction

[RUN ] P2  profile t-storm-2.5k  arm ON  state=not run collected=False
       arm     : ensure ON and force-recreate ALWAYS (--fresh-containers), so this leg starts on cold containers:
                 docker compose -f docker-compose.yml ... -f compose.profile.yml -f compose.agg.yml up -d --no-deps --force-recreate --scale correlation=2 correlation
       verify  : CORR_AGGREGATION_PLANE + corr_agg_enabled == 1 on BOTH replicas (mTLS /metrics on each replica's own ip:8443)
       run     : setsid nohup python3 scripts/scale-miniladder.py --profile t-storm-2.5k --devices 2500 --eps 1000 --run-dir /var/tmp/scale-runs/pair-2p5k-on-<MMDDHHMM>
       counters: LEG-SCOPED (fresh containers) — metrics-final.txt needs no subtraction

[RUN ] restore: redeploy WITHOUT compose.agg.yml and verify corr_agg_enabled 0 on both replicas

Nothing was touched (--dry-run).
```

The `residue`/`collect` lines and the full compose file list are elided above
only for width; the dry run prints them verbatim. Nothing on the stack was
touched to produce this section.
