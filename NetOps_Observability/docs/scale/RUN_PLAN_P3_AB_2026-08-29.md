# Run plan — P3 Aggregation plane, live A/B on the StormShape ladder (2026-08-29)

Executes step 4 of `docs/design/AGGREGATION_PLANE_P3_2026-08-29.md` §7, against
the §6b offline projection. Steps 1–3 are committed and deployed with
`CORR_AGGREGATION_PLANE` **default OFF** (`src/correlation/main.py` ~1855;
metrics `corr_agg_*`; `epoch_state()["aggregation"]`). Fable wrote this plan; an
Opus subagent executes it; Fable grades. **Nothing here is a code change** — the
only variable across legs is one environment variable delivered by
`deployment/docker/compose.agg.yml`.

## 0. What is being decided
§6b projected, offline, that ideal K3 aggregation removes **0 % / 36 % / 56 %**
of engine signals at the 2 % / 10 % / 25 % storm rungs. This plan measures the
LIVE version of that number, and — the part the projection cannot answer —
whether removing those signals makes TTUR better and leaves RCA accuracy intact.
A signal reduction that costs accuracy is a regression, not a lever.

## 1. Legs

| # | leg id | profile | arm | status |
|---|---|---|---|---|
| L0a | `storm-s02-08291929` (runid `08291929iqtm`) | `t-storm-2.5k` | **OFF** | ALREADY RUN — reuse, do not re-run |
| L0b | `storm-s03-08292148` (runid `08292148kdz4`) | `t-storm-2.5k` | **OFF** | ALREADY RUN — reuse, do not re-run. **7/9**: `accounting` FAIL (1 `netops.findings` row lost to a transport ReadError — tracker 188, fix `2852ad6f` post-wave) + `stability` FAIL (1 CommitFailedError, 53 UnknownMemberId, 1 consumer restart, worst loop stall 26.8 s — under the 30 s gate but ejected anyway); `memflat` **PASS** (storm replica-3 `cb969ae44891` 544 → 959 → 1,046 MiB end = **81.7 % of its 1,280 MiB cap**, FLAT ×1.09); onboard PASS 0.85; drain 1,155 s (peak lag 403,074); completion 104 s. **TTUR and accuracy recovered 2026-08-30 06:2xZ — neither existed on disk.** TTUR by the exact §5.3 clean-scope query, scope derived the same way as every other leg (burst 2026-08-29 21:51:36 → 22:06:36 from `report.json` `phases[burst].at` − 900 s, converged 22:27:38 from `phases[correlation_completion].at`), `AGG_CID` `bb1e46d6-5462-54dc-8465-777c707b9329` excluded, tenant `global` (confirmed from its burst evidence `producer_key_mode=tenant`, `producer_key=global`): **inc 2,685 · versions 11,198 · vpi 4.17 · sigs 89,378 · T1 p50/p95/p99 383/1,203/1,237 s · T1 max 1,684 s · T-last p95 1,834 s · merged 199 · undetermined 0 · confirmed 0**. Its 13,749 `corr_objects` rows (3,216 correlation ids, 21:51:47 → 22:59:41) survive in ClickHouse, which is what made the recovery possible. Twin **re-scored successfully** despite the `mlx-` devices having been purged after the run (the scorer reads `corr_objects`, not the device registry): **321/345 = 93.0 %**, positive 93 %, specificity 100 % over an empty negative set; all 24 FAILs are on the two chained templates (`enterprise_outage` 15/15, `upstream_link_failure` 9/20) — the tracker-187 `affected_includes` gap, identical in shape to L0a's 23 |
| L1 | `agg-10-off-08292249` (run `0829224959gv`) | `t-storm-10-2.5k` | OFF | **PASS 9/9**, 2026-08-30 00:13Z — both replicas verified OFF via mTLS; engine signals 94,942 (inc 1,274; versions 5,168; vpi 4.06); T1 p50/p95/p99 434/2,763/3,063 s; tlast95 3,273 s; converged 23:53:05 (burst end 23:07:41 → completion ≈ 2,724 s); twin accuracy 903/1005 (90 %); residue 0 |
| L2 | `agg-25-off-08300014` (run `083000149rrs`) | `t-storm-25-2.5k` | OFF | **FAIL 6/9 — INCOMPLETE** (valid OFF reading), 2026-08-30 02:17Z — drain/completion/memflat FAIL: pending 78,663 at the 2,700 s cap, lag 124,868; replica 4 alone carried the storm partition (rss 968→1,072 MiB, continuous 1–2.7 s loop stalls, **no rebalance/ejection**), replica 3 idle at 112 MiB. Engine signals 113,361 (inc 6,370; versions 16,602; vpi 2.61); T1 p50/p95/p99 1,833/3,750/4,491 s (scoped to what completed); undet 949; twin accuracy 1438/1773 (81 %); burst injection 900,000/900,000; residue 0. Deployed image has no 185/3 fix (`2852ad6f`, post-wave). |
| L3 | `agg-10-on-08300221` (run `08300221w0jg`) | `t-storm-10-2.5k` | **ON** | **PASS 9/9**, 2026-08-30 03:31Z — both replicas verified ON (`corr_agg_enabled=1`); aggregation observed 98,636 / suppressed 40,442 (41 %) on the storm replica; engine signals **76,680 vs L1 94,942 = −19.2 %** (inc 1,371; versions 6,701; vpi 4.89); T1 p50/p95/p99 282/1,985/2,224 s (L1: 434/2,763/3,063, p95 −28 %); tlast95 2,426 s; transport drain 1,745 s vs 2,550 s; completion after drain 130 s vs 170 s; lifecycle 3,294 s vs 4,123 s; twin accuracy 899/1005 (89.5 % vs 89.9 %); worst loop stall 10,575 ms; residue 0 |
| L4 | `agg-25-on-08300356` (run `08300356hdmy`) | `t-storm-25-2.5k` | **ON** | **8/9 — `memflat` FAIL only**, collected 2026-08-30 05:16Z — both replicas verified ON (`env "1"` + `corr_agg_enabled 1` over mTLS). Drain **PASS 2,263 s** (budget 2,700, peak lag 493,697, final 12) where L2 FAILed; correlation_completion **PASS 192 s** (pending 0 on both replicas, cohorts +27, versions persisted +9,369, `windows_rejected` +0) where L2 was INCOMPLETE; accounting **exact** (900,001 == 900,001 + 0 DLQ + 0 rejections, 2,500/2,500 devices); **memflat FAIL** — `netops-correlation-4` 1,124 MiB = **87.8 % of its 1,280 MiB cap** (> the 85 % headroom gate) *even though the curve is FLAT ×0.96 vs the pending-0 anchor* (1,087 → 1,171 → 1,124 MiB), replica-3 idle-flat 78 → 84 MiB (6.5 % of cap); stability **PASS** (0 CommitFailed, 0 UnknownMember, **0 restarts**, worst loop stall 14,994 ms, lifecycle 3,860 s); cleanup PASS, **residue 0**. Aggregation, L4-attributable (counters are cumulative on the same containers as L3 — L4 = capture − L3's capture): observed **172,453** / forwarded **72,293** / suppressed **100,160** (58.1 %; 172,453 = 72,293 + 100,160 exactly). Engine signals inside correlated incidents **113,361 → 84,826 = −25.2 %** vs L2. T1 p50/p95/p99 **317/2,655/2,795 s** (L2: 1,833/3,750/4,491, scoped only to what completed), T1 max 2,908 s, T-last p95 3,062 s; inc 1,431 / versions 6,507 / vpi 4.55; merged 113, **undetermined 1** (L2: 949). Twin accuracy **1,579/1,773 = 89 %** (L2: 1,438/1,773 = 81 %). `corr_agg_*` non-zero on `netops-correlation-4` only (observed 271,089 cumulative; replica-3 observed 0 with zero storm traffic) — the same partition-key asymmetry as L1/L3, and **not** a mixed arm: both replicas report `CORR_AGGREGATION_PLANE=1` and `corr_agg_enabled 1` |
| L5 | `agg-2p5k-on-08300516` (run `08300516wqrl`) | `t-storm-2.5k` | **ON** | **FAIL 5/9 — the neutrality guard**, collected 2026-08-30 06:20Z — both replicas verified ON (`env "1"` + `corr_agg_enabled 1.0` over mTLS, `ab-leg.json`). **PASS**: preflight · burst 900,000/900,000 @ 1,000/s · **drain 1,344 s** (budget 2,700, peak lag 416,669, final 1) · **correlation_completion 211 s** (budget 2,700; pending 0 on both replicas, cohorts +20, versions persisted +11,168, `windows_rejected` +0, `profiler_errors` +0) · cleanup **residue 0**. **FAIL ×4**: `onboard` — create rate first 40.7/s → last 20.0/s, **ratio 0.49** against the 0.6 floor, super-linear (this is *pre-burst device-API onboarding*, not the engine; all 2,500 devices were created and attributable, 0 absorbed by dedupe, so the workload still ran); `accounting` — 2 `netops.findings` ClickHouse insert failures (tracker 188, fix `2852ad6f` committed post-wave and deliberately not in this image), everything else exact: 900,001 injected == 900,001 OpenSearch-persisted, 0 DLQ lines, 2,500/2,500 devices covered, `unexplained_missing` 0; `memflat` — **NEW at this rung** (both OFF legs PASSed it): `netops-correlation-4` end **1,231 MiB = 96.2 % of its 1,280 MiB cap** (> the 85 % headroom gate) *while the curve is FLAT* — 1,151 MiB at input stop → 1,185 MiB at pending 0 → 1,231 MiB end, **×1.039 vs the pending-0 anchor**, settle 123 s; `netops-correlation-3` 87 → 165 → 175 MiB (×1.061, FLAT, 13.7 % of cap); ClickHouse `MEMORY_LIMIT_EXCEEDED` +0, p99 MemoryTracking 34.0 % of cap; `stability` — 2 CommitFailedError, 106 UnknownMemberId, 2 consumer restarts, 11 rebalances, 270 loop stalls, **worst loop stall 32,331 ms > the 30,000 ms Kafka session timeout** (L0a's signature exactly: 2 / 106 / 2, worst 35,690 ms). Aggregation, **L5-attributable** (counters are cumulative on the same containers as L3 *and* L4 — L5 = capture − L4's capture; replica-3 ran no prior leg traffic so its counters are already L5-only): observed **54,767** / forwarded **49,800** / suppressed **4,967** = **9.07 % suppressed** (54,767 = 49,800 + 4,967 exactly). TTUR, re-queried in-session and **reproducing `ttur.tsv` digit-for-digit**: inc **2,236** · versions 10,630 · vpi 4.75 · sigs 81,052 · T1 p50/p95/p99 **164/1,360/1,466 s** · T1 max 1,865 s · T-last p95 2,055 s · merged 184 · undetermined 0. Twin accuracy **327/345 = 94.8 %** (L0a 93.3 %, L0b 93.0 %) — 18 FAILs, all on the two chained templates. **L5 was the THIRD consecutive leg on `db5a31b7d5a0` / `1ce6206d8751`** (after L3 and L4) and began at a preflight-cold rss of 1,065 MiB = 83.2 % of cap; see §6.3 for the memory carry-over analysis that this makes necessary |

**Run L1 and L2 first (the stack is already OFF), then redeploy ONCE to ON and
run L3, L4, L5, then redeploy back to OFF.** Two redeploys total. Any other
order costs redeploys, and every redeploy is a chance to mis-flag a replica.

L0a/L0b are the OFF arm of the neutrality guard: L5 is compared against BOTH,
because the leg-to-leg noise floor of this benchmark is ±10 % on TTUR
(`P2_STEP6_2P5K_VERDICT_2026-08-29.md` §3) and one baseline cannot show it.
L0a's accuracy baseline is **93 % (322/345 stories)**,
`docs/scale/STORM_S02_ACCURACY_2026-08-29.md`. L0a's harness verdict was FAIL on
`stability` only — carry that forward as a known-state caveat, do not re-run it.

## 2. Standing rules (read before the first command)

- **One run at a time.** `scale-miniladder.py` takes a run lock at
  `/var/tmp/scale-runs/.lock` (pid + run id). Never start a second harness
  process, never run two legs concurrently, and never force past the lock —
  a lock refusal means a run is live, not that the lock is stale. At plan time
  `storm-s03-08292148` holds it. Wait for it.
- **03:17 UTC cron.** The host cron 1K canary (daily 03:17 UTC `t-nominal`, Sun
  04:17 `s1`; log `data/miniladder/cron.log`) is currently **DISABLED**
  (crontab commented out, 2026-08-29 06:00). Confirm with `crontab -l` before
  the first leg. If it has been re-enabled, do not start a leg that would
  overlap **03:17–~04:30 UTC** — attempt `p2-s012b-08290322` collided with it
  and failed onboard (devices absorbed by dedupe).
- **Residue.** A failed or interrupted leg leaves `mlx-*` devices that block the
  next onboard. Between legs verify residue 0; if not:
  `python3 scripts/scale-miniladder.py --cleanup-only mlx-` (it refuses any
  other prefix). Never delete non-`mlx-` devices.
- **No code changes during the wave.** Engine, harness and image are frozen from
  L1 to L5. If anything must change, the legs measured before it are a different
  experiment and must be labelled as such.
- **Never restart ClickHouse between a leg and its rescore** — it wipes the
  system-log history the memflat clause reads (lesson from s05/s06).
- Each leg is ~15 min burst + up to 45 min drain/completion budget. A `FAIL`
  line in the log does not mean the process exited: wait for the process.

## 3. Deployment

The correlation service is deployed with:

```bash
cd deployment/docker
COMPOSE="-f docker-compose.yml -f compose.offline-images.yml -f compose.tls.yml \
 -f compose.mem125.yml -f compose.lab.yml -f compose.profile.yml"
```

### 3.1 OFF arm (L1, L2) — the deployed default
No redeploy is needed if the stack already runs the frozen image with no
`compose.agg.yml`. Verify it anyway, in BOTH replicas:

```bash
for c in $(docker compose $COMPOSE ps -q correlation); do
  echo "== $c"; docker exec "$c" env | grep -c CORR_AGGREGATION_PLANE || echo "unset (=OFF)"
done
```
Expected: the variable is **unset** in both (count 0 / "unset (=OFF)"). Then
confirm the engine agrees — `corr_agg_enabled 0` on both replicas (§3.3).

### 3.2 ON arm (L3, L4, L5)

```bash
docker compose $COMPOSE -f compose.agg.yml \
  up -d --no-deps --force-recreate --scale correlation=2 correlation
```
`--no-deps` so no other service is disturbed; `--force-recreate` because an
environment-only change does not otherwise re-create a running container;
`--scale correlation=2` because the deployment runs two replicas and losing one
mid-redeploy silently halves ingest.

### 3.3 Replica verification (MANDATORY before every leg, both arms)

A leg where one replica is ON and the other OFF is a **mixed arm**: no metric in
the run output reveals it, and the leg is unusable. Two checks, both replicas:

```bash
for c in $(docker compose $COMPOSE ps -q correlation); do
  echo "== $c"
  docker exec "$c" env | grep CORR_AGGREGATION_PLANE || echo "  (unset -> OFF)"
  docker exec "$c" python -c "import urllib.request;print(urllib.request.urlopen(\
'http://127.0.0.1:8094/metrics',timeout=8).read().decode())" \
    | grep -E '^corr_agg_(enabled|observed_total|suppressed_total)'
done
```
- ON arm: `CORR_AGGREGATION_PLANE=1` from **both**, `corr_agg_enabled 1` on both.
- OFF arm: variable absent from both, `corr_agg_enabled 0` on both.
- ON arm, once the burst is flowing: sample the block twice ~30 s apart and
  confirm `corr_agg_observed_total` is **advancing** on both replicas. Flat
  under load = the plane is not on the ingest path → **stop the leg**, do not
  record it as an ON arm.

(The app port is mTLS-only under `compose.tls.yml`; `:8094` is the
loop-independent health sidecar, tracker 174 — it answers while the engine loop
is busy, which is exactly when you need it.)

Also record both replicas' container ids and `started_at` per leg: replica
identity matters (one replica carries the tenant; see the P2 verdicts).

### 3.4 Back to default
Redeploy **without** the file — the same command with `-f compose.agg.yml`
dropped. Never set the flag to `0` inside the overlay: the OFF arm is defined by
the file's absence, which is what keeps the two arms one argument apart.

## 4. Per-leg execution

For each of L1…L5, in the order of §1:

1. **Idle check.** `corr_engine_pending` ≈ 0 on both replicas and consumer lag
   < 5000 (preflight refuses otherwise). If pending is draining, WAIT.
2. **Residue check** (§2).
3. **Deploy + verify** (§3.1 or §3.2, then §3.3). Record the verification output
   verbatim in the leg's notes — it is the evidence that the arm was what the
   table says it was.
4. **Run**, as ONE tracked background job:

```bash
python3 scripts/scale-miniladder.py --profile <PROFILE> --devices 2500 --eps 1000 \
  --run-dir /var/tmp/scale-runs/agg-<rung>-<arm>-$(date -u +%m%d%H%M)
```
   with `<PROFILE>` / `<rung>` / `<arm>` per §1:
   - L1 `--profile t-storm-10-2.5k` → `agg-10-off-…`
   - L2 `--profile t-storm-25-2.5k` → `agg-25-off-…`
   - L3 `--profile t-storm-10-2.5k` → `agg-10-on-…`
   - L4 `--profile t-storm-25-2.5k` → `agg-25-on-…`
   - L5 `--profile t-storm-2.5k`    → `agg-2p5k-on-…`

   The run-dir name IS the run label: `report.json` records `runid` + `profile`
   but not the arm, and `data/miniladder/last-run.json` records `run_dir`. Name
   the directory exactly as above and the arm is recoverable from evidence
   alone. (Checked: the harness has no `--tag`; adding one would mean editing
   the harness mid-wave, which §2 forbids — the directory name carries it.)
5. **Collect** (§5) before starting the next leg.

## 5. What to collect, per leg

### 5.1 Harness phase verdicts
From `<run-dir>/report.json` + `report.md`: preflight · onboard · burst · drain ·
correlation_completion · accounting · memflat · stability · cleanup. Record
PASS/FAIL **and** the numbers: burst produced/planned, drain seconds, completion
seconds (or INCOMPLETE), accounting N==N, memflat ratio, worst stall, residue.
Also the scenario lines the harness logs at launch: achieved storm share, K3
unique / collapse %, promoted vs unpromotable, chunk peak/mean.

### 5.2 Engine metrics — BOTH replicas, at convergence
Scrape `:8094/metrics` per §3.3 and record:
- **Aggregation plane**: `corr_agg_enabled`, `corr_agg_observed_total`,
  `corr_agg_forwarded_total{class=…}` (per class — this is the delta-class
  breakdown §3 of the design predicts), `corr_agg_suppressed_total`,
  `corr_agg_keys`, `corr_agg_identities`, `corr_agg_evicted_total{reason=…}`,
  `corr_agg_state_transitions_total`, `corr_agg_recoveries_total`,
  `corr_agg_late_forwarded_total`, `corr_agg_beyond_lateness_total`.
  **Σ forwarded over all classes = the "signals reaching the engine" figure**
  in the comparison table; on an OFF leg that figure is the promoted-signal
  count instead (`corr_agg_*` stay 0 by construction).
- **Engine**: cohorts (`corr_engine_cohorts_total`), epochs
  (`corr_engine_epochs_total`), `corr_versions{outcome=persisted|damped}`,
  `corr_engine_windows_rejected_total`, `corr_signals_dropped_total{reason=…}`,
  `corr_stream_time_evictions_total`, `corr_edge_cache_dropped_total`,
  `corr_open_objects_epoch_peak`, `corr_lifecycle_passes_total`, loop-lag max,
  restarts (**0 required**).
- `epoch_state()["aggregation"]` on `/healthz` for the plane's own view.

Note whether the two replicas' `corr_agg_*` are both non-zero on an ON leg. One
zero replica = mixed arm found late; the leg is void.

### 5.3 TTUR — clean scope
Run the tool first:

```bash
python3 scripts/scale-rca-latency.py --device-prefix mlx-<runid>- \
  --since <burst_start_iso> --until <convergence_iso> \
  --json /var/tmp/rca-agg-<rung>-<arm>.json
```

Then the clean-scope numbers that every P1/P2 verdict table is built from:
per-incident `min(window_start)` inside the leg's burst window, with the
**storm-aggregate cid excluded** (it is `uuid5(SIGNAL_NS,
"corrobj|<tenant>|storm-noise")`, engine.py ~3279 — tenant-constant, therefore
shared by every leg, and a naive per-leg scope attributes it to whichever leg is
queried). Derive the cid once:

```bash
python3 -c "import uuid;NS=uuid.UUID('6e1f8c3a-67aa-5b9e-9d40-8a52c0de0001');\
print(uuid.uuid5(NS,'corrobj|<tenant>|storm-noise'))"
```

and substitute it, the leg's burst start/end and its convergence time:

```sql
-- Clean-scope TTUR (the exact query used for every verdict since P1; placeholders in <>):
-- window_start is the incident's own EVENT time (first symptom); created_at the engine's persist time.
WITH inc AS (
  SELECT correlation_id,
         min(window_start) t0, min(created_at) t1, max(created_at) tlast, count() nv,
         argMax(state, (created_at, version)) fstate,
         argMax(verdict_tier, (created_at, version)) ftier,
         max(signal_count) ms
  FROM netops.corr_objects
  WHERE created_at < '<CONVERGED>'
    AND correlation_id != toUUID('<AGG_CID>')
  GROUP BY correlation_id
  HAVING t0 >= '<BURST_START>' AND t0 < '<BURST_END>')
SELECT count() inc, sum(nv) versions, round(sum(nv)/count(),2) vpi, sum(ms) sigs,
       round(quantile(0.5)(dateDiff('second',t0,t1)),0) t1p50,
       round(quantile(0.95)(dateDiff('second',t0,t1)),0) t1p95,
       round(quantile(0.99)(dateDiff('second',t0,t1)),0) t1p99,
       max(dateDiff('second',t0,t1)) t1max,
       round(quantile(0.95)(dateDiff('second',t0,tlast)),0) tlast95,
       countIf(fstate='merged') merged, countIf(ftier='undetermined') undet,
       countIf(ftier='confirmed') confirmed
FROM inc
SETTINGS tenant_scope='__all__'
-- Validated 2026-08-29 against leg p2-s06 (BURST_START 14:25, BURST_END 14:46, CONVERGED 17:00):
-- inc 13,528 · versions 49,654 (incl. closes after the verdict's tighter cutoff) · T1 p95 2,100 s
-- (verdict doc: 2,105 s at a 16:xx cutoff) — reproduces.
```

Issued read-only the way the tools do it:
`docker exec $(docker compose $COMPOSE ps -q clickhouse) clickhouse-client
--query "<sql> SETTINGS tenant_scope='__all__'"`. Every leg's numbers are
re-queried **in the same session** as the comparison — the P2 wave learned that
legs queried on different days are not comparable.

### 5.4 Accuracy — twin scorer
Each `t-storm-*` run writes `<run-dir>/ground-truth.json`. Score it:

```bash
ln -s /var/tmp/scale-runs/agg-<rung>-<arm>-<MMDDHHMM> /var/tmp/scale-runs/x-<runid>
python3 scripts/lab/twin/twin.py --run-root /var/tmp/scale-runs score --runid <runid>
```
(the global `--run-root` goes BEFORE the subcommand; `twin.find_run_dir` globs
`*-<runid>`, which is why the symlink is named `x-<runid>`. Takes >10 min at
345 stories — run it detached, and only after the leg's harness process is
done.) Record: **stories pass rate (the RCA accuracy SLO)**, positive-story pass
rate, specificity on negative controls, and the per-template FAIL distribution.

## 6. Comparison table (fill one per rung)

Rung: `t-storm-<N>-2.5k` — legs `<off-leg-id>` vs `<on-leg-id>`

| metric | OFF | ON | §6b projection | Δ |
|---|--:|--:|--:|--:|
| signals reaching the engine | | | | |
| — `corr_agg_observed_total` | 0 (plane off) | | | |
| — `corr_agg_suppressed_total` | 0 | | | |
| completion (s, or INCOMPLETE) | | | — | |
| T1 p50 (s) | | | — | |
| T1 p95 (s) | | | — | |
| T1 p99 (s) | | | — | |
| T-last p95 (s) | | | — | |
| accuracy (stories pass %) | | | — | pp |
| evictions (`corr_agg_evicted_total`, `corr_stream_time_evictions_total`) | | | — | |
| incidents / versions / v-per-inc | | | — | |
| gate FAILs | | | — | |

§6b projection column: engine signals `98,635 → 63,382` (−36 %) at the 10 %
rung, `172,452 → 76,819` (−56 %) at 25 %, `54,766 → 54,766` (0 %) at 2 %.
The ON leg's measured "signals reaching the engine" is Σ
`corr_agg_forwarded_total{class}`; the OFF leg's is the leg's promoted-signal
count. State the measured-vs-projected gap explicitly — a large gap is a finding
about the classifier, not a rounding error.

Neutrality guard (2 % rung): compare L5 against **both** L0a and L0b, and quote
the OFF-vs-OFF spread beside the ON-vs-OFF delta. A delta inside the OFF-vs-OFF
spread is noise and must be reported as noise.

### 6.1 FILLED — rung `t-storm-10-2.5k`, legs `agg-10-off-08292249` (L1, OFF) vs `agg-10-on-08300221` (L3, ON)

Both legs ran the identical scenario (`storm-10-2.5k`, seed 20260829, shape
digest `d8bf0d5bc872fc77`, achieved storm share 10.00 %, 900,000/900,000 events
injected) on one image; the only difference is `CORR_AGGREGATION_PLANE`.

| metric | OFF (L1) | ON (L3) | §6b projection | Δ |
|---|--:|--:|--:|--:|
| **signals reaching the engine** | **98,636** (promoted count) | **58,194** (Σ `corr_agg_forwarded_total{class}`) | 98,635 → 63,382 (−36 %) | **−40,442 = −41.0 %** |
| — `corr_agg_observed_total` | 0 (plane off) | 98,636 | — | — |
| — `corr_agg_suppressed_total` | 0 | 40,442 (41.0 % of observed) | — | — |
| — forwarded by class (`first`/`state_transition`/`recovery`/`count_threshold`/`repeat`) | 0 / 0 / 0 / 0 / 0 | 43,290 / 4,934 / 8,802 / 1,129 / 39 | — | `contradiction`, `new_vantage`, `new_modality` = 0 on both |
| engine signals inside correlated incidents (`ttur.tsv sigs`) | 94,942 | 76,680 | — | −18,262 = −19.2 % |
| completion (s, or INCOMPLETE) | 170 | 130 | — | −40 s (−23.5 %) |
| transport drain (s) | 2,550 (peak lag 512,566) | 1,745 (peak lag 455,710) | — | −805 s (−31.6 %) |
| T1 p50 (s) | 434 | 282 | — | −152 s (−35.0 %) |
| T1 p95 (s) | 2,763 | 1,985 | — | −778 s (−28.2 %) |
| T1 p99 (s) | 3,063 | 2,224 | — | −839 s (−27.4 %) |
| T-last p95 (s) | 3,273 | 2,426 | — | −847 s (−25.9 %) |
| accuracy (stories pass %) | 903/1005 = 89.85 % | 899/1005 = 89.45 % | — | **−0.40 pp** |
| evictions (`corr_agg_evicted_total`, `corr_stream_time_evictions_total`) | 0 / 41,012 | 18,138 (expired 18,041 + ident_expired 97) / 23,441 | — | stream-time evictions −17,571 = −42.8 % |
| incidents / versions / v-per-inc | 1,274 / 5,168 / 4.06 | 1,371 / 6,701 / 4.89 | — | +97 inc / +1,533 versions / +0.83 vpi |
| gate FAILs | 0 (9/9 PASS) | 0 (9/9 PASS) | — | none new |

Supporting engine counters at convergence (storm replica; the idle replica's are
all 0 unless noted): cohorts 30 → 26 · epochs 67 → 53 · `corr_versions`
persisted 7,384 → 6,961, damped 4,071 → 3,239, heartbeat_touch 479 → 305 ·
`corr_engine_windows_rejected_total` 0 → 0 ·
`corr_signals_dropped_total{reason="window_rejected"}` 0 → 0 ·
`corr_edge_cache_dropped_total` 163,279 → 162,994 ·
`corr_open_objects_epoch_peak` 1,007 → 1,076 · `corr_engine_pending_peak`
5,483 → 3,191 · `corr_lifecycle_passes_total` 66 → 53 (idle replica 181 → 142) ·
`corr_loop_lag_max_ms` 9,174 → 10,575 · restarts 0 → 0 · residue 0 → 0 ·
accounting exactly lossless on both (900,001 == 900,001 + 0 DLQ + 0 rejections).
`corr_agg_keys` 37,766 and `corr_agg_identities` 18,714 at capture on L3;
`corr_agg_state_transitions_total` 13,736, `corr_agg_recoveries_total` 8,802,
`corr_agg_late_forwarded_total` 39, `corr_agg_beyond_lateness_total` 0.

**Measured vs projected.** §6b projected the plane would leave **63,382** of
98,635 promoted signals (−36 %); the live plane forwarded **58,194** of 98,636
(−41.0 %) — **5,188 fewer signals than projected, 5.3 pp more reduction**, i.e.
the classifier suppressed *more* than the ideal-K3 upper bound predicted. The
projection is an upper bound on removal only when every state transition and
recovery is forwarded; the live plane also folds within-bucket transitions
(observed 98,636 = forwarded 58,194 + suppressed 40,442 exactly, and
`corr_agg_state_transitions_total` 13,736 > forwarded `state_transition`
4,934), so the extra removal comes from transitions collapsing inside a bucket,
not from lost accounting. That gap is a finding about the classifier and is
carried into the verdict doc, not treated as rounding.

**Replica coverage.** On L3 only ONE replica has non-zero `corr_agg_*`:
`netops-correlation-4` (`db5a31b7d5a0`, observed 98,636); `netops-correlation-3`
(`1ce6206d8751`) reports observed 0. This is **not** a mixed arm: both replicas
report `corr_agg_enabled 1` and `CORR_AGGREGATION_PLANE=1` from `env`, and
replica-3 received **no storm traffic at all** —
`corr_ingest_events{counter="syslog_received"} 0`, `syslog_signals 0`,
`syslog_prefilter_passed 0`, and every engine counter 0 (cohorts 0, versions 0,
`open_objects_epoch_peak` 0, `stream_time_evictions` 0). The same asymmetry is
present on the OFF leg L1, where `netops-correlation-3` saw `syslog_received`
30 / `syslog_signals` 0 while `netops-correlation-4` saw 910,943 / 98,636. Both
replicas own 24 partitions with `corr_consumer_zero_assignments_total` 0 and
`corr_consumer_cold_partitions` 0 — the single tenant's storm keys hash to
partitions owned by one replica, the known "one replica carries the tenant"
behaviour of the P2 verdicts. Replica-4 carried it on BOTH legs, so the A/B is
same-replica.

**Sources.** `/var/tmp/scale-runs/agg-10-off-08292249/{ab-leg.json, ttur.tsv,
metrics-final.txt, report.md, accuracy-report.md, launcher.log}` ·
`/var/tmp/scale-runs/agg-10-on-08300221/{ab-leg.json, ttur.tsv,
metrics-final.txt, report.md, accuracy-report.md, launcher.log}` · projection
column from `docs/design/AGGREGATION_PLANE_P3_2026-08-29.md` §6b (also
reproduced in §6 above).

### 6.2 FILLED — rung `t-storm-25-2.5k`, legs `agg-25-off-08300014` (L2, OFF, **INCOMPLETE**) vs `agg-25-on-08300356` (L4, ON)

Both legs ran the identical scenario (`storm-25-2.5k`, seed 20260829, shape
digest `8b4f1943e5eda129`, target storm share 25.00 % / achieved 24.52 %
(−1.9 %), 138,689 promoted / 81,957 unpromotable, K3 unique 32,719 (76.4 %
collapse), chunk peak/mean 4,789/2,451.62 (1.953×), burst 900,000/900,000 @
1,000/s) on one image; the only difference is `CORR_AGGREGATION_PLANE`.

**Read the TTUR rows as directional only.** L2 never finished — its
`correlation_completion` is INCOMPLETE with 78,663 signals still pending at the
2,700 s cap — so its T1/T-last percentiles and its accuracy score are scoped to
the subset that *did* complete and are therefore optimistic. The decisive
comparison at this rung is not a percentile delta but **completion itself**:
INCOMPLETE → **PASS at 192 s**, and accuracy **81 % → 89 %**.

**Counter arithmetic.** Both legs' `corr_*` counters are cumulative on
containers that had already run the 10 % leg of the same arm, so the
leg-attributable figure is *this capture minus the previous leg's capture on the
same container*. L2 = its capture − L1's (the derivation the draft verdict §2.2
already documents); L4 = its capture − L3's (`db5a31b7d5a0`, started
02:21:18Z, is literally the same container that ran L3 — and L4's
`correlation_completion` baseline reads `versions_persisted` 6,961, exactly L3's
final value, which confirms the carry-over). Every derived cell below is marked
*(derived)*.

| metric | OFF (L2, INCOMPLETE) | ON (L4) | §6b projection | Δ |
|---|--:|--:|--:|--:|
| **signals reaching the engine** | **172,453** *(derived: 271,089 − 98,636 `syslog_prefilter_passed`)* | **72,293** (Σ `corr_agg_forwarded_total{class}`, *derived*: 130,487 cumulative − 58,194 on L3) | 172,452 → 76,819 (−56 %) | **−100,160 = −58.1 %** |
| — `corr_agg_observed_total` | 0 (plane off) | 172,453 *(derived: 271,089 − 98,636)* | — | — |
| — `corr_agg_suppressed_total` | 0 | 100,160 *(derived: 140,602 − 40,442)* = 58.1 % of observed | — | — |
| — forwarded `first` | 0 | 50,694 *(93,984 − 43,290)* | — | — |
| — forwarded `state_transition` | 0 | 5,989 *(10,923 − 4,934)* | — | — |
| — forwarded `recovery` | 0 | 11,622 *(20,424 − 8,802)* | — | — |
| — forwarded `count_threshold` | 0 | 3,919 *(5,048 − 1,129)* | — | — |
| — forwarded `repeat` | 0 | 69 *(108 − 39)* | — | — |
| — forwarded `contradiction` / `new_vantage` / `new_modality` | 0 | 0 / 0 / 0 | — | never fired (as at 10 %) |
| engine signals inside correlated incidents (`ttur.tsv sigs`) | 113,361 | 84,826 | — | −28,535 = **−25.2 %** |
| completion (s, or INCOMPLETE) | **INCOMPLETE** — pending 78,663 at the 2,700 s cap, oldest pending age 430 s | **192 s** (PASS, budget 2,700; pending 0 on both replicas) | — | **FAIL → PASS** |
| transport drain (s; peak lag) | **FAIL** — never reached baseline+eps in 2,700 s (peak 580,968, final 124,868) | **2,263 s** PASS (peak 493,697, final 12) | — | **FAIL → PASS**; peak lag −15.0 % |
| T1 p50 (s) *(L2 directional)* | 1,833 | 317 | — | −1,516 s (−82.7 %) |
| T1 p95 (s) *(L2 directional)* | 3,750 | 2,655 | — | −1,095 s (−29.2 %) |
| T1 p99 (s) *(L2 directional)* | 4,491 | 2,795 | — | −1,696 s (−37.8 %) |
| T1 max (s) *(L2 directional)* | 5,858 | 2,908 | — | −2,950 s (−50.4 %) |
| T-last p95 (s) *(L2 directional)* | 5,493 | 3,062 | — | −2,431 s (−44.3 %) |
| accuracy (stories pass %) | 1,438/1,773 = **81.11 %** | 1,579/1,773 = **89.06 %** | — | **+7.95 pp** |
| evictions — `corr_agg_evicted_total` | 0 (plane off) | 57,526 *(derived)*: expired 57,270 + ident_expired 256; capacity / ident_capacity / tenant_capacity 0 | — | — |
| evictions — `corr_stream_time_evictions_total` | **124,803** *(derived: 165,815 − 41,012)* | **62,208** *(derived: 85,649 − 23,441)* | — | −62,595 = −50.2 % |
| incidents / versions / v-per-inc | 6,370 / 16,602 / 2.61 | 1,431 / 6,507 / 4.55 | — | −4,939 inc / −10,095 versions / +1.94 vpi |
| merged / undetermined / confirmed | 313 / **949** / 0 | 113 / **1** / 0 | — | undetermined −948 |
| gate FAILs | **3** — drain, correlation_completion, memflat | **1** — memflat | — | **−2; no phase that PASSed on L2 FAILs on L4** |

Supporting counters at capture, storm replica `netops-correlation-4`, all
leg-attributable (*derived*, capture − previous leg on the same container; the
idle replica's engine counters are 0 on both legs): cohorts +27 (L2 +55) ·
epochs +76 · `corr_versions` persisted +9,442 (L2 +21,410), damped +2,687,
heartbeat_touch +121 · `corr_engine_windows_rejected_total` **0 on both** ·
`corr_signals_dropped_total{reason="window_rejected"}` **0 on both** ·
`corr_edge_cache_dropped_total` +344,106 (L2 +307,179) ·
`corr_open_objects_epoch_peak` 1,869 (L2 4,097; running max) ·
`corr_engine_pending_peak` **5,815 (L2 90,663; running max)** ·
`corr_lifecycle_passes_total` +75 over 3,860 s (L2 +27 over 6,717 s — the loop
was blocked, not idle) · `corr_loop_lag_max_ms` 14,993.8 (L2 14,035.8) ·
loop stalls in-window 583 (L2 1,440) · restarts 0 on both · residue 0 on both ·
accounting exactly lossless on both (900,001 == 900,001 + 0 DLQ + 0 rejections).
Plane-internal on L4 (*derived*): `corr_agg_state_transitions_total` +17,611,
`corr_agg_recoveries_total` +11,622, `corr_agg_late_forwarded_total` +69,
`corr_agg_beyond_lateness_total` 0; gauges at capture `corr_agg_keys` 47,141,
`corr_agg_identities` 40,623.

Per-template FAIL distribution (all 1,773 stories are `positive`; no negative
controls, so specificity 100 % is reported over an empty negative set on both):

| template | stories | FAIL OFF (L2) | FAIL ON (L4) |
|---|--:|--:|--:|
| `local_link_fault` | 771 | **0** | 6 |
| `bgp_peer_flap` | 514 | 172 | **39** |
| `ospf_adjacency_flap` | 308 | 0 | 0 |
| `upstream_link_failure` | 103 | 92 | 82 |
| `enterprise_outage` | 77 | 71 | 67 |
| **total** | **1773** | **335** | **194** |

**Measured vs projected.** §6b projected the plane would leave **76,819** of
172,452 promoted signals (−55.5 %, quoted as −56 %); the live plane forwarded
**72,293** of 172,453 (−58.1 %) — **4,526 fewer signals than projected, 2.6 pp
more reduction than the projection's upper bound on removal.** The direction is
the same as at the 10 % rung but the gap is *half the size* there (5.3 pp at
10 %), i.e. the projection tracks the classifier better as the storm share
rises. Accounting inside the plane is exact (172,453 observed = 72,293 forwarded
+ 100,160 suppressed), and `corr_agg_state_transitions_total` +17,611 against
forwarded `state_transition` 5,989 again locates the extra removal in
within-bucket transition folding, not in lost accounting. For corroboration the
harness's own in-run fleet-level projection for this rung
(`report.json` `…/shape/achieved/stream_projection`) is 172,113 → 77,520 =
−54.96 %, the same direction of gap.

**Replica coverage.** As on L1/L3, only `netops-correlation-4`
(`db5a31b7d5a0`) has non-zero `corr_agg_*` (observed 271,089 cumulative);
`netops-correlation-3` (`1ce6206d8751`) reports observed 0. **Not** a mixed arm:
`ab-leg.json` records `env "1"` and `corr_agg_enabled 1.0` for **both**
replicas, and replica-3 received no storm traffic at all
(`corr_ingest_events{counter="syslog_received"} 0`, `syslog_signals` 0,
`syslog_prefilter_passed` 0, cohorts 0, versions 0, `stream_time_evictions` 0),
so there was nothing for its plane to observe. The same asymmetry holds on the
OFF leg L2 (replica-3 `syslog_received` 30 / `syslog_signals` 0 vs replica-4
1,826,272 / 271,089), so the 25 % A/B is a same-replica comparison — carried by
replica-4 on both arms.

**Persisting finding, independent of the arm.** The storm partition lands on a
single replica in both arms: on L4 replica-4 ends at **87.8 % of its 1,280 MiB
cap** while replica-3 sits at 6.5 %, and on L2 the same replica ran to 83.8 %
with an unmeasurable slope. That is a capacity-headroom risk of the deployment's
partition-key distribution, not of the aggregation plane; it is carried as a
caveat in the verdict doc.

**Sources.** `/var/tmp/scale-runs/agg-25-off-08300014/{ab-leg.json, ttur.tsv,
metrics-final.txt, report.md, report.json, accuracy-report.md,
accuracy-report.json, twin-score.log}` ·
`/var/tmp/scale-runs/agg-25-on-08300356/{ab-leg.json, ttur.tsv, ttur-scope.json,
metrics-final.txt, report.md, report.json, accuracy-report.md,
accuracy-report.json, twin-score.log}` · L3 subtraction baselines from
`/var/tmp/scale-runs/agg-10-on-08300221/metrics-final.txt`, L1 baselines from
`/var/tmp/scale-runs/agg-10-off-08292249/metrics-final.txt` · projection column
from `docs/design/AGGREGATION_PLANE_P3_2026-08-29.md` §6b (reproduced in §6
above).

### 6.3 FILLED — rung `t-storm-2.5k` (2 %), legs `storm-s02-08291929` (L0a, OFF) and `storm-s03-08292148` (L0b, OFF) vs `agg-2p5k-on-08300516` (L5, ON) — **the neutrality guard**

All three legs ran the identical scenario plane: `storm-2.5k`, seed 20260829,
345 incidents, 11,071 promoted / 4,989 unpromotable scenario events, K3 unique
5,677 (48.7 % collapse), class shares first 24.0 % / transition 2.4 % / recovery
15.9 % / repeat 57.7 %, burst 900,000/900,000 @ 1,000/s, and byte-identical
in-run `stream_projection` (54,561 → 51,191 = −6.18 %). The ground-truth
`digest` differs across the three only because it hashes the run-scoped device
names. **Two OFF legs are carried because one baseline cannot show the
leg-to-leg noise floor**; the `OFF-vs-OFF spread` column is |L0a − L0b| / mean
of the two, and is the empirical noise floor *for this rung, measured on this
box, on this benchmark* — it is the number the ±10 % decision threshold must be
read against.

**Every TTUR row below was re-queried in ONE session (2026-08-30 06:2xZ)** with
the exact §5.3 clean-scope SQL, per-leg scope from each leg's own
`report.json` phase stamps, `AGG_CID` `bb1e46d6-…-777c707b9329` excluded, tenant
`global` on all three. L5's re-query **reproduces its on-disk `ttur.tsv`
digit-for-digit**; L0a's re-query reproduces T1 p99 (1,229), T1 max (1,622) and
merged (162) exactly and T1 p95 to 1 s (1,055 vs the 1,054 in
`STORM_S02_2P5K_VERDICT_2026-08-29.md` §3), but returns **inc 2,762 / versions
12,735 / vpi 4.61 / sigs 91,441 / T1 p50 460 / T-last p95 1,880** where that
verdict recorded 2,754 / 13,317 / 4.84 / 91,460 / 453 / 2,203 — the S02 verdict
used a later `created_at` cutoff, which admits post-convergence close-out
versions and inflates `versions` and `T-last p95`. **The re-queried numbers are
the ones used in the table below**, because they and L5's and L0b's were
produced by one query in one session, which is exactly what §5.3 requires.
L0b had no `ttur.tsv` and no twin score on disk at all; both were computed for
the first time here (§1 row L0b).

| metric | OFF (L0a) | OFF (L0b) | **OFF-vs-OFF spread** | ON (L5) | §6b projection | Δ ON vs L0a | Δ ON vs L0b |
|---|--:|--:|--:|--:|--:|--:|--:|
| **signals reaching the engine** | 47,012 (carrier-replica prefilter count, from the S02 verdict; **no fleet total survives on disk**) | **n/a** (no `metrics-final.txt` in the run dir) | **not computable** | **49,800** (Σ `corr_agg_forwarded_total{class}`, *derived*: 177,898 + 2,389 cumulative − 130,487 on L4) | 54,766 → 54,766 (0 %) | **not comparable** (see note below the table) | not comparable |
| — `corr_agg_observed_total` | 0 (plane off) | 0 (plane off) | — | **54,767** *(derived: 323,467 − 271,089 on replica-4, + 2,389 on replica-3)* | — | — | — |
| — `corr_agg_suppressed_total` | 0 | 0 | — | **4,967 = 9.07 % of observed** *(derived: 145,569 − 140,602)* | — | — | — |
| — forwarded `first` | 0 | 0 | — | 41,978 *(39,589 derived + 2,389)* | — | — | — |
| — forwarded `state_transition` | 0 | 0 | — | 3,144 *(14,067 − 10,923)* | — | — | — |
| — forwarded `recovery` | 0 | 0 | — | 4,627 *(25,051 − 20,424)* | — | — | — |
| — forwarded `count_threshold` | 0 | 0 | — | 21 *(5,069 − 5,048)* | — | — | — |
| — forwarded `repeat` | 0 | 0 | — | 30 *(138 − 108)* | — | — | — |
| — forwarded `contradiction` / `new_vantage` / `new_modality` | 0 | 0 | — | 0 / 0 / 0 | — | never fired (as at 10 % and 25 %) | — |
| engine signals inside correlated incidents (`ttur.tsv sigs`) | 91,441 | 89,378 | **2.28 %** | 81,052 | — | **−11.36 %** | **−9.32 %** |
| completion (s) | 118 | 104 | **12.61 %** | **211** | — | **+78.8 %** | **+102.9 %** |
| transport drain (s; peak lag) | 1,026 (403,844) | 1,155 (403,074) | **11.83 %** (peak lag 0.19 %) | **1,344** (416,669) | — | **+31.0 %** (peak lag +3.2 %) | **+16.4 %** (peak lag +3.4 %) |
| **T1 p50 (s)** | 460 | 383 | **18.27 %** | **164** | — | **−64.4 %** (better) | **−57.2 %** (better) |
| **T1 p95 (s)** | **1,055** | **1,203** | **13.11 %** | **1,360** | — | **+28.9 %** (worse) | **+13.1 %** (worse) |
| T1 p99 (s) | 1,229 | 1,237 | **0.65 %** | 1,466 | — | **+19.3 %** (worse) | **+18.5 %** (worse) |
| T1 max (s) | 1,622 | 1,684 | **3.75 %** | 1,865 | — | +15.0 % | +10.8 % |
| **T-last p95 (s)** | 1,880 | 1,834 | **2.48 %** | **2,055** | — | **+9.3 %** (inside ±10 %) | **+12.1 %** (worse) |
| **accuracy (stories pass)** | 322/345 = **93.33 %** | 321/345 = **93.04 %** | **0.29 pp** | **327/345 = 94.78 %** | — | **+1.45 pp** (better) | **+1.74 pp** (better) |
| positive-story pass / specificity | 93 % / 100 % *(empty negative set)* | 93 % / 100 % *(empty negative set)* | — | 95 % / 100 % *(empty negative set)* | — | +1.45 pp / flat | +1.74 pp / flat |
| incidents / versions / v-per-inc | 2,762 / 12,735 / 4.61 | 2,685 / 11,198 / 4.17 | 2.83 % / **12.84 %** / **10.02 %** | 2,236 / 10,630 / 4.75 | — | −19.0 % / −16.5 % / +3.0 % | −16.7 % / −5.1 % / +13.9 % |
| merged / undetermined / confirmed | 162 / 0 / 0 | 199 / 0 / 0 | 20.50 % (merged) | 184 / **0** / 0 | — | +13.6 % merged | −7.5 % merged |
| `corr_agg_evicted_total` | 0 (plane off) | 0 (plane off) | — | 64,751 *(derived)*: expired 64,495 + ident_expired 256; capacity / ident_capacity / tenant_capacity **0** | — | — | — |
| `corr_stream_time_evictions_total` | not on disk | not on disk | — | 65,582 *(derived: 151,231 − 85,649)* | — | — | — |
| storm-replica rss at end (% of the 1,280 MiB cap) | 838 MiB (**65.5 %**) | 1,046 MiB (**81.7 %**) | **22.1 %** | **1,231 MiB (96.2 %)** | — | +46.9 % | +17.7 % |
| **gate FAILs** | **1** — `stability` (2 CommitFailed, 106 UnknownMemberId, 2 restarts, worst stall **35,690 ms** > 30 s) | **2** — `accounting` (1 `netops.findings` row lost, tracker 188) + `stability` (1 CommitFailed, 53 UnknownMemberId, 1 restart, worst stall 26.8 s) | — | **4** — `onboard` (0.49) + `accounting` (2 findings, tracker 188) + **`memflat`** (96.2 % of cap, curve FLAT ×1.039) + `stability` (2 / 106 / 2, worst stall **32,331 ms**) | — | **`memflat` and `onboard` are NEW; `stability` is L0a's signature exactly; `accounting` is L0b's failure mode (2 rows vs 1)** | same |

**Why the "signals reaching the engine" row is not comparable at this rung.**
L0a's 47,012 is the only OFF number that exists, it is quoted from
`STORM_S02_2P5K_VERDICT_2026-08-29.md` §2 (which contrasts it with the s01
carrier's 75,199 and the nominal 44,280), and **neither L0a nor L0b kept a
`metrics-final.txt`**, so there is no way to establish from evidence whether
47,012 is a fleet total or one replica's — and L0a's traffic was *split* across
both replicas (window signals 22,917 on replica-4 vs 7,822 on replica-3), unlike
L1/L3/L4 where the idle replica saw literally zero. L5's derived fleet observed
is **54,767**, +16.5 % above 47,012 on an identical scenario plane. That is
either a real leg-to-leg swing in noise-pool promotion or a denominator
mismatch, and this evidence cannot tell them apart. **The row is reported and
explicitly excluded from the neutrality judgement**; §7 criterion 1 is judged on
TTUR and accuracy, which is what it asks for.

**Measured vs projected at 2 %.** §6b projected **zero** removal at this rung
(54,766 → 54,766). The plane removed **9.07 %** (54,767 observed → 49,800
forwarded). Two things are worth stating exactly:

1. §6b's *baseline* is essentially perfect: 54,766 projected against **54,767
   measured observed** — a one-signal match. It is L0a's 47,012 that does not
   line up with the projection, not the projection with the live plane.
2. §6b's *removal* of 0 % is wrong in the same direction as at the other two
   rungs, and by a comparable margin. The harness's own in-run fleet-level
   projection for this rung (`report.json` `…/shape/achieved/stream_projection`)
   is 54,561 → 51,191 = **−6.18 %**, so the live −9.07 % overshoots *that*
   estimate by 2.9 pp — the same size of gap as at 25 % (2.6 pp) and half of the
   10 % gap (5.3 pp). The mechanism is the one §6.1/§6.2 already located:
   `corr_agg_state_transitions_total` +7,771 *(derived: 39,118 − 31,347)*
   against forwarded `state_transition` 3,144 — transitions folding inside a
   60 s bucket rather than forwarding synchronously. Accounting inside the plane
   is exact (54,767 = 49,800 + 4,967).

**The plane's cost/benefit on this rung, honestly.** 9.07 % suppression at 2 %
storm share is **not** "no aggregation opportunity" — but it is small, and it is
the *only* thing the plane bought here. Against it: T1 p95 **+28.9 % / +13.1 %**
worse than the two OFF legs, T1 p99 +19.3 % / +18.5 % worse, completion +79 % /
+103 % worse, drain +31 % / +16 % worse, and a memflat FAIL neither OFF leg
had. The one unambiguous credit is accuracy (+1.45 / +1.74 pp, both outside the
0.29 pp OFF-vs-OFF accuracy spread) and T1 **p50** (−64 % / −57 %) — the plane
gets the median incident to first version much faster and the tail slower. That
split (p50 far better, p95/p99 worse) is itself the finding: suppression removes
the cheap repeat work early and defers a residue into the tail.

**Confound that must be read with every row above.** L5 is the **third
consecutive leg** on containers `db5a31b7d5a0` / `1ce6206d8751`, which had
already carried L3 and L4; both OFF legs were **first legs on freshly created
containers**. The storm replica entered L5 at a preflight-cold rss of
**1,065 MiB (83.2 % of its cap)**, i.e. above where L0a *ended*. §6.3a
below separates what can and cannot be attributed to the plane from this.

### 6.3a Memory across the ON container lifetime — what it does and does not show

Storm-carrying replica per leg (cap 1,280 MiB on every container; `cold` is the
preflight baseline sample, `end` is the memflat end sample):

| leg | arm | rung | container (carrier) | leg # on that container | cold | end | in-leg growth | end % of cap | memflat |
|---|---|---|---|--:|--:|--:|--:|--:|---|
| L0a | OFF | 2 % | `143e8533f1ee` (corr-4) | **1** | 60 MiB | 838 MiB | **+778** | 65.5 % | PASS (FLAT ×0.958) |
| L0b | OFF | 2 % | `cb969ae44891` (corr-3) | **1** | 62 MiB | **1,046 MiB** | **+984** | **81.7 %** | PASS (FLAT ×1.09) |
| L1 | OFF | 10 % | `cd8ce6063716` (corr-4) | **1** | 62 MiB | 935 MiB | +873 | 73.0 % | PASS (FLAT ×0.986) |
| L2 | OFF | 25 % | `cd8ce6063716` (corr-4) | **2** | **937 MiB** | 1,072 MiB | +135 | 83.8 % | FAIL (slope UNKNOWN — no pending-0 anchor) |
| L3 | ON | 10 % | `db5a31b7d5a0` (corr-4) | **1** | 69 MiB | 1,015 MiB | +946 | 79.3 % | PASS (FLAT ×0.964) |
| L4 | ON | 25 % | `db5a31b7d5a0` (corr-4) | **2** | **934 MiB** | 1,124 MiB | +190 | 87.8 % | FAIL (headroom; FLAT ×0.96) |
| L5 | ON | 2 % | `db5a31b7d5a0` (corr-4) | **3** | **1,065 MiB** | **1,231 MiB** | **+166** | **96.2 %** | FAIL (headroom; FLAT ×1.039) |

Idle (non-carrying) replica end rss: L0a 330 · L0b 182 · L1 111 · L2 134 · L3 69
· L4 84 · **L5 175** MiB.

Plane gauges at each ON capture (`corr_agg_keys` / `corr_agg_identities`, both
on the carrier; reported **as-is, gauge values at capture, not derived by
subtraction**):

| capture | `corr_agg_keys` | `corr_agg_identities` | cumulative `corr_agg_evicted_total{ident_expired}` |
|---|--:|--:|--:|
| L3 | 37,766 | 18,714 | 97 |
| L4 | 47,141 | 40,623 | 353 |
| **L5** | **29,855** | **66,529** | **609** |

(Idle replica at L5 capture: keys 2,389, identities 2,143.)

**What the data supports.**

1. **L5's memflat FAIL is a headroom verdict driven by carry-in, not by in-leg
   growth.** L5's own in-leg growth is **+166 MiB — the smallest of any 2 %
   leg**, roughly one fifth of L0a's +778 and one sixth of L0b's +984, and its
   slope verdict is FLAT (×1.039 vs a *measurable* pending-0 anchor). What put
   it at 96.2 % of cap is that it *started* at 1,065 MiB.
2. **Leg-over-leg carry-over is present on the OFF arm too, at the same
   magnitude.** The only arm-matched carry-in comparison available is leg 2:
   OFF cold **937 MiB** (L2, after L1) vs ON cold **934 MiB** (L4, after L3) —
   a 3 MiB difference. On this evidence the plane adds **nothing measurable** to
   the first carry-over.
3. **The OFF arm's own first-leg spread at this rung is larger than the gap the
   plane is being blamed for.** Two OFF legs, same rung, same scenario, both
   fresh containers: **838 MiB vs 1,046 MiB** — a 208 MiB, **22.1 %** spread,
   with L0b landing at 81.7 % of cap, i.e. 3.3 pp from failing the same gate L5
   failed. Storm-carrier end rss at 2 % is a high-variance quantity even with
   no plane at all.
4. **One plane-specific quantity does grow monotonically across the wave:
   `corr_agg_identities` 18,714 → 40,623 → **66,529**, while cumulative
   `ident_expired` evictions total only 609 and `ident_capacity` evictions are
   **0**.** `corr_agg_keys` by contrast is *not* monotone (37,766 → 47,141 →
   29,855), so the key table is being reclaimed and the identity table is not,
   over the ~4 h lifetime of these containers. That is resident plane state that
   grew by ~48k entries across three legs.

**What the data does NOT support, and must not be claimed.**

- There is **no OFF leg 3**. The ON arm's leg-2 → leg-3 carry-in increment
  (934 → 1,065 MiB, **+131 MiB**) has no OFF counterpart at all, so it cannot be
  attributed to the plane rather than to the engine's own third-leg carry-over.
- The identity-table growth in point 4 is **consistent with** contributing to
  that +131 MiB, but nothing here measures bytes per identity entry, and the
  plane's resident footprint is not separately instrumented. Correlating a
  monotone counter with a monotone rss is not attribution.
- L2's memflat FAIL is *slope-unknown*, so the OFF arm has no measurable
  leg-2 slope to compare L4's and L5's FLAT verdicts against.

**Conclusion, stated at exactly the strength the evidence carries.** L5's
`memflat` FAIL **cannot be separated** into "the plane's resident state" versus
"three consecutive legs on one container" with this data. The two facts that are
established are (a) the plane contributes **~0 MiB** to the first leg-to-leg
carry-over (937 vs 934 MiB, arm-matched), and (b) L5's *in-leg* behaviour is the
best of any 2 % leg (+166 MiB, FLAT). The two facts that are established
*against* the plane are (c) `corr_agg_identities` grows monotonically and is not
being reclaimed, and (d) no OFF leg ever reached 96.2 % of cap. **The single
measurement that would settle it is a `t-storm-2.5k` ON leg on freshly
recreated containers** — see the verdict doc's recommended follow-up.


## 7. Decision rule

`CORR_AGGREGATION_PLANE` becomes **default ON** if and only if ALL THREE hold:

1. **Neutrality guard passes.** On `t-storm-2.5k` (L5 vs L0a/L0b), TTUR is
   within **±10 %** (T1 p95, cross-checked against T1 p50 and T-last p95) and
   accuracy is **≥ OFF − 1 pp**. The 2 % rung has no aggregation opportunity by
   construction (§6b: 0 %), so any movement here is cost, not benefit.
2. **The 10 % rung earns it.** L3 vs L1 shows **≥20 % fewer signals reaching the
   engine**, with TTUR **not worse** and accuracy **not worse** than the OFF leg
   (both judged against the ±10 % / 1 pp noise floor above — "not worse" means
   not worse beyond noise, and a same-direction move at 25 % is corroboration,
   not a substitute).
3. **No new gate FAIL.** No phase that PASSed on the corresponding OFF leg FAILs
   on the ON leg (accounting must stay exactly lossless; `windows_rejected` 0;
   restarts 0; residue 0). A pre-existing FAIL that persists unchanged (e.g.
   L0a's `stability`) is not a new FAIL, but must be named.

If 1 fails → the plane costs something where it can gain nothing: do not default
ON; investigate the cost first. If 2 fails but 1 and 3 pass → the plane is safe
but unproven at a realistic share: keep it flag-OFF and record the measured
reduction against the §6b projection as the finding. If 3 fails → stop; the
failure is the result, and no reduction number buys past it.

Write the verdict to `docs/scale/P3_AB_2P5K_VERDICT_2026-08-29.md` with every
caveat: loaded box, leg-to-leg variance, replica identity, any cron overlap, any
mixed-arm leg discarded. No magnitude claim beyond what was measured.

## 8. Hard rules
No commits. No tracker edits. No deletes outside `mlx-*` devices. No engine or
harness change between L1 and L5. If a leg fails mid-way: run cleanup, record
the failure and its evidence, stop — do not silently re-run it into the same
table row.
