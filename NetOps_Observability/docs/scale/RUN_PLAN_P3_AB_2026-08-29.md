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
| L0b | `storm-s03-08292148` (runid `08292148kdz4`) | `t-storm-2.5k` | **OFF** | in flight at plan time — reuse when it lands |
| L1 | `agg-10-off-08292249` (run `0829224959gv`) | `t-storm-10-2.5k` | OFF | **PASS 9/9**, 2026-08-30 00:13Z — both replicas verified OFF via mTLS; engine signals 94,942 (inc 1,274; versions 5,168; vpi 4.06); T1 p50/p95/p99 434/2,763/3,063 s; tlast95 3,273 s; converged 23:53:05 (burst end 23:07:41 → completion ≈ 2,724 s); twin accuracy 903/1005 (90 %); residue 0 |
| L2 | `agg-25-off-08300014` (run `083000149rrs`) | `t-storm-25-2.5k` | OFF | **FAIL 6/9 — INCOMPLETE** (valid OFF reading), 2026-08-30 02:17Z — drain/completion/memflat FAIL: pending 78,663 at the 2,700 s cap, lag 124,868; replica 4 alone carried the storm partition (rss 968→1,072 MiB, continuous 1–2.7 s loop stalls, **no rebalance/ejection**), replica 3 idle at 112 MiB. Engine signals 113,361 (inc 6,370; versions 16,602; vpi 2.61); T1 p50/p95/p99 1,833/3,750/4,491 s (scoped to what completed); undet 949; twin accuracy 1438/1773 (81 %); burst injection 900,000/900,000; residue 0. Deployed image has no 185/3 fix (`2852ad6f`, post-wave). |
| L3 | `agg-10-on-08300221` (run `08300221w0jg`) | `t-storm-10-2.5k` | **ON** | **PASS 9/9**, 2026-08-30 03:31Z — both replicas verified ON (`corr_agg_enabled=1`); aggregation observed 98,636 / suppressed 40,442 (41 %) on the storm replica; engine signals **76,680 vs L1 94,942 = −19.2 %** (inc 1,371; versions 6,701; vpi 4.89); T1 p50/p95/p99 282/1,985/2,224 s (L1: 434/2,763/3,063, p95 −28 %); tlast95 2,426 s; transport drain 1,745 s vs 2,550 s; completion after drain 130 s vs 170 s; lifecycle 3,294 s vs 4,123 s; twin accuracy 899/1005 (89.5 % vs 89.9 %); worst loop stall 10,575 ms; residue 0 |
| L4 | `agg-25-on-<MMDDHHMM>` | `t-storm-25-2.5k` | **ON** | driver STOPPED 03:32Z at its 03:10–04:40 UTC canary guard — stale (canary removed from crontab 2026-08-29, owner-approved; crontab verified: watchdog, TLS rotate 05:07 need-based + defers restarts under a live run, hygiene). Relaunch: `python3 scripts/scale-ab-driver.py --from L4 --ignore-cron-window` (stack idle, arm ON) |
| L5 | `agg-2p5k-on-<MMDDHHMM>` | `t-storm-2.5k` | **ON** | to run — **neutrality guard** |

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
