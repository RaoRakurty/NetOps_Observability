# Storm run after `2852ad6f` — `t-storm-2.5k` verdict (2026-08-30, run `storm-s04-08300637`)

**Verdict: PASS 9 of 9.** First clean sweep of the storm profile. Completion
144 s, accounting exactly lossless (900,001 == 900,001 + 0 DLQ + 0 rejections),
memflat PASS on both replicas, stability PASS with **0 CommitFailed, 0
UnknownMemberId, 0 restarts, 0 rebalances** — the first storm leg with no
consumer ejection at all. Accuracy **326/345 = 94.49 %**, the best storm score
recorded (s02 93.33 %, s03 93.04 %), detection 100 %, specificity 100 %.

**But the stall did not shrink.** The worst loop stall is 29,974 ms, and
**27,844 ms of it is a genuinely BLOCKED synchronous stretch** at
`reconcile.find_continuation` — measured by the very instrumentation
`2852ad6f` added. The run passes stability only because the same commit raised
the Kafka session timeout from 30 s to 60 s, so a ~28 s block no longer ejects
the member. Tracker 185 part 3 therefore **remains open** as a residual;
tracker 188 is **closed** and its fault path was exercised live.

Image: `netops-correlation` `34d113a3a8bb`, code `2852ad6f` (tracker 188
findings retry-safety + tracker 185 part 3 sync-stretch instrumentation,
per-object persist yield, projected-ms offload gate, session timeout 60 s /
heartbeat 5 s), deployed 06:26:03Z. **Both replicas fresh** (`--force-recreate`),
`CORR_AGGREGATION_PLANE` unset on both (arm OFF, `corr_agg_enabled 0`), findings
dedup-window ALTER applied. `netops-correlation-4` carried the tenant partition;
`netops-correlation-3` was idle (0 versions, 0 cohorts).

---

## 1. Phases

| phase | status | numbers |
|---|---|---|
| preflight | PASS | 26 services running/healthy, consumers live, residue 0 |
| onboard | PASS | 37.37 → 31.37 devices/s, ratio **0.839** (floor 0.60), 2,500/2,500 created, 0 absorbed by dedupe, `stop=none` |
| burst | PASS | **900,000 / 900,000** events in 900 s @ 1,000/s, `producer_key_mode=tenant` key `global`, canary seen |
| drain | PASS | Kafka transport drained in **1,384 s** (budget 2,700), peak lag **418,448**, final 99, baseline 11 + ε 100 |
| correlation_completion | PASS | **143.8 s** (budget 2,700); pending **0** on both replicas, cohorts +22, versions persisted **+10,546**, damped +1,355, `windows_rejected` **+0**, `profiler_errors` **+0** |
| accounting | PASS | **exact**: 900,001 injected == 900,001 OpenSearch-persisted + **0** DLQ lines + **0** counted rejections; `ch_insert_failures {}`; 2,500/2,500 devices covered in `corr_signals` (54,007 rows); `unexplained_missing` 0 |
| memflat | PASS | corr-4 rss 515 → **1,060** (pending-0 anchor) → **1,018 MiB** end = **×0.961 FLAT**, settle 123 s, **79.5 % of its 1,280 MiB cap**; corr-3 66 → 67 → 95 MiB (×1.414 FLAT, settle 263 s, idle); ClickHouse anon 1,213 MiB ×0.929, `MEMORY_LIMIT_EXCEEDED` **+0**, p99 MemoryTracking 31.7 % of cap, MaxPartCount 9 |
| stability | PASS | **0** CommitFailed, **0** UnknownMemberId, **0** consumer restarts, **0** rebalances over a 2,916 s lifecycle; 226 loop stalls, **worst 29,974 ms** |
| cleanup | PASS | 2,500 devices deleted + verified, 0 `mlx-` devices of ANY run id remain, telemetry purged (CH + OS), **residue 0** |

## 2. TTUR — clean scope, all three legs re-queried in ONE session

Query: §5.3 of `RUN_PLAN_P3_AB_2026-08-29.md`, verbatim; storm-aggregate cid
`bb1e46d6-5462-54dc-8465-777c707b9329` (tenant `global`) excluded; scope derived
per leg from its own `report.json` (`phases[burst].at − burst_seconds` ..
`phases[correlation_completion].at`). All three issued **2026-08-30 07:44Z**
against the live ClickHouse — the same-session rule, because legs queried on
different days are not comparable. s03's row reproduces the number recorded in
the run plan digit-for-digit, which validates the recipe.

| leg | scope (burst → converged) | inc | versions | vpi | sigs | T1 p50 | **T1 p95** | T1 p99 | T1 max | T-last p95 | merged | undet |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| storm-s02 (L0a) | 19:32:37 → 19:47:37, conv < 20:06:45 | 2,762 | 12,735 | 4.61 | 91,441 | 460 | **1,055** | 1,229 | 1,622 | 1,880 | 162 | 0 |
| storm-s03 (L0b) | 21:51:36 → 22:06:36, conv < 22:27:38 | 2,685 | 11,198 | 4.17 | 89,378 | 383 | **1,203** | 1,237 | 1,684 | 1,834 | 199 | 0 |
| **storm-s04** | 06:40:02 → 06:55:02, conv < 07:20:33 | **1,632** | 10,535 | **6.46** | 88,672 | **68** | **832** | 1,297 | 1,869 | 2,251 | 194 | 0 |

Deltas, s04 vs the two OFF baselines: **T1 p95 −21.1 % vs s02, −30.8 % vs s03**
— both beyond the 13.11 % OFF-vs-OFF spread this rung is known to carry. **T1
p50 −85.2 % / −82.2 %**. Against them, T1 p99 is **+5.5 % / +4.9 %** and T-last
p95 **+19.7 % / +22.7 %**: the head and body of the distribution moved a long
way forward, the extreme tail did not.

**Shape change, stated because it is large and not explained here.** s04
resolved the same storm into **1,632 incidents instead of 2,685–2,762 (−39 %)**
at essentially unchanged signal volume (88,672 vs 89,378 / 91,441, −0.8 % /
−3.0 %), with versions-per-incident up from 4.17–4.61 to **6.46**. The same
symptoms consolidated into fewer, longer-lived objects. That is consistent with
more continuation adoption on the reconcile path (`reconcile.find_continuation`
ran 8,444 times on the carrier), which is also where the stall lives — but this
run cannot prove the causal link, and accuracy went **up**, not down, so nothing
here reads as a loss of resolution. It is flagged for the next leg to confirm.

## 3. Accuracy — twin scorer, 345 labelled incidents

| leg | passed | rate | detection | specificity | `enterprise_outage` | `upstream_link_failure` | clean templates |
|---|--:|--:|--:|--:|--:|--:|---|
| storm-s02 | 322/345 | 93.33 % | 100 % | 100 % | 0/15 | 12/20 | `local_link_fault` 150/150 · `bgp_peer_flap` 100/100 · `ospf_adjacency_flap` 60/60 |
| storm-s03 | 321/345 | 93.04 % | 100 % | 100 % | 0/15 | 11/20 | same three, all clean |
| **storm-s04** | **326/345** | **94.49 %** | 100 % | 100 % | **2/15** | **14/20** | same three, all clean |

All 19 s04 failures are on the two chained templates and on the same
`affected_includes` clause — **tracker 187**, unchanged in kind. `enterprise_outage`
scoring above zero for the first time (2/15) is a small movement on a template
that has never passed; it is not claimed as a fix.

## 4. The 29,974 ms stall — what it actually is

**Determination: a blocked synchronous stretch. The 185/3 bound did NOT cover
the site that produced it.** The evidence is not an inference — `2852ad6f`'s own
sync-only spans measure exactly this distinction, and they answer it directly.

`corr_sync_stretch_max_ms` on `netops-correlation-4` at convergence
(`metrics-final.txt`, mTLS `:8443`):

| metric | corr-4 (carrier) | corr-3 (idle) |
|---|--:|--:|
| `corr_loop_lag_max_ms` | **29,973.5** | 32.6 |
| `corr_sync_stretch_max_ms` | **27,843.7** | 0.0 |
| `sync_stretch_max_site` (`/healthz`) | **`reconcile.find_continuation`** | `lifecycle.partition` |
| `corr_sync_overruns_total` (budget 500 ms) | **16** | 0 |
| `corr_loop_lag_stalls_total` | 282 | 0 |

**27,843.7 / 29,973.5 = 92.9 % of the worst stall was time the event-loop thread
could not run anything** — no await inside it, so no heartbeat, no fetch, no
commit. The two are the same event, paired in the log to the second:

```
07:16:19,193 WARNING loop-thread block reconcile.find_continuation held the event loop 27844 ms
                     (budget 500 ms, overruns=5, worst=27844 ms at reconcile.find_continuation)
                     — this is SYNCHRONOUS time, no heartbeat can run inside it
07:16:21,064 WARNING event loop STALLED 29974ms (threshold 1000ms, stalls=147, worst=29974ms)
```

and it is not a one-off. Every large stall on the carrier pairs with a
same-site block:

| time | sync block (site) | matching loop stall |
|---|--:|--:|
| 07:06:38 / 07:06:4x | 26,928 ms `reconcile.find_continuation` | 26,471 ms |
| 07:09:49 | (same site, run-in) | 25,240 ms |
| 07:13:08 | 24,795 ms `reconcile.find_continuation` | 24,954 ms |
| **07:16:19 / 07:16:21** | **27,844 ms `reconcile.find_continuation`** | **29,974 ms** |
| 07:22:03 | 9,828 ms `reconcile.find_continuation` | — |

All 16 overruns: 14 at `reconcile.find_continuation` (27,844 · 26,928 · 24,795 ·
9,828 · 2,045 · 1,926 · then ~0.5–0.6 s), 2 at `reconcile.continuation_index`
(561 ms, 531 ms). Nothing else on either replica breached the 500 ms budget.

**Why the wall-clock profile does not contradict this.** The stage profiler's
wall spans on the carrier are much larger and enclose awaits — they are NOT the
stall: `reconcile.loop` max 81,572 ms · `lifecycle.merge` 55,481 ms ·
`handle.syslog` 34,979 ms · `engine.run_window` 30,359 ms · `lifecycle.quiesce`
**26,515 ms** · `persist.decision` 21,320 ms · `persist.evidence` 16,511 ms ·
`persist.batch_flush` 4,754 ms. This is the model `2852ad6f` asserted, and it
holds: `lifecycle.quiesce` is 26.5 s of **wall** time and contributed **0** sync
overruns — the s03 reading of quiesce as the blocking culprit was wrong, and the
per-object yield the commit added is doing its job there. The blocking site is
the other one the commit named: the reconcile tail. It received a `sync_span`
(measurement) but no offload and no yield — the projected-ms offload gate only
guards `_snap_call` / `_decision_offload` call sites, and
`find_continuation` is neither. `sync.reconcile.find_continuation` has 8,444
calls with p50 0.06 ms / p95 0.45 ms / p99 0.66 ms and max 27,844 ms: a handful
of pathological objects, not a broad regression.

**Why the run passed anyway.** The same commit set
`CORR_SESSION_TIMEOUT_MS=60000` (from 30,000) with a 5 s heartbeat. A 27.8 s
block is now 46 % of the session budget instead of 93 % of it, so the broker
never expired the member: 0 UnknownMemberId, 0 CommitFailed, 0 restarts, 0
rebalances — against s02's 2/106/2 and s03's 1/53/1. **The ejection was fixed by
widening the timeout, not by bounding the block.** That is a legitimate
defence-in-depth measure and it converted the run to 9/9, but it is not the same
thing as the loop being responsive, and the residual belongs on the tracker.

## 5. Findings retry (tracker 188) — the fault path WAS exercised live

Not deployed-but-untested: the exact failure mode that failed s03's accounting
occurred **three times** on `netops-correlation-4` during s04 and was recovered
every time.

```
07:06:40,865 WARNING clickhouse insert retry     table=netops.findings attempt=1/4 kind=transport rows=1 backoff=0.39s
07:06:41,360 WARNING clickhouse insert RECOVERED table=netops.findings attempt=2 rows=1
07:13:10,292 WARNING clickhouse insert retry     table=netops.findings attempt=1/4 kind=transport rows=1 backoff=0.23s
07:13:10,721 WARNING clickhouse insert RECOVERED table=netops.findings attempt=2 rows=1
07:16:22,239 WARNING clickhouse insert retry     table=netops.findings attempt=1/4 kind=transport rows=1 backoff=0.36s
07:16:26,327 WARNING clickhouse insert RECOVERED table=netops.findings attempt=2 rows=1
```

Three ambiguous `kind=transport` outcomes, one row each — s03's signature
exactly, and on s03 that cost one row and the accounting phase. Here every one
resends under its deterministic dedup token
(`finding:<topic>:<partition>:<offset>:<seq>:<sha256(row)>`, visible on the
`insert_deduplication_token=` parameter of every findings POST in the log) and
recovers on attempt 2. Outcome: **0 exhausted retries, 0 DLQ lines, 0
`ch_insert_failures`, accounting exactly lossless.** The 07:16:22 retry is the
one that landed inside the 29,974 ms stall — the backoff waited 4.1 s of wall
clock instead of 0.36 s and still recovered, which also exercises the retry
under loop starvation.

The `non_replicated_deduplication_window=1000` ALTER on `netops.findings` was
applied before the run, so the server-side half of the guarantee was live too.
**Tracker 188 is closed on live evidence, not on tests alone.**

## 6. Memory

| container | input stop | pending-0 anchor | end | ratio | % of 1,280 MiB cap | verdict |
|---|--:|--:|--:|--:|--:|---|
| `netops-correlation-4` (carrier) | 515 MiB | 1,060 MiB | **1,018 MiB** | **×0.961** | **79.5 %** | FLAT, settle 123 s |
| `netops-correlation-3` (idle) | 66 MiB | 67 MiB | 95 MiB | ×1.414 | 7.4 % | FLAT, settle 263 s |

ClickHouse anon 1,213 MiB (×0.929 vs anchor), `MEMORY_LIMIT_EXCEEDED` +0, p99
MemoryTracking 1,299 MiB = 31.7 % of its 4,096 MiB cap (peak 3,602 MiB = 87.9 %,
merges 350 MiB informational), `MaxPartCountForPartition` 9.

Compared with the wave: L5 (2 % ON, third leg on a warm container) ended at
**96.2 %** of cap and FAILed memflat; s03's carrier ended at **81.7 %**. s04's
**79.5 % on a fresh container, curve falling** is the cleanest storm memory
reading taken — and it is the fresh-container baseline §3.6 of the A/B verdict
asked for on the OFF side.

## 7. What `2852ad6f` changed, measured

| dimension | storm-s02 (L0a) | storm-s03 (L0b) | **storm-s04** | reading |
|---|--:|--:|--:|---|
| harness verdict | 8/9 | 7/9 | **9/9** | first clean sweep |
| completion | 118.4 s | 103.7 s | 143.8 s | slower, far inside the 2,700 s budget |
| transport drain | 1,026 s | 1,155 s | 1,384 s | slower; peak lag comparable (403,844 / 403,074 / 418,448) |
| accounting | exact | **FAIL** 1 `netops.findings` | **exact** | **188 fixed, fault exercised live (3 retries, 3 recoveries)** |
| CommitFailed / UnknownMember / restarts | 2 / 106 / 2 | 1 / 53 / 1 | **0 / 0 / 0** | ejections gone |
| rebalances | 17 | 6 | **0** | |
| worst loop stall | 35,690 ms | 27,711 ms | 29,974 ms | **not improved** |
| worst BLOCKED sync stretch | not measurable | not measurable | **27,844 ms** | the instrumentation is the deliverable |
| Kafka session timeout | 30,000 ms | 30,000 ms | **60,000 ms** | why 29,974 ms no longer ejects |
| memflat carrier end % of cap | 65.5 % | 81.7 % | **79.5 %** | fresh container, ×0.961 |
| T1 p95 (re-queried) | 1,055 s | 1,203 s | **832 s** | −21 % / −31 % |
| accuracy | 93.33 % | 93.04 % | **94.49 %** | +1.16 / +1.45 pp |

Net: 188 is closed, the ejection cascade is closed, latency and accuracy both
improved — and the blocking stretch that 185 part 3 set out to bound is
**still 27.8 s**, now visible instead of inferred.

## 8. Caveats

1. **Single run.** Every number here is n=1 on a benchmark whose OFF-vs-OFF T1
   p95 spread at this rung is **13.11 %** (measured, `P3_AB_2P5K_VERDICT` §3.1).
   The p95 improvement (−21 % / −31 %) exceeds that spread against both
   baselines; the completion and drain regressions (+22 %/+39 % and +35 %/+20 %)
   also exceed their own spreads and are **not** dismissed as noise — they are
   simply far inside budget.
2. **Fresh containers.** s04 ran on containers created 12 minutes earlier with
   no prior leg's state. s02 and s03 also ran on fresh containers, so the
   comparison is matched — but s04 is *not* comparable to the wave's L3/L4/L5,
   which stacked up to three legs on one container.
3. **The stability PASS has a 26 ms margin.** The harness gate is
   `worst_loop_lag_ms >= 30,000` (`scale-miniladder.py` `KAFKA_SESSION_TIMEOUT_MS`,
   default 30,000). s04 measured **29,974 ms**. Had the same block run 27 ms
   longer the run would read 8/9 with identical engine behaviour. That gate is
   also now **stale**: the deployed engine's session timeout is 60,000 ms, so
   30,000 ms is no longer the ejection boundary it was chosen to represent. It
   should be re-derived from `CORR_SESSION_TIMEOUT_MS`, or kept deliberately as
   a stricter defect gate and documented as such — either way it is not
   currently measuring what its name says.
4. **The stall is not fixed.** §4 is the finding of this run, not a footnote.
   Tracker 185 stays open with `reconcile.find_continuation` named.
5. **The incident-count shape change (−39 %) is unexplained** (§2). It did not
   cost accuracy in this run; it has not been reproduced.
6. **Arm.** OFF on both replicas (`CORR_AGGREGATION_PLANE` unset,
   `corr_agg_enabled 0`, `corr_agg_observed_total` 0). This leg says nothing
   about the aggregation plane and is not an A/B arm; it is the post-deploy OFF
   baseline.
7. **T-last p95 rose** (1,880 / 1,834 → 2,251 s, +20 %/+23 %). Objects live
   longer, consistent with the vpi 6.46 shape. Worth watching; not gated.

## 9. Tracker disposition

- **188 — CLOSED, row deleted.** Fix deployed, dedup window live on
  `netops.findings`, 13 tests green, **and the fault path exercised live** (§5:
  3 transport failures, 3 recoveries, 0 loss, accounting exact). Nothing about
  it remains open.
- **185 — parts 1 and 2 CLOSED; part 3 REWRITTEN as the residual.** Parts 1–3
  are deployed and s04's 9/9 with 0 ejections confirms the ejection cascade is
  gone. The sync-stretch bound itself is **not** achieved: 27,844 ms at
  `reconcile.find_continuation`, 55× the 500 ms budget, 16 overruns. The row is
  cut to the residual with the s04 numbers and the named site.
- **189 — unchanged.** Its audit items are untouched by `2852ad6f`: the stale
  `CH_DEDUP_SAFE_TABLES` comment about `corr_signals` is still in
  `main.py` (~line 6825), and none of the six tables gained natural-key tokens.
  Status text stays `⏳ not started`.
- **187 — unchanged.** All 19 accuracy failures are still the
  `affected_includes` clause on the two chained templates.

## 10. Artefacts

`/var/tmp/scale-runs/storm-s04-08300637/` — `report.md`, `report.json`,
`metrics-final.txt` (both replicas over mTLS `:8443`), `ttur.tsv`,
`ttur-scope.json`, `accuracy-report.md` / `.json`, `twin-score.log`,
`lag-curve.json`, `correlation-completion.json`, `ground-truth.json`;
scorer symlink `/var/tmp/scale-runs/x-08300637l2bv`.
