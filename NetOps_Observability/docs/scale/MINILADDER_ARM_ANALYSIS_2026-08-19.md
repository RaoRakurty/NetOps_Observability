# The failed soak arms, explained (2026-08-19)

Companion to `SOAK_VERDICT_2026-08-19.md`, which recorded the verdict. This file
answers the follow-on question: *why* did the nightly, DLQ and lag arms fail, and
which of them are defects versus thresholds.

**Headline: the three nightly failures are not three defects.** The 2026-08-19
run is fully explained by the ClickHouse PID leak (fixed, `2d4653c7`). The
2026-08-17 and 2026-08-18 runs share ONE root cause in correlation, and the
accounting arm is not a data-loss failure at all.

---

## Arm-by-arm

### 1. `preflight` / `cleanup` — 2026-08-19 only: **the PID leak. FIXED.**

`ClickHouse count on netops.corr_signals failed` with an empty error string,
because ClickHouse could not fork. `netops-clickhouse-1` had accumulated 18,247
zombie `ssl_client` processes from its own TLS healthcheck and saturated
systemd's `DefaultTasksMax=19046` at **2026-08-18T21:41:13Z**.

That timestamp is the whole explanation for this run: the 08-18 03:17 ladder ran
*before* saturation and passed preflight; the 08-19 03:17 ladder ran *after* it
and could not count a table. Full mechanism and proof in commit `2d4653c7`.

**Status: fixed and verified.** `init: true` now reaps orphans; 42 healthchecks
in a 420s window left 0 zombies where the old build would have left 42.

### 2. `drain` — 2026-08-17 and 2026-08-18: **a real capacity + rebalance defect**

Not "lag failed to drain" in the sense of a stuck consumer. The lag curve
declines monotonically the whole time — it is simply far too slow:

| | 2026-08-18 run |
|---|---|
| peak lag | 532,354 (t=7s) |
| final lag | 429,099 (t=900s) |
| net drain | ~103,000 over 900s = **~115 events/s** |
| injection rate | ~1,990/s |
| budget | 905s (3x burst) |
| time actually needed at observed rate | **~77 minutes** |

The 905s budget was never going to clear a 600k backlog at that rate, so this
arm will fail every night until either correlation gets faster or the budget
reflects measured capacity. Note ~115/s is a NET figure — organic lab traffic
keeps arriving during the drain — so it is a floor on the deficit, not
correlation's absolute throughput.

Underneath it is the interesting part, from `rebalance_diagnosis`:

```json
{"commit_failed": 7, "unknown_member": 110, "consumer_restarts": 2}
```

110 `UNKNOWN_MEMBER_ID` events means the group expelled a member 110 times
during one run — the coordinator decided a replica stopped heartbeating. And
`memflat` for the same run shows why:

```
netops-correlation-1  cold 332.8 MB -> warm 745.3 MB -> end 820.8 MB
                      limit 827.3 MB, pct_of_limit 99.2%, cold->end ratio 2.47
```

**The chain: correlation memory climbs ~2.5x under burst → reaches 99.2% of its
cgroup cap → the process stalls (GC/allocator pressure, and per tracker 156 the
on-loop `_archive_slice`/`slice_hash` work is sized by the 50k-floor WINDOW, not
by the object) → heartbeats miss the session timeout → the member is expelled →
rebalance → per tracker 155 the acquiring replica starts with an EMPTY window and
the in-flight evidence is silently discarded → the work is partly redone → lag
drains even slower.** Two `consumer_restarts` in a single run is the same story
at its worst.

This is tracker **156** (the residual on-loop path sized by something unbounded)
producing the memory and the stalls, and tracker **155** turning each resulting
rebalance into silent evidence loss. It is the strongest evidence yet that 156
should be fixed before 155 is measured — the rebalances 155 wants to study are
being *caused* by 156.

### 3. `accounting` — **NOT data loss. A threshold, plus a standing condition.**

The invariant the arm exists to protect held perfectly, both nights:

| | 2026-08-17 | 2026-08-18 |
|---|---|---|
| injected | 600,001 | 600,001 |
| persisted to OpenSearch | **600,001** | **600,001** |
| `unexplained_missing` | **0** | **0** |
| DLQ lines (run-attributable) | 786 | 200 |
| ClickHouse insert failures | 7 | 2 |
| per-device coverage | 1000/1000 | 1000/1000 |

Nothing was lost. Every injected event is accounted for, and the arm fails only
because it treats *any* nonzero DLQ or insert-failure count as a failure.

**What is in the DLQ is 100% one reason:**

```
41,068 / 41,068 lines: reason="identity_unattributable"
error: TenantClaimRefused (payload withheld — the router's sealed quarantine holds it; F-11)
topic: deadletter:syslog   lane: syslog
```

That is the zero-trust tenant attribution working exactly as designed: an event
whose identity cannot be attributed to a tenant is refused, counted, and its
payload sealed rather than guessed at. Per §3a that is the correct behaviour, and
it is the opposite of a leak.

**But the rate is a standing condition nobody has explained.** It is not
ladder-driven — it is constant background traffic:

```
DLQ lines per hour, 2026-08-19: 09h 2021(partial) | 10h 7534 | 11h 7530
                                12h 7539 | 13h 7539 | 14h 7529 | 15h 1420(partial)
```

**~7,530/hour — 2.09/s, ~181,000/day, flat.** Something in the lab emits syslog
continuously from a source that cannot be attributed to a tenant. Filed as
tracker **159**. It is not data loss and not urgent, but "the DLQ is never empty"
permanently defeats the accounting arm's zero-tolerance threshold, and a channel
that always has traffic in it is a bad place to notice a new problem.

### 4. `memflat` — **the same correlation defect as `drain`**

2026-08-17 flagged three containers (`clickhouse` 2.25x, `correlation-1` 11.73x,
`vector-aggregator` 1.72x); 2026-08-18, after the anchor was corrected to the
warm sample, flagged correlation-1 at 99.2% of its cap. ClickHouse's 2.25x on
08-17 is ordinary warm-cache growth measured from a cold anchor and is not
alarming at 29.4% of its limit. **Correlation is the real signal**, and it is
tracker 156.

---

## What this means for sequencing

**The stack is NOT yet "known-green", so do not re-baseline a soak.** The PID
leak is fixed, but the ladder's `drain` and `memflat` arms will still fail
tonight for reasons that are untouched by that fix. A 72h soak started now would
re-run into the same correlation memory ceiling, and its RSS arm would be
measuring a service that is one burst from an OOM kill.

Recommended order:

1. **Tracker 156** — offload `_archive_slice`/`slice_hash`, the last on-loop path
   sized by the window rather than the object. This is upstream of the memory
   growth, the expulsions and the drain deficit.
2. **Re-run the mini-ladder** and require `drain` + `memflat` to pass, or adjust
   the drain budget to measured capacity with that provenance recorded. One green
   nightly is the minimum bar for "known-green".
3. **Then re-baseline** with `scripts/lab/twin/soak_baseline.py --write`, which
   now records subject identity so the soak can be falsified (tracker 158).
4. **Then tracker 155** — and note it becomes a cleaner experiment once 156 stops
   manufacturing involuntary rebalances underneath it.

Tracker **159** (the 2/s unattributable syslog stream) can proceed in parallel;
nothing depends on it.
