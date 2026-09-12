# 72h appliance soak (2026-08-16T23:14:13Z → 2026-08-19T23:14:13Z) — VERDICT

**VERDICT: INVALID.** Recorded 2026-08-19T14:35Z, ~8.6h before the nominal end
time. This file is the immutable record required by tracker 155 / GA defect
class 4 before any ownership testing runs. It is written from live inspection of
the running stack, not from the soak's own status output.

**The soak did not fail to finish. It stopped measuring its subject on
2026-08-17T15:49:35Z and nothing noticed for 46 hours.**

Nothing in the stack was mutated to reach this verdict — every command below is
`docker inspect` / `docker stats --no-stream` / `docker logs` / file reads.

---

## Why INVALID and not "incomplete"

`soak-baseline.json` states the purpose: *"72h appliance-SKU soak — end check:
RSS vs this baseline, watchdog clean, nightly mini-ladder PASS streak,
DLQ/refusal counters explained"*. All four arms are dead, and the primary arm is
not merely failing — it is unmeasurable.

### Arm 1 — correlation RSS vs baseline: **INVALID** (primary arm)

The baseline was captured at `2026-08-16T23:14:13Z`. Both correlation containers
report:

```
netops-correlation-1  Created=2026-08-17T15:49:35.691Z  StartedAt=2026-08-17T15:49:51.575Z  RestartCount=0
netops-correlation-2  Created=2026-08-17T15:49:35.676Z  StartedAt=2026-08-17T15:49:53.490Z  RestartCount=0
```

`Created == StartedAt` with `RestartCount=0` means these are **new container
objects** — the replicas were *recreated*, not restarted in place. That happened
**16h35m into the 72h window**, and it reset exactly the RSS and uptime the soak
exists to measure.

Cause is unambiguous from the commit record: `94e8561d fix(correlation): bound
event-loop blocking under backlog — offload giant-object serialization`
(2026-08-17T15:06:39Z) changed the correlation image; deploying it recreated both
replicas at 15:49. The subsequent live proof run `59080b0b` (17:41) exercised
that new build. The soak was never paused or re-baselined for it.

Consequence: the current readings are not a 72h growth measurement.

| | baseline 08-16T23:14 | now 08-19T14:31 | container age now |
|---|---|---|---|
| netops-correlation-1 | 196.2 MiB | 604.5 MiB (76.62% of 789 MiB cap) | 22h41m |
| netops-correlation-2 | 216.1 MiB | 597.2 MiB (75.69% of 789 MiB cap) | 22h41m |

Reading 196 → 604 MiB as "3× growth over 72h" would be false twice over: it spans
**22.7h, not 72h**, and it spans **two different builds**. There is no honest
delta to compute. The growth that *is* visible inside the new build is real and
worth its own measurement — 597–604 MiB at ~76% of cap after <24h, against an
08-18 mini-ladder observation of correlation-1 at 783 MiB / 99.2% of cap — but
that is a fresh question, not this soak's answer.

### Arm 2 — watchdog clean: **FAIL**

`scripts/stack-watchdog.log` carries repeated `watchdog: DOWN -> clickhouse:
health=unhealthy` transitions and continuously firing vmalert CRITICALs
(`CollectorAllTargetsUnreachable`, `CollectorDown`, `CorrProbeLaneFlatlined`,
and at times `CHMemoryLimitExceeded`). ClickHouse is unhealthy right now — its
healthcheck cannot even exec:

```
OCI runtime exec failed: ... procReady not received
clickhouse: PID_CAPACITY_CRITICAL 19045/19046 (99%) — approaching the fork ceiling
clickhouse: PID_LEAK_SUSPECTED — cgroup task charge 19045 vs 798 live threads observed
```

The watchdog also reports two blind spots it correctly refuses to score as
healthy: `OPENSEARCH_UNVERIFIABLE` (five search-tier checks returning nothing
parsable) and `BUILD UNIDENTIFIED` (api built without `GIT_SHA`).

### Arm 3 — nightly mini-ladder PASS streak: **FAIL (0 for 3)**

Every nightly run inside the soak window failed.

| run | verdict | failing stages |
|---|---|---|
| 20260817T031701Z | **FAIL** | drain, accounting, memflat |
| 20260818T031701Z | **FAIL** | drain, accounting, memflat, cleanup |
| 20260819T031701Z | **FAIL** | preflight, cleanup (ClickHouse unhealthy/uncountable) |

The streak arm required a PASS streak. It got none.

### Arm 4 — DLQ / refusal counters explained: **FAIL**

Unexplained losses in two of the three runs: 786 DLQ events with ClickHouse
insert failures `{corr_signals: 5, findings: 2}` (08-17), and 200 DLQ events with
`{corr_edges: 1, corr_signals: 1}` (08-18). The `drain` stage failed both nights
with consumer lag that **never** returned to threshold (final 411,108 and
429,099) — the 'lag never drains' defect class.

---

## Second finding: the soak interlock cannot detect this failure

`soak_interlock()` (`scripts/lab/twin/ownership_runner.py:161`) is **time-only**.
It reads `soak_start_utc`, adds 72h, and compares to wall clock:

```python
end = start + _dt.timedelta(hours=soak_hours)
if now < end:
    return False, (...)
return True, (f"soak complete (ended {end.isoformat()})")
```

At `2026-08-19T23:14:13Z` it will return `(True, "soak complete")` — and it would
have returned that regardless of the fact that the containers it protects were
replaced 46 hours earlier. **The interlock guards a clock, not a measurement.**

Its default-closed discipline on *ambiguity* is genuinely good and should be kept
(unreadable/malformed baseline → `False`, "'unknown' is not 'clear'"). The gap is
narrower and worse: for the one failure mode that actually occurred — the soak's
subject being destroyed mid-run — the interlock **cannot go red**. It has no
continuity predicate.

This is **defect class 2b (a GREEN signal that proves nothing) in the gate's own
gating instrument** — the same shape as promtool reporting an empty result set as
SUCCESS. It is the eighth instance in this programme, and the first to appear in
the machinery built specifically to prevent instance seven.

The fix is small and mutation-testable: record the correlation containers'
`StartedAt` (or container IDs) *into* `soak-baseline.json` at capture time, and
have `soak_interlock()` refuse — `INVALID`, not `PASS` — when any of them no
longer matches at end-check. Filed as tracker **158**.

Secondary, lower-severity observation: a *missing* baseline file returns
`(True, "no soak in progress")`. Defensible as written (absence = no soak), but
it means deleting the baseline silently opens the gate. Worth a conscious
decision when 158 is fixed rather than an inherited default.

---

## Consequence for tracker 155 / defect class 4

**The five reversible ownership scenarios were NOT run. `T155_REVERSIBLE_GATE`
was NOT issued.** Defect class 4 remains an open GA correctness gate with no live
evidence behind it, exactly as `GA_GATE_TESTS.md` states.

Waiting until 23:14 tonight would not have repaired anything: the interlock would
have opened on the clock, and the run would have proceeded on a stack whose
ClickHouse cannot exec its own healthcheck, whose collectors are flatlined, and
whose last three ladder runs failed. Per the standing house rule, a run under
those conditions would not have produced a trustworthy PASS — and INVALID is a
real outcome that must never be folded into PASS.

Automatic `BUS_PARTITIONS` sizing therefore stays **FROZEN**. `BUS_PARTITIONS`
remains 4 live and was not touched. The broker was not restarted. The baseline
file was not modified.

### What has to be true before 155 can run

1. **Fix tracker 158** — the interlock must be able to go red for a
   subject-replaced soak, and the guard must be mutation-verified.
2. **Restore the stack to a state where a run can prove something** — ClickHouse
   healthy and countable (the PID-ceiling/exec failure first), collectors
   reporting, and at least one mini-ladder PASS. A stack that cannot correlate
   cannot satisfy the StoryProbe contract, and six INVALIDs is the honest
   outcome of running against it.
3. **Re-baseline and re-run the soak** if 72h appliance RSS evidence is still
   wanted — it must be re-earned on the current build, not inferred. This soak
   produced no usable RSS number.

Ordering note: 155 still precedes 157, and 157 still precedes any
template-family expansion. This verdict changes none of that — it establishes
only that 155's precondition was never met.
