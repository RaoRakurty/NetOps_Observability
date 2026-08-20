# Why 35,664 signals were shed — capacity, drain, or both?

Run `WA`, 1K workload, build `2e73707c`, 1.5 GiB diagnostic headroom.

**Answer: both, and they compound. But the dominant finding is structural and
was not on the list of candidate causes.**

---

## The structural finding

The evidence window is bounded by **count** (50,000 signals). The RCA horizon is
a **time** (`ENGINE_CFG.window_s = 900 s`, `engine.py:100`). A count bound cannot
express a time horizon — the window holds `50,000 / signal_rate` seconds — so
above `50,000 / 900 = 55.6 signals/s` it is **physically unable to cover the
configured horizon**, no matter how fast anything drains.

Measured live, mid-run:

```
window_signals    50,000      (full)
window_span_s       54.5      <- the window holds 54.5 s of event time
window_horizon_s   900.0      <- the engine is configured to correlate over 900 s
```

**A 16.5x shortfall.** Holding 900 s at the measured rate (~1,225 signals/s into
the window) would need ~1.1 million signals — roughly 1.1 GB for the window
alone. So this is not a tuning gap that a bigger constant closes.

The two parameters are simply inconsistent with each other at any realistic
event rate. Nothing in the code relates them, which is why it was invisible.

## The drain finding, and how the two compound

```
window_overflow_dropped        30,542
window_overflow_in_horizon     12,640   (41.4%)
window_overflow_age_min_s         735.1
window_overflow_age_max_s       1,160.4
```

At first reading `span = 54.5 s` and `victim age = 735–1160 s` look
contradictory. They are both true and the reconciliation is the point:

* **54.5 s** is the EVENT-TIME spread of the 50,000 signals held.
* **735–1160 s** is the WALL-CLOCK age of each victim when shed.

The window holds a dense 54-second slice of event time, and that slice is itself
**12–19 minutes stale**, because correlation is that far behind the bus. Signals
arrive at the window already old.

So:

| | count | share | meaning |
|---|---|---|---|
| shed while still inside the 900 s horizon | **12,640** | **41.4%** | **RCA evidence degradation** — eligible evidence pushed out by capacity |
| shed already past 900 s | 17,902 | 58.6% | would have aged out anyway; harmless in itself, but it is the drain deficit showing up as evidence staleness |

**Effective RCA input at 1K: a ~54-second slice of evidence that is ~12 minutes
old.**

## Answering the wave's question directly

> Are the signals shed because Correlix cannot process fast enough, or because
> the window is fundamentally undersized for the RCA horizon?

**Both, in different proportions, and neither fix alone is sufficient:**

* Fixing the drain would make the evidence *fresh* (removing the 58.6%) but the
  window would still span ~55 s against a 900 s horizon.
* Enlarging the window to cover 900 s needs ~1.1 M signals / ~1.1 GB, which
  trades an RCA gap for a memory problem — and Run C would have shown exactly
  that.

The real defect is that **`CORR_WINDOW_BUFFER` (a count) and
`ENGINE_CFG.window_s` (a time) are independent knobs describing the same thing**,
with no code relating them and nothing detecting the mismatch. Whichever binds
first silently decides what RCA sees.

## What this means for RCA correctness

`accounting` PASSED — 1000/1000 devices, 600,001/600,001 signals, 0 DLQ. So no
signal was *lost*: every one is durably in `corr_signals`. What was lost is
**correlation context**: 12,640 signals that the engine should have been able to
correlate against were not in the window when it ran.

That is why "an RCA object existed" is not a sufficient correctness definition
here. Verdicts may well be unchanged for the twin's deliberately-obvious
scenarios; what cannot be claimed from this run is that *evidence completeness*
or *confidence* is unaffected. Measuring that needs a ground-truth comparison
between a run that overflows and one that does not, which is the natural next
step and is **not** done.

## Runs B and C — not executed, and why the plan changed

The A/B/C decomposition existed to *infer* the cause from how overflow responds
to ingress rate and window size. Direct instrumentation answered the question
more strongly: `window_span_s` vs `window_horizon_s` states the structural
shortfall outright, and `window_overflow_in_horizon` separates degradation from
harmless loss without needing a comparison run.

Run B (reduced ingress) would now be **confirmatory**, and the prediction is
explicit: lower ingress means fewer signals/s into the window, so a longer span
and less in-horizon overflow — but the 55.6 signals/s threshold is unchanged, so
overflow returns at any realistic rate. Run C (larger window) is predicted to be
Case C — postponing failure while growing memory — and the ~1.1 GB arithmetic
says so before spending an hour on it.

Recorded as a prediction so it can be falsified rather than quietly assumed.

## Recommendation

Do **not** pick a new window constant. The fix is to make the two bounds
consistent and to say which one governs:

1. **Derive capacity from the horizon and a measured rate**, or bound the window
   by *time* directly and let count be a safety ceiling — so the horizon is the
   contract and capacity serves it.
2. **Detect and surface the mismatch**: when `window_span_s < window_horizon_s`
   while the window is full, the engine is correlating over less history than it
   is configured to. That is a degraded state and should be operator-visible —
   distinguishable from ordinary age pruning, which is exactly what
   `corr_window_overflow_in_horizon_total` now enables.
3. **Then** revisit the drain, because freshness and span are separate axes.

## Which tracker is next: 164, not 163

`open_objects` stayed at **0** throughout this run, and peaked in single digits
in every prior run. It is not the dimension under pressure at 1K, so bounding it
(163) would be solving a problem this workload does not have.

The pressure is on throughput and evidence freshness, which points at 164
(offload admission) and the drain — with the caveat that offload queue depth is
still uninstrumented, so 164's contribution is asserted by architecture, not yet
measured. That instrumentation is the honest precondition for prioritising it.

## Tracker 162 under a measured bound

With `open_objects` measured at 0–8 on this workload, the O(N) continuation scan
costs nothing today. 162 stays PARTIAL and low-priority until 163 establishes a
real bound on N; correct RCA semantics take priority over the Big-O target, and
the seam-bridge constraint that blocks a sound index is recorded on the row.
