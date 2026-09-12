# Correlation memory forensics — what owns the RSS, and what Linux does at the cap

Wave objective: stop inferring the memory/stall relationship and measure it.
Three 1k runs, cleanup disabled, dual-plane instrumentation.

**Headline: the dominant term is NOT live Python objects. After a drain the
process holds 665 MB RSS against 12–15 MB of traced live heap — a ~650 MB
allocator-residency gap. A retention fix (interning) cut the PEAK enough to
restore consumer stability, but the residency remains.**

---

## 1. The stability-measurement bug — FIXED first, on purpose

The old gate ran only when drain FAILED, read logs in a window ending with
drain, and inspected ONE replica (`cid()` returns the first). Run
`08192339borh` reported `commit_failed=0` while three CommitFailedError events
occurred after the window closed.

New `stability` phase: runs after everything, waits for settlement plus a grace
period, reads EVERY replica back to burst start. Counting is line-anchored — one
aiokafka traceback names `CommitFailedError` twice, so substring counting
reported two events for one. 18 tests, **11/11 mutants killed** (four survived
the first pass until the collection was made a testable seam).

## 2. The profiler was the first "finding" — discarded

The first forensic run recorded six event-loop stalls of 5, 5, 96, 39, 73 and
64 s. **Every captured stack showed the loop inside `tracemalloc.statistics()`,
called from the snapshot task.** The instrument caused the stalls it was
deployed to explain. That run's stall evidence is INVALID and is kept as
`memory-snapshots-CONTAMINATED.jsonl`.

The dual-plane design caught it: the external host sampler produced 229
uninterrupted rows through all six stalls, so the cgroup evidence never depended
on the wedged process.

Fixed: heavy analysis opt-in and off-loop via `asyncio.to_thread`, frames 12→4,
heavy only at RSS threshold crossings. 4/4 mutants killed.

## 3. What owns the memory

### Python side, during load

At the 85%-of-cap crossing: 216.2 MB traced, of which **engine.py +
path_graph.py = 157.8 MB across 2,593,452 blocks — 85% of the top sites**.

| bytes | blocks | site |
|---|---|---|
| 35.2M | 400,148 | `path_graph.py:675` `shared_token_relation` |
| 31.3M | 409,888 | `engine.py:808` `Edge(...)` |
| 31.0M | 600,220 | `engine.py:745` `Grounding(...)` |
| 20.9M | 373,161 | `engine.py:622` O(n²) candidate pairs |
| 26.5M | 400,146 | `path_graph.py:677-678` |

`shared_token_relation(token)` and the `Grounding` wrapping it are pure
functions of a token, built once per CANDIDATE PAIR — quadratic in the window.
Two pairs sharing a token got two identical immutable objects.

### After the drain — the decisive measurement

```
RSS 665.0 MB   traced live 11.9–15.2 MB   window_signals 1,170–3,532   open_objects 0
```

**~650 MB, 98% of RSS, is not live Python objects.** This is allocator
residency: the high-water mark of allocation churn, freed by Python and never
returned to the OS. It reproduces the earlier standalone result (clearing every
container released 0.9 MB of 67 MB; `malloc_trim` returned 9 MB more) and
explains why every previous "the containers are bounded" measurement was true
and none of them was the cause.

`MALLOC_ARENA_MAX` was measured and rejected earlier (293.0 / 293.3 / 293.0 MB
at default/2/1) — the churn is small objects in pymalloc, not glibc arenas.

## 4. What Linux does at the cap — measured, not inferred

External plane, before the fix:

```
peak 827.3 MB = 100% of cap   swap 812.8 MB   memory.max hits 25,708
PSI memory full_total 69.4 s
```

`oom_kill` stayed 0 — the container had swap, so it thrashed instead of dying.
Both replicas nonetheless restarted (`RestartCount=1`, `OOMKilled=false`).

## 5. What was executing during the stalls — the causal proof

With the profiler fixed, seven real stalls were captured:

| stall | event-loop stack |
|---|---|
| **26 s** | `uuid.py:285 bytes` ← `uuid5` ← `signal_id` ← `buffer_signal` |
| 9 s | **`asyncio/tasks.py:653 sleep`** in uvicorn's main loop |
| 9–12 s (×3) | `json.dumps` ← `_batch_token` ← `_insert_batch` |
| 5 s | dataclass `__init__` ← `syslog_control_signal` |
| 7 s | `ssl.write` ← aiokafka `send` |

**A 26-second `uuid5()` and a 9-second `asyncio.sleep()` are not CPU work.**
Sleep does nothing; it cannot be slow. Every one of these frames is an
allocation or page-touch site. The process is blocked in the kernel: with
812 MB swapped out, each touch faults it back in.

So the chain is proven rather than assumed:

```
working set > cap → 25,708 memory.max hits → 812 MB swapped → 69 s PSI full stall
→ trivial operations take 26 s → 36 s worst stall > 30 s session timeout
→ member ejected → UnknownMemberId ×102 → CommitFailed → rebalance
```

## 6. The fix, and its measured effect

Interning `Relation`/`Grounding` by token or seam id (frozen dataclasses of
scalars; bounded per §9 because the keys come from device-supplied tokens).
6/6 mutants killed.

Same workload, same cap, same BUS_PARTITIONS=4, same replica count:

| | before | after |
|---|---|---|
| peak swap | 812.8 MB | **431.3 MB** (−47%) |
| `memory.max` hits | 25,708 | **4,779** (−81%) |
| PSI memory full_total | 69.4 s | **5.1 s** (−93%) |
| stall stacks captured | 7 | **3** |
| worst event-loop stall | 36,290 ms | **12,031 ms** |
| `UnknownMemberIdError` | **102** | **0** |
| `CommitFailedError` | 2 | **0** |
| consumer restarts | 2 | **0** |
| **stability phase** | **FAIL** | **PASS** |

Worst stall is now below the 30 s session timeout, which is why membership holds.

## 7. What still fails

* **memflat** — 317 → 758 MiB (96% of cap) *after input stopped*. The peak is
  lower and the pressure far milder, but RSS still climbs during a long drain
  and does not come back.
* **drain** — final lag 440,415.

Both are the same residency story: the allocator keeps the high-water mark, so a
long drain re-approaches the cap even though live data is tiny.

## 8. Classification

**MIXED, and now quantified:**

* **Case B/C dominant** — allocator residency / unexplained gap: 665 MB RSS vs
  12–15 MB live after drain (~98% of RSS).
* **Case A contributing** — real retention during load (157.8 MB of duplicate
  immutables), now largely removed by interning, which is what lowered the
  high-water enough to restore stability.
* **Case D is the trigger mechanism** — cgroup reclaim/swap converts the
  residency into multi-second stalls once the cap is approached.
* **Not Case E** — the stalls are not CPU-bound application code; a 9-second
  `sleep()` proves that.

## 9. Not yet run

The **A/B memory-limit experiment** (item 7). Its purpose is now sharper: it
must distinguish "the legitimate working set fits under a higher cap and
plateaus" from "residency keeps climbing to whatever cap it is given". The
after-fix numbers make the second outcome plausible and the experiment
necessary — a higher limit must not be adopted before it is run.

## 10. Evidence

`forensic2/` (before) and `forensic3/` (after): `host-samples.jsonl`,
`memory-snapshots.jsonl`, `stall-stacks.txt`, `FREEZE.txt`, `ladder.log`.
`forensic/memory-snapshots-CONTAMINATED.jsonl` is the discarded profiler-caused
run, kept so the mistake stays visible.
