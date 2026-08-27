# Correlation engine — burst resilience + throughput design (2026-08-27)

Fable design. Fixes the storm-collapse GA blocker: under a burst the engine's
event loop stalls 108s → aiokafka heartbeat missed → broker ejects the consumer
→ batch replays → **"lag never drains" livelock**. Target from
`CORRELATION_THROUGHPUT_TARGET_2026-08-27.md`: ~1,000 eps/core (≈4,000 eps on
4 cores) so the 3,700-eps S1 storm is absorbed. **Resilience (never eject) is the
non-negotiable stage 1; throughput to target is stage 2.**

## Confirmed mechanism (from the code, not a guess)
`_offload` runs pure-CPU work via `run_in_executor(None, …)` — the default
**ThreadPool**. The docstring's own reasoning: the CPU call holds the GIL but not
the loop thread, so the GIL releases at the interpreter switch interval and the
heartbeat coroutine still gets scheduled. **True for SHORT calls; false under
storm.** When one `prepare_run_window`/`run_window` runs ~108s over a storm-sized
window — and the offload queue is UNBOUNDED (#164), so several such calls run
concurrently on a 4-core box — GIL convoy starves the I/O-bound heartbeat past
the 30s session timeout. The wall is per-cycle work size, not total CPU.

## Stage 1 — RESILIENCE (bound per-cycle work) — PRIORITY, low-risk
**Invariant to establish: no single offloaded call, and no single engine cycle,
may exceed a hard budget well under the Kafka session timeout** (target: any
offloaded call ≤ ~5 s; cycle heartbeat guaranteed within `session.timeout.ms`).

1. **Bound the per-cycle intake.** The engine already has bounded, tenant-fair
   cohort admission (`_select_cohort(pending, limit)`). Extend the SAME
   discipline to the PREP path: `prepare_run_window` must never see an unbounded
   window. Cap the signals/nodes processed per cycle; carry the remainder to the
   next cycle. Under a storm, lag grows (bounded) but the loop heartbeats +
   commits every cycle → **degrades gracefully, catches up, never ejected.**
2. **Bound the offload queue (#164).** Replace the default-executor unbounded
   queue with an explicit bounded pool (workers = cores−1, bounded queue) +
   backpressure: when saturated, the intake defers rather than piling unbounded
   concurrent CPU threads (which is what convoys the GIL). §9 (bounded queues,
   backpressure) — currently violated here.
3. **Yield the 50k-SHA prune** (`main.py:~954` — "50,000 SHA-1s with no await"):
   chunk it with cooperative `await asyncio.sleep(0)` so it can't monopolize a
   cycle either.

Stage 1 alone should end the livelock: short bounded cycles keep the heartbeat
alive under any backlog. Ship + verify this FIRST.

## Stage 2 — THROUGHPUT (toward ~1,000 eps/core) — measured, staged
Only after stage 1 proves resilient. Options, decided by measurement:
1. **ProcessPool for the heavy pure step.** Move `prepare_run_window`/`run_window`
   to a persistent `ProcessPoolExecutor` — a subprocess has its OWN GIL, so the
   main loop thread is never starved and the CPU work runs truly parallel across
   cores. **Risk to measure first: pickle cost of the window/prep per call.** A
   bounded window (stage 1) keeps the pickle small; measure that pickle+IPC does
   not exceed the compute it parallelizes. If it does, keep ThreadPool + rely on
   bounded short calls (stage 1) and pursue (2)/(3).
2. **Reduce per-cycle algorithmic cost** (#166 `run_window` per-cycle cost, #167
   per-pair throughput) — the remaining O(N) work on the hot path.
3. **Shard by tenant/partition** — the engine is already per-tenant in the prep;
   parallelizing tenants across process workers is the natural scale-out and the
   path to the stretch target.

## Correctness constraints (MUST preserve — this is bread-and-butter)
- **Determinism / replay.** `run_window` stays pure and replayable. ProcessPool
  preserves purity (same fn+inputs→same output). Bounding changes cycle
  granularity, NOT results, because OPEN_OBJECTS carries state across cycles.
- **Cross-cycle correlation (the key chunking risk).** A signal admitted in cycle
  N must still correlate with a related signal in cycle N+M via persistent
  OPEN_OBJECTS. **Must be tested** — a two-signal incident split across a chunk
  boundary must still produce ONE cohort, identical to the unbounded path.
- **Tenant isolation (§3a).** The per-tenant prep and the mixed-tenant-window
  REFUSAL must survive; process workers must not leak state across tenants; the
  org-isolation test must still pass.
- No new mutable global state; bounded everything (§9); observable (§10).

## Test plan (REQUIRED — the fix is only real if the storm can't eject it)
1. **Resilience test (stage 1):** drive a storm-sized window/backlog through the
   engine cycle and assert: zero consumer ejections (no CommitFailed /
   UnknownMemberId), every cycle heartbeats within the session timeout, worst
   cycle time under budget, and lag drains (catches up) instead of livelocking.
2. **Correctness-under-bounding:** a workload whose incidents span chunk
   boundaries yields byte-identical cohorts vs. the unbounded path (determinism).
3. **Throughput (stage 2):** measured eps/core before/after vs. the ~1,000
   target, on a quiet engine.
4. **Isolation:** existing org-isolation + mixed-tenant-refusal tests still pass.
5. Full gate (vet/test/-race N/A for Python — use the engine's pytest harnesses +
   the golden-wire/replay determinism tests).

## Build sequencing (Opus implements; Fable verifies)
- **A. Profile + confirm** (test harness, large window): pinpoint the exact
  hotspot (prep vs run_window vs prune) + confirm the GIL-convoy mechanism +
  validate the bounding approach. If it contradicts this design, STOP + report.
- **B. Implement Stage 1** (bounding + bounded offload queue + prune yield) +
  the resilience & correctness tests. Verify storm no longer ejects.
- **C. Re-run the storm ladder** (1k S1) against the fixed engine.
- **D. Stage 2** (ProcessPool/shard) gated on measuring stage-1 eps vs target.
