# First storm-realistic run — `t-storm-2.5k` verdict (2026-08-29, run `storm-s01-08291633`)

**Verdict: the storm profile did its job on the first try — it found a P2
regression the nominal benchmark could never show (a 115 s event-loop stall,
tracker 185, root-caused and fixed the same evening) and an unbounded product
query (tracker 186, fixed and deployed). Completion PASS 2,171 s and accounting
exact; stability FAIL and memflat FAIL are both downstream of those two
defects. TTUR on storm incidents: T1 p95 1,376 s. The run is the baseline for
the P3 A/B; it is NOT a clean pass.**

Image `46934f3f` (P2 + lever wave; pre-`675966cd`), ClickHouse budget +
merge-safe system logs, harness `29686b0c` (t-storm ladder). Replica-4 carried
the tenant.

## 1. Workload (ground truth `ground-truth.json` / `ground_truth.jsonl`)
345 incidents over 1,510 devices (990 background-only), scenario 16,060 events
= 1.78 % of the 900,000-event plan; 2,024 state transitions, 1,761 recoveries,
6,500 repeats ≤60 s on 1,377 identities, 135 multi-vantage incidents (max 25
vantages on one cause), 40 contradictions, 494 flap cycles, 0 silent devices;
**4,989 lines provably not promotable** (BGP route churn / update bursts —
tracker 184). Promoted signals 75,199 (t-nominal: 44,280).

## 2. Harness phases
preflight PASS · onboard PASS (ratio 0.64) · burst PASS 900,000/900,000 @
1,000/s · drain PASS **1,056 s** (nominal 380–425 s: +70 % promoted signals,
storm mode active) · **correlation_completion PASS 2,171 s** (cohorts +33,
0 rejections) — but **65,077 stream-time evictions** (nominal ~17.8k): pending
reached 0 partly by expiry after the stall · accounting PASS (exact) · **memflat
FAIL** — ClickHouse: 2 MEMORY_LIMIT_EXCEEDED, victims = the api backfill
worker's unbounded `corr_objects` fold (tracker 186); level fine (peak 2,436
MiB = 59 %, p99 1,606); correlation FLAT ×1.21 · **stability FAIL** — worst loop
stall **114,848 ms** > the 30 s Kafka session timeout → consumer ejected (224
UnknownMemberId, 4 CommitFailed, 4 consumer restarts) · cleanup PASS.

## 3. Engine (replica-4, run total)
cohorts 62 (33 in budget) · versions persisted 67,695 / damped 5,272 /
**heartbeat_touch 126** (storm incidents live long enough — the touch fires
here, not on nominal) · rank memo **88 %** hits (224,576 / 259,336; storm
repeats are what it caches) · storm mode active: deduped 135,893, aggregated
45,337 · prefilter rejected 1,317,804 / passed 75,199 · open objects peak 9,999
(cap) · evidence lag peak ~100 s · loop lag max 114,848 ms.
Stage profile: `persist.decision` 4,545 s (max 23.7 s) · `handle.syslog`
2,437 s (max 82 s — starved behind the stall) · `run_window` 1,243 s (140
calls) · `persist.batch_flush` 867 s (**max 116.5 s**) · `persist.evidence`
872 s (max 126 s).

## 4. Root causes (both fixed)
- **Tracker 185** (`675966cd`): every offload gate sized work by nodes+edges;
  the storm-noise aggregate has 922 nodes, 0 edges and ~95k signals, so its
  O(signals) hashing/serialisation ran on the loop thread; the batcher also
  had no row cap and awaited the INSERT under its lock. Fixed: signal-aware
  `_snap_cost`, 20,000-row dedup-safe block splitting; residuals (lock scope,
  gen-2 GC pauses) in build.
- **Tracker 186** (`0af9c896`, deployed): time-intel backfill folded the whole
  history every 15 min and had been failing every pass.

## 5. TTUR on storm incidents (clean scope, aggregate cid excluded)
5,889 incidents · 18,928 versions (3.21/inc) · Σ signals 82,808 · T1 p50 857 s
· **p95 1,376 s** · p99 1,499 s · max 1,786 s · T-last p95 3,099 s · merged 221 ·
undetermined 651 · **confirmed 0** — despite 135 multi-vantage incidents no
verdict reached `confirmed`; to be read against the twin scorer (whose queries
must first be bounded — it ran 329 unbounded SELECTs in an hour and was stopped).

## 6. Next
Residuals → redeploy → clean `t-storm-2.5k` (stability/memflat PASS expected)
→ P3 build → A/B on `t-storm-10-2.5k` / `t-storm-25-2.5k` → P4.
