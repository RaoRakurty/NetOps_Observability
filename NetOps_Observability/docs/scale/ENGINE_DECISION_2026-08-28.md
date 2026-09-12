# Correlation engine — scaling decision (2026-08-28)

Synthesis of the independent market benchmark (`/var/tmp/Correlix_Correlation_
Engine_Market_Benchmark.docx`) + Fable engineering. **Decision: one bounded
architecture-hardening pass → prove 2-worker scale-out → publish a tiered
envelope → STOP. Defer the Go rewrite and global orjson.**

## What the benchmark corrected in our own scale report (accepted)
- "The limit is not the algorithm" → **"bottleneck is implementation-level
  serialization/persistence, not candidate-search complexity."** (Search is
  optimized; serialization IS engine execution.)
- **Removed "5–20× under the physical ceiling"** from external material — no
  public benchmark matches our replayable-causal-graph + evidence + persistence
  contract, so the multiple is unsubstantiated. Internal-directional only.
- **Removed "exactly like Moogsoft"** — Moogsoft v9 scales its ingestion/UI, NOT
  its correlation core [ref 18]. Keep Flink/Kafka-Streams (partition-by-key).
- **Adopted the sizing formula:** `safe devices/shard = 0.70 × sustainable
  unique-correlation EPS/shard ÷ p95 unique EPS/device × skew`. At 0.05–0.26
  eps/device → ~270–3,500 devices/shard. Device count is event-rate-dependent.
- **Added time-to-first-useful-RCA** — survival + eventual drain ≠ timely outage
  explanation. Now a first-class gate.
- MSP (tenant-shard, parallel) vs single-enterprise (one domain until topology
  partitioning) — already our position.

## Where we pushed back (nuance)
- Lever 3 (chunk the hash serialize) was a SYMPTOM fix, not wrong — but the ROOT
  fix is bounding the OBJECT size (below), which shrinks serialization on every
  path (hash AND insert-body). Lever 3 stands as a safe interim.
- **orjson holds the GIL** [ref 16] (we were wrong to think it releases it) — but
  being fast makes the hold SHORT, so it's viable on NON-HASH paths only, after
  byte-compat tests. Never on the canonical replay hash.
- **Process isolation is already ours** — correlation replicas are separate
  containers/processes, not threads. The gap is bounding per-shard work + more
  shards, not the isolation model.
- The 500ms / p95≤5s / p99≤15s gates are good internal bars but SLA-calibratable;
  not hard external promises pre-customer.

## P0 — the one boundedness pass (before any 2.5K GA claim)
1. **Bound the parent RCA object** — decision + summary + state + counts +
   REPRESENTATIVE evidence in the parent; full evidence/edges/provenance as
   PAGED CHILD rows keyed by incident/object id. (Root fix for the 17.7s stall.)
2. **Bound every synchronous work unit** — row/byte/time budget on serialize +
   persist, yield between chunks; measure loop/scheduler lag directly.
3. **Storm mode (overload control)** — detect queue age/rate → dedup repeats,
   prioritize major/critical evidence, aggregate low-value repeats into counters,
   PRESERVE raw in the bus/store for replay. The "handle it maturely" answer.
4. Keep canonical hash serialization stdlib + byte-exact (replay pin).
5. Don't trade the stall for bad ClickHouse writes — batch ≥1,000 rows (ideally
   10k–100k) or reliable async inserts [ref 15]; separate bounded serialize from
   efficient DB batching.

## P1 — prove, then STOP
- Re-run standardized 1K + 2.5K after P0 against the acceptance gates (safety,
  work-unit ≤500ms, storm decision p95≤5s/p99≤15s, recovery, auditability).
- Run 5K on TWO independent 4-core worker processes/nodes → demonstrate **≥1.6×
  sustainable throughput (80% scale efficiency)**, no loss, no p99 regression,
  under BOTH balanced and skewed (hot-key) storm shapes.
- Publish the tiered envelope (Validated 1K / Conditional 2.5K / Scale-out >2.5K)
  with workload assumptions + an overload-behavior statement. **Then freeze
  optimization** until a prospect exceeds the tier.

## Deferred
Full Go rewrite; global orjson migration (esp. hash/replay paths); micro-
optimizing every serializer without first bounding object size + work duration;
any linear-scaling claim before the two-worker proof.

See [[capacity-and-pricing-model]], docs/scale/SHARDING_AND_CAPACITY_MODEL_2026-08-28.md,
docs/scale/CORRELATION_THROUGHPUT_TARGET_2026-08-27.md.
