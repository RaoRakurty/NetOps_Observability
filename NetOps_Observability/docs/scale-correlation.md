# Correlation engine — horizontal scale by tenant-keyed co-partitioning (scale P0)

**Status: shipped.** GA blocker: the correlation engine was a single asyncio
event loop over one 12-topic consumer — measured ceiling ~850–1050 events/s,
CPU-bound on one core, with Kafka buffering the excess unboundedly (lag and
RCA latency grew without limit). This document is the operating manual and
the design record for the fix.

## The design in one paragraph

Every producer onto the 12 consumed topics keys each record by **the tenant
the engine will attribute it to** (`"global"` for platform/untagged — the
same fold `canon_tenant` applies), hashed with the **Java-compatible murmur2**
partitioner. Every `netops.*` topic is created with the **same partition
count** (`BUS_PARTITIONS`). The consumer group uses the **range assignor**
(aiokafka's default RoundRobin is explicitly overridden — it does not keep
partition k of every topic on one member). Result: instance k of
`--scale correlation=N` owns partition k of EVERY topic — a complete,
disjoint slice of tenants with worker-local state, Kafka-Streams-style
co-partitioned tasks. The engine core was verified tenant-partitioned
(`run_window` refuses a mixed-tenant window; every in-memory correlation
structure is tenant-keyed), so N slices produce the union a single instance
would — see “Equivalence” below for the two honest caveats.

## Operating it

```bash
# 1. Raise the shared partition count (once, before scaling out):
#    set in deployment/docker/.env (or the install env)
BUS_PARTITIONS=4

# 2. Re-run topic init (idempotent; ALTERs existing topics UP, never down):
docker compose --profile embedded-bus up kafka-init

# 3. Scale the consumer:
docker compose up -d --scale correlation=4
```

* Replicas beyond `BUS_PARTITIONS` sit idle (range assignor assigns them
  nothing). Keep `N <= BUS_PARTITIONS`.
* Each replica logs its ownership at every rebalance
  (`rebalance #k: assignment=...`) and exposes it on `/healthz` under
  `consumer.assignment`. A `CO-PARTITIONING BROKEN` error log means topic
  partition counts diverged — re-run kafka-init and check
  `kafka-topics.sh --describe`.
* All replicas run one group (`netops-correlation`) with the range assignor;
  do not run mixed code versions with different assignors in one group (the
  coordinator needs a common protocol).

### Scale-up drain note (keyed data written before the increase)

Kafka never re-shuffles existing data: records produced BEFORE a partition
increase stay in the old partitions; only NEW records hash over the new
count. During the transition a tenant's in-flight backlog can therefore be
consumed by a different instance than its new traffic. This is the standard
Kafka scale-up semantics and is acceptable here because signals are
idempotent (deterministic ids + ClickHouse dedup tokens) — but correlation
WINDOWS spanning the transition may split transiently. For a clean cut:
quiesce producers (or pick a quiet window), let the consumer group drain lag
to ~0, run kafka-init with the new `BUS_PARTITIONS`, then scale out. The
same transient applies for ~60s whenever a device moves tenants in
`device_tenant.csv` (producer keying and consumer attribution refresh the
registry independently).

### ⚠ In-memory state does not follow partition ownership (tracker 155)

The drain note above scopes window splitting to a partition **increase**. That
understates it. `OPEN_OBJECTS` is a plain in-process dict initialised empty
(`main.py:910`) and **nothing rehydrates it** — there is no restore, no
checkpoint and no transfer between members. `on_partitions_revoked` flushes and
commits durable output but evicts no window state; `on_partitions_assigned`
records ownership and reconstructs nothing.

So on **any** ownership movement — replica restart, scale up or down, crash,
deployment, broker disturbance, not only a partition raise — the new owner
begins with an empty window for the tenants it just acquired, and the previous
owner holds state for tenants it no longer serves. Evidence accumulated in a
window that spans the move is lost. Nothing errors; the loss is silent and shows
up only as RCA that is missing, split, or under-evidenced.

Practical consequences until tracker 155 is resolved:

* Treat a correlation restart under `--scale N>1` as an event with a
  **correctness cost**, not merely a availability blip. Prefer quiet windows.
* Do not read "lag returned to zero" as "correlation recovered" — lag measures
  offsets, not window continuity.
* **Automatic `BUS_PARTITIONS` sizing is frozen** until state reconstruction or
  transfer is proven correct, however good the throughput numbers look.

### Partition budget: one setting, 17 topics, 12 of them consumed

`BUS_PARTITIONS` is a **multiplier on broker cost, not a single count**.
`kafka-init` applies it to all **17** bus topics it creates, against a
single-node KRaft broker — so `BUS_PARTITIONS=4` is ~68 broker partitions and
`=16` is ~272. Budget the broker, not just the consumer, before raising it.

Correlation subscribes to **12** of those 17 (`main.py` `TOPICS`). The other
five — `netops.applogs`, `netops.flows.raw`, `netops.cloudlogs`,
`netops.cloudcosts`, `netops.deadletter` — carry the same partition count for
no correlation benefit: roughly 29% of the partition cost buys no parallelism.

Whether one global partition control should keep applying to every bus topic,
or split by workload class (high-volume telemetry / correlation-critical /
low-volume control), is an open architecture question. **Do not re-partition
topics individually as a side effect of scale work** — it needs its own design
review and its own correctness qualification.

`python3 scripts/install.py --replan` prints the resulting broker partition
total, the max useful replica count, and the expected idle-replica count; see
`docs/RESOURCE_SIZING.md` for the resolution order and the raise-only rule.

## Producer / keying matrix (after this change)

| Topic | Producer(s) | Kafka client | Key (before → after) | Partitioner |
|---|---|---|---|---|
| netops.syslog | vector-aggregator `kafka_syslog` (+ quarantine restores via bus bridge) | librdkafka | none → tenant (registry via hostname) | `murmur2_random` |
| netops.snmptrap | vector-aggregator `kafka_snmptrap` | librdkafka | none → tenant (registry via device/host) | `murmur2_random` |
| netops.probes | vector-aggregator `kafka_probes`; rca-canary + api via bus bridge | librdkafka | none → tenant (registry via target; bridge: event tenant_id) | `murmur2_random` |
| netops.metrics | vector-aggregator `kafka_metrics` | librdkafka | none → tenant (registry via device) | `murmur2_random` |
| netops.cloud | vector-aggregator `kafka_cloud`; cloud-ingest poller | librdkafka; kafka-python | none → event `tenant_id` (`"global"` fallback) | `murmur2_random`; kafka-python default (murmur2) |
| netops.flows | **new:** vector-router `kafka_flows_keyed` (re-key hop) | librdkafka | none → tenant (registry via sampler_address) | `murmur2_random` |
| netops.flows.raw (new) | goflow2 | sarama | unkeyed (random) — deliberately; nothing consumes it by partition | n/a |
| netops.app.identities.v1 | Go fusion worker via bus bridge → `kafka_bus` | librdkafka | tenant (already) — bridge now folds ""→"global" | `murmur2_random` |
| netops.controller_events | Go NMS scheduler via bus bridge | librdkafka | tenant (already) | `murmur2_random` |
| netops.app.edge | rca-canary / future producers via bus bridge | librdkafka | envelope key → event tenant_id preferred | `murmur2_random` |
| netops.verification | Go verify service via bus bridge | librdkafka | tenant (already) | `murmur2_random` |
| netops.wireless_sessions / _events | external producers via bus bridge | librdkafka | event tenant_id → envelope key → "global" | `murmur2_random` |

Partitioner compatibility is the load-bearing subtlety: **the same tenant
string must hash to the same partition NUMBER at every producer.** Java's
murmur2 (`hash & 0x7fffffff % N`) is the reference; librdkafka's
`murmur2_random` and kafka-python's DefaultPartitioner match it, and both are
pinned by `tests/test_bus_partitions.py`. librdkafka's DEFAULT
(`consistent_random`) is CRC32 and does NOT match — never remove the
`librdkafka_options.partitioner` line from a keyed sink. goflow2's sarama
hash partitioner is FNV-1a and cannot match — that is WHY flows are re-keyed
by the router instead of keyed at goflow2.

### The flows re-key hop

goflow2 has no device→tenant knowledge and an incompatible partitioner, so it
now produces `netops.flows.raw` (unkeyed). The vector-router — which already
owns flow tenancy attribution for storage — consumes the raw topic
(`kafka_flows_raw`, group `netops-router-flows-rekey`) and republishes each
record **payload-untouched** onto `netops.flows`, keyed by the exporter's
tenant (`sampler_address` → `device_tenant.csv`). Everything downstream of
`netops.flows` (router storage pipeline, F-11 quarantine/restore loop, the
correlation consumer and its registry-anchored re-verification) is unchanged.
Costs, stated plainly: flows traverse the bus twice (the classic Kafka
Streams repartition-topic cost), and the correlation flow feed now depends on
router liveness (previously only storage did). ACLs: ANONYMOUS (goflow2)
moved to produce-only on `netops.flows.raw`; the router gained produce on
`netops.flows` (`deployment/docker/kafka/apply-acls.sh`).

### Keying rules for any FUTURE producer

1. Key by the event's tenant, exactly as the engine will attribute it
   (registry value for device-derived lanes, the event's `tenant_id` claim
   for claim-accepted lanes). Empty/unknown → the literal `"global"`.
2. Use a Java-murmur2-compatible partitioner.
3. Never key by device/host/resource — high-cardinality keys scatter one
   tenant across partitions and silently break the slice equivalence.
4. Bus-bridge producers (`{topic, key, event}` envelopes): stamp
   `tenant_id` in the event; the bridge prefers it, then the envelope key,
   then `"global"`.

## Consumer side

* `src/correlation/main.py build_consumer()`: range assignor pinned
  (`partition_assignment_strategy=(RangePartitionAssignor,)`), subscription
  via `subscribe(..., listener=_AssignmentLogger(...))` so every rebalance is
  logged and the co-partition invariant checked.
* `tenant_partition(tenant, n)` mirrors the producers' hashing and is the
  single in-process answer to "which instance owns tenant T". The cloud-log
  tailer (a file-based singleton side-input) uses it to elect exactly one
  replica — the one owning `CLOUD_LOGS_TENANT`'s partition — and fails OPEN
  before the first rebalance so single-replica/broker-less dev behavior is
  unchanged.
* Commit/replay semantics are unchanged (manual batched commits; dedup
  tokens absorb redelivery, including partition hand-offs at rebalance).

### Group-membership tuning (P1 max-poll rebalance thrash, 2026-08-16)

The G2 mini-ladder measured the defect live: a 24k-event backlog put the
consumer in a session-expiry rebalance loop (78× `UnknownMemberIdError`,
9× `CommitFailedError`, 3 supervisor restarts; drain collapsed ~1k/s → ~40/s,
lag never returned to baseline). Container logs showed 17-second event-loop
stalls — beyond aiokafka's 10 s `session_timeout_ms` default — so the broker
ejected the member, the commit failed, the batch replayed, repeat.

The stalls are fixed structurally (`run_window` in an executor; cooperative
yield every `CORR_CONSUME_YIELD_EVERY_N` messages in the consume loop —
aiokafka's buffered fast path never yields on its own; batched CH writes).
`build_consumer()` additionally pins an honest membership contract
(env-tunable, defaults in `main.py`):

| Setting | Default | Arithmetic |
|---|---|---|
| `CORR_SESSION_TIMEOUT_MS` | 30000 | worst measured loop latency with the engine chewing a storm window in the executor is ~0.2 s (GIL convoy); 30 s tolerates a >100× regression plus GC/CPU-throttle pauses |
| `CORR_HEARTBEAT_INTERVAL_MS` | 3000 | session/10 (Kafka guidance ≤ 1/3) |
| `CORR_MAX_POLL_INTERVAL_MS` | 300000 | worst legitimate poll gap = one loop iteration ≈ handler (≤5 direct CH inserts × 10 s httpx timeout) + commit (flush ≤10 s/table + 30 s commit bound) ≈ 90 s ≪ 300 s; a bigger gap is a real wedge and SHOULD leave the group |
| `CORR_REBALANCE_TIMEOUT_MS` | 60000 | revoke hook bound = one flush (≤10 s) + one commit (≤30 s) |
| `CORR_CONSUME_YIELD_EVERY_N` | 20 | 20 msgs × ≤10 ms/event sync CPU = ≤200 ms between loop hand-backs ≪ heartbeat 3 s |

### Bounded event-loop blocking (P1 regression at 1000-device scale, 2026-08-17)

The tuning above was **not sufficient**: the next ladder run (1000 devices,
600k events @ ~1784/s) reproduced the rebalance loop, and the honest cause was
a different one. Live evidence from `netops-correlation-2`:

```
03:34:47Z  corr-object 859c45d9 v4 open: ... nodes=750 edges=48375
```

The object **count** stayed small (5–15 per 5-minute interval, verified against
`netops.corr_objects`) but each object was **enormous** — a 1000-device fleet
emits one uniform link-fault signature, so the whole access layer folds into a
few giant graphs. Every per-object step is then a *single monolithic
synchronous call* whose cost scales with the graph. Measured on that exact
750-node / 48,375-edge shape:

| Call | Blocking |
|---|---|
| `ObjectSnapshot.content_hash()` | 1.60 s |
| `to_object_row()` | 0.66 s |
| `to_typed_edge_rows()` | 0.40 s |
| `to_evidence_rows()` | 0.31 s |
| `to_edge_rows()` | 0.16 s |
| `material_hash()` | 0.13 s |
| `CH.insert` NDJSON body build (22.5 MiB) | 0.68 s |
| `CHBatcher` content-hash token | 0.93 s |
| **per object, per cycle** | **~7.5 s** |

At 10–15 such objects that is **75–110 s of loop-owning time per cycle**, which
matches the 84 s / 193 s / 421 s gaps in the container log (2003 gaps ≥5 s,
44,340 s total).

**The mechanism is CUMULATIVE starvation, not one monster call.** No single call
above blocks for 30 s — the largest measured is 1.60 s. aiokafka runs
heartbeat/coordinator work in *background asyncio tasks*, so it is enough for the
loop to be owned by a long back-to-back *sequence* of medium blocks across the
session window: the heartbeat task simply does not get scheduled often enough.
That is why the session expires (→ `UnknownMemberIdError`) and the commit then
fails (`CommitFailedError`, poll gap past `max_poll_interval_ms`) → the batch
replays → repeat. **Cooperative `asyncio.sleep(0)` yields cannot fix it** —
each individual call is a single uninterruptible C-level `json.dumps`/`sha256`,
so there is no point *inside* one at which a yield could run; the work has to
leave the loop thread entirely.

The fix is structural, not tuned: every size-unbounded pure-CPU step goes
through `main._offload` (the default thread-pool executor). Measured on the
same object, inline froze the loop for **2.40 s**; offloaded the worst loop
latency was **0.39 s** — the loop keeps running no matter how large the object
gets, because the blocking call no longer owns the loop thread. Objects below
`CORR_OFFLOAD_MIN_ELEMENTS` (default 2000 nodes+edges, ≈0.1 s of work — 30×
under the 3 s heartbeat) keep the zero-overhead inline path.

A **loop-lag watchdog** (`loop_lag_watchdog`) now samples the loop's own
scheduling delay and counts stalls over `CORR_LOOP_LAG_WARN_MS` (default 1000,
3× under the heartbeat interval), surfaced as `corr_loop_lag_stalls_total` /
`corr_loop_lag_max_ms` and on `/healthz` — so the next blocker reports itself
instead of having to be inferred from gaps between log lines.

### Consumer state is a FOUR-value enum on `/healthz`

`consumer.state` distinguishes states that used to be indistinguishable:

| State | Meaning |
|---|---|
| `pending` | no assignment callback has run yet — says nothing about health |
| `idle` | joined the group, holds **zero** partitions. A **misconfiguration**: replicas beyond `BUS_PARTITIONS` get an empty set from the range assignor and consume nothing forever. Also counted as `corr_consumer_zero_assignments_total` with a WARNING naming cause and remedy |
| `cold_window` | holds partitions, at least one acquired less than one engine window ago — those tenants' RCA is **thin (degraded), not wrong** |
| `active` | holds partitions, all held for at least one engine window |

Previously `pending` and `idle` both serialized to `{}`, so a surplus replica
looked healthy forever while contributing no throughput. The state is computed
from *recorded assignment facts* (`CONSUMER_ASSIGNMENT_SEEN`,
`CONSUMER_PARTITION_ACQUIRED_AT`), never from `rebalances > 0` — that is racy
(the counter is bumped inside the callback) and cannot express `cold_window`.
`consumer.cold_partitions` names *which* partitions are thin, and
`corr_consumer_state{state=...}` / `corr_consumer_cold_partitions` are scraped.

**Honest limitation (tracker 155, NOT fixed here).** `cold_window` is a
*time-based proxy* for "the sliding window has not had time to refill". It is
not a measurement of carried-over state: `OPEN_OBJECTS` and `WINDOW_BUFFER` are
per-process with **no rehydration path**, so a partition acquired at a rebalance
necessarily starts with none of its tenants' in-flight correlation state — that
state is stranded in whichever replica held the partition before, and merges and
continuations that depended on it are lost. No elapsed time repairs that, so
**`active` must not be read as "no state was lost at the last rebalance"**. With
one replica this was a rare restart edge; with N replicas plus rebalances it is
routine, which is what tracker 155 covers.

### The revoke hook was an amplifier — now tightly bounded

`on_partitions_revoked` awaits the flush-then-commit hook, and the first version
capped the whole hook at `rebalance_timeout` (60 s). That callback runs **inside
the rejoin**, so a slow ClickHouse flush could add up to a full rebalance
timeout of latency *per revoke* — the hook that exists to break the thrash could
instead deepen it (starve → revoke → 60 s of flush I/O → re-revoke). The live
counters from the thrash window fit that reading: correlation-1 logged **20
rebalances against 17 hook runs, 6 of them FAILED** (i.e. hitting the bound).

Each leg now gets its own small budget, `CORR_REVOKE_BUDGET_S` (default 5 s),
with a 2× backstop on the whole hook — worst added rejoin latency ~10 s, ≤1/6 of
`rebalance_timeout` instead of equal to it. If the flush misses its budget the
hook **skips the commit and returns** (counted as
`corr_consumer_revoke_commits_total{outcome="skipped"}`): F-38 is preserved by
*not acknowledging*, never by waiting longer — the successor replays and the
per-message dedup tokens plus the batcher's commit guard absorb it.

**Deliberately NOT changed:** the dead-letter write path stays synchronous.
Microbenchmarked on the live volume it is p50 102 µs / p99 429 µs / max 7.1 ms
per record (~7.5k/s ceiling). More importantly it was **refuted empirically**:
in a 600k-event verification burst every event was tenant-refused and
dead-lettered, driving ~2.3k *synchronous* DLQ writes/s per replica — above the
ladder's 1784/s total — and the loop-lag watchdog recorded **max 633 ms drift
and ZERO stalls** while the backlog drained at ~3.7k events/s with zero
rebalances. A batched off-loop variant was prototyped and reverted: it trades
the immediate-durability property that seven durability tests and the
238k-lost-payload incident (`dlq_startup_check`) rest on for a saving that is
measurably not on the critical path. If `corr_loop_lag_stalls_total` ever
implicates it, the watchdog will say so with a number, and it gets its own
change then.

Regression suite: `src/correlation/test_loop_blocking.py`.

On `on_partitions_revoked` the consumer now flushes the signal batch and
commits exactly the handled-offset ledger (never the in-flight message —
F-38), so a rebalance no longer replays the whole uncommitted batch; a
member ejected between flush and commit is absorbed by the batcher's
commit guard (redelivered rows are not re-inserted — `corr_signals` is
plain MergeTree and would otherwise duplicate). Regression suite:
`src/correlation/test_consume_poll_cadence.py`.

## HTTP endpoints under `--scale N` (Docker DNS round-robins `correlation:8000`)

| Endpoint | Backing | Multi-replica semantics |
|---|---|---|
| `/findings`, `/correlations/{id}/replay` | ClickHouse | replica-safe — any replica answers identically |
| `/analyze` | stub | replica-safe |
| `/healthz` | in-memory | PER-INSTANCE diagnostic; now includes `consumer.assignment` naming which slice answered |
| `/metrics` | in-memory counters | PER-INSTANCE; scraped per replica via `dns_sd_configs` (vmscrape.yml + vmscrape-mtls.yml) so `increase()`/flat-line alerts stay truthful. A static target would round-robin N processes into one lying series. |
| `/deadletters` | in-memory ring | PER-INSTANCE diagnostic (each replica holds its own quarantine ring; the durable NDJSON in `CORR_DLQ_DIR` is shared across replicas — per-line appends interleave; rotation under N>1 may interleave generations) |

## Equivalence (what "N slices ≡ 1 instance" precisely means)

A dedicated audit verified the engine core is tenant-partitioned: clustering
(`run_window`) hard-rejects mixed-tenant windows, merges/continuations guard
on tenant, and every correlation-bearing in-memory structure is
tenant-keyed. One true cross-tenant coupling was found and FIXED with this
change: the syslog burst tracker (`SYSLOG_BUCKET`) was keyed by hostname
alone and is now keyed `(tenant, hostname)`, with the burst finding stamped
with the verified tenant (`test_scale_copartition.py` pins it).

Two honest caveats remain, both **capacity semantics**, not correctness:

1. **Per-process caps become per-slice caps.** `WINDOW_BUFFER` (maxlen),
   the episode-detector/z-score series LRU budgets, and the `storm_mode`
   degradation flag are per-process. Under saturation a single instance
   sheds/annotates across all tenants, while sliced instances each get a
   full budget — sliced output is the same-or-better, never worse. Below
   the caps (the normal regime) outputs are identical;
   `test_scale_copartition.py::test_tenant_slices_reproduce_the_single_instance_output`
   proves the sub-saturation equivalence over the keying function.
2. **Registry refresh skew.** Producers and consumers reload
   `device_tenant.csv` independently (≤60s apart), so a device that changes
   tenants can have events keyed under the old owner briefly (see the drain
   note).

## Files (the whole change)

* `src/correlation/main.py` — range assignor + `build_consumer()` factory,
  assignment logging/health, `tenant_partition`/`owns_tenant`, tailer
  election, tenant-scoped `SYSLOG_BUCKET`.
* `deployment/docker/vector/vector.yaml` — `__key` stamping on the
  syslog/snmptrap/probes/metrics/cloud lanes + bus-bridge tenant preference;
  murmur2 + key-strip on all keyed sinks.
* `deployment/docker/vector-router/vector.yaml` — `kafka_flows_raw` source,
  `flows_rekey` transform, `kafka_flows_keyed` sink.
* `deployment/docker/docker-compose.yml` + `compose.tls.yml` — kafka-init
  `BUS_PARTITIONS` create/alter, `KAFKA_NUM_PARTITIONS` alignment, goflow2
  raw topic, correlation scale notes.
* `deployment/docker/kafka/apply-acls.sh` — raw-topic + router-produce ACLs.
* `deployment/docker/cloud-ingest/producer_guard.py` — tenant keying choke
  point for the poller.
* `src/config/vmscrape.yml` / `vmscrape-mtls.yml` — per-replica DNS scrape.
* Tests: `src/correlation/test_scale_copartition.py`,
  `tests/test_bus_partitions.py`,
  `deployment/docker/cloud-ingest/test_producer_guard.py` (keying).
