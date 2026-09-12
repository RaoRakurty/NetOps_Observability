# Sharding & capacity model — two deployment scenarios (2026-08-28)

Owner direction (2026-08-28): follow industry-standard horizontal sharding; size
capacity for TWO scenarios — (A) single large enterprise (one tenant, big
network) and (B) MSP (many tenants). Fable architecture.

## The governing constraint
Correlation only happens WITHIN a shard (events must be processed together to
relate). So the **shard key determines what can correlate**, and that splits the
two scenarios by difficulty. Industry pattern (Flink/Kafka-Streams/Moogsoft):
**deterministic single-threaded shards, scaled horizontally.** We already have
this — the Kafka consumer group shards partitions across correlation replicas;
each replica is single-threaded for determinism/replay (a deliberate, correct
choice, and Python's GIL makes intra-shard threads useless anyway).

## Scenario B — MSP / multi-tenant (the EASY, clean axis)
**Shard by TENANT.** Each tenant's events → its own shard; all of that tenant's
cross-device/cross-seam correlation stays inside one shard (preserved);
cross-tenant correlation is forbidden (§3a) so no cross-shard coordination is
needed. Tenants are **embarrassingly parallel** — add cores/nodes → add tenants.
- **max devices / tenant = the single-shard ceiling.**
- **max tenants = total cores ÷ cores-per-shard** (+ per-tenant fixed overhead).
- Scales the way the vendors scale. Smaller lift: make sharding tenant-aware.

## Scenario A — single large enterprise (the HARD one)
One tenant, one big network = **one correlation domain** (every device may relate
to every other — the seam-owned-RCA value). To preserve that it wants ONE shard →
**bounded by the single-shard ceiling.** To exceed it, shard the network by
**topology domain / seam** (regions that correlate internally) **plus a
cross-domain correlation layer** — the genuinely hard distributed-correlation
problem. Defer until a prospect actually has a network this big.

## Both scenarios bottom out on the SAME number
**The single-shard ceiling** (eps a deterministic shard sustains ÷ per-device eps
≈ devices). That is exactly what the scale-testing programme measures (~1,000
eps/core today, storm-limited; resilience fixed so a shard never dies). At
measured production (0.05–0.26 eps/device) a ~1,000-eps shard ≈ 4k–20k devices
NOMINAL per shard; a design storm is the stress bound.

## Plan (staged, industry-standard)
1. **Tenant-aware sharding** — route a tenant's partitions to a dedicated shard
   set (the clean MSP axis, smaller lift). [next]
2. **Measure the single-shard ceiling** — devices/tenant at nominal AND storm.
   The "big day" number; it's per-shard.
3. **Horizontal-scaling measurement** — 2 → N shards; confirm tenants scale
   linearly with cores.
4. **Topology-domain sharding + cross-domain correlation** — the big-network
   project (Scenario A beyond one shard). Deferred until a real prospect needs it.

## Pricing/capacity tie-in
- MSP: price per tenant + per device; capacity = shards × per-shard devices.
- Enterprise: per device; capacity = single-shard ceiling (until topology sharding).
- Burst = SLO not billing (a shard SURVIVES a storm; absorbing it is the SLO knob).
See [[capacity-and-pricing-model]], [[three-project-portfolio]].
