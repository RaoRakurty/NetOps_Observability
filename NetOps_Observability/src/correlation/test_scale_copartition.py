"""Scale P0 — tenant-keyed co-partitioning (run: python3 -m pytest test_scale_copartition.py).

The horizontal-scale contract has three legs, each pinned here:

  1. KEYING — every producer keys a record by the tenant the engine will
     attribute it to (fallback "global"), hashed with the Java-compatible
     murmur2 partitioner. `tenant_partition` is the in-process mirror of that
     rule; these tests pin it against an INDEPENDENT reimplementation of the
     Java algorithm so a drift in aiokafka's murmur2 (or an accidental swap to
     CRC32/FNV) fails loudly instead of silently splitting tenants.
  2. ASSIGNMENT — the consumer must use the RANGE assignor. aiokafka's default
     is RoundRobin, which spreads TopicPartitions without keeping partition k
     of every topic on the same member — that silently breaks tenant
     stickiness across the 12 lanes. build_consumer() is the factory under
     test.
  3. EQUIVALENCE — partitioning a recorded multi-tenant window by the keying
     function into N slices and running each slice through the pure engine
     yields exactly the union the single instance produces. (The engine core
     is per-tenant by construction — run_window refuses a mixed window — so
     this holds as long as the keying function never splits one tenant.)
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import ClassVar

from aiokafka.coordinator.assignors.range import RangePartitionAssignor

import main
from catalog import builtin_catalog
from engine import run_window
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 6, 12, 9, 42, 0, tzinfo=timezone.utc)


# ── leg 1: keying ───────────────────────────────────────────────────────────

def _java_murmur2(data: bytes) -> int:
    """Independent reimplementation of Kafka's Java murmur2 (org.apache.kafka
    .common.utils.Utils#murmur2) — the reference every producer-side
    partitioner in this deployment claims compatibility with (librdkafka
    `murmur2_random`, kafka-python DefaultPartitioner, aiokafka)."""
    length = len(data)
    seed = 0x9747B28C
    m = 0x5BD1E995
    r = 24
    mask = 0xFFFFFFFF
    h = (seed ^ length) & mask
    n = (length // 4) * 4
    for i in range(0, n, 4):
        k = int.from_bytes(data[i:i + 4], "little", signed=False)
        k = (k * m) & mask
        k ^= k >> r
        k = (k * m) & mask
        h = (h * m) & mask
        h ^= k
    left = length % 4
    if left >= 3:
        h ^= (data[n + 2] & 0xFF) << 16
    if left >= 2:
        h ^= (data[n + 1] & 0xFF) << 8
    if left >= 1:
        h ^= data[n] & 0xFF
        h = (h * m) & mask
    h ^= h >> 13
    h = (h * m) & mask
    h ^= h >> 15
    # Java int is signed 32-bit; the partitioner masks with 0x7fffffff, which
    # erases the sign either way — return the unsigned 32-bit value.
    return h


def test_tenant_partition_matches_java_murmur2_reference():
    corpus = ["global", "t_acme", "t_9f31c2", "rca-canary", "tenant-with-dash",
              "ünïcode-tenant", "a", "ab", "abc", "abcd", "abcde", ""]
    for n in (1, 2, 3, 4, 6, 12, 16):
        for t in corpus:
            key = (t or "global").encode("utf-8")
            expect = (_java_murmur2(key) & 0x7FFFFFFF) % n
            assert main.tenant_partition(t, n) == expect, (t, n)


def test_empty_tenant_keys_as_global():
    """canon_tenant folds "" → "global"; the key derivation must follow, or the
    platform tenant's events would split between two partitions."""
    for n in (2, 3, 4, 12):
        assert main.tenant_partition("", n) == main.tenant_partition("global", n)


def test_single_partition_owns_everything():
    assert main.tenant_partition("anything", 1) == 0
    assert main.tenant_partition("anything", 0) == 0  # defensive floor


# ── leg 2: consumer wiring ──────────────────────────────────────────────────

class _Recorder:
    """AIOKafkaConsumer stand-in that records construction + subscription."""

    instances: ClassVar[list] = []

    def __init__(self, *topics, **kwargs):
        type(self).instances.append(self)
        self.ctor_topics = topics
        self.kwargs = kwargs
        self.subscribed: tuple = ()

    def subscribe(self, topics=(), pattern=None, listener=None):
        self.subscribed = (tuple(topics), listener)

    def partitions_for_topic(self, topic):
        return {0, 1}


def test_build_consumer_pins_range_assignor_and_subscription(monkeypatch):
    _Recorder.instances = []
    monkeypatch.setattr(main, "AIOKafkaConsumer", _Recorder)
    consumer = main.build_consumer()
    assert isinstance(consumer, _Recorder)
    kw = consumer.kwargs
    # Co-partitioning: RANGE, not aiokafka's RoundRobin default.
    assert kw["partition_assignment_strategy"] == (RangePartitionAssignor,)
    # Existing contracts that must survive the factory refactor:
    assert kw["enable_auto_commit"] is False, "#126: manual commit"
    assert "value_deserializer" not in kw, "raw bytes — decode inside the per-event try"
    assert kw["group_id"] == "netops-correlation"
    # Topics via subscribe() so the rebalance listener observes ownership.
    assert consumer.ctor_topics == ()
    topics, listener = consumer.subscribed
    assert set(topics) == set(main.TOPICS) and len(topics) == len(main.TOPICS)
    assert isinstance(listener, main._AssignmentLogger)


def test_range_assignor_copartitions_equal_partition_counts():
    """The property the whole design leans on: with every topic at N partitions
    and M members, RANGE gives member i the SAME partition set on every topic."""
    from aiokafka.coordinator.protocol import ConsumerProtocolMemberMetadata

    topics = list(main.TOPICS)
    cluster = _FakeCluster({t: 4 for t in topics})
    members = {
        f"member-{i}": ConsumerProtocolMemberMetadata(
            version=0, subscription=topics, user_data=b"")
        for i in range(4)
    }
    assignment = RangePartitionAssignor.assign(cluster, members)
    for member_id, a in assignment.items():
        per_topic = {t: sorted(ps) for t, ps in a.assignment}
        sets = {tuple(ps) for ps in per_topic.values()}
        assert len(sets) == 1, (
            f"{member_id} owns different partition sets per topic: {per_topic}")


class _FakeCluster:
    def __init__(self, partitions: dict[str, int]):
        self._p = partitions

    def partitions_for_topic(self, topic):
        n = self._p.get(topic)
        return set(range(n)) if n else None


# ── rebalance listener + singleton side-input election ──────────────────────

def _fresh_assignment_state():
    main.CONSUMER_ASSIGNMENT.clear()
    main.CONSUMER_PARTITION_TOTALS.clear()
    main.CONSUMER_PARTITION_ACQUIRED_AT.clear()
    main.CONSUMER_ASSIGNMENT_SEEN = False


class _TP:
    def __init__(self, topic, partition):
        self.topic, self.partition = topic, partition


def test_assignment_listener_records_ownership_and_owns_tenant(monkeypatch):
    _fresh_assignment_state()
    consumer = _Recorder()  # partitions_for_topic -> {0, 1}
    listener = main._AssignmentLogger(consumer)
    my_part = main.tenant_partition("t_acme", 2)
    asyncio.run(listener.on_partitions_assigned(
        [_TP(t, my_part) for t in main.TOPICS]))
    assert main.CONSUMER_ASSIGNMENT["netops.cloud"] == [my_part]
    assert main.CONSUMER_PARTITION_TOTALS["netops.cloud"] == 2
    assert main.owns_tenant("t_acme")
    # The other replica's tenant: some tenant hashing to the other partition.
    other = next(t for t in ("t_b0", "t_b1", "t_b2", "t_b3", "t_b4", "t_b5")
                 if main.tenant_partition(t, 2) != my_part)
    assert not main.owns_tenant(other)
    _fresh_assignment_state()


def test_owns_tenant_fails_open_before_first_rebalance():
    """Single-replica / broker-less dev behavior unchanged: with no recorded
    assignment the cloud-log tailer must keep running."""
    _fresh_assignment_state()
    assert main.owns_tenant("any-tenant")


def test_consumer_state_distinguishes_all_four_states(monkeypatch, caplog):
    """FOUR states, not two. /healthz used to render "no rebalance yet" and
    "rebalanced and got NOTHING" byte-identically ({} either way), so an
    instance beyond BUS_PARTITIONS — which the range assignor leaves empty and
    which then consumes nothing forever — looked healthy. And a partition
    acquired at a rebalance starts with an EMPTY window (no rehydration path,
    tracker 155), which an operator must be able to see because RCA for those
    tenants is thin rather than wrong."""
    _fresh_assignment_state()
    monkeypatch.setattr(main, "CONSUMER_ZERO_ASSIGNMENTS", 0)

    # (a) no assignment callback yet — "pending", NOT a misconfiguration.
    pending = asyncio.run(main.health())["consumer"]
    assert pending["state"] == "pending"
    assert pending["owned_partition_count"] == 0
    assert pending["cold_partitions"] == []

    # (d) joined and assigned NOTHING — "idle" + WARNING naming cause + remedy.
    listener = main._AssignmentLogger(_Recorder())
    with caplog.at_level("WARNING", logger="correlation"):
        asyncio.run(listener.on_partitions_assigned([]))
    idle = asyncio.run(main.health())["consumer"]
    assert idle["state"] == "idle", "an empty assignment must not read as pending"
    assert idle["owned_partition_count"] == 0
    assert idle["zero_assignments"] == 1
    msg = " ".join(r.getMessage() for r in caplog.records)
    assert "IDLE" in msg and "BUS_PARTITIONS" in msg, (
        f"the idle warning must name the cause and the remedy: {msg}")

    # (c) freshly acquired partitions — "cold_window": held for less than one
    # engine window, so their tenants' sliding window has not refilled.
    asyncio.run(listener.on_partitions_assigned([_TP(t, 0) for t in main.TOPICS]))
    cold = asyncio.run(main.health())["consumer"]
    assert cold["state"] == "cold_window", (
        "partitions acquired just now cannot have a warm window")
    assert cold["owned_partition_count"] == len(main.TOPICS)
    assert len(cold["cold_partitions"]) == len(main.TOPICS)

    # (b) the same partitions held for longer than one engine window — "active".
    aged = time.monotonic() - (main.ENGINE_CFG.window_s + 1)
    for key in main.CONSUMER_PARTITION_ACQUIRED_AT:
        main.CONSUMER_PARTITION_ACQUIRED_AT[key] = aged
    warm = asyncio.run(main.health())["consumer"]
    assert warm["state"] == "active"
    assert warm["cold_partitions"] == []

    # A retained partition keeps its (aged) timestamp across a rebalance, while a
    # NEWLY acquired one re-cools the replica — the distinction (c) exists for.
    asyncio.run(listener.on_partitions_assigned(
        [_TP(t, 0) for t in main.TOPICS] + [_TP(main.TOPICS[0], 1)]))
    assert main.CONSUMER_PARTITION_ACQUIRED_AT[f"{main.TOPICS[0]}:0"] == aged, (
        "a retained partition must not have its window reset")
    assert main.consumer_state() == "cold_window"
    assert main.cold_partitions() == [f"{main.TOPICS[0]}:1"]
    _fresh_assignment_state()


def test_consumer_state_is_not_derived_from_the_rebalance_counter():
    """The state must come from recorded assignment facts, never from
    `rebalances > 0` — that is racy (bumped inside the callback) and cannot
    express cold_window at all."""
    _fresh_assignment_state()
    main.CONSUMER_REBALANCES = 99          # a lie the state must ignore
    assert main.consumer_state() == "pending", (
        "state inferred from the rebalance counter instead of assignment facts")
    _fresh_assignment_state()


def test_copartition_mismatch_is_an_error(caplog):
    """Diverged partition counts (a failed --alter after raising
    BUS_PARTITIONS) must be LOUD: tenants would silently split otherwise."""
    _fresh_assignment_state()
    listener = main._AssignmentLogger(_Recorder())
    tps = [_TP(t, 0) for t in main.TOPICS] + [_TP("netops.flows", 1)]
    with caplog.at_level("ERROR", logger="correlation"):
        asyncio.run(listener.on_partitions_assigned(tps))
    assert any("CO-PARTITIONING BROKEN" in r.message for r in caplog.records)
    _fresh_assignment_state()


# ── leg 3: tenant-slice equivalence ─────────────────────────────────────────

def _sig(tenant: str, kind: str, entity: str, offset_s: float) -> Signal:
    return Signal(
        tenant_id=tenant,
        ts=T0 + timedelta(seconds=offset_s),
        source=Source.METRIC,
        kind=kind,
        observer=Observer(observer_id="obs1", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY,
        entity_type=EntityType.DEVICE,
        entity_id=entity,
        severity=Severity.HIGH,
        native_id=f"scale|{tenant}|{kind}|{entity}|{offset_s}",
        attrs={"onset_uncertainty_s": 5.0},
    )


def _recorded_stream() -> list[Signal]:
    """A recorded multi-tenant window: several tenants, interleaved arrival,
    same device NAMES reused across tenants (the hostile case for any keying
    that forgets the tenant)."""
    stream: list[Signal] = []
    tenants = ["global", "t_acme", "t_borg", "t_carol", "t_dave", "rca-canary"]
    for ti, tenant in enumerate(tenants):
        for j in range(4):
            stream.append(_sig(tenant, "metric_anomaly", "core-sw1", offset_s=ti + 7 * j))
            stream.append(_sig(tenant, "bgp_state_anomaly", f"edge-{j}", offset_s=ti + 7 * j + 2))
    # interleave deterministically by (ts, id) — arrival order must not matter
    stream.sort(key=lambda s: (s.ts, str(s.signal_id)))
    return stream


def _run_instance(signals: list[Signal]) -> dict:
    """What one correlation instance does with the signals it consumed:
    partition by tenant (engine_cycle) and run the pure engine per tenant."""
    catalog = builtin_catalog()
    by_tenant: dict[str, list[Signal]] = {}
    for s in signals:
        by_tenant.setdefault(s.tenant_id, []).append(s)
    out: dict = {}
    for tenant in sorted(by_tenant):
        for snap in run_window(tuple(by_tenant[tenant]), catalog, ()):
            out[(tenant, snap.correlation_id)] = snap.content_hash()
    return out


def test_tenant_slices_reproduce_the_single_instance_output():
    stream = _recorded_stream()
    single = _run_instance(stream)
    assert single, "fixture must produce correlation objects"
    for n_instances in (2, 3, 4):
        slices: dict[int, list[Signal]] = {i: [] for i in range(n_instances)}
        for s in stream:
            # The producer-side keying rule: partition by tenant key.
            slices[main.tenant_partition(s.tenant_id, n_instances)].append(s)
        # keying property: no tenant is ever split across slices
        seen: dict[str, int] = {}
        for i, sl in slices.items():
            for s in sl:
                assert seen.setdefault(s.tenant_id, i) == i, (
                    f"tenant {s.tenant_id} split across instances")
        union: dict = {}
        for i in range(n_instances):
            part = _run_instance(slices[i])
            overlap = set(union) & set(part)
            assert not overlap, f"two instances produced the same object: {overlap}"
            union.update(part)
        assert union == single, (
            f"N={n_instances}: sliced union differs from the single instance")


def test_syslog_burst_bucket_is_tenant_scoped(monkeypatch):
    """Regression for the one true cross-tenant coupling the scale audit found:
    SYSLOG_BUCKET was keyed by hostname alone, so two tenants sharing a device
    name pooled burst weight into one finding — and slicing by tenant changed
    the output. Now keyed (tenant, hostname): 5 err-events from each of two
    tenants on the SAME hostname (2 x 25 points) must NOT cross the 30-point
    threshold, and the finding a real burst emits carries the verified tenant."""
    findings: list[dict] = []

    class _CH:
        async def insert(self, table, rows, **kw):
            findings.extend(rows)
            return True

    monkeypatch.setattr(main, "ch", _CH())
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", False)
    # The claim IS the tenant here (the registry check has its own tests).
    monkeypatch.setattr(main, "verified_tenant",
                        lambda claimed, identity, lane, **kw: claimed or "global")

    async def _ch_insert(table, rows, **kw):
        findings.extend(rows)
        return True

    monkeypatch.setattr(main, "ch_insert", _ch_insert)
    main.SYSLOG_BUCKET.clear()
    try:
        async def scenario():
            for tenant in ("t_a", "t_b"):
                for _ in range(5):
                    await main.handle_syslog({"hostname": "core-sw1",
                                              "severity": "err",
                                              "tenant_id": tenant,
                                              "message": "x"})

        asyncio.run(scenario())
        assert not findings, f"cross-tenant pooled burst fired: {findings}"
        assert ("t_a", "core-sw1") in main.SYSLOG_BUCKET
        assert ("t_b", "core-sw1") in main.SYSLOG_BUCKET

        async def one_tenant_burst():
            for _ in range(2):  # 2 more err events -> 35 points for t_a alone
                await main.handle_syslog({"hostname": "core-sw1",
                                          "severity": "err",
                                          "tenant_id": "t_a",
                                          "message": "x"})

        asyncio.run(one_tenant_burst())
        assert findings and findings[0]["tenant_id"] == "t_a", (
            "a genuine single-tenant burst must fire, stamped with the "
            f"verified tenant: {findings}")
    finally:
        main.SYSLOG_BUCKET.clear()
