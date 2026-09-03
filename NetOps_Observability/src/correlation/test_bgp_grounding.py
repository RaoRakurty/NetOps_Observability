"""The BGP routing-observatory evidence lane, grounded by the SAME generic
intake the security lane uses — and by exactly one more row of data.

THE CONTRACT (docs/design/BGP_OPS_CAPABILITY_TRACKER_2026-09-02.md row 10 +
`src/backend/internal/bgpwatch/evidence.go` "THE GROUNDING SEAM"). `bgpwatch`
publishes an ALREADY-CANONICAL evidence envelope — entity + timestamp +
identity + attrs — onto `netops.bgp`. The engine's intake is generic in its
FIELD HANDLING but its kind vocabulary is a REGISTRY: an unregistered `kind`
dead-letters. So grounding a new class is one frozen row in
`signals.EVIDENCE_CLASSES` plus the operational half (the topic in
`CORR_EVIDENCE_TOPICS`, a Kafka Read+Describe ACL). This suite is the proof
that the row is all it took.

What is asserted here, in the order the evidence flows — deliberately mirroring
`test_security_grounding_t2b.py` clause for clause, because the whole claim is
that the second class needed no new mechanism:

  1. envelope -> Signal, field by field, against the EXACT wire shape
     `internal/bgpwatch/evidence.go` emits (prefix incidents AND peer-down),
     with an idempotent `signal_id` on redelivery.
  2. registration: six kinds, one modality, one causal layer, coverage
     classification, and the ClickHouse enum lockstep this class still owes.
  3. malformed input dead-letters + is counted, exactly like every other lane.
  4. grounding + the §10a cap: a BGP-only object can never reach `confirmed`,
     and a device's own BGP syslog is the SAME plane so it cannot lift it.
  5. removability: `CORR_EVIDENCE_TOPICS` without `netops.bgp` unsubscribes the
     class outright, and an ABSENT `netops.bgp` is dropped (never fatal) and
     re-probed until it appears.
  6. tenant isolation (§3a): a routing verdict about tenant A's device can
     never be filed under tenant B.
  7. the V1 byte-identity proof: this wave adds NO catalog template, so
     `catalog_version` — and therefore the `FIXTURE_GOLDEN` replay pin — does
     not move.
  8. metrics + /healthz exposure.

Run: python3 -m pytest test_bgp_grounding.py -q
"""
from __future__ import annotations

import asyncio
import logging
import pathlib
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest

import layers
import main
import signals
from catalog import BUILTIN_TEMPLATES, load_catalog
from confirmability import KIND_MODALITY
from coverage import EMITTED_KINDS, INTENTIONAL_BLIND, classify_kind
from engine import EngineConfig, run_window
from signals import (
    DeadLetter,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
    evidence_class_of,
    evidence_classes_of,
    evidence_signal_from_event,
)
from verdicts import VerdictTier

T0 = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)
TOPIC = "netops.bgp"
PREFIX = "203.0.113.0/24"
DEVICE = "edge-r1"

# The class's own vocabulary, read from the registry row rather than restated —
# a kind added to (or removed from) the row can never leave this suite passing
# vacuously.
BGP_KINDS = set(signals.EVIDENCE_CLASSES["bgp"].kinds)
BGP_SPEC = signals.EVIDENCE_CLASSES["bgp"]

CAT = load_catalog(BUILTIN_TEMPLATES)


# ── the exact wire shape bgpwatch.EvidenceEvent marshals ─────────────────────
def envelope(**over) -> dict:
    """One prefix incident, field for field as `EventFromIncident` builds it
    (internal/bgpwatch/evidence.go). `evidence_refs`, `seam_id` and
    `internet_facing` are deliberately ABSENT: bgpwatch emits none of them, and
    a fixture that invented them would be testing a producer we do not have."""
    ev = {
        "schema_version": "1",
        "tenant_id": "acme",
        "ts": "2026-09-02T12:00:00.123456789Z",
        "kind": "bgp_rpki_invalid",
        "entity_id": PREFIX,
        "entity_type": "prefix",
        "entity_tokens": [PREFIX, f"prefix:{PREFIX}"],
        "severity": "high",
        "native_id": f"bgp|bgp_rpki_invalid|acme|{PREFIX}|2026-09-02T12:00:00Z",
        "attrs": {
            "evidence_class": "bgp",
            "rule_id": "rpki_invalid",
            "incident_class": "rpki_invalid",
            "provider_source": "bgp-watch",
            "summary": f"{PREFIX} is RPKI-invalid at 3 of 4 collector vantages",
            "detail": "origin AS64511 does not match ROA for AS64500",
            "vantages": ["rrc00", "rrc03", "rrc12"],
            "vantage_count": 3,
            "observed_origins": ["AS64511"],
            "peers_seeing": 18,
            "peers_total": 24,
            "origin_baseline": "declared",
        },
    }
    ev.update(over)
    return ev


def peer_down_envelope(**over) -> dict:
    """`EventFromPeerDown` — the one kind that grounds on a DEVICE, because a
    BMP session really does belong to one box."""
    ev = {
        "schema_version": "1",
        "tenant_id": "acme",
        "ts": "2026-09-02T12:00:30Z",
        "kind": "bgp_peer_down",
        "entity_id": DEVICE,
        "entity_type": "device",
        "entity_tokens": [DEVICE, f"device:{DEVICE}", "peer:198.51.100.7"],
        "severity": "high",
        "native_id": f"bgp|bgp_peer_down|acme|{DEVICE}|198.51.100.7",
        "attrs": {
            "evidence_class": "bgp",
            "rule_id": "bgp_peer_down",
            "provider_source": "bgp-watch",
            "peer": "198.51.100.7",
            "peer_as": 64512,
            "down_reason": "hold timer expired",
            "session_id": "bmp-7",
            "summary": f"BMP peer 198.51.100.7 on {DEVICE} is down",
        },
    }
    ev.update(over)
    return ev


class FakeCH:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def insert(self, table: str, rows, dedup_token="") -> None:
        for r in rows:
            self.rows.append({"_table": table, **r})


@pytest.fixture
def rig(monkeypatch):
    """A hermetic engine: fake ClickHouse, empty window, a device registry that
    owns `edge-r1` for tenant `acme` and nothing else."""
    ch = FakeCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "_tenant_registry", lambda: {DEVICE: "acme"})
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    return ch


def bgp_rows(ch: FakeCH) -> list[dict]:
    return [r for r in ch.rows
            if r["_table"] == "netops.corr_signals" and r.get("source") == "bgp"]


def drive(ev: dict) -> None:
    asyncio.run(main.handle_evidence_event(ev))
    asyncio.run(main.SIGNAL_BATCH.flush())


# ══ 1. envelope -> Signal ════════════════════════════════════════════════════
def test_envelope_maps_onto_every_signal_field():
    sig = evidence_signal_from_event(envelope(), "acme")
    assert sig.tenant_id == "acme"
    # RFC3339Nano: the fraction is TRUNCATED to microseconds, never rounded.
    assert sig.ts == datetime(2026, 9, 2, 12, 0, 0, 123456, tzinfo=timezone.utc)
    assert sig.source is Source.BGP
    assert sig.kind == "bgp_rpki_invalid"
    assert sig.modality_class is ModalityClass.CONTROL_PLANE
    # a routing incident grounds on the PREFIX — never on a device that merely
    # happens to carry the route (that would be a fabricated attribution).
    assert sig.entity_type is EntityType.PREFIX
    assert sig.entity_id == PREFIX
    assert sig.severity is Severity.HIGH
    assert sig.entity_tokens == (PREFIX, f"prefix:{PREFIX}")
    # the witness is the platform's routing evaluator, never a device — so a
    # BGP verdict can never corroborate a device's own telemetry.
    assert sig.observer.observer_id == "bgp:bgp-watch"
    assert sig.observer.observer_type is ObserverType.PLATFORM
    assert sig.observer.observer_id != sig.entity_id


def test_peer_down_grounds_on_the_device_that_reported_it():
    sig = evidence_signal_from_event(peer_down_envelope(), "acme")
    assert sig.kind == "bgp_peer_down"
    assert sig.entity_type is EntityType.DEVICE and sig.entity_id == DEVICE
    assert "peer:198.51.100.7" in sig.entity_tokens
    assert sig.attrs["peer_as"] == 64512
    assert sig.attrs["down_reason"] == "hold timer expired"
    # still the platform lane as the witness — the device does not testify
    # about its own session here, BMP does.
    assert sig.observer.observer_id == "bgp:bgp-watch"
    assert sig.observer.observer_type is ObserverType.PLATFORM


def test_attrs_carry_class_and_provenance():
    attrs = evidence_signal_from_event(envelope(), "acme").attrs
    assert attrs["evidence_class"] == "bgp"           # the ENGINE's class
    # The lane's own `evidence_class` is KEPT under evidence_subclass rather
    # than dropped — the generic rule, applied even when the two agree.
    assert attrs["evidence_subclass"] == "bgp"
    # W1b provenance: the incident class that produced the verdict, and an
    # HONEST parser_rev — no parser ran, the record arrived canonical.
    assert attrs["rule_id"] == "rpki_invalid"
    assert attrs["parser_rev"] == "bus"
    # the measurement bgpwatch actually took, carried through untouched
    assert attrs["vantages"] == ["rrc00", "rrc03", "rrc12"]
    assert attrs["peers_seeing"] == 18 and attrs["peers_total"] == 24
    assert attrs["origin_baseline"] == "declared"


def test_the_incident_class_is_the_provenance_id_when_rule_id_is_absent():
    """`rule_id_fields` is an ORDERED lookup list, not an if-chain: a lane that
    only spells the id `incident_class` still lands a provenance id."""
    ev = envelope()
    ev["attrs"] = {k: v for k, v in ev["attrs"].items() if k != "rule_id"}
    assert evidence_signal_from_event(ev, "acme").attrs["rule_id"] == "rpki_invalid"


@pytest.mark.parametrize("kind", sorted(BGP_KINDS))
def test_every_kind_grounds_to_the_bgp_class(kind):
    """The registry claim, per kind: all six resolve to ONE class row — same
    source, same modality, same witness — and none of them dead-letters."""
    sig = evidence_signal_from_event(envelope(kind=kind), "acme")
    assert sig.kind == kind
    assert sig.source is Source.BGP
    assert sig.modality_class is ModalityClass.CONTROL_PLANE
    assert sig.attrs["evidence_class"] == "bgp"
    assert evidence_class_of(kind) == "bgp"
    assert signals.EVIDENCE_CLASS_BY_KIND[kind] is BGP_SPEC


def test_signal_id_is_idempotent_on_redelivery():
    a = evidence_signal_from_event(envelope(), "acme")
    b = evidence_signal_from_event(envelope(), "acme")
    assert a.signal_id == b.signal_id
    ts_ms = int(a.ts.timestamp() * 1000)
    assert a.signal_id == uuid.uuid5(signals.SIGNAL_NS, f"bgp|{a.native_id}|{ts_ms}")
    # the native_id carries the EPISODE start (bgpwatch.nativeID), so a NEW
    # episode of the same class on the same prefix is a NEW signal — which is
    # what makes two outages two stories instead of one.
    later = envelope()
    later["native_id"] = later["native_id"].replace(
        "2026-09-02T12:00:00Z", "2026-09-02T18:30:00Z")
    assert evidence_signal_from_event(later, "acme").signal_id != a.signal_id


def test_severity_and_entity_type_defaults_are_honest():
    assert evidence_signal_from_event(
        envelope(severity="critical"), "acme").severity is Severity.CRIT
    assert evidence_signal_from_event(
        envelope(severity="warning"), "acme").severity is Severity.WARN
    assert evidence_signal_from_event(
        envelope(severity="totally-unknown"), "acme").severity is Severity.WARN
    # entity_type omitted -> the class's declared default, which for a routing
    # incident is the PREFIX (not the DEVICE the security class defaults to).
    ev = envelope()
    ev.pop("entity_type")
    assert evidence_signal_from_event(ev, "acme").entity_type is EntityType.PREFIX


# ══ 2. registration ═════════════════════════════════════════════════════════
def test_kinds_modality_and_layer_are_registered():
    assert BGP_KINDS == {
        "bgp_rpki_invalid", "bgp_visibility_loss", "bgp_origin_change",
        "bgp_transit_change", "bgp_bogon_seen", "bgp_peer_down"}
    assert BGP_KINDS <= signals.EVIDENCE_BUS_KINDS
    for kind in BGP_KINDS:
        assert kind in EMITTED_KINDS
        assert KIND_MODALITY[kind] is ModalityClass.CONTROL_PLANE
        # Every one is an L3 REACHABILITY statement — same layer as the
        # IGP/BGP adjacency kinds, so onset ordering decides between them.
        assert layers.layer_of(kind) is layers.CausalLayer.NETWORK
        # No catalog signature REQUIRES one yet, and that is DECLARED rather
        # than discovered (see the coverage.INTENTIONAL_BLIND entries): this
        # wave grounds the lane without touching the rule base.
        assert classify_kind(kind, CAT) == "intentional_blind"
        entry = INTENTIONAL_BLIND[kind]
        assert entry["reason"] and entry["owner"] and entry["date_added"]


def test_the_class_reuses_the_control_plane_rather_than_minting_one():
    """A DELIBERATE choice, asserted so it cannot be quietly reversed.

    bgpwatch reads the global routing CONTROL PLANE (collector vantages, RPKI
    validity, BMP peer state) and shares that plane's blind spot exactly — it
    reports what routers SAY, not what packets do. Giving it a plane of its own
    would let a collector's view and the device's own BGP syslog "confirm" each
    other, i.e. count one kind of observation twice."""
    assert BGP_SPEC.modality is ModalityClass.CONTROL_PLANE
    assert BGP_SPEC.source is Source.BGP           # the LANE is its own, though
    assert BGP_SPEC.topic == TOPIC
    assert BGP_SPEC.default_entity_type is EntityType.PREFIX
    assert BGP_SPEC.observer_type is ObserverType.PLATFORM


def test_the_class_is_one_row_of_data():
    """Adding this class was a registry edit: the handler and the adapter name
    no class at all, and no engine module imports anything named bgpwatch."""
    assert TOPIC in signals.EVIDENCE_TOPICS
    src = pathlib.Path(main.__file__).read_text()
    body = src.split("async def handle_evidence_event", 1)[1].split(
        "\nasync def ", 1)[0]
    for token in sorted(BGP_KINDS) + ["bgpwatch"]:
        assert token not in body, (
            f"handle_evidence_event names {token!r} — the class must be "
            f"selected by registry lookup, never by a branch")


CH_SOURCE_ENUM_RE = re.compile(r"source\s+Enum8\(([^)]*)\)")
_ROOT = pathlib.Path(__file__).resolve().parents[2]


# The ClickHouse `source` Enum8 gained 'bgp'=15 in BOTH
# deployment/docker/clickhouse/init.sql (corr_signals + corr_signals_archive)
# and the CREATE/ALTER strings in
# src/backend/internal/chschema/corr_schema.go, so this is a PLAIN passing test
# now (it shipped as a strict xfail that turned XPASS the moment the value
# landed). It stays as the Python half of the enum-trio lockstep of
# correlation-data-contract.md §6 rule 5 — the Go halves are
# TestCorrSignalEnumsConsistent and
# TestCorrSignalSourceEnumMatchesEvidenceClasses. Without its value in the
# enum, a lane GROUNDS, scores and reaches a verdict in process but cannot be
# PERSISTED.
def test_every_registered_evidence_source_is_in_the_clickhouse_enum():
    init_sql = (_ROOT / "deployment" / "docker" / "clickhouse" / "init.sql").read_text()
    go_ddl = (_ROOT / "src" / "backend" / "internal" / "chschema"
              / "corr_schema.go").read_text()
    for text, name in ((init_sql, "init.sql"), (go_ddl, "corr_schema.go")):
        bodies = CH_SOURCE_ENUM_RE.findall(text)
        assert bodies, f"{name}: no `source` Enum8 definition found"
        for spec in signals.EVIDENCE_CLASSES.values():
            for body in bodies:
                assert f"'{spec.source.value}'" in body, (
                    f"{name}: source enum is missing "
                    f"'{spec.source.value}' — the {spec.name} lane cannot "
                    f"persist a signal")


# ══ 3. malformed input ══════════════════════════════════════════════════════
@pytest.mark.parametrize("over,why", [
    ({"kind": "bgp_definitely_not_a_kind"}, "unknown kind"),
    ({"entity_id": ""}, "no entity"),
    ({"native_id": ""}, "no identity"),
    ({"ts": "not-a-time"}, "unparseable ts"),
    ({"ts": ""}, "no event time — never substituted with arrival time"),
    ({"schema_version": "99"}, "unsupported schema"),
    ({"entity_type": "autonomous_system"}, "unknown entity type"),
])
def test_malformed_envelope_dead_letters(over, why):
    with pytest.raises(DeadLetter):
        evidence_signal_from_event(envelope(**over), "acme")


def test_handler_counts_and_quarantines_malformed_input(rig):
    dl, dropped = main.DEADLETTER_COUNT, main.EVIDENCE_EVENTS_DROPPED
    invalid = main.EVIDENCE_EVENTS_TOTAL["bgp|invalid"]
    main.QUARANTINE.clear()
    drive(envelope(entity_id=""))
    assert bgp_rows(rig) == []
    assert not main.WINDOW_BUFFER
    assert main.DEADLETTER_COUNT == dl + 1
    assert main.EVIDENCE_EVENTS_DROPPED == dropped + 1
    assert main.EVIDENCE_EVENTS_TOTAL["bgp|invalid"] == invalid + 1
    # the payload is KEPT (the same path every other lane's malformed input takes)
    assert any(q.get("topic") == "deadletter:evidence" for q in main.QUARANTINE)


def test_an_unregistered_bgp_shaped_kind_cannot_widen_the_metric_labels(rig):
    keys = set(main.EVIDENCE_EVENTS_TOTAL)
    before = main.EVIDENCE_EVENTS_TOTAL["unknown|invalid"]
    drive(envelope(kind="bgp_flowspec_rule_installed"))
    assert set(main.EVIDENCE_EVENTS_TOTAL) == keys          # bounded (§9)
    assert main.EVIDENCE_EVENTS_TOTAL["unknown|invalid"] == before + 1


# ══ 4. grounding + the §10a cap ═════════════════════════════════════════════
def netsig(kind: str, modality: ModalityClass, entity: str, observer: str,
           *, secs: int = 0, etype: EntityType = EntityType.DEVICE,
           tenant: str = "acme", src: Source = Source.SYSLOG) -> Signal:
    return Signal(
        tenant_id=tenant, ts=T0 + timedelta(seconds=secs), source=src,
        kind=kind, observer=Observer(observer_id=observer,
                                     observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=etype, entity_id=entity,
        severity=Severity.HIGH, native_id=f"{observer}|{kind}|{entity}|{secs}",
        entity_tokens=(entity,))


def bgp_signal(*, kind: str = "bgp_peer_down", entity: str = DEVICE,
               tenant: str = "acme", secs: int = 0,
               etype: str = "device", tokens=None) -> Signal:
    ev = peer_down_envelope(
        kind=kind, entity_id=entity, entity_type=etype,
        entity_tokens=list(tokens or [entity, f"device:{entity}"]),
        native_id=f"bgp|{kind}|{tenant}|{entity}|{secs}",
        ts=(T0 + timedelta(seconds=secs)).isoformat())
    return evidence_signal_from_event(ev, tenant)


def test_a_bgp_verdict_alone_is_never_confirmed():
    """One plane, one witness — the honest cap (INVARIANTS §10a: prefer still
    analyzing over an unsupported cause). Asserted for every kind."""
    for kind in sorted(BGP_KINDS):
        window = [bgp_signal(kind=kind)]
        for snap in run_window(window, CAT, (), EngineConfig()):
            assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED, kind


def test_two_bgp_verdicts_still_cannot_confirm():
    """Independence is about PLANES, not counts: a second routing verdict on
    the same device is the same modality AND the same witness."""
    window = [bgp_signal(kind="bgp_peer_down", secs=0),
              bgp_signal(kind="bgp_transit_change", secs=10)]
    for snap in run_window(window, CAT, (), EngineConfig()):
        assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED


def test_the_device_s_own_bgp_syslog_is_the_same_plane_and_cannot_confirm_it():
    """The reason the class reuses CONTROL_PLANE, stated as a test: a collector
    view and a syslog line about the same session are ONE kind of observation
    seen twice, and must not add up to proof."""
    window = [bgp_signal(kind="bgp_peer_down", secs=0),
              netsig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE,
                     DEVICE, f"syslog-{DEVICE}", secs=20)]
    snaps = run_window(window, CAT, (), EngineConfig())
    assert len(snaps) == 1, "the verdict and the syslog must land on ONE object"
    snap = snaps[0]
    kinds = {s.kind for n in snap.nodes for s in n.signals}
    assert {"bgp_peer_down", "bgp_adjacency_change"} <= kinds
    # the projection a consumer filters BGP stories with
    assert evidence_classes_of(kinds) == ("bgp",)
    modalities = {s.modality_class for n in snap.nodes for s in n.signals}
    assert modalities == {ModalityClass.CONTROL_PLANE}
    assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED


def test_a_bgp_verdict_co_locates_with_independently_measured_evidence():
    """It must still JOIN the object — capping the verdict is not the same as
    isolating the evidence. A second, independently MEASURED plane on the same
    device lands on one object with the routing verdict."""
    window = [bgp_signal(kind="bgp_peer_down", secs=0),
              netsig("device_cpu_high", ModalityClass.DEVICE_TELEMETRY,
                     DEVICE, f"snmp-{DEVICE}", secs=30, src=Source.METRIC)]
    snaps = run_window(window, CAT, (), EngineConfig())
    assert len(snaps) == 1
    kinds = {s.kind for n in snaps[0].nodes for s in n.signals}
    assert {"bgp_peer_down", "device_cpu_high"} <= kinds
    assert {ModalityClass.CONTROL_PLANE, ModalityClass.DEVICE_TELEMETRY} == {
        s.modality_class for n in snaps[0].nodes for s in n.signals}


# ══ 5. removability + the OPTIONAL lane ═════════════════════════════════════
def test_dropping_the_topic_makes_the_registration_inert(monkeypatch, rig):
    """`CORR_EVIDENCE_TOPICS` without netops.bgp unsubscribes the class and the
    engine consumes exactly the lanes it consumed before it existed."""
    assert main.evidence_topics_from_env("") == ()
    assert main.evidence_topics_from_env(None) == signals.EVIDENCE_TOPICS
    assert TOPIC in main.evidence_topics_from_env(None)
    # the security lane alone: bgp is gone, nothing else moves
    assert main.evidence_topics_from_env("netops.security") == ("netops.security",)
    # with bgp unsubscribed, the lane dispatch does not reach the handler …
    monkeypatch.setattr(main, "EVIDENCE_TOPIC_SET", frozenset({"netops.security"}))
    received = main.EVIDENCE_EVENTS_RECEIVED
    asyncio.run(main._handle_lane(TOPIC, envelope()))
    assert main.EVIDENCE_EVENTS_RECEIVED == received
    assert bgp_rows(rig) == [] and not main.WINDOW_BUFFER
    # … and the 12 network lanes are untouched by the class either way.
    assert len(main.LANE_TOPICS) == 12
    assert TOPIC not in main.LANE_TOPICS


def test_the_lane_is_optional_never_a_startup_gate():
    """An evidence class is REMOVABLE by construction, so "its topic is not on
    the broker yet" is a normal state — netops.bgp must be OPTIONAL, or its
    absence would fail the WHOLE subscription (the 2026-09-02 outage shape)."""
    assert TOPIC in main.OPTIONAL_TOPICS
    assert TOPIC not in main.REQUIRED_TOPICS
    assert main.REQUIRED_TOPICS + list(main.OPTIONAL_TOPICS) == main.TOPICS


def test_an_absent_bgp_topic_is_dropped_then_re_probed(monkeypatch, caplog):
    """The operational half, end to end on the real consume loop: the engine
    comes up on every other lane with ONE structured drop line for netops.bgp,
    and re-subscribes the moment the topic appears — no restart."""
    from test_optional_lane_subscription import FakeConsumer

    FakeConsumer.created = []
    FakeConsumer.present = set(main.TOPICS) - {TOPIC}
    FakeConsumer.unauthorized = set()
    FakeConsumer.start_error = None
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)
    monkeypatch.setattr(main, "CONSUMER_STOP_TIMEOUT_S", 0.2)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 1.0)
    monkeypatch.setattr(main, "CORR_TOPIC_PROBE_TIMEOUT_S", 1.0)
    monkeypatch.setattr(main, "CORR_EVIDENCE_REPROBE_S", 0.05)
    monkeypatch.setattr(main, "CORR_EVIDENCE_REPROBE_JITTER", 0.0)
    main.EVIDENCE_TOPICS_DROPPED.clear()
    main.SUBSCRIBED_TOPICS[:] = list(main.TOPICS)

    async def scenario():
        task = asyncio.create_task(main.consume())
        try:
            for _ in range(400):
                await asyncio.sleep(0.01)
                if main.EVIDENCE_TOPICS_DROPPED:
                    break
            assert main.EVIDENCE_TOPICS_DROPPED == {TOPIC: "absent"}
            assert TOPIC not in main.SUBSCRIBED_TOPICS
            # the operator enables FEATURE_BGP_ALERTS / kafka-init creates it
            FakeConsumer.created[0]._client.cluster.present.add(TOPIC)
            for _ in range(400):
                await asyncio.sleep(0.01)
                if TOPIC in main.SUBSCRIBED_TOPICS:
                    break
        finally:
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

    with caplog.at_level(logging.INFO, logger="correlation"):
        asyncio.run(scenario())

    assert TOPIC in main.SUBSCRIBED_TOPICS, "the recovered lane was not re-subscribed"
    assert main.EVIDENCE_TOPICS_DROPPED == {}
    assert len(FakeConsumer.created) == 1, "an absent optional lane restarted the engine"
    assert main.CONSUMER_START_FAILURES == 0
    drops = [r.getMessage() for r in caplog.records
             if r.levelno >= logging.ERROR and "optional lane DROPPED" in r.getMessage()]
    assert len(drops) == 1 and f"topic={TOPIC}" in drops[0]
    assert "reason=absent" in drops[0]
    assert any(f"optional lane RECOVERED: topic={TOPIC}" in r.getMessage()
               for r in caplog.records)


# ══ 6. tenant isolation (§3a) ═══════════════════════════════════════════════
def test_a_contradicted_tenant_claim_is_refused(rig):
    """`edge-r1` belongs to acme. A peer-down claiming it for `evil` is refused
    BEFORE anything is persisted — it can never attach to either tenant."""
    dl = main.DEADLETTER_COUNT
    invalid = main.EVIDENCE_EVENTS_TOTAL["bgp|invalid"]
    drive(peer_down_envelope(tenant_id="evil"))
    assert bgp_rows(rig) == []
    assert not main.WINDOW_BUFFER
    assert main.DEADLETTER_COUNT == dl + 1
    assert main.EVIDENCE_EVENTS_TOTAL["bgp|invalid"] == invalid + 1


def test_the_registry_tenant_wins_over_the_claim(rig):
    drive(peer_down_envelope(tenant_id="acme"))
    rows = bgp_rows(rig)
    assert len(rows) == 1 and rows[0]["tenant_id"] == "acme"
    assert rows[0]["source"] == "bgp" and rows[0]["kind"] == "bgp_peer_down"
    assert main.EVIDENCE_EVENTS_TOTAL["bgp|grounded"] >= 1


def test_a_prefix_the_registry_never_heard_of_is_orphan_not_misattributed(rig):
    """A PREFIX is never in the device registry, so every prefix incident is an
    `orphan` by construction — kept, filed under its OWN claimed tenant, and
    COUNTED so the coverage fact is visible rather than silent."""
    orphans = main.EVIDENCE_EVENTS_TOTAL["bgp|orphan"]
    drive(envelope(tenant_id="other"))
    rows = bgp_rows(rig)
    assert len(rows) == 1 and rows[0]["tenant_id"] == "other"
    assert main.EVIDENCE_EVENTS_TOTAL["bgp|orphan"] == orphans + 1


def test_a_verdict_never_joins_another_tenants_object():
    a = netsig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE,
               DEVICE, f"syslog-{DEVICE}", tenant="acme")
    b = bgp_signal(entity=DEVICE, tenant="other")
    for snap in run_window([a], CAT, (), EngineConfig()):
        assert snap.tenant_id == "acme"
        assert all(s.tenant_id == "acme" for n in snap.nodes for s in n.signals)
    with pytest.raises(ValueError, match="tenant"):
        run_window([a, b], CAT, (), EngineConfig())


# ══ 7. V1 byte-identity — the goldens do not move ═══════════════════════════
def test_the_class_adds_no_catalog_template_so_the_replay_pin_holds():
    """This wave grounds a lane; it does NOT edit the rule base. `catalog_version`
    is a hash of the templates, and `FIXTURE_GOLDEN` (the replay/damping pin)
    hashes `catalog_version` through the hypotheses blob — so authoring a BGP
    story family is a SEPARATE change with its own re-freeze proof, and this one
    must leave both exactly where it found them."""
    from test_bounded_object_paging import FIXTURE_GOLDEN, _fixture_snapshot

    assert _fixture_snapshot().content_hash() == FIXTURE_GOLDEN
    # …and no template references a bgp kind, which is WHY nothing moved.
    for template in BUILTIN_TEMPLATES:
        for clause in template.get("requires", ()):
            # a clause kind may be a `a|b|c` alternation — check every branch
            alts = {a.strip() for a in str(clause.get("kind", "")).split("|")}
            assert not (alts & BGP_KINDS), (
                f"{template['id']} consumes a bgp kind — the coverage "
                f"INTENTIONAL_BLIND entries and this assertion must be "
                f"removed together, and FIXTURE_GOLDEN re-frozen with proof")


# ══ 8. observability ════════════════════════════════════════════════════════
def test_counters_reach_healthz_and_metrics(rig):
    drive(peer_down_envelope())
    health = main._health_payload()
    ingest = health["ingest"]
    assert TOPIC in ingest["evidence_topics"]
    assert ingest["evidence_received"] >= 1 and ingest["evidence_signals"] >= 1
    for outcome in main.EVIDENCE_EVENT_OUTCOMES:
        assert f"bgp|{outcome}" in ingest["evidence_by_class"]
    text = main._metrics_text(health)
    for outcome in main.EVIDENCE_EVENT_OUTCOMES:
        assert (f'corr_evidence_events_total{{class="bgp",'
                f'outcome="{outcome}"}}') in text
