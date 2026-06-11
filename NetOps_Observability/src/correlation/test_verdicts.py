"""Build ③ contract tests — evidence independence + modality coverage →
verdict tier (#67 §4.5 + research C4). The independence model (transport vs
measurement authority) is specified HERE as executable cases; a behavior
change is a design change."""

from datetime import datetime, timedelta, timezone

from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from verdicts import (
    MIN_MODALITIES,
    MIN_OBSERVERS,
    VerdictTier,
    assess,
    coverage,
    witness_of,
)

T0 = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)
_seq = 0


def make_signal(
    observer_id: str,
    modality: ModalityClass,
    *,
    collection_path: str = "direct",
    observer_type: ObserverType = ObserverType.DEVICE,
    kind: str = "probe_loss",
    source: Source = Source.PROBE,
) -> Signal:
    global _seq
    _seq += 1
    return Signal(
        tenant_id="t1",
        ts=T0 + timedelta(seconds=_seq),
        source=source,
        kind=kind,
        observer=Observer(
            observer_id=observer_id,
            observer_type=observer_type,
            collection_path=collection_path,
        ),
        modality_class=modality,
        entity_type=EntityType.DEVICE,
        entity_id="leaf1",
        severity=Severity.WARN,
        native_id=f"test|{_seq}",
    )


TIER_RANK = {VerdictTier.UNDETERMINED: 0, VerdictTier.SUSPECTED: 1, VerdictTier.CONFIRMED: 2}


# --- the gate itself ---------------------------------------------------------


def test_no_evidence_is_undetermined():
    v = assess([])
    assert v.tier is VerdictTier.UNDETERMINED
    assert v.reasons == ("no evidence signals",)


def test_single_signal_is_suspected_never_confirmed():
    v = assess([make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY)])
    assert v.tier is VerdictTier.SUSPECTED
    assert any("single modality" in r for r in v.reasons)
    assert any("single observer" in r for r in v.reasons)


def test_two_modalities_same_observer_is_suspected():
    """A device reporting if_down AND loss on a probe it launched itself:
    the observer's own failure explains both — never corroboration."""
    v = assess([
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY),
        make_signal("leaf1", ModalityClass.ACTIVE_PROBE),
    ])
    assert v.tier is VerdictTier.SUSPECTED


def test_two_observers_same_modality_is_suspected():
    v = assess([
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY),
        make_signal("leaf2", ModalityClass.DEVICE_TELEMETRY),
    ])
    assert v.tier is VerdictTier.SUSPECTED
    assert any("blind spot" in r for r in v.reasons)


def test_independent_cross_modality_pair_confirms():
    v = assess([
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY),
        make_signal("probe-agent-dallas", ModalityClass.ACTIVE_PROBE,
                    observer_type=ObserverType.VANTAGE_AGENT),
    ])
    assert v.tier is VerdictTier.CONFIRMED
    assert v.coverage.independent_pair == ("leaf1", "probe-agent-dallas")
    assert any("independent confirming pair" in r for r in v.reasons)


# --- the authority model -----------------------------------------------------


def test_shared_controller_breaks_independence():
    """Two different nominal observers, both reported by the same SD-WAN
    controller: the controller is the effective witness for both."""
    v = assess([
        make_signal("edge-a", ModalityClass.CONTROL_PLANE,
                    collection_path="via_controller:vmanage-1"),
        make_signal("edge-b", ModalityClass.DEVICE_TELEMETRY,
                    collection_path="via_controller:vmanage-1"),
    ])
    assert v.tier is VerdictTier.SUSPECTED
    assert ("edge-a", "edge-b") in [tuple(g) for g in v.coverage.fate_groups]
    assert any("fate-shared" in r for r in v.reasons)


def test_distinct_controller_instances_are_independent():
    v = assess([
        make_signal("edge-a", ModalityClass.CONTROL_PLANE,
                    collection_path="via_controller:vmanage-1"),
        make_signal("edge-b", ModalityClass.DEVICE_TELEMETRY,
                    collection_path="via_controller:vmanage-2"),
    ])
    assert v.tier is VerdictTier.CONFIRMED


def test_instanceless_authority_collapses_per_kind():
    """No instance qualifier ⇒ conservatively one shared instance per kind:
    we under-claim independence, never over-claim it."""
    v = assess([
        make_signal("edge-a", ModalityClass.CONTROL_PLANE,
                    collection_path="via_controller"),
        make_signal("edge-b", ModalityClass.DEVICE_TELEMETRY,
                    collection_path="via_controller"),
    ])
    assert v.tier is VerdictTier.SUSPECTED


def test_transport_does_not_break_independence():
    """Telegraf/Vector relay device-measured counters; the device stays the
    observer. Two devices polled via the same aggregator ARE independent."""
    v = assess([
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY,
                    collection_path="via_aggregator"),
        make_signal("probe-agent", ModalityClass.ACTIVE_PROBE,
                    collection_path="via_aggregator",
                    observer_type=ObserverType.VANTAGE_AGENT),
    ])
    assert v.tier is VerdictTier.CONFIRMED


def test_unknown_collection_path_fails_closed():
    """Unrecognized path kinds share one bucket per kind: a malformed
    producer can weaken evidence, never manufacture confirmation."""
    a = make_signal("x1", ModalityClass.ACTIVE_PROBE, collection_path="via_mystery")
    b = make_signal("x2", ModalityClass.DEVICE_TELEMETRY, collection_path="via_mystery")
    assert assess([a, b]).tier is VerdictTier.SUSPECTED
    # ...but an unknown-path signal still pairs with a clean direct one:
    c = make_signal("clean", ModalityClass.DEVICE_TELEMETRY, collection_path="direct")
    assert assess([a, c]).tier is VerdictTier.CONFIRMED


def test_witness_parsing_is_total():
    for path in ("", "direct", "DIRECT", "via_controller:  C1 ", "garbage", ":::"):
        sig = make_signal("o1", ModalityClass.ACTIVE_PROBE, collection_path=path or "direct")
        w = witness_of(sig)
        assert w.observer_id == "o1"  # never raises, always classifies


# --- template-required modalities (evidence_missing honesty) ------------------


def test_required_modalities_cap_at_suspected_and_name_whats_missing():
    sigs = [
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY),
        make_signal("agent", ModalityClass.ACTIVE_PROBE,
                    observer_type=ObserverType.VANTAGE_AGENT),
    ]
    v = assess(sigs, required_modalities=frozenset({
        ModalityClass.ACTIVE_PROBE, ModalityClass.CONTROL_PLANE,
    }))
    assert v.tier is VerdictTier.SUSPECTED
    assert any(r == "required modality missing: control_plane" for r in v.reasons)
    # Satisfying the requirement flips it.
    sigs.append(make_signal("bgp-collector", ModalityClass.CONTROL_PLANE,
                            observer_type=ObserverType.PLATFORM))
    assert assess(sigs, required_modalities=frozenset({
        ModalityClass.ACTIVE_PROBE, ModalityClass.CONTROL_PLANE,
    })).tier is VerdictTier.CONFIRMED


# --- replay-grade properties --------------------------------------------------


def test_duplicate_signals_never_strengthen_evidence():
    s = make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY)
    assert assess([s, s, s]).tier is VerdictTier.SUSPECTED
    cov = coverage([s, s, s])
    assert cov.observer_count == 1 and cov.modality_count == 1


def test_order_invariance():
    sigs = [
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY),
        make_signal("agent", ModalityClass.ACTIVE_PROBE,
                    observer_type=ObserverType.VANTAGE_AGENT),
        make_signal("edge-a", ModalityClass.CONTROL_PLANE,
                    collection_path="via_controller:c1"),
    ]
    base = assess(sigs).to_dict()
    assert assess(list(reversed(sigs))).to_dict() == base
    assert assess(sigs[1:] + sigs[:1]).to_dict() == base


def test_monotonicity_adding_evidence_never_downgrades():
    pool = [
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY),
        make_signal("leaf1", ModalityClass.ACTIVE_PROBE),
        make_signal("edge-a", ModalityClass.CONTROL_PLANE,
                    collection_path="via_controller:c1"),
        make_signal("edge-b", ModalityClass.PASSIVE_FLOW,
                    collection_path="via_controller:c1",
                    observer_type=ObserverType.FLOW_EXPORTER),
        make_signal("agent", ModalityClass.ACTIVE_PROBE,
                    observer_type=ObserverType.VANTAGE_AGENT),
        make_signal("exporter-2", ModalityClass.PASSIVE_FLOW,
                    observer_type=ObserverType.FLOW_EXPORTER),
    ]
    prev = TIER_RANK[assess([]).tier]
    for i in range(1, len(pool) + 1):
        cur = TIER_RANK[assess(pool[:i]).tier]
        assert cur >= prev, f"tier downgraded at prefix {i}"
        prev = cur


def test_thresholds_are_the_documented_constants():
    assert MIN_MODALITIES == 2 and MIN_OBSERVERS == 2  # config-hash members


def test_verdict_dict_is_json_contract():
    v = assess([
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY),
        make_signal("agent", ModalityClass.ACTIVE_PROBE,
                    observer_type=ObserverType.VANTAGE_AGENT),
    ])
    d = v.to_dict()
    assert d["verdict_tier"] == "confirmed"
    assert d["modality_coverage"] == ["active_probe", "device_telemetry"]
    assert d["observer_coverage"] == ["agent", "leaf1"]
    assert d["independent_pair"] == ["agent", "leaf1"]
    assert isinstance(d["reasons"], list) and d["reasons"]
