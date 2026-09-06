# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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
    probe_authority: str = "high",   # default: real vantage (legacy "always trusted")
    agent_host: str = "",
    source_egress: str = "",
    attrs: dict | None = None,
) -> Signal:
    global _seq
    _seq += 1
    a = dict(attrs or {})
    if modality is ModalityClass.ACTIVE_PROBE:
        a.setdefault("probe_authority", probe_authority)
        if agent_host:
            a.setdefault("agent_host", agent_host)
        if source_egress:
            a.setdefault("source_egress", source_egress)
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
        attrs=a,
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
    assert any("control_plane" in r and "missing" in r for r in v.reasons)
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


# ── Probe authority & independence (Step 3) ───────────────────────────────────
# The load-bearing guards: probe-only, debug_only, low-authority, and fate-shared
# evidence MUST NOT reach `confirmed`. (docs/design/probe-authority-model.md)


def _probe(observer, **kw):  # convenience: an active_probe witness
    return make_signal(observer, ModalityClass.ACTIVE_PROBE,
                       observer_type=ObserverType.VANTAGE_AGENT, **kw)


def test_high_probe_plus_independent_modality_confirms():
    # The positive control: a high-authority (real-vantage) probe + an
    # independent device-telemetry observer on a DIFFERENT host → confirmed.
    v = assess([
        _probe("agentA", probe_authority="high", agent_host="hostA"),
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY),
    ], required_modalities=frozenset({ModalityClass.ACTIVE_PROBE}))
    assert v.tier is VerdictTier.CONFIRMED


def test_probe_only_never_confirms():
    # Two high-authority probes from two independent agents — still ONE modality.
    v = assess([
        _probe("agentA", probe_authority="high", agent_host="hostA"),
        _probe("agentB", probe_authority="high", agent_host="hostB"),
    ])
    assert v.tier is not VerdictTier.CONFIRMED  # single modality cannot confirm


def test_low_authority_probe_cannot_confirm_only_supports():
    # A LOW-authority (self/internal) probe + a device modality → suspected, not
    # confirmed: the probe can support a suspicion but never anchor a verdict, and
    # it does NOT satisfy an active_probe requirement.
    sigs = [
        _probe("self-probe", probe_authority="low", agent_host="hostA"),
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY),
    ]
    assert assess(sigs).tier is VerdictTier.SUSPECTED
    v = assess(sigs, required_modalities=frozenset({ModalityClass.ACTIVE_PROBE}))
    assert v.tier is VerdictTier.SUSPECTED
    assert any("low-authority" in r.lower() or "low" in r.lower() for r in v.reasons)


def test_debug_only_probe_is_excluded_entirely():
    # debug_only/lab probes are EXCLUDED from customer-facing verdicts: they do
    # not contribute even alongside a real modality, and a debug-only-only window
    # is undetermined (nothing admissible), not suspected.
    only_debug = assess([_probe("lab", probe_authority="debug_only", agent_host="ci")])
    assert only_debug.tier is VerdictTier.UNDETERMINED
    assert only_debug.coverage.excluded_debug == ("lab",)
    # debug probe must not turn a single-device suspicion into a confirmation
    v = assess([
        _probe("lab", probe_authority="debug_only", agent_host="ci"),
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY),
    ])
    assert v.tier is not VerdictTier.CONFIRMED
    assert v.coverage.modality_count == 1  # only the device counts


def test_fate_shared_probe_and_modality_cannot_confirm():
    # A high-authority probe and a device-telemetry collector on the SAME host
    # (shared fate) are NOT independent — one host failure correlates both — so
    # they cannot co-confirm. Moving the device to another host confirms.
    shared = assess([
        _probe("agentA", probe_authority="high", agent_host="hostX"),
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY,
                    attrs={"agent_host": "hostX"}),
    ])
    assert shared.tier is VerdictTier.SUSPECTED
    assert shared.coverage.independent_pair is None

    independent = assess([
        _probe("agentA", probe_authority="high", agent_host="hostX"),
        make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY,
                    attrs={"agent_host": "hostY"}),
    ])
    assert independent.tier is VerdictTier.CONFIRMED


def test_fate_shared_probes_collapse_to_one_observer():
    # Two probes sharing a NAT egress are one independent vantage, not two.
    cov = coverage([
        _probe("agentA", probe_authority="high", source_egress="1.2.3.4"),
        _probe("agentB", probe_authority="high", source_egress="1.2.3.4"),
    ])
    assert cov.fate_groups == (("agentA", "agentB"),)
    a = witness_of(_probe("agentA", probe_authority="high", source_egress="1.2.3.4"))
    b = witness_of(_probe("agentB", probe_authority="high", source_egress="1.2.3.4"))
    assert not a.independent_of(b)


# ── Verdict-gate independence AUDIT (evidence-accounting Phase B, constraint 3) ──
# These pin the four independence behaviors the Phase A audit flagged for proof
# before the Go accounting layer builds on the gate. See
# docs/design/rca-evidence-accounting-phaseA-audit.md §7 (audit findings).


def test_audit_a_same_host_observers_not_independent():
    """(a) api container + prober, both on the lab host → NOT independent. When
    co-location is stamped (shared agent_host), the fate check catches it; and
    because both are active_probe they can never form a cross-modality confirming
    pair anyway (defense in depth)."""
    api = witness_of(_probe("api", probe_authority="low", agent_host="lab-host"))
    prober = witness_of(_probe("prober", probe_authority="low", agent_host="lab-host"))
    assert not api.independent_of(prober)
    assert not prober.independent_of(api)
    # Same modality → no confirming pair regardless of independence.
    assert assess([
        _probe("api", probe_authority="low", agent_host="lab-host"),
        _probe("prober", probe_authority="low", agent_host="lab-host"),
    ]).tier is not VerdictTier.CONFIRMED


def test_audit_b_rtt_and_loss_from_one_stream_not_independent():
    """(b) RTT and loss from ONE probe stream (same observer) are one observation,
    not two — never independent (same observer_id)."""
    rtt = witness_of(make_signal("prober", ModalityClass.ACTIVE_PROBE, kind="probe_rtt_anomaly",
                                 agent_host="lab-host"))
    loss = witness_of(make_signal("prober", ModalityClass.ACTIVE_PROBE, kind="probe_loss",
                                  agent_host="lab-host"))
    assert not rtt.independent_of(loss)
    cov = coverage([
        make_signal("prober", ModalityClass.ACTIVE_PROBE, kind="probe_rtt_anomaly", agent_host="lab-host"),
        make_signal("prober", ModalityClass.ACTIVE_PROBE, kind="probe_loss", agent_host="lab-host"),
    ])
    assert cov.observer_count == 1 and cov.independent_pair is None


def test_audit_c_control_plane_and_lan_vantage_are_independent():
    """(c) A control-plane source (tunnel state) and a LAN vantage probe on a
    different host ARE independent and confirm — the P-027379 pair."""
    v = assess([
        make_signal("ipsec:lab-vpn-edge", ModalityClass.CONTROL_PLANE,
                    observer_type=ObserverType.DEVICE, kind="ipsec_tunnel_down"),
        _probe("lan-vantage-1", probe_authority="high", agent_host="lan-vantage-host"),
    ])
    assert v.tier is VerdictTier.CONFIRMED
    assert v.coverage.independent_pair == ("ipsec:lab-vpn-edge", "lan-vantage-1")


def test_audit_d_absent_colocation_never_fabricates_a_confirm():
    """(d) Fail-closed: when provenance is UNKNOWN the gate must not manufacture a
    confirmation. Two signals whose collection_path is unrecognized share one
    conservative authority bucket → not independent → cannot confirm, even across
    modalities. (Absence of co-location can only WEAKEN evidence, never strengthen
    it.)"""
    a = make_signal("x1", ModalityClass.ACTIVE_PROBE, collection_path="via_mystery",
                    probe_authority="high", observer_type=ObserverType.VANTAGE_AGENT)
    b = make_signal("x2", ModalityClass.CONTROL_PLANE, collection_path="via_mystery")
    v = assess([a, b])
    assert v.tier is not VerdictTier.CONFIRMED
    assert v.coverage.independent_pair is None
    # And a lone low-authority probe with no co-location info never anchors a
    # confirm (it lacks a trusted witness), so unknown provenance stays suspected.
    assert assess([_probe("p", probe_authority="low")]).tier is not VerdictTier.CONFIRMED


def test_duplicate_evidence_does_not_inflate_confidence():
    """Spec P3 #9 — the SAME event duplicated many times must NOT promote a verdict.
    Coverage counts UNIQUE witnesses (observer × modality), never the raw signal count,
    so 8 copies of one device-telemetry observer stay a single modality → suspected."""
    one = assess([make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY)])
    many = assess([make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY) for _ in range(8)])
    assert one.tier is VerdictTier.SUSPECTED
    assert many.tier is VerdictTier.SUSPECTED, "duplicates must not promote past suspected"
    assert many.coverage.modality_count == 1
    assert many.coverage.observer_count == 1
