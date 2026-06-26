"""End-to-end RCA flow tests — the COMPLETE internal pipeline as one path.

The per-stage units are covered exhaustively elsewhere (test_signals/episodes/
engine/verdicts/scoring/catalog/replay/producers/...). This module is the
*integration* spine the others don't give: realistic, multi-modal evidence for
the three lab-grounded failure scenarios is fed through

    canonical Signals → engine.run_window (build_nodes → grounding gate →
    edges → components → scoring → verdict gate) → ObjectSnapshot row contracts
    → replay determinism

and the OUTPUT object is asserted end to end — top hypothesis, verdict tier,
grounding kind, and the actionable `evidence_missing` the Inspector renders.

Plus the cross-stage REGRESSION guards that protect the invariants the product
depends on but no single unit owns:

  * the lab-grounded signatures speak the engine's REAL emitted vocabulary
    (the exact P3 bug: a catalog whose clause kinds the engine never emits
    scores 0 on every live object → permanent `undetermined` boilerplate);
  * rank ≠ verdict (a matched signature can still be only suspected);
  * a debug/lab probe can never drive a customer-facing verdict;
  * the same evidence always yields the same object (replay contract).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from catalog import builtin_catalog
from engine import EngineConfig, run_window
from replay import StoredObject, replay
from scoring import CONFIDENCE_FLOOR
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from verdicts import VerdictTier, coverage

# Fixed, tz-aware base time — never wall-clock (purity / replay contract).
T0 = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

# The signal kinds the engine actually EMITS today (producers.py + main.py
# intake, verified by grep). The lab-grounded signatures must stay inside this
# vocabulary or they silently stop matching live data (the P3 regression).
EMITTED_KINDS = frozenset({
    "probe_rtt_anomaly", "probe_loss",
    "if_metric_anomaly", "metric_anomaly", "device_resource_anomaly",
    "link_state_change", "bgp_adjacency_change", "bgp_state_anomaly",
    "ospf_adjacency_change", "isis_adjacency_change", "lldp_neighbor_change",
    "stp_topology_change", "device_restart",
    # cloud lane (#81 P3G — emitted by handle_cloud)
    "cloud_change", "cloud_audit", "cloud_flow_log", "cloud_health",
})

# The three signatures authored from real observed lab objects (P3, #67). These
# MUST match live evidence; the aspirational legacy six may reference vendor/
# feature kinds not emitted yet and are deliberately excluded from the vocab guard.
LAB_GROUNDED = frozenset({
    "sig.ent.middle-mile.dia-egress-latency",
    "sig.ent.wan-edge.bgp-peer-flap",
    "sig.ent.access.local-link-fault",
})

CATALOG = builtin_catalog()


def sig(
    kind: str,
    modality: ModalityClass,
    etype: EntityType,
    entity: str,
    observer: str,
    *,
    sev: Severity = Severity.HIGH,
    dev: float = 0.0,
    secs: int = 0,
    source: Source = Source.METRIC,
    otype: ObserverType = ObserverType.DEVICE,
    path: str = "direct",
    attrs: dict | None = None,
) -> Signal:
    """Build one canonical Signal. native_id is unique per call so signal_ids
    differ deterministically."""
    return Signal(
        tenant_id="t1",
        ts=T0 + timedelta(seconds=secs),
        source=source,
        kind=kind,
        observer=Observer(observer_id=observer, observer_type=otype, collection_path=path),
        modality_class=modality,
        entity_type=etype,
        entity_id=entity,
        severity=sev,
        native_id=f"{observer}|{kind}|{entity}|{secs}",
        deviation=dev,
        attrs=attrs or {},
    )


def _only_object(window: list[Signal]):
    snaps = run_window(window, CATALOG, (), EngineConfig())
    assert len(snaps) == 1, f"expected exactly one object, got {len(snaps)}"
    return snaps[0]


def _assert_replays_clean(snap, window: list[Signal]) -> None:
    """Persist the snapshot's row contracts, then re-run the pure core over the
    same window and assert zero drift (the determinism / replay guarantee)."""
    stored = StoredObject.from_rows(snap.to_object_row(version=1), snap.to_edge_rows(version=1))
    report = replay(stored, window, CATALOG)
    assert report.engine_pin_match and report.catalog_pin_match
    assert report.clean, f"replay drift: {report.differences}"


# ── Scenario A: local link fault → CONFIRMED (cross-modality, independent) ─────


def test_local_link_fault_confirmed_end_to_end():
    """L1/L2 link transition (control plane) + same-interface counter anomaly
    (device telemetry), two independent observers → one grounded object, the
    local-link-fault signature, CONFIRMED, and it replays clean."""
    link = sig("link_state_change", ModalityClass.CONTROL_PLANE, EntityType.INTERFACE,
               "leaf1:Gi0/1", "syslog-leaf1", source=Source.SYSLOG, secs=0)
    ifm = sig("if_metric_anomaly", ModalityClass.DEVICE_TELEMETRY, EntityType.INTERFACE,
              "leaf1:Gi0/1", "snmp-poller", dev=6.0, secs=5)
    window = [link, ifm]

    snap = _only_object(window)
    r = snap.ranking
    assert r.top_hypothesis == "sig.ent.access.local-link-fault"
    assert r.verdict_tier is VerdictTier.CONFIRMED
    # one grounded edge, via same-device containment (topo), not a bare co-occurrence
    assert len(snap.edges) == 1
    assert snap.edges[0].grounding.kind == "topo"
    # confirmed ⇒ nothing missing
    assert r.evidence_missing == ()
    _assert_replays_clean(snap, window)


# ── Scenario B: BGP peer flap, single witness → SUSPECTED (never confirmed) ────


def test_bgp_peer_flap_single_witness_is_suspected():
    """A lone BGP adjacency change matches the bgp-peer-flap signature (rank is
    set) but a single modality / single observer can never confirm — the verdict
    is SUSPECTED and evidence_missing says exactly why."""
    bgp = sig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE, EntityType.DEVICE,
              "wan-r2", "syslog-wanr2", source=Source.SYSLOG, secs=0)
    snap = _only_object([bgp])

    r = snap.ranking
    assert r.top_hypothesis == "sig.ent.wan-edge.bgp-peer-flap"
    assert r.verdict_tier is VerdictTier.SUSPECTED          # rank set, verdict not confirmed
    missing = " ".join(r.evidence_missing).lower()
    assert "single modality" in missing or "single observer" in missing
    _assert_replays_clean(snap, [bgp])


# ── Scenario C1: low-authority probe-only → SUSPECTED, names the shortfall ─────


def test_low_authority_probe_only_path_slowdown_is_suspected():
    """Two internal/low-authority probes to a shared target across the same path
    correlate (shared-target topo grounding) and match the DIA egress signature,
    but low-authority probe evidence can only SUPPORT — the verdict is suspected
    and evidence_missing flags the low authority. (The UI 'Possible path
    slowdown' case.)"""
    p1 = sig("probe_rtt_anomaly", ModalityClass.ACTIVE_PROBE, EntityType.PATH,
             "vp-a->8.8.8.8", "vantage-a", dev=5.0, secs=0, source=Source.PROBE,
             otype=ObserverType.VANTAGE_AGENT,
             attrs={"probe_authority": "low", "probe_scope": "internal_self_probe"})
    p2 = sig("probe_rtt_anomaly", ModalityClass.ACTIVE_PROBE, EntityType.PATH,
             "vp-b->8.8.8.8", "vantage-b", dev=5.0, secs=3, source=Source.PROBE,
             otype=ObserverType.VANTAGE_AGENT,
             attrs={"probe_authority": "low", "probe_scope": "internal_self_probe"})
    window = [p1, p2]

    snap = _only_object(window)
    r = snap.ranking
    assert r.top_hypothesis == "sig.ent.middle-mile.dia-egress-latency"
    assert r.verdict_tier is VerdictTier.SUSPECTED
    assert len(snap.edges) == 1 and snap.edges[0].grounding.kind == "topo"
    assert "authority" in " ".join(r.evidence_missing).lower()
    _assert_replays_clean(snap, window)


# ── Scenario C2: debug/lab probe-only → UNDETERMINED, evidence excluded ────────


def test_debug_only_probe_cannot_drive_a_verdict():
    """debug_only / lab probes form a graph object (they appear in the timeline)
    but are EXCLUDED from the customer-facing verdict entirely: no clause they
    satisfy, no observer admitted → UNDETERMINED. (The UI 'test checks ignored'
    case.)"""
    d1 = sig("probe_loss", ModalityClass.ACTIVE_PROBE, EntityType.PATH,
             "lab-a->10.0.0.1", "lab-a", dev=5.0, secs=0, source=Source.PROBE,
             otype=ObserverType.VANTAGE_AGENT,
             attrs={"probe_authority": "debug_only", "probe_scope": "synthetic_lab_probe"})
    d2 = sig("probe_loss", ModalityClass.ACTIVE_PROBE, EntityType.PATH,
             "lab-b->10.0.0.1", "lab-b", dev=5.0, secs=2, source=Source.PROBE,
             otype=ObserverType.VANTAGE_AGENT,
             attrs={"probe_authority": "debug_only", "probe_scope": "synthetic_lab_probe"})

    snap = _only_object([d1, d2])
    assert snap.ranking.top_hypothesis == "undetermined"
    assert snap.ranking.verdict_tier is VerdictTier.UNDETERMINED

    # the verdict layer sees the probes only to EXCLUDE them — nothing admissible.
    cov = coverage([d1, d2])
    assert set(cov.excluded_debug) == {"lab-a", "lab-b"}
    assert cov.observer_ids == frozenset()           # no admissible witness
    assert cov.independent_pair is None


# ── Discriminator: a co-incident link-down steals the BGP flap ────────────────


def test_discriminator_prefers_link_fault_when_link_is_down():
    """BGP flap + a same-device link transition + interface counters: the
    bgp-peer-flap signature is CONTRADICTED by the present link_state_change (its
    look-alike killer) and the link-fault explanation wins. Proves the
    discriminator (else_prefer) wiring end to end."""
    link = sig("link_state_change", ModalityClass.CONTROL_PLANE, EntityType.INTERFACE,
               "leaf1:Gi0/1", "syslog-leaf1", source=Source.SYSLOG, secs=0)
    ifm = sig("if_metric_anomaly", ModalityClass.DEVICE_TELEMETRY, EntityType.INTERFACE,
              "leaf1:Gi0/1", "snmp-poller", dev=6.0, secs=4)
    bgp = sig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE, EntityType.DEVICE,
              "leaf1", "syslog-leaf1", source=Source.SYSLOG, secs=6)
    snap = _only_object([link, ifm, bgp])

    r = snap.ranking
    assert r.top_hypothesis == "sig.ent.access.local-link-fault"
    assert r.verdict_tier is VerdictTier.CONFIRMED
    by_id = {h.template_id: h for h in r.hypotheses}
    assert by_id["sig.ent.wan-edge.bgp-peer-flap"].contradicted is True
    assert "sig.ent.access.local-link-fault" in by_id["sig.ent.wan-edge.bgp-peer-flap"].forced_competitors


# ── Regression guards ─────────────────────────────────────────────────────────


def test_lab_signatures_speak_the_engine_emitted_vocabulary():
    """THE P3 regression. Every REQUIRED clause of a lab-grounded signature must
    name at least one kind the engine actually emits — otherwise the signature
    silently scores 0 on every live object and the Inspector falls back to the
    alphabetical evidence_missing boilerplate (the exact bug fixed in d064255)."""
    seen = set()
    for t in CATALOG.templates:
        if t.id not in LAB_GROUNDED:
            continue
        seen.add(t.id)
        for clause in t.requires:
            if clause.optional:
                continue
            assert clause.kinds() & EMITTED_KINDS, (
                f"{t.id}: required clause {clause.kind!r} names no emitted kind "
                f"(emitted: {sorted(EMITTED_KINDS)})"
            )
        # discriminator 'absent' kinds must also be emittable to ever fire
        for disc in t.discriminators:
            assert disc.absent.kinds() & EMITTED_KINDS, (
                f"{t.id}: discriminator {disc.absent.kind!r} names no emitted kind"
            )
    assert seen == LAB_GROUNDED, f"lab signatures missing from catalog: {LAB_GROUNDED - seen}"


def test_rank_and_verdict_are_orthogonal():
    """Sacred invariant: a high-rank match does not imply a confirmed verdict.
    The same bgp-peer-flap signature is rank-1 in both, but the verdict tier is
    driven only by independent cross-modality coverage."""
    bgp = sig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE, EntityType.DEVICE,
              "wan-r2", "syslog-wanr2", source=Source.SYSLOG)
    snap = _only_object([bgp])
    top = next(h for h in snap.ranking.hypotheses if h.template_id == snap.ranking.top_hypothesis)
    assert top.confidence_rank >= CONFIDENCE_FLOOR          # ranked (high coverage)
    assert snap.ranking.verdict_tier is VerdictTier.SUSPECTED  # but NOT confirmed


def test_same_evidence_same_object_and_order_invariant():
    """Determinism: the same evidence — in any order — yields the same
    correlation id and the same content hash (the foundation of versioning and
    replay)."""
    link = sig("link_state_change", ModalityClass.CONTROL_PLANE, EntityType.INTERFACE,
               "leaf1:Gi0/1", "syslog-leaf1", source=Source.SYSLOG, secs=0)
    ifm = sig("if_metric_anomaly", ModalityClass.DEVICE_TELEMETRY, EntityType.INTERFACE,
              "leaf1:Gi0/1", "snmp-poller", dev=6.0, secs=5)
    a = run_window([link, ifm], CATALOG, (), EngineConfig())[0]
    b = run_window([ifm, link], CATALOG, (), EngineConfig())[0]
    assert a.correlation_id == b.correlation_id
    assert a.content_hash() == b.content_hash()
