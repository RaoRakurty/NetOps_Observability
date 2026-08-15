"""Engine-core tests (#67 build ⑥) — the properties the replay contract and
the owner's grounding constraint stand on:

  * grounding gate: no seam/topology grounding ⇒ NO edge, a counted gap hint
    (the gate never relaxes — an empty inventory yields zero seam edges)
  * determinism: same window (any input order) ⇒ identical snapshot rows and
    content hash
  * direction: claimed only when both available votes agree (2-of-3 rule with
    the topology vote abstaining in v0)
  * tenancy: a mixed-tenant window is rejected, never silently partitioned
"""

import dataclasses
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from catalog import builtin_catalog
from engine import (
    EngineConfig,
    SeamView,
    TopologyAdjacency,
    build_edges,
    build_nodes,
    engine_version,
    find_merges,
    resolve_grounding,
    run_window,
    seams_hash,
)
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

DALLAS_SEAM = SeamView(
    seam_id="dallas-dx-equinix",
    tenant_id="",
    seam_type="DX",
    endpoints=(("on_prem", "dallas-edge"), ("provider_edge", "equinix-pop")),
)


def sig(kind: str, entity_type: EntityType, entity_id: str, *, offset_s: float = 0,
        observer: str = "obs1", modality: ModalityClass = ModalityClass.DEVICE_TELEMETRY,
        severity: Severity = Severity.HIGH, unc_s: float = 5.0, tenant: str = "") -> Signal:
    return Signal(
        tenant_id=tenant,
        ts=T0 + timedelta(seconds=offset_s),
        source=Source.METRIC,
        kind=kind,
        observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=modality,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        native_id=f"test|{kind}|{entity_id}|{offset_s}",
        attrs={"onset_uncertainty_s": unc_s},
    )


def test_grounding_gate_blocks_ungrounded_pairs():
    nodes = build_nodes((
        sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1"),
        sig("metric_anomaly", EntityType.DEVICE, "austin-core", offset_s=10),
    ))
    edges, gap_hints = build_edges(nodes, (), EngineConfig())
    assert edges == ()
    assert gap_hints == 1


def test_seam_grounding_admits_edge():
    nodes = build_nodes((
        sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1"),
        sig("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop", offset_s=58,
            observer="probe1", modality=ModalityClass.ACTIVE_PROBE),
    ))
    edges, gap_hints = build_edges(nodes, (DALLAS_SEAM,), EngineConfig())
    assert len(edges) == 1 and gap_hints == 0
    e = edges[0]
    assert (e.grounding.kind, e.grounding.ref) == ("seam", "dallas-dx-equinix")
    assert e.w_reinforce > 1.0, "cross-modality pair must reinforce"
    # interface (L0) precedes and is a lower layer than segment (L2): both
    # votes agree → direction claimed.
    assert e.direction_conf > 0 and e.direction_basis == "onset_order+layer_prior"


def test_containment_topo_grounding():
    nodes = build_nodes((
        sig("device_cpu_high", EntityType.DEVICE, "dallas-edge"),
        sig("if_errors", EntityType.INTERFACE, "dallas-edge:Gi0/1", offset_s=20),
    ))
    edges, _ = build_edges(nodes, (), EngineConfig())
    assert len(edges) == 1
    assert edges[0].grounding.kind == "topo"
    assert "dallas-edge" in edges[0].grounding.ref


def test_shared_vantage_is_not_topology_grounding():
    """Two active probes from the SAME prober to UNRELATED destinations must NOT
    ground to each other via the shared vantage. (Before this fix, the shared
    `prober` token welded the platform's self-monitoring onto customer incidents.)"""
    nodes = build_nodes((
        sig("probe_loss", EntityType.PATH, "prober->nginx",
            observer="prober", modality=ModalityClass.ACTIVE_PROBE),
        sig("probe_loss", EntityType.PATH, "prober->192.0.2.120", offset_s=5,
            observer="prober", modality=ModalityClass.ACTIVE_PROBE),
    ))
    edges, gap_hints = build_edges(nodes, (), EngineConfig())
    assert edges == ()
    assert gap_hints == 1


def test_probe_still_grounds_to_its_destination_subject():
    """A probe to a device DOES still ground to a co-located device signal — via
    the real shared SUBJECT (the destination), not the vantage. The legitimate
    customer link survives; only the false vantage-bridge is removed."""
    nodes = build_nodes((
        sig("probe_loss", EntityType.PATH, "prober->dallas-edge",
            observer="prober", modality=ModalityClass.ACTIVE_PROBE),
        sig("bgp_peer_flap", EntityType.DEVICE, "dallas-edge", offset_s=8,
            observer="collector1"),
    ))
    edges, _ = build_edges(nodes, (), EngineConfig())
    assert len(edges) == 1
    assert edges[0].grounding.kind == "topo"
    assert "dallas-edge" in edges[0].grounding.ref


def test_chronic_condition_corroborates_recent_overlapping_partner():
    """A long-running condition (e.g. a chronically flapping BGP session whose
    first sample is ~10 min old) must still corroborate a RECENT cross-modality
    partner it OVERLAPS in time. Temporal proximity is measured between activity
    INTERVALS, not onsets — onset-to-onset distance (580s here) would decay the
    edge below attach_threshold and split a real probe ⟂ control-plane pair into
    two objects. Regression for the STAMP customer-path corroboration gap."""
    chronic = [
        sig("bgp_adjacency_change", EntityType.DEVICE, "dallas-edge:192.0.2.1", offset_s=o,
            observer="dallas-edge", modality=ModalityClass.CONTROL_PLANE)
        for o in (0, 300, 600)
    ]
    # Probe loss late in the chronic node's active interval (overlap, not onset-aligned).
    probe = sig("probe_loss", EntityType.PATH, "prober->dallas-edge", offset_s=580,
                observer="prober", modality=ModalityClass.ACTIVE_PROBE)
    nodes = build_nodes((*chronic, probe))
    edges, _gap_hints = build_edges(nodes, (), EngineConfig())
    assert len(edges) == 1, f"overlapping cross-modality pair must edge, got {edges}"
    assert edges[0].grounding.kind == "topo"  # shared 'dallas-edge' subject
    assert edges[0].w_reinforce > 1.0          # cross-modality reinforcement applied


_DIA_SEAM = SeamView(
    seam_id="sm-dia", tenant_id="", seam_type="DIA",
    endpoints=(("on_prem", "172.40.40.52"), ("probe_target", "192.0.2.120")),
    control_plane_owner="isp",
)


def _probe(off: float) -> Signal:
    s = Signal(
        tenant_id="", ts=T0 + timedelta(seconds=off), source=Source.PROBE, kind="probe_loss",
        observer=Observer(observer_id="prober", observer_type=ObserverType.VANTAGE_AGENT),
        modality_class=ModalityClass.ACTIVE_PROBE, entity_type=EntityType.PATH,
        entity_id="prober->192.0.2.120", severity=Severity.CRIT, native_id=f"p|{off}",
        entity_tokens=("prober", "192.0.2.120"),
    )
    # As classify_probe would stamp a TRUSTED customer-path probe (confirm-capable).
    s.attrs.update(probe_authority="high", probe_scope="customer_path", agent_host="prober")
    return s


def _bgp(off: float) -> Signal:
    return Signal(
        tenant_id="", ts=T0 + timedelta(seconds=off), source=Source.TRAP, kind="bgp_adjacency_change",
        observer=Observer(observer_id="192.0.2.120", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.DEVICE,
        entity_id="192.0.2.120:192.168.100.5", severity=Severity.CRIT, native_id=f"b|{off}",
        entity_tokens=("192.0.2.120", "192.168.100.5"),
    )


def test_dia_egress_corroborated_confirms_via_probe_and_control_plane():
    """END-TO-END feature gate: a TRUSTED customer-path probe and an independent
    control-plane BGP flap on the same DIA seam confirm together via the
    dia-egress-corroborated signature — even though the BGP node is chronic
    (offsets 0/300/600) and the probe is recent (30/60). Exercises both the
    interval-overlap temporal merge AND the multi-plane signature. A probe alone
    still never confirms (covered by verdicts tests)."""
    sigs = (_probe(30), _probe(60), _bgp(0), _bgp(300), _bgp(600))
    snaps = run_window(sigs, builtin_catalog(), (_DIA_SEAM,), EngineConfig())
    objs = [s for s in snaps if any(n.entity_id == "prober->192.0.2.120" for n in s.nodes)]
    assert len(objs) == 1, f"probe + bgp must form ONE object, got {len(snaps)} snapshots"
    r = objs[0].ranking
    assert r.top_hypothesis == "sig.ent.middle-mile.dia-egress-corroborated", r.top_hypothesis
    assert r.verdict_tier.value == "confirmed", r.verdict_tier


def test_direction_unclaimed_on_conflict():
    # The LOWER layer onsets later: onset-order and layer-prior disagree → no claim.
    nodes = build_nodes((
        sig("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop",
            observer="probe1", modality=ModalityClass.ACTIVE_PROBE),
        sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1", offset_s=120),
    ))
    edges, _ = build_edges(nodes, (DALLAS_SEAM,), EngineConfig())
    assert len(edges) == 1
    assert edges[0].direction_conf == 0.0
    assert edges[0].direction_basis in ("mixed", "none")


def test_direction_unclaimed_within_uncertainty():
    # Onset gap smaller than the summed uncertainty: the order vote abstains,
    # leaving one vote — not enough to claim.
    nodes = build_nodes((
        sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1", unc_s=30),
        sig("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop", offset_s=10,
            observer="probe1", modality=ModalityClass.ACTIVE_PROBE, unc_s=30),
    ))
    edges, _ = build_edges(nodes, (DALLAS_SEAM,), EngineConfig())
    assert len(edges) == 1 and edges[0].direction_conf == 0.0


def test_singleton_open_floor():
    crit = run_window([sig("metric_anomaly", EntityType.DEVICE, "edge1", severity=Severity.CRIT)],
                      builtin_catalog(), ())
    warn = run_window([sig("metric_anomaly", EntityType.DEVICE, "edge2", severity=Severity.WARN)],
                      builtin_catalog(), ())
    assert len(crit) == 1, "a critical singleton episode opens an object"
    assert warn == [], "a warn singleton stays an episode, not an object"


def test_mixed_tenant_window_rejected():
    with pytest.raises(ValueError):
        run_window([sig("a", EntityType.DEVICE, "d1", tenant="t1"),
                    sig("b", EntityType.DEVICE, "d2", tenant="t2")],
                   builtin_catalog(), ())


def golden_window() -> list[Signal]:
    return [
        sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1",
            observer="dallas-edge", unc_s=15),
        sig("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop", offset_s=58,
            observer="probe-agent-dallas", modality=ModalityClass.ACTIVE_PROBE, unc_s=5),
        sig("qos_drops", EntityType.INTERFACE, "dallas-edge:Gi0/1", offset_s=75,
            observer="dallas-edge", severity=Severity.WARN, unc_s=15),
    ]


def test_determinism_input_order_invariance():
    cat = builtin_catalog()
    a = run_window(golden_window(), cat, (DALLAS_SEAM,))
    b = run_window(list(reversed(golden_window())), cat, (DALLAS_SEAM,))
    assert len(a) == len(b) == 1
    assert a[0].correlation_id == b[0].correlation_id
    assert a[0].content_hash() == b[0].content_hash()
    assert a[0].to_object_row(1) == b[0].to_object_row(1)
    assert a[0].to_edge_rows(1) == b[0].to_edge_rows(1)


def test_snapshot_row_contract():
    snap = run_window(golden_window(), builtin_catalog(), (DALLAS_SEAM,))[0]
    row = snap.to_object_row(1)
    uuid.UUID(row["correlation_id"])           # well-formed deterministic id
    assert row["engine_version"] == engine_version(EngineConfig())
    assert row["catalog_version"] == builtin_catalog().version_hash()
    assert row["topology_version"] == seams_hash((DALLAS_SEAM,))
    assert row["node_count"] == 3 and row["signal_count"] == 3
    for e in snap.to_edge_rows(1):
        assert e["grounding_ref"], "grounded-edges constraint: ref never empty"


def test_engine_version_pins_config():
    assert engine_version(EngineConfig()) != engine_version(EngineConfig(tau_s=999))
    assert engine_version(EngineConfig()) == engine_version(EngineConfig())


# ── G1: L2/L3 adjacency grounding (the fabric-flap regression that was MISSING) ──
# A fabric link flap emits signals on the TWO ENDS of one link — different devices.
# Without an adjacency input they share no token and match no seam → no edge → no
# incident (the gap a live flap exposed). With the adjacency the engine grounds them.

def test_adjacency_rung_grounds_two_adjacent_devices():
    a = build_nodes((sig("link_state_change", EntityType.INTERFACE, "leaf1:Ethernet1",
                         observer="leaf1", modality=ModalityClass.CONTROL_PLANE),))[0]
    b = build_nodes((sig("isis_adjacency_change", EntityType.DEVICE, "spine1",
                         observer="spine1", modality=ModalityClass.CONTROL_PLANE),))[0]
    # No seam, no shared token → ungrounded without adjacency.
    assert resolve_grounding(a, b, ()) is None
    # With the known fabric link leaf1<->spine1 → grounded via the adjacency rung.
    adj = TopologyAdjacency.from_links([{"a": "leaf1", "b": "spine1", "a_if": "Ethernet1"}])
    g = resolve_grounding(a, b, (), adj)
    assert g is not None and g.kind == "topo" and g.ref == "adj:leaf1--spine1"


def test_fabric_link_flap_forms_one_grounded_incident_with_adjacency():
    # The exact shape of the live chaos: link-state on leaf1's port + IS-IS adjacency
    # drop on the spine end of the same link.
    window = [
        sig("link_state_change", EntityType.INTERFACE, "leaf1:Ethernet1",
            observer="leaf1", modality=ModalityClass.CONTROL_PLANE),
        sig("isis_adjacency_change", EntityType.DEVICE, "spine1", offset_s=3,
            observer="spine1", modality=ModalityClass.CONTROL_PLANE),
    ]
    cat = builtin_catalog()
    # BEFORE (no adjacency): the two ends never correlate — at most singletons, NO edge.
    assert all(len(s.edges) == 0 for s in run_window(window, cat, ()))
    # AFTER (adjacency wired): one object with one adjacency-grounded edge.
    adj = TopologyAdjacency.from_links([{"a": "leaf1", "b": "spine1"}])
    snaps = run_window(window, cat, (), adjacency=adj)
    edges = [e for s in snaps for e in s.edges]
    assert len(edges) == 1, "fabric flap must form exactly one grounded edge"
    assert edges[0].grounding.ref == "adj:leaf1--spine1"


def test_adjacency_is_backward_compatible_when_empty():
    # An empty adjacency must change nothing — seam/containment behavior is identical.
    a = build_nodes((sig("if_util_high", EntityType.INTERFACE, "leaf1:Gi0/1", observer="leaf1"),))[0]
    b = build_nodes((sig("qos_drops", EntityType.INTERFACE, "leaf1:Gi0/1", observer="leaf1"),))[0]
    # Same device → still grounds by containment, unaffected by the adjacency param.
    g = resolve_grounding(a, b, (), TopologyAdjacency())
    assert g is not None and g.ref.startswith("shared:")


# ── evidence-ledger immutability / audit (gap-report #9, P4 — NON-NEGOTIABLE) ──
# The evidence ledger is APPEND-ONLY and versioned: a re-evaluation re-stamps the
# frozen evidence under a NEW version label (never edits a prior version's record),
# every evidence row is auditable (explicit role + provenance note), and a real
# evidence change forces a new version rather than silently mutating the old one.


def test_evidence_rows_are_auditable_and_versioned():
    snap = run_window(golden_window(), builtin_catalog(), (DALLAS_SEAM,))[0]
    rows = snap.to_evidence_rows(1)
    assert rows, "a grounded snapshot must emit evidence rows"
    for r in rows:
        assert r["role"], "every evidence row carries an explicit role (audit)"
        assert r["note"], "every evidence row carries a provenance note (audit)"
        assert r["version"] == 1
        assert r["correlation_id"] == snap.correlation_id


def test_reversioning_is_append_not_in_place_mutation():
    """v2 of the SAME evidence differs from v1 ONLY by the version label — role,
    subject and note are frozen, proving a new version is an APPEND, not an edit."""
    snap = run_window(golden_window(), builtin_catalog(), (DALLAS_SEAM,))[0]
    v1, v2 = snap.to_evidence_rows(1), snap.to_evidence_rows(2)
    assert len(v1) == len(v2) and v1
    for a, b in zip(v1, v2):
        assert a["version"] == 1 and b["version"] == 2
        # non-version fields must be immutable across versions (no in-place edit)
        assert {k: v for k, v in a.items() if k != "version"} == {
            k: v for k, v in b.items() if k != "version"
        }, "non-version fields must be immutable across versions"


def test_evidence_change_forces_new_version_unchanged_does_not_churn():
    cat = builtin_catalog()
    full = run_window(golden_window(), cat, (DALLAS_SEAM,))[0]
    # Re-evaluating identical evidence ⇒ identical hash ⇒ engine_cycle keeps the
    # version (no churn) — see main.engine_cycle's `reg["hash"] != chash` gate.
    again = run_window(golden_window(), cat, (DALLAS_SEAM,))[0]
    assert full.content_hash() == again.content_hash()
    # Dropping a corroborating signal genuinely changes the evidence ⇒ the change
    # detector MUST move, so a NEW version is emitted (audit trail) — the prior
    # version's evidence is never overwritten in place.
    reduced = run_window([s for s in golden_window() if s.kind != "qos_drops"],
                         cat, (DALLAS_SEAM,))[0]
    assert reduced.correlation_id == full.correlation_id, "same object identity"
    assert reduced.content_hash() != full.content_hash(), "changed evidence ⇒ new version"


# ── #100 write-side damping: material vs instance-refresh change detection ────
# A sustained incident refreshes its window every cycle with new INSTANCES of the
# same evidence; content_hash (the replay pin) legitimately moves, but nothing an
# operator acts on changed. material_hash is the persistence gate: stable across
# instance refresh, moving on any operator-meaningful change.


def _refreshed_window() -> list:
    """golden_window plus later instances of the SAME evidence kinds on the SAME
    entities — the storm shape: window slides, instance ids rotate. The original
    signals stay in the window, so the earliest node (hence correlation_id) holds."""
    dup = [
        sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1",
            observer="dallas-edge", unc_s=15, offset_s=30),
        sig("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop", offset_s=88,
            observer="probe-agent-dallas", modality=ModalityClass.ACTIVE_PROBE, unc_s=5),
        sig("qos_drops", EntityType.INTERFACE, "dallas-edge:Gi0/1", offset_s=105,
            observer="dallas-edge", severity=Severity.WARN, unc_s=15),
    ]
    return golden_window() + dup


def test_material_hash_stable_across_instance_refresh():
    cat = builtin_catalog()
    base = run_window(golden_window(), cat, (DALLAS_SEAM,))[0]
    refreshed = run_window(_refreshed_window(), cat, (DALLAS_SEAM,))[0]
    assert refreshed.correlation_id == base.correlation_id, "same incident identity"
    assert refreshed.content_hash() != base.content_hash(), \
        "new instances must still move the replay pin"
    assert refreshed.material_hash() == base.material_hash(), \
        "instance refresh of the same evidence must NOT re-version (damping)"


def test_material_hash_moves_on_material_change():
    cat = builtin_catalog()
    base = run_window(golden_window(), cat, (DALLAS_SEAM,))[0]
    # Dropping a corroborating evidence KIND is operator-meaningful.
    reduced = run_window([s for s in golden_window() if s.kind != "qos_drops"],
                         cat, (DALLAS_SEAM,))[0]
    assert reduced.material_hash() != base.material_hash(), \
        "an evidence-kind change must persist a new version"


# ── C1: object merge — de-split cross-cycle identity drift (§4.4) ──────────────
def _obj(devs, cid, start_min, end_min):
    """A real ObjectSnapshot whose entity set is `devs` and window is
    [T0+start_min, T0+end_min] — built from real Nodes (run_window), then re-keyed
    via dataclasses.replace so the pure find_merges sees genuine snapshot shapes."""
    def one(d):
        return run_window(
            [sig("link_state_change", EntityType.DEVICE, d, severity=Severity.CRIT),
             sig("device_resource_anomaly", EntityType.DEVICE, d, severity=Severity.CRIT, offset_s=1)],
            builtin_catalog(), ())[0]
    nodes = tuple(n for d in devs for n in one(d).nodes)
    base = one(devs[0])
    return dataclasses.replace(
        base, correlation_id=cid, nodes=nodes,
        window_start=T0 + timedelta(minutes=start_min),
        window_end=T0 + timedelta(minutes=end_min))


def test_find_merges_coalesces_split_brain():
    # Same incident re-identified across windowing: same entities, overlapping window.
    survivor = _obj(["leaf1", "spine1"], "surv", 2, 7)
    stale = _obj(["leaf1", "spine1"], "stale", 0, 4)
    assert find_merges([survivor], [stale]) == [("stale", "surv")]


def test_find_merges_ignores_disjoint_entities():
    survivor = _obj(["leaf1", "spine1"], "surv", 0, 5)
    stale = _obj(["wan1", "dmz1"], "stale", 0, 5)
    assert find_merges([survivor], [stale]) == []  # 0% overlap → never merge


def test_find_merges_below_overlap_threshold_is_left_alone():
    survivor = _obj(["leaf1", "spine1", "leaf2"], "surv", 0, 5)
    stale = _obj(["leaf1", "wan1", "dmz1", "dmz2"], "stale", 0, 5)  # overlap=leaf1: 1/6≈0.17
    assert find_merges([survivor], [stale]) == []


def test_find_merges_requires_window_overlap():
    survivor = _obj(["leaf1", "spine1"], "surv", 100, 105)  # disjoint window
    stale = _obj(["leaf1", "spine1"], "stale", 0, 5)
    assert find_merges([survivor], [stale]) == []


def test_find_merges_never_crosses_tenants():
    # §3a default-closed, mirroring test_continuation_never_crosses_tenants.
    # main.engine_cycle feeds BOTH lists from the process-global all-tenant
    # OPEN_OBJECTS, so identically-named devices in two tenants (leaf1/spine1 —
    # the ordinary case) would otherwise tombstone one tenant's live incident
    # into the other's and write a foreign correlation_id to its merged_into.
    survivor = dataclasses.replace(
        _obj(["leaf1", "spine1"], "surv", 2, 7), tenant_id="tenant-b")
    stale = _obj(["leaf1", "spine1"], "stale", 0, 4)  # tenant-a: 100% entity overlap
    assert stale.tenant_id != survivor.tenant_id, "fixture must span two tenants"
    assert find_merges([survivor], [stale]) == []


def test_find_merges_still_coalesces_within_one_tenant():
    # The tenant guard must not disarm the merge itself: same tenant, same
    # incident re-identified across windowing, still tombstones.
    survivor = dataclasses.replace(
        _obj(["leaf1", "spine1"], "surv", 2, 7), tenant_id="tenant-b")
    stale = dataclasses.replace(
        _obj(["leaf1", "spine1"], "stale", 0, 4), tenant_id="tenant-b")
    assert find_merges([survivor], [stale]) == [("stale", "surv")]


def test_find_merges_is_deterministic_and_order_invariant():
    a = _obj(["leaf1", "spine1"], "aaa", 0, 5)   # earlier window
    b = _obj(["leaf1", "spine1"], "bbb", 1, 6)
    stale = _obj(["leaf1", "spine1"], "stale", 0, 5)  # equal overlap to both → tie-break
    r1 = find_merges([a, b], [stale])
    r2 = find_merges([b, a], [stale])
    assert r1 == r2 == [("stale", "aaa")]  # tie → earliest window_start, then cid


# ── C3: degradation markers — stale-topology w_topo cap + declaration (§8) ────
def test_stale_topology_caps_w_topo():
    nodes = build_nodes((
        sig("link_state_change", EntityType.DEVICE, "leaf1"),
        sig("device_resource_anomaly", EntityType.DEVICE, "leaf1", offset_s=1),
    ))
    fresh, _ = build_edges(nodes, (), EngineConfig())
    stale, _ = build_edges(nodes, (), EngineConfig(), topology_stale=True)
    assert fresh and stale
    assert fresh[0].w_topo == 0.9                  # same-device containment, full weight
    assert stale[0].w_topo == 0.4                  # capped to w_topo_stale_cap (§8)
    assert stale[0].weight <= fresh[0].weight      # a stale edge never outweighs a fresh one


def test_healthy_snapshot_declares_no_degradation_and_blob_is_unchanged():
    # The replay-safety guarantee: a healthy object's blob has NO degradation key, so
    # its content_hash + replay pin are byte-identical to pre-C3 — no churn, no drift.
    snap = run_window(golden_window(), builtin_catalog(), (DALLAS_SEAM,))[0]
    assert snap.topology_stale is False and snap.storm_mode is False
    assert '"degradation"' not in snap.hypotheses_blob()


def test_degraded_snapshot_declares_degradation():
    snap = run_window(golden_window(), builtin_catalog(), (DALLAS_SEAM,),
                      topology_stale=True, storm_mode=True)[0]
    assert snap.topology_stale and snap.storm_mode
    assert '"degradation":{"storm_mode":true,"topology_stale":true}' in snap.hypotheses_blob()


def test_degradation_changes_content_hash_so_a_transition_versions():
    healthy = run_window(golden_window(), builtin_catalog(), (DALLAS_SEAM,))[0]
    degraded = run_window(golden_window(), builtin_catalog(), (DALLAS_SEAM,), topology_stale=True)[0]
    assert healthy.content_hash() != degraded.content_hash()  # a real state change → new version
