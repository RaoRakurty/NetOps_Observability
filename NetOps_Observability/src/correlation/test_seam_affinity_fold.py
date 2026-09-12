# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 154 — grounded-seam evidence in ranking and object folding.

Measured by the digital twin's ground truth (run 081700325h7x, DX-flap story):

  (a) ranking ties at EQUAL confidence ignored the grounded seam's TYPE — the
      DIA/isp signature outranked the private-interconnect/carrier signature on
      a DX-grounded object purely by lexical template id;
  (b) a cloud-only object stood apart from the incident it was bridged to
      through the shared DX seam (entity-set Jaccard = 0 across the seam).

Properties pinned here:

  tie-break — grounded DX seam ⇒ the interconnect signature wins the tie; a
  strictly-higher-confidence hypothesis is NEVER displaced; no grounded seam
  (or token-only / foreign-tenant seam) ⇒ order unchanged; confidence numbers
  untouched.

  fold — same tenant + entity sets bridged through a shared grounded seam ⇒
  one object in-window and a merge/continuation candidate cross-cycle;
  different tenants NEVER fold (§3a — the twin's negative control is the
  regression canary); no shared seam ⇒ unchanged; window-overlap and all other
  merge guards unchanged.
"""

import dataclasses

from catalog import builtin_catalog
from engine import (
    Edge,
    Grounding,
    SeamView,
    _break_ties_by_seam_affinity,
    find_continuation,
    find_merges,
    run_window,
)
from path_graph import seam_relation
from scoring import HypothesisScore, RankingResult
from signals import EntityType, ModalityClass, Severity
from test_engine import sig
from verdicts import EvidenceCoverage, VerdictTier
from verdicts import Verdict as GateVerdict

DX_SEAM = SeamView(
    seam_id="dal-dx-1",
    tenant_id="",
    seam_type="DX",
    endpoints=(("member_edge", "edge-a1"),
               ("provider_resource", "dxcon-1/vif-100")),
)


def _dx_window(offset_s: float = 0.0) -> list:
    """The twin's DX-flap evidence shape: control-plane BGP fault on the edge
    device + customer-path probe loss across the seam. Both the DIA-egress and
    the private-interconnect signatures cover this fully — a real ranking tie."""
    return [
        sig("bgp_adjacency_change", EntityType.DEVICE, "edge-a1",
            offset_s=offset_s, observer="dev1",
            modality=ModalityClass.CONTROL_PLANE, severity=Severity.CRIT),
        sig("probe_loss", EntityType.PATH, "vantage-1->edge-a1",
            offset_s=offset_s + 10, observer="probe1",
            modality=ModalityClass.ACTIVE_PROBE, severity=Severity.CRIT),
    ]


def _cloud_window(offset_s: float = 0.0) -> list:
    """The provider-side half: two cloud signals on the DX attachment resource
    (a seam endpoint) — entity set DISJOINT from the network half's."""
    return [
        sig("cloud_bgp_session_down", EntityType.CLOUD_RESOURCE, "dxcon-1/vif-100",
            offset_s=offset_s, observer="cloudapi",
            modality=ModalityClass.CONTROL_PLANE, severity=Severity.CRIT),
        sig("cloud_route_count_drop", EntityType.CLOUD_RESOURCE, "dxcon-1/vif-100",
            offset_s=offset_s + 10, observer="cloudapi2",
            modality=ModalityClass.DEVICE_TELEMETRY, severity=Severity.CRIT),
    ]


# ── tie-break: grounded-seam-type affinity ────────────────────────────────────


def test_dx_grounded_tie_prefers_interconnect_signature():
    snaps = run_window(_dx_window(), builtin_catalog(), (DX_SEAM,))
    assert len(snaps) == 1
    snap = snaps[0]
    # Premise: the object is seam-grounded (authoritative rank-2 seam edge).
    assert any(e.grounding.kind == "seam" and e.grounding.authoritative
               and e.grounding.ref == "dal-dx-1" for e in snap.edges)
    r = snap.ranking
    by_id = {h.template_id: h for h in r.hypotheses}
    dia = by_id["sig.ent.middle-mile.dia-egress-corroborated"]
    icx = by_id["sig.ent.middle-mile.private-interconnect-bgp-down"]
    # Premise: a genuine tie — equal confidence, so this is ONLY a tie-break.
    assert dia.confidence_rank == icx.confidence_rank
    # The grounded seam is a DX interconnect: the interconnect signature
    # (CARRIER_INTERCONNECT + CLOUD_APP affinity) must win the tie.
    assert r.top_hypothesis == "sig.ent.middle-mile.private-interconnect-bgp-down"
    # Seam-level ownership follows: the named owner is the carrier, not the ISP.
    assert icx.owner == "carrier"
    # Confidence order is intact — the ranked list never puts a lower
    # confidence above a higher one (nothing fabricated, ties only re-ordered).
    confs = [h.confidence_rank for h in r.hypotheses]
    assert confs == sorted(confs, reverse=True)


def test_no_grounded_seam_leaves_order_unchanged():
    # Same evidence, no seam inventory: the pair grounds via shared resource
    # identity (rank 1, 'topo') — no seam evidence, so the pre-154 deterministic
    # order stands (DIA-egress first by the (-conf, -satisfied, id) sort).
    snaps = run_window(_dx_window(), builtin_catalog(), ())
    assert len(snaps) == 1
    snap = snaps[0]
    assert all(e.grounding.kind != "seam" for e in snap.edges)
    assert snap.ranking.top_hypothesis == "sig.ent.middle-mile.dia-egress-corroborated"


def _hyp(tid: str, conf: float, seams: tuple[str, ...],
         tier: VerdictTier = VerdictTier.SUSPECTED) -> HypothesisScore:
    return HypothesisScore(
        template_id=tid, title=tid, coverage=1.0, confidence_rank=conf,
        contradicted=False,
        verdict_gate=GateVerdict(
            tier=tier,
            coverage=EvidenceCoverage(
                modality_classes=frozenset(), observer_ids=frozenset(),
                independent_pair=None, fate_groups=()),
            reasons=()),
        satisfied=("k1",), missing=(), contradictions=(),
        forced_competitors=(), notes=(), owner="netops", first_steps=(),
        seams=seams,
    )


def _dx_seam_edge(authoritative: bool = True) -> Edge:
    return Edge(
        from_node="device:edge-a1:bgp_adjacency_change",
        to_node="path:vantage-1->edge-a1:probe_loss",
        grounding=Grounding("seam", "dal-dx-1",
                            seam_relation("dal-dx-1", authoritative)),
        weight=0.8, w_temporal=1.0, w_topo=0.8, w_reinforce=1.0,
        direction_conf=0.0, direction_basis="none",
    )


def _ranking(hyps: tuple[HypothesisScore, ...]) -> RankingResult:
    return RankingResult(
        top_hypothesis=hyps[0].template_id,
        verdict_tier=hyps[0].verdict_gate.tier,
        hypotheses=hyps, evidence_missing=(), catalog_version="test",
    )


def test_higher_confidence_wrong_affinity_still_wins():
    # A strictly-higher-confidence hypothesis with NO seam affinity must never
    # be displaced by a lower-confidence one with perfect affinity.
    hyps = (_hyp("sig.a.wrong-affinity", 1.0, ()),
            _hyp("sig.b.right-affinity", 0.9, ("CARRIER_INTERCONNECT", "CLOUD_APP")))
    r = _ranking(hyps)
    out = _break_ties_by_seam_affinity(r, (_dx_seam_edge(),), (DX_SEAM,), "")
    assert out == r  # untouched — no tie, no re-order


def test_tie_group_reorders_but_lower_ranks_untouched():
    hyps = (_hyp("sig.a.no-affinity", 1.0, ("DC_FABRIC",)),
            _hyp("sig.b.affine", 1.0, ("CARRIER_INTERCONNECT",)),
            _hyp("sig.c.low", 0.5, ("CARRIER_INTERCONNECT", "CLOUD_APP")))
    out = _break_ties_by_seam_affinity(_ranking(hyps), (_dx_seam_edge(),),
                                       (DX_SEAM,), "")
    assert [h.template_id for h in out.hypotheses] == \
        ["sig.b.affine", "sig.a.no-affinity", "sig.c.low"]
    assert out.top_hypothesis == "sig.b.affine"
    assert out.verdict_tier is VerdictTier.SUSPECTED  # tier still from the gate
    # Confidence numbers are byte-identical — nothing fabricated.
    assert [h.confidence_rank for h in out.hypotheses] == [1.0, 1.0, 0.5]


def test_token_matched_seam_edge_carries_no_affinity():
    # A rank-7 (non-authoritative) seam edge is a name coincidence: no re-order.
    hyps = (_hyp("sig.a.no-affinity", 1.0, ()),
            _hyp("sig.b.affine", 1.0, ("CARRIER_INTERCONNECT",)))
    r = _ranking(hyps)
    out = _break_ties_by_seam_affinity(
        r, (_dx_seam_edge(authoritative=False),), (DX_SEAM,), "")
    assert out == r


def test_foreign_tenant_seam_carries_no_affinity():
    foreign = dataclasses.replace(DX_SEAM, tenant_id="tenant-b")
    hyps = (_hyp("sig.a.no-affinity", 1.0, ()),
            _hyp("sig.b.affine", 1.0, ("CARRIER_INTERCONNECT",)))
    r = _ranking(hyps)
    out = _break_ties_by_seam_affinity(r, (_dx_seam_edge(),), (foreign,), "tenant-a")
    assert out == r


def test_undetermined_result_untouched():
    r = RankingResult(top_hypothesis="undetermined",
                      verdict_tier=VerdictTier.UNDETERMINED,
                      hypotheses=(_hyp("sig.a", 0.1, ()),
                                  _hyp("sig.b", 0.1, ("CARRIER_INTERCONNECT",))),
                      evidence_missing=("sig.a: needs x",), catalog_version="test")
    assert _break_ties_by_seam_affinity(r, (_dx_seam_edge(),), (DX_SEAM,), "") == r


# ── fold, in-window: seam-bridged components become ONE object ────────────────


def test_run_window_folds_seam_bridged_components():
    # Network half at t=0, cloud half at t=500: every cross pair decays below
    # attach_threshold (gap ≈ 490 s > ~361 s cross-modality ceiling), so edge
    # admission alone yields TWO components — but both halves sit on the same
    # grounded DX seam, so they must fold into ONE incident.
    window = _dx_window(0) + _cloud_window(500)
    snaps = run_window(window, builtin_catalog(), (DX_SEAM,))
    assert len(snaps) == 1, "seam-bridged halves must fold to ONE object"
    snap = snaps[0]
    ents = {n.entity_id for n in snap.nodes}
    assert {"edge-a1", "vantage-1->edge-a1", "dxcon-1/vif-100"} <= ents
    # No edge was fabricated across the fold: every cross-half pair stays
    # unconnected (the halves' own grounded edges are carried as they are).
    cloud_keys = {n.key for n in snap.nodes if n.entity_type is EntityType.CLOUD_RESOURCE}
    for e in snap.edges:
        assert (e.from_node in cloud_keys) == (e.to_node in cloud_keys), \
            "fold must not fabricate cross-half edges"


def test_run_window_fold_is_order_invariant():
    cat = builtin_catalog()
    window = _dx_window(0) + _cloud_window(500)
    a = run_window(window, cat, (DX_SEAM,))
    b = run_window(list(reversed(window)), cat, (DX_SEAM,))
    assert [s.content_hash() for s in a] == [s.content_hash() for s in b]


def test_run_window_no_fold_without_shared_seam():
    # Same two halves, empty seam inventory: each half grounds internally via
    # resource identity, nothing bridges them — two objects, unchanged.
    window = _dx_window(0) + _cloud_window(500)
    snaps = run_window(window, builtin_catalog(), ())
    assert len(snaps) == 2


def test_run_window_fold_ignores_foreign_tenant_seam():
    # §3a default-closed: a seam owned by ANOTHER tenant can never bridge this
    # window's components (the twin's negative control shape).
    foreign = dataclasses.replace(DX_SEAM, tenant_id="tenant-b")
    window = _dx_window(0) + _cloud_window(500)
    snaps = run_window(window, builtin_catalog(), (foreign,))
    assert len(snaps) == 2


# ── fold, cross-cycle: find_merges / find_continuation ───────────────────────


def _net_snap():
    return run_window(_dx_window(0), builtin_catalog(), (DX_SEAM,))[0]


def _cloud_snap(offset_s: float = 5.0):
    return run_window(_cloud_window(offset_s), builtin_catalog(), (DX_SEAM,))[0]


def test_find_merges_folds_seam_bridged_disjoint_halves():
    surv, stale = _net_snap(), _cloud_snap(5)
    # Premise: disjoint entity sets (Jaccard 0) + overlapping windows.
    assert not ({n.entity_id for n in surv.nodes}
                & {n.entity_id for n in stale.nodes})
    assert find_merges([surv], [stale]) == \
        [(stale.correlation_id, surv.correlation_id)]


def test_find_merges_seam_bridge_never_crosses_tenants():
    # The §3a guard outranks the bridge: same seam, same entities, other tenant.
    surv = _net_snap()
    stale = dataclasses.replace(_cloud_snap(5), tenant_id="tenant-b")
    assert find_merges([surv], [stale]) == []


def test_find_merges_no_bridge_without_shared_seam():
    # The cloud half grounded on a DIFFERENT seam (disjoint endpoints): no
    # shared grounded seam, disjoint entities — unchanged, no merge.
    other = SeamView(seam_id="fra-dx-9", tenant_id="", seam_type="DX",
                     endpoints=(("member_edge", "edge-z9"),
                                ("provider_resource", "dxcon-1/vif-100")))
    surv = _net_snap()
    stale = run_window(_cloud_window(60), builtin_catalog(), (other,))[0]
    assert find_merges([surv], [stale]) == []


def test_find_merges_seam_bridge_still_requires_window_overlap():
    # Existing guard unchanged: bridged halves in disjoint time windows are two
    # incidents, not one.
    surv = _net_snap()  # window ≈ [T0, T0+10s]
    stale = _cloud_snap(7200)  # two hours later
    assert find_merges([surv], [stale]) == []


def test_find_continuation_adopts_via_seam_bridge():
    open_obj, rekeyed = _net_snap(), _cloud_snap(5)
    assert find_continuation(rekeyed, [open_obj]) == open_obj.correlation_id


def test_find_continuation_seam_bridge_never_crosses_tenants():
    open_obj = _net_snap()
    rekeyed = dataclasses.replace(_cloud_snap(5), tenant_id="tenant-b")
    assert find_continuation(rekeyed, [open_obj]) == ""
