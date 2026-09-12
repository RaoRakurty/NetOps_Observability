# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 165 — the engine's temporal reach is DERIVED, not declared.

`window_s = 900.0` was never an RCA contract: the engine core never reads it
(its one appearance in engine.py is a comment saying the *caller* buffers it).
What actually bounds correlation in time is the scoring rule

    w_t    = exp(-gap / tau_s)
    weight = min(w_t * w_topo * w_r, 1.0)   admitted iff weight >= attach_threshold

so the maximum useful gap is a CONSEQUENCE of the weights, not a tunable. These
tests pin the closed form to the real `build_edges` behaviour: if anyone retunes
tau_s, attach_threshold, a w_topo or the cross-modality multiplier, the derived
reach moves with it — and if the closed form ever stops agreeing with what the
engine actually admits, these go red.
"""

import math

import pytest

from engine import (
    NEVER_ATTACHABLE,
    EngineConfig,
    build_edges,
    build_nodes,
    engine_temporal_reach_s,
    max_attachable_gap_s,
    required_retention_s,
    temporal_reach_table,
)
from signals import EntityType, ModalityClass
from test_engine import sig

CFG = EngineConfig()


# ── the empirical oracle: what does build_edges ACTUALLY admit? ───────────────

def _admits(gap_s: float, *, cross: bool, cfg: EngineConfig = CFG) -> bool:
    """Ground truth from the engine itself: same-device containment pair
    separated by `gap_s` of EVENT time — does an edge survive admission?"""
    mod_b = (ModalityClass.ACTIVE_PROBE if cross
             else ModalityClass.DEVICE_TELEMETRY)
    nodes = build_nodes((
        sig("if_util_high", EntityType.INTERFACE, "leaf1:Gi0/1", observer="leaf1"),
        sig("qos_drops", EntityType.INTERFACE, "leaf1:Gi0/1", observer="leaf1",
            offset_s=gap_s, modality=mod_b),
    ))
    assert len(nodes) == 2, "fixture must produce two distinct nodes"
    edges, _gaps = build_edges(nodes, (), cfg)
    return len(edges) == 1


def _empirical_max_gap(*, cross: bool, cfg: EngineConfig = CFG,
                       hi: float = 5000.0, tol: float = 1e-4) -> float:
    """Bisect the real engine for the largest gap it still admits."""
    lo = 0.0
    assert _admits(lo, cross=cross, cfg=cfg), "gap 0 must attach"
    assert not _admits(hi, cross=cross, cfg=cfg), "hi must be beyond reach"
    while hi - lo > tol:
        mid = (lo + hi) / 2
        if _admits(mid, cross=cross, cfg=cfg):
            lo = mid
        else:
            hi = mid
    return lo


@pytest.mark.parametrize("cross", [False, True])
def test_closed_form_matches_the_engine_at_the_boundary(cross):
    """The derivation is only worth anything if it predicts real admission."""
    derived = max_attachable_gap_s(CFG, CFG.w_topo_containment, cross_modality=cross)
    empirical = _empirical_max_gap(cross=cross)
    assert empirical == pytest.approx(derived, abs=0.01), (
        f"closed form {derived:.4f}s disagrees with engine {empirical:.4f}s")


@pytest.mark.parametrize("cross", [False, True])
def test_just_inside_attaches_just_outside_does_not(cross):
    """A one-second straddle of the derived boundary, through build_edges."""
    g = max_attachable_gap_s(CFG, CFG.w_topo_containment, cross_modality=cross)
    assert _admits(g - 0.5, cross=cross)
    assert not _admits(g + 0.5, cross=cross)


def test_the_reach_is_the_cross_modality_containment_corner():
    """396.5s, and it comes from the strongest grounding TIMES the reinforcement
    — not from clamping the product at 1.0 first (that would say 361.2s, the
    seam/cross figure, and under-retain by 35 seconds)."""
    reach = engine_temporal_reach_s(CFG)
    assert reach == pytest.approx(396.5267, abs=1e-3)
    assert reach == pytest.approx(
        max_attachable_gap_s(CFG, CFG.w_topo_containment, cross_modality=True))
    # the clamp-first mistake, pinned so it cannot be reintroduced silently
    clamp_first = CFG.tau_s * math.log(1.0 / CFG.attach_threshold)
    assert reach > clamp_first
    assert clamp_first == pytest.approx(361.1918, abs=1e-3)


def test_reach_is_the_max_over_the_published_table():
    table = temporal_reach_table(CFG)
    assert engine_temporal_reach_s(CFG) == max(r["max_gap_s"] for r in table)
    assert len(table) == 12          # 6 grounding classes x 2 modality cases


def test_every_table_row_is_confirmed_by_the_closed_form():
    for row in temporal_reach_table(CFG):
        assert row["max_gap_s"] == max_attachable_gap_s(
            CFG, row["w_topo"], cross_modality=row["cross_modality"])


# ── the derivation must MOVE when the weights move ───────────────────────────

def test_reach_scales_linearly_with_tau():
    doubled = EngineConfig(tau_s=CFG.tau_s * 2)
    assert engine_temporal_reach_s(doubled) == pytest.approx(
        2 * engine_temporal_reach_s(CFG))


def test_raising_the_threshold_shortens_the_reach_and_the_engine_agrees():
    strict = EngineConfig(attach_threshold=0.6)
    derived = max_attachable_gap_s(strict, strict.w_topo_containment, cross_modality=True)
    assert derived < engine_temporal_reach_s(CFG)
    assert _empirical_max_gap(cross=True, cfg=strict) == pytest.approx(derived, abs=0.01)


def test_stale_topology_collapses_the_reach():
    """§8 caps w_topo at 0.4 when the topology view is stale — the reach must
    fall with it, or a degraded engine would be told to retain as if healthy."""
    healthy = engine_temporal_reach_s(CFG)
    stale = engine_temporal_reach_s(CFG, topology_stale=True)
    assert stale < healthy
    assert stale == pytest.approx(
        max_attachable_gap_s(CFG, CFG.w_topo_stale_cap, cross_modality=True))


def test_grounding_too_weak_to_ever_attach_is_reported_not_guessed():
    """product < threshold ⇒ no gap works, not 'gap 0 works'."""
    assert max_attachable_gap_s(CFG, 0.2, cross_modality=False) == NEVER_ATTACHABLE
    # and the engine agrees: a config whose ONLY grounding is that weak admits nothing
    weak = EngineConfig(w_topo_containment=0.2, reinforce_cross_modality=1.0)
    assert not _admits(0.0, cross=False, cfg=weak)


def test_exactly_at_threshold_still_attaches_at_gap_zero():
    """product == attach_threshold is admitted (>=, not >) — boundary direction."""
    edge = EngineConfig(w_topo_containment=0.3, reinforce_cross_modality=1.0)
    assert max_attachable_gap_s(edge, 0.3, cross_modality=False) == pytest.approx(0.0)
    assert _admits(0.0, cross=False, cfg=edge)


# ── retention contract ───────────────────────────────────────────────────────

def test_retention_is_reach_plus_declared_lateness():
    assert required_retention_s(CFG, permitted_lateness_s=0.0) == pytest.approx(
        engine_temporal_reach_s(CFG))
    assert required_retention_s(CFG, permitted_lateness_s=120.0) == pytest.approx(
        engine_temporal_reach_s(CFG) + 120.0)


def test_lateness_must_be_supplied_never_negative():
    with pytest.raises(ValueError):
        required_retention_s(CFG, permitted_lateness_s=-1.0)


def test_window_s_is_gone_from_the_engine_config():
    """The whole point of 165: a second temporal constant sat next to tau_s
    describing the same concept and nothing related them, so it drifted. It is
    removed outright — the retention requirement derives from the scoring rule
    and cannot disagree with it."""
    assert not hasattr(CFG, "window_s")
    assert "window_s" not in CFG.__dataclass_fields__
    # the retired constant was 900 s: ~2.3x more than can ever attach
    assert 900.0 / engine_temporal_reach_s(CFG) > 2.0
