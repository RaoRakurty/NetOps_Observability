"""Tracker 165 phase 6 — RCA ground-truth A/B under two retention regimes.

The same deterministic story is pushed through two windows:

  Run A  count-limited (capacity eviction active)  — current product behaviour
  Run B  large enough to hold the engine's full temporal reach — reference

Everything that differs between them is caused by RETENTION, not by the story.

The result this pins is the one that makes tracker 165 a correctness issue
rather than a tuning issue: as retention shrinks, the RCA object's VERDICT TIER
does not move. It stays `suspected` while its evidence base collapses from four
nodes and six edges to one node and zero edges, and then to no object at all.
An operator watching verdicts alone sees nothing happen. That is why the
degradation state has to be reported explicitly.
"""
from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timedelta, timezone

import pytest

import main
import signals as S
from catalog import builtin_catalog
from engine import SeamView, run_window

TENANT = "acme"
CAT = builtin_catalog()
SEAMS = (SeamView(seam_id="dallas-dx-equinix", tenant_id=TENANT, seam_type="DX",
                  endpoints=(("on_prem", "dallas-edge"),
                             ("provider_edge", "equinix-pop"))),)
# Anchored to now: a story stamped in the fixed past trips the H14 age bound and
# a story stamped in the future is clamped to arrival — either would collapse the
# event-time spread this fixture is built on.
T0 = datetime.now(timezone.utc) - timedelta(seconds=400)


def _sig(kind, etype, eid, off, *, modality, source, sev=S.Severity.HIGH,
         obs="dallas-edge", tokens=("dallas-edge",)):
    return S.Signal(
        tenant_id=TENANT, ts=T0 + timedelta(seconds=off), source=source, kind=kind,
        observer=S.observer_of(obs, S.ObserverType.DEVICE,
                               collection_path="direct", clock_quality="unknown"),
        modality_class=modality, entity_type=etype, entity_id=eid, severity=sev,
        native_id=f"{kind}|{eid}|{off}", entity_tokens=tokens,
        attrs={"onset_uncertainty_s": 5.0})


# Cause at T+0, effects at T+120 / T+240, cross-modality corroboration at T+350.
# The widest span is 350 s — inside the engine's 396.5 s reach, so every one of
# these is evidence the engine is still entitled to use.
STORY = (
    _sig("bgp_session_down", S.EntityType.DEVICE, "dallas-edge", 0,
         modality=S.ModalityClass.CONTROL_PLANE, source=S.Source.SYSLOG),
    _sig("link_state_change", S.EntityType.INTERFACE, "dallas-edge:Gi0/1", 120,
         modality=S.ModalityClass.CONTROL_PLANE, source=S.Source.SYSLOG),
    _sig("if_util_high", S.EntityType.INTERFACE, "dallas-edge:Gi0/1", 240,
         modality=S.ModalityClass.DEVICE_TELEMETRY, source=S.Source.METRIC),
    _sig("probe_loss", S.EntityType.DEVICE, "dallas-edge", 350,
         modality=S.ModalityClass.ACTIVE_PROBE, source=S.Source.PROBE),
)
STORY_KINDS = frozenset(s.kind for s in STORY)
NOISE_PER_BEAT = 200


def _noise(n, off_base):
    """Unrelated same-tenant load on other devices, with their OWN tokens so
    they cannot ground against the story. They can only push it out."""
    return [_sig("metric_anomaly", S.EntityType.DEVICE, f"noise-{i % 97}",
                 off_base + i * 0.01, modality=S.ModalityClass.DEVICE_TELEMETRY,
                 source=S.Source.METRIC, sev=S.Severity.WARN,
                 obs=f"noise-{i % 97}", tokens=(f"noise-{i % 97}",))
            for i in range(n)]


def _run(maxlen: int, *, lag_s: float = 0.0, prune: bool = False) -> dict:
    main.WINDOW_BUFFER = deque(maxlen=maxlen)
    main._BUFFERED_ID_ORDER = deque(maxlen=maxlen)
    main._BUFFERED_IDS = set()
    main.TENANT_WATERMARK.clear()
    before_drop = main.WINDOW_OVERFLOW_DROPPED
    before_elig = main.WINDOW_OVERFLOW_IN_HORIZON
    for s in STORY:
        main.buffer_signal(s)
        for n in _noise(NOISE_PER_BEAT, (s.ts - T0).total_seconds() + 1):
            main.buffer_signal(n)
    if prune:
        # The real product path: the engine prunes before every evaluation.
        # `lag_s` is WALL-CLOCK processing delay, which since tracker 165 must
        # have no effect on what survives.
        asyncio.run(main._prune_buffer(
            datetime.now(timezone.utc) + timedelta(seconds=lag_s)))
    held = tuple(s for s in main.WINDOW_BUFFER if s.tenant_id == TENANT)
    snaps = run_window(held, CAT, SEAMS)
    obj = snaps[0] if snaps else None
    return {
        "span_s": main._window_span_s(),
        "eligible_drops": main.WINDOW_OVERFLOW_IN_HORIZON - before_elig,
        "total_drops": main.WINDOW_OVERFLOW_DROPPED - before_drop,
        "degraded": main.rca_evidence_degraded(),
        "reason": main.rca_degradation_reason(),
        "story_kept": sorted(s.kind for s in held if s.kind in STORY_KINDS),
        "objects": len(snaps),
        "tier": obj.ranking.verdict_tier.value if obj else None,
        "top": obj.ranking.top_hypothesis if obj else None,
        "story_nodes": sorted(n.key for n in obj.nodes
                              if "noise" not in n.key) if obj else [],
        "edges": len(obj.edges) if obj else 0,
    }


@pytest.fixture(scope="module")
def runs():
    return {ml: _run(ml) for ml in (60, 200, 300, 500, 700, 20000)}


# ── Run B: the reference ─────────────────────────────────────────────────────

def test_run_B_reference_recovers_the_whole_story(runs):
    b = runs[20000]
    assert b["total_drops"] == 0
    assert b["degraded"] is False
    assert b["span_s"] > 350
    assert b["story_kept"] == sorted(STORY_KINDS)
    assert b["objects"] == 1
    assert b["tier"] == "suspected"
    assert len(b["story_nodes"]) == 4
    assert b["edges"] == 6


# ── Run A: count-limited ─────────────────────────────────────────────────────

def test_run_A_loses_the_object_entirely_at_a_tight_cap(runs):
    """Classification 1 — verdict CHANGES. Not weaker: absent."""
    a = runs[60]
    assert a["eligible_drops"] > 0
    assert a["degraded"] is True
    assert a["story_kept"] == []
    assert a["objects"] == 0, "the RCA finding is gone, not merely thinner"


@pytest.mark.parametrize("maxlen,nodes,edges", [(300, 1, 0), (500, 2, 1), (700, 3, 3)])
def test_the_evidence_base_erodes_with_retention(runs, maxlen, nodes, edges):
    """Classification 3 — verdict same, EVIDENCE changes. The object survives
    with the same headline while its causal graph is hollowed out."""
    r = runs[maxlen]
    assert r["objects"] == 1
    assert len(r["story_nodes"]) == nodes
    assert r["edges"] == edges
    assert r["degraded"] is True


def test_the_verdict_tier_hides_the_degradation(runs):
    """The finding that forces an explicit degradation signal: every retention
    level that produces an object produces the SAME tier. Watching verdicts
    cannot distinguish a four-node, six-edge object from a one-node, zero-edge
    one."""
    tiers = {ml: r["tier"] for ml, r in runs.items() if r["objects"]}
    assert set(tiers.values()) == {"suspected"}, tiers
    assert runs[300]["edges"] == 0 and runs[20000]["edges"] == 6, (
        "the evidence differs by six edges under an identical verdict")


def test_degradation_is_monotone_in_retention(runs):
    """More retention is never less evidence — a sanity property that would
    catch a fixture that had started measuring noise instead of the story."""
    order = [60, 200, 300, 500, 700, 20000]
    ns = [len(runs[m]["story_nodes"]) for m in order]
    es = [runs[m]["edges"] for m in order]
    assert ns == sorted(ns), ns
    assert es == sorted(es), es


def test_every_shed_story_signal_was_counted_as_still_eligible(runs):
    """The degradation counter must actually cover this loss. If eligible drops
    were zero while the story vanished, the metric would be decorative."""
    for ml in (60, 200, 300, 500, 700):
        r = runs[ml]
        assert r["eligible_drops"] > 0, ml
        assert r["eligible_drops"] <= r["total_drops"]


# ── Phase 13: the NEW normal implementation vs the reference ─────────────────

@pytest.fixture(scope="module")
def shipped():
    """The product as it now ships: a record cap that is a safety ceiling
    rather than the horizon, stream-time expiry, and the engine's real prune
    running before evaluation — at four wall-clock processing delays."""
    return {lag: _run(20000, lag_s=lag, prune=True)
            for lag in (0, 900, 3600, 86400)}


def test_the_shipped_path_matches_the_reference_at_every_lag(runs, shipped):
    """The acceptance test for tracker 165.

    Reference (no pressure, no pruning) gave 4 nodes / 6 edges / suspected.
    The shipped path must reproduce that EXACTLY — including after a full day
    of wall-clock backlog, which under the old wall-clock horizon erased the
    story entirely.
    """
    ref = runs[20000]
    for lag, got in shipped.items():
        assert got["objects"] == ref["objects"] == 1, lag
        assert got["tier"] == ref["tier"], lag
        assert got["top"] == ref["top"], lag
        assert got["story_nodes"] == ref["story_nodes"], (
            f"evidence membership differs at lag={lag}s")
        assert got["edges"] == ref["edges"] == 6, (
            f"causal graph differs at lag={lag}s: {got['edges']} vs 6")


def test_the_shipped_path_is_not_degraded(shipped):
    """No resource ceiling binds at the reference size, so nothing is shed and
    the degradation state stays clean — the flag must not cry wolf either."""
    for lag, got in shipped.items():
        assert got["degraded"] is False, lag
        assert got["reason"] == "none", lag
        assert got["eligible_drops"] == 0, lag


def test_a_day_of_backlog_no_longer_hollows_the_graph(shipped):
    """The headline: 4 nodes / 6 edges at 24 h of processing delay. The prior
    wave measured 1 node / 0 edges under a fraction of that."""
    day = shipped[86400]
    assert len(day["story_nodes"]) == 4
    assert day["edges"] == 6


def test_when_the_ceiling_DOES_bind_the_reason_is_resource_capacity():
    """The ceiling still exists and still protects the process — but it now
    announces itself, with a reason, instead of silently redefining the
    horizon."""
    got = _run(200, prune=True)
    assert got["degraded"] is True
    assert got["reason"] == "resource_capacity"
    assert got["eligible_drops"] > 0
