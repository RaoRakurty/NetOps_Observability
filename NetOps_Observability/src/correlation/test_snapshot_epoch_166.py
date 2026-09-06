# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 166 — the snapshot/drain epoch.

Bounded cohorts limited pair EMISSION but not the per-transaction FIXED cost:
build_edges prepared toks/refs/seam+path memberships for every retained node and
_candidate_pairs built its inverted index over all of them, on EVERY transaction.
Splitting a cycle into K cohorts paid it K times.

`prepare_run_window` lifts all of that to a snapshot epoch. This file pins the
three things that makes true:

  1. INVARIANT (Phase 8) — K cohorts over one unchanged snapshot perform ONE
     preparation and ONE index build, not K.
  2. INVALIDATION (Phase 3) — a prep is reused only for the inputs it was built
     from. Every guarded input has a negative control; a guard that cannot go
     red is not a guard.
  3. EQUIVALENCE (Phase 10) — a prepped transaction is byte-identical to an
     unprepped one, and to the full-window reference, at every cohort count.

See docs/scale/SNAPSHOT_EPOCH_166.md for the design these pin.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import engine as eng
from catalog import builtin_catalog
from engine import (
    NO_ADJACENCY,
    EngineConfig,
    SeamView,
    TopologyAdjacency,
    build_edges,
    build_nodes,
    prepare_run_window,
    prepare_window,
    run_window,
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

T0 = datetime(2026, 8, 21, 9, 0, 0, tzinfo=timezone.utc)
CAT = builtin_catalog()


def sig(kind, etype, eid, *, offset_s=0.0, tokens=(), tenant="t1",
        modality=ModalityClass.DEVICE_TELEMETRY):
    return Signal(
        tenant_id=tenant, ts=T0 + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=kind, observer=Observer(observer_id="obs1", observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=etype, entity_id=eid,
        severity=Severity.HIGH, native_id=f"t|{kind}|{eid}|{offset_s}",
        entity_tokens=tokens, attrs={"onset_uncertainty_s": 5.0})


def estate(n_devices=24, per_device=3, tenant="t1"):
    """Every rung represented: containment, shared token, adjacency, seam,
    cross-modality — so a change in any of them can move the result."""
    sigs = []
    for d in range(n_devices):
        site = f"site-{d % 4}"
        sigs.append(sig("device_cpu_high", EntityType.DEVICE, f"dev-{d}",
                        offset_s=d % 20, tokens=(site,), tenant=tenant))
        for k in range(per_device):
            sigs.append(sig("if_errors", EntityType.INTERFACE, f"dev-{d}:Et{k}",
                            offset_s=(d + k) % 20, tokens=(site,), tenant=tenant,
                            modality=(ModalityClass.ACTIVE_PROBE if k % 2 else
                                      ModalityClass.DEVICE_TELEMETRY)))
    seams = tuple(
        SeamView(seam_id=f"seam-{s}", tenant_id=tenant, seam_type="DX",
                 endpoints=(("on_prem", f"dev-{s}"), ("provider_edge", f"pop-{s}")))
        for s in range(3))
    adjacency = TopologyAdjacency.from_links(
        [{"a": f"dev-{d}", "b": f"dev-{d + 1}"} for d in range(0, n_devices - 1, 2)])
    return tuple(sigs), seams, adjacency


def cohorts_of(nodes, k):
    """Split the node keys into k arrival-ordered cohorts."""
    keys = [n.key for n in nodes]
    size = (len(keys) + k - 1) // k
    return [frozenset(keys[i:i + size]) for i in range(0, len(keys), size)]


class _Counter:
    """Counts calls to the engine's two preparation entry points."""

    def __init__(self, monkeypatch):
        self.preps = 0
        self.indexes = 0
        real_prep, real_index = eng.prepare_window, eng._CandidateIndex

        def counting_prep(*a, **kw):
            self.preps += 1
            return real_prep(*a, **kw)

        def counting_index(*a, **kw):
            self.indexes += 1
            return real_index(*a, **kw)

        monkeypatch.setattr(eng, "prepare_window", counting_prep)
        monkeypatch.setattr(eng, "_CandidateIndex", counting_index)


# ── 1. the invariant: once per epoch, not once per cohort (Phase 8) ──────────


@pytest.mark.parametrize("k", [1, 2, 4, 8])
def test_K_cohorts_over_one_snapshot_prepare_ONCE(monkeypatch, k):
    sigs, seams, adjacency = estate()
    cfg = EngineConfig()
    c = _Counter(monkeypatch)
    prep = prepare_run_window(sigs, seams, cfg, adjacency, None, ())
    assert c.preps == 1 and c.indexes == 1, "the epoch itself must prepare once"
    for ck in cohorts_of(prep.nodes, k):
        run_window(sigs, CAT, seams, cfg, adjacency=adjacency,
                   cohort_keys=ck, prep=prep)
    assert c.preps == 1, (
        f"{k} cohorts triggered {c.preps} preparations — the epoch state was "
        f"rebuilt per transaction, which is the tracker 166 defect")
    assert c.indexes == 1, f"{k} cohorts triggered {c.indexes} index builds"


def test_without_a_prep_every_transaction_still_prepares(monkeypatch):
    """The control that makes the test above meaningful: with no epoch state,
    the cost IS paid per transaction. If this ever reads 1, the counter is
    broken and the invariant test proves nothing."""
    sigs, seams, adjacency = estate()
    cfg = EngineConfig()
    nodes = build_nodes(tuple(sorted(sigs, key=lambda s: (s.ts, str(s.signal_id)))))
    c = _Counter(monkeypatch)
    for ck in cohorts_of(nodes, 4):
        run_window(sigs, CAT, seams, cfg, adjacency=adjacency, cohort_keys=ck)
    assert c.preps == 4, f"expected one preparation per cohort, got {c.preps}"


# ── 2. invalidation — negative controls (Phase 3) ────────────────────────────


def test_prep_from_a_DIFFERENT_window_is_rejected_and_rebuilt(monkeypatch):
    sigs_a, seams, adjacency = estate(n_devices=8)
    sigs_b, _, _ = estate(n_devices=12)
    cfg = EngineConfig()
    prep_a = prepare_run_window(sigs_a, seams, cfg, adjacency, None, ())
    assert not prep_a.matches_window(sigs_b, seams, cfg, adjacency, None, ())
    c = _Counter(monkeypatch)
    got = run_window(sigs_b, CAT, seams, cfg, adjacency=adjacency, prep=prep_a)
    assert c.preps == 1, "a foreign prep must be rebuilt, not trusted"
    assert got == run_window(sigs_b, CAT, seams, cfg, adjacency=adjacency)


def test_prep_with_DIFFERENT_seams_is_rejected(monkeypatch):
    sigs, seams, adjacency = estate()
    other = seams[:1]
    cfg = EngineConfig()
    prep = prepare_run_window(sigs, seams, cfg, adjacency, None, ())
    assert not prep.matches_window(sigs, other, cfg, adjacency, None, ())
    c = _Counter(monkeypatch)
    got = run_window(sigs, CAT, other, cfg, adjacency=adjacency, prep=prep)
    assert c.preps == 1
    assert got == run_window(sigs, CAT, other, cfg, adjacency=adjacency)


def test_prep_with_DIFFERENT_adjacency_is_rejected(monkeypatch):
    sigs, seams, adjacency = estate()
    cfg = EngineConfig()
    prep = prepare_run_window(sigs, seams, cfg, adjacency, None, ())
    assert not prep.matches_window(sigs, seams, cfg, NO_ADJACENCY, None, ())
    c = _Counter(monkeypatch)
    got = run_window(sigs, CAT, seams, cfg, adjacency=NO_ADJACENCY, prep=prep)
    assert c.preps == 1
    assert got == run_window(sigs, CAT, seams, cfg, adjacency=NO_ADJACENCY)


def test_prep_with_a_DIFFERENT_path_view_is_rejected(monkeypatch):
    from test_path_graph import lab_path_view, lab_signals
    app, wan = lab_signals("acme")
    extras = [sig("metric_anomaly", EntityType.DEVICE, f"noise-{k}", offset_s=k,
                  tenant="acme") for k in range(6)]
    sigs = (app, wan, *extras)
    view = lab_path_view("acme")
    cfg = EngineConfig()
    prep = prepare_run_window(sigs, (), cfg, NO_ADJACENCY, view, ())
    assert not prep.matches_window(sigs, (), cfg, NO_ADJACENCY, None, ())
    c = _Counter(monkeypatch)
    got = run_window(sigs, CAT, (), cfg, paths=None, prep=prep)
    assert c.preps == 1, "dropping the path graph must invalidate the prep"
    assert got == run_window(sigs, CAT, (), cfg, paths=None)


def test_prep_with_a_DIFFERENT_config_is_rejected(monkeypatch):
    sigs, seams, adjacency = estate()
    cfg_a = EngineConfig()
    cfg_b = EngineConfig(attach_threshold=0.99)
    prep = prepare_run_window(sigs, seams, cfg_a, adjacency, None, ())
    assert not prep.matches_window(sigs, seams, cfg_b, adjacency, None, ())
    c = _Counter(monkeypatch)
    got = run_window(sigs, CAT, seams, cfg_b, adjacency=adjacency, prep=prep)
    assert c.preps == 1
    assert got == run_window(sigs, CAT, seams, cfg_b, adjacency=adjacency)


def test_build_edges_rejects_a_prep_built_for_other_nodes():
    """The engine-level guard, independently of run_window."""
    sigs_a, seams, adjacency = estate(n_devices=8)
    sigs_b, _, _ = estate(n_devices=10)
    cfg = EngineConfig()
    nodes_a = build_nodes(tuple(sorted(sigs_a, key=lambda s: (s.ts, str(s.signal_id)))))
    nodes_b = build_nodes(tuple(sorted(sigs_b, key=lambda s: (s.ts, str(s.signal_id)))))
    prep_a = prepare_window(nodes_a, seams, cfg, adjacency, None)
    assert not prep_a.matches(nodes_b, seams, cfg, adjacency, None)
    assert build_edges(nodes_b, seams, cfg, adjacency, prep=prep_a) \
        == build_edges(nodes_b, seams, cfg, adjacency)


def test_the_guard_can_actually_go_red():
    """MUTATION CONTROL. Force the guard to always accept and the engine must
    produce a WRONG answer — otherwise the negative controls above are vacuous
    and would pass against no guard at all."""
    sigs_a, seams, adjacency = estate(n_devices=8)
    sigs_b, _, _ = estate(n_devices=16)
    cfg = EngineConfig()
    nodes_a = build_nodes(tuple(sorted(sigs_a, key=lambda s: (s.ts, str(s.signal_id)))))
    nodes_b = build_nodes(tuple(sorted(sigs_b, key=lambda s: (s.ts, str(s.signal_id)))))
    prep_a = prepare_window(nodes_a, seams, cfg, adjacency, None)
    truth = build_edges(nodes_b, seams, cfg, adjacency)

    class AlwaysMatches:
        def __init__(self, inner): self._inner = inner
        def __getattr__(self, k): return getattr(self._inner, k)
        def matches(self, *a, **kw): return True

    mutant = build_edges(nodes_b, seams, cfg, adjacency, prep=AlwaysMatches(prep_a))
    assert mutant != truth, (
        "an always-true guard produced the correct answer — the guard is not "
        "load-bearing and these tests would not catch a stale prep")


# ── 3. equivalence (Phase 10) ────────────────────────────────────────────────


@pytest.mark.parametrize("k", [1, 2, 4, 8, 16])
def test_prepped_cohorts_equal_unprepped_cohorts(k):
    sigs, seams, adjacency = estate()
    cfg = EngineConfig()
    prep = prepare_run_window(sigs, seams, cfg, adjacency, None, ())
    for ck in cohorts_of(prep.nodes, k):
        with_prep = run_window(sigs, CAT, seams, cfg, adjacency=adjacency,
                               cohort_keys=ck, prep=prep)
        without = run_window(sigs, CAT, seams, cfg, adjacency=adjacency,
                             cohort_keys=ck)
        assert with_prep == without


@pytest.mark.parametrize("k", [1, 2, 4, 8])
def test_cohort_union_equals_the_full_window_edge_set(k):
    """The 166 core equivalence, now over the epoch path: streaming the window
    through K cohorts admits exactly the edges one unbounded pass admits."""
    sigs, seams, adjacency = estate()
    cfg = EngineConfig()
    prep = prepare_run_window(sigs, seams, cfg, adjacency, None, ())
    full = run_window(sigs, CAT, seams, cfg, adjacency=adjacency)
    full_edges = {(e.from_node, e.to_node) for s in full for e in s.edges}
    streamed: set = set()
    for ck in cohorts_of(prep.nodes, k):
        for s in run_window(sigs, CAT, seams, cfg, adjacency=adjacency,
                            cohort_keys=ck, prep=prep):
            streamed |= {(e.from_node, e.to_node) for e in s.edges}
    assert streamed == full_edges


def test_prep_reuse_preserves_the_path_graph_rungs():
    from test_path_graph import lab_path_view, lab_signals
    app, wan = lab_signals("acme")
    extras = [sig("metric_anomaly", EntityType.DEVICE, f"noise-{k}", offset_s=k,
                  tenant="acme") for k in range(6)]
    sigs = (app, wan, *extras)
    view = lab_path_view("acme")
    cfg = EngineConfig()
    prep = prepare_run_window(sigs, (), cfg, NO_ADJACENCY, view, ())
    assert run_window(sigs, CAT, (), cfg, paths=view, prep=prep) \
        == run_window(sigs, CAT, (), cfg, paths=view)


def test_replay_content_hash_is_unchanged_by_the_epoch_path():
    sigs, seams, adjacency = estate()
    cfg = EngineConfig()
    prep = prepare_run_window(sigs, seams, cfg, adjacency, None, ())
    a = run_window(sigs, CAT, seams, cfg, adjacency=adjacency, prep=prep)
    b = run_window(sigs, CAT, seams, cfg, adjacency=adjacency)
    assert [s.content_hash() for s in a] == [s.content_hash() for s in b]
    assert [s.correlation_id for s in a] == [s.correlation_id for s in b]


# ── 4. the epoch's own contract ──────────────────────────────────────────────


def test_epoch_refuses_a_mixed_tenant_window():
    """Raised at epoch build, before any cohort runs — same error run_window
    always raised, just earlier."""
    a, seams, adjacency = estate(n_devices=4, tenant="t1")
    b, _, _ = estate(n_devices=4, tenant="t2")
    with pytest.raises(ValueError, match="single-tenant"):
        prepare_run_window(a + b, seams, EngineConfig(), adjacency, None, ())


def test_epoch_is_none_for_an_empty_window():
    assert prepare_run_window((), (), EngineConfig()) is None


def test_cohort_indices_ignores_keys_that_are_not_in_the_snapshot():
    """A cohort names signals; a key whose node left the window (expiry between
    admission and evaluation) must be dropped, never index-error."""
    sigs, seams, adjacency = estate(n_devices=6)
    prep = prepare_run_window(sigs, seams, EngineConfig(), adjacency, None, ())
    real = next(iter(prep.key_index))
    idx = prep.cohort_indices(frozenset({real, "device:ghost:does_not_exist"}))
    assert idx == frozenset({prep.key_index[real]})
