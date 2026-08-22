"""Tracker 162 — the continuation candidate index must change NOTHING.

The index docstring carries the superset proof; this file pins it empirically:

  * EQUIVALENCE ORACLE — across seeded randomized open-object populations and
    probe snapshots, `find_continuation` over the index's candidates selects
    the IDENTICAL winner as over the full population. Selection identity is
    the whole contract; the index may only shrink what is EXAMINED.
  * THE BLOCKER CASE — the seam-bridged pair with ZERO shared entities (the
    DX cloud-half/network-half fixture from tracker 154b) must be in the
    candidate set: this is exactly what made entity-only indexing an RCA
    correctness regression on the tracker row's first attempt.
  * MUTATION WITNESS — an entity-only index provably MISSES that pair, so
    the seam clauses are load-bearing, not decorative.
  * The filter actually filters (entity-sparse fixture), deterministically.
"""
from __future__ import annotations

import random

import pytest

from catalog import builtin_catalog
from engine import ContinuationIndex, EngineConfig, find_continuation, run_window
from signals import EntityType
from test_archive_slice import sig
from test_seam_affinity_fold import _cloud_snap, _net_snap

CAT = builtin_catalog()


def _dev_snap(dev: str, offset_s: float = 0.0, extra_offset: float = 20.0):
    """A containment component on `dev` — entity-indexable candidates."""
    window = (
        sig("device_cpu_high", EntityType.DEVICE, dev, offset_s=offset_s),
        sig("if_errors", EntityType.INTERFACE, f"{dev}:Gi0/1",
            offset_s=offset_s + extra_offset),
    )
    return run_window(window, CAT, (), EngineConfig())[0]


# ── the blocker case, and its mutation witness ───────────────────────────────

def test_seam_bridged_zero_entity_candidate_is_retrievable():
    open_obj, probe = _net_snap(), _cloud_snap(5)
    assert not ({n.entity_id for n in open_obj.nodes}
                & {n.entity_id for n in probe.nodes}), "premise: disjoint entities"
    idx = ContinuationIndex([open_obj])
    cands = idx.candidates(probe)
    assert open_obj in cands, (
        "the seam-bridged zero-overlap candidate is not retrievable — the "
        "exact RCA correctness regression the tracker row warned about")
    assert find_continuation(probe, cands) == open_obj.correlation_id
    assert find_continuation(probe, [open_obj]) == open_obj.correlation_id


def test_mutation_entity_only_index_misses_the_bridge():
    """Proves by_ref/by_ev are load-bearing: an entity-only lookup over the
    same population cannot see the bridged pair."""
    open_obj, probe = _net_snap(), _cloud_snap(5)
    idx = ContinuationIndex([open_obj])
    entity_only = set()
    for n in probe.nodes:
        entity_only.update(idx._by_entity.get(n.entity_id, ()))
    assert not entity_only, (
        "entity-only retrieval now finds the bridged pair — if the fixture "
        "gained shared entities, this witness proves nothing; restore the "
        "disjoint premise")


# ── the equivalence oracle ───────────────────────────────────────────────────

def _population(rng: random.Random, n: int):
    """Open objects over a small device pool (forced overlaps) plus one
    seam-bridged network half."""
    snaps = [_dev_snap(f"pool-{rng.randrange(8)}", offset_s=i * 40.0)
             for i in range(n)]
    snaps.append(_net_snap())
    # de-duplicate by correlation_id — same (device, onset) collides by design
    uniq = {}
    for s in snaps:
        uniq.setdefault(s.correlation_id, s)
    return list(uniq.values())


@pytest.mark.parametrize("seed", [1, 7, 42, 1337])
def test_oracle_index_candidates_select_the_identical_winner(seed):
    rng = random.Random(seed)
    population = _population(rng, 12)
    idx = ContinuationIndex(population)
    probes = ([_dev_snap(f"pool-{k}", offset_s=5.0) for k in range(8)]
              + [_cloud_snap(5), _dev_snap("stranger-dev", offset_s=3.0)])
    for probe in probes:
        full = find_continuation(probe, population)
        via_index = find_continuation(probe, idx.candidates(probe))
        assert via_index == full, (
            f"seed {seed}: index changed the winner for probe "
            f"{probe.correlation_id[:8]}: {via_index!r} != {full!r}")


def test_oracle_holds_with_exclusions_and_cache():
    """The caller passes exclude/entity_cache; equivalence must survive both."""
    population = _population(random.Random(3), 10)
    idx = ContinuationIndex(population)
    probe = _dev_snap("pool-2", offset_s=5.0)
    excluded = frozenset(s.correlation_id for s in population[:3])
    cache: dict = {}
    full = find_continuation(probe, population, exclude=excluded,
                             entity_cache=cache)
    via = find_continuation(probe, idx.candidates(probe), exclude=excluded,
                            entity_cache=cache)
    assert via == full


# ── the filter filters, deterministically ────────────────────────────────────

def test_disjoint_probe_yields_no_candidates():
    population = [_dev_snap(f"iso-{i}") for i in range(20)]
    idx = ContinuationIndex(population)
    probe = _dev_snap("unrelated-dev", offset_s=1.0)
    assert idx.candidates(probe) == (), (
        "an entity-disjoint, seam-free probe retrieved candidates — the "
        "filter is not filtering")


def test_candidates_preserve_population_order():
    population = [_dev_snap("same-dev", offset_s=o) for o in (0.0, 500.0, 1000.0)]
    population = list({s.correlation_id: s for s in population}.values())
    idx = ContinuationIndex(population)
    probe = _dev_snap("same-dev", offset_s=2.0)
    got = [s.correlation_id for s in idx.candidates(probe)]
    want = [s.correlation_id for s in population
            if s.correlation_id in set(got)]
    assert got == want, "candidate order drifted from population order"
