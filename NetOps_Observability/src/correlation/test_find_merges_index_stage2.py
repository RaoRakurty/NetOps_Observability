"""Stage-2 Lever 2 — the `find_merges` survivor index must change NOTHING.

Lever 2 replaces `find_merges`'s O(survivors × stale) cross-product with the
tracker-162 `ContinuationIndex` pattern: the survivors are indexed and each
stale candidate probes only the plausible merge targets. This is a
RESULTS-PRESERVING optimization — the pair set is byte-identical to the
brute-force cross-product for every input. This file is the guardrail that
proves it.

  * EQUIVALENCE ORACLE — across seeded randomized survivor/stale populations
    (including the concentrated case where many objects share one entity),
    the indexed `find_merges` returns the EXACT same (merged_cid, survivor_cid)
    pair set as an independent brute-force reference that scans every survivor.
    The pair set — same survivor selection, same tie-breaks, same order — is
    the whole contract; the index may only shrink what is EXAMINED.
  * THE BLOCKER CASE — the seam-bridged pair with ZERO shared entities (the DX
    cloud-half/network-half fixture from tracker 154b) must still merge: this
    is exactly the shape that made an entity-only index unsound for its twin.
  * THE PRUNE IS REAL — at a storm shape where only a few survivors plausibly
    merge, the index's candidate set is much smaller than the full survivor
    list, and merges stay correct. So the optimization actually optimizes.
  * Determinism / order-invariance preserved.
"""
from __future__ import annotations

import dataclasses
import random

import pytest

from engine import (
    ContinuationIndex,
    _entity_ids,
    _seam_bridged,
    _windows_overlap,
    find_merges,
)
from test_engine import _obj
from test_seam_affinity_fold import _cloud_snap, _net_snap

# ── the independent brute-force reference (pre-index cross-product) ───────────

def brute_find_merges(survivors, candidates, min_overlap: float = 0.4):
    """The O(survivors × stale) cross-product `find_merges` had before Lever 2,
    reimplemented independently: every candidate is evaluated against EVERY
    survivor, no index. This is the oracle the indexed engine must match."""
    surv = sorted(survivors, key=lambda s: (s.window_start, s.correlation_id))
    pairs: list[tuple[str, str]] = []
    for cand in sorted(candidates, key=lambda s: (s.window_start, s.correlation_id)):
        ce = _entity_ids(cand)
        if not ce:
            continue
        best = None
        best_cid = ""
        for s in surv:  # <- the whole point: NO pruning, scans all survivors
            if (s.tenant_id != cand.tenant_id
                    or s.correlation_id == cand.correlation_id
                    or not _windows_overlap(cand, s)):
                continue
            se = _entity_ids(s)
            union = ce | se
            jac = len(ce & se) / len(union) if union else 0.0
            if jac < min_overlap and not _seam_bridged(cand, s):
                continue
            if (best is None or jac > best[0]
                    or (jac == best[0]
                        and (s.window_start, s.correlation_id) < (best[1], best[2]))):
                best = (jac, s.window_start, s.correlation_id)
                best_cid = s.correlation_id
        if best_cid:
            pairs.append((cand.correlation_id, best_cid))
    return sorted(pairs)


# ── population builders ──────────────────────────────────────────────────────

_TENANTS = ("", "tenant-a", "tenant-b")


def _rand_obj(rng: random.Random, pool: list[str], cid: str,
              max_devs: int = 3) -> object:
    """A device-containment object over a small shared pool — forces the
    entity overlaps (and concentration) that exercise merge selection."""
    k = rng.randint(1, max_devs)
    devs = rng.sample(pool, min(k, len(pool)))
    start = rng.randint(0, 40)
    obj = _obj(devs, cid, start, start + rng.randint(2, 8))
    return dataclasses.replace(obj, tenant_id=rng.choice(_TENANTS))


def _mixed_population(rng: random.Random, n_surv: int, n_stale: int,
                      pool_size: int = 6):
    """Random survivors + stale over a small device pool, salted with a
    seam-bridged DX network/cloud pair (zero shared entities) so the seam
    clause is exercised alongside the entity clause."""
    pool = [f"dev-{i}" for i in range(pool_size)]
    survivors = [_rand_obj(rng, pool, f"S{i}") for i in range(n_surv)]
    stale = [_rand_obj(rng, pool, f"T{i}") for i in range(n_stale)]
    # a genuine seam-bridged disjoint-entity pair (survivor net half, stale
    # cloud half) — the 154b shape find_merges must still fold.
    survivors.append(_net_snap())
    stale.append(_cloud_snap(5))
    # de-dup by correlation_id (same (dev, onset) collides by construction);
    # keep survivor/stale namespaces disjoint so a cid is never both.
    survivors = list({s.correlation_id: s for s in survivors}.values())
    s_ids = {s.correlation_id for s in survivors}
    stale = list({s.correlation_id: s for s in stale
                  if s.correlation_id not in s_ids}.values())
    return survivors, stale


# ── the equivalence oracle (the teeth) ───────────────────────────────────────

@pytest.mark.parametrize("seed", [1, 3, 7, 42, 101, 1337, 2026])
def test_oracle_indexed_find_merges_matches_brute_force(seed):
    rng = random.Random(seed)
    survivors, stale = _mixed_population(rng, n_surv=14, n_stale=18)
    indexed = find_merges(survivors, stale)
    brute = brute_find_merges(survivors, stale)
    assert indexed == brute, (
        f"seed {seed}: the survivor index changed the merge pair set — "
        f"indexed {indexed!r} != brute {brute!r}")


@pytest.mark.parametrize("seed", [5, 11, 99])
def test_oracle_concentrated_shared_entity(seed):
    """The concentrated case: MANY objects all containing one hub device, so
    the index's by-entity bucket holds nearly everything and the predicate
    still selects among genuine overlaps. Byte-identical to brute force."""
    rng = random.Random(seed)
    hub = "hub-core-1"
    survivors = []
    for i in range(20):
        obj = _obj([hub, f"leaf-{i}"], f"S{i}", i % 10, (i % 10) + 6)
        survivors.append(dataclasses.replace(obj, tenant_id=rng.choice(_TENANTS)))
    stale = []
    for i in range(24):
        obj = _obj([hub, f"leaf-{i}"], f"T{i}", i % 12, (i % 12) + 5)
        stale.append(dataclasses.replace(obj, tenant_id=rng.choice(_TENANTS)))
    assert find_merges(survivors, stale) == brute_find_merges(survivors, stale)


# ── the blocker case: seam-bridged zero-entity merge survives the index ───────

def test_seam_bridged_zero_entity_still_merges():
    surv, stale = _net_snap(), _cloud_snap(5)
    assert not ({n.entity_id for n in surv.nodes}
                & {n.entity_id for n in stale.nodes}), "premise: disjoint entities"
    # retrievable from the survivor index by the seam clause (by_ref/by_ev)…
    idx = ContinuationIndex([surv])
    assert surv in idx.candidates(stale), (
        "seam-bridged survivor not retrievable — the entity-only-index blocker")
    # …and the merge is preserved end-to-end.
    assert find_merges([surv], [stale]) == [(stale.correlation_id, surv.correlation_id)]
    assert find_merges([surv], [stale]) == brute_find_merges([surv], [stale])


# ── the prune is real ────────────────────────────────────────────────────────

def test_index_prunes_the_survivor_scan():
    """A storm shape: many survivors on distinct devices, a stale object that
    plausibly merges into only a couple of them. The index candidate set must
    be far smaller than the full survivor list — proving the O(n²) scan is cut,
    not just correct."""
    survivors = [_obj([f"iso-{i}"], f"S{i}", 0, 5) for i in range(200)]
    survivors = list({s.correlation_id: s for s in survivors}.values())
    # a stale object sharing an entity with exactly two survivors.
    stale = _obj(["iso-3", "iso-7"], "T0", 0, 5)

    idx = ContinuationIndex(survivors)
    cand = idx.candidates(stale)
    assert len(cand) <= 5, (
        f"index returned {len(cand)} of {len(survivors)} survivors — the "
        f"filter is barely filtering")
    assert len(cand) < len(survivors) / 10, "expected an order-of-magnitude prune"
    # correctness at the same shape: iso-3 and iso-7 each 1/2 overlap ≥ 0.4,
    # so the stale merges into the earliest-window / lexical-first survivor.
    result = find_merges(survivors, [stale])
    assert result == brute_find_merges(survivors, [stale])
    assert result == [("T0", "S3")]  # equal overlap → earliest start, then cid


def test_prune_measured_predicate_evaluations():
    """Count predicate evaluations directly: indexed vs brute. At a wide,
    sparse survivor set the indexed engine must evaluate far fewer pairs."""
    survivors = list({s.correlation_id: s for s in
                      (_obj([f"iso-{i}"], f"S{i}", 0, 5) for i in range(150))}.values())
    stale = [_obj(["iso-5"], "T0", 0, 5), _obj(["iso-9"], "T1", 0, 5)]

    idx = ContinuationIndex(survivors)
    indexed_evals = sum(len(idx.candidates(c)) for c in stale)
    brute_evals = len(stale) * len(survivors)
    assert indexed_evals < brute_evals / 20, (
        f"indexed evaluated {indexed_evals} pairs vs brute {brute_evals} — "
        f"the prune is not delivering the expected reduction")
    # and it is still correct.
    assert find_merges(survivors, stale) == brute_find_merges(survivors, stale)


# ── determinism / order invariance ───────────────────────────────────────────

def test_determinism_and_order_invariance():
    rng = random.Random(2027)
    survivors, stale = _mixed_population(rng, n_surv=10, n_stale=12)
    base = find_merges(survivors, stale)
    for _ in range(5):
        s = survivors[:]
        t = stale[:]
        random.Random(_).shuffle(s)
        random.Random(_ + 100).shuffle(t)
        assert find_merges(s, t) == base, "merge result depended on input order"
