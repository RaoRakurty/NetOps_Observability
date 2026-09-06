# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P2 memflat remediation — the RankMemo BYTE bound and the ephemeral-clause leak.

Source of truth for both defects: `docs/scale/P2_MEMFLAT_ATTRIBUTION_2026-08-29.md`
(bench `bench_memflat_p2.py`), confirmed against the live 2.5K run in
`docs/scale/P2_STEPS012_2P5K_VERDICT_2026-08-29.md` §3.

TWO CLAIMS UNDER TEST
---------------------
1. **`RankMemo` is bounded in BYTES, not just entries** (brief §5.1). An entry
   costs 10-26 KiB, so `CORR_RANK_MEMO_MAX=50000` licensed 500-650 MiB on a
   1.25 GiB box; the live replica minted 20,117 entries and grew +259 MiB.
   `CORR_RANK_MEMO_BYTES_MAX` (default 96 MiB) now evicts LRU until BOTH bounds
   hold, and `estimate_result_bytes` is the meter. Tests B1-B13.

   **The meter is CALIBRATED, not an upper bound** (2026-08-29). The live 2.5K
   run p2-s04-08290653 (replica-3, /metrics 07:54 UTC) held only 1,780 entries
   in 96 MiB — ~56 KiB/entry — evicted 38,177 and dropped the hit rate from
   66 % to 6 %. `estimate_result_bytes` now runs an id-`seen` walk that charges
   catalog-owned objects ZERO and the per-instance `__dict__` it used to miss;
   measured at 0.978x / 0.982x of a tracemalloc marginal over 400 real
   storm-shaped results (`bench_memflat_p2.py --calibrate`). Tests B5-B5e.
2. **`scoring`'s causal-chain clauses are interned** (brief §5.2). The two call
   sites built a fresh `Clause(kind=...)` per call; the id-keyed `Clause.kinds`
   cache pinned each one until it self-evicted at 4,096 (2,292 pinned foreign
   clauses measured). `witness_clause` interns by the witness STRING, and the
   scored bytes must not move by one character. Tests C1-C5.

Every test is a mutant check — what turns it red is named in its docstring.
"""
from __future__ import annotations

import gc
import json
import sys
import tracemalloc
import types
from enum import Enum
from pathlib import Path

import pytest

import catalog as CATMOD
import main
import rank_memo as RM
import scoring

# `test_p2_rank_memo` owns the P2 step-2 engine fixtures (evidence shapes, the
# cohort drain, the persisted-blob projection) and `test_fixtures` the 112-file
# catalog corpus; reuse both rather than forking silently divergent copies.
import test_p2_rank_memo as RMT
from catalog import Clause, builtin_catalog
from rank_memo import RankMemo, estimate_result_bytes
from scoring import RankingResult, rank, score_template, witness_clause
from test_fixtures import fixture_files, signal_from_fixture

CAT = builtin_catalog()


# ── the REFERENCE instruments ────────────────────────────────────────────────

_SKIP_TYPES: tuple[type, ...] = (
    type, types.ModuleType, types.FunctionType, types.MethodType,
    types.BuiltinFunctionType, types.GetSetDescriptorType,
    types.MemberDescriptorType, types.WrapperDescriptorType,
    types.MethodDescriptorType, types.ClassMethodDescriptorType,
)


def reference_deep_bytes(obj: object, seen: set[int] | None = None,
                         owned: frozenset[int] = frozenset(), *,
                         charge_singletons: bool = False) -> int:
    """Deep size by `gc.get_referents` — the instrument `bench_memflat_p2.py`
    uses, and the one that needs NO per-type knowledge, so a container the
    production walk forgot cannot be missed here too.

    It is independently anchored: over 400 real storm-shaped results this walk
    read 8,307,634 B against 8,307,450 B that `tracemalloc` saw freed when the
    same results were dropped — 0.002 % apart. That anchor was taken with ONE
    shared `seen` set across the whole batch, so every object the batch shares
    was charged exactly once — which is what makes it agree with tracemalloc,
    and what B5b (a FRESH `seen` per result) must reproduce by other means.

    TWO ownership rules, and the walk must apply BOTH or it is not measuring
    what the estimator measures:

    * `owned` — the catalog's id set, skipped for the same reason the estimator
      skips it (B5c).
    * **Enum members are process-wide singletons** and are skipped for exactly
      the same reason. `VerdictTier.CONFIRMED` is one module-level object that
      every result in the process points at; dropping a memo entry frees none
      of it, `rank_memo._walk` charges it 0 by an explicit documented rule, and
      the tracemalloc anchor above never saw it freed either. Charging it to
      every result is a per-result tax on shared memory — measured at 503 B
      (3.10.12) and 788 B (3.12.14) per result over the catalog corpus, 11 %
      and 20 % of the SMALLEST fixture's reading. It is not proportional to the
      result, so it hits the small fixtures hardest: it is what drove B5b's
      per-fixture floor to 0.744 on 3.12 (green at 0.800 on 3.10 — the enum
      members' managed `__dict__` grew from 104 B to 304 B on 3.11+, which is
      the whole of the local-vs-CI divergence). `charge_singletons=True` runs
      that mutant, and B5b executes it.

    Slower and more exact than the production estimator; it exists only to bound
    the estimator's error (B5b) without paying for a tracemalloc run."""
    if seen is None:
        seen = set()
    total = 0
    stack: list = [obj]
    while stack:
        item = stack.pop()
        oid = id(item)
        if oid in seen or oid in owned or isinstance(item, _SKIP_TYPES):
            continue
        if not charge_singletons and isinstance(item, Enum):
            continue
        seen.add(oid)
        total += sys.getsizeof(item)
        # CPython >= 3.11 managed dicts: until something touches an instance's
        # `__dict__`, its attribute values live inline in the instance's own
        # allocation — `getsizeof(instance)` reports only the 48 B header and
        # `get_referents` hands back the VALUES with no dict container — so
        # this walk would silently under-read real, allocated, per-instance
        # memory that tracemalloc (the anchor, B5) and the estimator both
        # charge (measured on 3.12.14: 269.5 B actually held per small frozen
        # dataclass instance vs 48 B this walk saw; on the full corpus the
        # blindness pushed est/ref to 1.16 with no estimator change). Touching
        # `__dict__` materializes the real dict so the container is walked
        # like any other object. A no-op on pre-managed-dict interpreters,
        # where the dict always exists, and for slotted/dict-less objects.
        getattr(item, "__dict__", None)
        stack.extend(gc.get_referents(item))
    return total


def catalog_owned() -> frozenset[int]:
    """The estimator's own ownership set, resolved for the built-in catalog —
    and it must be the set the estimator will ACTUALLY use, not merely a
    non-empty one.

    `_owned_ids` resolves by catalog VERSION over `scoring._CATALOG_PLAN_CACHE`,
    which is keyed by `id(catalog)` and cleared wholesale at 4 entries. So when
    another `builtin_catalog()` instance of the same version is cached and
    `CAT`'s own plan is not, this returns a set that is non-empty and WRONG: it
    holds that other instance's `inapplicable` HypothesisScore objects, not the
    ones `rank(CAT, ...)` puts in the results under test. The reference walk
    then charges what the estimator skips, and B5b reads 0.56x — an
    order-dependent failure that hides whenever an earlier test in the file
    happens to have materialized the plan first (`pytest -k B5b` alone was red
    while the file was green).

    Materializing the plan first is what makes both instruments see one
    ownership set. It builds nothing the tests do not already build — every
    `ranking_of` call below goes through this same plan."""
    scoring._catalog_plan(CAT)
    owned = RM._owned_ids(CAT.version_hash())
    assert owned, "the catalog ownership set did not resolve — B5* prove nothing"
    return owned


def ranking_of(path) -> RankingResult:
    data = json.loads(path.read_text())
    return rank(CAT, [signal_from_fixture(s, i)
                      for i, s in enumerate(data["signals"])])


FIXTURES = fixture_files()
# Three named, structurally different fixtures for the estimator-accuracy test:
# a confirmed multi-modality signature, an undetermined one (few hypotheses,
# long evidence_missing), and a cloud signature with a causal chain.
THREE = [p for p in FIXTURES
         if p.stem in ("bgp-peer-flap-confirmed", "ambiguous-undetermined",
                       "cloud-ipsec-tunnel-down-confirmed")]


# ═══ B — the byte bound ═════════════════════════════════════════════════════

def test_B0_the_fixtures_are_present_and_the_meter_is_not_trivial():
    """PREMISE. A fixture set that vanished, or an estimator that returned a
    constant, would make every B test below vacuous."""
    assert len(THREE) == 3, f"named fixtures missing: {[p.stem for p in FIXTURES]}"
    sizes = [estimate_result_bytes(ranking_of(p)) for p in THREE]
    assert all(s > 2_000 for s in sizes), sizes
    assert len(set(sizes)) == 3, "the estimator returns the same number for all three"


def test_B1_the_byte_bound_evicts_lru_until_it_holds():
    """MUTANT CHECK for the byte bound: drop the `bytes_used > bytes_max` term
    from `put`'s eviction loop and this goes red — 50 entries survive under a
    budget that fits 3.

    The entry bound is deliberately slack (10,000) so ONLY the byte bound can
    be doing the evicting."""
    result = ranking_of(THREE[0])
    # `entry_bytes` — NOT `estimate_result_bytes` — is the unit the bound is
    # denominated in: the memo stores the COMPACT blob (rank_memo.py, THE
    # COMPACT CACHED FORM) and charges its exact size plus the per-entry
    # bookkeeping. `estimate_result_bytes` remains the meter of the OBJECT
    # form, tested for its own sake in B5-B11 and used when the codec refuses.
    one = RM.entry_bytes(result)
    memo = RankMemo(max_entries=10_000, max_bytes=one * 3 + one // 2)
    for i in range(50):
        memo.put(f"k{i:03d}", result)
    assert len(memo) == 3, f"byte bound not enforced: {memo.stats()}"
    assert memo.bytes_used <= memo.bytes_max
    assert memo.evicted == 47
    assert memo.evicted_bytes == 47 * one
    # …and the survivors are the most recent three.
    assert list(memo._lru) == ["k047", "k048", "k049"]


def test_B2_the_entries_bound_is_still_enforced():
    """MUTANT CHECK for the ENTRY bound surviving the change: delete the
    `len(self._lru) > self.max_entries` term and this goes red."""
    result = ranking_of(THREE[0])
    memo = RankMemo(max_entries=4, max_bytes=1 << 40)   # bytes cannot bind
    for i in range(40):
        memo.put(f"k{i:03d}", result)
    assert len(memo) == 4 and memo.evicted == 36
    assert memo.bytes_used == 4 * RM.entry_bytes(result)
    assert memo.stats()["max_entries"] == 4


def test_B3_lru_order_is_preserved_under_the_byte_bound():
    """A `get` must promote, and the byte bound must evict the LEAST RECENTLY
    USED entry — not the oldest-inserted. MUTANT: make `put` evict `last=True`
    and this goes red."""
    result = ranking_of(THREE[0])
    one = RM.entry_bytes(result)
    memo = RankMemo(max_entries=10_000, max_bytes=one * 3)
    for key in ("a", "b", "c"):
        memo.put(key, result)
    assert len(memo) == 3
    # `==`, not `is`: a compact-mode hit REBUILDS the value from the blob, and
    # equality is exactly the contract (T4 pins the resulting bytes).
    assert memo.get("a") == result          # promote 'a'; 'b' becomes the LRU
    memo.put("d", result)
    assert len(memo) == 3 and memo.evicted == 1
    assert memo.get("b") is None, "the byte bound evicted the wrong entry"
    assert memo.get("a") == result and memo.get("c") == result and memo.get("d") == result
    assert list(memo._lru) == ["a", "c", "d"]


def test_B4_stats_exposes_the_byte_readout_and_it_balances():
    """§10 observable + the accounting identity: `bytes` is exactly the sum of
    the held entries' estimates, and `evicted_bytes` exactly the sum of the
    dropped ones. MUTANT: forget `self.bytes_used -= dropped` on eviction and
    the identity breaks."""
    memo = RankMemo(max_entries=10_000, max_bytes=1 << 40)
    rankings = {p.stem: ranking_of(p) for p in FIXTURES[:25]}
    for key, value in rankings.items():
        memo.put(key, value)
    stats = memo.stats()
    for field in ("entries", "max_entries", "bytes", "bytes_max", "hits",
                  "misses", "evicted", "evicted_bytes", "unkeyable"):
        assert field in stats, f"stats() lost {field}"
    assert stats["bytes_max"] == 1 << 40
    assert stats["evicted_bytes"] == 0
    assert stats["bytes"] == sum(RM.entry_bytes(v) for v in rankings.values())
    assert stats["bytes"] == memo.bytes_used == sum(memo._sizes.values())

    # now squeeze it and re-check both halves of the identity
    held = list(memo._lru)
    tight = RankMemo(max_entries=10_000, max_bytes=stats["bytes"] // 2)
    for key in held:
        tight.put(key, rankings[key])
    assert tight.bytes_used == sum(tight._sizes.values()) <= tight.bytes_max
    assert tight.evicted_bytes == stats["bytes"] - tight.bytes_used
    assert tight.evicted == len(held) - len(tight)


CALIBRATION_MIN_RESULTS = 200


def _corpus_evidence() -> list[list]:
    """One evidence list per catalog fixture, freshly built each call."""
    return [[signal_from_fixture(s, i)
             for i, s in enumerate(json.loads(p.read_text())["signals"])]
            for p in FIXTURES]


def test_B5_the_estimator_is_calibrated_against_a_tracemalloc_marginal():
    """THE CALIBRATION. `estimate_result_bytes` must read within **0.80x-1.30x**
    of the memory the process actually gives back when N real `rank()` results
    are dropped — the only definition of "what a memo entry costs" a byte bound
    can be denominated in.

    The reference is `tracemalloc`: start tracing, mint the results, read
    `current`, drop them, read `current` again. Cross-entry sharing is charged
    once by that instrument, exactly as RSS charges it.

    Measured on the 2.5K-shaped bench fixture (`bench_memflat_p2.py
    --calibrate`, 400 rank-key-distinct storm results): **0.978x** at
    400 dev/3k sig and **0.982x** at 250 dev/5k sig x 4 epochs. This test runs
    the same procedure over the 112-fixture catalog corpus, doubled to clear the
    200-result floor.

    MUTANT (asserted, not described): remove the ownership test from the walk —
    the same measurement lands at ~1.59x and the band goes red. The assertion
    below runs that mutant explicitly via the `owned` override.

    SKIPS CLEANLY when tracemalloc is unavailable or already tracing (its
    counters are process-global; a second instrument would be measuring this
    one)."""
    if tracemalloc.is_tracing():
        pytest.skip("tracemalloc is already tracing this process")
    evidence = _corpus_evidence() + _corpus_evidence()
    assert len(evidence) >= CALIBRATION_MIN_RESULTS, len(evidence)
    # Warm every lazily-built structure a first call would allocate — the
    # catalog plan, the witness-clause intern, the estimator's per-type field
    # table and its per-catalog ownership set — so none of it is charged to the
    # results inside the traced window.
    warm = [rank(CAT, ev) for ev in evidence[:5]]
    estimate_result_bytes(warm[0])
    estimate_result_bytes(warm[0], frozenset())
    del warm
    gc.collect()

    try:
        tracemalloc.start(1)
    except (RuntimeError, ValueError) as exc:      # pragma: no cover - exotic build
        pytest.skip(f"tracemalloc unavailable: {exc}")
    try:
        gc.collect()
        results = [rank(CAT, ev) for ev in evidence]
        gc.collect()
        held = tracemalloc.get_traced_memory()[0]
        n = len(results)
        estimated = sum(estimate_result_bytes(r) for r in results)
        no_ownership = sum(estimate_result_bytes(r, frozenset()) for r in results)
        del results
        gc.collect()
        after = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()

    marginal = held - after
    assert marginal > 0, "tracemalloc saw nothing freed — the reference is broken"
    per_entry = marginal / n
    assert 1_000 <= per_entry <= 200_000, f"{per_entry:.0f} B/entry is not a result"
    ratio = estimated / marginal
    assert 0.80 <= ratio <= 1.30, (
        f"estimator {estimated} vs tracemalloc marginal {marginal} = {ratio:.3f}x "
        f"over {n} results ({per_entry / 1024:.1f} KiB/entry)")
    # THE MUTANT, executed: charging catalog-owned objects to every entry puts
    # the same measurement outside the band.
    assert no_ownership / marginal > 1.30, (
        f"ownership-off ratio {no_ownership / marginal:.3f}x is inside the band — "
        "the ownership test is not what is doing the work")


def test_B5b_the_estimator_tracks_the_reference_walk_across_the_whole_corpus():
    """The per-fixture and corpus-wide check that needs no tracemalloc: the
    calibrated estimator against the `gc.get_referents` reference walk with the
    SAME ownership rules. Both must see the same graph, so the band is tight.

    "The same rules" is the whole content of this test, and it is what it got
    wrong until 2026-09-03: the reference charged the process-wide Enum
    singletons to every result while the estimator (correctly, and provably —
    B5's tracemalloc anchor) charges them 0. That is a per-result tax on memory
    no eviction ever frees, so it falls hardest on the SMALLEST fixtures, and on
    CPython 3.11+ — where an Enum member's managed `__dict__` costs 304 B rather
    than 104 B — it pushed `security-threat-signal-story-confirmed` to
    est/ref = 4531/6092 = 0.744 and turned the gate red on the 3.12 runner while
    the 3.10 dev box read 0.800 and stayed green. The band did NOT move; the
    instrument was corrected (`reference_deep_bytes`, `charge_singletons`).

    MUTANTS, both executed below: stop recursing into `hypotheses` and the ratio
    collapses to ~0.02 (B11 owns that one); charge the singletons back to the
    reference and the per-fixture floor drops out of the band again."""
    owned = catalog_owned()
    results = [ranking_of(p) for p in FIXTURES]
    pairs = [(estimate_result_bytes(r), reference_deep_bytes(r, None, owned))
             for r in results]
    for est, ref in pairs:
        assert 0.75 <= est / ref <= 1.30, (est, ref)
    total_est = sum(e for e, _ in pairs)
    total_ref = sum(r for _, r in pairs)
    assert 0.90 <= total_est / total_ref <= 1.15, (total_est, total_ref)

    # THE MUTANT, executed: charge the shared Enum singletons to every result
    # and the corpus floor falls materially — the rule is what does the work,
    # not a band that happens to be wide enough.
    inflated = [reference_deep_bytes(r, None, owned, charge_singletons=True)
                for r in results]
    floor = min(e / r for e, r in pairs)
    mutant_floor = min(e / m for (e, _), m in zip(pairs, inflated))
    assert mutant_floor < floor - 0.05, (mutant_floor, floor)
    assert all(m >= r for (_, r), m in zip(pairs, inflated))

    # ...and the objects that tax buys are the SAME objects every time: far
    # fewer distinct Enum members exist than the mutant charges for. A cost
    # that does not grow with the corpus is not a per-entry cost.
    charged = [{id(m) for m in _enum_members_reached(r, owned)} for r in results]
    distinct = set().union(*charged)
    assert len(distinct) * 4 <= sum(len(c) for c in charged), (
        len(distinct), sum(len(c) for c in charged))


def _enum_members_reached(obj: object, owned: frozenset[int]) -> list[Enum]:
    """Every Enum member `reference_deep_bytes` would reach in `obj` — the
    shared pool B5b's mutant proves is charged once per result."""
    seen: set[int] = set()
    found: list[Enum] = []
    stack: list = [obj]
    while stack:
        item = stack.pop()
        oid = id(item)
        if oid in seen or oid in owned or isinstance(item, _SKIP_TYPES):
            continue
        seen.add(oid)
        if isinstance(item, Enum):
            found.append(item)
            continue
        getattr(item, "__dict__", None)
        stack.extend(gc.get_referents(item))
    return found


def test_B5b2_enum_singletons_are_charged_zero_by_the_estimator():
    """THE OTHER HALF of B5b's ownership rule, asserted on the production walk
    directly rather than inferred from a ratio: a module-level Enum member is
    charged 0 — a memo entry that points at `VerdictTier.CONFIRMED` retains
    nothing when it is evicted.

    MUTANT: drop `_walk`'s `0 if isinstance(obj, Enum)` and every assertion here
    goes red. It is asserted here because no BAND can catch it: charging the
    members lands at 1.17x of B5's tracemalloc marginal on 3.12 — wrong, and
    still inside the 1.30 band."""
    from signals import ModalityClass
    from verdicts import VerdictTier
    for member in (VerdictTier.CONFIRMED, VerdictTier.SUSPECTED,
                   ModalityClass.CONTROL_PLANE):
        assert estimate_result_bytes(member, frozenset()) == 0, member
        # ...and a container of them costs the container alone.
        assert estimate_result_bytes((member,), frozenset()) == sys.getsizeof(
            (member,)), member
    # A str-subclass Enum member must NOT fall into the `type(obj) is str`
    # branch — the reason that branch tests `type(obj) is str` and not
    # `isinstance`. MUTANT: relax it to `isinstance` and this goes red.
    assert isinstance(VerdictTier.CONFIRMED, str), "fixture assumption changed"
    assert estimate_result_bytes(VerdictTier.CONFIRMED, frozenset()) == 0


def test_B5c_catalog_owned_objects_are_charged_zero():
    """THE FIX. Everything reachable from the `Catalog` — template titles, owner
    strings, first-steps tuples, and the shared `inapplicable` HypothesisScore
    objects `scoring._catalog_plan` hands to every RCA object — lives as long as
    the catalog does. Evicting a memo entry frees none of it, so charging it was
    46 % of the old estimator's error (12.8 KiB of 33.6 KiB/entry).

    MUTANT: drop the `oid in owned` test from `_walk` and every assertion here
    goes red."""
    owned = catalog_owned()
    _, inapplicable = scoring._catalog_plan(CAT)
    shared = next(iter(inapplicable.values()))
    assert estimate_result_bytes(shared, owned) == 0, "a shared score was charged"
    assert estimate_result_bytes(shared, frozenset()) > 1_000, "nothing to charge"

    template = CAT.enabled_templates()[0]
    assert estimate_result_bytes(template.title, owned) == 0
    assert estimate_result_bytes(template.title, frozenset()) > 0
    assert estimate_result_bytes(template.verdict.first_steps, owned) == 0

    # A result whose whole hypothesis set is catalog-owned costs its own header
    # and nothing else.
    from dataclasses import replace as dc_replace
    result = ranking_of(THREE[0])
    hollow = dc_replace(result, hypotheses=tuple(inapplicable.values())[:5],
                        evidence_missing=())
    assert estimate_result_bytes(hollow) < 500, estimate_result_bytes(hollow)
    assert estimate_result_bytes(hollow, frozenset()) > 10_000


def test_B5d_a_substructure_reached_twice_is_charged_once():
    """The id-`seen` walk. Without it the near-tree's repeats cost 5.5 KiB of
    the old 33.6 KiB/entry.

    MUTANT: delete the `oid in seen` guards and `(top, top)` costs twice
    `(top,)` instead of one extra pointer."""
    import copy
    top = ranking_of(THREE[0]).hypotheses[0]
    one = estimate_result_bytes((top,), frozenset())
    twice = estimate_result_bytes((top, top), frozenset())
    assert twice == one + (sys.getsizeof((None, None)) - sys.getsizeof((None,))), (
        f"a repeat cost {twice - one} B, not one pointer slot")
    # A deepcopy is NOT a second charge: `copy.deepcopy` returns the SAME object
    # for every immutable leaf, so only the containers are new. Two structurally
    # DIFFERENT hypotheses are the honest control.
    other = ranking_of(THREE[0]).hypotheses[1]
    assert other != top
    distinct = estimate_result_bytes((top, other), frozenset())
    assert distinct > twice * 1.5, "two DISTINCT hypotheses must cost roughly twice"
    shallow = estimate_result_bytes((top, copy.deepcopy(top)), frozenset())
    assert twice < shallow < distinct


def test_B5e_the_ownership_set_is_cached_revalidated_and_fails_open():
    """The ownership set is resolved from `RankingResult.catalog_version` against
    `scoring._CATALOG_PLAN_CACHE`, cached per version, and revalidated by
    IDENTITY so a catalog reload cannot leave a stale set behind. When no
    catalog resolves it is EMPTY — the estimator falls back to charging
    everything, which is the conservative direction for a memory bound.

    MUTANT: return a stale set without the identity revalidation and the reload
    branch here goes red."""
    owned = RM._owned_ids(CAT.version_hash())
    assert owned and RM._owned_ids(CAT.version_hash()) is owned, "not cached"
    assert RM._owned_ids("cat-no-such-version") == frozenset()

    # a cache wipe rebuilds the same set from the live catalog
    RM._OWNED_CACHE.clear()
    rebuilt = RM._owned_ids(CAT.version_hash())
    assert rebuilt == owned and rebuilt is not owned

    # ...and with no plan for the version, the estimate is the conservative one
    result = ranking_of(THREE[0])
    tight = estimate_result_bytes(result)
    saved_plan = dict(scoring._CATALOG_PLAN_CACHE)
    try:
        scoring._CATALOG_PLAN_CACHE.clear()
        RM._OWNED_CACHE.clear()
        loose = estimate_result_bytes(result)
    finally:
        scoring._CATALOG_PLAN_CACHE.clear()
        scoring._CATALOG_PLAN_CACHE.update(saved_plan)
        RM._OWNED_CACHE.clear()
    assert loose > tight * 1.4, (loose, tight)
    assert estimate_result_bytes(result) == tight, "the set did not come back"


def test_B6_the_byte_bound_default_and_its_knob():
    """96 MiB, read from `CORR_RANK_MEMO_BYTES_MAX` in rank_memo.py (NOT
    main.py, which owns the entry knob). A zero/negative budget must not
    disable the bound — same fail-closed rule the entry bound has."""
    assert RM.DEFAULT_MAX_BYTES == 96 * 1024 * 1024
    assert RM.DEFAULT_MAX_ENTRIES == 50_000
    assert RankMemo().bytes_max == RM.DEFAULT_MAX_BYTES
    assert RankMemo(max_bytes=0).bytes_max == 1
    assert RankMemo(max_bytes=-5).bytes_max == 1
    # …and the knob lives HERE, not in main.py (which owns CORR_RANK_MEMO_MAX).
    src = Path(RM.__file__).read_text(encoding="utf-8")
    assert 'os.environ.get("CORR_RANK_MEMO_BYTES_MAX"' in src


def test_B7_one_oversized_entry_is_kept_rather_than_evicting_to_empty():
    """The documented exception. A budget smaller than a single entry must not
    turn `put` into a no-op loop that empties the memo — it keeps exactly one.
    MUTANT: drop the `len(self._lru) > 1` guard and this hangs at len 0 (and the
    memo can never serve anything again)."""
    result = ranking_of(THREE[0])
    memo = RankMemo(max_entries=10_000, max_bytes=1)
    memo.put("only", result)
    assert len(memo) == 1 and memo.get("only") == result
    memo.put("second", result)
    assert len(memo) == 1 and memo.evicted == 1
    assert memo.get("only") is None and memo.get("second") == result
    assert memo.bytes_used == RM.entry_bytes(result) > memo.bytes_max


def test_B8_clear_resets_the_byte_accounting():
    """`RankMemo.clear()` released 100 % of its bytes in the brief's §4; the
    counter must agree. MUTANT: forget `self.bytes_used = 0` in `clear` and the
    memo believes it is full forever."""
    memo = RankMemo()
    for path in FIXTURES[:10]:
        memo.put(path.stem, ranking_of(path))
    assert memo.bytes_used > 0
    memo.clear()
    assert len(memo) == 0 and memo.bytes_used == 0 and memo._sizes == {}
    assert memo.stats()["bytes"] == 0
    memo.put("again", ranking_of(THREE[0]))
    assert memo.bytes_used == RM.entry_bytes(ranking_of(THREE[0]))


def test_B9_re_putting_a_key_replaces_its_charge():
    """MUTANT: `self.bytes_used += size` without subtracting the previous charge
    and the memo drifts to 'full' while holding one entry."""
    small = ranking_of(THREE[0])
    large = ranking_of(THREE[2])
    memo = RankMemo(max_entries=10_000, max_bytes=1 << 40)
    for _ in range(20):
        memo.put("k", small)
    assert len(memo) == 1 and memo.bytes_used == RM.entry_bytes(small)
    memo.put("k", large)
    assert len(memo) == 1 and memo.bytes_used == RM.entry_bytes(large)
    assert memo.evicted == 0 and memo.evicted_bytes == 0
    assert memo.get("k") == large


def test_B10_the_estimator_is_deterministic_and_content_derived():
    """No `hash()`, no clock: the same value graph must give the same number
    every call, and two results REBUILT from the same evidence must estimate
    equal — in this process and in any other.

    `id()` IS used, deliberately: it is the membership token of the id-`seen`
    walk and of the catalog-ownership test. It is only ever asked "have I
    charged this object already / does the catalog own it", never mixed into the
    number, so the SUM is a function of the graph's sharing structure — which
    `rank()` reproduces exactly — and not of any address.

    A `deepcopy` is deliberately NOT asserted equal: a copy really does own the
    catalog's strings instead of pointing at them, and costs more. That is the
    estimator being right, not drifting."""
    import copy
    result = ranking_of(THREE[0])
    first = estimate_result_bytes(result)
    assert all(estimate_result_bytes(result) == first for _ in range(5))
    # CONTENT determinism: rank the same evidence again -> a new graph with the
    # same sharing structure -> the same number.
    rebuilt = ranking_of(THREE[0])
    assert rebuilt == result and rebuilt is not result
    assert estimate_result_bytes(rebuilt) == first
    # ...and a deepcopy costs MORE, because it no longer shares the catalog.
    clone = copy.deepcopy(result)
    assert clone == result
    assert estimate_result_bytes(clone) > first
    # Inspect the CODE OBJECT, not the source text: the docstring names the very
    # things it forbids, so a substring scan would be self-defeating.
    names = set(RM._walk.__code__.co_names) | set(
        estimate_result_bytes.__code__.co_names)
    assert not (names & {"hash", "time", "random", "monotonic"}), names
    assert "_getsizeof" in names and "len" in names, names


def test_B11_the_estimator_walks_the_whole_value_graph():
    """MUTANT CHECK that B5's ratio is not an accident of a header-only walk:
    the hypotheses must dominate, and each nested layer must be visible."""
    result = ranking_of(THREE[0])
    assert result.hypotheses, "fixture must produce hypotheses"
    from dataclasses import replace as dc_replace
    # `evidence_missing` is CATALOG-shaped, not hypothesis-shaped: one line per
    # unsatisfied template requirement, so it grows with every template that
    # ships (the 157/167 wave pushed the bare shell past `full/5` with no walk
    # change at all). The dominance claim under test is about the HYPOTHESES
    # payload, so the baseline strips both. The header-only-walk mutant is
    # still caught: with `hypotheses` invisible the full result estimates at
    # about the bare shell, nowhere near 5x it.
    headless = dc_replace(result, hypotheses=(), evidence_missing=())
    assert estimate_result_bytes(headless) < estimate_result_bytes(result) / 5
    top = result.hypotheses[0]
    assert estimate_result_bytes(top) > estimate_result_bytes(top.verdict_gate)
    assert estimate_result_bytes(top.verdict_gate) > \
        estimate_result_bytes(top.verdict_gate.reasons)


def test_B12_a_tight_byte_bound_is_still_byte_identical_to_memo_off():
    """The bound may evict, never CORRUPT. A memo squeezed to two entries must
    produce byte-for-byte the objects, digests, blobs and rows a memo-off run
    produces (the T4 contract, now under eviction pressure). MUTANT: return a
    stale entry after an eviction and this goes red."""
    one = RM.entry_bytes(rank(CAT, tuple(RMT.component(1))))
    memo = RankMemo(max_entries=10_000, max_bytes=one * 4)

    # Phase 1 — a working set that FITS: re-ranking the same 3 components over 3
    # cohorts must hit. (A cyclic scan wider than the bound is the one access
    # pattern LRU gives 0 hits on, so the two phases are separate on purpose.)
    small = RMT.mixed_window(3)
    small_cohorts = [RMT.keys_of(small)] * 3
    off_small = RMT.drain(small, small_cohorts, rank_memo=None)
    on_small = RMT.drain(small, small_cohorts, rank_memo=memo)
    assert memo.hits > 0, "the memo never hit — this proves nothing"

    # Phase 2 — the SAME memo against a working set twice its budget: it must
    # evict, and the objects must still match a memo-off run byte for byte.
    big = RMT.mixed_window(8)
    big_cohorts = [RMT.keys_of(big)] * 2
    off_big = RMT.drain(big, big_cohorts, rank_memo=None)
    on_big = RMT.drain(big, big_cohorts, rank_memo=memo)
    assert memo.evicted > 0, "the bound never bit — this proves nothing"
    assert memo.bytes_used <= memo.bytes_max and len(memo) <= 5

    for expected, actual in zip(off_small + off_big, on_small + on_big):
        assert [s.correlation_id for s in expected] == [s.correlation_id for s in actual]
        assert expected == actual
        assert RMT.fingerprint(expected) == RMT.fingerprint(actual)


def test_B13_the_new_stats_keys_reach_epoch_state(monkeypatch):
    """`main.epoch_state()` passes `RANK_MEMO.stats()` through verbatim, so the
    byte readout arrives with no main.py change.

    KNOWN GAP, deliberately not asserted as working (main.py belongs to another
    change in flight): `/metrics` enumerates the memo series BY HAND, and
    `rank_memo_stats()`'s memo-OFF branch returns a hardcoded dict. Both need a
    one-line follow-up — see `RankMemo.stats`'s NOTE."""
    memo = RankMemo()
    memo.put("k", ranking_of(THREE[0]))
    monkeypatch.setattr(main, "RANK_MEMO", memo)
    exported = main.epoch_state()["rank_memo"]
    assert exported == memo.stats()
    for field in ("bytes", "bytes_max", "evicted_bytes"):
        assert field in exported, f"epoch_state dropped {field}"
    assert exported["bytes"] > 0


# ═══ C — the ephemeral causal-chain clauses ═════════════════════════════════

CAUSAL_TEMPLATES = [t for t in CAT.enabled_templates() if t.causal_chain]
WITNESS_KINDS = sorted({st.witness for t in CAUSAL_TEMPLATES for st in t.causal_chain})


def catalog_owned_clause_ids(cat) -> set[int]:
    owned: set[int] = set()
    for template in cat.enabled_templates():
        for clause in template.requires:
            owned.add(id(clause))
        for disc in template.discriminators:
            owned.add(id(disc.absent))
    return owned


def foreign_clauses_pinned(cat) -> int:
    """Entries in the id-keyed `Clause.kinds` cache holding a Clause the catalog
    does NOT own — the brief's 2,292 pure-waste entries."""
    owned = catalog_owned_clause_ids(cat)
    return sum(1 for key in CATMOD._CLAUSE_KINDS_CACHE if key not in owned)


def test_C0_the_fixture_reaches_the_repaired_call_sites():
    """PREMISE for C1: the catalog must actually declare causal chains, or the
    growth test measures nothing."""
    assert CAUSAL_TEMPLATES, "no template declares a causal_chain"
    assert WITNESS_KINDS, "no causal-chain witness kinds"
    source = Path(scoring.__file__).read_text(encoding="utf-8")
    # Comment lines quote the removed call sites on purpose (that is the change
    # note); only CODE may not contain them.
    code = "\n".join(line for line in source.splitlines()
                     if not line.lstrip().startswith("#"))
    assert "Clause(kind=st.witness)" not in code
    assert "Clause(kind=stage.witness)" not in code
    assert code.count("witness_clause(st.witness)") == 1
    assert code.count("witness_clause(stage.witness)") == 1


@pytest.mark.parametrize("calls", [3, 60])
def test_C1_the_kinds_cache_no_longer_grows_with_call_count(calls):
    """THE DEFECT (brief §5.2): each `score_template` call minted a fresh
    `Clause(kind=st.witness)` that the id-keyed cache pinned and could never
    serve. Pinned-foreign count must now be a function of the WITNESS
    VOCABULARY, not of the number of calls.

    MUTANT: restore `Clause(kind=st.witness)` at scoring.py:263 and the count
    becomes `calls x len(causal_chain)` — 3 vs 60 diverge and this goes red."""
    if not CATMOD.CORR_CLAUSE_KINDS_CACHE:
        pytest.skip("CORR_CLAUSE_KINDS_CACHE=0: no identity cache to pin anything")
    evidence = tuple(RMT.component(1))
    CATMOD._CLAUSE_KINDS_CACHE.clear()
    for _ in range(calls):
        for template in CAUSAL_TEMPLATES:
            score_template(template, evidence)
    pinned = foreign_clauses_pinned(CAT)
    assert pinned <= len(WITNESS_KINDS), (
        f"{pinned} foreign clauses pinned after {calls} calls "
        f"(witness vocabulary is {len(WITNESS_KINDS)})")
    # …and it is exactly the interned set, not an accident of a cleared cache.
    assert len(CATMOD._CLAUSE_KINDS_CACHE) >= pinned


def test_C1b_the_pinned_count_is_identical_at_3_and_at_60_calls():
    """The same claim as one assertion instead of two parametrised runs, so a
    regression cannot hide behind a changed baseline."""
    if not CATMOD.CORR_CLAUSE_KINDS_CACHE:
        pytest.skip("CORR_CLAUSE_KINDS_CACHE=0")
    evidence = tuple(RMT.component(1))
    counts = []
    for calls in (3, 60):
        CATMOD._CLAUSE_KINDS_CACHE.clear()
        for _ in range(calls):
            for template in CAUSAL_TEMPLATES:
                score_template(template, evidence)
        counts.append(foreign_clauses_pinned(CAT))
    assert counts[0] == counts[1], f"pinned grows with call count: {counts}"


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_C2_interning_moves_no_scored_byte(path, monkeypatch):
    """BYTE IDENTITY over the whole 112-fixture catalog corpus: the ranking
    dataclass, its persisted `to_dict()` JSON and the `hypotheses_blob()` bytes
    must be identical with the intern and with a fresh `Clause` per call.

    MUTANT: give `witness_clause` a different default (say `optional=True`) and
    the causal-chain fixtures diverge."""
    data = json.loads(path.read_text())
    signals = [signal_from_fixture(s, i) for i, s in enumerate(data["signals"])]
    interned = rank(CAT, signals)
    monkeypatch.setattr(scoring, "witness_clause", lambda kind: Clause(kind=kind))
    fresh = rank(CAT, signals)
    assert interned == fresh
    assert json.dumps(interned.to_dict(), sort_keys=True) == \
        json.dumps(fresh.to_dict(), sort_keys=True)
    assert RMT.blob_of(interned) == RMT.blob_of(fresh)


def test_C3_the_interned_clause_is_value_identical_and_stable():
    """One object per witness string, equal by value to a fresh construction,
    and the same object on every call — which is exactly what makes the
    downstream identity cache hit."""
    for kind in WITNESS_KINDS:
        shared = witness_clause(kind)
        assert shared is witness_clause(kind), "identity is not stable"
        assert shared == Clause(kind=kind), "value drifted from a fresh Clause"
        assert shared.kinds() == Clause(kind=kind).kinds()
        assert shared.entity_type is None and shared.min_deviation is None
        assert shared.role is None and shared.optional is False


def test_C4_the_witness_clause_cache_is_bounded():
    """§9: bounded, and overflow clears rather than grows. MUTANT: delete the
    bound and the dict is an unbounded strong-ref map keyed by attacker-visible
    strings."""
    assert scoring._WITNESS_CLAUSE_CACHE_MAX == 4096
    saved = dict(scoring._WITNESS_CLAUSE_CACHE)
    try:
        scoring._WITNESS_CLAUSE_CACHE.clear()
        for i in range(scoring._WITNESS_CLAUSE_CACHE_MAX + 5):
            witness_clause(f"synthetic_kind_{i}")
        assert len(scoring._WITNESS_CLAUSE_CACHE) <= scoring._WITNESS_CLAUSE_CACHE_MAX
        assert witness_clause("synthetic_kind_0") == Clause(kind="synthetic_kind_0")
    finally:
        scoring._WITNESS_CLAUSE_CACHE.clear()
        scoring._WITNESS_CLAUSE_CACHE.update(saved)


def test_C5_the_catalog_plan_kind_index_is_unchanged_by_interning(monkeypatch):
    """`_template_kinds` (scoring.py:378) is the second repaired site; it feeds
    the tracker-167 inapplicable-template index, so a drift there would silently
    change which templates get scored analytically."""
    from scoring import _catalog_plan, _template_kinds
    interned = {t.id: _template_kinds(t) for t in CAT.enabled_templates()}
    monkeypatch.setattr(scoring, "witness_clause", lambda kind: Clause(kind=kind))
    fresh = {t.id: _template_kinds(t) for t in CAT.enabled_templates()}
    assert interned == fresh
    index, inapplicable = _catalog_plan(CAT)
    assert index == interned
    assert set(inapplicable) == set(interned)


# ═══ C — THE COMPACT CACHED FORM (rank_memo.py, THE COMPACT CACHED FORM) ═════
#
# The memo stores a `bytes` blob of the per-EVIDENCE half of a `RankingResult`
# and rebuilds the value from the catalog on a hit: 24.5 KiB/entry -> ~1.15 KiB
# (21x), so the 96 MiB bound admits ~85,000 entries instead of ~2,900 and the
# live run's 20,117-key population fits whole. These tests pin the ONE thing
# that buys: that the rebuilt value is EQUAL, byte for byte, or is refused.

def _all_rankings() -> list[RankingResult]:
    return [ranking_of(p) for p in FIXTURES]


def test_C0_the_compact_form_is_the_default_and_the_corpus_is_not_trivial():
    """PREMISE. If the codec silently refused everything, every C test below
    would pass vacuously on the object fallback."""
    import os
    knob = os.environ.get("CORR_RANK_MEMO_COMPACT", "1").lower()
    assert RM.DEFAULT_COMPACT is (knob in ("1", "true", "yes"))
    if knob in ("1", "true", "yes"):
        assert RankMemo().compact is True, "the compact form is not the default"
    assert RankMemo(compact=True).compact is True
    encoded = [RM.encode_result(r) for r in _all_rankings()]
    assert len(encoded) >= 25
    assert all(b is not None for b in encoded), \
        f"{sum(b is None for b in encoded)} of {len(encoded)} results refused"
    assert len({bytes(b) for b in encoded}) > 5, "the codec returns one blob"


def test_C1_the_round_trip_is_equal_and_byte_identical_over_the_whole_corpus():
    """THE CONTRACT. A decoded entry must be `==` the value that was encoded AND
    must produce the identical persisted `hypotheses_blob()` bytes — the T1/T4
    oracles, applied to the codec instead of to the key.

    MUTANT: drop `first_steps` from the rebuild (or restore `note` unconditionally
    instead of only for an unwitnessed rung) and this goes red."""
    checked = 0
    for result in _all_rankings():
        blob = RM.encode_result(result)
        assert blob is not None
        back = RM.decode_result(blob)
        assert back == result, result.top_hypothesis
        assert RMT.blob_of(back) == RMT.blob_of(result), result.top_hypothesis
        assert back.to_dict() == result.to_dict()
        checked += 1
    assert checked >= 25


def test_C2_the_compact_entry_is_an_order_of_magnitude_smaller_and_exact():
    """The whole point, and the accounting: the charge is the blob's real size
    plus the per-entry bookkeeping — measured, not estimated."""
    ratios = []
    for result in _all_rankings():
        blob = RM.encode_result(result)
        assert blob is not None
        assert RM.entry_bytes(result, compact=True) == \
            sys.getsizeof(blob) + RM._ENTRY_OVERHEAD
        assert RM.entry_bytes(result, compact=False) == \
            estimate_result_bytes(result) + RM._ENTRY_OVERHEAD
        ratios.append(estimate_result_bytes(result) / sys.getsizeof(blob))
    assert min(ratios) > 3.0, f"the compact form barely shrank: {min(ratios):.1f}x"
    assert sum(ratios) / len(ratios) > 8.0, \
        f"mean shrink {sum(ratios)/len(ratios):.1f}x, expected >8x"


def test_C3_the_codec_is_deterministic_and_content_derived():
    """No `hash()`, no clock, no address: the same value must encode to the same
    bytes in this process and in any other, or the byte bound would wobble."""
    result = ranking_of(THREE[0])
    first = RM.encode_result(result)
    assert all(RM.encode_result(result) == first for _ in range(5))
    # a freshly ranked, structurally identical result -> identical bytes
    assert RM.encode_result(ranking_of(THREE[0])) == first


@pytest.mark.parametrize("field,value", [
    ("title", "a title the template does not carry"),
    ("owner", "someone-else"),
    ("first_steps", ("a step the template does not declare",)),
    ("seams", ("seam-not-in-template",)),
    ("blast_radius", "wider than declared"),
    ("template_id", "sig.no.such.template"),
])
def test_C4_a_field_the_catalog_cannot_rebuild_is_REFUSED(field, value):
    """FAIL-CLOSED. Every field the codec drops is verified against the template
    before it is dropped; a mismatch refuses the encoding and the memo stores the
    object, exactly as it did before.

    MUTANT: delete the `!= fixed` guard in `encode_result` and this goes red —
    the codec would silently hand back the TEMPLATE's wording in place of the
    scorer's."""
    import dataclasses
    result = ranking_of(THREE[0])
    assert result.hypotheses, "fixture has no hypotheses to doctor"
    doctored = dataclasses.replace(result.hypotheses[0], **{field: value})
    forged = dataclasses.replace(result, hypotheses=(doctored,) + result.hypotheses[1:])
    assert RM.encode_result(forged) is None, f"{field} was dropped unverified"
    # …and the memo keeps working: it stores the object instead.
    memo = RankMemo()
    memo.put("forged", forged)
    assert type(memo._lru["forged"]) is RankingResult
    assert memo.get("forged") is forged


def test_C4b_a_doctored_causal_chain_rung_is_REFUSED():
    """The chain's stage/root/note come from the template and its
    witnessed/kinds from the evidence; a rung that does not follow that rule is
    not rebuildable, so it is refused rather than guessed."""
    import dataclasses
    chained = [r for r in _all_rankings()
               if any(h.causal_chain for h in r.hypotheses)]
    assert chained, "no fixture exercises the causal chain — C4b proves nothing"
    result = chained[0]
    i, hyp = next((i, h) for i, h in enumerate(result.hypotheses) if h.causal_chain)
    assert RM.encode_result(result) is not None
    rung = dict(hyp.causal_chain[0])
    rung["note"] = "a note the template never declared"
    rung["witnessed"] = True
    doctored = dataclasses.replace(
        hyp, causal_chain=(rung,) + hyp.causal_chain[1:])
    forged = dataclasses.replace(
        result, hypotheses=result.hypotheses[:i] + (doctored,)
        + result.hypotheses[i + 1:])
    assert RM.encode_result(forged) is None


def test_C5_an_unresolvable_catalog_refuses_to_encode_and_fails_closed_on_get(
        monkeypatch):
    """A blob is only decodable while the templates it was encoded against are
    alive. If they are not, `get` must report a MISS (the caller ranks in full),
    never a partially rebuilt verdict.

    MUTANT: return the raw blob from `get`, or rebuild from a DIFFERENT
    catalog, and this goes red."""
    import dataclasses
    result = ranking_of(THREE[0])
    memo = RankMemo(compact=True)
    memo.put("k", result)
    assert type(memo._lru["k"]) is bytes
    monkeypatch.setattr(RM, "_VIEW_CACHE", {})
    monkeypatch.setattr(scoring, "_CATALOG_PLAN_CACHE", {})
    assert RM.encode_result(result) is None
    assert memo.get("k") is None, "a value was rebuilt with no catalog"
    assert len(memo) == 0 and memo.bytes_used == 0, "the dead entry was kept"
    # an unknown version never resolves either
    alien = dataclasses.replace(result, catalog_version="no-such-version")
    assert RM.encode_result(alien) is None


def test_C6_the_kill_switch_restores_the_object_store():
    """`CORR_RANK_MEMO_COMPACT=0` / `compact=False` must give back exactly the
    pre-change memo: the identical object, charged by the calibrated walk."""
    result = ranking_of(THREE[0])
    memo = RankMemo(compact=False)
    memo.put("k", result)
    assert type(memo._lru["k"]) is RankingResult
    assert memo.get("k") is result, "the object store stopped sharing"
    assert memo.bytes_used == estimate_result_bytes(result) + RM._ENTRY_OVERHEAD
    src = Path(RM.__file__).read_text(encoding="utf-8")
    assert 'os.environ.get(\n    "CORR_RANK_MEMO_COMPACT"' in src \
        or 'os.environ.get(' in src and "CORR_RANK_MEMO_COMPACT" in src


def test_C7_a_compact_memo_is_byte_identical_to_memo_off_end_to_end():
    """The T4 contract against the CODEC: a drain served by a compact memo must
    produce the same objects, digests and blobs a memo-off drain produces.

    MUTANT: rebuild `notes` from the template instead of from the blob and this
    goes red on the first role-clause hit."""
    memo = RankMemo(compact=True)
    win = RMT.mixed_window(6)
    cohorts = [RMT.keys_of(win)] * 3
    off = RMT.drain(win, cohorts, rank_memo=None)
    on = RMT.drain(win, cohorts, rank_memo=memo)
    assert memo.hits > 0, "the memo never hit — this proves nothing"
    assert all(type(v) is bytes for v in memo._lru.values()), \
        "the drain never exercised the compact form"
    for expected, actual in zip(off, on):
        assert expected == actual
        assert RMT.fingerprint(expected) == RMT.fingerprint(actual)
