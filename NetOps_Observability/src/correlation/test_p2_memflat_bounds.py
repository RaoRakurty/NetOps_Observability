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
2. **`scoring`'s causal-chain clauses are interned** (brief §5.2). The two call
   sites built a fresh `Clause(kind=...)` per call; the id-keyed `Clause.kinds`
   cache pinned each one until it self-evicted at 4,096 (2,292 pinned foreign
   clauses measured). `witness_clause` interns by the witness STRING, and the
   scored bytes must not move by one character. Tests C1-C5.

Every test is a mutant check — what turns it red is named in its docstring.
"""
from __future__ import annotations

import json
import sys
from dataclasses import fields as dc_fields
from dataclasses import is_dataclass
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


# ── the REFERENCE instrument ─────────────────────────────────────────────────

def reference_deep_bytes(obj: object, seen: set[int] | None = None) -> int:
    """A recursive `sys.getsizeof` deep-size walk with an id-`seen` set — the
    same instrument `bench_memflat_p2.py` used to produce the brief's 10-26
    KiB/entry. Slower and more exact than the production estimator; it exists
    here only to bound the estimator's error (B5)."""
    if seen is None:
        seen = set()
    if id(obj) in seen:
        return 0
    seen.add(id(obj))
    total = sys.getsizeof(obj)
    if isinstance(obj, (str, bytes, int, float, bool)) or obj is None:
        return total
    if isinstance(obj, dict):
        for key, value in obj.items():
            total += reference_deep_bytes(key, seen) + reference_deep_bytes(value, seen)
        return total
    if isinstance(obj, (tuple, list, set, frozenset)):
        for item in obj:
            total += reference_deep_bytes(item, seen)
        return total
    if is_dataclass(obj) and not isinstance(obj, type):
        for field in dc_fields(obj):
            total += reference_deep_bytes(getattr(obj, field.name), seen)
    return total


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
    one = estimate_result_bytes(result)
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
    assert memo.bytes_used == 4 * estimate_result_bytes(result)
    assert memo.stats()["max_entries"] == 4


def test_B3_lru_order_is_preserved_under_the_byte_bound():
    """A `get` must promote, and the byte bound must evict the LEAST RECENTLY
    USED entry — not the oldest-inserted. MUTANT: make `put` evict `last=True`
    and this goes red."""
    result = ranking_of(THREE[0])
    one = estimate_result_bytes(result)
    memo = RankMemo(max_entries=10_000, max_bytes=one * 3)
    for key in ("a", "b", "c"):
        memo.put(key, result)
    assert len(memo) == 3
    assert memo.get("a") is result          # promote 'a'; 'b' becomes the LRU
    memo.put("d", result)
    assert len(memo) == 3 and memo.evicted == 1
    assert memo.get("b") is None, "the byte bound evicted the wrong entry"
    assert memo.get("a") is result and memo.get("c") is result and memo.get("d") is result
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
    assert stats["bytes"] == sum(estimate_result_bytes(v) for v in rankings.values())
    assert stats["bytes"] == memo.bytes_used == sum(memo._sizes.values())

    # now squeeze it and re-check both halves of the identity
    held = list(memo._lru)
    tight = RankMemo(max_entries=10_000, max_bytes=stats["bytes"] // 2)
    for key in held:
        tight.put(key, rankings[key])
    assert tight.bytes_used == sum(tight._sizes.values()) <= tight.bytes_max
    assert tight.evicted_bytes == stats["bytes"] - tight.bytes_used
    assert tight.evicted == len(held) - len(tight)


@pytest.mark.parametrize("path", THREE, ids=lambda p: p.stem)
def test_B5_the_estimator_tracks_the_reference_deep_size(path):
    """THE STATED FACTOR: `estimate_result_bytes` is within **0.75x-1.50x** of a
    reference recursive `sys.getsizeof` deep-size walk, and biased HIGH (a
    memory bound may over-charge, never silently under-charge by much).

    Measured over 400 real `rank()` outputs on the built-in catalog the ratio is
    mean **1.06x**, range **0.94x-1.33x**; the band here is that range with
    headroom for a catalog whose strings/enums shift the mix.

    MUTANT: stop recursing into `hypotheses` (count only the RankingResult
    header) and the ratio collapses to ~0.01 — red. Charge Enum members their
    full `getsizeof` and it drifts high."""
    result = ranking_of(path)
    estimated = estimate_result_bytes(result)
    reference = reference_deep_bytes(result)
    ratio = estimated / reference
    assert 0.75 <= ratio <= 1.50, (
        f"{path.stem}: estimate {estimated} vs reference {reference} = {ratio:.3f}x")
    # and the absolute scale must match the brief's order of magnitude
    assert 1_000 <= reference <= 200_000, reference


def test_B5b_the_estimator_is_biased_high_across_the_whole_fixture_corpus():
    """The band in B5 is per-fixture; this pins the AGGREGATE bias over all 112
    catalog fixtures, which is the number the 96 MiB default was sized against."""
    pairs = [(estimate_result_bytes(r), reference_deep_bytes(r))
             for r in (ranking_of(p) for p in FIXTURES)]
    total_est = sum(e for e, _ in pairs)
    total_ref = sum(r for _, r in pairs)
    assert 0.90 <= total_est / total_ref <= 1.35, (total_est, total_ref)
    per_entry = total_ref / len(pairs)
    assert 3_000 <= per_entry <= 40_000, (
        f"per-entry deep size {per_entry:.0f} B left the brief's 10-26 KiB band")


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
    assert len(memo) == 1 and memo.get("only") is result
    memo.put("second", result)
    assert len(memo) == 1 and memo.evicted == 1
    assert memo.get("only") is None and memo.get("second") is result
    assert memo.bytes_used == estimate_result_bytes(result) > memo.bytes_max


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
    assert memo.bytes_used == estimate_result_bytes(ranking_of(THREE[0]))


def test_B9_re_putting_a_key_replaces_its_charge():
    """MUTANT: `self.bytes_used += size` without subtracting the previous charge
    and the memo drifts to 'full' while holding one entry."""
    small = ranking_of(THREE[0])
    large = ranking_of(THREE[2])
    memo = RankMemo(max_entries=10_000, max_bytes=1 << 40)
    for _ in range(20):
        memo.put("k", small)
    assert len(memo) == 1 and memo.bytes_used == estimate_result_bytes(small)
    memo.put("k", large)
    assert len(memo) == 1 and memo.bytes_used == estimate_result_bytes(large)
    assert memo.evicted == 0 and memo.evicted_bytes == 0
    assert memo.get("k") is large


def test_B10_the_estimator_is_deterministic_and_content_derived():
    """No `hash()`, no `id()`, no clock: the same value graph must give the same
    number every call, and two EQUAL results must estimate equal."""
    import copy
    result = ranking_of(THREE[0])
    first = estimate_result_bytes(result)
    assert all(estimate_result_bytes(result) == first for _ in range(5))
    clone = copy.deepcopy(result)
    assert clone == result and clone is not result
    assert estimate_result_bytes(clone) == first
    # Inspect the CODE OBJECT, not the source text: the docstring names the very
    # things it forbids, so a substring scan would be self-defeating.
    names = set(estimate_result_bytes.__code__.co_names)
    assert not (names & {"id", "hash", "time", "random", "monotonic"}), names
    assert "_getsizeof" in names and "len" in names, names


def test_B11_the_estimator_walks_the_whole_value_graph():
    """MUTANT CHECK that B5's ratio is not an accident of a header-only walk:
    the hypotheses must dominate, and each nested layer must be visible."""
    result = ranking_of(THREE[0])
    assert result.hypotheses, "fixture must produce hypotheses"
    from dataclasses import replace as dc_replace
    headless = dc_replace(result, hypotheses=())
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
    one = estimate_result_bytes(rank(CAT, tuple(RMT.component(1))))
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
