"""Tracker 195 — the persist side must BOUND `corr_objects.hypotheses`.

THE DEFECT. There was no write-side bound at all. Against a 29 KiB mean the
table holds 1,195 rows > 1 MiB, 74 > 10 MiB, 11 > 50 MiB, max 76.53 MiB, and
because MergeTree granularity is adaptive ONE such row makes its whole GRANULE
unreadable: a one-key SELECT for an innocent 22-30 KiB neighbour dies at
`read_rows = 0` with `Code: 241 ... allocate chunk of 536871039 bytes,
maximum: 512.00 MiB ... (while reading column hypotheses)`.

WHERE THE BYTES ARE (measured 2026-09-02, and NOT what the tracker row
assumed): on `e571c39d-…` v3, 80,243,943 B total of which
`grounding_context.path_graph.relations` is 80,173,403 B (99.91 %, 195,888
items) and `ranking.hypotheses` only 69,729 B. The row's `degradation` block is
ABSENT, so these monsters are not storm-mode objects at all. The real storm
aggregate (`bb1e46d6-…` for tenant `global`) measures 643-648 BYTES per version
at 8k-21k nodes — see `test_the_storm_aggregate_is_far_below_any_usable_cap`.

The tests below pin: below-cap rows are byte-for-byte untouched; above-cap rows
stay valid JSON under the cap with the verdict, the top hypothesis and every
contradiction intact; the marker and the counter make it visible; and the
output is bounded for arbitrary inputs.
"""
from __future__ import annotations

import json
import random

import pytest

import engine

CAP = engine.CORR_HYPOTHESES_MAX_BYTES


def _rel(i: int, rank: int | None = None) -> dict:
    """A serialized Relation exactly as `Relation.to_dict()` emits it."""
    return {"edge_type": "depends_on", "method": "traceroute_icmp",
            "rank": (i % 7) + 1 if rank is None else rank,
            "evidence_class": "observed", "confidence": "strong",
            "authoritative": i % 2 == 0, "evidence_ref": f"ev-{i:08d}",
            "observation_method": "traceroute_icmp",
            "observed_at": "2026-09-02T00:00:00Z", "data_class": "live",
            "ref": f"obs-{i:08d}", "seam_id": "", "transformation": "none",
            "stale": False, "unknown_hops": [], "supporting_refs": [],
            "contract_version": "1.0"}


def _hyp(i: int, *, contradicted: bool = False, pad: int = 500) -> dict:
    """A serialized HypothesisScore (the ~5.3 KiB shape measured in-tree)."""
    return {"id": f"tmpl-{i}", "title": "T" * 120, "coverage": 0.9 - i * 0.1,
            "confidence": 0.9 - i * 0.1, "confidence_label": "likely",
            "contradicted": contradicted, "satisfied": ["link_state_change"],
            "missing": [], "contradictions": ["bgp_state_change"] if contradicted else [],
            "forced_competitors": [], "notes": ["n" * pad], "seams": ["wan"],
            "deployment_scope": "hybrid", "operator_phrase": "o" * pad,
            "manager_phrase": "m" * pad, "blast_radius": "site",
            "false_positives": [], "causal_chain": [],
            "verdict": {"owner": "network", "first_steps": ["check the link"],
                        "tier": "likely"}}


def _blob(n_rel: int = 0, n_hyp: int = 4, contradicted_at: int | None = 2) -> str:
    hyps = [_hyp(i, contradicted=(i == contradicted_at)) for i in range(n_hyp)]
    ctx: dict = {"topology_version": "seams-abc123", "seams": [],
                 "topology_gap_hints": 0}
    if n_rel:
        ctx["path_graph"] = {
            "contract_version": "1.0",
            "relations": [_rel(i) for i in range(n_rel)],
            "observations": [], "endpoints": [], "service_bindings": [],
            "nat_sessions": [], "routes": [], "freshness_s": 30.0}
    return json.dumps({"ranking": {"top_hypothesis": "tmpl-0",
                                   "verdict_tier": "likely",
                                   "hypotheses": hyps,
                                   "evidence_missing": ["bgp_state_change"],
                                   "catalog_version": "cat-1"},
                       "grounding_context": ctx},
                      separators=(",", ":"), sort_keys=True)


# ── below the cap: nothing moves ───────────────────────────────────────────

def test_a_below_cap_blob_is_returned_byte_for_byte():
    """The 99.95 % path. Not "equal" — the SAME object, so the row bytes, the
    version and every replay pin are provably untouched."""
    blob = _blob(n_rel=21)                       # the measured innocent shape
    assert len(blob) < 40_000
    out, marker = engine.bound_hypotheses_blob(blob)
    assert out is blob
    assert marker is None


@pytest.mark.parametrize("n_rel", [0, 1, 3, 14, 21, 2000])
def test_every_measured_legitimate_row_survives_untouched(n_rel):
    """The four rows the 186 splitter skipped carry 22,029-30,773 B with 0-21
    relations; 2,000 relations is ~5x the largest legitimate object seen. All
    of them must be under the cap with room to spare."""
    blob = _blob(n_rel=n_rel)
    out, marker = engine.bound_hypotheses_blob(blob)
    assert marker is None, f"{n_rel} relations ({len(blob)} B) tripped the cap"
    assert out is blob


def test_the_default_cap_is_justified_by_the_measured_distribution():
    """1 MiB: ~34x the largest measured legitimate row (30,773 B), two orders
    below the 512 MiB per-query guard that refuses the read today, and above
    every one of the 2.38 M rows except the 0.05 % tail."""
    assert engine.hypotheses_cap_bytes() == 1 << 20
    assert engine.hypotheses_cap_bytes() > 30_773 * 30
    assert engine.hypotheses_cap_bytes() < 512 * (1 << 20) // 100


# ── above the cap: bounded, valid, and honest about it ─────────────────────

def test_an_oversized_blob_is_capped_and_stays_valid_json():
    blob = _blob(n_rel=40_000)                  # the monster shape, scaled down
    assert len(blob) > 10 * (1 << 20)   # the row's ">10 MiB" bucket
    out, marker = engine.bound_hypotheses_blob(blob)

    assert len(out) <= CAP
    doc = json.loads(out)                        # never cut mid-JSON
    assert marker is not None and marker["applied"] is True
    assert marker["original_bytes"] == len(blob)
    assert marker["dropped_relations"] > 0
    assert doc["hypotheses_truncated"] == marker


def test_the_verdict_and_the_top_hypothesis_survive_truncation():
    before = json.loads(_blob(n_rel=40_000))
    out, _ = engine.bound_hypotheses_blob(_blob(n_rel=40_000))
    after = json.loads(out)

    assert after["ranking"]["top_hypothesis"] == before["ranking"]["top_hypothesis"]
    assert after["ranking"]["verdict_tier"] == before["ranking"]["verdict_tier"]
    assert after["ranking"]["evidence_missing"] == before["ranking"]["evidence_missing"]
    assert after["ranking"]["hypotheses"][0] == before["ranking"]["hypotheses"][0]
    # The relation list is the only thing that lost members.
    assert after["ranking"]["hypotheses"] == before["ranking"]["hypotheses"]


def test_contradictions_are_never_dropped():
    """A contradicted look-alike is WHY the ranking is trustworthy. Force the
    ranking itself over the cap and the contradicted entry must still be there."""
    hyps = [_hyp(0), _hyp(1, pad=400_000), _hyp(2, contradicted=True),
            _hyp(3, pad=400_000), _hyp(4, pad=400_000)]
    blob = json.dumps({"ranking": {"top_hypothesis": "tmpl-0",
                                   "verdict_tier": "confirmed",
                                   "hypotheses": hyps, "evidence_missing": [],
                                   "catalog_version": "cat-1"},
                       "grounding_context": {"seams": []}},
                      separators=(",", ":"), sort_keys=True)
    out, marker = engine.bound_hypotheses_blob(blob)
    doc = json.loads(out)

    assert len(out) <= CAP
    assert marker is not None and marker["dropped_hypotheses"] > 0
    kept = doc["ranking"]["hypotheses"]
    assert kept[0]["id"] == "tmpl-0", "the top hypothesis was dropped"
    assert any(h["id"] == "tmpl-2" and h["contradicted"] for h in kept), (
        "a contradicted hypothesis was shed — the verdict is no longer honest")
    assert doc["ranking"]["verdict_tier"] == "confirmed"


def test_the_surviving_relations_are_the_best_evidence_in_the_original_order():
    """Rank 1-5 is observed/authoritative, 6 inferred, 7 shared token — the same
    ladder `hypotheses_blob` reasons with. Survivors keep the builder's order so
    a reader sees the list it expects, only shorter."""
    out, _ = engine.bound_hypotheses_blob(_blob(n_rel=40_000))
    rels = json.loads(out)["grounding_context"]["path_graph"]["relations"]

    assert rels, "every relation was dropped"
    assert max(r["rank"] for r in rels) == 1, "a weaker relation displaced a rank-1"
    refs = [r["ref"] for r in rels]
    assert refs == sorted(refs), "the survivors were reordered"


def test_truncation_is_deterministic():
    a, _ = engine.bound_hypotheses_blob(_blob(n_rel=40_000))
    b, _ = engine.bound_hypotheses_blob(_blob(n_rel=40_000))
    assert a == b, "the same object must always shed the same evidence"


def test_the_blob_is_ascii_so_character_length_is_byte_length():
    """The byte accounting the cap does (`len(str)`) is only exact because both
    `hypotheses_blob()` and the re-dump use json.dumps' default
    ensure_ascii=True. ClickHouse's `length()` counts bytes."""
    hyps = [_hyp(0), _hyp(1)]
    hyps[0]["title"] = "liaison café — 帯域"
    blob = json.dumps({"ranking": {"top_hypothesis": "tmpl-0",
                                   "verdict_tier": "likely", "hypotheses": hyps,
                                   "evidence_missing": [], "catalog_version": "c"},
                       "grounding_context": {"seams": []}},
                      separators=(",", ":"), sort_keys=True)
    assert blob.isascii() and len(blob) == len(blob.encode("utf-8"))
    out, _ = engine.bound_hypotheses_blob(blob, max_bytes=1 << 16)
    assert out.isascii() and len(out) == len(out.encode("utf-8"))


# ── the ladder's lower rungs ───────────────────────────────────────────────

def test_the_whole_path_graph_block_goes_before_the_verdict_does():
    """A path_graph whose non-relation members alone blow the cap: the block is
    dropped as a named unit, and the ranking is still intact."""
    blob = json.dumps(
        {"ranking": {"top_hypothesis": "tmpl-0", "verdict_tier": "likely",
                     "hypotheses": [_hyp(0)], "evidence_missing": [],
                     "catalog_version": "cat-1"},
         "grounding_context": {"seams": [], "path_graph": {
             "contract_version": "1.0", "relations": [],
             "observations": [{"id": f"o{i}", "pad": "p" * 400} for i in range(600)],
             "endpoints": [], "service_bindings": [], "nat_sessions": [],
             "routes": [], "freshness_s": 30.0}}},
        separators=(",", ":"), sort_keys=True)
    out, marker = engine.bound_hypotheses_blob(blob, max_bytes=1 << 16)
    doc = json.loads(out)

    assert len(out) <= 1 << 16
    assert marker is not None
    assert "grounding_context.path_graph" in marker["dropped_blocks"]
    assert doc["ranking"]["hypotheses"][0]["id"] == "tmpl-0"


def test_a_cap_below_the_floor_is_clamped_up_not_obeyed():
    """A misconfigured 1 KiB cap would truncate EVERY object instead of the
    pathological tail. One HypothesisScore alone measures ~5 KiB."""
    assert engine.hypotheses_cap_bytes(1024) == engine.HYPOTHESES_CAP_FLOOR
    assert engine.hypotheses_cap_bytes(0) == 0            # explicitly disabled
    assert engine.hypotheses_cap_bytes(-1) == 0
    _out, marker = engine.bound_hypotheses_blob(_blob(n_rel=40_000), max_bytes=0)
    assert marker is None, "cap 0 must be a true bypass, not a silent cap"


def test_an_unparseable_payload_is_never_cut_mid_json():
    junk = "{" + "x" * (2 << 20)
    out, marker = engine.bound_hypotheses_blob(junk)
    assert out == junk, "bytes we cannot parse must be passed through, not sliced"
    assert marker is not None and marker["applied"] is False
    assert marker["reason"] == "unparseable"


def test_an_irreducible_document_declares_that_it_is_still_over_cap():
    """No silent failures: if even the floor exceeds the cap, the row says so
    rather than pretending the bound held."""
    huge = _hyp(0, pad=200_000)
    blob = json.dumps({"ranking": {"top_hypothesis": "tmpl-0",
                                   "verdict_tier": "likely", "hypotheses": [huge],
                                   "evidence_missing": [], "catalog_version": "c"},
                       "grounding_context": {"seams": []}},
                      separators=(",", ":"), sort_keys=True)
    out, marker = engine.bound_hypotheses_blob(blob, max_bytes=1 << 16)
    assert marker is not None and marker.get("floor_exceeded") is True
    json.loads(out)


# ── the storm aggregate: exempt by construction, not by special case ───────

def test_the_storm_aggregate_is_far_below_any_usable_cap():
    """AGG_CID DECISION. `run_window` builds the tenant-constant storm-noise
    aggregate with `hypotheses=()` and `edges=()`, so its blob carries no
    ranking body and no `path_graph` block at all. MEASURED on the live table:
    643-648 BYTES per version at 8,928-21,231 nodes. The cap therefore cannot
    change its semantics and needs NO special case — which is the honest
    outcome, since a silent exemption would be a hole in the bound."""
    blob = json.dumps(
        {"ranking": {"top_hypothesis": "undetermined",
                     "verdict_tier": "undetermined", "hypotheses": [],
                     "evidence_missing": [], "catalog_version": "cat-1"},
         "grounding_context": {"topology_version": "seams-abc123", "seams": [],
                               "topology_gap_hints": 0,
                               "degradation": {"topology_stale": False,
                                               "storm_mode": True,
                                               "storm_aggregate": {
                                                   "occurrences": 23241,
                                                   "distinct_entities": 8230,
                                                   "window_span_s": 300.0}}}},
        separators=(",", ":"), sort_keys=True)
    assert len(blob) < 1024, "the aggregate grew a body — re-check the AGG_CID note"
    out, marker = engine.bound_hypotheses_blob(blob)
    assert out is blob and marker is None


# ── property: bounded and parseable for arbitrary rankings ─────────────────

@pytest.mark.parametrize("seed", range(12))
def test_property_any_ranking_comes_out_bounded_and_parseable(seed):
    rnd = random.Random(seed)
    n_hyp = rnd.randint(1, 12)
    hyps = [_hyp(i, contradicted=rnd.random() < 0.25,
                 pad=rnd.choice([50, 5_000, 120_000]))
            for i in range(n_hyp)]
    n_rel = rnd.choice([0, 5, 5_000, 20_000])
    ctx: dict = {"topology_version": "tv", "seams": [], "topology_gap_hints": 0}
    if n_rel:
        ctx["path_graph"] = {"contract_version": "1.0",
                             "relations": [_rel(i, rank=rnd.randint(1, 7))
                                           for i in range(n_rel)],
                             "observations": [], "endpoints": [],
                             "service_bindings": [], "nat_sessions": [],
                             "routes": [], "freshness_s": 30.0}
    blob = json.dumps({"ranking": {"top_hypothesis": "tmpl-0",
                                   "verdict_tier": "likely", "hypotheses": hyps,
                                   "evidence_missing": [], "catalog_version": "c"},
                       "grounding_context": ctx},
                      separators=(",", ":"), sort_keys=True)
    cap = rnd.choice([1 << 16, 1 << 18, 1 << 20])
    out, marker = engine.bound_hypotheses_blob(blob, max_bytes=cap)

    doc = json.loads(out)                       # ALWAYS parseable
    if marker is None:
        assert out is blob and len(blob) <= cap
        return
    assert doc["ranking"]["top_hypothesis"] == "tmpl-0"
    assert doc["ranking"]["verdict_tier"] == "likely"
    if marker.get("floor_exceeded"):
        # Irreducible (one enormous protected hypothesis) — declared, never faked.
        assert doc["hypotheses_truncated"]["floor_exceeded"] is True
    else:
        assert len(out) <= cap, f"cap {cap} exceeded: {len(out)}"
    kept = {h["id"] for h in doc["ranking"]["hypotheses"]}
    for i, h in enumerate(hyps):
        if i == 0 or h["contradicted"]:
            assert h["id"] in kept, f"protected hypothesis {h['id']} was dropped"
