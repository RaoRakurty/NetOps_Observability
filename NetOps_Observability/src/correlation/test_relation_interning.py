# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 156 — interned Relations/Groundings must be value-identical, bounded.

Memory forensics on a 1k run (2026-08-20) attributed 157.8 MB across 2,593,452
blocks — 85% of the traced heap at the 85%-of-cap crossing — to engine.py and
path_graph.py. The dominant sites build a fresh Relation and Grounding for every
CANDIDATE PAIR, which is quadratic in the window, even though both are pure
functions of a token or seam id.

The risk of interning is handing out a WRONG shared object, so every field that
distinguishes two relations must distinguish two cache entries. The risk of not
bounding it is that the keys come from device-supplied tokens.
"""
from __future__ import annotations

import pytest

import engine
import path_graph as pg


@pytest.fixture(autouse=True)
def _clear():
    for c in (pg._SHARED_TOKEN_RELATIONS, pg._SEAM_RELATIONS,
              engine._SHARED_TOKEN_GROUNDINGS, engine._SEAM_TOKEN_GROUNDINGS):
        c.clear()
    yield
    for c in (pg._SHARED_TOKEN_RELATIONS, pg._SEAM_RELATIONS,
              engine._SHARED_TOKEN_GROUNDINGS, engine._SEAM_TOKEN_GROUNDINGS):
        c.clear()


# --- value identity --------------------------------------------------------

def test_shared_token_relation_is_shared_for_the_same_token():
    a = pg.shared_token_relation("core-1")
    b = pg.shared_token_relation("core-1")
    assert a is b
    assert len(pg._SHARED_TOKEN_RELATIONS) == 1


def test_shared_token_relation_differs_per_token():
    a = pg.shared_token_relation("core-1")
    b = pg.shared_token_relation("core-2")
    assert a is not b and a != b
    assert a.evidence_ref != b.evidence_ref and a.ref != b.ref


def test_interned_relation_equals_a_freshly_built_one():
    """The cached instance must be indistinguishable from a new one."""
    import dataclasses
    cached = pg.shared_token_relation("tok")
    pg._SHARED_TOKEN_RELATIONS.clear()
    fresh = pg.shared_token_relation("tok")
    assert cached == fresh
    assert dataclasses.asdict(cached) == dataclasses.asdict(fresh)


def test_seam_relation_structural_flag_is_part_of_identity():
    """Rank 2 vs rank 7 — sharing across this flag would be a verdict change."""
    strong = pg.seam_relation("seam-a", True)
    candidate = pg.seam_relation("seam-a", False)
    assert strong is not candidate
    assert strong.confidence != candidate.confidence
    assert strong.method != candidate.method


def test_seam_relation_differs_per_seam_id():
    assert pg.seam_relation("s1", True) is not pg.seam_relation("s2", True)


# --- groundings ------------------------------------------------------------

def test_shared_token_grounding_is_shared_and_carries_its_relation():
    g1 = engine._shared_token_grounding("tok")
    g2 = engine._shared_token_grounding("tok")
    assert g1 is g2
    assert g1.kind == "topo" and g1.ref == "shared:tok"
    assert g1.relation is pg.shared_token_relation("tok")


def test_shared_token_grounding_differs_per_token():
    a = engine._shared_token_grounding("t1")
    b = engine._shared_token_grounding("t2")
    assert a is not b and a.ref != b.ref


def test_seam_token_grounding_is_shared_and_candidate_ranked():
    g = engine._seam_token_grounding("seam-x")
    assert engine._seam_token_grounding("seam-x") is g
    assert g.kind == "seam" and g.ref == "seam-x"
    assert g.authoritative is False, "a token-matched seam must stay CANDIDATE"
    assert g.rank == 7


def test_interned_grounding_keeps_its_derived_properties():
    """rank/authoritative/data_class are read off the shared object."""
    g = engine._shared_token_grounding("tok")
    assert g.rank == 7
    assert g.authoritative is False
    assert isinstance(g.data_class, str)


# --- bounded ---------------------------------------------------------------

def test_relation_cache_is_bounded_and_counts_evictions(monkeypatch):
    monkeypatch.setattr(pg, "RELATION_CACHE_MAX", 10)
    before = pg.RELATION_CACHE_EVICTED
    for i in range(200):
        pg.shared_token_relation(f"tok{i}")
    assert len(pg._SHARED_TOKEN_RELATIONS) <= 11
    assert pg.RELATION_CACHE_EVICTED > before


def test_grounding_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(engine, "GROUNDING_CACHE_MAX", 10)
    for i in range(200):
        engine._shared_token_grounding(f"tok{i}")
    assert len(engine._SHARED_TOKEN_GROUNDINGS) <= 11


def test_eviction_still_returns_a_correct_object(monkeypatch):
    """Overflow degrades to 'build a fresh one', never to a wrong one."""
    monkeypatch.setattr(pg, "RELATION_CACHE_MAX", 2)
    monkeypatch.setattr(engine, "GROUNDING_CACHE_MAX", 2)
    for i in range(50):
        tok = f"tok{i}"
        g = engine._shared_token_grounding(tok)
        assert g.ref == f"shared:{tok}"
        assert g.relation.evidence_ref == f"token:{tok}"


def test_a_hostile_token_stream_cannot_grow_the_caches_without_bound(monkeypatch):
    """Tokens come from device-supplied names."""
    monkeypatch.setattr(pg, "RELATION_CACHE_MAX", 100)
    monkeypatch.setattr(engine, "GROUNDING_CACHE_MAX", 100)
    for i in range(20000):
        engine._shared_token_grounding(f"attacker-{i}")
    assert len(engine._SHARED_TOKEN_GROUNDINGS) <= 101
    assert len(pg._SHARED_TOKEN_RELATIONS) <= 101
