"""Tracker 165 phases 6-8 — shared identity strings must change nothing but memory.

`buffer_signal` now replaces `entity_id` and `entity_tokens` with canonical
shared instances. That is only acceptable if it is invisible everywhere else:
identical ids, identical ClickHouse rows, identical archive rows, identical
edges, identical RCA. These tests compare a shared window against an unshared
one field by field and byte by byte.

`attrs` is deliberately NOT shared, and one test pins the reason so a future
change cannot quietly start sharing a mutable dict.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import main
import signals as S
from catalog import builtin_catalog
from engine import EngineConfig, SeamView, build_edges, build_nodes, run_window

TENANT = "acme"
CFG = EngineConfig()
CAT = builtin_catalog()
T0 = datetime.now(timezone.utc) - timedelta(seconds=300)
SEAMS = (SeamView(seam_id="dallas-dx-equinix", tenant_id=TENANT, seam_type="DX",
                  endpoints=(("on_prem", "dallas-edge"),
                             ("provider_edge", "equinix-pop"))),)


@pytest.fixture(autouse=True)
def _clean():
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main.TENANT_WATERMARK.clear()
    S._ENTITY_ID_CACHE.clear(); S._ENTITY_TOKENS_CACHE.clear()
    yield
    S._ENTITY_ID_CACHE.clear(); S._ENTITY_TOKENS_CACHE.clear()


def _sig(kind, etype, eid, off, *, modality, source, sev=S.Severity.HIGH,
         obs="dallas-edge", tokens=("dallas-edge",)):
    return S.Signal(
        tenant_id=TENANT, ts=T0 + timedelta(seconds=off), source=source, kind=kind,
        observer=S.observer_of(obs, S.ObserverType.DEVICE,
                               collection_path="direct", clock_quality="unknown"),
        modality_class=modality, entity_type=etype, entity_id=eid, severity=sev,
        native_id=f"{kind}|{eid}|{off}", entity_tokens=tokens,
        attrs={"onset_uncertainty_s": 5.0})


STORY = (
    _sig("bgp_session_down", S.EntityType.DEVICE, "dallas-edge", 0,
         modality=S.ModalityClass.CONTROL_PLANE, source=S.Source.SYSLOG),
    _sig("link_state_change", S.EntityType.INTERFACE, "dallas-edge:Gi0/1", 90,
         modality=S.ModalityClass.CONTROL_PLANE, source=S.Source.SYSLOG),
    _sig("if_util_high", S.EntityType.INTERFACE, "dallas-edge:Gi0/1", 180,
         modality=S.ModalityClass.DEVICE_TELEMETRY, source=S.Source.METRIC),
    _sig("probe_loss", S.EntityType.DEVICE, "dallas-edge", 260,
         modality=S.ModalityClass.ACTIVE_PROBE, source=S.Source.PROBE),
)


def _buffer(share: bool):
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main.TENANT_WATERMARK.clear()
    S._ENTITY_ID_CACHE.clear(); S._ENTITY_TOKENS_CACHE.clear()
    if share:
        for s in STORY:
            main.buffer_signal(s)
    else:
        orig_id, orig_tok = S.shared_entity_id, S.shared_entity_tokens
        S.shared_entity_id = lambda x: x
        S.shared_entity_tokens = lambda x: x
        try:
            for s in STORY:
                main.buffer_signal(s)
        finally:
            S.shared_entity_id, S.shared_entity_tokens = orig_id, orig_tok
    return tuple(main.WINDOW_BUFFER)


# ── identity and persistence are byte-identical ──────────────────────────────

def test_signal_ids_are_unchanged():
    plain, shared = _buffer(False), _buffer(True)
    assert [str(s.signal_id) for s in plain] == [str(s.signal_id) for s in shared]


def test_native_ids_are_unchanged():
    plain, shared = _buffer(False), _buffer(True)
    assert [s.native_id for s in plain] == [s.native_id for s in shared]


def test_to_ch_row_is_byte_identical():
    import json
    plain, shared = _buffer(False), _buffer(True)
    a = [json.dumps(s.to_ch_row(), sort_keys=True, default=str) for s in plain]
    b = [json.dumps(s.to_ch_row(), sort_keys=True, default=str) for s in shared]
    assert a == b


def test_archive_row_is_byte_identical():
    import json
    plain, shared = _buffer(False), _buffer(True)
    main._CYCLE_ROW_CACHE.clear()
    a = [json.dumps(main._archive_row(s, "cid-1", 1), sort_keys=True, default=str)
         for s in plain]
    main._CYCLE_ROW_CACHE.clear()
    b = [json.dumps(main._archive_row(s, "cid-1", 1), sort_keys=True, default=str)
         for s in shared]
    assert a == b


def test_field_values_are_equal_even_where_identity_differs():
    plain, shared = _buffer(False), _buffer(True)
    for p, s in zip(plain, shared):
        assert p.entity_id == s.entity_id
        assert p.entity_tokens == s.entity_tokens
        assert p.attrs == s.attrs
        assert p.observer == s.observer


# ── the engine sees no difference ────────────────────────────────────────────

def test_nodes_and_edges_are_identical():
    plain, shared = _buffer(False), _buffer(True)
    np_, ns = build_nodes(plain), build_nodes(shared)
    assert [n.key for n in np_] == [n.key for n in ns]
    ep, _ = build_edges(np_, SEAMS, CFG)
    es, _ = build_edges(ns, SEAMS, CFG)
    assert len(ep) == len(es)
    assert [(e.from_node, e.to_node, round(e.weight, 12)) for e in ep] == \
           [(e.from_node, e.to_node, round(e.weight, 12)) for e in es]


def test_grounding_and_seam_bridging_are_identical():
    plain, shared = _buffer(False), _buffer(True)
    ep, gp = build_edges(build_nodes(plain), SEAMS, CFG)
    es, gs = build_edges(build_nodes(shared), SEAMS, CFG)
    assert gp == gs, "gap hints differ — grounding changed"
    assert [(e.grounding.kind, e.grounding.ref) for e in ep] == \
           [(e.grounding.kind, e.grounding.ref) for e in es]


def test_full_rca_output_is_identical():
    plain, shared = _buffer(False), _buffer(True)
    rp = run_window(plain, CAT, SEAMS)
    rs = run_window(shared, CAT, SEAMS)
    assert len(rp) == len(rs) == 1
    a, b = rp[0], rs[0]
    assert a.ranking.top_hypothesis == b.ranking.top_hypothesis
    assert a.ranking.verdict_tier == b.ranking.verdict_tier
    assert a.ranking.evidence_missing == b.ranking.evidence_missing
    assert sorted(n.key for n in a.nodes) == sorted(n.key for n in b.nodes)
    assert len(a.edges) == len(b.edges)
    assert a.content_hash() == b.content_hash(), (
        "the replay content hash changed — sharing is NOT semantically neutral")


def test_content_hash_is_the_strongest_check():
    """The replay contract is a hash over the whole object; if sharing altered
    anything the engine reads, this is where it shows."""
    plain, shared = _buffer(False), _buffer(True)
    assert run_window(plain, CAT, SEAMS)[0].content_hash() == \
           run_window(shared, CAT, SEAMS)[0].content_hash()


# ── sharing actually happened (or the tests above prove nothing) ─────────────

def test_the_strings_really_are_shared():
    """Negative control for the whole file: if sharing silently stopped working
    every equivalence test above would still pass."""
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main.TENANT_WATERMARK.clear()
    S._ENTITY_ID_CACHE.clear(); S._ENTITY_TOKENS_CACHE.clear()
    for i in range(20):
        # Build DISTINCT-but-equal strings. Passing the same literal would make
        # every signal share identity through CPython's constant pool, and the
        # assertions below would pass with the cache switched off entirely —
        # which is exactly what a mutation run caught.
        # ruff FLY002 suggests literals here; do NOT take that advice — a
        # literal is precisely what makes this test vacuous.
        eid = "".join(["leaf", "9", ":", "Gi0/", "2"])          # noqa: FLY002
        tok = ("".join(["leaf", "9"]), "".join(["Gi0/", "2"]))  # noqa: FLY002
        assert eid == "leaf9:Gi0/2"
        main.buffer_signal(_sig(
            "link_state_change", S.EntityType.INTERFACE, eid, i,
            modality=S.ModalityClass.CONTROL_PLANE, source=S.Source.SYSLOG,
            tokens=tok))
    held = list(main.WINDOW_BUFFER)
    assert len(held) == 20
    first = held[0]
    assert all(s.entity_id is first.entity_id for s in held), "entity_id not shared"
    assert all(s.entity_tokens is first.entity_tokens for s in held), "tokens not shared"


def test_attrs_are_NOT_shared():
    """Pinned refusal. `attrs` is a mutable dict and main.py stamps into it on
    the probe path after construction, so sharing it would let one signal's
    enrichment rewrite another's evidence. If someone starts sharing it, this
    goes red and they have to make it immutable first."""
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main.TENANT_WATERMARK.clear()
    for i in range(5):
        main.buffer_signal(_sig(
            "link_state_change", S.EntityType.INTERFACE, "leaf3:Gi0/1", i,
            modality=S.ModalityClass.CONTROL_PLANE, source=S.Source.SYSLOG))
    held = list(main.WINDOW_BUFFER)
    ids = {id(s.attrs) for s in held}
    assert len(ids) == len(held), (
        "attrs dicts are being shared between signals — a mutation on one would "
        "corrupt the others (see main.py probe path)")
    held[0].attrs["probe_intent"] = "x"
    assert "probe_intent" not in held[1].attrs


# ── the cache is bounded (phase 7) ───────────────────────────────────────────

def test_cache_is_bounded_and_evicts(monkeypatch):
    monkeypatch.setattr(S, "ENTITY_CACHE_MAX", 50)
    before = S.ENTITY_CACHE_EVICTED
    for i in range(500):
        S.shared_entity_id(f"dev{i}:Gi0/{i}")
    assert len(S._ENTITY_ID_CACHE) <= 50
    assert S.ENTITY_CACHE_EVICTED > before


def test_eviction_is_value_safe_never_identity_critical(monkeypatch):
    """A miss must yield an EQUAL string, never a different one — the cache is
    an allocation optimisation, never a correctness input."""
    monkeypatch.setattr(S, "ENTITY_CACHE_MAX", 2)
    a = S.shared_entity_id("leaf1:Gi0/1")
    for i in range(10):
        S.shared_entity_id(f"filler{i}")
    b = S.shared_entity_id("leaf1:Gi0/1")   # evicted by now
    assert a == b, "eviction changed a value"


def test_cache_population_is_observable():
    S._ENTITY_ID_CACHE.clear()
    S.shared_entity_id("leaf1:Gi0/1")
    S.shared_entity_tokens(("leaf1", "Gi0/1"))
    st = S.entity_cache_stats()
    assert st["entity_ids"] >= 1 and st["entity_token_tuples"] >= 1
    assert st["max"] == S.ENTITY_CACHE_MAX
    assert "evicted" in st


def test_cardinality_is_naturally_bounded_by_the_estate():
    """The bound is not arbitrary: distinct entity_ids are devices x interfaces,
    not 'every unique value forever'. 1000 devices of 48 ports is ~48k, inside
    the default ceiling."""
    S._ENTITY_ID_CACHE.clear()
    for d in range(200):
        for p in range(48):
            S.shared_entity_id(f"leaf{d}:Gi0/{p}")
    assert len(S._ENTITY_ID_CACHE) == 200 * 48
    assert len(S._ENTITY_ID_CACHE) < S.ENTITY_CACHE_MAX
