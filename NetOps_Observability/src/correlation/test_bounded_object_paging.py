"""P0 boundedness pass — paged child-row emission (ENGINE_DECISION_2026-08-28 #1/#2).

The residual hot-shard stall was serializing a whole storm object's child rows
(typed/untyped edges + evidence — up to ~180k) as ONE list and issuing ONE
insert, a single synchronous work unit whose C serialize tracked the object's
edge count. Those rows now emit in BOUNDED PAGES (engine.ObjectSnapshot.*_page +
main._emit_child_rows). These tests pin the two properties that make that safe:

  * DETERMINISM / no data loss — concatenating every page reproduces the old
    monolithic to_edge_rows / to_typed_edge_rows / to_evidence_rows BYTE-FOR-BYTE
    (same order, same dicts), and content_hash (the replay pin) is UNCHANGED.
  * BOUNDED + still-batching — the persist path lands child rows in multiple
    inserts (not one giant blob) yet each insert is a healthy multi-row batch
    (not tiny per-row writes), every batch carries a DISTINCT dedup token, and
    every child row is tenant-scoped exactly like the parent (§3a).
"""

from __future__ import annotations

import asyncio
import dataclasses
import math
import uuid
from datetime import datetime, timedelta, timezone

import pytest

import main
from catalog import builtin_catalog
from engine import Edge, EngineConfig, Grounding, run_window
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 6, 12, 9, 42, 0, tzinfo=timezone.utc)

# content_hash of _fixture_snapshot(). content_hash is the replay/damping pin —
# the paging change touches only ROW EMISSION and is forbidden from moving this
# value. A drift here means the canonical hash path regressed (replay would
# drift + every open object would re-version on deploy).
#
# RE-FROZEN ONCE, 2026-08-31, tracker 157 (was "19b20bafb5eff558", frozen from
# the pre-P0 tree). The structural grounding gate changed this object's RANKING,
# deliberately and for the better: its evidence is a CPU alarm and interface
# errors on ONE device, dallas-edge, and the pre-157 engine returned
# `sig.ent.fabric.spine-leaf-path-degradation` at 0.5 as the top hypothesis — a
# leaf/spine fabric verdict over a single box, which is the exact defect 157
# exists to kill. It is now `undetermined` with a per-clause checklist. The hash
# moved because the VERDICT moved; the hash PATH is untouched, and re-freezing
# here is the record of that, not a licence to re-freeze again.
#
# RE-FROZEN AGAIN, 2026-09-02, T2b (was "9faa2431af85b896"). content_hash pins
# `catalog_version` (it is part of the hypotheses blob), and the catalog gained
# the three Exposure Story templates — so the pin MUST move whenever the rule
# base does, by design. This object's DECISION is unchanged and that was checked
# rather than assumed: rebuilt against the pre-T2b template list, its hypotheses
# blob is byte-identical modulo the `catalog_version` string, and the verdict is
# still `undetermined`. The same property is asserted for whole objects in
# test_security_grounding_t2b.py
# ::test_v1_stream_is_byte_identical_with_and_without_the_templates.
#
# RE-FROZEN AGAIN, 2026-09-02, A9b (was "4bbdad70a36d0cee"). Same mechanism as
# the T2b re-freeze directly above, and for the same reason: `content_hash` pins
# `catalog_version`, and five templates gained ONE OPTIONAL clause each
# (`device_config_change` — the "what changed?" evidence). An optional clause
# that matches nothing contributes no coverage and no bonus (scoring.py:
# `coverage` divides by the REQUIRED clauses only), so this object's DECISION
# cannot move — and that was CHECKED, not assumed: rebuilt against the pre-A9b
# template list, its whole object row is byte-identical except the
# `catalog_version` stamp, and the verdict is still `undetermined` with the same
# top hypothesis. The proof is
# test_config_change_symptom.py::test_v1_stream_is_byte_identical_with_and_without_the_optional_clause.
FIXTURE_GOLDEN = "e8223a77e621d10e"


def _sig(kind, et, eid, *, off=0.0, src=Source.METRIC, sev=Severity.HIGH,
         tokens=()):
    return Signal(
        tenant_id="t1", ts=T0 + timedelta(seconds=off), source=src, kind=kind,
        observer=Observer(observer_id="obs1", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=et,
        entity_id=eid, severity=sev, native_id=f"fx|{kind}|{eid}|{off}",
        entity_tokens=tokens, attrs={"onset_uncertainty_s": 5.0})


def _fixture_snapshot():
    """A small, real, deterministic object with an edge AND a matched
    app-identity (so the evidence stream exercises BOTH sections — per-edge rows
    then per-identity rows)."""
    window = (
        _sig("device_cpu_high", EntityType.DEVICE, "dallas-edge"),
        _sig("if_errors", EntityType.INTERFACE, "dallas-edge:Gi0/1", off=20),
        _sig("app_identity", EntityType.APP, "TeamsApp", off=15,
             src=Source.APP_IDENTITY, sev=Severity.INFO, tokens=("dallas-edge",)),
    )
    snaps = run_window(window, builtin_catalog(), (), EngineConfig())
    return next(s for s in snaps
                if "dallas-edge" in s.affected().get("devices", []))


def _synthetic_edges(n: int) -> tuple[Edge, ...]:
    """n deterministic candidate edges (rank-7, grounding_ref non-empty so the
    corr_edges CHECK is satisfied) — the storm shape the paging bounds."""
    return tuple(
        Edge(from_node=f"device:d{i}:m", to_node=f"device:d{i + 1}:m",
             grounding=Grounding("topo", f"shared:tok{i % 37}", None),
             weight=0.5, w_temporal=0.4, w_topo=0.3, w_reinforce=0.2,
             direction_conf=0.0, direction_basis="none")
        for i in range(n))


def _scaled(snap, n_edges: int):
    """The fixture object re-shaped to n edges — keeps its matched identity so
    the evidence stream still has both sections."""
    return dataclasses.replace(snap, edges=_synthetic_edges(n_edges))


def _reassemble(page_fn, total: int, page_size: int) -> list[dict]:
    out: list[dict] = []
    start = 0
    while start < total:
        stop = min(start + page_size, total)
        out.extend(page_fn(7, start, stop))
        start = stop
    return out


class _FakeCH:
    """Records every insert (table, rows, dedup_token) in call order — no
    insert_detailed, so ch_insert takes the bool-outcome path."""

    def __init__(self):
        self.calls: list[tuple[str, str, list[dict]]] = []

    async def insert(self, table, rows, dedup_token=""):
        rows = list(rows)
        self.calls.append((table, dedup_token, rows))
        return True

    def rows_for(self, table: str) -> list[dict]:
        out: list[dict] = []
        for t, _tok, rows in self.calls:
            if t == table:
                out.extend(rows)
        return out

    def inserts_for(self, table: str) -> list[list[dict]]:
        return [rows for t, _tok, rows in self.calls if t == table]

    def tokens_for(self, table: str) -> list[str]:
        return [tok for t, tok, _rows in self.calls if t == table]


@pytest.fixture(autouse=True)
def _clean_archive_hash():
    main._ARCHIVE_SLICE_HASH.clear()
    yield
    main._ARCHIVE_SLICE_HASH.clear()


def _run(coro):
    return asyncio.run(coro)


# ── determinism / replay pin ────────────────────────────────────────────────

def test_content_hash_is_byte_identical_to_the_frozen_golden():
    snap = _fixture_snapshot()
    assert snap.content_hash() == FIXTURE_GOLDEN
    # stable across calls (pure) and independent of the paging methods existing
    assert snap.content_hash() == snap.content_hash()


def test_edge_and_evidence_counts_are_consistent():
    snap = _scaled(_fixture_snapshot(), 250)
    assert len(snap.edges) == 250
    assert snap.evidence_row_count() == len(snap.to_evidence_rows(7))
    assert snap.evidence_row_count() == 250 + len(snap.identity_signals)


@pytest.mark.parametrize("page_size", [1, 7, 64, 1000, 999999])
def test_pages_reassemble_to_the_monolithic_rows_byte_for_byte(page_size):
    snap = _scaled(_fixture_snapshot(), 500)
    v = 7
    assert _reassemble(snap.edge_row_page, len(snap.edges), page_size) \
        == snap.to_edge_rows(v)
    assert _reassemble(snap.typed_edge_row_page, len(snap.edges), page_size) \
        == snap.to_typed_edge_rows(v)
    assert _reassemble(snap.evidence_row_page, snap.evidence_row_count(), page_size) \
        == snap.to_evidence_rows(v)


# ── persist path: bounded, batching, idempotent, tenant-scoped ───────────────

def _persist(snap, ch, monkeypatch, *, page=1000, batch=2000, v2=True,
             offload_min=2000):
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_ROW_PAGE_SIZE", page)
    monkeypatch.setattr(main, "CORR_ROW_BATCH_ROWS", batch)
    monkeypatch.setattr(main, "CORR_EDGES_V2", v2)
    monkeypatch.setattr(main, "CORR_OFFLOAD_MIN_ELEMENTS", offload_min)
    _run(main._persist_snapshot(snap, 3, "open", []))


def test_persisted_child_rows_reassemble_to_the_monolithic_rows(monkeypatch):
    snap = _scaled(_fixture_snapshot(), 2500)
    ch = _FakeCH()
    _persist(snap, ch, monkeypatch, page=1000, batch=2000, v2=True)
    assert ch.rows_for("netops.corr_edges") == snap.to_edge_rows(3)
    assert ch.rows_for(main.CORR_PATH_EDGES_TABLE) == snap.to_typed_edge_rows(3)
    assert ch.rows_for("netops.corr_evidence") == snap.to_evidence_rows(3)
    # exactly one parent row
    assert len(ch.inserts_for("netops.corr_objects")) == 1
    assert len(ch.rows_for("netops.corr_objects")) == 1


def test_child_rows_land_in_healthy_batches_not_per_row(monkeypatch):
    snap = _scaled(_fixture_snapshot(), 2500)
    ch = _FakeCH()
    _persist(snap, ch, monkeypatch, page=1000, batch=2000, v2=False)
    edge_inserts = ch.inserts_for("netops.corr_edges")
    # 2500 rows, batch floor 2000 → [2000, 500], NOT 2500 tiny writes
    assert [len(b) for b in edge_inserts] == [2000, 500]
    assert len(edge_inserts) == math.ceil(2500 / 2000)


def test_each_child_batch_has_a_distinct_dedup_token(monkeypatch):
    snap = _scaled(_fixture_snapshot(), 2500)
    ch = _FakeCH()
    _persist(snap, ch, monkeypatch, page=1000, batch=2000, v2=False)
    tokens = ch.tokens_for("netops.corr_edges")
    assert len(tokens) == 2
    assert len(set(tokens)) == len(tokens)          # distinct → CH won't collapse
    assert all(t.endswith(f":edges:{i}") for i, t in enumerate(tokens))


def test_child_rows_are_tenant_scoped_exactly_like_the_parent(monkeypatch):
    snap = _scaled(_fixture_snapshot(), 800)
    ch = _FakeCH()
    _persist(snap, ch, monkeypatch, page=100, batch=250, v2=True)
    for table in ("netops.corr_edges", main.CORR_PATH_EDGES_TABLE,
                  "netops.corr_evidence", "netops.corr_objects"):
        scopes = {r["tenant_id"] for r in ch.rows_for(table)}
        assert scopes == {snap.tenant_id}, table
    assert snap.tenant_id == "t1"


def test_offloaded_big_object_path_reassembles_identically(monkeypatch):
    # offload_min=0 forces the big/offloaded page-build branch in _emit_child_rows
    snap = _scaled(_fixture_snapshot(), 1500)
    ch = _FakeCH()
    _persist(snap, ch, monkeypatch, page=256, batch=512, v2=True, offload_min=0)
    assert ch.rows_for("netops.corr_edges") == snap.to_edge_rows(3)
    assert ch.rows_for(main.CORR_PATH_EDGES_TABLE) == snap.to_typed_edge_rows(3)
    assert ch.rows_for("netops.corr_evidence") == snap.to_evidence_rows(3)


def test_empty_object_emits_no_child_rows(monkeypatch):
    snap = _scaled(_fixture_snapshot(), 0)
    # no edges, still one identity → evidence has the identity rows only
    ch = _FakeCH()
    _persist(snap, ch, monkeypatch, page=100, batch=250, v2=True)
    assert ch.inserts_for("netops.corr_edges") == []
    assert ch.inserts_for(main.CORR_PATH_EDGES_TABLE) == []
    assert ch.rows_for("netops.corr_evidence") == snap.to_evidence_rows(3)


# ── edge-evidence provenance (QA D-01) ──────────────────────────────────────
#
# `_edge_evidence_row` hardcoded `signal_id` to the nil UUID, so every
# `corr_evidence` -> `corr_signals` join returned nothing and the security
# Exposure Story LIST could never return a row. The row now carries a REAL,
# deterministic representative signal id from one of the edge's endpoint nodes.
# These live here because this file owns the evidence-row emission contract:
# the id must be real AND the byte-for-byte paging identity above must survive.

NIL_UUID = str(uuid.UUID(int=0))


def _edge_rows(snap, version=7):
    return [r for r in snap.to_evidence_rows(version) if r["subject_kind"] == "edge"]


def test_edge_evidence_carries_a_real_endpoint_signal_id():
    snap = _fixture_snapshot()
    by_key = {n.key: n for n in snap.nodes}
    rows = _edge_rows(snap)
    assert rows, "the fixture object must have at least one edge"
    for e, row in zip(snap.edges, rows):
        assert row["signal_id"] != NIL_UUID
        # it belongs to ONE of this edge's endpoint nodes — never a stranger
        owned = {str(s.signal_id)
                 for k in (e.from_node, e.to_node)
                 for s in (by_key[k].signals if k in by_key else ())}
        assert row["signal_id"] in owned
        # and specifically the earliest signal of from_node (the stated rule)
        assert row["signal_id"] == str(by_key[e.from_node].signals[0].signal_id)


def test_edge_evidence_signal_id_is_deterministic_across_builds():
    a, b = _fixture_snapshot(), _fixture_snapshot()
    assert a.content_hash() == b.content_hash()          # same object, twice
    assert a.to_evidence_rows(7) == b.to_evidence_rows(7)
    ids = [r["signal_id"] for r in _edge_rows(a)]
    assert ids == [r["signal_id"] for r in _edge_rows(b)]
    assert NIL_UUID not in ids
    # stable across repeated calls on ONE snapshot too (the node_index cache
    # must not make the second call differ from the first)
    assert a.to_evidence_rows(7) == a.to_evidence_rows(7)


def test_node_index_is_cached_and_never_a_dataclass_field():
    snap = _fixture_snapshot()
    first = snap.node_index()
    assert snap.node_index() is first                    # cached on the instance
    assert first == {n.key: n for n in snap.nodes}
    # NOT a field: it must not enter __eq__/__hash__/replace(), and a copy
    # rebuilds rather than inheriting a stale index.
    assert "_node_index_c" not in {f.name for f in dataclasses.fields(snap)}
    copy = dataclasses.replace(snap, edges=snap.edges)
    assert copy.node_index() is not first
    assert copy.node_index() == first


def test_an_unresolvable_endpoint_falls_back_instead_of_raising():
    """A synthetic/carried edge whose endpoint node aged out of the window must
    still persist — it degrades to the nil UUID, it does not crash."""
    snap = _scaled(_fixture_snapshot(), 3)               # nodes d0..d3 do not exist
    rows = _edge_rows(snap)
    assert len(rows) == 3
    assert {r["signal_id"] for r in rows} == {NIL_UUID}
    # the identity rows on the same object still carry their real ids
    ident = [r for r in snap.to_evidence_rows(7) if r["subject_kind"] == "app"]
    assert ident and all(r["signal_id"] != NIL_UUID for r in ident)
    # a node present but holding no signals also falls back, never raises
    empty = dataclasses.replace(
        snap,
        nodes=tuple(dataclasses.replace(n, signals=()) for n in snap.nodes),
        edges=snap.edges[:1] + (Edge(
            from_node=snap.nodes[0].key, to_node=snap.nodes[1].key,
            grounding=Grounding("topo", "shared:tok", None),
            weight=0.5, w_temporal=0.4, w_topo=0.3, w_reinforce=0.2,
            direction_conf=0.0, direction_basis="none"),))
    assert _edge_rows(empty)[-1]["signal_id"] == NIL_UUID


@pytest.mark.parametrize("page_size", [1, 2, 5, 999999])
def test_paging_identity_holds_for_real_signal_ids(page_size):
    """The byte-for-byte paging contract on an object whose edge rows carry
    REAL ids (the scaled fixture above only exercises the fallback)."""
    snap = _fixture_snapshot()
    assert _reassemble(snap.evidence_row_page, snap.evidence_row_count(),
                       page_size) == snap.to_evidence_rows(7)
    assert NIL_UUID not in {r["signal_id"] for r in _edge_rows(snap)}
