# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The scorer's ClickHouse SQL SHAPE contract, its batching, and the
mini-ladder emission-journal mode.

Regression for the 2026-08-29 storm incident: scoring a 345-story mini-ladder
run against a 2 M-row / 46 GiB corr_objects issued 329 SELECTs worth 3,639 s
of ClickHouse time (worst 82 s, two refused at the memory cap) and was killed
before it wrote a report — because every read folded the WHOLE table:

  * `WHERE toString(correlation_id) IN (...)` casts the key, so the
    `(tenant_id, correlation_id, version)` primary key cannot be used;
  * no tenant bound and no time bound, so a question about 15 minutes was
    answered by scanning the entire retained history;
  * the wide `hypotheses` blob (48 GiB) was selected on EVERY object lookup,
    whether or not any clause needed it;
  * one query per story instead of one per batch.

These tests hold the repaired shape to that contract. They assert on the SQL
text on purpose: the cost of these queries is decided by their shape, and a
shape regression is invisible to a functional test that only checks verdicts.
"""
import json
import os

import pytest
import scorer
from test_scorer import (
    DX_GT,
    NEG_GT,
    OID,
    PREFIX,
    STATE,
    TENANTS,
    WINDOW,
    FakeStack,
    _obj,
    ctx_for,
)

CORR_TABLES = ("netops.corr_objects", "netops.corr_current",
               "netops.corr_edges", "netops.corr_signals")


def _story(i, devices, expect=None):
    return {
        "story_id": f"s{i:03d}",
        "template": "local_link_fault",
        "fired_at": "2026-08-17T00:00:00Z",
        "affected": {"devices": devices, "tenants": ["acme"]},
        "extra_entities": [],
        "expect": expect if expect is not None else {
            "rca": {"verdict_tier_at_least": "suspected",
                    "affected_includes": [devices[0]]}},
    }


def _fleet(n_stories, per_story=3, n_objects=6):
    """n stories over a shared device fleet, with a few objects that cover
    the first stories' devices."""
    stories = []
    for i in range(n_stories):
        devices = [f"dev-{i * per_story + k:04d}" for k in range(per_story)]
        stories.append(_story(i, devices))
    objects = []
    for j in range(min(n_objects, n_stories)):
        gt = stories[j]
        objects.append(_obj(
            f"{j:08d}-0000-4000-8000-000000000000", "suspected",
            "sig.ent.access.local-link-fault",
            [PREFIX + d for d in gt["affected"]["devices"]]))
    return stories, objects


# ── SQL shape contract ───────────────────────────────────────────────────────

def _corr_reads(stack):
    return [(q, s) for q, s in stack.queries
            if any(t in q for t in CORR_TABLES)]


def test_every_corr_read_is_window_and_tenant_bounded():
    stories, objects = _fleet(6)
    stack = FakeStack(objects=objects,
                      signals={PREFIX + "dev-0000": {"link_state": 1}})
    scorer.score_run(stack, stories + [DX_GT], STATE, {}, ctx=ctx_for(stack))
    reads = _corr_reads(stack)
    assert reads, "the scorer issued no ClickHouse read at all"
    for q, _ in reads:
        assert f"tenant_id = '{TENANTS[0]}'" in q or "(tenant_id, " in q, \
            f"read is not tenant-scoped (CLAUDE.md §3a): {q}"
        # Every read is bounded to the run window, OR keyed on the primary-key
        # prefix by ids that a window-bounded read already produced. A window
        # predicate on top of a full-key lookup buys nothing and could only
        # DROP a row whose window drifted, so the contract is "window or key".
        windowed = f"'{WINDOW.start}'" in q and f"'{WINDOW.end}'" in q
        keyed = "toUUID('" in q
        assert windowed or keyed, f"read is bounded to neither: {q}"
    scans = [q for q, _ in reads if "toUUID('" not in q]
    assert scans, "the membership scan must exist"
    for q in scans:
        assert f"'{WINDOW.start}'" in q and f"'{WINDOW.end}'" in q, \
            f"a SCAN must be bounded to the run window: {q}"


def test_every_corr_read_is_name_or_key_bounded_never_a_full_fold():
    """No read may select from corr_objects/corr_current with only a time
    predicate — the entity names or the object keys must narrow it too."""
    stories, objects = _fleet(4)
    stack = FakeStack(objects=objects)
    scorer.score_run(stack, stories + [DX_GT], STATE, {}, ctx=ctx_for(stack))
    for q, _ in _corr_reads(stack):
        bounded = ("multiSearchAny(" in q          # entity-name bound
                   or "toUUID('" in q)             # key bound
        assert bounded, f"unbounded fold over a corr table: {q}"
        assert "toString(correlation_id) IN" not in q, \
            "casting the key defeats the primary index (the storm defect)"
        assert "toString(correlation_id) =" not in q, \
            "casting the key defeats the primary index (the storm defect)"


def test_latest_version_comes_from_the_hot_projection_not_a_history_fold():
    stories, objects = _fleet(4)
    stack = FakeStack(objects=objects)
    scorer.score_run(stack, stories, STATE, {}, ctx=ctx_for(stack))
    latest = [q for q, _ in stack.queries if "netops.corr_current" in q]
    assert latest, "the latest version must be read from corr_current FINAL"
    for q in latest:
        assert "FINAL" in q
        assert "(tenant_id, correlation_id) IN (" in q, \
            "the keyed lookup must lead with tenant_id (primary-key prefix)"
    # ...and no LIMIT 1 BY fold of the history table unless the projection
    # actually had a gap (none here).
    assert not [q for q, _ in stack.queries
                if "netops.corr_objects" in q and "LIMIT 1 BY" in q]


def test_the_blob_column_is_never_read_unless_a_clause_needs_it():
    """`hypotheses` is 48 GiB uncompressed on the storm table. Only a
    `seam.owner` clause reads it, and only for that story's chosen object."""
    stories, objects = _fleet(4)
    stack = FakeStack(objects=objects)
    scorer.score_run(stack, stories, STATE, {}, ctx=ctx_for(stack))
    assert not [q for q, _ in stack.queries if "hypotheses" in q], \
        "no story asked for an owner, so nothing may read the blob column"

    stack = FakeStack(objects=[_obj("obj-1", "suspected",
                                    "sig.ent.middle-mile.interconnect-bgp",
                                    [PREFIX + "edge-a1"])],
                      edges={"obj-1": [PREFIX + "dal-dx-1"]})
    scorer.score_run(stack, [DX_GT], STATE, {}, ctx=ctx_for(stack))
    blob = [(q, s) for q, s in stack.queries if "hypotheses" in q]
    assert len(blob) == 1, "one keyed blob read for the one owner clause"
    q, settings = blob[0]
    assert "(tenant_id, correlation_id, version) IN (" in q
    assert settings["max_block_size"] == scorer.CH_BLOB_BLOCK_ROWS, \
        "the wide read must cap its block size (timeintel_backfill.go)"


def test_every_read_carries_the_containment_settings_on_the_wire():
    stories, objects = _fleet(3)
    stack = FakeStack(objects=objects,
                      signals={PREFIX + "dev-0000": {"link_state": 1}})
    scorer.score_run(stack, stories + [NEG_GT], STATE, {}, ctx=ctx_for(stack))
    reads = _corr_reads(stack)
    assert reads
    for q, settings in reads:
        assert settings["max_memory_usage"] == scorer.CH_MAX_MEMORY, q
        assert settings["max_execution_time"] == scorer.CH_MAX_EXECUTION_S, q
        assert settings["max_threads"] == scorer.CH_MAX_THREADS, q
        assert str(settings["log_comment"]).startswith("twin-scorer:"), q


def test_settings_reach_clickhouse_as_a_settings_clause():
    """The stack helper is what actually puts them on the wire."""
    import stack as stack_mod
    clause = stack_mod.format_ch_settings({
        "max_memory_usage": 1 << 30, "max_execution_time": 60,
        "max_threads": 2, "log_comment": "twin-scorer:membership"})
    assert clause == ("tenant_scope='__all__', log_comment="
                      "'twin-scorer:membership', max_execution_time=60, "
                      "max_memory_usage=1073741824, max_threads=2")
    with pytest.raises(ValueError):
        stack_mod.format_ch_settings({"max_threads; DROP TABLE x": 2})
    with pytest.raises(ValueError):
        stack_mod.format_ch_settings({"log_comment": "x'; DROP TABLE y; --"})


def test_signals_read_is_bounded_and_not_a_like_wildcard_per_entity():
    stories, _ = _fleet(3)
    stack = FakeStack(objects=[])           # every story misses -> trails
    scorer.score_run(stack, stories, STATE, {}, ctx=ctx_for(stack))
    sig = [q for q, _ in stack.queries if "corr_signals" in q]
    assert len(sig) == 1, "one batched trail read, not one per entity"
    assert "LIKE" not in sig[0], \
        "LIKE reads `_` as a wildcard and cost 906 queries on the storm run"
    assert "multiSearchAny(entity_id" in sig[0]
    assert f"ts BETWEEN '{WINDOW.start}'" in sig[0]


def test_seam_edges_read_is_keyed_and_batched():
    stack = FakeStack(objects=[_obj("obj-1", "suspected",
                                    "sig.ent.middle-mile.interconnect-bgp",
                                    [PREFIX + "edge-a1"])],
                      edges={"obj-1": [PREFIX + "dal-dx-1"]})
    scorer.score_run(stack, [DX_GT], STATE, {}, ctx=ctx_for(stack))
    edges = [q for q, _ in stack.queries if "corr_edges" in q]
    assert len(edges) == 1
    assert "correlation_id IN (toUUID(" in edges[0]
    assert "grounding_kind = 'seam'" in edges[0]


# ── batching ─────────────────────────────────────────────────────────────────

def test_n_stories_cost_at_most_ceil_n_over_batch_membership_queries():
    n, batch = 40, 8
    stories, objects = _fleet(n)
    stack = FakeStack(objects=objects)
    scorer.score_run(stack, stories, STATE, {},
                     ctx=ctx_for(stack, story_batch=batch))
    membership = [q for q, _ in stack.queries
                  if "multiSearchAny(affected" in q]
    assert len(membership) <= -(-n // batch), \
        f"{len(membership)} membership queries for {n} stories at batch {batch}"
    assert len(membership) >= 2, "the fixture must actually exercise batching"


def test_batched_results_equal_the_per_story_path():
    """The batched path and the one-story-at-a-time path must agree, clause
    for clause — batching is a cost change, never a semantic one."""
    n = 24
    stories, objects = _fleet(n, n_objects=10)
    stories += [DX_GT, NEG_GT]

    batched_stack = FakeStack(
        objects=objects + [_obj("obj-1", "suspected",
                                "sig.ent.middle-mile.interconnect-bgp",
                                [PREFIX + "edge-a1"])],
        edges={"obj-1": [PREFIX + "dal-dx-1"]},
        signals={PREFIX + "dev-0072": {"link_state": 3}})
    batched = scorer.score_run(batched_stack, stories, STATE, {},
                               ctx=ctx_for(batched_stack, story_batch=7))

    # per-story: a fresh context per story, nothing prefetched
    per_story = []
    solo_queries = 0
    for gt in stories:
        solo_stack = FakeStack(
            objects=objects + [_obj("obj-1", "suspected",
                                    "sig.ent.middle-mile.interconnect-bgp",
                                    [PREFIX + "edge-a1"])],
            edges={"obj-1": [PREFIX + "dal-dx-1"]},
            signals={PREFIX + "dev-0072": {"link_state": 3}})
        per_story.append(scorer.score_story(
            solo_stack, gt, PREFIX, STATE["device_tenants"], {},
            ctx=ctx_for(solo_stack)))
        solo_queries += len(solo_stack.queries)

    assert [json.dumps(r, sort_keys=True) for r in batched["stories"]] == \
        [json.dumps(r, sort_keys=True) for r in per_story]
    assert batched["read_bounds"]["clickhouse_queries"] < solo_queries, \
        "batching must cost strictly fewer queries than the per-story path"


def test_a_story_wider_than_the_needle_cap_is_split_not_dropped():
    """multiSearch* takes fewer than 2^8 needles; a 300-device blast radius
    must be SPLIT across queries, and still find its object."""
    devices = [f"acc-{i:04d}" for i in range(300)]
    gt = _story(1, devices)
    stack = FakeStack(objects=[
        _obj("giant", "suspected", "sig.ent.access.local-link-fault",
             [PREFIX + devices[-1]], nodes=900)])
    ctx = ctx_for(stack, max_needles=64)
    r = scorer.score_story(stack, gt, PREFIX, {}, {}, ctx=ctx)
    membership = [q for q, _ in stack.queries
                  if "multiSearchAny(affected" in q]
    assert len(membership) == 5, "300 needles at a cap of 64 -> 5 queries"
    for q in membership:
        # the needle list appears three times: arrayFilter, the positions
        # call it pairs with, and the multiSearchAny predicate
        assert q.count("'" + PREFIX) <= 64 * 3, "a query exceeded the cap"
    assert [o["id"] for o in r["objects"]] == [OID["giant"]]


def test_batching_never_leaks_another_storys_object():
    """Two stories in ONE membership query must still get only their own
    objects — the per-story assignment is done on the matched names."""
    a = _story(1, ["dev-a"])
    b = _story(2, ["dev-b"])
    stack = FakeStack(objects=[
        _obj("11111111-1111-4111-8111-111111111111", "suspected", "sig.a",
             [PREFIX + "dev-a"]),
        _obj("22222222-2222-4222-8222-222222222222", "suspected", "sig.b",
             [PREFIX + "dev-b"]),
    ])
    rep = scorer.score_run(stack, [a, b], STATE, {},
                           ctx=ctx_for(stack, story_batch=8))
    assert len([q for q, _ in stack.queries
                if "multiSearchAny(affected" in q]) == 1
    by = {r["story_id"]: [o["top_hypothesis"] for o in r["objects"]]
          for r in rep["stories"]}
    assert by["s001"] == ["sig.a"] and by["s002"] == ["sig.b"]


def test_membership_keeps_an_object_whose_blast_radius_later_shrank():
    """Membership is evaluated over EVERY version's `affected` (the shape the
    rewrite preserved): an object that named the device in v1 and dropped it
    by v7 is still a candidate, judged on its FINAL verdict."""
    oid = "44444444-4444-4444-8444-444444444444"

    class Shrinking(FakeStack):
        def ch_json(self, query, timeout=60, settings=None, strict=False):
            if "multiSearchAny(affected" in query:
                self.queries.append((query, dict(settings or {})))
                return [{"id": oid, "hits": [PREFIX + "dev-gone"]}]
            return super().ch_json(query, timeout, settings, strict)

    stack = Shrinking(objects=[
        _obj(oid, "suspected", "sig.late", [PREFIX + "dev-still-here"])])
    r = scorer.score_story(stack, _story(1, ["dev-gone"]), PREFIX, {}, {},
                           ctx=ctx_for(stack))
    assert [o["id"] for o in r["objects"]] == [oid]


# ── loud failures ────────────────────────────────────────────────────────────

def test_a_refused_read_aborts_instead_of_scoring_every_story_a_miss():
    from stack import StackError

    class Refusing(FakeStack):
        def ch_json(self, query, timeout=60, settings=None, strict=False):
            raise StackError("Code: 241 MEMORY_LIMIT_EXCEEDED")

    stories, _ = _fleet(3)
    with pytest.raises(StackError):
        scorer.score_run(Refusing(), stories, STATE, {},
                         ctx=ctx_for(Refusing()))


def test_ch_json_strict_raises_where_the_lenient_form_returns_empty(
        monkeypatch):
    import stack as stack_mod
    st = stack_mod.Stack.__new__(stack_mod.Stack)
    monkeypatch.setattr(stack_mod.Stack, "ch",
                        lambda self, q, t=60, s=None: (False, "Code: 241"))
    assert stack_mod.Stack.ch_json(st, "SELECT 1") == []
    with pytest.raises(stack_mod.StackError):
        stack_mod.Stack.ch_json(st, "SELECT 1", strict=True)


def test_a_context_without_a_tenant_is_refused():
    with pytest.raises(scorer.ScorerError):
        scorer.ScoreContext(FakeStack(), WINDOW, [])


def test_score_story_without_a_context_is_refused():
    with pytest.raises(scorer.ScorerError):
        scorer.score_story(FakeStack(), DX_GT, PREFIX, {}, {})


def test_a_hot_projection_gap_falls_back_loudly_instead_of_losing_the_object():
    oid = "55555555-5555-4555-8555-555555555555"

    class Gapped(FakeStack):
        def ch_json(self, query, timeout=60, settings=None, strict=False):
            if "netops.corr_current" in query:
                self.queries.append((query, dict(settings or {})))
                return []            # the projection is missing this object
            return super().ch_json(query, timeout, settings, strict)

    stack = Gapped(objects=[
        _obj(oid, "suspected", "sig.ent.access.local-link-fault",
             [PREFIX + "dev-0000"])])
    ctx = ctx_for(stack)
    r = scorer.score_story(stack, _story(0, ["dev-0000"]), PREFIX, {}, {},
                           ctx=ctx)
    assert ctx.projection_gaps == 1
    fallback = [q for q, _ in stack.queries
                if "netops.corr_objects" in q and "LIMIT 1 BY" in q]
    assert len(fallback) == 1
    assert "(tenant_id, correlation_id) IN (" in fallback[0]
    assert [o["id"] for o in r["objects"]] == [oid]


# ── the run window ───────────────────────────────────────────────────────────

def test_window_from_ground_truth_fired_at():
    w = scorer.run_window(
        {"created": "2026-08-17T00:00:00Z"},
        [{"fired_at": "2026-08-17T00:10:00Z"},
         {"fired_at": "2026-08-17T00:20:00Z"}],
        slack_s=600, settle_s=1200)
    assert w.start == "2026-08-16 23:50:00"
    assert w.end == "2026-08-17 00:40:00"


def test_window_from_a_mini_ladder_report_json(tmp_path):
    (tmp_path / "report.json").write_text(json.dumps({
        "phases": [{"phase": "preflight", "at": "2026-08-29T16:33:43Z"},
                   {"phase": "cleanup", "at": "2026-08-29T17:59:10Z"}],
        "generated": "2026-08-29T17:59:10Z"}))
    w = scorer.run_window({"runid": "x", "prefix": ""},
                          [{"fired_at": None}], str(tmp_path),
                          slack_s=900, settle_s=3600)
    assert w.start == "2026-08-29 16:18:43"
    assert w.end == "2026-08-29 18:59:10"
    assert "report.json" in w.source


def test_window_falls_back_to_artifact_mtimes_loudly(tmp_path):
    (tmp_path / "ground_truth.jsonl").write_text("{}\n")
    w = scorer.run_window({"runid": "x"}, [{"fired_at": None}], str(tmp_path))
    assert "mtime" in w.source


def test_an_undatable_run_is_refused_rather_than_scanned_whole():
    with pytest.raises(scorer.ScorerError) as exc:
        scorer.run_window({"runid": "x"}, [{"fired_at": None}], None)
    assert "unbounded" in str(exc.value)


def test_tenants_are_discovered_from_the_window_when_state_has_none():
    class TenantStack(FakeStack):
        def ch_json(self, query, timeout=60, settings=None, strict=False):
            self.queries.append((query, dict(settings or {})))
            assert "corr_current" in query and WINDOW.start in query
            return [{"tenant_id": "global"}]

    stack = TenantStack()
    assert scorer.run_tenants(stack, {"runid": "x"}, WINDOW) == ["global"]
    assert scorer.run_tenants(stack, STATE, WINDOW) == ["t-acme"]


# ── mini-ladder emission-journal mode ────────────────────────────────────────

def test_missing_events_jsonl_is_a_documented_mode_not_a_warning(tmp_path,
                                                                 capsys):
    import twin
    journal, notes = twin.read_emission_journal(
        str(tmp_path), {"runid": "r", "source": "scale-miniladder"})
    assert journal == {}
    assert len(notes) == 1
    assert "scale-miniladder" in notes[0]
    assert "WITHOUT emission counts" in notes[0]
    cap = capsys.readouterr()
    assert "WARNING" not in cap.err, \
        "a mini-ladder run journals no emission — that is a mode, not a fault"
    assert "emission journal: absent" in cap.out


def test_a_present_but_unreadable_journal_is_still_loud(tmp_path, capsys):
    import twin
    path = tmp_path / "events.jsonl"
    path.write_text("this is not json\n")
    journal, notes = twin.read_emission_journal(
        str(tmp_path), {"runid": "r", "source": "twin"})
    assert journal == {}
    assert notes and "unreadable" in notes[0]
    assert "WARNING" in capsys.readouterr().err


def test_a_readable_journal_still_counts_lanes_per_story(tmp_path):
    import twin
    (tmp_path / "events.jsonl").write_text(
        json.dumps({"story_id": "s1", "lane": "syslog"}) + "\n"
        + json.dumps({"story_id": "s1", "lane": "syslog"}) + "\n"
        + json.dumps({"story_id": "s1", "lane": "cloud"}) + "\n"
        + json.dumps({"lane": "syslog"}) + "\n")
    journal, notes = twin.read_emission_journal(str(tmp_path), {"runid": "r"})
    assert journal == {"s1": {"syslog": 2, "cloud": 1}}
    assert notes == []


def test_the_mode_note_reaches_the_report_and_the_markdown():
    stories, objects = _fleet(2)
    stack = FakeStack(objects=objects)
    note = ("no events.jsonl (scale-miniladder run): evidence trails are "
            "scored WITHOUT emission counts")
    rep = scorer.score_run(stack, stories, STATE, {}, ctx=ctx_for(stack),
                           notes=[note])
    assert rep["notes"] == [note]
    assert note in scorer.render_md(rep)


def test_cmd_score_passes_the_run_dir_and_the_mode_note_through(tmp_path,
                                                                monkeypatch):
    """End to end on the exact mini-ladder run dir shape this defect was found
    on: state.json + ground_truth.jsonl + report.json, and NO events.jsonl."""
    import argparse

    import twin

    rd = tmp_path / "storm-s01-08291633"
    rd.mkdir()
    (rd / "state.json").write_text(json.dumps({
        "runid": "08291633gaaz", "prefix": "", "device_tenants": {},
        "scenario": "storm-2.5k", "source": "scale-miniladder"}))
    (rd / "ground_truth.jsonl").write_text(json.dumps(_story(0, ["dev-0000"]))
                                           + "\n")
    (rd / "report.json").write_text(json.dumps({
        "phases": [{"phase": "preflight", "at": "2026-08-29T16:33:43Z"},
                   {"phase": "cleanup", "at": "2026-08-29T17:59:10Z"}]}))
    os.symlink(str(rd), str(tmp_path / "x-08291633gaaz"))

    seen = {}

    def fake_score_run(stack, gt, state, journal, run_dir=None, ctx=None,
                       notes=None):
        seen["run_dir"] = run_dir
        seen["notes"] = list(notes or [])
        seen["journal"] = journal
        return {"runid": state["runid"], "stories_passed": 0,
                "stories_total": 1, "accuracy_slo": 0.0,
                "positive_pass_rate": 0.0, "specificity": 1.0,
                "detection_rate": 0.0, "per_template": {},
                "read_bounds": {"window": {"start": "a", "end": "b"},
                                "tenants": ["global"],
                                "clickhouse_queries": 3},
                "notes": list(notes or []), "stories": []}

    monkeypatch.setattr(twin.scorer_mod, "score_run", fake_score_run)
    monkeypatch.setattr(twin.Stack, "login", lambda self: None)
    args = argparse.Namespace(run_root=str(tmp_path), runid="08291633gaaz",
                              env_file="/nonexistent/.env",
                              base_url="http://localhost:8000",
                              project="netops")
    assert twin.cmd_score(args) == 0
    assert seen["run_dir"] == str(tmp_path / "x-08291633gaaz")
    assert seen["journal"] == {}
    assert len(seen["notes"]) == 1 and "scale-miniladder" in seen["notes"][0]
    assert (rd / "accuracy-report.json").exists()   # via the symlink
    assert (rd / "accuracy-report.md").exists()


def test_an_empty_window_is_refused_not_rendered_as_zero_accuracy():
    """"the engine found nothing" and "you looked in the wrong window" must
    never render as the same 0% report."""
    class Empty(FakeStack):
        def ch_json(self, query, timeout=60, settings=None, strict=False):
            self.queries.append((query, dict(settings or {})))
            return []

    with pytest.raises(scorer.ScorerError) as exc:
        scorer.run_tenants(Empty(), {"runid": "x"}, WINDOW)
    assert "REFUSING" in str(exc.value)


def test_the_reported_query_count_includes_the_tenant_discovery_read():
    """The report's query count must equal what ClickHouse actually saw."""
    class Counting(FakeStack):
        def ch_json(self, query, timeout=60, settings=None, strict=False):
            if "SELECT DISTINCT toString(tenant_id)" in query:
                self.queries.append((query, dict(settings or {})))
                return [{"tenant_id": TENANTS[0]}]
            return super().ch_json(query, timeout, settings, strict)

    stories, objects = _fleet(3)
    stack = Counting(objects=objects)
    state = {k: v for k, v in STATE.items() if k != "tenants"}
    rep = scorer.score_run(stack, stories, state, {},
                           run_dir=None)
    assert rep["read_bounds"]["clickhouse_queries"] == len(stack.queries)
