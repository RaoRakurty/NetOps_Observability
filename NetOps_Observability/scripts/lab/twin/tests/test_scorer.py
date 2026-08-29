"""Scorer logic on fixture data: hit / miss / wrong-verdict / false-positive
on a negative control — plus the aggregate SLO math and the evidence trail on
a miss (design §5/§8.4 scoring contract).

The FakeStack here answers the BOUNDED query shapes the 2026-08-29 storm
rewrite introduced (window + tenant + name bound, `corr_current` for the
latest version, keyed lookups on the primary-key prefix). The SHAPES are
asserted in test_scorer_bounds.py; this file is about the verdicts.
"""
import json
import re

import pytest
import scorer

PREFIX = "twx-r1-"

STATE = {
    "runid": "r1",
    "prefix": PREFIX,
    "created": "2026-08-17T00:00:00Z",
    "tenants": {"acme": {"tenant_id": "t-acme"}},
    "device_tenants": {"edge-a1": "acme", "rtr-c1": "coyote",
                       "rtr-c3": "coyote", "br-b2": "bluesky"},
}

WINDOW = scorer.Window("2026-08-16 00:00:00", "2026-08-18 00:00:00",
                       "test fixture")
TENANTS = ["t-acme"]

DX_GT = {
    "story_id": "dx-flap-1",
    "template": "dx_circuit_flap_cloud_withdrawal",
    "fired_at": "2026-08-17T00:00:00Z",
    "affected": {"seam": "dal-dx-1", "devices": ["edge-a1"],
                 "tenants": ["acme"]},
    "extra_entities": ["dxcon-twin0001/vif-100"],
    "expect": {
        "rca": {"verdict_tier_at_least": "suspected",
                "hypothesis_matches": "private-interconnect|interconnect-bgp",
                "affected_includes": ["edge-a1"],
                "single_incident": True},
        "seam": {"seam_id": "dal-dx-1", "seam_type": "DX", "owner": "carrier"},
        "forbid": {"cross_tenant_merge": True},
    },
}

NEG_GT = {
    "story_id": "no-merge-1",
    "template": "negative_unrelated_concurrency",
    "fired_at": "2026-08-17T00:00:30Z",
    "affected": {"devices": ["rtr-c1", "rtr-c3", "br-b2"],
                 "tenants": ["coyote", "bluesky"]},
    "extra_entities": [],
    "expect": {"rca": {},
               "forbid": {"cross_tenant_merge": True, "confirmed": True}},
}

# Fixture object name -> a real UUID: the keyed reads validate correlation ids
# before embedding them, so the fixtures have to be honest about the type.
OID = {
    "obj-1": "11111111-1111-4111-8111-111111111111",
    "obj-2": "22222222-2222-4222-8222-222222222222",
    "obj-3": "33333333-3333-4333-8333-333333333333",
    "obj-9": "99999999-9999-4999-8999-999999999999",
    "giant": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
}


def _obj(oid, tier, hyp, affected_names, owner="carrier", state="open",
         nodes=3):
    # hypotheses mirrors the LIVE corr_objects column shape (verified
    # 2026-08-17): {"grounding_context": {...}, "ranking": {"hypotheses":
    # [...], ...}} — the 2026-08-17 live run crashed the first scorer cut,
    # which assumed a bare list.
    return {
        "id": OID.get(oid, oid), "state": state, "verdict_tier": tier,
        "top_hypothesis": hyp, "conf": 0.72, "node_count": nodes,
        "version": 4,
        "affected": json.dumps({"devices": affected_names}),
        "hypotheses": json.dumps({
            "grounding_context": {"seams": []},
            "ranking": {"top_hypothesis": hyp,
                        "hypotheses": [{"id": hyp,
                                        "verdict": {"owner": owner}}]},
        }),
    }


def needles_of(query):
    """The needle list of a `multiSearchAny(<col>, [...])` predicate."""
    inner = query.split("multiSearchAny(")[1].split("[", 1)[1].split("]", 1)[0]
    return [n.strip().strip("'") for n in inner.split(",")]


def ids_of(query):
    return set(re.findall(r"toUUID\('([^']+)'\)", query))


class FakeStack:
    """Answers the scorer's bounded ClickHouse query shapes from fixtures."""

    def __init__(self, objects=(), edges=None, signals=None):
        self.objects = list(objects)
        self.edges = {OID.get(k, k): v for k, v in (edges or {}).items()}
        self.signals = signals or {}
        self.object_queries = 0
        self.queries = []

    def ch_json(self, query, timeout=60, settings=None, strict=False):
        self.queries.append((query, dict(settings or {})))
        if "netops.corr_objects" in query and "multiSearchAny(affected" in query:
            # Membership over EVERY version, bounded by tenant + window.
            names = needles_of(query)
            self.object_queries += 1
            assert "hypotheses" not in query, \
                "the membership scan must not carry the unbounded blob columns"
            return [{"id": o["id"],
                     "hits": [n for n in names if n in o["affected"]]}
                    for o in self.objects
                    if any(n in o["affected"] for n in names)]
        if "netops.corr_current" in query:
            ids = ids_of(query)
            self.object_queries += 1
            assert "hypotheses" not in query, \
                "the latest-version read must not carry the blob column"
            return [{k: v for k, v in o.items() if k != "hypotheses"}
                    for o in self.objects if o["id"] in ids]
        if "hypotheses" in query and "netops.corr_objects" in query:
            ids = ids_of(query)
            return [{"id": o["id"], "hypotheses": o["hypotheses"]}
                    for o in self.objects if o["id"] in ids]
        if "netops.corr_objects" in query and "LIMIT 1 BY" in query:
            # hot-projection gap fallback: latest version from the history
            ids = ids_of(query)
            self.object_queries += 1
            return [{k: v for k, v in o.items() if k != "hypotheses"}
                    for o in self.objects if o["id"] in ids]
        if "corr_edges" in query:
            ids = ids_of(query)
            return [{"id": oid, "grounding_ref": ref}
                    for oid in sorted(ids)
                    for ref in self.edges.get(oid, [])]
        if "corr_signals" in query:
            names = needles_of(query)
            return [{"hits": [name], "kind": kind, "n": n}
                    for name in names
                    for kind, n in self.signals.get(name, {}).items()]
        raise AssertionError(f"unexpected query: {query}")


def ctx_for(stack, story_batch=scorer.STORY_BATCH, max_needles=None):
    return scorer.ScoreContext(
        stack, WINDOW, TENANTS, story_batch=story_batch,
        max_needles=max_needles or scorer.MAX_NEEDLES)


def test_hit_every_clause_passes():
    stack = FakeStack(
        objects=[_obj("obj-1", "suspected",
                      "sig.ent.middle-mile.private-interconnect-bgp-down",
                      [PREFIX + "edge-a1", PREFIX + "dxcon-twin0001/vif-100"])],
        edges={"obj-1": [PREFIX + "dal-dx-1"]},
    )
    r = scorer.score_story(stack, DX_GT, PREFIX, STATE["device_tenants"], {},
                           ctx=ctx_for(stack))
    assert r["status"] == "PASS", r["clauses"]
    assert {c["clause"] for c in r["clauses"]} >= {
        "detected", "verdict_tier_at_least", "hypothesis_matches",
        "affected_includes", "single_incident", "seam_grounded", "seam_owner",
        "forbid.cross_tenant_merge"}


def test_miss_reports_evidence_trail():
    stack = FakeStack(objects=[],
                      signals={PREFIX + "edge-a1": {"bgp_adjacency_change": 2}})
    r = scorer.score_story(stack, DX_GT, PREFIX, STATE["device_tenants"],
                           {"syslog": 4, "cloud": 3, "probes": 8},
                           ctx=ctx_for(stack))
    assert r["status"] == "FAIL"
    detected = next(c for c in r["clauses"] if c["clause"] == "detected")
    assert not detected["ok"]
    trail = r["evidence_trail"]
    assert trail["events_journaled"] == {"syslog": 4, "cloud": 3, "probes": 8}
    assert trail["signals_by_kind"] == {"bgp_adjacency_change": 2}


def test_wrong_verdict_tier_fails_that_clause_only():
    stack = FakeStack(
        objects=[_obj("obj-1", "undetermined",
                      "sig.ent.middle-mile.private-interconnect-bgp-down",
                      [PREFIX + "edge-a1"])],
        edges={"obj-1": [PREFIX + "dal-dx-1"]},
    )
    r = scorer.score_story(stack, DX_GT, PREFIX, STATE["device_tenants"], {},
                           ctx=ctx_for(stack))
    assert r["status"] == "FAIL"
    by = {c["clause"]: c["ok"] for c in r["clauses"]}
    assert by["detected"] is True
    assert by["verdict_tier_at_least"] is False
    assert by["hypothesis_matches"] is True


def test_negative_control_false_positive_cross_tenant_merge():
    merged = _obj("obj-9", "suspected", "sig.generic",
                  [PREFIX + "rtr-c1", PREFIX + "br-b2"])  # coyote + bluesky
    stack = FakeStack(objects=[merged])
    r = scorer.score_story(stack, NEG_GT, PREFIX, STATE["device_tenants"], {},
                           ctx=ctx_for(stack))
    assert r["status"] == "FAIL"
    clause = next(c for c in r["clauses"]
                  if c["clause"] == "forbid.cross_tenant_merge")
    assert not clause["ok"]
    assert "coyote" in clause["detail"] and "bluesky" in clause["detail"]


def test_negative_control_clean_passes_and_confirmed_forbidden():
    # same-tenant object at suspected: allowed; a CONFIRMED one is not.
    ok_obj = _obj("obj-2", "suspected", "sig.generic", [PREFIX + "rtr-c1"])
    stack = FakeStack(objects=[ok_obj])
    r = scorer.score_story(stack, NEG_GT, PREFIX, STATE["device_tenants"], {},
                           ctx=ctx_for(stack))
    assert r["status"] == "PASS"
    bad_obj = _obj("obj-3", "confirmed", "sig.generic", [PREFIX + "rtr-c1"])
    stack = FakeStack(objects=[bad_obj])
    r = scorer.score_story(stack, NEG_GT, PREFIX, STATE["device_tenants"], {},
                           ctx=ctx_for(stack))
    assert r["status"] == "FAIL"


def test_score_run_aggregates_slo_and_specificity():
    stack = FakeStack(
        objects=[_obj("obj-1", "suspected",
                      "sig.ent.middle-mile.private-interconnect-bgp-down",
                      [PREFIX + "edge-a1"])],
        edges={"obj-1": [PREFIX + "dal-dx-1"]},
    )
    rep = scorer.score_run(stack, [DX_GT, NEG_GT], STATE, {},
                           ctx=ctx_for(stack))
    assert rep["stories_total"] == 2
    assert rep["stories_passed"] == 2
    assert rep["accuracy_slo"] == 1.0
    assert rep["specificity"] == 1.0
    md = scorer.render_md(rep)
    assert "dx-flap-1" in md and "no-merge-1" in md
    # the report carries the bounds the reads actually used
    assert rep["read_bounds"]["window"]["start"] == WINDOW.start
    assert rep["read_bounds"]["tenants"] == TENANTS
    assert "Read bounds" in md


def test_sql_identifier_zero_trust():
    with pytest.raises(ValueError):
        scorer._lit("x'; DROP TABLE netops.corr_signals; --")


def test_malformed_hypotheses_column_never_crashes_the_run():
    """Regression for the 2026-08-17 live run: a hypotheses shape the scorer
    did not expect must degrade to a recorded clause failure, never a crash
    that loses every story's verdict to the teardown."""
    weird = _obj("obj-1", "suspected",
                 "sig.ent.middle-mile.private-interconnect-bgp-down",
                 [PREFIX + "edge-a1"])
    for bad in ('"just a string"', "[]", "{}", "not json at all",
                json.dumps({"ranking": {"hypotheses": ["str-entry"]}})):
        weird["hypotheses"] = bad
        stack = FakeStack(objects=[dict(weird)],
                          edges={"obj-1": [PREFIX + "dal-dx-1"]})
        r = scorer.score_story(stack, DX_GT, PREFIX,
                               STATE["device_tenants"], {},
                               ctx=ctx_for(stack))
        owner_clause = next(c for c in r["clauses"]
                            if c["clause"] == "seam_owner")
        assert owner_clause["ok"] is False  # honest miss, not a crash


def test_score_run_records_a_crashing_story_loudly():
    class Exploding(FakeStack):
        def ch_json(self, query, timeout=60, settings=None, strict=False):
            if "netops.corr_current" in query:
                raise RuntimeError("boom")
            return super().ch_json(query, timeout, settings, strict)

    stack = Exploding(objects=[_obj("obj-1", "suspected", "sig.generic",
                                    [PREFIX + "edge-a1", PREFIX + "rtr-c1"])])
    with pytest.raises(RuntimeError):
        scorer.score_run(stack, [DX_GT, NEG_GT], STATE, {},
                         ctx=ctx_for(stack))


def test_score_run_records_a_per_story_crash_without_losing_the_others():
    """A clause that blows up on ONE story must not cost every other story its
    verdict (2026-08-17: the whole report was lost to teardown)."""
    bad = dict(DX_GT)
    bad["expect"] = {"rca": {"hypothesis_matches": "("}}  # invalid regex
    stack = FakeStack(objects=[_obj("obj-1", "suspected", "sig.generic",
                                    [PREFIX + "edge-a1"])])
    rep = scorer.score_run(stack, [bad, NEG_GT], STATE, {},
                           ctx=ctx_for(stack))
    assert rep["stories"][0]["clauses"][0]["clause"] == "scorer_error"
    assert rep["stories"][1]["status"] == "PASS"


def test_object_lookup_is_two_queries_per_story_regardless_of_entity_count():
    """`affected` and `hypotheses` are unbounded String columns. A story with
    many affected devices (the giant-object scenario has 130) must NOT issue one
    scan per device: measured live 2026-08-17, the per-name form drove
    ClickHouse to ~3 GiB and started losing queries to `Code: 241 Memory limit
    (total) exceeded`, silently costing the scorer the objects it must judge."""
    devices = [f"acc-{i:04d}" for i in range(1, 131)]
    gt = {
        "story_id": "access-layer-fold", "template": "link_down_cascade",
        "fired_at": "2026-08-17T00:00:00Z",
        "affected": {"devices": devices, "tenants": ["bigfold"]},
        "extra_entities": [],
        "expect": {"rca": {"verdict_tier_at_least": "suspected",
                           "affected_includes": ["acc-0001", "acc-0130"],
                           "single_incident": True}},
    }
    stack = FakeStack(objects=[
        _obj("giant", "suspected", "sig.ent.access.local-link-fault",
             [PREFIX + d for d in devices], nodes=780)])
    r = scorer.score_story(stack, gt, PREFIX,
                           {d: "bigfold" for d in devices}, {},
                           ctx=ctx_for(stack))
    # two lean phases (membership, then the narrow latest-version read) —
    # NOT one per entity
    assert stack.object_queries == 2, "batched two-phase, not one per entity"
    assert r["status"] == "PASS", r["clauses"]
    assert [o["id"] for o in r["objects"]] == [OID["giant"]]


def test_object_lookup_still_refuses_unsafe_identifiers():
    """Batching must not weaken the zero-trust SQL-embed rule."""
    gt = dict(DX_GT)
    gt["affected"] = {"devices": ["ok-1", "bad' OR 1=1 --"],
                      "tenants": ["acme"]}
    gt["extra_entities"] = []
    stack = FakeStack()
    with pytest.raises(scorer.ScorerError) as exc:
        scorer.score_run(stack, [gt], STATE, {}, ctx=ctx_for(stack))
    assert "SQL-embed safe" in str(exc.value)
    assert stack.queries == [], "nothing may reach ClickHouse after a refusal"
