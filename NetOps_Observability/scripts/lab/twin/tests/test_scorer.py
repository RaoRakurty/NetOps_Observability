"""Scorer logic on fixture data: hit / miss / wrong-verdict / false-positive
on a negative control — plus the aggregate SLO math and the evidence trail on
a miss (design §5/§8.4 scoring contract)."""
import json

import scorer

PREFIX = "twx-r1-"

STATE = {
    "runid": "r1",
    "prefix": PREFIX,
    "device_tenants": {"edge-a1": "acme", "rtr-c1": "coyote",
                       "rtr-c3": "coyote", "br-b2": "bluesky"},
}

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


def _obj(oid, tier, hyp, affected_names, owner="carrier", state="open",
         nodes=3):
    # hypotheses mirrors the LIVE corr_objects column shape (verified
    # 2026-08-17): {"grounding_context": {...}, "ranking": {"hypotheses":
    # [...], ...}} — the 2026-08-17 live run crashed the first scorer cut,
    # which assumed a bare list.
    return {
        "id": oid, "state": state, "verdict_tier": tier,
        "top_hypothesis": hyp, "conf": 0.72, "node_count": nodes,
        "affected": json.dumps({"devices": affected_names}),
        "hypotheses": json.dumps({
            "grounding_context": {"seams": []},
            "ranking": {"top_hypothesis": hyp,
                        "hypotheses": [{"id": hyp,
                                        "verdict": {"owner": owner}}]},
        }),
    }


class FakeStack:
    """Answers the scorer's three ClickHouse query shapes from fixtures."""

    def __init__(self, objects=(), edges=None, signals=None):
        self.objects = list(objects)
        self.edges = edges or {}
        self.signals = signals or {}

    def ch_json(self, query):
        if "corr_objects_latest" in query:
            name = query.split("position(affected, '")[1].split("'")[0]
            return [dict(o) for o in self.objects if name in o["affected"]]
        if "corr_edges" in query:
            oid = query.split("toString(correlation_id) = '")[1].split("'")[0]
            return [{"grounding_ref": r} for r in self.edges.get(oid, [])]
        if "corr_signals" in query:
            name = query.split("entity_id LIKE '%")[1].split("%'")[0]
            return [{"kind": k, "n": n}
                    for k, n in self.signals.get(name, {}).items()]
        raise AssertionError(f"unexpected query: {query}")


def test_hit_every_clause_passes():
    stack = FakeStack(
        objects=[_obj("obj-1", "suspected",
                      "sig.ent.middle-mile.private-interconnect-bgp-down",
                      [PREFIX + "edge-a1", PREFIX + "dxcon-twin0001/vif-100"])],
        edges={"obj-1": [PREFIX + "dal-dx-1"]},
    )
    r = scorer.score_story(stack, DX_GT, PREFIX, STATE["device_tenants"], {})
    assert r["status"] == "PASS", r["clauses"]
    assert {c["clause"] for c in r["clauses"]} >= {
        "detected", "verdict_tier_at_least", "hypothesis_matches",
        "affected_includes", "single_incident", "seam_grounded", "seam_owner",
        "forbid.cross_tenant_merge"}


def test_miss_reports_evidence_trail():
    stack = FakeStack(objects=[],
                      signals={PREFIX + "edge-a1": {"bgp_adjacency_change": 2}})
    r = scorer.score_story(stack, DX_GT, PREFIX, STATE["device_tenants"],
                           {"syslog": 4, "cloud": 3, "probes": 8})
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
    r = scorer.score_story(stack, DX_GT, PREFIX, STATE["device_tenants"], {})
    assert r["status"] == "FAIL"
    by = {c["clause"]: c["ok"] for c in r["clauses"]}
    assert by["detected"] is True
    assert by["verdict_tier_at_least"] is False
    assert by["hypothesis_matches"] is True


def test_negative_control_false_positive_cross_tenant_merge():
    merged = _obj("obj-9", "suspected", "sig.generic",
                  [PREFIX + "rtr-c1", PREFIX + "br-b2"])  # coyote + bluesky
    r = scorer.score_story(FakeStack(objects=[merged]), NEG_GT, PREFIX,
                           STATE["device_tenants"], {})
    assert r["status"] == "FAIL"
    clause = next(c for c in r["clauses"]
                  if c["clause"] == "forbid.cross_tenant_merge")
    assert not clause["ok"]
    assert "coyote" in clause["detail"] and "bluesky" in clause["detail"]


def test_negative_control_clean_passes_and_confirmed_forbidden():
    # same-tenant object at suspected: allowed; a CONFIRMED one is not.
    ok_obj = _obj("obj-2", "suspected", "sig.generic", [PREFIX + "rtr-c1"])
    r = scorer.score_story(FakeStack(objects=[ok_obj]), NEG_GT, PREFIX,
                           STATE["device_tenants"], {})
    assert r["status"] == "PASS"
    bad_obj = _obj("obj-3", "confirmed", "sig.generic", [PREFIX + "rtr-c1"])
    r = scorer.score_story(FakeStack(objects=[bad_obj]), NEG_GT, PREFIX,
                           STATE["device_tenants"], {})
    assert r["status"] == "FAIL"


def test_score_run_aggregates_slo_and_specificity():
    stack = FakeStack(
        objects=[_obj("obj-1", "suspected",
                      "sig.ent.middle-mile.private-interconnect-bgp-down",
                      [PREFIX + "edge-a1"])],
        edges={"obj-1": [PREFIX + "dal-dx-1"]},
    )
    rep = scorer.score_run(stack, [DX_GT, NEG_GT], STATE, {})
    assert rep["stories_total"] == 2
    assert rep["stories_passed"] == 2
    assert rep["accuracy_slo"] == 1.0
    assert rep["specificity"] == 1.0
    md = scorer.render_md(rep)
    assert "dx-flap-1" in md and "no-merge-1" in md


def test_sql_identifier_zero_trust():
    import pytest
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
                               STATE["device_tenants"], {})
        owner_clause = next(c for c in r["clauses"]
                            if c["clause"] == "seam_owner")
        assert owner_clause["ok"] is False  # honest miss, not a crash


def test_score_run_records_a_crashing_story_loudly():
    class Exploding(FakeStack):
        def ch_json(self, query):
            raise RuntimeError("boom")

    rep = scorer.score_run(Exploding(), [DX_GT, NEG_GT], STATE, {})
    assert rep["stories_total"] == 2
    assert all(r["status"] == "FAIL" for r in rep["stories"])
    assert all(r["clauses"][0]["clause"] == "scorer_error"
               for r in rep["stories"])
