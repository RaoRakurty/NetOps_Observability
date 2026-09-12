# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Build ④ contract tests — catalog spec validation + version hash + scorer
semantics. The per-signature scenario fixtures live in fixtures/ and run via
test_fixtures.py; this file pins the machinery itself."""

import pytest
from pydantic import ValidationError

from catalog import BUILTIN_TEMPLATES, builtin_catalog, load_catalog
from scoring import CONFIDENCE_FLOOR, CONTRADICTION_PENALTY, TOP_K, rank
from verdicts import VerdictTier


def test_builtin_catalog_validates():
    cat = builtin_catalog()
    assert len(cat.enabled_templates()) == 103  # +3 Exposure Story (T2b evidence-class grounding seed); +9 wireless (#128 Phase 3: ap-down pair, 3 RF, capwap, wlc-failover, 2 onboarding); +3 NMS controller-intel (P4b); +1 saas-experience-degraded; +1 cloud app-dependency-down; +1 cloud ipsec-tunnel-down; +1 middle-mile ipsec-underlay-down; +4 cloud edge-dependency attribution (Wave 3 #9: lb-5xx / waf-block / firewall-reject / dns-failure)
    assert all(t.id.startswith("sig.ent.") for t in cat.templates)


def test_catalog_version_hash_is_content_addressed():
    a = builtin_catalog().version_hash()
    b = builtin_catalog().version_hash()
    assert a == b and a.startswith("cat-") and len(a) == 16
    # Content change ⇒ new version (replay contract C6).
    mutated = [dict(t) for t in BUILTIN_TEMPLATES]
    mutated[0] = dict(mutated[0], title="renamed")
    assert load_catalog(mutated).version_hash() != a
    # Disabling a template changes the EFFECTIVE catalog ⇒ new version too.
    disabled = [dict(t) for t in BUILTIN_TEMPLATES]
    disabled[0] = dict(disabled[0], enabled=False)
    assert load_catalog(disabled).version_hash() != a


def test_catalog_lint_rejects_bad_templates():
    base = dict(BUILTIN_TEMPLATES[0])
    with pytest.raises(ValidationError):
        load_catalog([base, dict(base)])  # duplicate id
    with pytest.raises(ValidationError):
        load_catalog([dict(base, discriminators=[
            {"absent": {"kind": "x"}, "else_prefer": "sig.ent.no.such-id"},
        ])])  # dangling else_prefer
    with pytest.raises(ValidationError):
        load_catalog([dict(base, discriminators=[
            {"absent": {"kind": "x"}, "else_prefer": base["id"]},
        ])])  # self-preference
    with pytest.raises(ValidationError):
        load_catalog([dict(base, requires=[
            {"kind": "a", "optional": True},
        ])])  # all-optional evidence chain
    with pytest.raises(ValidationError):
        load_catalog([dict(base, requires=[{"kind": "a||b"}])])  # empty alternation token
    with pytest.raises(ValidationError):
        load_catalog([dict(base, id="not-namespaced")])


def test_empty_evidence_is_undetermined_with_mechanical_missing():
    res = rank(builtin_catalog(), [])
    assert res.top_hypothesis == "undetermined"
    assert res.verdict_tier is VerdictTier.UNDETERMINED
    assert res.evidence_missing  # names the nearest templates' unmet clauses
    assert all(": needs " in m for m in res.evidence_missing)
    assert res.catalog_version == builtin_catalog().version_hash()


def test_ranking_is_deterministic_and_bounded():
    res = rank(builtin_catalog(), [])
    again = rank(builtin_catalog(), [])
    assert res.to_dict() == again.to_dict()
    assert len(res.hypotheses) <= TOP_K + 6  # top-K + forced competitors only


def test_config_constants_documented():
    # Config-hash members; P4 calibration re-fits them, nothing tunes silently.
    assert CONTRADICTION_PENALTY == 0.2
    assert CONFIDENCE_FLOOR == 0.3
    assert TOP_K == 4
