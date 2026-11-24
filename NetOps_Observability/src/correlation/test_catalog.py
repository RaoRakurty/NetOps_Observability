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
    assert len(cat.enabled_templates()) == 105  # +1 sdwan-controller-unreachable (controller fan-in, 2026-11-11); +1 admin-link-change-induced (tracker 385); +3 Exposure Story (T2b evidence-class grounding seed); +9 wireless (#128 Phase 3: ap-down pair, 3 RF, capwap, wlc-failover, 2 onboarding); +3 NMS controller-intel (P4b); +1 saas-experience-degraded; +1 cloud app-dependency-down; +1 cloud ipsec-tunnel-down; +1 middle-mile ipsec-underlay-down; +4 cloud edge-dependency attribution (Wave 3 #9: lb-5xx / waf-block / firewall-reject / dns-failure)
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


# Owner 2026-11-24 (option B, ENGINE_SEMVER 3.7.0): a template with two or more
# REQUIRED clauses names the clause it is ABOUT with `anchor`, so its generic
# clauses alone never earn it partial coverage ("local link fault — suspected
# 0.5" from a traffic swing with no link change: 1,184 lab objects in 7 days).
# Every multi-required template needs an anchor or a row here. This ledger only
# SHRINKS: anchoring a template means deleting its row (the stale check fails
# otherwise), and a new multi-required template must ship with an anchor.
# Audited 2026-11-24 and deliberately left pending (no single defining clause):
# sig.ent.middle-mile.dia-egress-corroborated (probe symptom + BGP cause are the
# story only together) — owner decision.
ANCHOR_PENDING = frozenset({
    "sig.ent.access.dns-local-resolver-failure",
    "sig.ent.access.pmtud-blackhole",
    "sig.ent.access.stp-loop-broadcast-storm",
    "sig.ent.app.dns-failover-wrong-target",
    "sig.ent.app.edge-dns-failure",
    "sig.ent.app.edge-firewall-reject",
    "sig.ent.app.edge-lb-5xx",
    "sig.ent.app.edge-waf-block",
    "sig.ent.app.lb-target-health-failure",
    "sig.ent.app.tls-cert-expired",
    "sig.ent.cloud.ipsec-tunnel-down",
    "sig.ent.cloud.k8s-pod-ip-exhaustion",
    "sig.ent.cloud.k8s-service-endpoint-empty",
    "sig.ent.cloud.lb-probe-semantics-mismatch",
    "sig.ent.cloud.lb-probe-source-blocked",
    "sig.ent.cloud.lb-snat-hotspot-imbalance",
    "sig.ent.cloud.mesh-mtls-cert-rotation-failure",
    "sig.ent.cloud.private-connectivity-down",
    "sig.ent.cloud.private-dns-ruleset-gap",
    "sig.ent.cloud.private-endpoint-dns-mismatch",
    "sig.ent.cloud.region-degradation",
    "sig.ent.cloud.route-table-blackhole",
    "sig.ent.cloud.sg-nacl-block",
    "sig.ent.fabric.spine-leaf-path-degradation",
    "sig.ent.middle-mile.dia-egress-corroborated",
    "sig.ent.middle-mile.dx-optics-degrade",
    "sig.ent.middle-mile.expressroute-arp-unresolved",
    "sig.ent.middle-mile.interconnect-jumbo-mtu-mismatch",
    "sig.ent.middle-mile.interconnect-vlan-tag-mismatch",
    "sig.ent.middle-mile.ipsec-underlay-down",
    "sig.ent.middle-mile.private-interconnect-missing-prefix",
    "sig.ent.security.fw-aa-session-owner-mismatch",
    "sig.ent.security.fw-ha-failover-drift",
    "sig.ent.security.nat-snat-exhaustion",
    "sig.ent.security.proxy-pac-wpad-failure",
    "sig.ent.security.waf-body-limit-block",
    "sig.ent.security.waf-rule-false-positive",
    "sig.ent.spdc.cfp-osfp-vendor-interoperability-risk",
    "sig.ent.spdc.channel-frequency-misalignment",
    "sig.ent.spdc.coherent-osnr-degradation",
    "sig.ent.spdc.dwdm-mux-demux-attenuation",
    "sig.ent.spdc.edfa-saturation-or-gain-tilt",
    "sig.ent.spdc.fec-masking-highspeed",
    "sig.ent.spdc.high-power-module-thermal-throttle",
    "sig.ent.spdc.mpo-broken-strand",
    "sig.ent.spdc.mpo-cassette-type-mismatch",
    "sig.ent.spdc.mpo-dirty-multifiber",
    "sig.ent.spdc.mpo-missing-fibers",
    "sig.ent.spdc.mpo-pinout-gender-mismatch",
    "sig.ent.spdc.mpo-polarity-mismatch",
    "sig.ent.spdc.mpo-row-flip",
    "sig.ent.spdc.osfp-incompatible-part",
    "sig.ent.spdc.pam4-lane-ber-divergence",
    "sig.ent.spdc.pam4-lane-skew-excessive",
    "sig.ent.spdc.parallel-optic-lane-swap",
    "sig.ent.spdc.patchpanel-crossconnect-error",
    "sig.ent.spdc.pcs-lane-deskew-failure",
    "sig.ent.spdc.qsfpdd-single-lane-failure",
    "sig.ent.spdc.roadm-filter-edge-impairment",
    "sig.ent.wan-edge.congestion",
    "sig.ent.wan-edge.sdwan-tunnel-degraded",
    "sig.ent.wan-edge.tunnel-mtu-blackhole",
})


def _multi_required(t) -> bool:
    return sum(1 for c in t.requires if not c.optional) >= 2


def test_multi_required_templates_have_an_anchor_or_a_ledger_row():
    missing = sorted(t.id for t in builtin_catalog().enabled_templates()
                     if _multi_required(t) and not any(c.anchor for c in t.requires)
                     and t.id not in ANCHOR_PENDING)
    assert missing == [], f"multi-required templates with no anchor and no ANCHOR_PENDING row: {missing}"


def test_anchor_pending_ledger_is_not_stale():
    by_id = {t.id: t for t in builtin_catalog().enabled_templates()}
    stale = sorted(i for i in ANCHOR_PENDING
                   if i not in by_id or not _multi_required(by_id[i])
                   or any(c.anchor for c in by_id[i].requires))
    assert stale == [], f"remove these rows from ANCHOR_PENDING (anchored, gone or single-clause): {stale}"


def test_owner_audited_anchors_2026_11_24():
    by_id = {t.id: t for t in builtin_catalog().enabled_templates()}
    expect = {
        "sig.ent.access.local-link-fault": "link_state_change",
        "sig.ent.middle-mile.lastmile-circuit-flap": "link_state_change",
        "sig.ent.middle-mile.private-interconnect-bgp-down": "bgp_adjacency_change|bgp_state_anomaly",
        "sig.ent.wireless.ap-down-power": "wireless_ap_down",
    }
    for tid, kind in expect.items():
        anchored = [c.kind for c in by_id[tid].requires if c.anchor]
        assert anchored == [kind], (tid, anchored)
