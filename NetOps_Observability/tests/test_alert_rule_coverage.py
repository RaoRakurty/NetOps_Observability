# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: an alert-rule unit test must actually resolve the rules it names.

WHY THIS EXISTS. `rules-scale-slo.yaml` shipped unvalidated: `preflight-configs.sh`
ran `promtool check rules` on `rules.yaml` only, and the unit-test harness mounted
only that file — so a `*.test.yaml` naming a scale-slo alert resolved ZERO rules and
promtool reported the empty result as **SUCCESS**. A green test proving nothing is
the same class as the orphaned failure counters in `test_ga_failure_accounting.py`
and the warn-and-continue swallows in `test_error_swallow_keeper`-style guards: the
signal existed, nothing consumed it.

The mount/check half is fixed in `preflight-configs.sh` (both rule files are checked
and both are mounted for every test file). These tests close the half a docker-based
promtool run structurally CANNOT: they are static, need no container, and fail the
cheap lane the moment the two sides drift again.

Deliberately NOT asserted here: rule semantics. promtool owns firing behaviour; this
file only guarantees the promtool run is aimed at something real.
"""

from __future__ import annotations

import re
from pathlib import Path

CONFIG = Path(__file__).resolve().parents[1] / "src" / "config"
RULES_TESTS = CONFIG / "rules-tests"
PREFLIGHT = Path(__file__).resolve().parents[1] / "scripts" / "preflight-configs.sh"

ALERT_DEF = re.compile(r"^\s*-?\s*alert:\s*(\S+)", re.MULTILINE)
ALERT_REF = re.compile(r"alertname:\s*(\S+)")


def _rule_files() -> list[Path]:
    return sorted(CONFIG.glob("rules*.yaml"))


def _defined_alerts() -> set[str]:
    names: set[str] = set()
    for f in _rule_files():
        names |= set(ALERT_DEF.findall(f.read_text(encoding="utf-8")))
    return names


def test_rule_files_exist() -> None:
    """Sanity: the discovery globs must not go vacuously empty."""
    files = _rule_files()
    assert files, f"no rules*.yaml found under {CONFIG} — the globs below prove nothing"
    assert _defined_alerts(), "no `alert:` definitions parsed — regex or layout drifted"


def test_every_rule_file_is_promtool_checked() -> None:
    """Every rules*.yaml must be named in preflight-configs.sh's check step.

    A new rule file that nobody checks is exactly how rules-scale-slo.yaml went
    unvalidated for its whole life.
    """
    script = PREFLIGHT.read_text(encoding="utf-8")
    missing = [f.name for f in _rule_files() if f.name not in script]
    assert not missing, (
        "rules file(s) not referenced by scripts/preflight-configs.sh, so "
        f"`promtool check rules` never sees them: {missing}"
    )


def test_every_rule_file_is_mounted_for_unit_tests() -> None:
    """Every rules*.yaml must be mounted into the promtool TEST invocation.

    promtool resolves alert names against the mounted rule_files only; an
    unmounted file makes every test naming its alerts silently vacuous.
    """
    script = PREFLIGHT.read_text(encoding="utf-8")
    # The test loop is the region after the unit-test marker; require each rule
    # file to appear in a -v mount there.
    idx = script.find("rules-tests")
    assert idx != -1, "preflight-configs.sh no longer runs rules-tests/*.test.yaml"
    tail = script[idx:]
    unmounted = [f.name for f in _rule_files() if f.name not in tail]
    assert not unmounted, (
        "rules file(s) not mounted for the promtool unit-test run — tests naming "
        f"their alerts would resolve ZERO rules and PASS: {unmounted}"
    )


def test_referenced_alerts_all_exist() -> None:
    """Every alertname a test asserts on must be defined in some rule file.

    This is the direct guard against the original defect: promtool treats "no
    such alert" as an empty result set, and an empty result set as success.
    """
    defined = _defined_alerts()
    orphans: dict[str, list[str]] = {}
    for tf in sorted(RULES_TESTS.glob("*.test.yaml")):
        refs = set(ALERT_REF.findall(tf.read_text(encoding="utf-8")))
        missing = sorted(r for r in refs if r not in defined)
        if missing:
            orphans[tf.name] = missing
    assert not orphans, (
        "test(s) assert on alertname(s) that no rules*.yaml defines. promtool "
        "reports these as SUCCESS (empty result == expected empty), so the test "
        f"is green while proving nothing: {orphans}"
    )


def test_each_test_file_names_at_least_one_alert() -> None:
    """A *.test.yaml with no alertname assertion cannot prove a rule fires.

    Promtool-only coverage would report such a file as passing; catch it here.
    """
    barren = [
        tf.name
        for tf in sorted(RULES_TESTS.glob("*.test.yaml"))
        if not ALERT_REF.search(tf.read_text(encoding="utf-8"))
    ]
    assert not barren, (
        "rule unit test file(s) assert on no alertname at all — they pass "
        f"vacuously: {barren}"
    )


# ── page-tier guards (2026-09-02) ───────────────────────────────────────────
#
# The `tier` label is the routing contract: `tier: page` means "this wakes a
# human", and the owner ruling fixes that set at FOUR conditions. A tier that
# can grow without anyone noticing is how a pager becomes noise and then gets
# muted — which is the failure mode that turned a 5-minute incident into a
# 3-hour one on 2026-09-02. These two guards are cheap, static, and bite the
# moment the page tier grows without its evidence.
#
# Deliberately NOT asserted: how many page rules there are. Pinning a count
# turns every legitimate addition into a merge conflict and teaches people to
# bump the number without thinking. What is pinned is that each one must (a)
# tell the operator what to do and (b) be PROVEN to fire.

import yaml  # noqa: E402  (kept next to the tests that need it)


def _rules_with_tier(tier: str) -> dict[str, dict]:
    """Every alert rule carrying labels.tier == `tier`, by alertname."""
    found: dict[str, dict] = {}
    for f in _rule_files():
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for group in doc.get("groups", []):
            for rule in group.get("rules", []):
                if "alert" not in rule:
                    continue
                if (rule.get("labels") or {}).get("tier") == tier:
                    found[rule["alert"]] = rule
    return found


def test_page_tier_rules_carry_an_actionable_runbook() -> None:
    """A page must say what to do about itself, and the target must exist.

    A 3 a.m. alert whose runbook annotation is missing — or points at a file
    somebody moved — is an alert the operator cannot act on.
    """
    root = Path(__file__).resolve().parents[1]
    page = _rules_with_tier("page")
    assert page, "no `tier: page` rules found — the label or the parse drifted"

    missing, dangling = [], []
    for name, rule in sorted(page.items()):
        runbook = (rule.get("annotations") or {}).get("runbook", "")
        if not runbook:
            missing.append(name)
            continue
        if not (root / runbook.split("#", 1)[0]).exists():
            dangling.append(f"{name} -> {runbook}")
    assert not missing, f"`tier: page` rule(s) with no runbook annotation: {missing}"
    assert not dangling, f"runbook annotation(s) pointing at a missing file: {dangling}"


def test_page_tier_rules_are_proven_to_fire() -> None:
    """Every `tier: page` alert must have a promtool test that FIRES it.

    `test_referenced_alerts_all_exist` above proves a test's alertname resolves
    to a real rule. This proves the converse for the tier that matters: that the
    rule has been driven into the firing state by synthetic series at least
    once. A page rule with only silence assertions — or with none at all — is
    exactly the "green test proving nothing" this module exists to prevent, and
    for the page tier the cost of that is a missed outage.
    """
    page = set(_rules_with_tier("page"))
    fires: set[str] = set()
    for tf in sorted(RULES_TESTS.glob("*.test.yaml")):
        doc = yaml.safe_load(tf.read_text(encoding="utf-8")) or {}
        for case in doc.get("tests", []):
            for assertion in case.get("alert_rule_test", []) or []:
                # exp_alerts absent or [] == "must stay silent". Only a
                # non-empty expectation proves the rule can actually fire.
                if assertion.get("exp_alerts"):
                    fires.add(assertion.get("alertname", ""))

    unproven = sorted(page - fires)
    assert not unproven, (
        "`tier: page` rule(s) with no promtool test asserting they FIRE: "
        f"{unproven}. Add a firing case (and its all-clear sibling) to "
        f"{RULES_TESTS.relative_to(Path(__file__).resolve().parents[1])}/."
    )
