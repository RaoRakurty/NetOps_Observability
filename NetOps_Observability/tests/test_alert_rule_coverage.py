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
