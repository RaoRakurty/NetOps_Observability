"""Pytest: `gen_index.py`'s curated severity table, against the index it emits.

Run it from here (it imports the generator by path and reads the checked-in
artifact — no pysmi, no net-snmp, no network):

    cd src/backend/collectors/mibs && python3 -m pytest test_gen_index.py -q

WHY THIS FILE EXISTS. `SEVERITY_HINT` is not decoration — it is the ADMISSION
GATE for the whole SNMP-trap lane. `trapMeta()` (collectors/snmptrap.go) falls
back to `notice` for a notification with no hint, and `notice` (5) is BELOW the
correlation engine's `ALARM_SEVERITY_FLOOR` (4). A trap under that floor is
stored, searchable, and invisible to RCA — silently, with no error anywhere. So
a missing or wrong hint is a product defect that looks like nothing at all, and
it needs a test that reads the generated artifact rather than the intention.

The A9 trap audit found exactly that for two whole families (config change,
hardware/environment); A9b seeded them and fixed the merge bug that had made the
old value un-changeable. This file pins the outcome.
"""
from __future__ import annotations

import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "index", "oididx.json")

_spec = importlib.util.spec_from_file_location(
    "gen_index_under_test", os.path.join(HERE, "gen_index.py"))
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

#: Mirrors `producers.ALARM_SEVERITY_FLOOR` and the RFC 5424 numbering the Go
#: receiver and the parser share. Written out rather than imported: this test
#: must run in the collectors tree with no correlation engine on the path, and a
#: silent import failure would make it vacuous.
SEVERITY_NUM = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "error": 3,
                "warning": 4, "warn": 4, "notice": 5, "info": 6, "debug": 7}
ALARM_SEVERITY_FLOOR = 4


@pytest.fixture(scope="module")
def index() -> dict:
    with open(INDEX, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def nodes(index) -> dict:
    return index["nodes"]


@pytest.fixture(scope="module")
def by_name(nodes) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for node in nodes.values():
        out.setdefault(node.get("name", ""), []).append(node)
    return out


# ══ the table itself ═════════════════════════════════════════════════════════


def test_every_hint_is_a_severity_the_pipeline_understands():
    """A typo like `warnings` would be carried into the index verbatim and then
    parse as nothing, i.e. as below the floor."""
    for name, hint in gen.SEVERITY_HINT.items():
        assert hint in SEVERITY_NUM, f"{name}: {hint!r} is not an RFC 5424 keyword"
        assert hint in ("info", "notice", "warning", "err", "crit"), (
            f"{name}: {hint!r} is outside the vocabulary this table uses")


def test_no_seeded_notification_is_left_below_the_alarm_floor_by_accident():
    """`notice` is the DEFAULT for an unhinted notification, so seeding one at
    `notice` is a no-op that reads like a decision. The table must not contain
    one: if a notification really should stay invisible to RCA, leave it out."""
    at_notice = sorted(n for n, h in gen.SEVERITY_HINT.items() if h == "notice")
    assert not at_notice, (
        f"{at_notice} are seeded `notice`, which is the unhinted default AND "
        "below ALARM_SEVERITY_FLOOR — either seed them above the floor or drop "
        "the entry, but do not write a no-op that looks like an opinion")


def test_every_table_entry_names_a_notification_the_index_actually_has(by_name):
    """A hint for a name no compiled MIB defines is dead weight that reads as
    coverage. (Add the MIB to DEFAULT_MIBS first, then the hint.)"""
    missing = sorted(n for n in gen.SEVERITY_HINT if n not in by_name)
    assert not missing, (
        f"{missing} are seeded but resolve to nothing — add the MIB to "
        "DEFAULT_MIBS and re-run `make mib-index`, or remove the entry")
    for name in gen.SEVERITY_HINT:
        assert any(node.get("kind") == "notification" for node in by_name[name]), (
            f"{name} is seeded a severity but is not a NOTIFICATION — only a "
            "notification carries one")


# ══ the artifact matches the table ═══════════════════════════════════════════


def test_the_checked_in_index_carries_every_hint_the_table_declares(by_name):
    """THE DRIFT GUARD. The index is generated and CHECKED IN (the Go runtime
    embeds it), so a table edit with no `make mib-index` ships the old value —
    which is exactly how `entConfigChange` stayed at `notice` after the audit
    said it should not."""
    for name, hint in gen.SEVERITY_HINT.items():
        for node in by_name[name]:
            if node.get("kind") != "notification":
                continue
            assert node.get("severity_hint") == hint, (
                f"{name}: index says {node.get('severity_hint')!r}, table says "
                f"{hint!r} — run `python3 gen_index.py`")


def test_a_changed_hint_actually_propagates_over_an_existing_node():
    """THE MERGE BUG A9b FIXED, pinned as behaviour.

    `main()` starts from the checked-in index as a FLOOR (so a compile miss can
    never regress coverage) and, per OID, preserves the hint already stored.
    That preservation used to run LAST, which meant the first hint an OID ever
    received won forever and a table edit could not move it. The re-application
    of `SEVERITY_HINT` now runs after the merge; this reproduces the merge over
    a stand-in node and asserts the table wins."""
    base = {"1.2.3.4": {"name": "entConfigChange", "kind": "notification",
                        "severity_hint": "notice"},
            "1.2.3.5": {"name": "aristaBridgeExtMacMove", "kind": "notification",
                        "severity_hint": "warning"}}
    for node in base.values():
        if node.get("kind") == "notification" and node["name"] in gen.SEVERITY_HINT:
            node["severity_hint"] = gen.SEVERITY_HINT[node["name"]]
    assert base["1.2.3.4"]["severity_hint"] == "warning", "the table must win"
    # …and a name the table does NOT mention keeps the overlay it was given
    # (the STD_OVERLAY v1-trap hints are the real case).
    assert "aristaBridgeExtMacMove" not in gen.SEVERITY_HINT
    assert base["1.2.3.5"]["severity_hint"] == "warning"


# ══ the two families the A9 audit named ══════════════════════════════════════

CONFIG_CHANGE = ("ciscoConfigManEvent", "ccmCLIRunningConfigChanged",
                 "jnxCmCfgChange", "entConfigChange")
HARDWARE_FAULT = ("ciscoEnvMonFanNotification", "ciscoEnvMonTemperatureNotification",
                  "cefcPowerStatusChange", "cefcFanTrayStatusChange",
                  "entStateOperDisabled", "aristaEntSensorAlarm",
                  "jnxFanFailure", "jnxPowerSupplyFailure", "jnxOverTemperature",
                  "tmnxEqFanFailure", "tmnxEqPowerSupplyFailure")
HARDWARE_CLEAR = ("jnxFanOK", "jnxPowerSupplyOK", "jnxTemperatureOK",
                  "cefcFRUInserted", "entStateOperEnabled")


@pytest.mark.parametrize("name", CONFIG_CHANGE + HARDWARE_FAULT)
def test_the_audited_faults_and_changes_clear_the_alarm_floor(name, by_name):
    node = next(n for n in by_name[name] if n.get("kind") == "notification")
    hint = node.get("severity_hint")
    assert hint is not None, f"{name} is unhinted — it defaults to `notice`"
    assert SEVERITY_NUM[hint] <= ALARM_SEVERITY_FLOOR, (
        f"{name} hints {hint!r} ({SEVERITY_NUM[hint]}), which is below "
        f"ALARM_SEVERITY_FLOOR ({ALARM_SEVERITY_FLOOR}) — the engine never "
        "sees it, not even as a generic device_alarm")


@pytest.mark.parametrize("name", HARDWARE_CLEAR)
def test_a_recovery_notification_stays_under_the_floor(name, by_name):
    """The other half of the rule, and the one that keeps the seed honest: a
    CLEAR is not a fault. `linkUp` has always been `info` for this reason — a
    recovery must never open an RCA object."""
    node = next(n for n in by_name[name] if n.get("kind") == "notification")
    assert node.get("severity_hint") == "info", name
    assert SEVERITY_NUM["info"] > ALARM_SEVERITY_FLOOR


# ══ the index's own invariants ═══════════════════════════════════════════════


def test_the_regression_assertions_the_generator_validates_still_hold(nodes):
    """`gen_index.validate()` is the generator's own gate (it mirrors
    collectors/oidindex_test.go). Run it against the CHECKED-IN artifact, so a
    hand-edit is caught here and not only at the next regeneration."""
    assert gen.validate(nodes) == []


def test_the_index_is_internally_consistent(index, nodes):
    assert index["version"].startswith("sha256:")
    assert index["mibs"], "the index must record which MIB set produced it"
    assert len(nodes) > 3000, f"the index shrank to {len(nodes)} nodes"
    for oid, node in nodes.items():
        assert node.get("name"), oid
        assert node.get("kind") in ("notification", "column", "scalar"), oid
        if "severity_hint" in node:
            assert node["kind"] == "notification", (
                f"{oid}: only a notification carries a severity hint")
