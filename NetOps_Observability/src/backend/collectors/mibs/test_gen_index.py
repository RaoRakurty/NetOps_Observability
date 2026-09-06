# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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

import hashlib
import importlib.util
import json
import os
import re

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


# ══ the pinned, checksum-verified fetch (licence audit D4) ═══════════════════
#
# WHY THIS BLOCK EXISTS. ARISTA-SMI-MIB and ARISTA-BRIDGE-EXT-MIB are NOT
# redistributed by this repo (no licence grant), so they are fetched at build
# time into a gitignored cache. That turns a file that was simply present into a
# network dependency, and the failure mode of a network dependency is a silent
# skip — exactly the class scripts/CLAUDE.md §16.1 exists to kill. These tests
# pin the fail-closed behaviour instead of trusting the code to have it.
#
# None of them touch the network: `_download` is stubbed everywhere it matters.

_BODY = b"-- a stand-in MIB module\nX-MIB DEFINITIONS ::= BEGIN\nEND\n"
_BODY_SHA = hashlib.sha256(_BODY).hexdigest()


@pytest.fixture()
def fetch_env(tmp_path, monkeypatch):
    """Point the fetcher at a temp cache with one pinned module, no network."""
    monkeypatch.setattr(gen, "FETCHED", str(tmp_path / ".fetched"))
    monkeypatch.setattr(gen, "FETCH_PINS", {
        "X-MIB": {"sha256": _BODY_SHA, "urls": ("https://example.invalid/X-MIB",)},
    })
    monkeypatch.delenv("MIB_FETCH", raising=False)
    return tmp_path / ".fetched"


def test_a_verified_download_is_cached_and_reused(fetch_env, monkeypatch):
    calls: list[str] = []

    def fake(url: str) -> bytes:
        calls.append(url)
        return _BODY

    monkeypatch.setattr(gen, "_download", fake)
    assert gen.fetch_pinned_mibs() == (["X-MIB"], [])
    assert (fetch_env / "X-MIB").read_bytes() == _BODY
    # Second run must verify the cache, not re-download it.
    assert gen.fetch_pinned_mibs() == (["X-MIB"], [])
    assert len(calls) == 1


def test_a_download_that_does_not_match_the_pin_is_fatal_and_leaves_no_file(
        fetch_env, monkeypatch):
    """THE POINT OF THE PIN. A mirror that moved must never reach the parser,
    and a rejected body must not be left behind as a half-trusted cache entry."""
    monkeypatch.setattr(gen, "_download", lambda url: b"-- something else\n")
    with pytest.raises(gen.FetchError) as err:
        gen.fetch_pinned_mibs()
    assert "re-pin" in str(err.value) and _BODY_SHA in str(err.value)
    assert not (fetch_env / "X-MIB").exists()


def test_an_edited_cache_file_is_fatal_on_the_next_run(fetch_env, monkeypatch):
    """Never trust cached data without validation (CLAUDE.md §3)."""
    monkeypatch.setattr(gen, "_download", lambda url: _BODY)
    gen.fetch_pinned_mibs()
    (fetch_env / "X-MIB").write_bytes(_BODY + b"-- injected\n")
    with pytest.raises(gen.FetchError) as err:
        gen.fetch_pinned_mibs()
    assert "stale or tampered" in str(err.value)


def test_an_unreachable_mirror_is_fatal_rather_than_a_silent_skip(
        fetch_env, monkeypatch):
    """`no network` must NOT be indistinguishable from `nothing to do` — and the
    error has to name the way out, or the operator is stuck."""
    def boom(url: str) -> bytes:
        raise gen.FetchError(f"{url}: URLError: unreachable")

    monkeypatch.setattr(gen, "_download", boom)
    with pytest.raises(gen.FetchError) as err:
        gen.fetch_pinned_mibs()
    assert "unreachable" in str(err.value)
    assert "MIB_FETCH=0" in str(err.value)


def test_only_an_explicit_opt_out_degrades_without_failing(fetch_env, monkeypatch):
    """The ONE non-fatal path, and it is a declaration by the operator — the
    caller reports it (`gen_index: WARNING …`) rather than swallowing it."""
    def never(url: str) -> bytes:
        raise AssertionError("MIB_FETCH=0 must not touch the network")

    monkeypatch.setattr(gen, "_download", never)
    monkeypatch.setenv("MIB_FETCH", "0")
    assert gen.fetch_pinned_mibs() == ([], ["X-MIB"])


def test_a_pin_without_a_usable_sha256_is_refused(fetch_env, monkeypatch):
    """A pin is the whole trust anchor; an empty or malformed one is not a
    'best effort', it is an unverified download."""
    monkeypatch.setattr(gen, "_download", lambda url: _BODY)
    for bad in ("", "deadbeef", "Z" * 64, _BODY_SHA.upper()):
        monkeypatch.setattr(gen, "FETCH_PINS", {
            "X-MIB": {"sha256": bad, "urls": ("https://example.invalid/X-MIB",)}})
        with pytest.raises(gen.FetchError, match="no usable sha256 pin"):
            gen.fetch_pinned_mibs()


def test_a_non_https_pin_is_refused_before_any_request(fetch_env):
    with pytest.raises(gen.FetchError, match="not https"):
        gen._download("http://example.invalid/X-MIB")


def test_the_real_pins_are_well_formed_and_https():
    """Guards the checked-in table itself, not a fixture."""
    assert set(gen.FETCH_PINS) == {"ARISTA-SMI-MIB", "ARISTA-BRIDGE-EXT-MIB"}, (
        "the fetch table is the licence boundary — adding to it is a licence "
        "decision, so it is pinned here deliberately")
    for mod, pin in gen.FETCH_PINS.items():
        assert re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]), mod
        assert pin["urls"], mod
        for url in pin["urls"]:
            assert url.startswith("https://"), f"{mod}: {url}"


def test_the_arista_mibs_are_not_redistributed_in_the_tree(fetch_env):
    """Licence audit D4: these two must NOT come back into `vendored/`, which
    is checked in and ships in the customer source tarball."""
    for mod in gen.FETCH_PINS:
        assert not os.path.exists(os.path.join(gen.VENDORED, mod)), (
            f"{mod} is vendored again — it carries no redistribution grant; it "
            "belongs in the gitignored .fetched/ cache")


def test_the_netsnmp_search_path_includes_the_fetch_cache(fetch_env, monkeypatch):
    """The whole point of the cache: the SMIv1 pass must actually see it."""
    monkeypatch.setattr(gen, "_download", lambda url: _BODY)
    gen.fetch_pinned_mibs()
    dirs = gen.netsnmp_mib_dirs()
    assert dirs[0] == gen.VENDORED, "the vendored tree stays authoritative/first"
    assert str(fetch_env) in dirs


def test_the_arista_v1_traps_survive_with_no_network_at_all(nodes):
    """The honest no-network claim, asserted rather than asserted-in-prose: the
    30065.3.2.0.x MAC-move traps are hand-anchored in STD_OVERLAY, so they need
    no MIB file and stay ABOVE the alarm floor even on an offline build."""
    for oid in ("1.3.6.1.4.1.30065.3.2.0.1", "1.3.6.1.4.1.30065.3.2.0.2"):
        overlay = gen.STD_OVERLAY[oid]
        assert overlay["name"] == "aristaBridgeExtMacMove"
        assert SEVERITY_NUM[overlay["severity_hint"]] <= ALARM_SEVERITY_FLOOR
        assert nodes[oid]["name"] == overlay["name"]


def test_the_ietf_modules_replaced_the_cisco_extracts(fetch_env):
    """Licence audit D3: SNMPv2-TC/CONF must be the RFC text, not Cisco's."""
    for name, rfc in (("SNMPv2-TC", "2579"), ("SNMPv2-CONF", "2580")):
        with open(os.path.join(gen.VENDORED, name), encoding="utf-8") as fh:
            text = fh.read()
        assert "cisco Systems" not in text, f"{name} is the Cisco extract again"
        assert f"RFC {rfc}" in text and "trustee.ietf.org/license-info" in text
        assert f"{name} DEFINITIONS ::= BEGIN" in text
        # An SMI comment ends at the SECOND `--` on a line: a second one in the
        # licence header silently turns the rest into live tokens and net-snmp
        # then fails to register the module at all (observed, not theorised).
        # Only the header we wrote is checked — inside the module, `-----` runs
        # appear in quoted DESCRIPTION text, where comment rules do not apply.
        header = text.split(f"{name} DEFINITIONS ::= BEGIN", 1)[0]
        for lineno, line in enumerate(header.split("\n"), 1):
            if line.startswith("--"):
                assert line.count("--") == 1, (
                    f"{name}:{lineno}: a second `--` closes the comment and the "
                    f"rest of the line becomes live tokens: {line!r}")
