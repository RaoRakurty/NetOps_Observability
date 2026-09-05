"""The panel↔metric audit's gNMI ownership gate — an EMPTY gate is now legal.

`scripts/audit_metric_contract.py` used to fail outright when the gnmic
`ownership-gate` parsed no delete patterns: an empty gate meant nothing was
withheld from the gNMI canonical lane, so every family with an SNMP counterpart
would be produced twice.

Since bb76e8e7 (tracker 230) the gate is empty BY DESIGN. The hand-back moved
from that global delete list to `SNMPMetric.Owner` in
`src/backend/collectors/profiles.go`, which is applied PER DEVICE — the global
gate had cost the gNMI-only SR Linux spines their interface, CPU and temperature
series entirely, because both sides withheld them.

So the audit must accept an empty gate — but ONLY while the guarantee the gate
used to carry still holds. That guarantee is what these tests pin:

  * an empty gate + every ungated family Owner "gnmi"        → clean
  * an empty gate + one family still SNMP-owned              → FAILS, named
  * a profiles.go the parse no longer understands            → FAILS (never
    vacuously clean — a silent empty owner map would make the check pass free)
  * the ownership-gate processor deleted from gnmic.yaml     → FAILS (it is the
    only mechanism for a future hand-back)
  * a non-empty gate still gets its stale-pattern guard

The audit is stdlib-only by contract (its CI job installs nothing), so it
re-implements the parse that `test_gnmi_ownership_contract.py` does with PyYAML.
Both read the same two real files, so neither can drift against a transcription
— and the test below asserts the two agree on the live tree.

Run:  python3 -m pytest tests/test_metric_contract_gnmi_gate.py -v
"""
from __future__ import annotations

import importlib.util
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = importlib.util.spec_from_file_location(
    "audit_metric_contract",
    os.path.join(ROOT, "scripts", "audit_metric_contract.py"))


def load_audit():
    """A FRESH module per test — every test rebinds GNMIC_YAML / PROFILES_GO to
    a fixture, and a shared module would leak that into the next one."""
    mod = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(mod)
    return mod


# A minimal gnmic.yaml carrying only what the audit parses: the canon-names
# rewrite targets and the ownership-gate processor. Written as text, not YAML,
# because the audit reads the file as text (stdlib, no PyYAML).
def gnmic_fixture(gate_patterns: list[str] | None, gate_present: bool = True) -> str:
    gate = ""
    if gate_present:
        gate = "  ownership-gate:\n    event-delete:\n      value-names:"
        if gate_patterns:
            gate += "\n" + "".join(f'        - "{p}"\n' for p in gate_patterns)
        else:
            gate += " []\n"
    return (
        "processors:\n"
        "  canon-names:\n"
        "    event-strings:\n"
        "      transforms:\n"
        "        - replace:\n"
        '            apply-on: "name"\n'
        '            old: ".*in-octets$"\n'
        '            new: "device_if_in_octets"\n'
        "        - replace:\n"
        '            apply-on: "name"\n'
        '            old: ".*cpu/utilization$"\n'
        '            new: "device_cpu_percent"\n'
        + gate +
        "  vendor-nokia:\n"
        "    event-add-tag: {}\n"
    )


def profiles_fixture(owners: dict[str, str]) -> str:
    """A builtinProfiles() literal in the shape the audit's regex expects."""
    rows = "".join(
        f'\t\t\t\t{{Name: "{fam}", OID: "1.3.6.1.2.1.1.1.0"'
        + (f', Owner: "{owner}"' if owner else "")
        + "},\n"
        for fam, owner in sorted(owners.items()))
    return (
        "package collectors\n\n"
        "func builtinProfiles() []SNMPProfile {\n"
        "\treturn []SNMPProfile{\n"
        "\t\t{\n"
        '\t\t\tName: "generic",\n'
        "\t\t\tMetrics: []SNMPMetric{\n"
        + rows +
        "\t\t\t},\n"
        "\t\t},\n"
        "\t}\n"
        "}\n"
    )


def run_lane(tmp_path, gnmic_text: str, profiles_text: str, snmp_emitted=None):
    mod = load_audit()
    g = tmp_path / "gnmic.yaml"
    g.write_text(gnmic_text)
    p = tmp_path / "profiles.go"
    p.write_text(profiles_text)
    mod.GNMIC_YAML = str(g)
    mod.PROFILES_GO = str(p)
    emitted = {"device_if_in_octets", "device_cpu_percent"} if snmp_emitted is None else snmp_emitted
    return mod.gnmi_canonical_lane(emitted)


# ── the fix: an empty gate is valid, but only when profiles.go carries it ─────

def test_empty_gate_is_clean_when_every_family_is_gnmi_owned(tmp_path):
    """The state the tree is actually in since bb76e8e7 — this is the CI failure
    the change removes."""
    emitted, problems = run_lane(
        tmp_path,
        gnmic_fixture([]),
        profiles_fixture({"device_if_in_octets": "gnmi", "device_cpu_percent": "gnmi"}))
    assert problems == [], f"an empty gate with a consistent owner mirror must pass: {problems}"
    assert emitted == {"device_if_in_octets", "device_cpu_percent"}, \
        "an empty gate withholds nothing, so every mapped family is emitted by gNMI"


def test_empty_gate_with_an_snmp_owned_family_still_fails(tmp_path):
    """The guarantee the old message existed to protect, re-proven by the new
    mechanism: with neither the gate nor the Owner withholding it, the family is
    produced twice on a dual-transport device."""
    _, problems = run_lane(
        tmp_path,
        gnmic_fixture([]),
        profiles_fixture({"device_if_in_octets": "gnmi", "device_cpu_percent": "snmp"}))
    joined = "\n".join(problems)
    assert "double-produce" in joined and "device_cpu_percent" in joined, \
        f"a family SNMP-owned outside the gate must be reported by name: {problems}"
    assert "device_if_in_octets" not in joined, \
        "the correctly gNMI-owned family must not be dragged into the failure"
    assert "ownership gate is EMPTY" in joined, \
        "the failure must say WHY an empty gate is not enough here"


def test_an_absent_owner_key_defaults_to_snmp_and_is_caught(tmp_path):
    """The default matters: a metric with no `Owner:` at all is SNMP-owned, so
    omitting the key is the same defect as writing Owner: "snmp"."""
    _, problems = run_lane(
        tmp_path,
        gnmic_fixture([]),
        profiles_fixture({"device_if_in_octets": "gnmi", "device_cpu_percent": ""}))
    assert any("device_cpu_percent" in p and "double-produce" in p for p in problems), \
        f"a missing Owner key must read as SNMP-owned, not as 'unknown, assume fine': {problems}"


# ── the guard may not pass vacuously ─────────────────────────────────────────

def test_an_unparseable_profiles_go_fails_rather_than_passing_free(tmp_path):
    """If the Go literal's shape changes, the owner map goes empty — and an empty
    map makes the double-produce check trivially true. That must be LOUD."""
    _, problems = run_lane(tmp_path, gnmic_fixture([]), "package collectors\n")
    assert any("builtinProfiles" in p for p in problems), \
        f"a stale profiles.go parse must be reported, not silently tolerated: {problems}"


def test_a_missing_profiles_go_fails(tmp_path):
    mod = load_audit()
    g = tmp_path / "gnmic.yaml"
    g.write_text(gnmic_fixture([]))
    mod.GNMIC_YAML = str(g)
    mod.PROFILES_GO = str(tmp_path / "does-not-exist.go")
    _, problems = mod.gnmi_canonical_lane({"device_if_in_octets", "device_cpu_percent"})
    assert any("profiles.go not found" in p for p in problems), problems


def test_deleting_the_ownership_gate_processor_fails(tmp_path):
    """An empty processor is exactly what gets tidied away as dead config — and
    then a future hand-back to SNMP silently does nothing. Same reasoning as
    test_the_gate_is_still_wired_into_every_canonical_chain."""
    _, problems = run_lane(
        tmp_path,
        gnmic_fixture(None, gate_present=False),
        profiles_fixture({"device_if_in_octets": "gnmi", "device_cpu_percent": "gnmi"}))
    assert any("ownership-gate" in p and "not in gnmic.yaml" in p for p in problems), \
        f"removing the gate processor must fail the audit: {problems}"


# ── a non-empty gate keeps every guard it had ────────────────────────────────

def test_a_populated_gate_still_withholds_and_still_rejects_a_stale_pattern(tmp_path):
    """Gating a family hands it back to SNMP: it leaves the gNMI emit set, and
    being SNMP-owned there is then correct rather than a double-produce."""
    emitted, problems = run_lane(
        tmp_path,
        gnmic_fixture(["^device_cpu_percent$"]),
        profiles_fixture({"device_if_in_octets": "gnmi", "device_cpu_percent": "snmp"}))
    assert problems == [], f"a gated, SNMP-owned family is the consistent state: {problems}"
    assert emitted == {"device_if_in_octets"}, \
        "a gated family must not count as gNMI-emitted"

    _, stale = run_lane(
        tmp_path,
        gnmic_fixture(["^device_cpu_percent$", "^device_nothing_matches_this$"]),
        profiles_fixture({"device_if_in_octets": "gnmi", "device_cpu_percent": "snmp"}))
    assert any("stale/dead gate entry" in p for p in stale), \
        f"the stale-pattern guard must survive the change: {stale}"


# ── and the audit must agree with the PyYAML mirror on the REAL tree ─────────

def test_the_audit_and_the_contract_test_read_the_live_tree_the_same_way():
    """Two parsers, two languages of the same two files. If they disagree, one of
    them is wrong about what ships — and the audit is the blocking one."""
    yaml = pytest.importorskip("yaml", reason="the audit is stdlib-only; the mirror test needs PyYAML")
    mod = load_audit()
    contract = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
        "gnmi_ownership_contract",
        os.path.join(ROOT, "tests", "test_gnmi_ownership_contract.py")))
    contract.__loader__.exec_module(contract)

    cfg = yaml.safe_load(open(contract.BASE_CFG))
    assert mod.snmp_family_owners()[0] == contract.snmp_owners(), \
        "the audit's stdlib owner parse and the contract test's disagree about profiles.go"

    audit_targets, problems = mod.gnmi_canonical_lane(mod.emitted_metrics())
    assert problems == [], f"the live tree must be a clean gNMI-lane contract: {problems}"
    assert audit_targets == contract.gnmic_canonical_families(cfg) - contract.gated_families(cfg), \
        "the audit and the contract test disagree about what the gNMI lane emits"
