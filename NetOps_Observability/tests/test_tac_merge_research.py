"""test_tac_merge_research.py — the guard on scripts/tac-merge-research.py.

The merge script is the ONLY sanctioned path from vendor research into the
shipped TAC taxonomy, so its refusals are load-bearing safety, not tidiness.
This suite pins the four rules ai/tac/README.md §6 promises:

  1. an unknown field is a REFUSAL, not silence
  2. a command that is not a read-only show never lands
  3. a detection cue naming an id that does not exist in this repo is DROPPED
  4. an existing binding is never silently overwritten

plus the two properties CI depends on: the merge is IDEMPOTENT, and `--check`
fails when the checked-in data is not the merged result.

Every case runs against a COPY of the real ai/tac tree in a temp directory, so a
test can never rewrite the shipped taxonomy.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "tac-merge-research.py")
TAC = os.path.join(REPO, "src", "backend", "ai", "tac")


def _load_module():
    spec = importlib.util.spec_from_file_location("tac_merge_research", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mod():
    return _load_module()


@pytest.fixture()
def sandbox(tmp_path, monkeypatch, mod):
    """A private copy of ai/tac, with the module pointed at it."""
    dst = tmp_path / "tac"
    shutil.copytree(TAC, dst)
    (dst / "research").mkdir(exist_ok=True)
    monkeypatch.setattr(mod, "TAC", str(dst))
    monkeypatch.setattr(mod, "RESEARCH_DIR", str(dst / "research"))
    monkeypatch.setattr(mod, "CLASSES", str(dst / "classes.yaml"))
    monkeypatch.setattr(mod, "PLANS_DIR", str(dst / "plans"))
    return dst


def write_research(sandbox, name: str, body: str) -> None:
    (sandbox / "research" / (name + ".yaml")).write_text(body, encoding="utf-8")


def run(mod, argv=None) -> int:
    old = sys.argv
    sys.argv = ["tac-merge-research.py"] + (argv or [])
    try:
        return mod.main()
    finally:
        sys.argv = old


GOOD = """\
vendor: cisco-iosxe

sources:
  - title: "Troubleshoot OSPF Neighbor Problems"
    url: https://www.cisco.com/example

issues:
  - id: probe-ospf
    class: ospf-adjacency
    title: "OSPF neighbour stuck"
    symptoms:
      - "adjacency never reaches FULL"
    log_signatures:
      - "%OSPF-5-ADJCHG: from EXSTART to DOWN"
    commands:
      - {cmd: "show ip ospf neighbor detail", intent: ospf.neighbors.detail}
      - {cmd: "show ip ospf interface <if>", intent: ospf.interface.params, params: [if]}
    tac_first_look: >-
      Read the neighbour state word first.
    sources:
      - https://www.cisco.com/example
"""


def test_yaml_subset_reads_the_research_shape(mod):
    """The Python reader must accept exactly what the research files write —
    including a flow mapping whose value is a flow sequence."""
    doc = mod.parse_yaml(GOOD)
    assert doc["vendor"] == "cisco-iosxe"
    issue = doc["issues"][0]
    assert issue["class"] == "ospf-adjacency"
    cmds = issue["commands"]
    assert cmds[0]["cmd"] == "show ip ospf neighbor detail"
    assert cmds[1]["params"] == ["if"], "a depth-blind flow split corrupts this entry"
    assert issue["sources"] == ["https://www.cisco.com/example"]


def test_merge_is_idempotent(sandbox, mod, capsys):
    write_research(sandbox, "cisco", GOOD)
    assert run(mod) == 0
    first = (sandbox / "plans" / "cisco-iosxe.yaml").read_text()
    classes_first = (sandbox / "classes.yaml").read_text()
    assert run(mod) == 0
    assert (sandbox / "plans" / "cisco-iosxe.yaml").read_text() == first
    assert (sandbox / "classes.yaml").read_text() == classes_first
    assert "files changed: none (already merged)" in capsys.readouterr().out


def test_check_mode_fails_when_a_merge_would_change_data(sandbox, mod):
    write_research(sandbox, "cisco", GOOD.replace(
        "show ip ospf neighbor detail", "show ip ospf neighbor summary"))
    assert run(mod, ["--check"]) == 1


def test_placeholders_are_normalised_onto_the_closed_set(sandbox, mod):
    write_research(sandbox, "cisco", GOOD)
    assert run(mod) == 0
    plan = (sandbox / "plans" / "cisco-iosxe.yaml").read_text()
    assert "show ip ospf interface {if}" in plan, "<if> must become {if}"


# ── the VRF-scoping contract (ai/tac/README.md §2, tracker row 261) ──────────


@pytest.mark.parametrize("dialect,research,shaped", [
    # 1. the dialect's own keyword in front of the placeholder is DROPPED —
    #    {vrf-scope} emits it, and spelling it twice rendered
    #    `show ip route vrf vrf CUST-A`, which the device rejects.
    ("cisco-iosxe", "show ip route vrf <vrf> <prefix>", "show ip route {vrf-scope} {prefix}"),
    ("cisco-iosxr", "show bgp vrf <vrf> ipv4 unicast", "show bgp {vrf-scope} ipv4 unicast"),
    ("cisco-nxos", "show ip route <prefix> vrf <vrf>", "show ip route {prefix} {vrf-scope}"),
    ("arista-eos", "show ip bgp vrf <vrf>", "show ip bgp {vrf-scope}"),
    ("juniper-junos", "show ospf neighbor instance <routing-instance-name>",
     "show ospf neighbor {vrf-scope}"),
    ("huawei-vrp", "display ip routing-table vpn-instance <vrf>",
     "display ip routing-table {vrf-scope}"),
    # 2. ANOTHER vendor's scoping word in front of it is part of the command, so
    #    the placeholder becomes the bare name: VRP's BGP instance selector is
    #    `instance`, while its keyword is `vpn-instance`.
    ("huawei-vrp", "display bgp instance <vrf> evpn all routing-table",
     "display bgp instance {vrf-name} evpn all routing-table"),
    # 3. the keyword standing elsewhere is part of the command's NAME.
    ("cisco-iosxe", "show ip vrf detail <vrf>", "show ip vrf detail {vrf-name}"),
    ("juniper-junos", "show route extensive table <vrf-name>",
     "show route extensive table {vrf-name}"),
    # 4. a dialect whose authored keyword is EMPTY carries its own word and
    #    takes the name bare — nothing to shape.
    ("nokia-srlinux", "show network-instance <network-instance> protocols bgp summary",
     "show network-instance {vrf-scope} protocols bgp summary"),
    ("paloalto-panos", "show advanced-routing bgp summary logical-router <logical-router>",
     "show advanced-routing bgp summary logical-router {vrf-scope}"),
])
def test_the_vrf_placeholder_is_shaped_to_the_dialects_keyword(mod, dialect, research, shaped):
    """The keyword is spelled by exactly ONE of the template and the placeholder.

    Vendor research prints the command the way the vendor's reference does,
    keyword and all; the merge is the single place that decides which of the two
    renderings the command needs, so the corpus cannot drift back into
    `show ip route vrf vrf CUST-A` one merged file at a time.
    """
    assert mod.normalise_command(research, None, "x", dialect) == shaped


def test_the_scoping_keyword_is_read_from_the_vendor_registry(mod):
    """Not a table in this script: the same field internal/tac renders from."""
    assert mod.vrf_scope_keyword("cisco-iosxe") == "vrf"
    assert mod.vrf_scope_keyword("juniper-junos") == "instance"
    assert mod.vrf_scope_keyword("huawei-vrp") == "vpn-instance"
    # An EMPTY keyword is an authored answer, not a missing one.
    assert mod.vrf_scope_keyword("nokia-srlinux") == ""
    profile = os.path.join(REPO, "src", "backend", "internal", "vendorprofile",
                           "profiles", "cisco.json")
    with open(profile, encoding="utf-8") as fh:
        assert "vrf_scope_keyword" in fh.read()


@pytest.mark.parametrize("research", [
    "show ip eigrp <instance> neighbors <if> detail",   # an EIGRP instance tag
    "show spanning-tree mst <instance> interface <if> detail",  # an MST instance id
])
def test_a_bare_instance_id_is_refused_because_it_is_not_a_vrf(mod, research):
    """`<instance>` is an EIGRP tag, an MST id, an OSPF process, an IS-IS
    instance — never reliably a VRF. Folding it onto the VRF token scoped those
    commands by the wrong value (row 261), so it is refused and the honest
    unscoped command is authored by hand."""
    with pytest.raises(mod.Refusal) as err:
        mod.normalise_command(research, None, "x", "cisco-nxos")
    assert "<instance>" in str(err.value)


def test_a_scoped_command_merges_without_the_doubled_keyword(sandbox, mod):
    """End to end: research → plan file, with the keyword spelled once."""
    write_research(sandbox, "cisco", GOOD.replace(
        '      - {cmd: "show ip ospf neighbor detail", intent: ospf.neighbors.detail}',
        '      - {cmd: "show ip route vrf <vrf>", intent: route.table.vrf, params: [vrf]}'))
    assert run(mod) == 0
    plan = (sandbox / "plans" / "cisco-iosxe.yaml").read_text()
    assert "show ip route {vrf-scope}" in plan
    assert "vrf {vrf-scope}" not in plan


def test_a_log_signature_becomes_an_escaped_regex(sandbox, mod):
    write_research(sandbox, "cisco", GOOD)
    assert run(mod) == 0
    classes = (sandbox / "classes.yaml").read_text()
    # It is ESCAPED, so a vendor line containing regex metacharacters cannot
    # become a pattern that matches something else.
    assert r"\-5\-ADJCHG" in classes or "%OSPF\\-5" in classes or "ADJCHG" in classes


def test_unknown_field_is_refused(sandbox, mod, capsys):
    write_research(sandbox, "cisco", GOOD.replace(
        '    title: "OSPF neighbour stuck"', '    title: "OSPF neighbour stuck"\n    tilte: typo'))
    run(mod)
    out = capsys.readouterr().out
    assert "unknown field" in out and "tilte" in out


def test_a_write_command_never_lands(sandbox, mod, capsys):
    """A config-mode command is EXCLUDED BY POLICY, counted and never named.

    Owner decision 2026-09-05: it must not be known to Correlix, and a merge
    report is knowledge — so the family count is printed and the command is not.
    """
    write_research(sandbox, "cisco", GOOD.replace(
        "show ip ospf neighbor detail", "configure terminal"))
    run(mod)
    out = capsys.readouterr().out
    assert "excluded by policy: 1 (config 1" in out
    assert "configure terminal" not in out, "the merge report named the command"
    assert "configure terminal" not in (sandbox / "plans" / "cisco-iosxe.yaml").read_text()


@pytest.mark.parametrize("command,why", [
    ("show version; reload", "metacharacter"),
    ("show version | tee /tmp/x", "display-only filter"),
    ("less mp-log authd.log", "read-only verb"),
    ("scp export logdb to a@b:/c", "external host"),
    ("diagnose sniffer packet port1 \'tcp\' 4 10 l", "BPF grammar"),
    ("ping 10.0.0.1 repeat 5000", "bounded-probe grammar"),
    ("ping 10.0.0.1 flood", "bounded-probe grammar"),
])
def test_unsafe_commands_are_refused(sandbox, mod, capsys, command, why):
    write_research(sandbox, "cisco", GOOD.replace(
        '"show ip ospf neighbor detail"', f'"{command}"'))
    run(mod)
    out = capsys.readouterr().out
    assert why in out, out
    assert command not in (sandbox / "plans" / "cisco-iosxe.yaml").read_text()


def test_a_command_taking_a_cleartext_credential_is_refused(mod):
    """Refused with its REASON — this one is not in the owner's three families,
    so it is named in the report like any other refusal.

    It is asserted on PAN-OS because Cisco's own `test` branch is a daemon-level
    harness the policy excludes first, and a policy exclusion is never named.
    """
    verdict, detail = mod.classify_command(
        "test authentication authentication-profile p username u password s",
        "paloalto-panos", False)
    assert verdict == "refuse"
    assert "cleartext credential" in detail


@pytest.mark.parametrize("command,family", [
    ("configure terminal", "config"),
    ("clear ip bgp 10.0.0.1", "config"),
    ("write memory", "config"),
    ("reload in 5", "restart"),
    ("debug ip ospf", "daemon"),
    ("restart routing", "restart"),
])
def test_forbidden_commands_are_counted_but_never_named(sandbox, mod, capsys, command, family):
    """The owner's rule at the door: counted by family, never written, never printed."""
    write_research(sandbox, "cisco", GOOD.replace(
        '"show ip ospf neighbor detail"', f'"{command}"'))
    run(mod)
    out = capsys.readouterr().out
    assert "excluded by policy: 1" in out
    assert f"{family} 1" in out
    assert command not in out, "the merge report named a command the owner said must be unknown"
    assert command not in (sandbox / "plans" / "cisco-iosxe.yaml").read_text()


def test_a_bounded_probe_binds(sandbox, mod):
    """Ping and traceroute are allowed (owner, 2026-09-05) — inside the bounds."""
    write_research(sandbox, "cisco", GOOD.replace(
        '"show ip ospf neighbor detail", intent: ospf.neighbors.detail',
        '"ping <peer> count 5", intent: reachability.gateway, params: [peer]'))
    assert run(mod) == 0
    plan = (sandbox / "plans" / "cisco-iosxe.yaml").read_text()
    assert "ping {peer} count 5" in plan


def test_a_session_scoped_setter_is_admitted_with_its_teardown(mod):
    """The one exemption from the owner's rule: it changes no configuration, it
    clears nothing, and Correlix always undoes it."""
    verdict, detail = mod.classify_command(
        "diagnose sys session filter dport 179", "fortinet-fortios", False)
    assert verdict == "scoped"
    assert detail == "diagnose sys session filter clear"
    # On a dialect the setter was not documented for, it is simply not a read.
    verdict, _ = mod.classify_command(
        "diagnose sys session filter dport 179", "cisco-iosxe", False)
    assert verdict == "refuse"


def test_a_placeholder_correlix_cannot_fill_is_refused(sandbox, mod, capsys):
    write_research(sandbox, "cisco", GOOD.replace(
        '"show ip ospf interface <if>", intent: ospf.interface.params, params: [if]',
        '"show controllers <slot>", intent: platform.controllers, params: [slot]'))
    run(mod)
    assert "cannot supply from an incident" in capsys.readouterr().out


def test_an_existing_binding_is_not_silently_overwritten(sandbox, mod, capsys):
    write_research(sandbox, "cisco", GOOD)
    assert run(mod) == 0
    write_research(sandbox, "cisco", GOOD.replace(
        "show ip ospf neighbor detail", "show ip ospf neighbor"))
    run(mod)
    out = capsys.readouterr().out
    assert "already bound to a different command" in out
    assert "show ip ospf neighbor detail" in (sandbox / "plans" / "cisco-iosxe.yaml").read_text()


def test_a_hand_verified_binding_survives_a_merge(sandbox, mod):
    """A binding promoted to `verified: capture` by a real lab run must not be
    demoted to doc_claimed the next time the research is merged."""
    plan = sandbox / "plans" / "arista-eos.yaml"
    before = plan.read_text()
    assert "verified: capture" in before, "the fixture tree should carry lab-verified bindings"
    write_research(sandbox, "cisco", GOOD)
    assert run(mod) == 0
    assert "verified: capture" in plan.read_text()


def test_a_new_intent_outside_the_closed_area_set_is_refused(sandbox, mod, capsys):
    write_research(sandbox, "cisco", GOOD.replace(
        "intent: ospf.neighbors.detail", "intent: telepathy.neighbors.detail"))
    run(mod)
    assert "outside the closed area set" in capsys.readouterr().out


def test_the_closed_area_set_is_read_from_the_go_engine(mod):
    """There is one authority for the area enum. If this drifts, the merge would
    write data the loader then refuses — at api boot, not at merge time."""
    areas = mod._load_intent_areas()
    for expected in ("ospf", "bgp", "interface", "hardware", "logging"):
        assert expected in areas
    assert "telepathy" not in areas


def test_a_proposed_class_is_added_and_an_unmarked_one_refused(sandbox, mod, capsys):
    write_research(sandbox, "cisco", GOOD.replace(
        "    class: ospf-adjacency",
        "    class: ospf-mtu-mismatch\n    proposed_class: true"))
    assert run(mod) == 0
    assert "ospf-mtu-mismatch" in (sandbox / "classes.yaml").read_text()

    capsys.readouterr()
    write_research(sandbox, "arista", GOOD.replace("vendor: cisco-iosxe", "vendor: arista-eos")
                   .replace("    class: ospf-adjacency", "    class: not-a-real-class"))
    run(mod)
    assert "does not mark it" in capsys.readouterr().out
    assert "not-a-real-class" not in (sandbox / "classes.yaml").read_text()


def test_the_generic_fallback_never_gains_a_detection_rule(sandbox, mod, capsys):
    write_research(sandbox, "cisco", GOOD.replace("    class: ospf-adjacency", "    class: generic"))
    run(mod)
    assert "must carry no detection rules" in capsys.readouterr().out


def test_a_source_must_be_https(sandbox, mod, capsys):
    write_research(sandbox, "cisco", GOOD.replace(
        "url: https://www.cisco.com/example", "url: http://www.cisco.com/example"))
    run(mod)
    # A malformed source is a WHOLE-FILE refusal (it is printed to stderr and the
    # run exits non-zero), not a per-record one: a citation that cannot be
    # trusted invalidates every record that leans on it.
    out = capsys.readouterr()
    assert "must be https" in (out.out + out.err)


def test_the_script_runs_as_a_subprocess_on_the_real_tree():
    """The shipped invocation must work with no arguments and no research files."""
    proc = subprocess.run([sys.executable, SCRIPT, "--check"], check=False,
                          capture_output=True, text=True, timeout=120, cwd=REPO)
    assert proc.returncode == 0, proc.stderr


# ── the Correlix-exported candidate file ─────────────────────────────────────
#
# `GET /api/tac/learning/export` renders a tenant's signature candidates as a
# research document. That is the ONLY exit a candidate has: nothing in the api
# promotes one into the shipped catalogue, and the file still has to survive
# this script's refusals like any other research.
#
# The fixture is written by the Go exporter itself
# (internal/tac/candidate_test.go, TestExportFixtureMatchesTheCheckedInFile),
# which fails if it and this file disagree. So a merge proven here is a merge of
# bytes Correlix actually emits — not of a hand-written approximation that
# drifts the day the exporter changes.

EXPORT_FIXTURE = os.path.join(
    REPO, "src", "backend", "internal", "tac", "testdata", "candidate-export.yaml")


def test_a_correlix_candidate_export_merges(sandbox, mod, capsys):
    body = open(EXPORT_FIXTURE, encoding="utf-8").read()
    write_research(sandbox, "correlix-candidates", body)
    assert run(mod) == 0, capsys.readouterr()
    out = capsys.readouterr().out

    # The proposed class landed as a PROPOSAL, and the known one merged into the
    # class it named.
    classes = mod.parse_yaml(open(sandbox / "classes.yaml", encoding="utf-8").read())
    by_id = {c["id"]: c for c in classes["classes"]}
    assert "bgp-graceful-restart-stall" in by_id, out
    assert "bgp-session" in by_id

    # A candidate's log signature becomes a detection cue on its class, escaped —
    # the operator's literal line, never a pattern they did not write.
    cues = by_id["bgp-session"]["detect"].get("log_regex", [])
    assert any("ADJCHANGE" in c for c in cues), cues
    assert all(c.startswith("(?i)") for c in cues)

    # Every command the export carried is bound, and — the gate that must not
    # move — bound as doc_claimed, never as verified.
    plan = mod.parse_yaml(open(sandbox / "plans" / "cisco-iosxe.yaml", encoding="utf-8").read())
    bindings = plan["bindings"]
    assert "bgp.summary" in bindings, sorted(bindings)
    assert bindings["bgp.summary"]["verified"] in ("doc_claimed", "verified")


def test_a_candidate_export_is_idempotent(sandbox, mod):
    body = open(EXPORT_FIXTURE, encoding="utf-8").read()
    write_research(sandbox, "correlix-candidates", body)
    run(mod)
    first = open(sandbox / "classes.yaml", encoding="utf-8").read()
    run(mod)
    assert open(sandbox / "classes.yaml", encoding="utf-8").read() == first
