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
    write_research(sandbox, "cisco", GOOD.replace(
        "show ip ospf neighbor detail", "configure terminal"))
    run(mod)
    out = capsys.readouterr().out
    assert "state-changing command" in out or "read-only verb" in out
    assert "configure terminal" not in (sandbox / "plans" / "cisco-iosxe.yaml").read_text()


@pytest.mark.parametrize("command,why", [
    ("show version; reload", "metacharacter"),
    ("show version | tee /tmp/x", "display-only filter"),
    ("debug ip ospf", "read-only verb"),
    ("ping 10.0.0.1", "transmits from the device"),
    ("test authentication authentication-profile p username u password s", "cleartext credential"),
    ("scp export logdb to a@b:/c", "external host"),
    ("diagnose sniffer packet port1 'tcp' 4 10 l", "BPF grammar"),
    ("diagnose test application ipsmonitor 99", "restart the daemon"),
    ("diagnose sys session filter dst 10.0.0.1", "daemon-side read scope"),
])
def test_unsafe_commands_are_refused(sandbox, mod, capsys, command, why):
    write_research(sandbox, "cisco", GOOD.replace(
        '"show ip ospf neighbor detail"', '"%s"' % command))
    run(mod)
    out = capsys.readouterr().out
    assert why in out, out
    assert command not in (sandbox / "plans" / "cisco-iosxe.yaml").read_text()


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
    proc = subprocess.run([sys.executable, SCRIPT, "--check"],
                          capture_output=True, text=True, timeout=120, cwd=REPO)
    assert proc.returncode == 0, proc.stderr
