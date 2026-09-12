# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""test_tac_forbidden_policy.py — the guard on the OUTPUT-ONLY command policy.

Owner decision, 2026-09-05: a command that changes configuration, that restarts
or reboots, or that touches a daemon must not merely be refused — it must not be
KNOWN to Correlix at all. `src/backend/ai/tac/forbidden.yaml` is that rule as
data, and this suite proves the enforcement is structural rather than a habit:

  1. `scripts/tac-purge-forbidden.py --check` passes over the WHOLE corpus,
     research files included — nothing forbidden is carried anywhere;
  2. the policy matches on TOKENS, so `show reload cause` stays allowed;
  3. ping and traceroute are allowed, inside the bounds, and a flood is not;
  4. the Python matcher and the Go one (internal/tac/forbidden.go,
     internal/protocoldiag/probe.go) agree on the bounds and the families;
  5. the purge is idempotent, and a forbidden record put back is removed again
     WITHOUT its text appearing in the report.

The Go half is tested in `internal/tac/forbidden_test.go`; this is the half that
runs the scripts.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
PURGE = os.path.join(SCRIPTS, "tac-purge-forbidden.py")
MERGE = os.path.join(SCRIPTS, "tac-merge-research.py")
TAC = os.path.join(REPO, "src", "backend", "ai", "tac")
FORBIDDEN = os.path.join(TAC, "forbidden.yaml")
GO_TAC = os.path.join(REPO, "src", "backend", "internal", "tac")
GO_PROBE = os.path.join(REPO, "src", "backend", "internal", "protocoldiag", "probe.go")

if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import tac_forbidden


def _merge_module():
    spec = importlib.util.spec_from_file_location("tac_merge_research", MERGE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def policy():
    mod = _merge_module()
    with open(FORBIDDEN, encoding="utf-8") as fh:
        return tac_forbidden.load_policy(mod.parse_yaml(fh.read()))


# ── (1) the corpus is clean ─────────────────────────────────────────────────


def test_check_passes_over_the_whole_corpus():
    """The shipped invocation, over the real tree, including research/*.yaml."""
    proc = subprocess.run([sys.executable, PURGE, "--check"], check=False,
                          capture_output=True, text=True, timeout=180, cwd=REPO)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "excluded by policy: 0" in proc.stdout


def test_the_census_is_present_and_adds_up(policy):
    census = policy.census
    total = int(census["total"])
    by_family = census["by_family"]
    assert total == sum(int(by_family[f]) for f in tac_forbidden.FAMILIES)
    rows = census.get("by_dialect") or []
    for row in rows:
        assert int(row["total"]) == sum(int(row[f]) for f in tac_forbidden.FAMILIES)
    assert sum(int(r["total"]) for r in rows) <= total


# ── (2) tokens, not substrings ──────────────────────────────────────────────


@pytest.mark.parametrize("dialect,command", [
    ("cisco-iosxe", "show reload"),
    ("cisco-nxos", "show system internal ethpm event-history"),
    ("cisco-iosxr", "show processes cpu"),
    ("cisco-iosxr", "admin show platform"),
    ("juniper-junos", "show system processes extensive"),
    ("nokia-srlinux", "info from state interface ethernet-1/1"),
    ("huawei-vrp", "display cpu-usage"),
    ("fortinet-fortios", "get system status"),
    ("fortinet-fortios", "diagnose debug crashlog read"),
    ("fortinet-fortios", "execute log display"),
    ("paloalto-panos", "request license info"),
    ("arista-eos", "show agent Rib logs"),
])
def test_output_commands_stay_allowed(policy, dialect, command):
    assert policy.match(dialect, command) is None, command


@pytest.mark.parametrize("dialect,command,family", [
    ("cisco-iosxe", "configure terminal", "config"),
    ("cisco-iosxe", "clear counters", "config"),
    ("cisco-iosxe", "reload", "restart"),
    ("cisco-iosxe", "debug ip ospf hello", "daemon"),
    ("cisco-nxos", "system internal ethpm restart", "daemon"),
    ("juniper-junos", "request system reboot", "restart"),
    ("juniper-junos", "restart routing", "daemon"),
    ("nokia-sros", "admin reboot", "restart"),
    ("nokia-srlinux", "tools system app-management application bgp_mgr restart", "daemon"),
    ("huawei-vrp", "reset bgp all", "config"),
    ("huawei-vrp", "pads diagnose", "daemon"),
    ("fortinet-fortios", "diagnose test application miglogd 6", "daemon"),
    ("fortinet-fortios", "execute reboot", "restart"),
    ("paloalto-panos", "debug dnsproxyd show sys-statistics", "daemon"),
])
def test_forbidden_commands_land_in_the_right_family(policy, dialect, command, family):
    rule = policy.match(dialect, command)
    assert rule is not None, command
    assert rule.family == family, f"{command} → {rule.family} (rule {rule})"


def test_an_unknown_dialect_still_gets_the_common_rules(policy):
    for command in ("reload", "configure terminal", "write memory", "kill 1"):
        assert policy.match("some-unknown-os", command) is not None


def test_no_rule_begins_with_a_read_verb(policy):
    for rule in policy.rules():
        assert rule.tokens[0] not in tac_forbidden.READ_LEADS, str(rule)


# ── (3) ping and traceroute, bounded ────────────────────────────────────────


@pytest.mark.parametrize("command", [
    "ping 192.0.2.1",
    "ping 192.0.2.1 repeat 5 size 1500 df-bit",
    "ping 192.0.2.1 vrf management",
    "traceroute 192.0.2.1 ttl 30 probe 3",
    "execute ping 192.0.2.1",
    "ping count 5 host 192.0.2.1",
    "ping {peer}",
])
def test_a_bounded_probe_is_allowed(command):
    assert tac_forbidden.is_probe_command(command)
    assert tac_forbidden.validate_bounded_probe(command) == " ".join(command.split())


@pytest.mark.parametrize("command", [
    "ping",
    "ping 192.0.2.1 repeat 100",
    "ping 192.0.2.1 size 18000",
    "ping 192.0.2.1 flood",
    "ping 192.0.2.1 sweep 100 2000 1",
    "ping 192.0.2.1 count 5 rapid",
    "ping 192.0.2.1 pattern 0xdeadbeef",
    "traceroute 192.0.2.1 ttl 255",
    "ping 192.0.2.1; reload",
])
def test_an_unbounded_probe_is_refused(command):
    with pytest.raises(tac_forbidden.ProbeRefusal):
        tac_forbidden.validate_bounded_probe(command)


def test_a_probe_is_never_forbidden_by_the_policy(policy):
    for dialect in ("cisco-iosxe", "fortinet-fortios", "juniper-junos", "nokia-sros"):
        for command in ("ping 192.0.2.1", "traceroute 192.0.2.1", "execute ping 192.0.2.1"):
            assert policy.match(dialect, command) is None, (dialect, command)


# ── (4) the Python and Go halves agree ──────────────────────────────────────


def test_the_probe_bounds_match_the_go_grammar():
    """One rule, two implementations: the numbers must be the same numbers."""
    with open(GO_PROBE, encoding="utf-8") as fh:
        src = fh.read()
    for name, want in (("MaxProbeCount", tac_forbidden.MAX_PROBE_COUNT),
                       ("MaxProbeSize", tac_forbidden.MAX_PROBE_SIZE),
                       ("MaxProbeTimeoutSeconds", tac_forbidden.MAX_PROBE_TIMEOUT_S),
                       ("MaxProbeHops", tac_forbidden.MAX_PROBE_HOPS),
                       ("MaxProbeProbes", tac_forbidden.MAX_PROBE_PROBES),
                       ("maxProbeTokens", tac_forbidden.MAX_PROBE_TOKENS)):
        match = re.search(rf"\b{name}\s*=\s*(\d+)", src)
        assert match, f"{name} is not declared in probe.go"
        assert int(match.group(1)) == want, f"{name}: Go says {match.group(1)}, Python says {want}"


def test_the_family_set_matches_the_go_engine():
    with open(os.path.join(GO_TAC, "forbidden.go"), encoding="utf-8") as fh:
        src = fh.read()
    match = re.search(r"var forbiddenFamilies = \[\]string\{([^}]*)\}", src)
    assert match, "forbiddenFamilies is not declared in forbidden.go"
    names = re.findall(r"Family(\w+)", match.group(1))
    assert [n.lower() for n in names] == list(tac_forbidden.FAMILIES)


def test_every_banned_probe_modifier_is_banned_on_both_sides():
    with open(GO_PROBE, encoding="utf-8") as fh:
        src = fh.read()
    block = src[src.index("var probeBanned"):]
    block = block[:block.index("\n}")]
    go_banned = set(re.findall(r'"([^"]+)"', block))
    assert go_banned == set(tac_forbidden.PROBE_BANNED)


# ── (5) the purge removes, idempotently, without naming ─────────────────────


@pytest.fixture()
def sandbox(tmp_path):
    """A private copy of the whole repo slice the two scripts touch."""
    root = tmp_path / "repo"
    (root / "src" / "backend" / "ai").mkdir(parents=True)
    shutil.copytree(TAC, root / "src" / "backend" / "ai" / "tac")
    (root / "scripts").mkdir()
    for name in ("tac-purge-forbidden.py", "tac_forbidden.py", "tac-merge-research.py"):
        shutil.copy(os.path.join(SCRIPTS, name), root / "scripts" / name)
    # The merge reads repo facts (alerts, signatures, skills); the purge does
    # not, so only the tac tree and the scripts are needed here.
    return root


def run_purge(sandbox, *args):
    return subprocess.run([sys.executable, str(sandbox / "scripts" / "tac-purge-forbidden.py"), *args],
                          check=False, capture_output=True, text=True, timeout=180, cwd=str(sandbox))


def test_a_forbidden_record_is_removed_and_never_named(sandbox):
    research = sandbox / "src" / "backend" / "ai" / "tac" / "research" / "cisco-iosxe.yaml"
    body = research.read_text(encoding="utf-8")
    marker = "clear ip bgp 198.51.100.7 soft"
    injected = body.replace(
        '    commands:\n',
        f'    commands:\n      - {{cmd: "{marker}", intent: bgp.clear}}\n', 1)
    assert injected != body
    research.write_text(injected, encoding="utf-8")

    check = run_purge(sandbox, "--check")
    assert check.returncode == 1, check.stdout
    assert "excluded by policy: 1" in check.stdout
    assert marker not in check.stdout + check.stderr, "the report named the command"

    applied = run_purge(sandbox)
    assert applied.returncode == 0, applied.stdout + applied.stderr
    assert marker not in research.read_text(encoding="utf-8")
    assert marker not in applied.stdout + applied.stderr

    again = run_purge(sandbox, "--check")
    assert again.returncode == 0, again.stdout
    assert "excluded by policy: 0" in again.stdout


def test_the_purge_is_idempotent(sandbox):
    first = run_purge(sandbox)
    assert first.returncode == 0, first.stdout + first.stderr
    before = {}
    for root, _, names in os.walk(sandbox / "src"):
        for name in names:
            path = os.path.join(root, name)
            with open(path, "rb") as fh:
                before[path] = fh.read()
    second = run_purge(sandbox)
    assert second.returncode == 0, second.stdout + second.stderr
    for path, body in before.items():
        with open(path, "rb") as fh:
            assert fh.read() == body, f"{path} changed on a second run"


def test_a_broken_policy_file_is_a_hard_stop(sandbox):
    path = sandbox / "src" / "backend" / "ai" / "tac" / "forbidden.yaml"
    path.write_text(path.read_text(encoding="utf-8").replace(
        "  - id: daemon\n", "  - id: daemons\n", 1), encoding="utf-8")
    proc = run_purge(sandbox, "--check")
    assert proc.returncode != 0
    assert "families" in (proc.stdout + proc.stderr)
