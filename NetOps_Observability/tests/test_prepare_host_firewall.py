# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""prepare-host.sh --firewall: one source of truth, no lock-out (FMEA row 8).

TRACKER 320 / FMEA 2026-09-15 §2 row 8, §3.3 P1. The hand-kept rule list in
prepare-host.sh drifted from what compose actually publishes:

  * it opened 1162/udp — the CONTAINER side of the trap mapping — while compose
    publishes host 162/udp (`${SNMP_TRAP_PORT:-162}:1162/udp`);
  * it never opened 514 (tcp+udp), 11019/tcp (BMP) or 443/tcp (the TLS
    ingress, the DEFAULT install);
  * it enabled a default-deny firewall under a running setup wizard on 8800
    and locked the operator out of the page they were using.

The rules pinned here:
  * the host port set is DERIVED from docker-compose.yml + compose.tls.yml (and
    .env overrides), never typed by hand — loopback-bound publishes are not
    opened;
  * 443 is opened for a TLS install, BASE_PORT for a plaintext one, both while
    the scheme is not yet decided;
  * 8800 (the wizard) is opened as a separately tagged, documented, closable rule;
  * every allow rule lands BEFORE the default-deny + enable;
  * after enabling, the rules are verified and the listeners that answered
    before are probed again; a failure rolls the firewall back and says so.

The firewall block of prepare-host.sh runs for real with fake `ufw` /
`firewall-cmd` / `sshd` binaries that record their argv. Nothing touches the
host firewall.

Run:  python3 -m pytest tests/test_prepare_host_firewall.py -v
"""

from __future__ import annotations

import re
import shutil
import socket
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
PREP = ROOT / "scripts" / "prepare-host.sh"
COMPOSE_DIR = ROOT / "deployment" / "docker"

BEGIN = "# >>> firewall-lib"
END = "# <<< firewall-lib"

DEVICE_PORTS = {"514/tcp", "514/udp", "5514/tcp", "5514/udp", "2055/udp",
                "4739/udp", "6343/udp", "162/udp", "11019/tcp"}


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _lib() -> str:
    src = PREP.read_text(encoding="utf-8")
    assert BEGIN in src and END in src, (
        "prepare-host.sh has no delimited firewall block — the port set must be "
        "derived by testable code, not a hand list")
    return src[src.index(BEGIN):src.index(END)]


# A stateful fake ufw: `status` reflects enable/disable; every call recorded.
FAKE_UFW = r"""#!/bin/bash
printf '%s\n' "$*" >> "$UFW_LOG"
st="$FAKE_FW/ufw-active"
case "$1" in
  status)
    if [ -f "$st" ]; then
      echo "Status: active"
      if [ "${2:-}" = verbose ]; then
        echo "Default: $(cat "$FAKE_FW/ufw-default" 2>/dev/null || echo deny) (incoming), allow (outgoing), disabled (routed)"
      fi
      echo
      [ -z "${FAKE_UFW_DROP_RULE:-}" ] || true
      grep -v "^${FAKE_UFW_DROP_RULE:-__none__}\$" "$FAKE_FW/ufw-rules" 2>/dev/null | while read -r r; do
        printf '%-28s ALLOW IN    Anywhere\n' "$r"
      done
    else
      echo "Status: inactive"
    fi ;;
  allow) shift; echo "$1" >> "$FAKE_FW/ufw-rules" ;;
  delete) : ;;
  default) [ "$2" = deny ] || [ "$2" = allow ] && [ "${3:-}" = incoming ] && echo "$2" > "$FAKE_FW/ufw-default" ;;
  --force)
    case "$2" in
      enable) touch "$st" ;;
      disable) rm -f "$st" ;;
    esac ;;
esac
exit 0
"""

FAKE_FIREWALLCMD = r"""#!/bin/bash
printf '%s\n' "$*" >> "$FWCMD_LOG"
# Copy to a scalar first: ${*##pat} would strip per positional parameter.
all="$*"
case "$all" in
  --state) echo running; exit 0 ;;
  *--query-port=*)
     p="${all##*--query-port=}"
     grep -qx "$p" "$FAKE_FW/fwd-ports" 2>/dev/null && exit 0 || exit 1 ;;
  *--add-port=*) p="${all##*--add-port=}"; echo "$p" >> "$FAKE_FW/fwd-ports" ;;
  *--list-ports*) tr '\n' ' ' < "$FAKE_FW/fwd-ports" 2>/dev/null; echo ;;
esac
exit 0
"""


def _run(tmp_path: Path, *, self_dir: Path | None = None, check: bool = False,
         backend: str = "ufw", ufw_active_before: bool = False,
         block_after: str = "", drop_rule: str = "", env_file: str | None = None,
         compose_dir: Path | None = None, close_wizard: bool = False):
    fw = tmp_path / "fw"
    fw.mkdir()
    if ufw_active_before:
        (fw / "ufw-active").touch()
        (fw / "ufw-default").write_text("allow\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    if backend == "ufw":
        _write_exec(bindir / "ufw", FAKE_UFW)
        _write_exec(bindir / "firewall-cmd", "#!/bin/sh\nexit 127\n")
    else:
        _write_exec(bindir / "firewall-cmd", FAKE_FIREWALLCMD)
    _write_exec(bindir / "apt-get", "#!/bin/sh\necho \"apt-get $*\" >> \"$UFW_LOG\"\nexit 0\n")
    _write_exec(bindir / "sshd", "#!/bin/sh\n[ \"$1\" = -T ] && echo 'port 22'\nexit 0\n")
    _write_exec(bindir / "hostname", "#!/bin/sh\necho 192.0.2.10\n")

    if self_dir is None:
        # Source-checkout layout: scripts/ next to deployment/docker.
        self_dir = tmp_path / "tree" / "scripts"
        self_dir.mkdir(parents=True)
        dc = compose_dir or (tmp_path / "tree" / "deployment" / "docker")
        dc.mkdir(parents=True, exist_ok=True)
        for f in ("docker-compose.yml", "compose.tls.yml"):
            shutil.copy(COMPOSE_DIR / f, dc / f)
        if env_file is not None:
            (dc / ".env").write_text(env_file)

    ufw_log = tmp_path / "ufw.log"
    fwcmd_log = tmp_path / "fwcmd.log"
    harness = "\n".join([
        "set -euo pipefail",
        'pass(){ printf "PASS %s\\n" "$1"; }',
        'fixd(){ printf "FIXED %s\\n" "$1"; }',
        'need(){ printf "FIX %s\\n" "$1"; FIXES=$((FIXES+1)); }',
        'fixfail(){ printf "FIX FAILED %s\\n" "$1"; FAILED=$((FAILED+1)); }',
        "FIXES=0; FAILED=0",
        f"CHECK={1 if check else 0}",
        f"CLOSE_WIZARD_PORT={1 if close_wizard else 0}",
        f'SELF_DIR="{self_dir}"',
        _lib(),
        # The real probe dials the management address; the fake answers
        # "listening" until the firewall is enabled, then drops $FAKE_BLOCK_AFTER.
        'fw_probe_port() {',
        '  if [ -n "${FAKE_BLOCK_AFTER:-}" ] && [ "$2" = "$FAKE_BLOCK_AFTER" ] \\',
        '     && { [ -f "$FAKE_FW/ufw-active" ] && grep -q "^--force enable" "$UFW_LOG" 2>/dev/null \\',
        '          || grep -q -- "--reload" "$FWCMD_LOG" 2>/dev/null; }; then return 1; fi',
        '  return 0',
        '}',
        "fw_main",
        'echo "FIXES=$FIXES FAILED=$FAILED"',
    ])
    env = {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "UFW_LOG": str(ufw_log),
        "FWCMD_LOG": str(fwcmd_log),
        "FAKE_FW": str(fw),
        "FAKE_BLOCK_AFTER": block_after,
        "FAKE_UFW_DROP_RULE": drop_rule,
    }
    r = subprocess.run(["bash", "-c", harness], capture_output=True, text=True,
                       timeout=120, env=env, check=False)
    calls = ufw_log.read_text().splitlines() if ufw_log.exists() else []
    fcalls = fwcmd_log.read_text().splitlines() if fwcmd_log.exists() else []
    return r, calls, fcalls


def _allowed(calls: list[str]) -> set[str]:
    out = set()
    for c in calls:
        m = re.match(r"^allow (\S+)", c)
        if m:
            out.add(m.group(1))
    return out


# ── the static bug, red on HEAD ─────────────────────────────────────────────

def test_the_hand_list_with_the_container_side_trap_port_is_gone() -> None:
    code = re.sub(r"^\s*#.*$", "", PREP.read_text(), flags=re.MULTILINE)
    assert "1162" not in code, (
        "prepare-host.sh opens 1162 — the CONTAINER port of the trap mapping; "
        "compose publishes host 162/udp")


# ── derivation ──────────────────────────────────────────────────────────────

def _compose_host_ports(tls: bool) -> set[str]:
    """Independent reading of what compose publishes off-host (PyYAML)."""
    class _L(yaml.SafeLoader):
        pass

    def _p(loader, node):
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_scalar(node)
    _L.add_constructor("!override", _p)
    base = yaml.load((COMPOSE_DIR / "docker-compose.yml").read_text(), Loader=_L)["services"]
    over = yaml.load((COMPOSE_DIR / "compose.tls.yml").read_text(), Loader=_L)["services"]
    ports: set[str] = set()
    for name, svc in base.items():
        plist = (svc or {}).get("ports") or []
        if tls and name in over and "ports" in (over[name] or {}):
            plist = over[name]["ports"]
        for p in plist:
            s = re.sub(r"\$\{[A-Z_]+:-(\d+)\}", r"\1", str(p))
            proto = "udp" if s.endswith("/udp") else "tcp"
            s = s.split("/")[0]
            bits = s.split(":")
            if len(bits) == 3:
                if bits[0] in ("127.0.0.1", "::1", "localhost"):
                    continue
                bits = bits[1:]
            ports.add(f"{bits[0]}/{proto}")
    return ports


def test_fresh_host_opens_every_compose_published_port_plus_both_ingresses(tmp_path: Path) -> None:
    r, calls, _ = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    allowed = _allowed(calls)
    expected = _compose_host_ports(tls=False) | _compose_host_ports(tls=True)
    assert DEVICE_PORTS <= expected, "compose changed shape; revisit DEVICE_PORTS"
    assert expected <= allowed, f"missing: {sorted(expected - allowed)}"
    assert "443/tcp" in allowed and "8000/tcp" in allowed
    assert "1162/udp" not in allowed
    assert not {"8098/tcp", "8099/tcp"} & allowed, "loopback-bound publishes must not be opened"
    assert "22/tcp" in allowed, "SSH must be allowed before default-deny"
    assert "8800/tcp" in allowed, "the setup wizard must stay reachable"


def test_tls_install_opens_443_and_not_the_loopback_plaintext_port(tmp_path: Path) -> None:
    env = ("COMPOSE_FILE=docker-compose.yml:compose.tls.yml\nBASE_PORT=8000\n")
    r, calls, _ = _run(tmp_path, env_file=env)
    assert r.returncode == 0, r.stdout + r.stderr
    allowed = _allowed(calls)
    assert "443/tcp" in allowed
    assert "8000/tcp" not in allowed, "under TLS :8000 is bound to 127.0.0.1"
    assert DEVICE_PORTS <= allowed


def test_plaintext_install_follows_env_port_overrides(tmp_path: Path) -> None:
    env = "BASE_PORT=9000\nSYSLOG_PORT=6514\nSNMP_TRAP_PORT=10162\n"
    r, calls, _ = _run(tmp_path, env_file=env)
    assert r.returncode == 0, r.stdout + r.stderr
    allowed = _allowed(calls)
    assert {"9000/tcp", "6514/udp", "6514/tcp", "10162/udp"} <= allowed, sorted(allowed)
    assert "443/tcp" not in allowed and "8000/tcp" not in allowed
    assert "5514/udp" not in allowed and "162/udp" not in allowed


def test_bundle_host_derives_ports_from_the_source_tarball(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    with tarfile.open(bundle / "correlix-source-9.9.9.tar.gz", "w:gz") as tf:
        for f in ("docker-compose.yml", "compose.tls.yml"):
            tf.add(COMPOSE_DIR / f, arcname=f"NetOps_Observability/deployment/docker/{f}")
    r, calls, _ = _run(tmp_path, self_dir=bundle)
    assert r.returncode == 0, r.stdout + r.stderr
    allowed = _allowed(calls)
    assert DEVICE_PORTS | {"443/tcp", "8000/tcp"} <= allowed, sorted(allowed)


def test_no_compose_file_is_a_named_refusal_not_a_guess(tmp_path: Path) -> None:
    empty = tmp_path / "nowhere"
    empty.mkdir()
    r, calls, _ = _run(tmp_path, self_dir=empty)
    out = r.stdout + r.stderr
    assert "FIX FAILED" in out and "docker-compose.yml" in out, out
    assert not [c for c in calls if c.startswith(("allow", "--force enable", "default"))], calls


# ── ordering and lock-out safety ────────────────────────────────────────────

def test_allow_rules_land_before_default_deny_and_enable(tmp_path: Path) -> None:
    r, calls, _ = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    idx_enable = calls.index("--force enable")
    idx_deny = next(i for i, c in enumerate(calls) if c.startswith("default deny incoming"))
    last_allow = max(i for i, c in enumerate(calls) if c.startswith("allow"))
    assert last_allow < idx_deny < idx_enable, calls
    assert "FIX FAILED" not in r.stdout


def test_the_wizard_rule_is_tagged_and_closable(tmp_path: Path) -> None:
    r, calls, _ = _run(tmp_path)
    wiz = [c for c in calls if c.startswith("allow 8800/tcp")]
    assert wiz and "comment" in wiz[0], wiz
    assert "--close-wizard-port" in r.stdout + PREP.read_text()
    # and closing it removes exactly that rule
    second = tmp_path / "second"
    second.mkdir()
    _, calls2, _ = _run(second, close_wizard=True)
    assert any(c.startswith("delete allow 8800/tcp") for c in calls2), calls2
    assert not [c for c in calls2 if c.startswith(("default", "--force enable"))], calls2


def test_a_listener_that_stops_answering_rolls_the_firewall_back(tmp_path: Path) -> None:
    r, calls, _ = _run(tmp_path, block_after="8800")
    out = r.stdout + r.stderr
    assert "FIX FAILED" in out and "8800" in out, out
    assert "--force disable" in calls, (
        "UFW was inactive before this run; rollback must disable it again")
    assert calls.index("--force disable") > calls.index("--force enable")


def test_rollback_on_an_already_active_firewall_restores_its_default(tmp_path: Path) -> None:
    r, calls, _ = _run(tmp_path, ufw_active_before=True, block_after="22")
    out = r.stdout + r.stderr
    assert "FIX FAILED" in out and "22" in out, out
    assert "--force disable" not in calls, "an operator's active firewall is not ours to disable"
    assert calls[-1].startswith("default allow incoming"), calls


def test_a_rule_that_did_not_land_rolls_back(tmp_path: Path) -> None:
    r, calls, _ = _run(tmp_path, drop_rule="162/udp")
    out = r.stdout + r.stderr
    assert "FIX FAILED" in out and "162/udp" in out, out
    assert "--force disable" in calls


def test_check_mode_names_missing_rules_and_changes_nothing(tmp_path: Path) -> None:
    fw_pre = tmp_path / "pre"
    fw_pre.mkdir()
    r, calls, _ = _run(tmp_path, check=True, ufw_active_before=True)
    out = r.stdout + r.stderr
    assert "FIX" in out and "443/tcp" in out and "162/udp" in out, out
    assert not [c for c in calls if not c.startswith("status")], calls


# ── firewalld ───────────────────────────────────────────────────────────────

def test_firewalld_hosts_get_the_same_port_set(tmp_path: Path) -> None:
    r, _, fcalls = _run(tmp_path, backend="firewalld")
    assert r.returncode == 0, r.stdout + r.stderr
    perm = {c.split("--add-port=")[1] for c in fcalls
            if "--permanent" in c and "--add-port=" in c}
    assert DEVICE_PORTS | {"443/tcp", "8000/tcp", "22/tcp"} <= perm, sorted(perm)
    wizard = [c for c in fcalls if "--add-port=8800/tcp" in c]
    assert wizard and all("--permanent" not in c for c in wizard), (
        "the wizard port is runtime-only on firewalld: gone at the next reload/reboot")
    assert "FIX FAILED" not in r.stdout


def test_firewalld_rollback_removes_what_this_run_added(tmp_path: Path) -> None:
    r, _, fcalls = _run(tmp_path, backend="firewalld", block_after="22")
    out = r.stdout + r.stderr
    assert "FIX FAILED" in out, out
    assert any("--remove-port=443/tcp" in c for c in fcalls), fcalls


# ── the real probe ──────────────────────────────────────────────────────────

def test_the_real_probe_distinguishes_open_from_closed(tmp_path: Path) -> None:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    cport = closed.getsockname()[1]
    closed.close()
    lib = _lib()
    script = "set -euo pipefail\n" + lib + (
        f"\nif fw_probe_port 127.0.0.1 {port}; then echo OPEN; else echo SHUT; fi"
        f"\nif fw_probe_port 127.0.0.1 {cport}; then echo OPEN2; else echo SHUT2; fi\n")
    try:
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           timeout=30, env={"PATH": "/usr/bin:/bin"}, check=False)
    finally:
        srv.close()
    assert "OPEN" in r.stdout.split() and "SHUT2" in r.stdout.split(), r.stdout + r.stderr


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_prepare_host_is_shellcheck_clean() -> None:
    r = subprocess.run(["shellcheck", str(PREP)],
                       capture_output=True, text=True, timeout=120, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
