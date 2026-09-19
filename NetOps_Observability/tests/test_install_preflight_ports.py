# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Preflight's port set is DERIVED from compose, not typed by hand (FMEA S6).

`install-correlix.sh` carried its own `STACK_INGEST_PORTS` list while
`prepare-host.sh --firewall` derived its set from the compose files. Two lists,
one host: the hand-kept one is how 443 and 11019 went unchecked and how the
firewall came to open the CONTAINER side (1162/udp) of the trap mapping while
compose published 162/udp (TRACKER 320). On a customer appliance that means
either an install that dies ten minutes in on a busy port nobody checked, or a
firewall that blocks the telemetry the product exists to receive.

Pinned here:
  * preflight's port set comes from prepare-host.sh's firewall library — the
    SAME parser that decides what --firewall opens, never a second one;
  * a port added to a compose file shows up in preflight with no edit here;
  * the `${VAR:-default}` that moves a port is still quoted back to the
    customer in the busy-port failure;
  * the two callers agree, port for port;
  * a derivation that cannot run says so and skips the check — it never
    silently passes and never falls back to a hand list (§16.1).

Everything runs the REAL scripts with `ss` faked on PATH inside tmp_path.
No docker, no host ports, no firewall.

Run:  python3 -m pytest tests/test_install_preflight_ports.py -v
"""

from __future__ import annotations

import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
INSTALL = ROOT / "scripts" / "install-correlix.sh"
PREPARE = ROOT / "scripts" / "prepare-host.sh"
COMPOSE_DIR = ROOT / "deployment" / "docker"

_PATH_LINE = 'export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"'
UI_PORT = "8000"


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _fakes_win(src: str) -> str:
    assert src.count(_PATH_LINE) == 1, "install-correlix.sh PATH line changed — update the harness"
    return src.replace(_PATH_LINE, 'export PATH="${PATH:?test harness sets PATH}"')


def _script_without_dispatch() -> str:
    src = _fakes_win(INSTALL.read_text(encoding="utf-8"))
    return src[:src.rindex('\ncase "$CMD" in\n')] + "\n"


SYNTHETIC_COMPOSE = """name: netops
services:
  syslog-ng:
    image: x
    ports:
      - "514:514/udp"
      - "${SYSLOG_PORT:-5514}:514/tcp"
  api:
    image: y
    ports:
      - "${BASE_PORT:-8000}:8080"
      - "127.0.0.1:${MOCK_HOST_PORT:-8098}:8091"
"""


def _tree(tmp_path: Path, *, compose: str | None = None, real: bool = False,
          prepare: bool = True) -> Path:
    root = tmp_path / "NetOps_Observability"
    (root / "scripts").mkdir(parents=True)
    dc = root / "deployment" / "docker"
    dc.mkdir(parents=True)
    if real:
        shutil.copy(COMPOSE_DIR / "docker-compose.yml", dc / "docker-compose.yml")
        shutil.copy(COMPOSE_DIR / "compose.tls.yml", dc / "compose.tls.yml")
    else:
        (dc / "docker-compose.yml").write_text(compose or SYNTHETIC_COMPOSE)
    dst = root / "scripts" / "install-correlix.sh"
    dst.write_text(_fakes_win(INSTALL.read_text(encoding="utf-8")))
    dst.chmod(0o755)
    if prepare:
        shutil.copy(PREPARE, root / "scripts" / "prepare-host.sh")
    return root


FAKE_SS = """#!/bin/bash
printf '%s\\n' "$*" >> "$SS_LOG"
printf '%s\\n' "${FAKE_SS_OUT:-}"
"""

# The harness PATH has to carry /usr/bin for real coreutils, and that is also
# where the developer's (and the CI runner's) live docker sits. A refusing fake
# goes FIRST so a check that one day reaches for a container runtime fails this
# test instead of talking to a real daemon.
REFUSING_DOCKER = """#!/bin/sh
printf 'fake docker: a test must never reach a container runtime: %s\\n' "$*" >&2
exit 97
"""


def _env(tmp_path: Path, bindir: Path, **extra: str) -> dict:
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp_path),
           "SS_LOG": str(tmp_path / "ss.log"), "CORRELIX_NO_SIZING": "1"}
    env.update(extra)
    return env


def _bin(tmp_path: Path) -> Path:
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    _write_exec(b / "ss", FAKE_SS)
    _write_exec(b / "docker", REFUSING_DOCKER)
    return b


def _assert_fakes_win(env: dict) -> None:
    """`ss` and `docker` must resolve inside tmp_path, never on the host.

    install-correlix.sh prepends /usr/local/bin:/usr/bin:/bin to PATH, which is
    how a fake loses; `_fakes_win` neutralises that one line, and this proves
    the result before any harness runs."""
    bindir = Path(env["PATH"].split(":")[0])
    probe = subprocess.run(["bash", "-c", "command -v ss; command -v docker"], env=env,
                           capture_output=True, text=True, timeout=10, check=False)
    assert probe.stdout.split() == [str(bindir / "ss"), str(bindir / "docker")], \
        "a test could reach the host's real ss/docker — refusing to run: " + probe.stdout


def _harness(root: Path, tail: str, env: dict, timeout: int = 120):
    _assert_fakes_win(env)
    h = root / "scripts" / "harness.sh"
    h.write_text(_script_without_dispatch() + tail)
    return subprocess.run(["bash", str(h)], capture_output=True, text=True, timeout=timeout,
                          env=env, stdin=subprocess.DEVNULL, check=False)


def _derived(root: Path, env: dict) -> tuple[set[str], subprocess.CompletedProcess]:
    r = _harness(root, 'derive_stack_ingest_ports\nprintf "%s\\n" $STACK_INGEST_PORTS\n', env)
    entries = {ln.strip() for ln in r.stdout.splitlines()
               if "/" in ln and not ln.startswith(("[", " "))}
    return entries, r


def _ports(entries: set[str]) -> set[str]:
    return {e.split(":")[0] for e in entries}


# ── what compose really publishes, read independently of the shell ──────────

def _published_off_host() -> set[str]:
    """Every host port docker-compose.yml + compose.tls.yml publish off-host,
    read with PyYAML so the shell's parser is checked against something else."""
    class _Loader(yaml.SafeLoader):
        """compose.tls.yml uses compose's `!override` merge tag."""

    _Loader.add_multi_constructor(
        "!", lambda loader, suffix, node: loader.construct_sequence(node)
        if isinstance(node, yaml.SequenceNode) else loader.construct_object(node))

    out: set[str] = set()
    for name in ("docker-compose.yml", "compose.tls.yml"):
        doc = yaml.load((COMPOSE_DIR / name).read_text(encoding="utf-8"), Loader=_Loader)
        for svc in (doc.get("services") or {}).values():
            for spec in (svc or {}).get("ports") or []:
                spec = str(spec)
                proto = "tcp"
                if spec.endswith("/udp"):
                    proto, spec = "udp", spec[:-4]
                elif spec.endswith("/tcp"):
                    spec = spec[:-4]
                # ${VAR:-default} -> default; the test rig has no .env.
                while "${" in spec:
                    head, _, rest = spec.partition("${")
                    var, _, tail = rest.partition("}")
                    spec = head + (var.split(":-")[1] if ":-" in var else "") + tail
                bits = spec.split(":")
                if len(bits) == 1:
                    continue
                if len(bits) == 3:
                    if bits[0].startswith("127.") or bits[0] in ("localhost", "::1"):
                        continue
                    host = bits[1]
                else:
                    host = bits[0]
                if host.isdigit():
                    out.add(f"{host}/{proto}")
    assert out, "parsed no published ports out of the compose files"
    return out


# ── one source of truth ─────────────────────────────────────────────────────

def test_the_derived_set_is_what_compose_publishes(tmp_path: Path) -> None:
    root = _tree(tmp_path, real=True)
    entries, r = _derived(root, _env(tmp_path, _bin(tmp_path)))
    assert r.returncode == 0, r.stdout + r.stderr
    # The UI port has its own check, with the --ui-port remedy.
    expected = _published_off_host() - {f"{UI_PORT}/tcp"}
    assert _ports(entries) == expected, r.stdout + r.stderr


def test_preflight_and_the_firewall_open_the_same_ports(tmp_path: Path) -> None:
    """The two callers must not be able to disagree — they share one parser."""
    root = _tree(tmp_path, real=True)
    entries, _ = _derived(root, _env(tmp_path, _bin(tmp_path)))
    lib = PREPARE.read_text(encoding="utf-8")
    block = lib[lib.index("# >>> firewall-lib"):lib.index("# <<< firewall-lib")]
    script = root / "fw.sh"
    script.write_text(
        "set -euo pipefail\n"
        'pass(){ :; }; fixd(){ :; }; need(){ :; }; fixfail(){ :; }\n'
        f'SELF_DIR="{root / "scripts"}"\nCHECK=0\nCLOSE_WIZARD_PORT=0\n'
        + block
        + f'\nfw_locate_compose\nFW_ENV_FILE="{root}/deployment/docker/.env"\nfw_stack_ports\n')
    fw_env = _env(tmp_path, _bin(tmp_path))
    _assert_fakes_win(fw_env)
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=120,
                       env=fw_env, stdin=subprocess.DEVNULL, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    firewall = {ln.strip() for ln in r.stdout.splitlines() if "/" in ln}
    assert _ports(entries) == firewall - {f"{UI_PORT}/tcp"}, (
        f"preflight checks {sorted(_ports(entries))} but the firewall opens {sorted(firewall)}")


def test_a_port_added_to_compose_shows_up_in_preflight(tmp_path: Path) -> None:
    """The point of deriving: no second edit, ever."""
    extended = SYNTHETIC_COMPOSE.replace(
        '      - "514:514/udp"\n',
        '      - "514:514/udp"\n      - "${NEW_PORT:-9999}:9999/tcp"\n')
    root = _tree(tmp_path, compose=extended)
    entries, r = _derived(root, _env(tmp_path, _bin(tmp_path)))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "9999/tcp" in _ports(entries), r.stdout
    assert "9999/tcp:NEW_PORT" in entries, \
        "the variable that moves a new port must come across with it"


def test_the_web_ui_port_is_left_to_its_own_check(tmp_path: Path) -> None:
    """port_in_use checks the UI port and offers `--ui-port`. Deriving from
    compose must not ALSO report the compose default: a customer passing
    --ui-port 9443 is usually doing it BECAUSE 8000 is taken, and there is no
    .env yet for the parser to learn the new port from."""
    root = _tree(tmp_path)
    r = _harness(root,
                 'UI_PORT=9443\nderive_stack_ingest_ports\nprintf "%s\\n" $STACK_INGEST_PORTS\n',
                 _env(tmp_path, _bin(tmp_path)))
    assert r.returncode == 0, r.stdout + r.stderr
    ports = _ports({ln.strip() for ln in r.stdout.splitlines() if "/" in ln})
    assert "8000/tcp" not in ports and "9443/tcp" not in ports, ports
    assert "514/udp" in ports, "the device-facing ports must still be checked"


def test_a_loopback_bound_publish_is_not_checked(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    entries, _ = _derived(root, _env(tmp_path, _bin(tmp_path)))
    assert "8098/tcp" not in _ports(entries), \
        "a 127.0.0.1-bound publish cannot conflict with another host service"


# ── the customer-facing report ──────────────────────────────────────────────

def test_a_busy_derived_port_stops_the_install_and_names_the_mover(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    bindir = _bin(tmp_path)
    env = _env(tmp_path, bindir,
               FAKE_SS_OUT="tcp LISTEN 0 25 0.0.0.0:5514 0.0.0.0:*")
    r = _harness(root, "check_ingest_ports\n", env)
    assert r.returncode != 0, r.stdout + r.stderr
    out = r.stdout + r.stderr
    assert "5514/tcp" in out and "SYSLOG_PORT=<port>" in out, out


def test_a_free_host_passes_the_check(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    r = _harness(root, "check_ingest_ports\n", _env(tmp_path, _bin(tmp_path), FAKE_SS_OUT=""))
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_installer_carries_no_hand_written_port_list() -> None:
    src = INSTALL.read_text(encoding="utf-8")
    assert 'STACK_INGEST_PORTS="514/tcp' not in src, (
        "the hand-kept port registry is back — it is how 443 and 162/udp went "
        "missing (FMEA S6); derive it from the compose files instead")
    assert "fw_stack_port_entries" in src or "fw_stack_ports" in src, (
        "preflight must reuse prepare-host.sh's firewall library, not parse compose itself")


def test_a_derivation_that_cannot_run_says_so_and_checks_nothing(tmp_path: Path) -> None:
    """§16.1: no silent skip, no guessed list, and not a failed install either —
    a host we cannot measure is reported, and the install goes on."""
    root = _tree(tmp_path, prepare=False)
    r = _harness(root, "check_ingest_ports\necho REACHED_END\n",
                 _env(tmp_path, _bin(tmp_path), FAKE_SS_OUT="tcp LISTEN 0 25 0.0.0.0:5514 0.0.0.0:*"))
    assert r.returncode == 0, r.stdout + r.stderr
    out = r.stdout + r.stderr
    assert "REACHED_END" in out
    assert "514" not in out.replace("5514", ""), "no hand-written fallback list may be used"
    assert "prepare-host.sh" in out, "the reason the ports were not checked must be named"


@pytest.mark.parametrize("port,words", [
    ("514", "syslog"),
    ("2055", "NetFlow"),
    ("162", "SNMP"),
    ("443", "web"),
])
def test_every_derived_port_is_explained_in_plain_language(tmp_path: Path, port: str,
                                                           words: str) -> None:
    root = _tree(tmp_path)
    r = _harness(root, f'port_purpose {port}\n', _env(tmp_path, _bin(tmp_path)))
    assert r.returncode == 0, r.stdout + r.stderr
    assert words.lower() in r.stdout.lower(), r.stdout
