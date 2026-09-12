# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The TLS install must not also serve the product in the clear.

FRESH-INSTALL ACCEPTANCE, 2026-09-06, DEFECT-7 (tracker 265). A default
install is a TLS/mTLS install. It came up, the wizard called it a "Full
TLS/mTLS mesh" — and `http://10.70.245.123:8000/` served the entire dashboard,
with `POST /api/auth/login` answering 401 rather than refusing, over plaintext,
to anything that could reach the host. The messaging made it worse rather than
academic: the URL the wizard printed did not work, so the operator's natural
next move was the http one, carrying the generated administrator password in
the clear.

Two halves, and `compose.tls.yml`'s own NOTE said to close them together:

  1. the URLs the product prints must be TLS-aware and reachable (the
     graphical half shipped in d31245c7; install.py's and
     install-correlix.sh's terminal paths are pinned here);
  2. the plaintext host publish must stop being an off-box ingress.

For (2) the plaintext listener is KEPT but bound to 127.0.0.1 rather than
deleted, because the tooling that qualifies and watches an appliance —
deploy-qualify.sh, stack-watchdog.sh, install-correlix.sh's wait_healthy and
verify_admin_login, install.py's readiness gate — all speak
http://localhost:8000 and all run ON the host. A 301 would break every one of
them (none follow redirects; verify_admin_login POSTs). Off the host, :8000 is
simply not published any more.

These are static/rendered checks over the committed files. The compose
rendering runs the real `docker compose config` when docker is available and
skips, saying why, when it is not.

Run:  python3 -m pytest tests/test_install_tls_ingress.py -v
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_DIR = ROOT / "deployment" / "docker"
BASE = COMPOSE_DIR / "docker-compose.yml"
TLS = COMPOSE_DIR / "compose.tls.yml"
INSTALL_PY = ROOT / "scripts" / "install.py"
INSTALL_SH = ROOT / "scripts" / "install-correlix.sh"
GUI_HTML = ROOT / "scripts" / "installer-gui" / "ui.html"


def _compose_yaml(text: str) -> dict:
    """Compose merge tags (!override, !reset) are not plain YAML."""

    class _Loader(yaml.SafeLoader):
        pass

    def _passthrough(loader, node):
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        return loader.construct_scalar(node)

    _Loader.add_constructor("!override", _passthrough)
    _Loader.add_constructor("!reset", _passthrough)
    return yaml.load(text, Loader=_Loader)


# ── the declaration ─────────────────────────────────────────────────────────

def test_base_compose_publishes_plaintext_on_every_interface() -> None:
    """The plaintext-default variant is unchanged: a non-TLS evaluation
    install still answers on <host>:8000, which is its whole point."""
    ports = _compose_yaml(BASE.read_text())["services"]["nginx"]["ports"]
    assert ports == ["${BASE_PORT:-8000}:8080"], ports


def test_tls_overlay_overrides_the_port_list_rather_than_appending() -> None:
    """`ports` is a LIST and compose MERGES lists across files. Restating the
    key without `!override` would leave the base file's 0.0.0.0 publish in
    place and this whole change would be a no-op — which is exactly how the
    plaintext ingress survived every earlier attempt to reason about it."""
    text = TLS.read_text()
    m = re.search(r"^  nginx:[\s\S]*?^    ports: (!override)\n((?:      - [^\n]*\n)+)",
                  text, re.DOTALL | re.MULTILINE)
    assert m, "compose.tls.yml's nginx ports block is not `ports: !override`"
    entries = [ln.strip().lstrip("- ").strip('"') for ln in m.group(2).splitlines()]
    assert entries == ["443:8443", "127.0.0.1:${BASE_PORT:-8000}:8080"], entries


def test_tls_overlay_still_publishes_the_https_ingress() -> None:
    ports = _compose_yaml(TLS.read_text())["services"]["nginx"]["ports"]
    assert any(str(p).endswith("443:8443") for p in ports), ports


def test_the_plaintext_listener_itself_is_not_removed() -> None:
    """tls.conf terminates TLS and proxies to 127.0.0.1:8080 INSIDE the same
    container — the :8080 server block is load-bearing under TLS, so this
    change must be about the host publish and nothing else."""
    tls_conf = (COMPOSE_DIR / "nginx" / "tls.conf.example").read_text()
    assert "127.0.0.1:8080" in tls_conf
    assert "listen 8080" in (COMPOSE_DIR / "nginx" / "default.conf").read_text()
    assert "listen 8080" in (COMPOSE_DIR / "nginx" / "default-mtls.conf").read_text()


# ── the rendering (what docker actually does with it) ───────────────────────

def _render(*files: Path) -> dict:
    if shutil.which("docker") is None:
        pytest.skip("docker is not on PATH — the rendered-config check needs it")
    args = ["docker", "compose"]
    for f in files:
        args += ["-f", f.name]
    args += ["config", "--format", "json"]
    res = subprocess.run(args, cwd=str(COMPOSE_DIR), capture_output=True,
                         text=True, timeout=120, check=False,
                         env={**os.environ, "COMPOSE_FILE": "", "COMPOSE_PROFILES": ""})
    if res.returncode != 0:
        pytest.skip("`docker compose config` cannot render here (no .env / no "
                    f"compose v2): {res.stderr.strip()[:200]}")
    return json.loads(res.stdout)


def test_rendered_tls_stack_binds_plaintext_to_loopback_only() -> None:
    ports = _render(BASE, TLS)["services"]["nginx"]["ports"]
    by_target = {p["target"]: p for p in ports}
    assert 8443 in by_target, f"the https ingress is gone: {ports}"
    assert str(by_target[8443]["published"]) == "443"
    assert by_target[8443].get("host_ip") in (None, "", "0.0.0.0"), (
        "the TLS ingress must stay reachable from the network")
    assert 8080 in by_target, (
        "the plaintext listener must stay published to LOOPBACK — the "
        "host-local qualifier and watchdog probes speak http://localhost:8000")
    assert by_target[8080]["host_ip"] == "127.0.0.1", (
        f"http://<host>:8000 still serves the dashboard and the auth API on a "
        f"TLS install: {by_target[8080]}")
    # And exactly two: an appended duplicate from a list merge would republish
    # 8000 on 0.0.0.0 while this test still saw the loopback entry.
    assert len(ports) == 2, ports


def test_rendered_plaintext_stack_is_unchanged() -> None:
    ports = _render(BASE)["services"]["nginx"]["ports"]
    assert len(ports) == 1, ports
    assert ports[0]["target"] == 8080
    assert ports[0].get("host_ip") in (None, "", "0.0.0.0"), (
        "a plaintext evaluation install must still answer on <host>:8000")


# ── the messaging half ──────────────────────────────────────────────────────

def test_install_py_prints_a_reachable_https_url_under_tls() -> None:
    src = INSTALL_PY.read_text()
    assert "def _reachable_host()" in src
    assert 'dash_host = _reachable_host()' in src
    assert 'f"https://{dash_host}/"' in src, (
        "install.py must print a host an operator can actually reach — the "
        "acceptance watched it hand out https://localhost/ over SSH")
    assert "during the migration window" not in src, (
        "the plaintext port is no longer an off-box ingress; the migration "
        "window is over and the message must not still promise it")


def test_install_py_says_the_plaintext_port_is_loopback_only() -> None:
    """Not printing a wrong URL is not enough: an operator who knows :8000
    used to work needs to be told why it does not any more (§16.1 in spirit —
    a changed behaviour that is not stated reads as a fault)."""
    src = INSTALL_PY.read_text()
    block = src[src.index('print(f"  Dashboard: https://{dash_host}/'):]
    block = block[:block.index("else:")]
    assert "loopback" in block and "answers on this host" in block, block


def test_reachable_host_never_raises_and_degrades_to_localhost() -> None:
    import importlib.util
    spec = importlib.util.spec_from_file_location("_inst", INSTALL_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    host = mod._reachable_host()
    assert host and not host.startswith("127."), host
    # Both discovery paths dead => "localhost", never an exception and never ""
    mod._route_source_address = lambda: None
    mod._first_host_address = lambda: None
    assert mod._reachable_host() == "localhost"


def test_install_correlix_success_url_is_tls_aware() -> None:
    """The terminal path's own success screen. It printed
    `http://<host>:8000` unconditionally — under TLS that is now a refused
    connection off the box."""
    src = INSTALL_SH.read_text()
    assert "tls_active()" in src and "compose.tls.yml" in src
    assert "dashboard_url()" in src
    assert "$(dashboard_url)" in src
    assert not re.search(r'Open the UI:.*http://\$\{host\}', src), (
        "print_success still hardcodes an http URL")
    assert not re.search(r'cx_result ok "http://\$\{host\}', src), (
        "the GUI result marker still hardcodes an http URL")


def test_the_gui_and_the_terminal_agree_about_the_tls_url() -> None:
    """Two paths, one answer. The wizard rewrites a loopback host to the one
    the browser used; the terminal resolves the host's own address. Neither may
    quote a port under TLS — 443 is the ingress."""
    assert "'https://' + host + '/'" in GUI_HTML.read_text()
    assert "printf 'https://%s/'" in INSTALL_SH.read_text()
    assert 'f"https://{dash_host}/"' in INSTALL_PY.read_text()


def test_docs_explain_the_new_port_behaviour() -> None:
    """A customer-visible change nobody documented is a support ticket."""
    doc = (ROOT / "docs" / "INSTALL.md").read_text()
    low = doc.lower()
    assert "loopback" in low or "127.0.0.1" in doc, (
        "docs/INSTALL.md must say that a TLS install stops publishing :8000 "
        "off-box")
    assert "8000" in doc and "https://" in doc
