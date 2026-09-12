# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: a container whose healthcheck forks must reap what it orphans.

INCIDENT 2026-08-19. The 2026-08-09 TLS-enforce wave removed ClickHouse's
plaintext 8123 listener, so its healthcheck became
`wget --no-check-certificate -qO- https://127.0.0.1:8443/ping`. BusyBox wget
forks an `ssl_client` helper to do the TLS handshake and exits before it, so
`ssl_client` is orphaned onto the container's PID 1 — clickhouse-server, an
application that never reaps. Every zombie keeps its PID charge against the
cgroup, so the container leaked one PID per healthcheck (every 10s), climbed
monotonically for 52.2h, and hit systemd's DefaultTasksMax=19046. After that
NOTHING in the container could fork, including the healthcheck itself
("procReady not received"): 18,247 zombies against 798 real threads.

It was silent for 10 days and would kill any appliance ~2.2 days after install.

The general rule this encodes: if PID 1 is your application and something in
the container forks, you need an init to reap. `init: true` costs nothing.
"""
from __future__ import annotations

import os
import re

import pytest

yaml = pytest.importorskip("yaml")

DOCKER_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "deployment", "docker")

# Commands that fork a helper process which outlives its parent. BusyBox wget
# spawns ssl_client for TLS; curl and openssl s_client do their own handshake.
FORKS_A_TLS_HELPER = re.compile(r"\bwget\b[^|;]*\bhttps://", re.I)


def _compose_files() -> list[str]:
    return sorted(
        os.path.join(DOCKER_DIR, f) for f in os.listdir(DOCKER_DIR)
        if f.endswith((".yml", ".yaml")) and "sizing" not in f)


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that tolerates Compose's `!override` / `!reset` tags.

    Without this, safe_load raises on compose.tls.yml and
    docker-compose.override.yml — the two files that actually carried the
    defect — and every guard below would pass by parsing nothing.
    `test_compose_files_are_discoverable` exists to catch exactly that.
    """


_ComposeLoader.add_multi_constructor(
    "", lambda loader, suffix, node: _construct_untagged(loader, node))


def _construct_untagged(loader, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_scalar(node)


def _services(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        doc = yaml.load(fh, Loader=_ComposeLoader) or {}
    return doc.get("services") or {}


def _healthcheck_test(svc: dict) -> str:
    hc = (svc or {}).get("healthcheck") or {}
    test = hc.get("test")
    if isinstance(test, list):
        return " ".join(str(t) for t in test)
    return str(test or "")


def _init_of(service_name: str) -> bool:
    """`init: true` anywhere in the compose set counts — it is a merged key."""
    for path in _compose_files():
        svc = _services(path).get(service_name)
        if svc and svc.get("init") is True:
            return True
    return False


def _all_service_names() -> set:
    names = set()
    for path in _compose_files():
        names |= set(_services(path))
    return names


def test_compose_files_are_discoverable():
    """The globs cannot go empty — otherwise every guard below passes vacuously."""
    assert _compose_files(), f"no compose files found under {DOCKER_DIR}"
    assert _all_service_names(), "no services parsed from any compose file"


def test_the_clickhouse_healthcheck_that_caused_the_incident_is_still_covered():
    """Pins the exact shape. If the probe is rewritten, this must be revisited."""
    found = [
        (os.path.basename(p), name)
        for p in _compose_files()
        for name, svc in _services(p).items()
        if FORKS_A_TLS_HELPER.search(_healthcheck_test(svc))
    ]
    assert found, (
        "no healthcheck matches the forking-TLS-probe pattern any more. If the "
        "ClickHouse probe was deliberately changed, update this guard; do not "
        "delete it — a pattern that matches nothing proves nothing.")
    assert any(name == "clickhouse" for _, name in found), found


@pytest.mark.parametrize("path", _compose_files())
def test_forking_tls_healthchecks_have_an_init_to_reap(path):
    """The defect itself: fork a TLS helper with no init and you leak PIDs."""
    offenders = [
        name for name, svc in _services(path).items()
        if FORKS_A_TLS_HELPER.search(_healthcheck_test(svc))
        and not _init_of(name)
    ]
    assert not offenders, (
        f"{os.path.basename(path)}: service(s) {offenders} run a healthcheck "
        "that forks a TLS helper (BusyBox wget -> ssl_client) but declare no "
        "`init: true`. PID 1 is the application and will not reap the orphan, "
        "so the container leaks one PID per healthcheck until it cannot fork "
        "at all. This is the 2026-08-19 ClickHouse incident exactly.")


def test_clickhouse_and_correlation_declare_init():
    """Both services observed leaking zombies on 2026-08-19."""
    for name in ("clickhouse", "correlation"):
        assert _init_of(name), (
            f"service {name!r} lost `init: true`. It was added because its "
            "PID 1 is an application that does not reap orphaned children.")
