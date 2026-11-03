# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""Every published UDP telemetry port has HOST port == CONTAINER port (tracker 373).

Why. Docker clears stale UDP conntrack entries for a published port when it
(re)creates the mapping — but since Engine 29.5.0 it matches on the CONTAINER
port (moby#53384, open; still true in 29.9.2). With a mapping like
`162:1162`, a conntrack entry created while the container was down survives
every recreate for any sender that keeps talking more often than every 30 s,
and that sender's packets reach the receiver re-sourced from the bridge gateway.
On the lab (2026-11-01) that silently stripped device and tenant attribution
from 163 of 200 traps — the chattiest, flapping device first.

With host == container port, Docker's own flush covers it on every recreate.
The receivers therefore listen on the published port, and each listener reads
the SAME variable its publish entry does, so an override can never re-split
them.
"""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"
COMPOSE_TLS = ROOT / "deployment" / "docker" / "compose.tls.yml"


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that reads compose's `!override` / `!reset` merge tags as the
    plain value they wrap."""


def _compose_tag(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _compose_tag)


def _services(path: Path) -> dict:
    doc = yaml.load(path.read_text(encoding="utf-8"), Loader=_ComposeLoader)
    return (doc or {}).get("services") or {}


def _split(entry: str) -> tuple[str, str]:
    """`[ip:]host:container` → (host, container), with `${VAR:-d}` kept whole."""
    parts, depth, cur = [], 0, ""
    for ch in entry:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == ":" and depth == 0:
            parts.append(cur)
            cur = ""
            continue
        cur += ch
    parts.append(cur)
    return parts[-2], parts[-1]


def _udp_publishes(path: Path) -> list[tuple[str, str, str]]:
    out = []
    for name, svc in _services(path).items():
        for p in svc.get("ports") or []:
            if isinstance(p, str) and p.endswith("/udp"):
                host, container = _split(p[: -len("/udp")])
                out.append((name, host, container))
    return out


def test_every_udp_publish_maps_a_port_to_itself() -> None:
    pubs = _udp_publishes(COMPOSE) + _udp_publishes(COMPOSE_TLS)
    assert pubs, "no UDP publishes found — the parser is not reading compose"
    split = [(svc, h, c) for svc, h, c in pubs if h != c]
    assert not split, (
        "UDP publish with host port != container port (tracker 373 — Docker's conntrack "
        f"flush matches the container port, so a chatty sender stays mis-sourced): {split}")


def test_the_split_reads_variable_defaults_whole() -> None:
    assert _split("${SNMP_TRAP_PORT:-162}:${SNMP_TRAP_PORT:-162}") == (
        "${SNMP_TRAP_PORT:-162}", "${SNMP_TRAP_PORT:-162}")
    assert _split("127.0.0.1:8000:8000") == ("8000", "8000")
    assert _split("${SYSLOG_PORT:-5514}:514") == ("${SYSLOG_PORT:-5514}", "514")


def test_each_receiver_listens_on_the_variable_it_publishes() -> None:
    """The publish entry and the listener move together under an override."""
    svcs = _services(COMPOSE)
    api_env = svcs["api"]["environment"]
    assert api_env["SNMP_TRAP_LISTEN"] == ":${SNMP_TRAP_PORT:-162}"
    assert "${SNMP_TRAP_PORT:-162}:${SNMP_TRAP_PORT:-162}/udp" in svcs["api"]["ports"]
    assert svcs["api"]["sysctls"]["net.ipv4.ip_unprivileged_port_start"] == "0", (
        "the trap receiver binds 162 without root or CAP_NET_BIND_SERVICE")

    assert svcs["syslog-ng"]["environment"]["SYSLOG_PORT"] == "${SYSLOG_PORT:-5514}"
    core = (ROOT / "deployment" / "docker" / "syslog-ng" / "core.conf").read_text(encoding="utf-8")
    assert "udp(ip(0.0.0.0) port(`SYSLOG_PORT`)" in core
    assert "tcp(ip(0.0.0.0) port(`SYSLOG_PORT`)" in core

    for path in (COMPOSE, COMPOSE_TLS):
        cmd = _services(path)["goflow2"]["command"]
        listen = cmd[cmd.index("-listen") + 1]
        for var in ("${NETFLOW_PORT:-2055}", "${SFLOW_PORT:-6343}", "${IPFIX_PORT:-4739}"):
            assert var in listen, f"{path.name}: goflow2 must listen on {var}, the port it publishes"


def test_the_helm_syslog_pod_sets_the_port_core_conf_reads() -> None:
    pipeline = (ROOT / "deployment" / "helm" / "correlix" / "templates" / "pipeline.yaml").read_text(
        encoding="utf-8")
    assert '{name: SYSLOG_PORT, value: "5514"}' in pipeline, (
        "core.conf reads SYSLOG_PORT from the environment; unset, syslog-ng does not start")
