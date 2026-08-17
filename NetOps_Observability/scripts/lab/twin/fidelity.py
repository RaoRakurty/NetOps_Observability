"""source-IP fidelity orchestration (tracker 152 fidelity wave, design §3.4
`source_ip` mode / risk R-4).

The mechanics, chosen because they touch NO product service definition:

  * the compose overlay (`deployment/docker/docker-compose.twin.yml`) creates
    `twinnet` (198.19.0.0/16; docker IPAM confined to 198.19.255.0/24 so the
    device address plan 198.19.0-1.x can never collide with an
    auto-assigned container address) and attaches ONLY the twin service;
  * intake services that must see per-device source IPs (api for traps,
    goflow2 for flows, syslog-ng if ever needed) are attached at RUN TIME with
    `docker network connect` — a HOT, restart-free, fully reversible operation
    on the running container; `twin.py teardown` disconnects exactly the
    containers this run connected (recorded in state.json);
  * the twin container holds one /32 alias per simulated device on its
    twinnet leg (CAP_NET_ADMIN, granted to the twin service only) and binds
    emitting sockets per device, so trap source-IP and flow `sampler_address`
    are genuinely per-device — the property the trap receiver's source-IP
    attribution and vector-router's `flows_rekey` registry lookup key on.

Everything here is bounded docker-CLI work from the host (the run() idiom of
stack.py); every failure carries stderr (§16.1).
"""
from __future__ import annotations

import base64
import json
import os
import time

from stack import run, warn

DOCKER_TIMEOUT = 30
EXEC_TIMEOUT = 60
AGENT_READY_TIMEOUT_S = 60

TWINNET_SUBNET = "198.19.0.0/16"


class FidelityError(RuntimeError):
    """source_ip mode could not be established; the message says the fix."""


def twinnet_name(project: str) -> str:
    return f"{project}_twinnet"


def network_exists(network: str) -> bool:
    rc, _, _ = run(["docker", "network", "inspect", network], DOCKER_TIMEOUT)
    return rc == 0


def container_networks(cid: str) -> dict:
    rc, out, err = run(["docker", "inspect", "-f",
                        "{{json .NetworkSettings.Networks}}", cid],
                       DOCKER_TIMEOUT)
    if rc != 0:
        raise FidelityError(f"docker inspect {cid[:12]} failed: {err.strip()}")
    try:
        return json.loads(out) or {}
    except json.JSONDecodeError as exc:
        raise FidelityError(f"docker inspect returned junk: {out[:120]}") from exc


def ensure_attached(network: str, cid: str) -> bool:
    """Hot-attach `cid` to `network` unless already attached. Returns True
    when THIS call attached it (the caller records that for teardown — we
    must never disconnect an attachment we did not make)."""
    if network in container_networks(cid):
        return False
    rc, _, err = run(["docker", "network", "connect", network, cid],
                     DOCKER_TIMEOUT)
    if rc != 0:
        raise FidelityError(f"docker network connect {network} {cid[:12]} "
                            f"failed: {err.strip()}")
    return True


def detach(network: str, cid: str) -> str:
    """Reverse of ensure_attached. Returns '' or a problem string."""
    if network not in container_networks(cid):
        return ""
    rc, _, err = run(["docker", "network", "disconnect", network, cid],
                     DOCKER_TIMEOUT)
    if rc != 0:
        return f"docker network disconnect {network} {cid[:12]}: {err.strip()}"
    return ""


def net_ip(cid: str, network: str) -> str:
    nets = container_networks(cid)
    ip = str((nets.get(network) or {}).get("IPAddress") or "")
    if not ip:
        raise FidelityError(f"container {cid[:12]} has no address on "
                            f"{network} after attach")
    return ip


def add_aliases(twin_cid: str, ips: list[str]) -> None:
    """Idempotent per-device /32 aliases on the twin container's twinnet leg
    (delegated to the in-container udp_agent, which owns the iface lookup)."""
    cmd = ["docker", "exec", twin_cid, "python3", "/twin/udp_agent.py",
           "aliases", "--subnet", TWINNET_SUBNET]
    for ip in ips:
        cmd += ["--add", ip]
    rc, out, err = run(cmd, EXEC_TIMEOUT)
    if rc != 0:
        raise FidelityError(f"alias setup failed: {(out or err).strip()[:300]}")


def send_batch(twin_cid: str,
               datagrams: list[tuple[str | None, str, int, bytes]]) -> tuple[bool, str]:
    """Send (src_ip, host, port, payload) datagrams from inside the twin
    container. Returns (ok, error-detail)."""
    lines = [json.dumps({"src": src, "host": host, "port": port,
                         "data": base64.b64encode(data).decode()})
             for src, host, port, data in datagrams]
    rc, out, err = run(["docker", "exec", "-i", twin_cid, "python3",
                        "/twin/udp_agent.py", "send"],
                       EXEC_TIMEOUT, "\n".join(lines) + "\n")
    if rc != 0:
        return False, (out or err).strip()[:300]
    return True, ""


def wait_agents_ready(agents_dir: str, generation: str,
                      want: int, timeout_s: float = AGENT_READY_TIMEOUT_S) -> dict:
    """Block until the in-container supervisor reports `generation` with
    `want` agents running. Raises with the supervisor's own errors on
    failure/timeout — never a bare 'timed out'."""
    status_path = os.path.join(agents_dir, "status.json")
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            with open(status_path, encoding="utf-8") as f:
                last = json.load(f)
        except (OSError, json.JSONDecodeError):
            last = {}
        if last.get("generation") == generation:
            if last.get("errors"):
                raise FidelityError(f"snmpsim supervisor reported errors for "
                                    f"generation {generation}: "
                                    f"{last['errors'][:3]}")
            if int(last.get("running") or 0) >= want:
                return last
        time.sleep(2)
    raise FidelityError(
        f"snmpsim agents never reached generation {generation!r} with "
        f"{want} running within {timeout_s:.0f}s (last status: {last or 'none'}"
        f") — is the twin overlay up? "
        f"(docker compose -f docker-compose.yml -f docker-compose.twin.yml "
        f"up -d twin)")


def idle_manifest(agents_dir: str) -> None:
    """Write the empty manifest that makes the supervisor stop all agents —
    the teardown half of the agent lifecycle."""
    os.makedirs(agents_dir, exist_ok=True)
    tmp = os.path.join(agents_dir, ".manifest.json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"generation": "idle", "agents": []}, f)
    os.replace(tmp, os.path.join(agents_dir, "manifest.json"))


def wait_agents_idle(agents_dir: str, timeout_s: float = 30) -> list[str]:
    """After idle_manifest: wait for running==0. Returns problems (empty on
    success) instead of raising — teardown must report, not abort."""
    status_path = os.path.join(agents_dir, "status.json")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with open(status_path, encoding="utf-8") as f:
                st = json.load(f)
            if st.get("generation") in ("idle", "shutdown") \
                    and int(st.get("running") or 0) == 0:
                return []
        except (OSError, json.JSONDecodeError):
            pass  # supervisor may be mid-write; the deadline bounds this
        time.sleep(2)
    warn("snmpsim agents did not report idle in time")
    return [("snmpsim agents still running after idle manifest (supervisor "
             "down?) — check `docker logs` of the twin service")]
