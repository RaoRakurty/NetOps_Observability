#!/usr/bin/env python3
"""snmpsim_supervisor — per-device SNMP agent supervisor for the twin
container (tracker 152 fidelity wave, design §4.3).

Runs as PID 1 of the `twin-snmpsim` compose service. Watches the shared
manifest (`/data/twin/agents/manifest.json`, written host-side by
`snmpsim_gen.generate_agents`) and reconciles reality to it:

  * adds one /32 alias per agent on the twinnet interface (CAP_NET_ADMIN),
  * spawns one pinned `snmpsim-command-responder` per agent bound to that
    address (identity == address — what discovery/polling key on),
  * tears down agents that left the manifest (an empty manifest = idle),
  * writes `status.json` next to the manifest after every reconcile so the
    host-side twin can WAIT on readiness instead of hoping (§10: no silent
    failures — every spawn error lands in status.json AND on stderr).

The snmpsim dependency exists ONLY inside this container's pinned image
(design §4.1); nothing here is importable by the product.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import sys
import time

POLL_S = 2.0
RESPONDER = "snmpsim-command-responder"


def log(msg: str) -> None:
    print(f"snmpsim-supervisor: {msg}", file=sys.stderr, flush=True)


def _run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                           check=False)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return 127, "", str(exc)


def iface_for_subnet(subnet: str) -> str:
    net = ipaddress.ip_network(subnet)
    rc, out, err = _run(["ip", "-o", "-4", "addr", "show"])
    if rc != 0:
        raise RuntimeError(f"ip addr show failed: {err.strip()}")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet" \
                and ipaddress.ip_address(parts[3].split("/")[0]) in net:
            return parts[1]
    raise RuntimeError(f"no interface inside {subnet} — attach this "
                       f"container to twinnet")


class Supervisor:
    def __init__(self, manifest_path: str, subnet: str):
        self.manifest_path = manifest_path
        self.status_path = os.path.join(os.path.dirname(manifest_path),
                                        "status.json")
        self.subnet = subnet
        self.iface = ""
        self.generation = ""
        self.procs: dict[str, subprocess.Popen] = {}   # device -> proc
        self.ips: dict[str, str] = {}                  # device -> alias ip

    # -- pieces -----------------------------------------------------------
    def _alias(self, action: str, ip: str) -> str:
        rc, _, err = _run(["ip", "addr", action, f"{ip}/32",
                           "dev", self.iface])
        if rc != 0 and "File exists" not in err \
                and "Cannot assign" not in err:
            return f"ip addr {action} {ip}: {err.strip()}"
        return ""

    def _spawn(self, agent: dict, data_root: str) -> tuple[subprocess.Popen | None, str]:
        # snmpsim's CLI is ORDER-SENSITIVE: --v3-* flags open an SNMP
        # engine section and the endpoint/data-dir that follow bind to it —
        # v3 flags AFTER the endpoint leave the engine with "agent endpoint
        # address(es) not specified" and the responder exits 1.
        cmd = [RESPONDER,
               "--log-level", "error", "--logging-method", "stderr",
               # snmpsim refuses to KEEP running as root: it binds :161 (root
               # needed in this netns), then drops to this image-local user.
               "--process-user", "twin", "--process-group", "twin"]
        v3 = agent.get("v3")
        if v3:
            cmd += ["--v3-engine-id", v3["engine_id"],
                    "--v3-user", v3["user"],
                    "--v3-auth-key", v3["auth_key"],
                    "--v3-auth-proto", v3["auth_proto"],
                    "--v3-priv-key", v3["priv_key"],
                    "--v3-priv-proto", v3["priv_proto"]]
        cmd += ["--data-dir", os.path.join(data_root, agent["data_dir"]),
                "--agent-udpv4-endpoint", f"{agent['ip']}:{agent['port']}"]
        try:
            return subprocess.Popen(cmd), ""
        except OSError as exc:
            return None, f"spawn {agent['device']}: {exc}"

    def _stop(self, device: str) -> None:
        p = self.procs.pop(device, None)
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=10)
        ip = self.ips.pop(device, "")
        if ip:
            err = self._alias("del", ip)
            if err:
                log(err)

    # -- reconcile --------------------------------------------------------
    def reconcile(self) -> None:
        try:
            with open(self.manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
        except FileNotFoundError:
            return  # no run yet — stay idle, keep whatever status stands
        except (OSError, json.JSONDecodeError) as exc:
            self.write_status("unreadable", 0, [f"manifest: {exc}"])
            return
        gen = str(manifest.get("generation") or "")
        agents = manifest.get("agents") or []
        # restart-crashed even inside a generation
        dead = [d for d, p in self.procs.items() if p.poll() is not None]
        if gen == self.generation and not dead:
            return
        errors: list[str] = []
        wanted = {a["device"]: a for a in agents}
        for device in list(self.procs):
            if device not in wanted or gen != self.generation \
                    or device in dead:
                self._stop(device)
        data_root = os.path.dirname(self.manifest_path)
        for device, agent in wanted.items():
            if device in self.procs:
                continue
            err = self._alias("add", agent["ip"])
            if err:
                errors.append(err)
                continue
            proc, perr = self._spawn(agent, data_root)
            if proc is None:
                errors.append(perr)
                continue
            self.procs[device] = proc
            self.ips[device] = agent["ip"]
        # a responder that dies during startup is a config error — the
        # interpreter+pysnmp import takes a couple of seconds, so give it a
        # real grace window; status.json must not say "running" for a corpse.
        time.sleep(3.0)
        for device in list(self.procs):
            p = self.procs[device]
            if p.poll() is not None:
                errors.append(f"{device}: responder exited rc={p.returncode} "
                              f"immediately")
                self._stop(device)
        self.generation = gen
        self.write_status(gen, len(self.procs), errors)
        log(f"generation {gen!r}: {len(self.procs)} agents running"
            + (f", {len(errors)} errors: {errors}" if errors else ""))

    def write_status(self, gen: str, running: int,
                     errors: list[str]) -> None:
        doc = {"generation": gen, "running": running, "errors": errors,
               "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        tmp = self.status_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=1)
            os.replace(tmp, self.status_path)
        except OSError as exc:
            log(f"status write failed: {exc}")

    def shutdown(self) -> None:
        for device in list(self.procs):
            self._stop(device)
        self.write_status("shutdown", 0, [])


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="snmpsim_supervisor.py")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--subnet", default="198.19.0.0/16")
    args = ap.parse_args(argv)
    if shutil.which(RESPONDER) is None:
        log(f"FATAL: {RESPONDER} not on PATH — wrong image?")
        return 1
    sup = Supervisor(args.manifest, args.subnet)
    try:
        sup.iface = iface_for_subnet(args.subnet)
    except RuntimeError as exc:
        log(f"FATAL: {exc}")
        return 1
    stop = {"flag": False}

    def _sig(*_a) -> None:
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    log(f"watching {args.manifest} (iface {sup.iface})")
    while not stop["flag"]:
        sup.reconcile()
        time.sleep(POLL_S)
    sup.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
