#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""udp_agent — dumb UDP send/alias helper that runs INSIDE the twin container
(tracker 152 fidelity wave, design §3.4 `source_ip` mode).

All encoding intelligence stays host-side (`wire.py`, unit-tested); this agent
only (a) manages the per-device IP aliases on the twinnet interface and
(b) sends pre-encoded datagrams from per-device source addresses. It is
invoked via `docker exec -i` per emission tick (the same batched-exec idiom as
the kafka console-producer path).

    udp_agent.py aliases --subnet 198.19.0.0/16 --add IP [--add IP ...]
    udp_agent.py aliases --subnet 198.19.0.0/16 --flush
    udp_agent.py send            # JSON lines on stdin:
                                 # {"src": "198.19.0.1"|null, "host": H,
                                 #  "port": N, "data": "<base64>"}

Output: one JSON summary line on stdout; exit 0 only when everything worked
(§16.1 — a partial send is an error the caller must see, never a silent
success). Requires CAP_NET_ADMIN for `aliases` (the compose overlay grants it
to the twin service only).
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import socket
import subprocess
import sys

IP_TIMEOUT = 10


def _run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=IP_TIMEOUT, check=False)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return 127, "", str(exc)


def _iface_for_subnet(subnet: str) -> str:
    """The interface holding an address inside `subnet` (the twinnet leg)."""
    net = ipaddress.ip_network(subnet)
    rc, out, err = _run(["ip", "-o", "-4", "addr", "show"])
    if rc != 0:
        raise RuntimeError(f"ip addr show failed: {err.strip()}")
    for line in out.splitlines():
        parts = line.split()
        # "N: eth1    inet 198.19.255.3/16 ..."
        if len(parts) >= 4 and parts[2] == "inet":
            ip = parts[3].split("/")[0]
            if ipaddress.ip_address(ip) in net:
                return parts[1]
    raise RuntimeError(f"no interface holds an address in {subnet} — is this "
                       f"container attached to twinnet?")


def cmd_aliases(args: argparse.Namespace) -> int:
    dev = _iface_for_subnet(args.subnet)
    errors: list[str] = []
    added = flushed = 0
    if args.flush:
        rc, out, err = _run(["ip", "-o", "-4", "addr", "show", "dev", dev])
        if rc != 0:
            errors.append(f"list {dev}: {err.strip()}")
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "inet" \
                    and parts[3].endswith("/32"):
                rc2, _, err2 = _run(["ip", "addr", "del", parts[3],
                                     "dev", dev])
                if rc2 != 0:
                    errors.append(f"del {parts[3]}: {err2.strip()}")
                else:
                    flushed += 1
    for ip in args.add or []:
        rc, _, err = _run(["ip", "addr", "add", f"{ip}/32", "dev", dev])
        # "File exists" = alias already present from a previous tick of the
        # same run — genuinely idempotent, not a swallowed failure.
        if rc != 0 and "File exists" not in err:
            errors.append(f"add {ip}: {err.strip()}")
        else:
            added += 1
    print(json.dumps({"iface": dev, "added": added, "flushed": flushed,
                      "errors": errors}))
    return 1 if errors else 0


def cmd_send(_args: argparse.Namespace) -> int:
    socks: dict[str, socket.socket] = {}
    sent = failed = 0
    errors: list[str] = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            src = d.get("src") or ""
            sk = socks.get(src)
            if sk is None:
                sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                if src:
                    sk.bind((src, 0))
                socks[src] = sk
            sk.sendto(base64.b64decode(d["data"]),
                      (d["host"], int(d["port"])))
            sent += 1
        except (OSError, ValueError, KeyError) as exc:
            failed += 1
            if len(errors) < 5:
                errors.append(f"{type(exc).__name__}: {exc}")
    for sk in socks.values():
        sk.close()
    print(json.dumps({"sent": sent, "failed": failed, "errors": errors}))
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="udp_agent.py",
                                 description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    al = sub.add_parser("aliases", help="add/flush per-device /32 aliases")
    al.add_argument("--subnet", required=True,
                    help="twinnet subnet (e.g. 198.19.0.0/16)")
    al.add_argument("--add", action="append", default=[])
    al.add_argument("--flush", action="store_true",
                    help="remove all /32 aliases from the twinnet iface first")
    sub.add_parser("send", help="send base64 datagrams from stdin JSON lines")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "aliases":
            return cmd_aliases(args)
        return cmd_send(args)
    except RuntimeError as exc:
        print(json.dumps({"errors": [str(exc)]}))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
