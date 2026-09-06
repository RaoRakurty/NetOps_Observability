# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""tgen CLI — craft enterprise/SaaS/AI traffic as flow telemetry and/or packets.

  python -m tgen --collector 10.70.245.122 --mode ipfix --fps 2000 --duration 0
  python -m tgen --mode all --apps ai,collaboration,m365 --workers 4
  python -m tgen --mode packets --duration 60         # real frames (CAP_NET_RAW)
  python -m tgen --mode l7 --apps web-https,dns        # real client sessions
"""
from __future__ import annotations

import argparse
import multiprocessing as mp
import os
import random
import signal
import sys
import time

from .catalog import CATALOG, by_names, categories
from .encoders.ipfix import IpfixEncoder
from .encoders.netflow9 import NetflowV9Encoder
from .encoders.sflow import SflowEncoder
from .flow import realize
from .sender import RateLimiter, UdpSender

PORTS = {"ipfix": 4739, "netflow9": 2055, "sflow": 6343}


def _telemetry_worker(mode: str, collector: str, port: int, apps, fps: int,
                      batch: int, duration: int, seed: int) -> None:
    rnd = random.Random(seed)
    enc = {"ipfix": IpfixEncoder, "netflow9": NetflowV9Encoder, "sflow": SflowEncoder}[mode]()
    sender = UdpSender(collector, port)
    rl = RateLimiter(rate=max(fps, 1), burst=max(fps, batch * 2))
    weights = [a.weight for a in apps]
    end = time.monotonic() + duration if duration else None
    flows_sent = 0
    last_log = time.monotonic()
    while end is None or time.monotonic() < end:
        rl.take(batch)
        flows = [realize(rnd.choices(apps, weights=weights, k=1)[0], rnd) for _ in range(batch)]
        datagram = enc.encode(flows)
        sender.send_batch([datagram])
        flows_sent += batch
        if time.monotonic() - last_log > 5:
            print(f"[{mode} w{seed}] {flows_sent} flows sent", flush=True)
            last_log = time.monotonic()


def _packets_worker(collector_unused, apps, pps, duration, seed) -> None:
    from .packets import RawPacketGen
    rnd = random.Random(seed)
    try:
        gen = RawPacketGen()
    except PermissionError:
        print("packets mode needs CAP_NET_RAW (run the container with --cap-add NET_RAW)", file=sys.stderr)
        return
    gen.run(apps, pps, duration, rnd)


def _l7_worker(apps, rate, duration, seed) -> None:
    from .l7 import run_sessions
    rnd = random.Random(seed)
    stats = run_sessions(apps, rate, duration, rnd)
    print(f"[l7 w{seed}] sessions ok={stats['ok']} fail={stats['fail']}", flush=True)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="tgen", description="OTG-modeled lab traffic generator")
    p.add_argument("--collector", default=os.getenv("TGEN_COLLECTOR", "10.70.245.122"),
                   help="NMS collector IP (goflow2)")
    p.add_argument("--mode", default="ipfix",
                   choices=["ipfix", "netflow9", "sflow", "packets", "l7", "all"])
    p.add_argument("--apps", default="", help="comma list of app or category names (default: all)")
    p.add_argument("--fps", type=int, default=2000, help="flows/sec for telemetry modes")
    p.add_argument("--pps", type=int, default=500, help="packets/sec for packets mode")
    p.add_argument("--l7-rate", type=float, default=5.0, help="sessions/sec for l7 mode")
    p.add_argument("--batch", type=int, default=32, help="flows per telemetry datagram")
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--duration", type=int, default=0, help="seconds (0 = run forever)")
    p.add_argument("--list", action="store_true", help="list the app catalog and exit")
    p.add_argument("--port", type=int, default=0, help="override collector port")
    p.add_argument("--serve", action="store_true",
                   help="run the control API + dashboard (stats/start/stop) instead of a one-shot run")
    p.add_argument("--api-port", type=int, default=int(os.getenv("TGEN_API_PORT", "8080")))
    p.add_argument("--autostart", action="store_true", default=True,
                   help="(serve mode) begin generating immediately")
    p.add_argument("--no-autostart", dest="autostart", action="store_false")
    args = p.parse_args(argv)

    if args.serve:
        from .server import serve
        overrides = {"fps": args.fps, "batch": args.batch, "workers": args.workers,
                     "apps": [s.strip() for s in args.apps.split(",") if s.strip()]}
        serve(args.collector, args.api_port, args.autostart, overrides)
        return 0

    apps = by_names(args.apps.split(",")) if args.apps else CATALOG
    if args.list or not apps:
        print(f"categories: {sorted(categories())}")
        for a in CATALOG:
            print(f"  {a.name:18} {a.category:14} {a.proto:3} ports={a.dst_ports} w={a.weight}")
        return 0

    print(f"tgen: mode={args.mode} collector={args.collector} apps={len(apps)} "
          f"workers={args.workers} fps={args.fps} duration={args.duration or '∞'}", flush=True)

    procs: list[mp.Process] = []
    modes = ["ipfix", "netflow9", "sflow"] if args.mode == "all" else [args.mode]

    for m in modes:
        for w in range(args.workers):
            seed = w + hash(m) % 1000
            if m in PORTS:
                port = args.port or PORTS[m]
                fps = max(1, args.fps // args.workers)
                pr = mp.Process(target=_telemetry_worker,
                                args=(m, args.collector, port, apps, fps, args.batch, args.duration, seed))
            elif m == "packets":
                pr = mp.Process(target=_packets_worker,
                                args=(args.collector, apps, args.pps // args.workers, args.duration, seed))
            else:  # l7
                pr = mp.Process(target=_l7_worker,
                                args=(apps, args.l7_rate / args.workers, args.duration, seed))
            pr.start()
            procs.append(pr)

    def _stop(*_):
        for pr in procs:
            pr.terminate()
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    for pr in procs:
        pr.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
