"""Shared live statistics for the dashboard.

Workers publish a small per-worker snapshot into a multiprocessing Manager dict
~1/sec; the API aggregates them into totals + rates + per-app / per-protocol /
per-mode breakdowns (the IXIA/Ostinato counters).
"""
from __future__ import annotations

import time
from collections import defaultdict


class WorkerStat:
    """Per-worker rolling counters, flushed to the shared dict periodically."""

    def __init__(self, shared, wid: str, mode: str):
        self.shared = shared
        self.wid = wid
        self.mode = mode
        self.flows = 0
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.pkts = 0
        self.per_app: dict[str, int] = defaultdict(int)
        self.per_proto: dict[str, int] = defaultdict(int)
        self._last = 0.0

    def add_flow(self, app: str, proto: int, fwd_b: int, rev_b: int, pkts: int) -> None:
        self.flows += 1
        self.tx_bytes += fwd_b
        self.rx_bytes += rev_b
        self.pkts += pkts
        self.per_app[app] += 1
        self.per_proto[{6: "tcp", 17: "udp", 1: "icmp"}.get(proto, str(proto))] += 1

    def flush(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last < 1.0:
            return
        self._last = now
        self.shared[self.wid] = {
            "mode": self.mode, "flows": self.flows, "tx_bytes": self.tx_bytes,
            "rx_bytes": self.rx_bytes, "pkts": self.pkts, "ts": now,
            "per_app": dict(self.per_app), "per_proto": dict(self.per_proto),
        }


class Aggregator:
    """Reads the shared per-worker snapshots and computes totals + rates."""

    def __init__(self, shared):
        self.shared = shared
        self._prev_total = (0, 0, 0, 0.0)  # flows, tx, rx, ts

    def snapshot(self) -> dict:
        flows = tx = rx = pkts = 0
        per_app: dict[str, int] = defaultdict(int)
        per_proto: dict[str, int] = defaultdict(int)
        per_mode: dict[str, int] = defaultdict(int)
        workers = []
        for wid, s in list(self.shared.items()):
            flows += s["flows"]; tx += s["tx_bytes"]; rx += s["rx_bytes"]; pkts += s["pkts"]
            per_mode[s["mode"]] += s["flows"]
            for a, c in s.get("per_app", {}).items():
                per_app[a] += c
            for p, c in s.get("per_proto", {}).items():
                per_proto[p] += c
            workers.append({"id": wid, "mode": s["mode"], "flows": s["flows"]})

        now = time.time()
        pf, ptx, prx, pts = self._prev_total
        dt = max(now - pts, 1e-6) if pts else 1.0
        fps = (flows - pf) / dt if pts else 0.0
        bps = ((tx + rx) - (ptx + prx)) * 8 / dt if pts else 0.0
        self._prev_total = (flows, tx, rx, now)

        top_apps = sorted(per_app.items(), key=lambda kv: -kv[1])[:25]
        return {
            "totals": {"flows": flows, "tx_bytes": tx, "rx_bytes": rx, "pkts": pkts},
            "rates": {"fps": round(fps, 1), "bps": round(bps, 1)},
            "per_app": [{"app": a, "flows": c} for a, c in top_apps],
            "per_proto": [{"proto": p, "flows": c} for p, c in sorted(per_proto.items(), key=lambda kv: -kv[1])],
            "per_mode": [{"mode": m, "flows": c} for m, c in sorted(per_mode.items())],
            "workers": workers,
            "ts": now,
        }
