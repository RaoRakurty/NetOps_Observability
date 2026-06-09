#!/usr/bin/env python3
"""
telemetry.py — audit the data plane: are logs, metrics, flows and correlation
findings actually reachable and flowing? Endpoint errors (5xx / 401) FAIL; an
endpoint that's up but returning zero rows is reported as WARN (the lab may be
idle) rather than failing — it tells you the pipe is dry, not broken.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import run_audit  # noqa: E402


class Audit:
    NAME = "telemetry"
    TITLE = "Telemetry data-flow audit"

    def __init__(self, api, rep, args):
        self.api, self.rep, self.args = api, rep, args

    def flow(self, name, path, count_key=None):
        st, b = self.api.call("GET", path)
        if st == 401:
            self.rep.fail(name, "401 with admin token")
            return
        if st == 0 or st >= 500:
            self.rep.fail(name, f"status {st}: {str(b)[:100]}")
            return
        if st != 200:
            self.rep.warn(name, f"reachable but status {st}")
            return
        n = _count(b, count_key)
        if n == 0:
            self.rep.warn(name, "reachable but 0 rows (pipe up, no data — idle lab?)")
        else:
            self.rep.ok(name, f"{n} rows")

    def run(self):
        r = self.rep
        r.section("Logs (OpenSearch)")
        self.flow("Log indices", "/api/logs/indices")

        r.section("Metrics (VictoriaMetrics / Prometheus)")
        self.flow("Metric names", "/api/metrics/names")

        r.section("Flows (ClickHouse)")
        self.flow("Flows top", "/api/flows/top?since=86400s&limit=10")
        self.flow("Flows by-proto", "/api/flows/by-proto?since=86400s")
        self.flow("Flows by-type", "/api/flows/by-type?since=86400s")

        r.section("Correlation findings (ClickHouse)")
        self.flow("Findings (24h)", "/api/findings?since=86400s")

        r.section("Devices (inventory feeding telemetry)")
        self.flow("Devices", "/api/devices")

        r.section("Authorization")
        st, _ = self.api.call("GET", "/api/logs/indices", token=None)
        r.expect("No token → 401 on logs", st == 401, bad_detail=f"got {st}")


def _count(b, count_key):
    if isinstance(b, list):
        return len(b)
    if isinstance(b, dict):
        if count_key and isinstance(b.get(count_key), list):
            return len(b[count_key])
        # common shapes: {data:{result:[...]}} (prom), {rows:[...]}, {hits:{hits:[...]}}
        for path in (("data", "result"), ("rows",), ("data",), ("hits", "hits")):
            cur = b
            for k in path:
                cur = cur.get(k) if isinstance(cur, dict) else None
            if isinstance(cur, list):
                return len(cur)
        return len(b)
    return 0


if __name__ == "__main__":
    sys.exit(run_audit(Audit))
