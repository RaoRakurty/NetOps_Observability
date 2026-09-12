#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""
reports.py — audit the reporting plane: delivery channels, schedules/runs and
execution history are readable. Read-only by design — it never calls /run or
/preview, which generate and (for /run) DELIVER a report.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import run_audit  # noqa: E402


class Audit:
    NAME = "reports"
    TITLE = "Reporting audit"

    def __init__(self, api, rep, args):
        self.api, self.rep, self.args = api, rep, args

    def run(self):
        r = self.rep
        r.section("Delivery channels")
        st, ch = self.api.call("GET", "/api/reports/channels")
        r.expect("List report channels", st == 200 and isinstance(ch, list),
                 ok_detail=f"channels: {ch}", bad_detail=f"got {st}")

        r.section("Schedules / runs")
        st, runs = self.api.call("GET", "/api/reports/runs")
        r.expect("List report runs", st == 200 and isinstance(runs, (dict, list)),
                 ok_detail=f"{len(runs) if isinstance(runs, (dict, list)) else 0} scheduled", bad_detail=f"got {st}")

        r.section("Execution history")
        st, ex = self.api.call("GET", "/api/reports/executions")
        r.expect("List report executions", st == 200,
                 ok_detail=f"{len(ex) if isinstance(ex, (dict, list)) else ''} executions", bad_detail=f"got {st}")
        r.info("Skipped /api/reports/run and /preview", "those generate/deliver a report")

        r.section("Authorization")
        st, _ = self.api.call("GET", "/api/reports/runs", token=None)
        r.expect("No token → 401 on reports", st == 401, bad_detail=f"got {st}")


if __name__ == "__main__":
    sys.exit(run_audit(Audit))
