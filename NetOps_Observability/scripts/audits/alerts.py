#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""
alerts.py — audit the alerting plane: rules, active alerts, incidents. Read-only
(rule/incident mutation has side effects), but deeper than smoke: it validates the
shape of each rule and reports the live counts.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import run_audit  # noqa: E402


class Audit:
    NAME = "alerts"
    TITLE = "Alerts / rules / incidents audit"

    def __init__(self, api, rep, args):
        self.api, self.rep, self.args = api, rep, args

    def run(self):
        r = self.rep
        r.section("Alert rules")
        st, rules = self.api.call("GET", "/api/rules")
        if r.expect("List rules", st == 200 and isinstance(rules, list), bad_detail=f"got {st}"):
            def sev(x):
                return x.get("severity") or (x.get("labels") or {}).get("severity")
            bad = [x for x in rules if not (isinstance(x, dict) and x.get("name") and x.get("expr") and sev(x))]
            r.expect("Every rule has name + expr + severity", not bad,
                     ok_detail=f"{len(rules)} rules", bad_detail=f"{len(bad)} malformed rule(s)")
            sevs = sorted({sev(x) for x in rules if isinstance(x, dict) and sev(x)})
            r.info("Rule severities present", ", ".join(sevs) or "(none)")

        r.section("Active alerts")
        st, alerts = self.api.call("GET", "/api/alerts")
        r.expect("List alerts", st == 200 and isinstance(alerts, list),
                 ok_detail=f"{len(alerts) if isinstance(alerts, list) else 0} firing", bad_detail=f"got {st}")

        r.section("Incidents")
        st, inc = self.api.call("GET", "/api/incidents")
        r.expect("List incidents", st == 200 and isinstance(inc, list),
                 ok_detail=f"{len(inc) if isinstance(inc, list) else 0} incidents", bad_detail=f"got {st}")

        r.section("Authorization")
        st, _ = self.api.call("GET", "/api/rules", token=None)
        r.expect("No token → 401 on rules", st == 401, bad_detail=f"got {st}")


if __name__ == "__main__":
    sys.exit(run_audit(Audit))
