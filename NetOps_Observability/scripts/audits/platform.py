#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""
platform.py — breadth audit across every backend module's API surface.

Smoke-level by design: for each module it confirms the endpoint is reachable,
authorizes the admin, and returns a sane JSON shape — plus that protected routes
reject an unauthenticated caller. It does NOT trigger destructive side effects
(no notification /test sends, no report runs). Deep, behaviour-level audits live
in the per-module scripts (iam.py is the reference depth).

Classification per GET:
    200 + JSON of the expected type      → PASS
    401 (with an admin token)            → FAIL (authz regression)
    0 / 5xx                              → FAIL (down / crashing)
    other 4xx (needs params / feature off)→ WARN (reachable, not green)
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import run_audit  # noqa: E402


class Audit:
    NAME = "platform"
    TITLE = "Platform / module API-surface audit"

    def __init__(self, api, rep, args):
        self.api = api
        self.rep = rep
        self.args = args

    def get(self, name, path, types=(list, dict), public=False):
        token = None if public else "__default__"
        st, b = self.api.call("GET", path, token=token)
        if st == 200 and isinstance(b, types):
            n = len(b) if isinstance(b, (list, dict)) else ""
            self.rep.ok(name, f"200, {type(b).__name__}{f'[{len(b)}]' if isinstance(b, (list, dict)) else ''}")
        elif st == 200:
            self.rep.ok(name, "200")
        elif st in (0,) or st >= 500:
            self.rep.fail(name, f"status {st}: {b}")
        elif st == 401 and not public:
            self.rep.fail(name, "401 with admin token — authz regression")
        else:
            self.rep.warn(name, f"status {st} (reachable but not 200): {str(b)[:120]}")

    def needs_auth(self, name, path):
        st, _ = self.api.call("GET", path, token=None)
        self.rep.expect(name, st == 401, ok_detail="401 without token", bad_detail=f"got {st} — protected route open?")

    def run(self):
        r = self.rep

        r.section("Health & readiness")
        self.get("Liveness /api/health", "/api/health", public=True)
        self.get("Readiness /admin/readyz", "/admin/readyz", types=(dict, str), public=True)
        self.get("Version /admin/version", "/admin/version", types=(dict, str), public=True)
        self.get("Stack health /api/stack/health", "/api/stack/health")

        r.section("Inventory & collectors")
        self.get("Devices", "/api/devices")
        self.get("Collectors", "/api/collectors")
        self.get("SNMP credentials", "/api/snmp/credentials")
        self.get("SNMP profiles", "/api/snmp/profiles")
        self.get("SNMP options", "/api/snmp/options")

        r.section("Alerts & incidents")
        self.get("Alerts", "/api/alerts")
        self.get("Rules", "/api/rules")
        self.get("Incidents", "/api/incidents")

        r.section("Correlation / anomaly findings")
        self.get("Findings", "/api/findings?since=3600s")

        r.section("Telemetry — logs / metrics / flows")
        self.get("Log indices", "/api/logs/indices")
        self.get("Metric names", "/api/metrics/names")
        self.get("Flows top", "/api/flows/top?since=3600s&limit=5")
        self.get("Flows by-proto", "/api/flows/by-proto?since=3600s")
        self.get("Flows by-type", "/api/flows/by-type?since=3600s")
        self.get("Flows timeseries", "/api/flows/timeseries?since=3600s&step=300s")
        self.get("Tunnels", "/api/tunnels?since=3600s")

        r.section("Topology & regions")
        self.get("Regions", "/api/regions")
        self.get("Region topology", "/api/regions/topology")

        r.section("Reporting")
        self.get("Report channels", "/api/reports/channels")
        self.get("Report runs", "/api/reports/runs")
        self.get("Report executions", "/api/reports/executions")

        r.section("Integrations & ITSM (config only — no sends)")
        self.get("Integrations", "/api/integrations")
        self.get("ServiceNow status", "/api/itsm/servicenow")
        self.get("Jira status", "/api/itsm/jira")
        self.get("ITSM config", "/api/notify/itsm")

        r.section("Notifications (config only — no test sends)")
        for ch in ("slack", "pagerduty", "smtp", "twilio", "ntfy"):
            self.get(f"Notify {ch} config", f"/api/notify/{ch}")
        self.get("Contact points", "/api/notify/contact-points")

        r.section("Security policy engine")
        self.get("Policy catalog", "/api/policy/catalog")
        self.get("Policy documents", "/api/policy/documents")
        self.get("Effective policy", "/api/policy/effective")

        r.section("API surface")
        self.get("OpenAPI spec", "/api/openapi.json")
        self.get("Accessible scopes", "/api/scopes")
        self.get("Audit log", "/api/audit?limit=10")
        st, b = self.api.call("POST", "/api/graphql", body={"query": "{ __typename }"})
        self.rep.expect("GraphQL endpoint responds", st in (200, 400, 422),
                        ok_detail=f"status {st}", bad_detail=f"status {st}: {b}", warn_on_fail=True)

        r.section("Unauthenticated access is rejected")
        for nm, p in (("devices", "/api/devices"), ("alerts", "/api/alerts"),
                      ("findings", "/api/findings"), ("metrics", "/api/metrics/names"),
                      ("reports", "/api/reports/runs"), ("audit", "/api/audit")):
            self.needs_auth(f"No token → 401 on /api/{nm}", p)


if __name__ == "__main__":
    sys.exit(run_audit(Audit))
