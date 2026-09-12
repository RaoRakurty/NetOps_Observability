#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""
integrations.py — audit the ITSM / integration plane: provider config and
connector status are readable and well-shaped. Config-only — no tickets are
created, no outbound sync is triggered.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import run_audit  # noqa: E402


class Audit:
    NAME = "integrations"
    TITLE = "Integrations / ITSM audit"

    def __init__(self, api, rep, args):
        self.api, self.rep, self.args = api, rep, args

    def run(self):
        r = self.rep
        r.section("Integration platform config")
        st, integ = self.api.call("GET", "/api/integrations")
        r.expect("List integrations", st == 200 and isinstance(integ, (dict, list)), bad_detail=f"got {st}: {integ}")

        r.section("ITSM connector status")
        for name, path in (("ServiceNow", "/api/itsm/servicenow"), ("Jira", "/api/itsm/jira")):
            st, b = self.api.call("GET", path)
            if r.expect(f"{name} status reachable", st == 200 and isinstance(b, dict), bad_detail=f"got {st}"):
                r.info(f"{name} state", f"enabled={b.get('enabled')} connected={b.get('connected', b.get('reachable'))}")
        st, _ = self.api.call("GET", "/api/notify/itsm")
        r.expect("ITSM config readable", st == 200, bad_detail=f"got {st}")

        r.section("Webhook ingress is signature-gated (not open)")
        # Inbound provider webhooks authenticate via per-tenant path token + HMAC;
        # a bare POST with no signature must be rejected (not 2xx).
        st, _ = self.api.call("POST", "/api/integrations/webhook/servicenow", token=None, body={"x": 1})
        r.expect("Unsigned webhook POST is rejected", st >= 400,
                 ok_detail=f"rejected {st}", bad_detail=f"got {st} — open webhook ingress?", warn_on_fail=True)

        r.section("Authorization")
        st, _ = self.api.call("GET", "/api/integrations", token=None)
        r.expect("No token → 401 on integrations", st == 401, bad_detail=f"got {st}")


if __name__ == "__main__":
    sys.exit(run_audit(Audit))
