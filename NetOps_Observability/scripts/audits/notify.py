#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""
notify.py — audit the notification plane: per-channel config is readable and the
contact-point store does a clean CRUD lifecycle.

SAFETY: the /api/notify/*/test endpoints actually deliver a message to the real
provider, so this audit NEVER calls them — config + contact-point store only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import run_audit, q  # noqa: E402


class Audit:
    NAME = "notify"
    TITLE = "Notifications config audit"

    def __init__(self, api, rep, args):
        self.api = api
        self.rep = rep
        self.args = args
        self.tag = f"audit_{os.getpid()}"

    def run(self):
        r = self.rep
        r.section("Channel config is readable (no test sends)")
        for ch in ("slack", "pagerduty", "smtp", "twilio", "ntfy", "itsm"):
            st, b = self.api.call("GET", f"/api/notify/{ch}")
            r.expect(f"GET notify/{ch} config", st == 200, bad_detail=f"got {st}")
        r.info("Skipped /api/notify/*/test on purpose", "those endpoints deliver real messages")

        r.section("Contact points — CRUD lifecycle")
        st, before = self.api.call("GET", "/api/notify/contact-points")
        r.expect("List contact points", st == 200 and isinstance(before, list), bad_detail=f"got {st}")
        name = f"{self.tag}_cp"
        st, cp = self.api.call("POST", "/api/notify/contact-points",
                              body={"name": name, "type": "email", "email": ["audit@example.invalid"], "enabled": False})
        created = st in (200, 201) and isinstance(cp, dict)
        r.expect("Create contact point (email, disabled)", created, bad_detail=f"got {st}: {cp}")
        if created:
            cid = cp.get("id")
            st, lst = self.api.call("GET", "/api/notify/contact-points")
            r.expect("New contact point appears in list",
                     isinstance(lst, list) and any(c.get("id") == cid for c in lst), bad_detail="not found")
            st, _ = self.api.call("DELETE", f"/api/notify/contact-points/{q(cid)}")
            r.expect("Delete contact point", st in (200, 204), bad_detail=f"got {st}")
            st, lst = self.api.call("GET", "/api/notify/contact-points")
            r.expect("Deleted contact point is gone",
                     not (isinstance(lst, list) and any(c.get("id") == cid for c in lst)),
                     bad_detail="still present after delete")

        r.section("Authorization")
        st, _ = self.api.call("GET", "/api/notify/slack", token=None)
        r.expect("No token → 401 on notify config", st == 401, bad_detail=f"got {st}")


if __name__ == "__main__":
    sys.exit(run_audit(Audit))
