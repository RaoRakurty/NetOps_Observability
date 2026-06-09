#!/usr/bin/env python3
"""
collectors.py — audit the collection plane: collector status + SNMP credential
and profile config (CRUD lifecycle, secret hygiene). No device polling is
triggered (no discovery refresh) — config-plane only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import run_audit, q  # noqa: E402


class Audit:
    NAME = "collectors"
    TITLE = "Collectors & SNMP config audit"

    def __init__(self, api, rep, args):
        self.api = api
        self.rep = rep
        self.args = args
        self.tag = f"audit_{os.getpid()}"

    def run(self):
        r = self.rep
        r.section("Collector status")
        st, b = self.api.call("GET", "/api/collectors")
        r.expect("List collectors", st == 200 and isinstance(b, list), bad_detail=f"got {st}")

        r.section("SNMP credentials — CRUD + secret hygiene")
        # v2c lifecycle.
        name = f"{self.tag}_cred"
        st, cred = self.api.call("POST", "/api/snmp/credentials",
                                body={"name": name, "version": "v2c", "community": "audit-secret-community"})
        created = st in (200, 201) and isinstance(cred, dict)
        r.expect("Create SNMP credential (v2c)", created, bad_detail=f"got {st}: {cred}")
        if not created:
            return
        cid = cred.get("id")
        st, lst = self.api.call("GET", "/api/snmp/credentials")
        present = isinstance(lst, list) and any(c.get("id") == cid for c in lst)
        r.expect("New credential appears in list", present, bad_detail=f"not found (got {st})")

        # POSTURE: the v2c community is returned in cleartext (by design — the field
        # comment says "shown so operators can verify it"). It IS a credential, and
        # the struct doc claims it "redacts every secret to a boolean", so flag it.
        listed = next((c for c in lst if c.get("id") == cid), {}) if isinstance(lst, list) else {}
        community_shown = cred.get("community") == "audit-secret-community" or listed.get("community") == "audit-secret-community"
        if community_shown:
            r.warn("v2c community is returned in CLEARTEXT by the API",
                   "deliberate (operators verify it in the UI) but it is a credential and the v3 keys "
                   "are masked — consider redacting to has_community only, or gate behind a reveal action.")
        else:
            r.ok("v2c community is not echoed back")

        st, _ = self.api.call("DELETE", f"/api/snmp/credentials/{q(cid)}")
        r.expect("Delete SNMP credential", st in (200, 204), bad_detail=f"got {st}")
        st, lst = self.api.call("GET", "/api/snmp/credentials")
        gone = not (isinstance(lst, list) and any(c.get("id") == cid for c in lst))
        r.expect("Deleted credential is gone", gone, bad_detail="still present after delete")

        # v3 USM keys MUST be masked — this is the hard guarantee (regression FAIL).
        st, v3 = self.api.call("POST", "/api/snmp/credentials", body={
            "name": f"{self.tag}_v3", "version": "v3", "security_name": "auditor",
            "security_level": "authPriv", "auth_protocol": "SHA", "auth_key": "audit-auth-secret-1",
            "priv_protocol": "AES128", "priv_key": "audit-priv-secret-1",
        })
        if st in (200, 201) and isinstance(v3, dict):
            v3id = v3.get("id")
            leaked = v3.get("auth_key") or v3.get("priv_key")
            r.expect("v3 auth/priv keys are NEVER returned (masked to has_* flags)", not leaked,
                     ok_detail=f"has_auth_key={v3.get('has_auth_key')} has_priv_key={v3.get('has_priv_key')}",
                     bad_detail=f"v3 USM key leaked: auth_key={v3.get('auth_key')!r} priv_key={v3.get('priv_key')!r}")
            if v3id:
                self.api.call("DELETE", f"/api/snmp/credentials/{q(v3id)}")
        else:
            r.warn("Could not create a v3 credential to test key masking", f"got {st}: {v3}")

        r.section("SNMP profiles & options")
        st, prof = self.api.call("GET", "/api/snmp/profiles")
        r.expect("List SNMP profiles", st == 200 and isinstance(prof, list), bad_detail=f"got {st}")
        st, opt = self.api.call("GET", "/api/snmp/options")
        r.expect("SNMP options catalog", st == 200, bad_detail=f"got {st}")

        r.section("Authorization")
        st, _ = self.api.call("GET", "/api/snmp/credentials", token=None)
        r.expect("No token → 401 on SNMP credentials", st == 401, bad_detail=f"got {st}")


if __name__ == "__main__":
    sys.exit(run_audit(Audit))
