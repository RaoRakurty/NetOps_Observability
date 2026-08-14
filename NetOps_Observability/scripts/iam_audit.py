#!/usr/bin/env python3
"""
iam_audit.py — end-to-end IAM / tenancy security audit for NetOps_Observability.

Exercises EVERY identity component through the live API and asserts it behaves as
expected: the Region → Organization → Tenant → User tree, role bindings, the
session/token lifecycle, and the password / lockout / session policy knobs.

It answers the operational questions:
  • When you DISABLE or DELETE a user, do they actually lose access — or are they
    still "remembered" by a cached token?
  • When you REVOKE a role binding or an API key, does access stop?
  • Is there cross-tenant leakage (org A seeing org B's users)?
  • Are the password-policy controls (min length, complexity, reuse/history,
    lockout, expiry, idle/session timeout) actually ENFORCED, or just stored?

Design:
  • Stdlib only (urllib) — matches the project's offline / zero-dependency ethos.
  • Idempotent: every resource it creates is prefixed `audit_<pid>_` and torn
    down in a finally block, even on failure.
  • Severities:
       PASS  a control that should hold, holds.
       FAIL  a security control that IS implemented has regressed → exit 1.
       WARN  a known gap / inherent trade-off (e.g. JWT cached until expiry,
             a policy knob that is stored but not yet enforced) → exit 0,
             unless --strict (then WARN also fails).
       INFO  context only.

Usage:
    python3 scripts/iam_audit.py \
        --base-url http://localhost:8000 \
        --user admin --password '<admin password>'
    # or via env: IAM_AUDIT_BASE_URL, IAM_AUDIT_USER, IAM_AUDIT_PASSWORD
    #   --strict   treat WARN as failure (exit 1)
    #   --keep     don't delete the resources it created (for debugging)

Exit code: 0 = all PASS (WARN allowed unless --strict); 1 = at least one FAIL.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

# ---- tiny HTTP client ------------------------------------------------------

class API:
    def __init__(self, base_url):
        self.base = base_url.rstrip("/")

    def call(self, method, path, token=None, body=None):
        """Return (status_code, parsed_json_or_text). Never raises on HTTP error."""
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                raw = r.read().decode()
                return r.status, _maybe_json(raw)
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            return e.code, _maybe_json(raw)
        except urllib.error.URLError as e:
            return 0, {"error": str(e)}


def _maybe_json(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw


# ---- result accounting -----------------------------------------------------

class Report:
    def __init__(self, strict):
        self.strict = strict
        self.counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0}
        self.failures = []

    def _emit(self, sev, name, detail):
        self.counts[sev] += 1
        color = {"PASS": "\033[32m", "FAIL": "\033[31m", "WARN": "\033[33m", "INFO": "\033[36m"}[sev]
        reset = "\033[0m"
        line = f"  {color}{sev:4}{reset}  {name}"
        if detail:
            line += f"\n          ↳ {detail}"
        print(line)
        if sev == "FAIL" or (sev == "WARN" and self.strict):
            self.failures.append(name)

    def ok(self, name, detail=""):
        self._emit("PASS", name, detail)

    def fail(self, name, detail=""):
        self._emit("FAIL", name, detail)

    def warn(self, name, detail=""):
        self._emit("WARN", name, detail)

    def info(self, name, detail=""):
        self._emit("INFO", name, detail)

    def expect(self, name, condition, ok_detail="", bad_detail="", warn_on_fail=False):
        """Assert `condition`; PASS if true, else FAIL (or WARN if warn_on_fail)."""
        if condition:
            self.ok(name, ok_detail)
        elif warn_on_fail:
            self.warn(name, bad_detail)
        else:
            self.fail(name, bad_detail)
        return condition

    def section(self, title):
        print(f"\n\033[1m── {title}\033[0m")

    def summary(self):
        c = self.counts
        print("\n" + "=" * 64)
        print(f" PASS {c['PASS']}   FAIL {c['FAIL']}   WARN {c['WARN']}   INFO {c['INFO']}")
        if self.failures:
            print(" Failed checks:")
            for f in self.failures:
                print(f"   • {f}")
        print("=" * 64)
        return 1 if self.failures else 0


# ---- the audit -------------------------------------------------------------

class Audit:
    def __init__(self, api, rep, admin_user, admin_pass, keep):
        self.api = api
        self.rep = rep
        self.admin_user = admin_user
        self.admin_pass = admin_pass
        self.keep = keep
        self.tok = None                 # admin token
        self.tag = f"audit_{os.getpid()}"
        # teardown registries (reverse-dependency order matters)
        self.users = []
        self.bindings = []
        self.tenants = []   # (id, name)
        self.orgs = []
        self.apikeys = []

    # -- helpers --
    def login(self, user, password):
        st, b = self.api.call("POST", "/api/auth/login", body={"username": user, "password": password})
        if st == 200 and isinstance(b, dict):
            return b
        return None

    def admin(self, method, path, body=None):
        return self.api.call(method, path, self.tok, body)

    def mk_user(self, name, password, role="read-only", tenant_id="", status="active"):
        st, b = self.admin("POST", "/api/users",
                           {"username": name, "password": password, "role": role,
                            "tenant_id": tenant_id, "status": status})
        if st == 201:
            self.users.append(name)
        return st, b

    # -- 0. connectivity + admin login --
    def phase_login(self):
        self.rep.section("0. Connectivity & admin login")
        st, _ = self.api.call("GET", "/api/health")
        if not self.rep.expect("API reachable (/api/health)", st in (200, 401),
                               bad_detail=f"got status {st} — is the stack up on {self.api.base}?"):
            return False
        lr = self.login(self.admin_user, self.admin_pass)
        if not self.rep.expect("Admin can log in", lr is not None,
                               bad_detail="admin login failed — wrong --password? (see README / .env ADMIN_INITIAL_PASSWORD)"):
            return False
        self.tok = lr["token"]
        st, me = self.admin("GET", "/api/auth/me")
        self.rep.expect("Access token authorizes /api/auth/me", st == 200,
                        ok_detail=f"role={me.get('role') if isinstance(me, dict) else '?'}")
        return True

    # -- 1. unauthenticated / bad-credential rejection --
    def phase_auth_negative(self):
        self.rep.section("1. Authentication — negative paths")
        st, _ = self.api.call("GET", "/api/users")
        self.rep.expect("No token → 401 on protected route", st == 401, bad_detail=f"got {st}")
        st, _ = self.api.call("POST", "/api/auth/login", body={"username": self.admin_user, "password": "definitely-wrong"})
        self.rep.expect("Wrong password → 401", st == 401, bad_detail=f"got {st}")
        st, _ = self.api.call("POST", "/api/auth/login", body={"username": "ghost_nonexistent", "password": "x"})
        self.rep.expect("Unknown user → 401 (no enumeration)", st == 401, bad_detail=f"got {st}")
        st, _ = self.api.call("GET", "/api/users", token="garbage.token.here")
        self.rep.expect("Forged/garbage token → 401", st == 401, bad_detail=f"got {st}")

    # -- 2. regions (catalog) --
    def phase_regions(self):
        self.rep.section("2. Regions (data-residency catalog)")
        st, regions = self.admin("GET", "/api/regions")
        self.rep.expect("List regions", st == 200 and isinstance(regions, list) and len(regions) > 0,
                        ok_detail=f"{len(regions) if isinstance(regions, list) else 0} regions")
        self.region_id = regions[0]["id"] if isinstance(regions, list) and regions else "us-east"
        self.rep.info("Regions are a fixed catalog (GET-only)", "no create/delete API by design")

    # -- 3. org → tenant → user tree (CRUD + cascade) --
    def phase_tree(self):
        self.rep.section("3. Organization → Tenant → User tree (CRUD + cascade)")
        org_name = f"{self.tag}_orgA"
        st, org = self.admin("POST", "/api/orgs", {"name": org_name, "home_region": self.region_id})
        if not self.rep.expect("Create organization", st == 201 and isinstance(org, dict),
                               bad_detail=f"got {st}: {org}"):
            return
        self.org_a = org["id"]
        self.orgs.append(self.org_a)

        # Org-owned user (tenant_id = org id) — must NOT be global.
        st, _ = self.mk_user(f"{self.tag}_alice", "Aud1tPass!2345", role="operator", tenant_id=self.org_a)
        self.rep.expect("Create org-scoped user (tenant_id = org id)", st == 201, bad_detail=f"got {st}")
        st, allusers = self.admin("GET", "/api/users")
        alice = _find(allusers, "username", f"{self.tag}_alice")
        self.rep.expect("Org user is strictly associated (not global)",
                        alice is not None and alice.get("tenant_id") == self.org_a,
                        ok_detail=f"tenant_id={alice.get('tenant_id') if alice else '?'}",
                        bad_detail="org user has empty/global tenant_id — would be a global account")

        # Optional tenant inside the org.
        tname = f"{self.tag}_tenant1"
        st, ten = self.admin("POST", "/api/tenants",
                            {"name": tname, "note": "audit", "operator_restricted": False,
                             "org_id": self.org_a, "region": ""})
        if self.rep.expect("Create tenant inside org", st == 201 and isinstance(ten, dict), bad_detail=f"got {st}: {ten}"):
            self.tenants.append((ten["id"], ten["name"]))
            st, _ = self.mk_user(f"{self.tag}_tom", "Aud1tPass!2345", role="read-only", tenant_id=ten["id"])
            self.rep.expect("Create tenant-scoped user", st == 201, bad_detail=f"got {st}")

        # Cascade guard: an org that still owns tenants cannot be deleted.
        st, _ = self.admin("DELETE", f"/api/orgs/{self.org_a}")
        self.rep.expect("Delete org with tenants is REFUSED (cascade guard)", st in (400, 409),
                        ok_detail=f"refused with {st}",
                        bad_detail=f"got {st} — org deleted while it still owned a tenant!")

    # -- 4. cross-tenant isolation (the leak test) --
    def phase_isolation(self):
        self.rep.section("4. Cross-tenant isolation (leak test)")
        # Second org with its own admin + user.
        st, orgb = self.admin("POST", "/api/orgs", {"name": f"{self.tag}_orgB", "home_region": self.region_id})
        if not self.rep.expect("Create second organization", st == 201, bad_detail=f"got {st}"):
            return
        self.org_b = orgb["id"]
        self.orgs.append(self.org_b)
        self.mk_user(f"{self.tag}_a_admin", "Aud1tPass!2345", role="admin", tenant_id=self.org_a)
        self.mk_user(f"{self.tag}_b_bob", "Aud1tPass!2345", role="operator", tenant_id=self.org_b)

        lr = self.login(f"{self.tag}_a_admin", "Aud1tPass!2345")
        if not self.rep.expect("Org-A admin can log in", lr is not None):
            return
        st, visible = self.api.call("GET", "/api/users", lr["token"])
        if st != 200 or not isinstance(visible, list):
            self.rep.warn("Org-A admin user listing", f"status {st}: {visible}")
            return
        names = [u.get("username") for u in visible]
        tenants_seen = {u.get("tenant_id") for u in visible}
        leaked = [n for n in names if n in (f"{self.tag}_b_bob", self.admin_user)]
        self.rep.expect("Org-A admin sees ONLY org-A users (no cross-tenant leak)",
                        not leaked,
                        ok_detail=f"sees {names}",
                        bad_detail=f"LEAK: org-A admin sees {leaked}; tenants={tenants_seen}")

    # -- 5. disable / delete enforcement + token caching window --
    def phase_lifecycle(self):
        self.rep.section("5. Disable / Delete enforcement + token caching window")
        u = f"{self.tag}_victim"
        self.mk_user(u, "Aud1tPass!2345", role="read-only", tenant_id="")
        pre = self.login(u, "Aud1tPass!2345")
        self.rep.expect("New user can log in", pre is not None)
        pre_tok = pre["token"] if pre else None

        # DISABLE → new login must be refused (regression target for the fix).
        st, _ = self.admin("PATCH", f"/api/users/{u}", {"status": "disabled"})
        self.rep.expect("Disable user (PATCH status=disabled)", st == 200, bad_detail=f"got {st}")
        st, _ = self.api.call("POST", "/api/auth/login", body={"username": u, "password": "Aud1tPass!2345"})
        self.rep.expect("Disabled user CANNOT start a new session", st == 401,
                        bad_detail=f"got {st} — disabled account still logs in!")
        # Refresh must also be refused for the disabled account.
        if pre and pre.get("refresh_token"):
            st, _ = self.api.call("POST", "/api/auth/refresh", body={"refresh_token": pre["refresh_token"]})
            self.rep.expect("Disabled user CANNOT refresh", st == 401, bad_detail=f"got {st}")

        # Caching window: does the access token issued BEFORE disable still work?
        if pre_tok:
            st, _ = self.api.call("GET", "/api/auth/me", pre_tok)
            if st == 200:
                self.rep.warn("Pre-issued access token still valid AFTER disable",
                              "JWT is stateless: revocation lags by up to ACCESS_TOKEN_TTL (default 1h). "
                              "withAuth() does not re-load the user per request. Mitigate with a short TTL "
                              "or a per-request status/jti check if instant kill is required.")
            else:
                self.rep.ok("Pre-issued access token rejected after disable (instant revoke)")

        # DELETE → login refused; principal's bindings cleaned up.
        st, _ = self.admin("DELETE", f"/api/users/{u}")
        if st == 204 and u in self.users:
            self.users.remove(u)
        self.rep.expect("Delete user", st == 204, bad_detail=f"got {st}")
        st, _ = self.api.call("POST", "/api/auth/login", body={"username": u, "password": "Aud1tPass!2345"})
        self.rep.expect("Deleted user cannot log in", st == 401, bad_detail=f"got {st}")
        st, binds = self.admin("GET", "/api/bindings")
        dangling = [b for b in binds if isinstance(b, dict) and b.get("principal_id", "").lower() == u.lower()] if isinstance(binds, list) else []
        self.rep.expect("Deleted user leaves no dangling role bindings", not dangling,
                        bad_detail=f"orphaned bindings: {dangling}")

    # -- 6. role binding grant / revoke (cross-tenant reach) --
    def phase_bindings(self):
        self.rep.section("6. Role bindings — grant / revoke")
        u = f"{self.tag}_granted"
        self.mk_user(u, "Aud1tPass!2345", role="read-only", tenant_id="")
        scope = f"org:{self.org_a}"
        st, b = self.admin("POST", "/api/bindings",
                          {"principal_id": u, "role_id": "operator", "scope_id": scope, "effect": "allow"})
        if self.rep.expect("Grant binding to existing user", st == 201 and isinstance(b, dict), bad_detail=f"got {st}: {b}"):
            bid = b["id"]
            # unknown principal must be rejected (the bug class the UI picker fixed)
            st2, _ = self.admin("POST", "/api/bindings",
                              {"principal_id": "nobody_xyz", "role_id": "operator", "scope_id": scope, "effect": "allow"})
            self.rep.expect("Grant to unknown principal is REFUSED", st2 == 400, bad_detail=f"got {st2}")
            # revoke → gone immediately (bindings are read live per request)
            st, _ = self.admin("DELETE", f"/api/bindings/{_q(bid)}")
            self.rep.expect("Revoke binding", st == 204, bad_detail=f"got {st}")
            st, binds = self.admin("GET", "/api/bindings")
            still = any(isinstance(x, dict) and x.get("id") == bid for x in binds) if isinstance(binds, list) else True
            self.rep.expect("Revoked binding is gone (not cached server-side)", not still,
                            bad_detail="binding still present after revoke")

    # -- 7. API key issue / use / revoke --
    def phase_apikeys(self):
        self.rep.section("7. API keys — issue / use / revoke")
        st, res = self.admin("POST", "/api/apikeys",
                           {"label": f"{self.tag}_key", "scopes": ["read:devices"]})
        if not self.rep.expect("Issue API key", st in (200, 201) and isinstance(res, dict) and res.get("secret"),
                               bad_detail=f"got {st}: {res}"):
            return
        secret = res["secret"]
        kid = res.get("key", {}).get("id")
        if kid:
            self.apikeys.append(kid)
        st, _ = self.api.call("GET", "/api/devices", token=secret)
        self.rep.expect("Valid API key authorizes a scoped call", st in (200, 204),
                        bad_detail=f"got {st}", warn_on_fail=True)
        if kid:
            st, _ = self.admin("DELETE", f"/api/apikeys/{_q(kid)}")
            if st == 204 and kid in self.apikeys:
                self.apikeys.remove(kid)
            self.rep.expect("Revoke API key", st == 204, bad_detail=f"got {st}")
            st, _ = self.api.call("GET", "/api/devices", token=secret)
            self.rep.expect("Revoked API key is rejected immediately", st == 401,
                            bad_detail=f"got {st} — revoked key still works!")

    # -- 8. password policy enforcement --
    def phase_password_policy(self):
        self.rep.section("8. Password policy — enforcement")
        scope = "provider"
        st, base = self.admin("GET", f"/api/security-settings?scope={scope}")
        if not self.rep.expect("Read security settings", st == 200 and isinstance(base, dict), bad_detail=f"got {st}"):
            return
        original = dict(base)

        # change-password is a PUBLIC route (so the forced-change-at-login flow works):
        # it identifies the account by the `username` in the body and proves ownership
        # with the current password. So self-service change calls must pass username.
        def change_pw(user, current, new):
            return self.api.call("POST", "/api/auth/change-password", None,
                                 {"username": user, "current_password": current, "new_password": new})

        # 8a. min length floor — always enforced on create (validatePassword, ≥8).
        st, _ = self.mk_user(f"{self.tag}_short", "x")
        self.rep.expect("Below-floor password REJECTED on create", st >= 400, bad_detail=f"got {st}")
        if st == 201:
            self.users.append(f"{self.tag}_short")

        # Turn on a strong policy for the scope.
        strong = dict(base)
        strong.update({"min_password_length": 12, "require_uppercase": True, "require_lowercase": True,
                       "require_number": True, "require_special": True})
        self.admin("PUT", f"/api/security-settings?scope={scope}", strong)

        # 8b. admin CREATE vs configured policy — "abcdefgh" clears the hard floor (8) but
        #     violates the configured min-length(12)+complexity.
        st, _ = self.mk_user(f"{self.tag}_weakcreate", "abcdefgh")
        if st == 201:
            self.users.append(f"{self.tag}_weakcreate")
            self.rep.warn("Admin CREATE bypasses the configured password policy",
                          "CreateFull validates only the hard floor (≥8 chars) — the scope's "
                          "min-length(12) and complexity rules are NOT applied on create. "
                          "Only self-service change-password enforces the full policy. "
                          "Fix: run validatePasswordAgainstPolicy in the create handler too.")
        else:
            self.rep.ok("Admin create enforces the configured policy", f"weak create rejected ({st})")

        # 8c. self-service CHANGE — track the current password so later steps don't drift.
        cu = f"{self.tag}_chg"
        self.mk_user(cu, "Initial-Pass-99!")  # meets the strong policy
        cur = "Initial-Pass-99!"
        # min length IS enforced on change-password (resolved policy min-length).
        st, _ = change_pw(cu, cur, "short1")
        self.rep.expect("change-password enforces min length", st >= 400,
                        ok_detail=f"too-short change rejected ({st})", bad_detail=f"got {st}")
        # complexity CLASSES — a long single-class password under a require-all policy.
        st, _ = change_pw(cu, cur, "abcdefghijklmnop")  # 16 chars, lowercase only
        if st < 400:
            cur = "abcdefghijklmnop"
            self.rep.warn("Complexity classes NOT enforced on change",
                          "require_uppercase/lowercase/number/special are stored but only the "
                          "min-length is checked — a long single-class password is accepted. "
                          "Wire the complexity classes into the resolved password rules.")
        else:
            self.rep.ok("Complexity classes enforced on change", f"single-class rejected ({st})")

        # 8d. reuse / history — change new == current (uses the tracked current password).
        st, _ = change_pw(cu, cur, cur)
        if st < 400:
            self.rep.warn("Password REUSE (new == current) is allowed",
                          "password_history is stored but reuse is not blocked on change. "
                          "Enforce against the current hash (and a recent-history list) in ChangePassword.")
        else:
            self.rep.ok("Password reuse (new == current) blocked", f"rejected ({st})")

        # 8d. lockout — set a low threshold, exceed it, then try the CORRECT password.
        lock = dict(base)
        lock.update({"login_attempts_allowed": 3, "unlock_time_seconds": 300})
        self.admin("PUT", f"/api/security-settings?scope={scope}", lock)
        lu = f"{self.tag}_lock"
        self.mk_user(lu, "Lockout-Pass-1!", role="read-only")
        for _ in range(5):
            self.api.call("POST", "/api/auth/login", body={"username": lu, "password": "wrong"})
        st, _ = self.api.call("POST", "/api/auth/login", body={"username": lu, "password": "Lockout-Pass-1!"})
        if st == 200:
            self.rep.warn("Account lockout NOT enforced",
                          "login_attempts_allowed/unlock_time_seconds are stored but the login handler "
                          "has no failed-attempt counter — brute force is not throttled. "
                          "Add a per-account attempt counter + lock window in handleLogin.")
        else:
            self.rep.ok("Account lockout enforced", f"correct password refused after bad attempts ({st})")

        # 8e. expiry — document (not time-testable here).
        self.rep.info("Password expiry not time-testable in a single run",
                      f"password_expire_enabled={original.get('password_expire_enabled')} / days={original.get('password_expire_days')}")

        # 8f. session lifecycle — idle + absolute are now enforced server-side at the
        #     refresh boundary (per-scope policy). We can't wall-clock idle in one run,
        #     but we can verify the machinery is live: a short access token and the
        #     scope's idle/absolute policy are present + enforced.
        idle = base.get("idle_timeout_minutes")
        absol = base.get("absolute_timeout_minutes")
        self.rep.expect("Session idle/absolute policy present (per scope)",
                        isinstance(idle, int) and idle > 0 and isinstance(absol, int) and absol > 0,
                        ok_detail=f"idle={idle}m absolute={absol}m (configurable per Provider/Org/Tenant)",
                        bad_detail=f"idle={idle} absolute={absol}")
        # Short access token (the refresh-boundary idle signal).
        fresh = self.login(self.admin_user, self.admin_pass)
        exp = (fresh or {}).get("expires_in", 0)
        self.rep.expect("Access token is short (≤1h) so idle is meaningful",
                        0 < exp <= 3600, ok_detail=f"expires_in={exp}s", bad_detail=f"expires_in={exp}s")
        self.rep.info("Idle/absolute enforced at /api/auth/refresh",
                      "server-side sessions; wall-clock expiry covered by Go tests (TestSessionIdleAndAbsoluteAtRefresh)")

        # restore original policy
        self.admin("PUT", f"/api/security-settings?scope={scope}", original)
        self.rep.ok("Security settings restored to original")

    # -- teardown --
    def teardown(self):
        if self.keep:
            self.rep.section("Teardown skipped (--keep)")
            return
        self.rep.section("Teardown")
        for kid in self.apikeys:
            self.admin("DELETE", f"/api/apikeys/{_q(kid)}")
        for b in self.bindings:
            self.admin("DELETE", f"/api/bindings/{_q(b)}")
        for name in self.users:
            self.admin("DELETE", f"/api/users/{_q(name)}")
        for tid, tname in self.tenants:
            self.admin("DELETE", f"/api/tenants/{_q(tid)}?confirm={_q(tname)}&force=true")
        for oid in self.orgs:
            self.admin("DELETE", f"/api/orgs/{_q(oid)}")
        # verify clean
        _st, users = self.admin("GET", "/api/users")
        leftover = [u.get("username") for u in users if isinstance(u, dict) and u.get("username", "").startswith(self.tag)] if isinstance(users, list) else []
        self.rep.expect("All audit users cleaned up", not leftover, bad_detail=f"leftover: {leftover}", warn_on_fail=True)
        _st, orgs = self.admin("GET", "/api/orgs")
        oleft = [o.get("id") for o in orgs if isinstance(o, dict) and o.get("name", "").startswith(self.tag)] if isinstance(orgs, list) else []
        self.rep.expect("All audit orgs cleaned up", not oleft, bad_detail=f"leftover: {oleft}", warn_on_fail=True)

    def run(self):
        if not self.phase_login():
            return
        try:
            self.phase_auth_negative()
            self.phase_regions()
            self.phase_tree()
            self.phase_isolation()
            self.phase_lifecycle()
            self.phase_bindings()
            self.phase_apikeys()
            self.phase_password_policy()
        finally:
            self.teardown()


def _find(lst, key, val):
    if not isinstance(lst, list):
        return None
    for x in lst:
        if isinstance(x, dict) and x.get(key) == val:
            return x
    return None


def _q(s):
    return urllib.parse.quote(str(s), safe="")


def main():
    ap = argparse.ArgumentParser(description="NetOps_Observability IAM/tenancy security audit")
    ap.add_argument("--base-url", default=os.environ.get("IAM_AUDIT_BASE_URL", "http://localhost:8000"))
    ap.add_argument("--user", default=os.environ.get("IAM_AUDIT_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("IAM_AUDIT_PASSWORD", ""))
    ap.add_argument("--strict", action="store_true", help="treat WARN as failure (exit 1)")
    ap.add_argument("--keep", action="store_true", help="don't delete created resources")
    args = ap.parse_args()

    if not args.password:
        print("ERROR: admin password required (--password or IAM_AUDIT_PASSWORD).", file=sys.stderr)
        return 2

    print(f"IAM audit → {args.base_url}  (admin: {args.user})")
    rep = Report(strict=args.strict)
    audit = Audit(API(args.base_url), rep, args.user, args.password, keep=args.keep)
    audit.run()
    return rep.summary()


if __name__ == "__main__":
    sys.exit(main())
