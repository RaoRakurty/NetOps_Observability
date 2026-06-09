"""
common.py — shared harness for the NetOps_Observability audit suite.

Every per-module audit (iam, platform, notify, collectors, copilot, …) imports
`API`, `Report` and `run_audit` from here so they share one HTTP client, one
result/severity model, and one CLI. Stdlib only (urllib) — matches the project's
offline / zero-dependency ethos.

Severities:
    PASS  a control/behaviour that should hold, holds.
    FAIL  something that IS implemented regressed → exit 1.
    WARN  a known gap / inherent trade-off (stored-but-unenforced policy, a
          disabled optional feature) → exit 0, unless --strict.
    INFO  context only.

Each module audit defines `class Audit` with `NAME`, `TITLE` and `run(self)`,
using `self.api` (an API) and `self.rep` (a Report). Run one with run_audit(),
or run the whole suite with `python3 scripts/audits/run.py`.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


class API:
    def __init__(self, base_url, token=None):
        self.base = base_url.rstrip("/")
        self.token = token

    def call(self, method, path, token="__default__", body=None):
        tok = self.token if token == "__default__" else token
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if tok:
            req.add_header("Authorization", "Bearer " + tok)
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                return r.status, _maybe_json(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, _maybe_json(e.read().decode())
        except urllib.error.URLError as e:
            return 0, {"error": str(e)}

    def login(self, user, password):
        st, b = self.call("POST", "/api/auth/login", token=None,
                          body={"username": user, "password": password})
        return b if st == 200 and isinstance(b, dict) else None


def _maybe_json(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def q(s):
    return urllib.parse.quote(str(s), safe="")


class Report:
    def __init__(self, strict=False):
        self.strict = strict
        self.counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0}
        self.failures = []

    def _emit(self, sev, name, detail):
        self.counts[sev] += 1
        color = {"PASS": "\033[32m", "FAIL": "\033[31m", "WARN": "\033[33m", "INFO": "\033[36m"}[sev]
        line = f"  {color}{sev:4}\033[0m  {name}"
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

    def expect(self, name, cond, ok_detail="", bad_detail="", warn_on_fail=False):
        if cond:
            self.ok(name, ok_detail)
        elif warn_on_fail:
            self.warn(name, bad_detail)
        else:
            self.fail(name, bad_detail)
        return cond

    def section(self, title):
        print(f"\n\033[1m── {title}\033[0m")

    def merge(self, other):
        for k in self.counts:
            self.counts[k] += other.counts[k]
        self.failures.extend(other.failures)

    def summary(self, title="Summary"):
        c = self.counts
        print("\n" + "=" * 64)
        print(f" {title}:  PASS {c['PASS']}   FAIL {c['FAIL']}   WARN {c['WARN']}   INFO {c['INFO']}")
        if self.failures:
            print(" Failed checks:")
            for f in self.failures:
                print(f"   • {f}")
        print("=" * 64)
        return 1 if self.failures else 0


def parse_args(desc):
    ap = argparse.ArgumentParser(description=desc)
    ap.add_argument("--base-url", default=os.environ.get("IAM_AUDIT_BASE_URL", "http://localhost:8000"))
    ap.add_argument("--user", default=os.environ.get("IAM_AUDIT_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("IAM_AUDIT_PASSWORD", ""))
    ap.add_argument("--strict", action="store_true", help="treat WARN as failure")
    ap.add_argument("--keep", action="store_true", help="don't delete created resources")
    return ap.parse_args()


def run_audit(audit_cls):
    """Standalone entry point for a single module audit script."""
    args = parse_args(audit_cls.TITLE)
    if not args.password:
        print("ERROR: admin password required (--password or IAM_AUDIT_PASSWORD).", file=sys.stderr)
        return 2
    api = API(args.base_url)
    lr = api.login(args.user, args.password)
    if not lr:
        print(f"ERROR: admin login failed at {args.base_url} (user {args.user}).", file=sys.stderr)
        return 2
    api.token = lr["token"]
    rep = Report(strict=args.strict)
    print(f"\033[1m{audit_cls.TITLE}\033[0m → {args.base_url}")
    audit = audit_cls(api, rep, args)
    audit.run()
    return rep.summary(audit_cls.NAME)
