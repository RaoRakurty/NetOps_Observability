#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""test-plan.py — size the local test effort to the risk of the change.

WHY THIS EXISTS (2026-10-17)
----------------------------
Two failure modes, opposite in direction:

* PR #22 sat red for a week on four GENERATED files (SBOM, licence notices,
  base-image digest lock, a toolchain pin) left stale by a Go bump. Each is a
  deterministic check that takes well under a second locally, yet it cost a
  full CI round and blocked every PR behind it.
* Running the whole suite for a tracker edit is waste, and waste is what
  CLAUDE.md §17 forbids spending tokens and wall-clock on.

So the effort follows the diff, not habit. This script reads the changed paths
and prints which tier applies, what to run locally, and what is left to CI.
`--run-fast` executes the cheap deterministic checks the diff calls for and
exits non-zero on failure — the pre-push hook runs it and BLOCKS.

WHAT IT NEVER DOES
------------------
It never relaxes the merge gate. CI (.github/workflows/) runs everything that
applies, whatever this script says; "too slow" only ever moves a leg from the
laptop to CI (-race, the 20-minute root package, pgintegration), never out of
the gate. When a path matches nothing it falls to the STRICTEST plausible tier,
not the loosest.

Tiers, lowest to highest (a diff takes the highest tier any path reaches):
  docs        prose only — no code gate locally
  frontend    tsc + vite build + the Playwright specs for the area
  code        affected package tests; root package + -race left to CI
  high-risk   full local gate + pgintegration, whatever the diff size
"""
from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import os
import subprocess
import sys
from dataclasses import dataclass, field

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PREFIX = "NetOps_Observability/"
GIT_TIMEOUT_S = 30

TIERS = ("docs", "frontend", "code", "high-risk")

# Paths whose change can make a GENERATED artifact stale. Any hit runs the
# artifact checks below (they are sub-second, so the trigger is generous).
ARTIFACT_INPUTS = (
    "src/backend/go.mod", "src/backend/go.sum", "src/backend/vendor/modules.txt",
    "*/go.mod",
    "src/frontend/package.json", "src/frontend/package-lock.json",
    "docs-portal/package.json", "docs-portal/package-lock.json",
    "src/correlation/requirements*.txt", "*/requirements*.txt",
    "deployment/docker/Dockerfile*", "deployment/docker/*compose*.yml",
    "scripts/license-data.json", "scripts/license-audit.py", "scripts/sbom.py",
    "docs/THIRD_PARTY_LICENSES.md", "docs/sbom/*", "docs/compliance/oci-inventory.json",
)

# High-risk regardless of size: tenant isolation, auth, crypto/trust, schema,
# the LLM boundary, and the dependency/supply-chain surface (CLAUDE.md §3,
# §3a, §6, §8, §15).
HIGH_RISK = (
    "src/backend/migrations/*", "src/backend/tlsconfig/*", "src/backend/internalca/*",
    "src/backend/sealing/*", "src/backend/*auth*", "src/backend/*tenant*",
    "src/backend/*rls*", "src/backend/*isolation*", "src/backend/*rbac*",
    "src/backend/*copilot*", "src/backend/ai/*", "src/backend/*iris*",
    "src/backend/go.mod", "src/backend/go.sum", "*package-lock.json",
    "*requirements*.txt", "deployment/docker/Dockerfile*",
    "scripts/install*", "scripts/install-correlix.sh", "scripts/make-installer.sh",
    ".github/workflows/*",
)

DOCS = ("*.md", "docs/*", "*.txt", "LICENSE*", "NOTICE*")
FRONTEND = ("src/frontend/*", "docs-portal/*")


@dataclass
class Plan:
    tier: str = "docs"
    reasons: list[str] = field(default_factory=list)
    artifact_checks: bool = False
    local: list[str] = field(default_factory=list)
    ci_only: list[str] = field(default_factory=list)


def _match(path: str, patterns: tuple[str, ...]) -> str | None:
    for pat in patterns:
        if fnmatch.fnmatch(path, pat):
            return pat
    return None


def _raise(plan: Plan, tier: str, why: str) -> None:
    if TIERS.index(tier) > TIERS.index(plan.tier):
        plan.tier = tier
    plan.reasons.append(f"{tier}: {why}")


def _rel(raw: str) -> str:
    """Repo-root path (git diff output) -> project-relative path."""
    return raw.removeprefix(PREFIX)


def _go_packages(rels: list[str]) -> list[str]:
    """Backend package dirs (relative to src/backend) touched by .go edits."""
    root = "src/backend/"
    return sorted({os.path.dirname(r[len(root):]) or "."
                   for r in rels
                   if r.startswith(root) and r.endswith(".go") and "/vendor/" not in r})


def classify(paths: list[str]) -> Plan:
    """Map changed paths (repo-root or project relative) to a Plan. Pure: no IO."""
    plan = Plan()
    rels = [_rel(r) for r in paths]
    for p in rels:
        if _match(p, ARTIFACT_INPUTS):
            plan.artifact_checks = True
        if (hit := _match(p, HIGH_RISK)):
            _raise(plan, "high-risk", f"{p} (matches {hit})")
        elif _match(p, FRONTEND):
            _raise(plan, "frontend", p)
        elif _match(p, DOCS) and not p.startswith("src/"):
            # prose outside the source tree; an .md under src/ can be a skill or
            # prompt the product loads (src/backend/ai/skills/*.md), so it is code.
            plan.reasons.append(f"docs: {p}")
        else:
            _raise(plan, "code", p)

    if plan.artifact_checks:
        plan.local.append("python3 scripts/test-plan.py --run-fast   (SBOM, notices, digest lock, toolchain pins)")
    go_pkgs = _go_packages(rels)
    if plan.tier in ("code", "high-risk"):
        if go_pkgs:
            sub = [d for d in go_pkgs if d != "."]
            if sub:
                pkgs = " ".join("./" + d for d in sub)
                plan.local.append(f"(cd src/backend && go test -timeout 60m {pkgs})")
            plan.local.append("bash scripts/ci-backend-guard.sh   (build, vet, golangci-lint — the pre-push hook runs it)")
            plan.ci_only.append("go test -race (no cgo on this host)")
            if "." in go_pkgs:
                plan.local.append("(cd src/backend && go test -timeout 60m -run '<tests for the touched files>' .)")
                plan.ci_only.append("root package full run (15-20 min) — locally too when the change alters shared root logic")
        if any(r.startswith("src/correlation/") for r in rels):
            plan.local.append("(cd src/correlation && python3 -m pytest -q)")
        if any(r.startswith("tests/") or (r.startswith("scripts/") and r.endswith(".py")) for r in rels):
            plan.local.append("python3 -m pytest -q tests/<the touched test files>")
        if any(r.endswith(".sh") for r in rels):
            plan.local.append("shellcheck <the touched .sh files>   (scripts/CLAUDE.md §16.3)")
    if any(r.startswith("src/frontend/") for r in rels):
        plan.local.append("(cd src/frontend && ./node_modules/.bin/tsc -b && ./node_modules/.bin/vite build)")
        plan.local.append("Playwright: the e2e specs for the touched area (full npm run e2e in CI)")
    if plan.tier == "high-risk":
        plan.local.append("go test -tags=pgintegration against a real Postgres when storage/tenant code changed (§17)")
        plan.local.append("the §3a isolation test for any data-returning surface touched")
        plan.ci_only.append("govulncheck (needs the vuln DB)")
    if plan.tier == "docs" and not plan.artifact_checks:
        plan.local.append("nothing — docs-only; CI still runs whatever applies")
    return plan


def changed_paths(base: str) -> list[str]:
    """Paths changed between base and HEAD, repo-root relative."""
    out = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"],
                         cwd=PROJECT, capture_output=True, text=True,
                         timeout=GIT_TIMEOUT_S, check=False)
    if out.returncode != 0:
        raise RuntimeError(f"git diff {base}...HEAD failed: {out.stderr.strip()}")
    return [ln for ln in out.stdout.splitlines() if ln.strip()]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(PROJECT, rel))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {rel}")
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.join(PROJECT, "scripts"))
    spec.loader.exec_module(mod)
    return mod


def run_fast_checks() -> list[str]:
    """The deterministic generated-artifact checks. Returns failure messages."""
    failures: list[str] = []
    cwd = os.getcwd()
    os.chdir(PROJECT)
    try:
        try:
            sbom = _load("sbom", "scripts/sbom.py")
            if sbom.main(["--check"]) != 0:
                failures.append("docs/sbom/ is stale — run `python3 scripts/sbom.py` and commit")
        except Exception as exc:  # noqa: BLE001 — reported, never swallowed
            failures.append(f"SBOM check could not run: {exc!r}")
        try:
            la = _load("license_audit", "scripts/license-audit.py")
            data = la.load_data()
            expected = la.render_notices(la.build_inventory(data), data)
            with open("docs/THIRD_PARTY_LICENSES.md", encoding="utf-8") as fh:
                if fh.read() != expected:
                    failures.append("docs/THIRD_PARTY_LICENSES.md is stale — run "
                                    "`python3 scripts/license-audit.py --notices` "
                                    "and `(cd src/frontend && node scripts/gen-licenses.mjs)`")
        except Exception as exc:  # noqa: BLE001 — reported, never swallowed
            failures.append(f"licence-notices check could not run: {exc!r}")
    finally:
        os.chdir(cwd)
    # Digest lock + toolchain pins: reuse the tests themselves (0.2 s), so the
    # hook can never disagree with CI about what "current" means.
    try:
        res = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                              "tests/test_oci_digest_lock.py", "tests/test_toolchain_pin.py"],
                             cwd=PROJECT, capture_output=True, text=True, timeout=120, check=False)
        if res.returncode != 0:
            failures.append("digest lock / toolchain pin failed "
                            "(OCI_SOURCE_COMPLIANCE.md §13 for a base-image bump):\n"
                            + "\n".join(res.stdout.splitlines()[-15:]))
    except FileNotFoundError as exc:
        failures.append(f"pytest could not start: {exc!r}")
    except subprocess.TimeoutExpired:
        failures.append("digest lock / toolchain pin tests exceeded 120 s — state UNKNOWN")
    return failures


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", default="origin/main", help="diff base (default origin/main)")
    ap.add_argument("--run-fast", action="store_true",
                    help="run the cheap deterministic checks the diff calls for; non-zero on failure")
    ap.add_argument("--always", action="store_true",
                    help="with --run-fast: run the artifact checks even if no input changed")
    ap.add_argument("paths", nargs="*", help="classify these paths instead of the git diff")
    args = ap.parse_args(argv)

    try:
        paths = args.paths or changed_paths(args.base)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"test-plan: cannot read the diff ({exc}); treating as high-risk", file=sys.stderr)
        paths, forced = [], True
    else:
        forced = False
    plan = classify(paths)
    if forced:
        _raise(plan, "high-risk", "diff unreadable — strictest tier")
        plan.artifact_checks = True

    if args.run_fast:
        if not (plan.artifact_checks or args.always):
            print("test-plan: no generated-artifact input changed — fast checks not needed")
            return 0
        failures = run_fast_checks()
        for f in failures:
            print(f"✗ {f}", file=sys.stderr)
        if failures:
            return 1
        print("✓ test-plan: generated artifacts current (SBOM, notices, digest lock, toolchain pins)")
        return 0

    print(f"tier: {plan.tier}   ({len(paths)} changed path(s))")
    for r in plan.reasons[:25]:
        print(f"  · {r}")
    if len(plan.reasons) > 25:
        print(f"  · … {len(plan.reasons) - 25} more")
    print("run locally:")
    for c in plan.local:
        print(f"  - {c}")
    if plan.ci_only:
        print("left to CI (still blocking at merge):")
        for c in plan.ci_only:
            print(f"  - {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
