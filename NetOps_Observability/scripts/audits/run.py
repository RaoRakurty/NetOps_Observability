#!/usr/bin/env python3
"""
run.py — run the whole NetOps_Observability audit suite (or named modules).

Each module audit is an independent, standalone script; this orchestrator runs
them in sequence, forwards the shared flags, and aggregates the exit codes
(non-zero if ANY module reports a FAIL).

Usage:
    python3 scripts/audits/run.py --password '<admin pw>'
    python3 scripts/audits/run.py iam platform --password '<pw>'   # subset
    python3 scripts/audits/run.py --password '<pw>' --strict       # WARN→fail

Modules: iam, platform, collectors, notify, copilot  (auto-discovers new
audits/*.py too). Env: IAM_AUDIT_BASE_URL / IAM_AUDIT_USER / IAM_AUDIT_PASSWORD.
"""
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)

# Stable ordering; iam first (deepest), then breadth, then per-module.
ORDER = ["iam", "platform", "alerts", "telemetry", "collectors", "notify", "reports", "integrations"]


def discover():
    """Map module name → script path. iam lives at scripts/iam_audit.py."""
    mods = {"iam": os.path.join(SCRIPTS, "iam_audit.py")}
    for p in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        base = os.path.basename(p)
        if base in ("common.py", "run.py", "__init__.py"):
            continue
        mods[base[:-3]] = p
    ordered = {m: mods[m] for m in ORDER if m in mods}
    for m, p in mods.items():
        ordered.setdefault(m, p)
    return ordered


def main():
    argv = sys.argv[1:]
    mods = discover()
    # A bare token matching a known module name selects it; everything else
    # (flags AND their values) is forwarded verbatim to each module script.
    names = [a for a in argv if a in mods]
    flags = [a for a in argv if a not in mods]
    selected = names or list(mods.keys())

    unknown = [n for n in selected if n not in mods]
    if unknown:
        print(f"Unknown module(s): {unknown}. Available: {list(mods.keys())}", file=sys.stderr)
        return 2

    print(f"\033[1m═══ NetOps_Observability audit suite ═══\033[0m  modules: {', '.join(selected)}")
    results = {}
    for name in selected:
        print(f"\n\033[1m###### {name} ######\033[0m")
        rc = subprocess.call([sys.executable, mods[name], *flags])
        results[name] = rc

    print("\n\033[1m═══ Suite result ═══\033[0m")
    worst = 0
    for name in selected:
        rc = results[name]
        tag = "\033[32mOK\033[0m" if rc == 0 else (f"\033[31mFAIL(rc={rc})\033[0m")
        print(f"  {name:12} {tag}")
        worst = max(worst, rc)
    print("All modules passed." if worst == 0 else "One or more modules reported failures.")
    return worst


if __name__ == "__main__":
    sys.exit(main())
