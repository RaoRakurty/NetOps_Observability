#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""ci_gate.py — one verdict per workflow: did every job the plan selected pass?

Jobs a diff does not need are skipped by `if:` on the planner's output
(scripts/test-plan.py --ci-groups). GitHub reports a skipped job as passing,
so without this gate "skipped because the plan said so" and "skipped because
something went wrong" look identical. The gate tells them apart.

Input: the workflow's `needs` context as JSON (env NEEDS = toJSON(needs)),
which carries each job's `result` and the plan job's outputs, plus one
`--job ID=GROUP` per job (GROUP is a planner group, or `always`).

Truth table (anything not listed is a FAIL — unknown means fail):
  plan job not success / plan missing or malformed     FAIL
  selected (or always) job: success                    pass
  selected (or always) job: failure|cancelled|skipped  FAIL
  unselected job: skipped or success                   pass
  unselected job: failure or cancelled                 FAIL (never ignore red)
  a job in `needs` the gate was not told about,
  or a mapped job missing from `needs`                 FAIL
"""
from __future__ import annotations

import argparse
import json
import os
import sys

RESULTS = {"success", "failure", "cancelled", "skipped"}


def evaluate(needs: dict, jobs: dict[str, str], plan_job: str = "plan") -> list[str]:
    """Return failure reasons; empty means the gate passes. Pure."""
    errs: list[str] = []
    p = needs.get(plan_job)
    if not isinstance(p, dict) or p.get("result") != "success":
        res = p.get("result") if isinstance(p, dict) else None
        return [f"planner job '{plan_job}' result is {res!r}, not success — selection unknown"]
    try:
        plan = json.loads((p.get("outputs") or {}).get("plan") or "")
        groups = plan["groups"]
        if plan.get("schema") != 1 or not isinstance(groups, dict) or not all(isinstance(v, bool) for v in groups.values()):
            raise ValueError("bad shape")
    except (ValueError, KeyError, TypeError) as exc:
        return [f"planner output unreadable ({exc}) — selection unknown"]

    seen = set(needs) - {plan_job}
    for job in sorted(seen - set(jobs)):
        errs.append(f"job '{job}' is in needs but has no --job mapping")
    for job, group in sorted(jobs.items()):
        if job not in needs:
            errs.append(f"job '{job}' is mapped but not in needs")
            continue
        if group != "always" and group not in groups:
            errs.append(f"job '{job}' maps to group '{group}' the planner did not report")
            continue
        selected = group == "always" or groups[group]
        res = needs[job].get("result") if isinstance(needs[job], dict) else None
        if res not in RESULTS:
            errs.append(f"job '{job}' result {res!r} is unknown")
        elif selected and res != "success":
            why = "unexpectedly skipped" if res == "skipped" else res
            errs.append(f"job '{job}' ({group}) was selected and is {why}")
        elif not selected and res in ("failure", "cancelled"):
            errs.append(f"job '{job}' ({group}) was not selected but is {res}")
    return errs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--job", action="append", default=[], metavar="ID=GROUP", required=True)
    ap.add_argument("--plan-job", default="plan")
    args = ap.parse_args(argv)
    jobs: dict[str, str] = {}
    for spec in args.job:
        jid, sep, group = spec.partition("=")
        if not sep or not jid or not group:
            print(f"ci-gate: bad --job {spec!r} (want ID=GROUP)", file=sys.stderr)
            return 2
        jobs[jid] = group
    try:
        needs = json.loads(os.environ.get("NEEDS", ""))
        if not isinstance(needs, dict):
            raise TypeError("not an object")
    except (ValueError, TypeError) as exc:
        print(f"ci-gate: FAIL — NEEDS is not readable JSON ({exc})", file=sys.stderr)
        return 1
    errs = evaluate(needs, jobs, args.plan_job)
    for e in errs:
        print(f"ci-gate: FAIL — {e}", file=sys.stderr)
    if errs:
        return 1
    for job, group in sorted(jobs.items()):
        print(f"ci-gate: {job} ({group}): {needs[job]['result']}")
    print("ci-gate: pass — every selected job succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
