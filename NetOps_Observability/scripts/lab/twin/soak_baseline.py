#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Capture the appliance-soak baseline — including WHO was measured.

Until tracker 158 this file had no writer at all: `data/miniladder/
soak-baseline.json` was produced by hand, and it recorded RSS numbers with no
record of which containers produced them. That is why the 2026-08-19 soak could
lose its subject 16h35m in — both correlation replicas were recreated deploying
94e8561d — and still be on course to be read as "complete" 46 hours later.

An RSS number is meaningless without the identity of the process that produced
it. This tool records both, so `ownership_runner.soak_state()` can tell a soak
that measured its subject for 72h from one that merely waited 72h.

USAGE
  python3 soak_baseline.py --write            # capture a new baseline
  python3 soak_baseline.py --verify           # judge the baseline on disk
  python3 soak_baseline.py --write --force    # replace an existing baseline

--write REFUSES to overwrite an existing baseline without --force, because
clobbering a baseline mid-soak destroys the same evidence the interlock exists
to protect.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ownership_runner import (
    SOAK_COMPLETE,
    SOAK_HOURS,
    SOAK_INVALID,
    _sh,
    soak_state,
    subject_identity,
)

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))),
    "data", "miniladder", "soak-baseline.json")

# Correlation is the subject the ownership scenarios disturb, so its identity
# is what the interlock must verify. The RSS map still covers the whole stack.
SUBJECT_SERVICE = "correlation"


def capture_rss(runner=None) -> dict:
    """{container name: mem usage} for the whole project. Empty on failure."""
    run = runner or _sh
    rc, out, err = run(("docker", "stats", "--no-stream", "--format",
                        "{{.Name}}\t{{.MemUsage}}"))
    if rc != 0:
        print(f"soak_baseline: WARNING: docker stats failed rc={rc}: "
              f"{(err or out).strip()}", file=sys.stderr, flush=True)
        return {}
    rss = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[0].strip():
            rss[parts[0].strip()] = parts[1].split("/")[0].strip()
    return rss


def git_sha(runner=None) -> str:
    run = runner or _sh
    rc, out, _ = run(("git", "rev-parse", "HEAD"))
    return out.strip() if rc == 0 else ""


def build_baseline(now: _dt.datetime, *, project: str = "netops",
                   service: str = SUBJECT_SERVICE, runner=None,
                   identity_probe=None) -> dict:
    """Assemble the baseline document. Raises if the subject is invisible."""
    probe = identity_probe or (
        lambda: subject_identity(project=project, service=service,
                                 runner=runner))
    subject = probe()
    if not subject:
        raise RuntimeError(
            f"REFUSING to write a baseline: no running '{service}' containers "
            "could be identified. A baseline with no subject is exactly the "
            "defect tracker 158 fixed — it cannot later prove anything.")
    return {
        "soak_start_utc": now.isoformat(),
        "purpose": (
            f"{SOAK_HOURS:.0f}h appliance-SKU soak — end check: RSS vs this "
            "baseline, watchdog clean, nightly mini-ladder PASS streak, "
            "DLQ/refusal counters explained. The 'subject' block below is what "
            "makes the RSS arm falsifiable: if those exact containers are not "
            "still running at end-check, the soak is INVALID, not complete."),
        "subject": {
            "service": service,
            "project": project,
            "containers": subject,
        },
        "git_sha": git_sha(runner),
        "rss": capture_rss(runner),
    }


def _write(path: str, force: bool, now: _dt.datetime) -> int:
    if os.path.exists(path) and not force:
        print(f"REFUSED: {path} already exists. Overwriting it mid-soak "
              "destroys the evidence the interlock protects. Re-run with "
              "--force if you really mean to discard it.", file=sys.stderr)
        return 2
    doc = build_baseline(now)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    os.replace(tmp, path)
    subject = doc["subject"]["containers"]
    print(f"baseline written: {path}")
    print(f"  start   : {doc['soak_start_utc']}")
    print(f"  git sha : {doc['git_sha'] or '(unknown)'}")
    print(f"  subject : {len(subject)} x {doc['subject']['service']}")
    for c in subject:
        print(f"            {c['id']}  started={c['started_at']}  "
              f"image={c['image']}")
    print(f"  rss     : {len(doc['rss'])} container(s)")
    return 0


def _verify(path: str, now: _dt.datetime) -> int:
    state, reason = soak_state(now, path)
    print(f"[{state}] {reason}")
    if state == SOAK_COMPLETE:
        return 0
    return 1 if state == SOAK_INVALID else 3


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--path", default=DEFAULT_PATH)
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)
    if args.write == args.verify:
        ap.error("choose exactly one of --write / --verify")
    now = _dt.datetime.now(_dt.timezone.utc)
    return _write(args.path, args.force, now) if args.write \
        else _verify(args.path, now)


if __name__ == "__main__":
    sys.exit(main())
