#!/usr/bin/env python3
"""Typed loader + invariant checks for the three-catalog telemetry catalog.

Run standalone:  python3 telemetry-catalog/catalog.py   (exit 1 on any violation)
The invariants are also asserted by test_catalog.py in CI.
"""
from __future__ import annotations

import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))

FIDELITY_LADDER = ["doc_claimed", "lab_validated", "live_validated", "degraded", "failed"]
ADVERTISABLE = {"lab_validated", "live_validated"}          # may be called "supported"
NEEDS_FIXTURE = {"lab_validated", "live_validated"}          # must point at a fixture
NEEDS_ISSUE = {"degraded", "failed"}                         # must carry an issue_ref
NEEDS_LIVE_CAPTURE = {"doc_claimed"}                         # must carry a live_capture plan


def _load(name):
    return yaml.safe_load(open(os.path.join(HERE, name)))


# Event→metric correlation forward-references: an event whose paired metric is a
# Phase-3 family not yet built. Printed (so they're visible) but not a failure.
FORWARD_REFS: list[str] = []


def check() -> list[str]:
    norm = _load("normalization.yaml")
    coll = _load("collection.yaml")
    ident = _load("identity.yaml")
    problems: list[str] = []
    FORWARD_REFS.clear()

    families = norm["families"]
    canonical_keys = {e["canonical_key"] for e in ident["entities"].values()}
    structural = {"vendor", "transport"}  # labels not sourced from an entity tag

    # --- normalization invariants ---
    for fname, fam in families.items():
        if not fname.startswith("device_"):
            problems.append(f"normalization: family '{fname}' is not a canonical device_* name")
        if fam.get("kind") not in ("state_enum", "gauge", "counter"):
            problems.append(f"normalization: family '{fname}' has invalid kind {fam.get('kind')!r}")
        if fam["kind"] == "state_enum" and not fam.get("enum"):
            problems.append(f"normalization: state_enum family '{fname}' has no enum map")
        for lbl in fam.get("labels", []):
            if lbl not in canonical_keys and lbl not in structural:
                problems.append(f"normalization: family '{fname}' label '{lbl}' is neither an identity key nor structural")
        if not fam.get("owner", {}).get("transport"):
            problems.append(f"normalization: family '{fname}' has no owner.transport")

    # --- collection invariants ---
    for i, row in enumerate(coll["rows"]):
        tag = f"collection[{i}] {row.get('vendor')}/{row.get('platform')}/{row.get('signal_family')}"
        fs = row.get("fidelity_status")
        if fs not in FIDELITY_LADDER:
            problems.append(f"{tag}: fidelity_status '{fs}' not in ladder {FIDELITY_LADDER}")
        if row.get("signal_family") not in families:
            problems.append(f"{tag}: signal_family not defined in normalization catalog")
        if not row.get("os_version"):
            problems.append(f"{tag}: missing os_version constraint")
        if fs in NEEDS_FIXTURE:
            fx = row.get("fixture")
            if not fx:
                problems.append(f"{tag}: fidelity '{fs}' requires a fixture")
            elif not os.path.exists(os.path.join(HERE, fx)):
                problems.append(f"{tag}: fixture '{fx}' not found")
        if fs in NEEDS_ISSUE and not row.get("issue_ref"):
            problems.append(f"{tag}: fidelity '{fs}' requires an issue_ref")
        # doc_claimed rows MUST carry a live_capture plan so the deferred
        # validation is never silently forgotten — the explicit "validate later".
        if fs in NEEDS_LIVE_CAPTURE:
            lc = row.get("live_capture") or {}
            if lc.get("status") != "pending":
                problems.append(f"{tag}: doc_claimed requires live_capture.status: pending")
            if not lc.get("blocked_on"):
                problems.append(f"{tag}: doc_claimed requires live_capture.blocked_on (why not validated yet)")

    # --- event catalog: correlation invariant (events must join metrics) ---
    events = _load("events.yaml").get("families") or {}
    metric_label_space = set()
    for fam in families.values():
        metric_label_space.update(fam.get("labels", []))
    for ename, efam in events.items():
        join = efam.get("join_on", [])
        if not join:
            problems.append(f"events: family '{ename}' has no join_on (cannot correlate to a metric)")
        produced = set(efam.get("labels", {}).keys())
        for k in join:
            if k not in produced:
                problems.append(f"events: '{ename}' join_on '{k}' is not a label the parser produces")
            if k not in metric_label_space:
                problems.append(f"events: '{ename}' join_on '{k}' is not a canonical identity key used by any metric family")
        # Event-family fidelity (tracker 184). Optional — the Phase-2 families
        # predate the field — but when declared it must sit on the ladder, and a
        # doc_claimed row must carry the same explicit "validate later" plan the
        # collection rows do, so a documented-but-uncaptured grammar can never
        # drift into reading as supported.
        efs = efam.get("fidelity_status")
        if efs is not None:
            if efs not in FIDELITY_LADDER:
                problems.append(f"events: '{ename}' fidelity_status '{efs}' not in ladder {FIDELITY_LADDER}")
            if efs in NEEDS_LIVE_CAPTURE:
                elc = efam.get("live_capture") or {}
                if elc.get("status") != "pending":
                    problems.append(f"events: '{ename}' doc_claimed requires live_capture.status: pending")
                if not elc.get("blocked_on"):
                    problems.append(f"events: '{ename}' doc_claimed requires live_capture.blocked_on")
            if efs in NEEDS_ISSUE and not efam.get("issue_ref"):
                problems.append(f"events: '{ename}' fidelity '{efs}' requires an issue_ref")
        cw = efam.get("correlates_with")
        if cw and cw not in families:
            # correlates_with may point at a Phase-3 metric not yet in
            # normalization.yaml — a forward-reference, tracked (printed) not failed.
            FORWARD_REFS.append(f"{ename} → {cw} (Phase-3 metric, not yet built)")

    # --- ownership collision: a (vendor, platform, family) advertised on two
    #     different transports is a double-production hazard ---
    owners: dict[tuple, set] = {}
    for row in coll["rows"]:
        if row.get("fidelity_status") in ADVERTISABLE:
            key = (row["vendor"], row["platform"], row["signal_family"])
            owners.setdefault(key, set()).add(row["method"])
    for key, methods in owners.items():
        if len(methods) > 1:
            problems.append(f"ownership: {key} advertised on multiple transports {methods} — declare one owner")

    return problems


def main() -> int:
    problems = check()
    coll = _load("collection.yaml")["rows"]
    from collections import Counter
    by_fid = Counter(r.get("fidelity_status") for r in coll)
    print("telemetry catalog — invariant check")
    print(f"  collection rows : {len(coll)}")
    print(f"  by fidelity     : {dict(by_fid)}")
    print(f"  advertisable    : {sum(by_fid[f] for f in ADVERTISABLE)} (lab/live validated)")
    if FORWARD_REFS:
        print(f"  event→metric forward-refs (Phase-3 metrics pending):")
        for f in FORWARD_REFS:
            print(f"    · {f}")
    # Live-capture backlog — the explicit "validate later" queue.
    pending = [r for r in coll if r.get("fidelity_status") == "doc_claimed"]
    if pending:
        print(f"\n  LIVE-CAPTURE BACKLOG ({len(pending)} doc_claimed → validate later):")
        for r in pending:
            print(f"    ☐ {r['vendor']}/{r['platform']} {r['signal_family']}"
                  f" — blocked: {(r.get('live_capture') or {}).get('blocked_on','?')}")
    if problems:
        print(f"\n✗ {len(problems)} invariant violations:")
        for p in problems:
            print(f"  ✗ {p}")
        return 1
    print("\n  ✓ catalog invariants clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
