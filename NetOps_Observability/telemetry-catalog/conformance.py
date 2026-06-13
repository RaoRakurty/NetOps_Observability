#!/usr/bin/env python3
"""Conformance harness — the gNMI equivalent of LibreNMS .snmprec replay.

For every lab/live-validated collection row, replay its captured fixture through
the code-owned normalization engine and assert the canonical output is
well-formed (right family name, all required labels present, enum mapped to a
valid integer / gauge numeric). This is what prevents empty-panel + silent
mis-normalization regressions and what PROMOTES a row's fidelity from doc_claimed.

Run standalone:  python3 telemetry-catalog/conformance.py
"""
from __future__ import annotations

import json
import os
import sys

import yaml

from normalize import load_catalog, normalize_event

HERE = os.path.dirname(os.path.abspath(__file__))


def replay_fixture(fixture_path: str, vendor: str, cat) -> list[dict]:
    series = []
    with open(fixture_path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            series.extend(normalize_event(ev, vendor=vendor, cat=cat))
    return series


def conform_row(row: dict, cat) -> list[str]:
    """Return problems for one validated collection row's fixture replay."""
    probs = []
    fam_name = row["signal_family"]
    fam = cat.families[fam_name]
    required = set(fam["labels"])
    fx = os.path.join(HERE, row["fixture"])
    series = replay_fixture(fx, row["vendor"], cat)
    if not series:
        return [f"{row['vendor']}/{fam_name}: fixture replayed to ZERO canonical series (mapping broken?)"]
    for s in series:
        if s["name"] != fam_name:
            probs.append(f"{row['vendor']}/{fam_name}: produced unexpected family '{s['name']}'")
        missing = required - set(s["labels"])
        if missing:
            probs.append(f"{row['vendor']}/{fam_name}: series missing required labels {missing} (got {set(s['labels'])})")
        if fam["kind"] == "state_enum":
            valid = {int(k) for k in fam["enum"]}
            if int(s["value"]) not in valid:
                probs.append(f"{row['vendor']}/{fam_name}: enum value {s['value']} not in {valid}")
    return probs


def run() -> tuple[int, list[str]]:
    coll = yaml.safe_load(open(os.path.join(HERE, "collection.yaml")))
    cat = load_catalog()
    problems, checked = [], 0
    for row in coll["rows"]:
        if row.get("fidelity_status") in ("lab_validated", "live_validated") and row.get("fixture"):
            checked += 1
            problems.extend(conform_row(row, cat))
    return checked, problems


def main() -> int:
    checked, problems = run()
    print(f"conformance harness — replayed {checked} validated fixtures")
    if problems:
        print(f"\n✗ {len(problems)} conformance failures:")
        for p in problems:
            print(f"  ✗ {p}")
        return 1
    print("  ✓ all validated fixtures conform to the canonical contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
