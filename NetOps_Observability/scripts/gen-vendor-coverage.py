#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""gen-vendor-coverage.py: the per-vendor coverage scorecard and its ratchet
(tracker 387 PR 14, plan §6a "Coverage scorecard").

It derives what Correlix can actually read, per vendor and per lane, from the data
that decides it, and writes three artifacts:

  src/backend/parsercov/vendor_coverage.json
      The scorecard: MIB nodes, trap definitions, grammars, rules by fidelity and
      fixtures. The API embeds it and /api/admin/parser/stats serves it.
  telemetry-catalog/vendor_coverage_floor.json
      The ratchet. One count per vendor, lane and measure, which may only rise.
  deployment/{docker,helm/...}/vector-router/vector.yaml
      The known-label block of the parse-status metrics, so a label can only come
      from a set this catalogue defines (`netops_parse_status_events`).

THE RATCHET. `--check` fails on a stale artifact and on any count below its floor.
A plain run raises each floor to the current count and REFUSES to lower one: losing
coverage takes a hand edit to the floor file, in a diff somebody reviews. Fidelity
promotion moves a rule between buckets, so the floor holds the rule total and the
validated count rather than each bucket.

WHAT COUNTS AS A FIXTURE is a statement of VALUE, never of presence. A syslog
fixture counts only if it asserts `parser_status: parsed` and a specific event type.
A field present on 100 % of records with the value `unparsed` is the failure this
programme exists to catch (plan §6, PR 14).

Adding a vendor means adding data: this file names none.

Usage:
    python3 scripts/gen-vendor-coverage.py            # write, raising the floor
    python3 scripts/gen-vendor-coverage.py --check    # exit 1 if stale or below floor
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, os.path.join(REPO_ROOT, "telemetry-catalog"))

import bake_rules

PROFILES_DIR = "src/backend/internal/vendorprofile/profiles"
OID_INDEX = "src/backend/collectors/mibs/index/oididx.json"
TRAP_PACKS = "src/backend/collectors/mibs/packs"
TRAP_FIXTURES = "telemetry-catalog/fixtures/trap_events.jsonl"
OLDER_GRAMMARS = "telemetry-catalog/legacy_grammars.yaml"
OLDER_SUITE = "deployment/docker/vector/tests/syslog-legacy-grammars.yaml"

COVERAGE_REL = "src/backend/parsercov/vendor_coverage.json"
FLOOR_REL = "telemetry-catalog/vendor_coverage_floor.json"
ROUTER_RELS = ("deployment/docker/vector-router/vector.yaml",
               "deployment/helm/correlix/files/vector-router/vector.yaml")

BEGIN_MARK = "  # >>> BEGIN GENERATED-PARSE-LABELS (scripts/gen-vendor-coverage.py)"
END_MARK = "  # <<< END GENERATED-PARSE-LABELS"

#: The scorecard's row for what holds for every sender.
STANDARD = "standard"
#: Catalogue tokens that mean "not vendor-anchored" (catalog_consistency_test.go).
NEUTRAL_TOKENS = frozenset({"standard", "any", "generic"})
ENTERPRISE_ROOT = "1.3.6.1.4.1."
LANES = ("syslog", "snmptrap")
#: `lane:` values of a rule row, onto the lane its records arrive on.
RULE_LANE = {"syslog": "syslog", "port": "syslog", "catalog": "syslog", "trap": "snmptrap"}
VALIDATED = frozenset({"lab_validated", "live_validated"})
#: Every value either executor writes to parser_status. Anything else is `other`.
PARSER_STATUSES = ("parsed", "unparsed", "decoded", "partially_decoded", "raw_only")
#: A record with no parser id at all, and the bucket for an id outside the catalogue.
PARSER_NONE, LABEL_OTHER = "none", "other"
#: The vendor value the aggregator writes when nothing identified the sender.
VENDOR_UNKNOWN = "unknown"


class GenerationError(RuntimeError):
    """The coverage cannot be derived honestly: never emit a guess."""


def _read_json(root: str, rel: str) -> dict:
    with open(os.path.join(root, rel), encoding="utf-8") as fh:
        return json.load(fh)


def load_profiles(root: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in sorted(glob.glob(os.path.join(root, PROFILES_DIR, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        out[doc["vendor"]] = doc
    if not out:
        raise GenerationError(f"no vendor profiles under {PROFILES_DIR}")
    return out


def _enterprise_owner(profiles: dict[str, dict]) -> dict[str, str]:
    owner: dict[str, str] = {}
    for vendor, doc in profiles.items():
        for prefix in doc["detection"].get("sysobjectid_prefixes") or ():
            owner[prefix[len(ENTERPRISE_ROOT):]] = vendor
    return owner


def _oid_vendor(oid: str, owner: dict[str, str]) -> str | None:
    """Whose MIB tree an OID sits in: a vendor, the standards row, or None for an
    enterprise no profile claims (it still decodes, it just credits nobody)."""
    if not oid.startswith(ENTERPRISE_ROOT):
        return STANDARD
    return owner.get(oid[len(ENTERPRISE_ROOT):].split(".", 1)[0])


def _empty_lane(lane: str) -> dict:
    row: dict = {"rules": {}, "fixtures": 0}
    if lane == "syslog":
        row["grammars"] = 0
    else:
        row["mib_nodes"] = 0
        row["mibs"] = 0
        row["trap_definitions"] = 0
    return row


def _vendors_of_tokens(tokens: list[str], where: str, known: set[str]) -> set[str]:
    out: set[str] = set()
    for tok in tokens or [STANDARD]:
        if tok in NEUTRAL_TOKENS:
            out.add(STANDARD)
        elif tok in known:
            out.add(tok)
        else:
            raise GenerationError(f"{where}: vendor {tok!r} has no profile")
    return out


def _older_grammars(root: str) -> list[dict]:
    with open(os.path.join(root, OLDER_GRAMMARS), encoding="utf-8") as fh:
        return yaml.safe_load(fh)["grammars"]


def _older_fixtures_by_vendor(root: str) -> dict[str, int]:
    """Cases of the hand-written suite that assert a parse, by the vendor they name.
    The suite is plain VRL, so read its assertions rather than guess at its titles."""
    with open(os.path.join(root, OLDER_SUITE), encoding="utf-8") as fh:
        suite = yaml.safe_load(fh)
    counts: dict[str, int] = {}
    for case in suite["tests"]:
        src = "\n".join(c.get("source", "") for out in case.get("outputs", [])
                        for c in out.get("conditions", []))
        if 'assert_eq!(.parser_status, "parsed")' not in src:
            continue
        m = re.search(r'assert_eq!\(\.vendor, "([^"]+)"\)', src)
        if m:
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return counts


def _counts_as_syslog_fixture(fx: dict) -> bool:
    expect = fx.get("expect") or {}
    return expect.get("parser_status") == "parsed" and bool(expect.get("event_type"))


def compute(root: str, packs_dir: str) -> dict:
    """The scorecard. Pure over the files it reads; sorted, so the output is stable."""
    profiles = load_profiles(root)
    known = set(profiles)
    table = {v: {lane: _empty_lane(lane) for lane in LANES} for v in [*known, STANDARD]}
    owner = _enterprise_owner(profiles)

    # ── trap lane: what the OID index and the trap packs can name ───────────
    nodes = _read_json(root, OID_INDEX)["nodes"]
    mibs: dict[str, set[str]] = {}
    for oid, node in nodes.items():
        vendor = _oid_vendor(oid, owner)
        if vendor is None:
            continue
        table[vendor]["snmptrap"]["mib_nodes"] += 1
        mibs.setdefault(vendor, set()).add(node.get("mib") or "")
    for vendor, names in mibs.items():
        table[vendor]["snmptrap"]["mibs"] = len(names - {""})
    for path in sorted(glob.glob(os.path.join(root, TRAP_PACKS, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            pack = json.load(fh)
        for oid in pack.get("notifications") or {}:
            vendor = _oid_vendor(oid, owner)
            if vendor is not None:
                table[vendor]["snmptrap"]["trap_definitions"] += 1

    # ── rules, from the same rows the engine bakes ──────────────────────────
    packs = bake_rules.load_packs(packs_dir)
    _, rows = bake_rules.load(os.path.join(root, "telemetry-catalog", "events.yaml"), packs_dir)
    vendors_of_rule: dict[str, set[str]] = {}
    for row in rows:
        lane = RULE_LANE.get(row["lane"])
        if lane is None:
            raise GenerationError(f"rule {row['rule_id']}: lane {row['lane']!r} has no scorecard lane")
        vendors = _vendors_of_tokens(list(row.get("vendors") or ()), f"rule {row['rule_id']}", known)
        vendors_of_rule[row["rule_id"]] = vendors
        fidelity = row.get("fidelity_status") or "unrated"
        for vendor in vendors:
            bucket = table[vendor][lane]["rules"]
            bucket[fidelity] = bucket.get(fidelity, 0) + 1

    # ── syslog grammars and fixtures ────────────────────────────────────────
    for pack in packs:
        vendors = _vendors_of_tokens([pack["vendor"]] if pack["vendor"] else [], f"pack {pack['pack']}", known)
        for vendor in vendors:
            row = table[vendor]["syslog"]
            row["grammars"] += len(pack.get("grammars") or ())
            row["fixtures"] += sum(1 for fx in pack["fixtures"] if _counts_as_syslog_fixture(fx))
    for g in _older_grammars(root):
        for vendor in _vendors_of_tokens(g["vendors"], f"older grammar {g['parser_id']}", known):
            table[vendor]["syslog"]["grammars"] += 1
    for vendor, n in _older_fixtures_by_vendor(root).items():
        if vendor in table:
            table[vendor]["syslog"]["fixtures"] += n

    # ── trap fixtures: credited through the rule they prove ─────────────────
    with open(os.path.join(root, TRAP_FIXTURES), encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            rule_id = (json.loads(line).get("_expect") or {}).get("rule_id") or ""
            for vendor in vendors_of_rule.get(rule_id, ()):
                table[vendor]["snmptrap"]["fixtures"] += 1

    rows_out = []
    for vendor in sorted(known) + [STANDARD]:
        doc = profiles.get(vendor)
        # An agent identity or a pseudo-vendor is not a row a person reads as a
        # vendor; its lines are what the standards row covers.
        if doc is not None and doc["detection"].get("agent_identity"):
            continue
        rows_out.append({
            "vendor": vendor,
            "display_name": doc["display_name"] if doc else "Any vendor",
            "standard": doc is None,
            "lanes": {lane: _sorted(table[vendor][lane]) for lane in LANES},
        })
    return {"schema": 1, "vendors": rows_out}


def _sorted(node: dict) -> dict:
    return {k: _sorted(v) if isinstance(v, dict) else v for k, v in sorted(node.items())}


def floors_of(coverage: dict) -> dict[str, int]:
    """Flatten to the counts the ratchet holds."""
    out: dict[str, int] = {}
    for row in coverage["vendors"]:
        for lane, stats in row["lanes"].items():
            base = f"{row['vendor']}/{lane}"
            rules = stats["rules"]
            out[f"{base}/rules_total"] = sum(rules.values())
            out[f"{base}/rules_validated"] = sum(n for f, n in rules.items() if f in VALIDATED)
            for measure, value in stats.items():
                if measure != "rules":
                    out[f"{base}/{measure}"] = value
    return out


def below_floor(current: dict[str, int], floor: dict[str, int]) -> list[str]:
    return [f"{key}: {current.get(key, 0)} is below its floor {want}"
            for key, want in sorted(floor.items()) if current.get(key, 0) < want]


def known_parser_ids(root: str, packs_dir: str) -> list[str]:
    grammars, _ = bake_rules.pack_tables(bake_rules.load_packs(packs_dir))
    ids = {g["parser_id"] for g in grammars} | {g["parser_id"] for g in _older_grammars(root)}
    return sorted(ids)


def known_vendors(root: str) -> list[str]:
    """Every value the vendor label may carry. Detection identities stay in: a trap's
    enterprise arc can name one, and folding it into `other` would hide who sent it. A
    neutral catalogue token names nobody, so no record can carry it."""
    return sorted((set(load_profiles(root)) - NEUTRAL_TOKENS) | {VENDOR_UNKNOWN})


def render_block(vendors: list[str], parser_ids: list[str]) -> str:
    vlist, plist, slist = (json.dumps(x) for x in (vendors, parser_ids, list(PARSER_STATUSES)))
    return f"""{BEGIN_MARK}
  # GENERATED from the vendor profiles and the catalogue. DO NOT EDIT: re-run
  # scripts/gen-vendor-coverage.py; a drift test fails on a stale copy.
  #
  # Bounded label cardinality by construction: a label value is either in these
  # lists or it is `{LABEL_OTHER}`, whatever a record on the bus claims. No device,
  # tenant or free-text value can reach a label. See the metrics below for the count.
  parse_status_labels:
    type: remap
    inputs: [syslog_tagged, snmptrap_tagged]
    source: |
      cx_lane = "syslog"
      if (string(.topic) ?? "") == "netops.snmptrap" {{ cx_lane = "snmptrap" }}
      cx_vendor = string(.vendor) ?? ""
      if cx_vendor == "" {{
        cx_vendor = "{VENDOR_UNKNOWN}"
      }} else if !includes({vlist}, cx_vendor) {{
        cx_vendor = "{LABEL_OTHER}"
      }}
      cx_parser = string(.parser_id) ?? ""
      if cx_parser == "" {{
        cx_parser = "{PARSER_NONE}"
      }} else if !includes({plist}, cx_parser) {{
        cx_parser = "{LABEL_OTHER}"
      }}
      cx_status = string(.parser_status) ?? ""
      if !includes({slist}, cx_status) {{ cx_status = "{LABEL_OTHER}" }}
      # The stored record is the other branch of this fan-out: this copy keeps only
      # what the counter reads, so holding it costs nothing.
      . = {{ "lane": cx_lane, "vendor": cx_vendor, "parser_id": cx_parser, "parser_status": cx_status }}

  trap_varbind_counts:
    type: remap
    inputs: [snmptrap_tagged]
    source: |
      cx_vendor = string(.vendor) ?? ""
      if cx_vendor == "" {{
        cx_vendor = "{VENDOR_UNKNOWN}"
      }} else if !includes({vlist}, cx_vendor) {{
        cx_vendor = "{LABEL_OTHER}"
      }}
      cx_resolved = 0
      cx_unresolved = 0
      for_each(array(.varbinds) ?? []) -> |_i, vb| {{
        if (string(vb.name) ?? "") != "" {{
          cx_resolved = cx_resolved + 1
        }} else {{
          cx_unresolved = cx_unresolved + 1
        }}
      }}
      . = {{ "vendor": cx_vendor, "resolved": cx_resolved, "unresolved": cx_unresolved }}
{END_MARK}
"""


def splice(existing: str, block: str) -> str:
    start = existing.find(BEGIN_MARK)
    end = existing.find(END_MARK)
    if start < 0 or end < 0 or end < start:
        raise GenerationError("the router config has no generated-label markers")
    return existing[:start] + block + existing[end + len(END_MARK) + 1:]


def _dump(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def build(root: str, packs_dir: str, floor: dict[str, int]) -> tuple[dict[str, str], list[str]]:
    """(path → content, breaches). The floor written is the old one raised to current."""
    coverage = compute(root, packs_dir)
    current = floors_of(coverage)
    breaches = below_floor(current, floor)
    raised = {k: max(current.get(k, 0), floor.get(k, 0)) for k in sorted(set(current) | set(floor))}
    out = {
        os.path.join(root, COVERAGE_REL): _dump(coverage),
        os.path.join(root, FLOOR_REL): _dump(raised),
    }
    block = render_block(known_vendors(root), known_parser_ids(root, packs_dir))
    for rel in ROUTER_RELS:
        path = os.path.join(root, rel)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                out[path] = splice(fh.read(), block)
    return out, breaches


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 if stale or below a floor")
    ap.add_argument("--root", default=REPO_ROOT, help="the tree to read and write")
    ap.add_argument("--packs-dir", default=None, help="another vendor-pack directory")
    args = ap.parse_args(argv)
    packs_dir = args.packs_dir or os.path.join(args.root, "telemetry-catalog", "vendor-packs")
    floor_path = os.path.join(args.root, FLOOR_REL)
    floor: dict[str, int] = {}
    if os.path.exists(floor_path):
        with open(floor_path, encoding="utf-8") as fh:
            floor = json.load(fh)
    try:
        artifacts, breaches = build(args.root, packs_dir, floor)
    except (GenerationError, bake_rules.BakeError) as exc:
        print(f"gen-vendor-coverage: {exc}", file=sys.stderr)
        return 2
    if breaches:
        print("gen-vendor-coverage: coverage went DOWN. Restore it, or, if the loss is "
              f"deliberate, lower the entry in {FLOOR_REL} by hand in a reviewed diff:",
              file=sys.stderr)
        for line in breaches:
            print(f"  - {line}", file=sys.stderr)
        return 1
    stale: list[str] = []
    for path, content in artifacts.items():
        rel = os.path.relpath(path, args.root)
        cur = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                cur = fh.read()
        if cur == content:
            continue
        if args.check:
            stale.append(rel)
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"gen-vendor-coverage: wrote {rel}")
    if stale:
        print("gen-vendor-coverage: STALE, re-run scripts/gen-vendor-coverage.py:", file=sys.stderr)
        for rel in stale:
            print(f"  - {rel}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
