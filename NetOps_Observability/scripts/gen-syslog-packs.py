#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""gen-syslog-packs.py: compile vendor-pack grammars into the aggregator's Stage B
(tracker 387, plan §5.1, §6a).

The grammars live in `telemetry-catalog/vendor-packs/*.yaml`. The engine runs them
through `src/correlation/syslog_packs.py`, baked by `bake_rules.py`; Vector runs them
through the block this script splices into `syslog_normalized`. It writes

  deployment/docker/vector/vector.yaml              the spliced block
  deployment/helm/correlix/files/vector/vector.yaml the same block
  deployment/docker/vector/tests/syslog-packs.yaml  its `vector test` suite

The suite runs against the shipped transform (`insert_at: syslog_normalized`). Its
expected values come from `syslog_packs.PackTable.parse` and from each fixture's own
`expect:`, and generation refuses a fixture on which the two disagree. So a green run
means the VRL, the Python and the pack's own statement all agree.

The block only sets `cx_pk_*` locals plus the envelope rewrite. The hand-written code
around it applies them, and that code names no vendor either: a pack needs no VRL.

Usage:
    python3 scripts/gen-syslog-packs.py            # write the artifacts
    python3 scripts/gen-syslog-packs.py --check    # exit 1 if stale
    python3 scripts/gen-syslog-packs.py --packs-dir D --root R   # another tree
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
for _p in (os.path.join(REPO_ROOT, "telemetry-catalog"),
           os.path.join(REPO_ROOT, "src", "correlation")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import bake_rules
import syslog_pack_vrl as V
from syslog_packs import PackTable

BEGIN_MARK = "      # >>> BEGIN GENERATED-SYSLOG-PACKS (scripts/gen-syslog-packs.py)"
END_MARK = "      # <<< END GENERATED-SYSLOG-PACKS"
CONFIG_RELS = ("deployment/docker/vector/vector.yaml",
               "deployment/helm/correlix/files/vector/vector.yaml")
TESTS_REL = "deployment/docker/vector/tests/syslog-packs.yaml"

#: The fields a fixture's `expect:` may assert, in the order they are written.
ASSERTED = ("vendor", "vendor_source", "parser_id", "parser_status", "facility",
            "event_type", "summary", "severity_native_text", "severity_native_code",
            "normalized_severity", "event_category", "dedup_key", "procid", "message",
            "message_original")


class GenerationError(RuntimeError):
    """The packs could not be compiled faithfully: never emit a guess."""


def _envelope_lines(rows: list[dict]) -> list[str]:
    out = ['cx_pk_raw = string(.message) ?? ""']
    for e in rows:
        out += [
            f"# envelope {e['id']} ({e['fidelity']})",
            f"if !exists(.{e['preserve_as']}) && contains(cx_pk_raw, {json.dumps(e['literal'])}) {{",
            f"  cx_pk_e, cx_pk_eerr = parse_regex(cx_pk_raw, r'{e['pattern']}')",
            "  if cx_pk_eerr == null {",
            f"    .{e['preserve_as']} = cx_pk_raw",
            f"    .message = {V.group_expr('cx_pk_e', e['message'])}",
        ]
        skips = e.get("skip_values") or []
        for field, group in (e.get("lift") or {}).items():
            cond = ['cx_pk_lift != ""'] + [f"cx_pk_lift != {json.dumps(s)}" for s in skips]
            out += [
                f"    cx_pk_lift = {V.group_expr('cx_pk_e', group)}",
                f"    if {' && '.join(cond)} {{",
                f"      .{field} = cx_pk_lift",
                "    }",
            ]
        out += ["  }", "}"]
    return out


def _grammar_lines(rows: list[dict]) -> list[str]:
    out = [
        'cx_pk_parser = ""',
        'cx_pk_vendor = ""',
        'cx_pk_fac = ""',
        'cx_pk_et = ""',
        'cx_pk_sum = ""',
        'cx_pk_ntxt = ""',
        'cx_pk_ncode = ""',
        'cx_pk_cat = ""',
        "cx_pk_sev = 99",
        'cx_pk_msg = string(.message) ?? ""',
        "cx_pk_app = downcase(.appname)",
    ]
    for g in rows:
        cond = V.match_condition(g, "cx_pk_msg", "cx_pk_app", "cx_inventory_vendor",
                                 'cx_pk_parser == ""')
        out += [
            f"# grammar {g['id']} ({g['fidelity']})",
            f"if {cond} {{",
            f"  cx_pk_m, cx_pk_merr = parse_regex(cx_pk_msg, r'{g['pattern']}')",
            "  if cx_pk_merr == null {",
            f"    cx_pk_parser = {json.dumps(g['parser_id'])}",
            f"    cx_pk_vendor = {json.dumps(g['vendor'])}",
        ]
        if g["facility"]:
            out.append(f"    cx_pk_fac = {V.template_expr(g['facility'], 'cx_pk_m')}")
        if g["event_type"]:
            out.append(f"    cx_pk_et = downcase({V.template_expr(g['event_type'], 'cx_pk_m')})")
        if g["summary"]:
            out.append(f"    cx_pk_sum = {V.template_expr(g['summary'], 'cx_pk_m')}")
        if g["native_text"]:
            out.append(f"    cx_pk_ntxt = {V.group_expr('cx_pk_m', g['native_text'])}")
        if g["native_code"]:
            out.append(f"    cx_pk_ncode = {V.group_expr('cx_pk_m', g['native_code'])}")
        if g["category"]:
            out.append(f"    cx_pk_cat = {json.dumps(g['category'])}")
        out += V.severity_lines(g, "cx_pk_m", "cx_pk_sev", "    ")
        out += ["  }", "}"]
    return out


def render_block(grammars: list[dict], envelopes: list[dict]) -> str:
    lines = [
        BEGIN_MARK,
        "      # GENERATED from telemetry-catalog/vendor-packs/*.yaml. DO NOT EDIT: change",
        "      # a pack and re-run scripts/gen-syslog-packs.py; a drift test fails on a",
        "      # stale copy. Sets cx_pk_* locals plus the envelope rewrite; nothing here",
        "      # drops or reorders a record.",
    ]
    for ln in _envelope_lines(envelopes) + _grammar_lines(grammars):
        lines.append(("      " + ln).rstrip())
    lines.append(END_MARK)
    return "\n".join(lines) + "\n"


def splice(existing: str, block: str) -> str:
    start = existing.find(BEGIN_MARK)
    end = existing.find(END_MARK)
    if start < 0 or end < 0 or end < start:
        raise GenerationError(
            f"vector.yaml carries no generated pack block:\n  {BEGIN_MARK}\n  {END_MARK}")
    end_line = existing.find("\n", end)
    return existing[:start] + block + existing[end_line + 1:]


def _yaml_str(value: object) -> str:
    return json.dumps(value if isinstance(value, str) else str(value))


def decide_fixtures(packs: list[dict], table: PackTable) -> list[tuple[str, dict, dict]]:
    """(case name, input event, expected doc fields) for every fixture of every
    pack, refusing one whose `expect:` the Python executor does not reproduce."""
    cases: list[tuple[str, dict, dict]] = []
    for pack in packs:
        for fx in pack["fixtures"]:
            ev = {k: fx[k] for k in ("hostname", "appname", "severity", "message") if k in fx}
            ev.setdefault("hostname", "spine1")
            ev.setdefault("appname", "unknown")
            ev.setdefault("severity", "notice")
            got = table.parse(ev)
            want = dict(fx["expect"])
            for key, val in want.items():
                actual = got.get(key)
                if key not in got and key not in ASSERTED:
                    raise GenerationError(
                        f"fixture {fx['name']!r}: expect names unknown field {key!r}")
                if actual != val and not (key == "message" and val == ev["message"]):
                    raise GenerationError(
                        f"fixture {fx['name']!r}: expect {key}={val!r}, the Python "
                        f"executor says {actual!r} (event: {ev!r})")
            cases.append((f"{pack['pack']}: {fx['name']}", ev, want))
    return cases


def render_tests(cases: list[tuple[str, dict, dict]]) -> str:
    body = [
        "# SPDX-License-Identifier: Apache-2.0",
        "# Copyright 2026 Correlix",
        "",
        "# syslog-packs.yaml: GENERATED by scripts/gen-syslog-packs.py. DO NOT EDIT.",
        "#",
        "# `vector test` proof that the shipped syslog_normalized transform agrees with",
        "# `syslog_packs.PackTable.parse` and with every pack fixture's own expect:.",
        f"# cases: {len(cases)}",
        "#",
        "# Keep every dollar sign out of this file: Vector interpolates environment",
        "# variables in the raw config text, comments included.",
        "# tests/test_syslog_packs.py runs it together with vector.yaml.",
        "",
        "tests:",
    ]
    for name, ev, want in cases:
        body += [
            f"  - name: {_yaml_str(name)}",
            "    inputs:",
            "      - insert_at: syslog_normalized",
            "        type: log",
            "        log_fields:",
        ]
        for key in ("hostname", "appname", "severity", "message"):
            body.append(f"          {key}: {_yaml_str(ev[key])}")
        body += [
            "    outputs:",
            "      - extract_from: syslog_normalized",
            "        conditions:",
            "          - type: vrl",
            "            source: |",
        ]
        for key in ASSERTED:
            if key not in want:
                continue
            body.append(f'              assert_eq!(.{key}, {_yaml_str(want[key])}, '
                        f'"wrong {key}")')
        if not want:
            # A fixture with nothing to assert claims that no pack has an opinion.
            body.append('              assert!(!exists(.event_category), "no pack row applies")')
            body.append('              assert!(!exists(.vendor_source), "no pack row applies")')
    return "\n".join(body) + "\n"


def _check_no_dollar(text: str, where: str) -> None:
    if re.search(r"\$", text):
        raise GenerationError(f"{where} carries a dollar sign: Vector would interpolate it")


def build(packs_dir: str, root: str) -> dict[str, str]:
    packs = bake_rules.load_packs(packs_dir)
    grammars, envelopes = bake_rules.pack_tables(packs)
    table = PackTable(grammars, envelopes)
    block = render_block(grammars, envelopes)
    tests = render_tests(decide_fixtures(packs, table))
    _check_no_dollar(block, "the generated block")
    _check_no_dollar(tests, "the generated suite")
    out = {os.path.join(root, TESTS_REL): tests}
    for rel in CONFIG_RELS:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            out[path] = splice(fh.read(), block)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 if stale")
    ap.add_argument("--packs-dir", default=bake_rules.PACKS_DIR)
    ap.add_argument("--root", default=REPO_ROOT,
                    help="the tree to write into (a test generates a synthetic one)")
    args = ap.parse_args(argv)
    try:
        artifacts = build(args.packs_dir, args.root)
    except (GenerationError, bake_rules.BakeError) as exc:
        print(f"gen-syslog-packs: {exc}", file=sys.stderr)
        return 2
    stale: list[str] = []
    for path, content in artifacts.items():
        rel = os.path.relpath(path, args.root)
        current = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                current = fh.read()
        if current == content:
            continue
        if args.check:
            stale.append(rel)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"gen-syslog-packs: wrote {rel}")
    if args.check and stale:
        print("gen-syslog-packs: STALE, re-run scripts/gen-syslog-packs.py:", file=sys.stderr)
        for rel in stale:
            print(f"  - {rel}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
