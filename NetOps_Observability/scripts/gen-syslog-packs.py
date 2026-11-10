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
  deployment/docker/syslog-ng/core.conf             the frame shapes (`edge_shapes`)
  deployment/helm/correlix/files/syslog-ng/core.conf the same shapes

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
from syslog_packs import PackTable, field_is_observed

import syslog_pack_vrl as V

BEGIN_MARK = "      # >>> BEGIN GENERATED-SYSLOG-PACKS (scripts/gen-syslog-packs.py)"
END_MARK = "      # <<< END GENERATED-SYSLOG-PACKS"
CONFIG_RELS = ("deployment/docker/vector/vector.yaml",
               "deployment/helm/correlix/files/vector/vector.yaml")
TESTS_REL = "deployment/docker/vector/tests/syslog-packs.yaml"
SHAPES_BEGIN = "# >>> BEGIN GENERATED-EDGE-SHAPES (scripts/gen-syslog-packs.py)"
SHAPES_END = "# <<< END GENERATED-EDGE-SHAPES"
EDGE_CONFIG_RELS = ("deployment/docker/syslog-ng/core.conf",
                    "deployment/helm/correlix/files/syslog-ng/core.conf")

#: The fields a fixture's `expect:` may assert, in the order they are written.
ASSERTED = ("vendor", "vendor_source", "parser_id", "parser_status", "facility",
            "event_type", "summary", "severity_native_text", "severity_native_code",
            "normalized_severity", "event_category", "dedup_key", "procid", "message",
            "message_original", "title", "correlation_key", "audit_user", "audit_action",
            "audit_source", "audit_via", "session_id", "audit_groups", "metrics",
            "guidance", "enrichment")


class GenerationError(RuntimeError):
    """The packs could not be compiled faithfully: never emit a guess."""


def _envelope_lines(rows: list[dict]) -> list[str]:
    if not rows:
        return []   # VRL warns on an unused local
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
        # The rich event fields (tracker 387, the trap lane's names), merged onto the
        # record by the hand-written code after this block.
        "cx_pk_out = {}",
        "cx_pk_obs = []",
        "cx_pk_der = []",
        "cx_pk_unk = []",
        'cx_pk_pack = ""',
    ]
    record = None
    if any(_reads_record(g) for g in rows):
        record = {"host": "cx_pk_host", "device": "cx_pk_device"}
        out += [
            "cx_pk_host = .hostname",
            'cx_pk_device = string(cx_inv.device_id) ?? ""',
            'if cx_pk_device == "" {',
            "  cx_pk_device = cx_pk_host",
            "}",
        ]
    tables = _guidance_tables(rows)
    if tables:
        out.append(f"cx_pk_gt = {json.dumps(tables, sort_keys=True)}")
    if any(g.get("with_msgid") for g in rows):
        # `<MSGID>: <message>` for the rows that read a tag from RFC 5424 MSGID; `-`
        # is the nil value. Only declared when a row reads it: VRL warns on an unused local.
        out += [
            'cx_pk_mid = string(.msgid) ?? ""',
            "cx_pk_midmsg = cx_pk_msg",
            'if cx_pk_mid != "" && cx_pk_mid != "-" {',
            '  cx_pk_midmsg = cx_pk_mid + ": " + cx_pk_msg',
            "}",
        ]
    for g in rows:
        hay = "cx_pk_midmsg" if g.get("with_msgid") else "cx_pk_msg"
        cond = V.match_condition(g, hay, "cx_pk_app", "cx_inventory_vendor",
                                 'cx_pk_parser == ""')
        out += [
            f"# grammar {g['id']} ({g['fidelity']})",
            f"if {cond} {{",
            f"  cx_pk_m, cx_pk_merr = parse_regex({hay}, r'{g['pattern']}')",
            "  if cx_pk_merr == null {",
            f"    cx_pk_parser = {json.dumps(g['parser_id'])}",
            f"    cx_pk_vendor = {json.dumps(g['vendor'])}",
        ]
        if g["facility"]:
            out.append(f"    cx_pk_fac = {V.template_expr(g['facility'], 'cx_pk_m')}")
        if g["event_type"]:
            out.append(f"    cx_pk_et = downcase({V.template_expr(g['event_type'], 'cx_pk_m')})")
        if g["summary"]:
            out += V.template_lines(g["summary"], "cx_pk_m", "cx_pk_sum", "    ")
        if g["native_text"]:
            out.append(f"    cx_pk_ntxt = {V.group_expr('cx_pk_m', g['native_text'])}")
        if g["native_code"]:
            out.append(f"    cx_pk_ncode = {V.group_expr('cx_pk_m', g['native_code'])}")
        if g["category"]:
            out.append(f"    cx_pk_cat = {json.dumps(g['category'])}")
        out += V.severity_lines(g, "cx_pk_m", "cx_pk_sev", "    ")
        out += _event_model_lines(g, record, "    ")
        out += ["  }", "}"]
    out += _event_model_epilogue(bool(tables))
    return out


#: syslog_packs._OBSERVED_ORDER, as the locals that hold each value here.
_OBSERVED_LOCALS = (("facility", "cx_pk_fac"), ("event_type", "cx_pk_et"),
                    ("summary", "cx_pk_sum"), ("severity_native_text", "cx_pk_ntxt"),
                    ("severity_native_code", "cx_pk_ncode"))
_DERIVED_FIELDS = ("title", "correlation_key")


def _reads_record(g: dict) -> bool:
    return any(re.search(r"\{(?:host|device)\}", t) for t in (g.get("fields") or {}).values())


def _guidance_tables(rows: list[dict]) -> dict[str, dict]:
    """`<pack>|<event_type>` -> guidance, one literal for every pack that states any."""
    out: dict[str, dict] = {}
    for g in rows:
        for et, guide in (g.get("guidance") or {}).items():
            out[f"{g['pack']}|{et}"] = guide
    return out


def _event_model_lines(g: dict, record: dict | None, ind: str) -> list[str]:
    """The per-grammar half of syslog_packs._event_model: this row's templates and
    metrics, each named into observed / derived / unknown in declaration order. The
    shared half (the line's own fields, guidance, the enrichment object) is the
    epilogue, written once."""
    out = [f"{ind}cx_pk_pack = {json.dumps(g['pack'])}"]
    for name, tmpl in (g.get("fields") or {}).items():
        lst = "cx_pk_obs" if field_is_observed(name, tmpl) else "cx_pk_der"
        out += V.template_lines(tmpl, "cx_pk_m", "cx_pk_v", ind, record)
        out.append(f'{ind}if cx_pk_v != "" {{ cx_pk_out = merge(cx_pk_out, {{{json.dumps(name)}: cx_pk_v}}); '
                   f'{lst} = push({lst}, "{name}") }} else {{ cx_pk_unk = push(cx_pk_unk, "{name}") }}')
    if g.get("metrics"):
        out.append(f"{ind}cx_pk_met = {{}}")
        for name, group in g["metrics"].items():
            raw = V.group_expr("cx_pk_m", group)
            out += [f"{ind}cx_pk_mf, cx_pk_mferr = to_float({raw})",
                    (f'{ind}if cx_pk_mferr == null && {raw} != "" {{ '
                     f'cx_pk_met = merge(cx_pk_met, {{{json.dumps(name)}: {{"value": cx_pk_mf, "basis": "observed"}}}}); '
                     f'cx_pk_obs = push(cx_pk_obs, "metrics.{name}") }} else {{ '
                     f'cx_pk_unk = push(cx_pk_unk, "metrics.{name}") }}')]
        out.append(f'{ind}if length(cx_pk_met) > 0 {{ cx_pk_out = merge(cx_pk_out, {{"metrics": cx_pk_met}}) }}')
    return out


def _event_model_epilogue(has_guidance: bool) -> list[str]:
    """Once, after the grammars: the line's own fields first (syslog_packs._OBSERVED_ORDER),
    pack guidance by `<pack>|<event_type>`, and the enrichment object."""
    out = ['if cx_pk_parser != "" {', "  cx_pk_base = []"]
    for name, local in _OBSERVED_LOCALS:
        out.append(f'  if {local} != "" {{ cx_pk_base = push(cx_pk_base, "{name}") }}')
    out += ['  cx_pk_derv = append(["normalized_severity"], cx_pk_der)',
            '  if cx_pk_cat != "" { cx_pk_derv = push(cx_pk_derv, "dedup_key") }',
            "  cx_pk_gfl = []"]
    if has_guidance:
        out += ['  cx_pk_g = get(cx_pk_gt, [cx_pk_pack + "|" + cx_pk_et]) ?? null',
                "  if is_object(cx_pk_g) {",
                '    cx_pk_out = merge(cx_pk_out, {"guidance": merge(object!(cx_pk_g), {"basis": "pack_guidance"})})',
                '    cx_pk_gfl = ["guidance"]',
                "  }"]
    out += [('  cx_pk_out = merge(cx_pk_out, {"enrichment": {"fields_observed": append(cx_pk_base, cx_pk_obs), '
             '"fields_derived": cx_pk_derv, "fields_guidance": cx_pk_gfl, "unknown": cx_pk_unk}})'),
            "}"]
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


def render_edge_shapes(shapes: list[dict]) -> str:
    """The generated part of syslog-ng's core.conf. Both objects must exist because the
    framing channel names them, so a catalogue with no such row refuses to generate."""
    filters = [s for s in shapes if s["no_header"]]
    rewrites = [s for s in shapes if not s["no_header"]]
    if not filters or not rewrites:
        raise GenerationError("edge_shapes needs at least one `no_header` and one `replace` row")
    lines = [SHAPES_BEGIN,
             "# GENERATED from telemetry-catalog/vendor-packs/*.yaml. DO NOT EDIT: change a",
             "# pack and re-run scripts/gen-syslog-packs.py; a drift test fails on a stale copy."]
    for s in filters:
        lines.append(f"# {s['id']} ({s['fidelity']})")
    alternatives = " or ".join(f"message('{s['match']}')" for s in filters)
    lines += [f"filter f_shape_no_header {{ {alternatives}; }};", "rewrite r_edge_shapes {"]
    for s in rewrites:
        lines += [f"    # {s['id']} ({s['fidelity']})",
                  f"    subst('{s['match']}', '{s['replace']}', value(\"MESSAGE\"));"]
    lines += ["};", SHAPES_END]
    return "\n".join(lines) + "\n"


def splice_edge_shapes(existing: str, block: str) -> str:
    start = existing.find(SHAPES_BEGIN)
    end = existing.find(SHAPES_END)
    if start < 0 or end < 0 or end < start:
        raise GenerationError(
            f"core.conf carries no generated shape block:\n  {SHAPES_BEGIN}\n  {SHAPES_END}")
    end_line = existing.find("\n", end)
    return existing[:start] + block + existing[end_line + 1:]


def _yaml_str(value: object) -> str:
    return json.dumps(value if isinstance(value, str) else str(value))


def _vrl_literal(value: object) -> str:
    """A fixture's expected value as VRL: JSON is a VRL literal for objects and arrays."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return _yaml_str(value)


def decide_fixtures(packs: list[dict], table: PackTable) -> list[tuple[str, dict, dict]]:
    """(case name, input event, expected doc fields) for every fixture of every
    pack, refusing one whose `expect:` the Python executor does not reproduce."""
    cases: list[tuple[str, dict, dict]] = []
    for pack in packs:
        for fx in pack["fixtures"]:
            ev = {k: fx[k] for k in ("hostname", "appname", "severity", "message", "msgid",
                                     ) if k in fx}
            ev.setdefault("hostname", "spine1")
            ev.setdefault("appname", "unknown")
            ev.setdefault("severity", "notice")
            got = table.parse(ev)
            want = dict(fx["expect"])
            if not want and "parser_id" in got:
                raise GenerationError(
                    f"fixture {fx['name']!r}: an empty expect claims no pack applies, "
                    f"but {got['parser_id']} matched (event: {ev!r})")
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


def render_tests(cases: list[tuple[str, dict, dict]], parser_ids: list[str]) -> str:
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
        for key in ("hostname", "appname", "severity", "message", "msgid"):
            if key in ev:
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
            body.append(f'              assert_eq!(.{key}, {_vrl_literal(want[key])}, '
                        f'"wrong {key}")')
        if not want:
            # A fixture with nothing to assert claims that no pack has an opinion.
            body.append('              assert!(!exists(.event_category), "no pack row applies")')
            body.append(f'              assert!(!includes({json.dumps(parser_ids)}, '
                        '.parser_id), "no pack row applies")')
    return "\n".join(body) + "\n"


def _check_no_dollar(text: str, where: str) -> None:
    if re.search(r"\$", text):
        raise GenerationError(f"{where} carries a dollar sign: Vector would interpolate it")


def build(packs_dir: str, root: str) -> dict[str, str]:
    packs = bake_rules.load_packs(packs_dir)
    grammars, envelopes = bake_rules.pack_tables(packs)
    table = PackTable(grammars, envelopes)
    block = render_block(grammars, envelopes)
    tests = render_tests(decide_fixtures(packs, table),
                         sorted({g["parser_id"] for g in grammars}))
    _check_no_dollar(block, "the generated block")
    _check_no_dollar(tests, "the generated suite")
    out = {os.path.join(root, TESTS_REL): tests}
    for rel in CONFIG_RELS:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            out[path] = splice(fh.read(), block)
    shapes = render_edge_shapes(bake_rules.edge_shapes(packs))
    for rel in EDGE_CONFIG_RELS:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            out[path] = splice_edge_shapes(fh.read(), shapes)
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
