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
from syslog_packs import PackTable, field_is_observed, template_parts, var_name

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
            "audit_source", "audit_via", "session_id", "audit_groups", "dump_id", "metrics",
            "guidance", "enrichment")


#: The event time of a fixture that states none (see decide_fixtures).
DEFAULT_FIXTURE_TIME = "2026-01-01T00:00:00Z"


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
        # The rich event fields (tracker 387, the trap lane's names): a branch only
        # names its grammar; the epilogue renders every field from one table, once.
        # VRL type-checks each branch against every local in scope, so per-branch
        # template code made the transform about 2x slower to compile, and a table
        # declared up here about 10x (a 2-case `vector test` went from 20 s to 193 s).
        'cx_pk_gid = ""',
        'cx_pk_capj = "{}"',
    ]
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
        labels = g.get("labels") or {}
        if g["facility"]:
            out.append(f"    cx_pk_fac = {V.template_expr(g['facility'], 'cx_pk_m', labels)}")
        if g["event_type"]:
            out.append(f"    cx_pk_et = downcase({V.template_expr(g['event_type'], 'cx_pk_m', labels)})")
        if g["summary"]:
            out += V.template_lines(g["summary"], "cx_pk_m", "cx_pk_sum", "    ", labels=labels)
        if g["native_text"]:
            out.append(f"    cx_pk_ntxt = {V.group_expr('cx_pk_m', g['native_text'])}")
        if g["native_code"]:
            out.append(f"    cx_pk_ncode = {V.group_expr('cx_pk_m', g['native_code'])}")
        if g["category"]:
            out.append(f"    cx_pk_cat = {json.dumps(g['category'])}")
        out += V.severity_lines(g, "cx_pk_m", "cx_pk_sev", "    ")
        out += [f"    cx_pk_gid = {json.dumps(g['id'])}",
                "    cx_pk_capj = encode_json(cx_pk_m)"]
        out += ["  }", "}"]
    out += _event_model_epilogue(rows, _guidance_tables(rows))
    return out


#: syslog_packs._OBSERVED_ORDER, as the locals that hold each value here.
_OBSERVED_LOCALS = (("facility", "cx_pk_fac"), ("event_type", "cx_pk_et"),
                    ("summary", "cx_pk_sum"), ("severity_native_text", "cx_pk_ntxt"),
                    ("severity_native_code", "cx_pk_ncode"))


def _guidance_tables(rows: list[dict]) -> dict[str, dict]:
    """`<pack>|<event_type>` -> guidance, one literal for every pack that states any."""
    out: dict[str, dict] = {}
    for g in rows:
        for et, guide in (g.get("guidance") or {}).items():
            out[f"{g['pack']}|{et}"] = guide
    return out


def _fields_used(rows: list[dict]) -> list[str]:
    seen: dict[str, None] = {}
    for g in rows:
        for name in g.get("fields") or {}:
            seen.setdefault(name, None)
    return list(seen)


def _event_model_atoms(template: str) -> list[dict]:
    """A template as segments the epilogue renders without parsing: `{"c": clause,
    "a": atoms}`, an atom `=text` (literal), `@group`, `@group|table` (read through a
    label table) or `%host` / `%device` / `%minute` (the record's reserved names). A
    clause segment renders only when none of its groups is empty
    (syslog_packs._render)."""
    segs: list[dict] = []
    cur: dict = {"c": False, "a": []}
    for kind, text in template_parts(template):
        if kind in ("[", "]"):
            if cur["a"]:
                segs.append(cur)
            cur = {"c": kind == "[", "a": []}
        elif kind == "lit":
            cur["a"].append("=" + text)
        else:
            reserved = var_name(text)[0] in bake_rules.RESERVED_TEMPLATE_VARS
            cur["a"].append(("%" if reserved else "@") + text)
    if cur["a"]:
        segs.append(cur)
    return segs


def _event_model_table(rows: list[dict]) -> dict[str, dict]:
    """grammar id -> its pack, its label tables (`l`) and its declared fields then
    metrics, in order: `k` is `o` (observed field), `d` (derived field) or `m` (metric;
    `t` when it keeps the matched text rather than a number)."""
    table: dict[str, dict] = {}
    for g in rows:
        entries: list[dict] = []
        for name, tmpl in (g.get("fields") or {}).items():
            entries.append({"k": "o" if field_is_observed(name, tmpl) else "d", "n": name,
                            "s": _event_model_atoms(tmpl)})
        for name, spec in (g.get("metrics") or {}).items():
            if isinstance(spec, dict):
                entries.append({"k": "m", "n": name, "g": spec["text"], "t": True})
            else:
                entries.append({"k": "m", "n": name, "g": spec})
        table[g["id"]] = {"pack": g["pack"], "e": entries,
                          **({"l": g["labels"]} if g.get("labels") else {})}
    return table


def _event_model_epilogue(rows: list[dict], tables: dict[str, dict]) -> list[str]:
    """Once, after the grammars: the matched grammar's fields rendered from its
    captures, the line's own fields first in `fields_observed`
    (syslog_packs._OBSERVED_ORDER), each declared name into observed / derived /
    unknown in declaration order, pack guidance by `<pack>|<event_type>`, the
    metrics and the enrichment object. The matched grammar hands over its id and its
    captures as JSON text, and each grammar's spec is JSON text in the table: an
    object or table literal here is type-checked field by field, and carried through
    every branch, which is what made the transform slow to compile."""
    fields = _fields_used(rows)
    # `cx_pk_out` is read by the hand-written applier whether or not a grammar matched.
    # The table literals are declared here, after the grammars, never in the prologue:
    # a large literal is part of the type state VRL carries through every branch.
    out = ["cx_pk_out = {}",
           # Spelled apart from the hand-written applier's `if cx_pk_parser != "" {`,
           # which a test locates by that text to prove that code names no vendor.
           "if length(cx_pk_parser) > 0 {",
           "  cx_pk_emt = " + json.dumps({k: json.dumps(v, sort_keys=True) for k, v
                                         in sorted(_event_model_table(rows).items())}),
           '  cx_pk_spec = object(parse_json(string(get(cx_pk_emt, [cx_pk_gid]) ?? "") ?? "") ?? {}) ?? {}',
           '  cx_pk_pack = string(cx_pk_spec.pack) ?? ""',
           "  cx_pk_caps = object(parse_json(cx_pk_capj) ?? {}) ?? {}",
           "  cx_pk_host = .hostname",
           '  cx_pk_device = string(cx_inv.device_id) ?? ""',
           '  if cx_pk_device == "" { cx_pk_device = cx_pk_host }',
           # The record's event time as its UTC minute (syslog_packs.record_minute); a
           # string time must state its zone, as the Python executor requires.
           "  cx_pk_ts = .timestamp",
           '  if is_string(cx_pk_ts) { cx_pk_ts = parse_timestamp(string!(cx_pk_ts), "%+") ?? null }',
           '  cx_pk_minute = ""',
           "  cx_pk_tsv, cx_pk_tserr = timestamp(cx_pk_ts)",
           '  if cx_pk_tserr == null { cx_pk_minute = format_timestamp!(cx_pk_tsv, "%Y-%m-%dT%H:%M", timezone: "UTC") }',
           "  cx_pk_lbl = object(cx_pk_spec.l) ?? {}",
           '  cx_pk_obs = ""',
           '  cx_pk_der = ""',
           '  cx_pk_unk = ""',
           "  cx_pk_fo = {}",
           "  cx_pk_met = {}",
           "  for_each(array(cx_pk_spec.e) ?? []) -> |_cx_pk_i, cx_pk_ent| {",
           "    cx_pk_eo = object(cx_pk_ent) ?? {}",
           '    cx_pk_name = string(cx_pk_eo.n) ?? ""',
           '    if cx_pk_eo.k == "m" {',
           '      cx_pk_raw = string(get(cx_pk_caps, [string(cx_pk_eo.g) ?? ""]) ?? "") ?? ""',
           "      cx_pk_mf, cx_pk_mferr = to_float(cx_pk_raw)",
           '      if cx_pk_eo.t == true && cx_pk_raw != "" {',
           '        cx_pk_met = set!(cx_pk_met, [cx_pk_name], {"value": cx_pk_raw, "basis": "observed"})',
           '        cx_pk_obs = cx_pk_obs + "metrics." + cx_pk_name + ","',
           '      } else if cx_pk_eo.t != true && cx_pk_mferr == null && cx_pk_raw != "" {',
           '        cx_pk_met = set!(cx_pk_met, [cx_pk_name], {"value": cx_pk_mf, "basis": "observed"})',
           '        cx_pk_obs = cx_pk_obs + "metrics." + cx_pk_name + ","',
           "      } else {",
           '        cx_pk_unk = cx_pk_unk + "metrics." + cx_pk_name + ","',
           "      }",
           '    } else if cx_pk_name != "" {',
           '      cx_pk_v = ""',
           "      for_each(array(cx_pk_eo.s) ?? []) -> |_cx_pk_j, cx_pk_seg| {",
           "        cx_pk_so = object(cx_pk_seg) ?? {}",
           '        cx_pk_sv = ""',
           "        cx_pk_miss = false",
           "        for_each(array(cx_pk_so.a) ?? []) -> |_cx_pk_k, cx_pk_at| {",
           '          cx_pk_as = string(cx_pk_at) ?? ""',
           '          cx_pk_ar = slice(cx_pk_as, 1) ?? ""',
           '          if starts_with(cx_pk_as, "=") {',
           "            cx_pk_sv = cx_pk_sv + cx_pk_ar",
           "          } else {",
           '            cx_pk_vt = split(cx_pk_ar, "|")',
           '            cx_pk_vn = string(cx_pk_vt[0]) ?? ""',
           '            cx_pk_x = string(get(cx_pk_caps, [cx_pk_vn]) ?? "") ?? ""',
           '            if cx_pk_as == "%host" { cx_pk_x = cx_pk_host }',
           '            if cx_pk_as == "%device" { cx_pk_x = cx_pk_device }',
           '            if cx_pk_as == "%minute" { cx_pk_x = cx_pk_minute }',
           '            if length(cx_pk_vt) > 1 && cx_pk_x != "" {',
           '              cx_pk_x = string(get(cx_pk_lbl, [string(cx_pk_vt[1]) ?? "", cx_pk_x]) ?? null) ?? cx_pk_x',
           "            }",
           '            if cx_pk_x == "" { cx_pk_miss = true }',
           "            cx_pk_sv = cx_pk_sv + cx_pk_x",
           "          }",
           "        }",
           "        if !(cx_pk_miss && cx_pk_so.c == true) { cx_pk_v = cx_pk_v + cx_pk_sv }",
           "      }",
           '      if cx_pk_v == "" {',
           '        cx_pk_unk = cx_pk_unk + cx_pk_name + ","',
           "      } else {",
           "        cx_pk_fo = set!(cx_pk_fo, [cx_pk_name], cx_pk_v)",
           '        if cx_pk_eo.k == "o" {',
           '          cx_pk_obs = cx_pk_obs + cx_pk_name + ","',
           "        } else {",
           '          cx_pk_der = cx_pk_der + cx_pk_name + ","',
           "        }",
           "      }",
           "    }",
           "  }"]
    # One static key per field, so the record keeps a known type after the applier's
    # merge (a set! object merged onto it would make every field unknown).
    for name in fields:
        out += [f'  cx_pk_fx = string(cx_pk_fo.{name}) ?? ""',
                f'  if cx_pk_fx != "" {{ cx_pk_out = merge(cx_pk_out, {{"{name}": cx_pk_fx}}) }}']
    out += ['  if length(cx_pk_met) > 0 { cx_pk_out = merge(cx_pk_out, {"metrics": cx_pk_met}) }',
            '  cx_pk_base = ""']
    for name, local in _OBSERVED_LOCALS:
        out.append(f'  if {local} != "" {{ cx_pk_base = cx_pk_base + "{name}," }}')
    out += ['  cx_pk_derv = "normalized_severity," + cx_pk_der',
            '  if cx_pk_cat != "" { cx_pk_derv = cx_pk_derv + "dedup_key," }',
            '  cx_pk_gfl = ""']
    if tables:
        out += ["  cx_pk_gt = " + json.dumps({k: json.dumps(v, sort_keys=True)
                                          for k, v in sorted(tables.items())}),
                '  cx_pk_g = parse_json(string(get(cx_pk_gt, [cx_pk_pack + "|" + cx_pk_et]) ?? "") ?? "") ?? null',
                "  if is_object(cx_pk_g) {",
                '    cx_pk_out = merge(cx_pk_out, {"guidance": merge(object!(cx_pk_g), {"basis": "pack_guidance"})})',
                '    cx_pk_gfl = "guidance,"',
                "  }"]
    out += [('  cx_pk_out = merge(cx_pk_out, {"enrichment": {'
             '"fields_observed": compact(split(cx_pk_base + cx_pk_obs, ",")), '
             '"fields_derived": compact(split(cx_pk_derv, ",")), '
             '"fields_guidance": compact(split(cx_pk_gfl, ",")), '
             '"unknown": compact(split(cx_pk_unk, ","))}})'),
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
                                     "timestamp") if k in fx}
            # Vector stamps a test event with the current time when it states none, so
            # every case states one: the same input for both executors, run to run.
            ev.setdefault("timestamp", DEFAULT_FIXTURE_TIME)
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
        for key in ("hostname", "appname", "severity", "message", "msgid", "timestamp"):
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
