# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Compile one vendor-pack grammar row into VRL.

Shared by `gen-syslog-packs.py` (Stage B of the aggregator) and
`gen-syslog-admission.py` (the admission stamp), so the two programs read a pack
grammar through the same text. Rows are what `bake_rules.pack_tables` returns. This
module names no vendor: a new pack needs nothing here.

Every regex sits behind a `contains()` on the row's literal, so a line no pack
recognises costs one substring test per row.
"""

from __future__ import annotations

import json
import re

_TEMPLATE_RE = re.compile(r"\{(\w+)\}")

#: A grammar's `{group}` read from a parse_regex result. `string(...) ?? ""` is the
#: only form that compiles: the two-value parse makes the result's type open.
def group_expr(result: str, group: str) -> str:
    return f'(string({result}.{group}) ?? "")'


def template_expr(template: str, result: str) -> str:
    """A `{group}` template as a VRL string expression."""
    parts: list[str] = []
    pos = 0
    for m in _TEMPLATE_RE.finditer(template):
        if m.start() > pos:
            parts.append(json.dumps(template[pos:m.start()]))
        parts.append(group_expr(result, m.group(1)))
        pos = m.end()
    if pos < len(template):
        parts.append(json.dumps(template[pos:]))
    return " + ".join(parts) if parts else '""'


def severity_lines(row: dict, result: str, target: str, indent: str) -> list[str]:
    """Assign the row's embedded severity to `target`; leaves it alone when the
    line states a value the row's map does not know (`99` stays 99)."""
    if row.get("sev_digit"):
        return [f"{indent}{target} = to_int({result}.{row['sev_digit']}) ?? 99"]
    if row.get("sev_word"):
        word = group_expr(result, row["sev_word"])
        out = [f"{indent}cx_pk_word = {word}"]
        for i, (name, num) in enumerate(sorted(row["sev_map"].items())):
            kw = "if" if i == 0 else "} else if"
            out.append(f'{indent}{kw} cx_pk_word == {json.dumps(name)} {{')
            out.append(f"{indent}  {target} = {num}")
        out.append(f"{indent}}}")
        return out
    return []


def match_condition(row: dict, msg_var: str, app_var: str, vendor_var: str,
                    done_var: str) -> str:
    """The cheap gates, in the order `syslog_packs.Grammar.applies` states them.

    `done_var` closes the chain once a row has matched: first match wins.
    """
    conds = [done_var]
    if row.get("vendor"):
        conds.append(f'({vendor_var} == "" || {vendor_var} == {json.dumps(row["vendor"])})')
    conds.append(f"contains({msg_var}, {json.dumps(row['literal'])})")
    if row.get("apps"):
        conds.append(f"includes({json.dumps(sorted(row['apps']))}, {app_var})")
    return " && ".join(conds)
