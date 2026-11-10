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


#: A grammar's `{group}` read from a parse_regex result. `string(...) ?? ""` is the
#: only form that compiles: the two-value parse makes the result's type open.
def group_expr(result: str, group: str) -> str:
    return f'(string({result}.{group}) ?? "")'


#: `{group}`, or a `[` / `]` optional-clause bound (syslog_packs.template_parts).
_TEMPLATE_TOKEN_RE = re.compile(r"\{(\w+)\}|\[|\]")


def _template_tokens(template: str) -> list[tuple[str, str]]:
    """(kind, text) with kind `lit`, `var`, `[` or `]` (syslog_packs.template_parts)."""
    out: list[tuple[str, str]] = []
    pos = 0
    for m in _TEMPLATE_TOKEN_RE.finditer(template):
        if m.start() > pos:
            out.append(("lit", template[pos:m.start()]))
        out.append(("var", m.group(1)) if m.group(1) else (m.group(0), ""))
        pos = m.end()
    if pos < len(template):
        out.append(("lit", template[pos:]))
    return out


def _var_expr(result: str, name: str, record: dict[str, str] | None) -> str:
    """A template name: a record name (`host`, `device`) when `record` maps it, else the
    regex group of that name."""
    if record and name in record:
        return record[name]
    return group_expr(result, name)


def _concat(parts: list[tuple[str, str]], result: str,
            record: dict[str, str] | None = None) -> str:
    exprs = [json.dumps(t) if k == "lit" else _var_expr(result, t, record) for k, t in parts]
    return " + ".join(exprs) if exprs else '""'


def template_expr(template: str, result: str) -> str:
    """A `{group}` template with no optional clause, as one VRL string expression."""
    toks = _template_tokens(template)
    if any(k in "[]" for k, _ in toks):
        raise ValueError("a template with an optional clause needs template_lines")
    return _concat(toks, result)


def template_lines(template: str, result: str, target: str, indent: str,
                   record: dict[str, str] | None = None) -> list[str]:
    """Assign a template to `target` as VRL statements.

    `[ by {user}]` is an optional clause: appended only when every group in it matched
    (syslog_packs._render states the same rule in Python). VRL 0.40 has no `if` inside
    an expression, so a template with a clause is built up in statements."""
    toks = _template_tokens(template)
    if not any(k in "[]" for k, _ in toks):
        return [f"{indent}{target} = {_concat(toks, result, record)}"]
    out = [f'{indent}{target} = ""']
    plain: list[tuple[str, str]] = []
    clause: list[tuple[str, str]] | None = None
    for kind, text in toks:
        if kind == "[":
            if plain:
                out.append(f"{indent}{target} = {target} + {_concat(plain, result, record)}")
                plain = []
            clause = []
        elif kind == "]":
            body = clause or []
            cond = " && ".join(f'{_var_expr(result, t, record)} != ""'
                               for k, t in body if k == "var")
            out += [f"{indent}if {cond} {{",
                    f"{indent}  {target} = {target} + {_concat(body, result, record)}",
                    f"{indent}}}"]
            clause = None
        else:
            (plain if clause is None else clause).append((kind, text))
    if plain:
        out.append(f"{indent}{target} = {target} + {_concat(plain, result, record)}")
    return out


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
                    open_cond: str) -> str:
    """The cheap gates, in the order `syslog_packs.Grammar.applies` states them.

    `open_cond` is true until a row has matched: first match wins.
    """
    conds = [open_cond]
    if row.get("vendor"):
        conds.append(f'({vendor_var} == "" || {vendor_var} == {json.dumps(row["vendor"])})')
    conds.append(f"contains({msg_var}, {json.dumps(row['literal'])})")
    if row.get("apps"):
        conds.append(f"includes({json.dumps(sorted(row['apps']))}, {app_var})")
    return " && ".join(conds)
