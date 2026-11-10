#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Bake `events.yaml` into `src/correlation/parser_rules.py` (A3).

WHY A BAKE AND NOT A RUNTIME READ. The correlation image copies `src/correlation/`
only — `telemetry-catalog/` is a REPO artifact and is deliberately not shipped
(see deployment/docker/Dockerfile.correlation). A runtime YAML read would
therefore resolve to nothing in production and to the real rules in tests: the
worst possible failure mode. So the catalog is compiled, at development time,
into a CHECKED-IN generated module, and CI proves the two agree:

    python3 bake_rules.py            # regenerate
    python3 bake_rules.py --check    # CI drift guard: exits 1 if stale

`test_bake_drift.py` runs `--check` as a test, so a rule edit that forgets to
re-bake is RED before it can ship a parser whose behaviour disagrees with its
own spec.

VALIDATION IS PART OF THE BAKE (never a separate, skippable step): unknown keys
are rejected, every required key must be present, every guard/extraction/emit
tree must COMPILE, and `pattern_src` must actually occur inside the guard it
claims to register with the ingest screen. A row that does not validate does not
bake — the generated module is never partially correct.
"""
from __future__ import annotations

import argparse
import copy
import os
import pprint
import re
import sys
from typing import Any

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
EVENTS = os.path.join(HERE, "events.yaml")
#: One YAML file per vendor pack (README, "Vendor packs"). A new vendor is a new
#: file here; nothing in the bake, the engine or the Vector generator names one.
PACKS_DIR = os.path.join(HERE, "vendor-packs")
TARGET = os.path.abspath(
    os.path.join(HERE, "..", "src", "correlation", "parser_rules.py"))

# The rule model lives with the code it drives; importing it here is what
# guarantees the bake validates against the SAME compiler the runtime uses.
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "src", "correlation")))

from rule_model import (
    LANE_FIELDS,
    LANE_VARS,
    RuleError,
    compile_rule,
    pack_digest,
    rules_hash,
)

LANES = ("syslog", "port", "trap", "catalog")
RUNTIME_LANES = ("syslog", "port", "trap")   # what the image actually ships
SOURCES = ("syslog", "trap")
SEVERITIES = ("info", "warn", "high", "crit")
ENTITY_TYPES = ("device", "interface", "device_or_interface", "path")
#: The catalog's fidelity ladder (README). A ROW may state its own rung when the
#: family's rung is not its evidence — see `fidelity_status` below.
FIDELITY_STATUSES = ("doc_claimed", "lab_validated", "live_validated",
                     "degraded", "failed")

ROW_KEYS = frozenset({
    "rule_id", "lane", "source", "kind", "entity_type", "family", "vendors",
    "markers", "pattern_src", "state", "state_re", "severity", "generic",
    "shadow", "guard", "extract", "emit", "fidelity_status", "known_benign",
    "benign_reason",
})
ROW_REQUIRED = ("rule_id", "lane", "source", "kind", "entity_type", "guard", "emit")
EMIT_KEYS = frozenset({
    "kind", "metric", "modality", "entity", "severity", "native_id",
    "content_tag", "tokens", "tokens_fallback", "attrs", "omit_empty",
})
ENTITY_KEYS = frozenset({"type", "id", "when", "else"})
#: `_frag` holds the YAML anchors the rows share (they expand at load, so the
#: baked table carries the literal text — nothing is indirect at runtime).
TOP_KEYS = frozenset({"version", "parser_rev", "rules", "families", "_frag"})
FAMILY_KEYS = frozenset({
    "labels", "correlates_with", "join_on", "fidelity_status", "live_capture",
    "issue_ref",
})


class BakeError(Exception):
    """A rule row that must not reach the generated module."""


# ── validation ───────────────────────────────────────────────────────────────


def _re_patterns(node: Any) -> list[str]:
    """Every regex SOURCE string reachable in a guard tree."""
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "re" and isinstance(v, list) and len(v) >= 2:
                out.append(str(v[1]))
            else:
                out.extend(_re_patterns(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_re_patterns(v))
    return out


#: Guard/extraction keys whose FIRST element names a haystack.
_FIELD_OPS = frozenset({
    "contains", "re", "eq", "ne", "equals_any", "not_in", "findall",
})


def _fields_used(node: Any, out: set[str]) -> set[str]:
    """Every lane haystack a spec tree reads (`$var` references excluded)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in _FIELD_OPS and isinstance(v, (list, tuple)) and v:
                head = v[0]
                if k == "re" and isinstance(head, (list, tuple)):
                    for alt in v:                       # extraction form
                        if isinstance(alt, (list, tuple)) and alt:
                            out.add(str(alt[0]))
                    continue
                out.add(str(head))
                continue
            if k == "truthy" and isinstance(v, str):
                out.add(v)
                continue
            if k in ("scan", "pick") and isinstance(v, dict) and "field" in v:
                out.add(str(v["field"]))
            _fields_used(v, out)
    elif isinstance(node, (list, tuple)):
        for v in node:
            _fields_used(v, out)
    return out


def validate_row(row: dict, families: dict, seen: set[str]) -> None:
    rid = row.get("rule_id")
    where = f"rule {rid!r}"
    unknown = sorted(set(row) - ROW_KEYS)
    if unknown:
        raise BakeError(f"{where}: unknown key(s) {unknown}")
    for k in ROW_REQUIRED:
        if row.get(k) in (None, ""):
            raise BakeError(f"{where}: missing required key {k!r}")
    if not isinstance(rid, str) or not rid:
        raise BakeError(f"{where}: rule_id must be a non-empty string")
    if rid in seen:
        raise BakeError(f"{where}: duplicate rule_id")
    seen.add(rid)
    if row["lane"] not in LANES:
        raise BakeError(f"{where}: lane {row['lane']!r} not in {LANES}")
    if row["source"] not in SOURCES:
        raise BakeError(f"{where}: source {row['source']!r} not in {SOURCES}")
    if row["entity_type"] not in ENTITY_TYPES:
        raise BakeError(f"{where}: entity_type {row['entity_type']!r} unknown")
    if "family" not in row:
        raise BakeError(f"{where}: must declare `family` (null when it has none)")
    fam = row["family"]
    if fam is not None and fam not in families:
        raise BakeError(f"{where}: family {fam!r} is not defined in `families:`")
    sev = row.get("severity")
    if sev is not None and sev not in SEVERITIES:
        raise BakeError(f"{where}: severity {sev!r} not in {SEVERITIES}")
    # A9: a row-level fidelity claim. A trap rule for a symptom the syslog rules
    # already carry shares their FAMILY but not their evidence — promoting the
    # family would restate a syslog capture the trap says nothing about — so the
    # rung is stated on the row. It is a CATALOG claim, not grammar: it never
    # enters `rules_hash` (see Rule.digest_fields).
    fid = row.get("fidelity_status")
    if fid is not None and fid not in FIDELITY_STATUSES:
        raise BakeError(
            f"{where}: fidelity_status {fid!r} not on the ladder {FIDELITY_STATUSES}")
    for k in ("generic", "shadow", "known_benign"):
        if k in row and not isinstance(row[k], bool):
            raise BakeError(f"{where}: {k} must be a boolean")
    if row.get("known_benign"):
        if not str(row.get("benign_reason") or "").strip():
            raise BakeError(f"{where}: known_benign must state its benign_reason")
        if row.get("shadow") or row.get("generic"):
            raise BakeError(f"{where}: known_benign cannot be shadow or generic")
    for k in ("vendors", "markers"):
        v = row.get(k, [])
        if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
            raise BakeError(f"{where}: {k} must be a list of strings")
    for m in row.get("markers", []):
        if m != m.upper():
            raise BakeError(
                f"{where}: marker {m!r} must be UPPER-CASE — the ingest screen "
                "matches an upper-cased classification token")
    # The screen contract: a registered pattern that is not in the guard would
    # advertise coverage for a gate that no longer exists.
    pat = row.get("pattern_src")
    if pat is not None and pat not in _re_patterns(row["guard"]):
        raise BakeError(
            f"{where}: pattern_src is not a `re` node of its own guard — the "
            "ingest screen would claim coverage for a gate that is gone")
    emit = row["emit"]
    if not isinstance(emit, dict):
        raise BakeError(f"{where}: emit must be a mapping")
    unknown = sorted(set(emit) - EMIT_KEYS)
    if unknown:
        raise BakeError(f"{where}: unknown emit key(s) {unknown}")
    ent = emit.get("entity")
    if ent is not None:
        unknown = sorted(set(ent) - ENTITY_KEYS)
        if unknown:
            raise BakeError(f"{where}: unknown emit.entity key(s) {unknown}")
        if "when" in ent and "else" not in ent:
            raise BakeError(f"{where}: emit.entity has `when` but no `else`")
    if emit.get("severity") is None and row.get("severity") is None:
        raise BakeError(f"{where}: declares neither emit.severity nor severity")
    # tracker 218: `omit_empty` drops an attr the event did not carry. It may
    # only name a key the rule actually emits — otherwise the row is claiming a
    # conditional field that nothing builds, and the claim would never fire.
    omit = emit.get("omit_empty") or ()
    if not isinstance(omit, list | tuple):
        raise BakeError(f"{where}: emit.omit_empty must be a list of attr keys")
    stray_attrs = sorted(set(map(str, omit)) - set(emit.get("attrs") or {}))
    if stray_attrs:
        raise BakeError(
            f"{where}: emit.omit_empty names {stray_attrs}, which the rule does "
            "not emit")
    if row["lane"] in RUNTIME_LANES:
        for k in ("metric", "modality", "native_id"):
            if not emit.get(k):
                raise BakeError(f"{where}: a runtime rule needs emit.{k}")
    # A rule may only read the haystacks ITS LANE builds. Without this the
    # mistake surfaces as a KeyError on a production line — the worst possible
    # place to discover a typo — because the compiler inlines the field access.
    allowed = LANE_FIELDS.get(row["lane"], frozenset())
    used = _fields_used(row.get("guard"), set()) | _fields_used(row.get("extract"), set())
    stray = sorted(f for f in used if not f.startswith("$") and f not in allowed)
    if stray:
        raise BakeError(
            f"{where}: reads field(s) {stray} that lane {row['lane']!r} does not "
            f"build (it has {sorted(allowed)})")
    # An extraction may not shadow a var the lane seeds: the seeded value wins,
    # so the grammar would silently never run.
    shadowed = sorted(set(row.get("extract") or ()) & LANE_VARS.get(row["lane"], frozenset()))
    if shadowed:
        raise BakeError(
            f"{where}: extraction(s) {shadowed} shadow a lane var — the lane's "
            "value would win and this grammar would never run")
    # The compiler is the last word: if it cannot build the closures, the row is
    # not a rule.
    try:
        compile_rule(normalize_row(row))
    except (RuleError, KeyError, TypeError, ValueError) as exc:
        raise BakeError(f"{where}: does not compile — {exc}") from exc


def validate_family(name: str, fam: dict) -> None:
    unknown = sorted(set(fam) - FAMILY_KEYS)
    if unknown:
        raise BakeError(f"family {name!r}: unknown key(s) {unknown}")
    if not fam.get("labels"):
        raise BakeError(f"family {name!r}: must declare `labels`")
    if not fam.get("join_on"):
        raise BakeError(f"family {name!r}: must declare `join_on`")


# ── normalization ────────────────────────────────────────────────────────────


def normalize_row(row: dict) -> dict:
    """The row as the model consumes it — defaults filled, aliases expanded.

    Deep-copied first: YAML anchors make several rows share ONE dict object
    (the twelve port rules share `emit`), so filling a default in place would
    write another rule's `kind` into all of them.
    """
    out = copy.deepcopy(row)
    out.setdefault("vendors", [])
    out.setdefault("markers", [])
    out.setdefault("generic", False)
    out.setdefault("shadow", False)
    out.setdefault("known_benign", False)
    emit = out["emit"]
    emit.setdefault("kind", out["kind"])
    # A row's own `kind` is a BAKE-TIME CONSTANT, folded into the templates that
    # use it. The twelve port rules share one `emit:` anchor and differ only in
    # `kind`, so `{kind}` / `{var: kind}` is how the anchor stays one shape —
    # but resolving it per event would make every rule pay for a var lookup the
    # rule already knows the answer to.
    if isinstance(emit.get("native_id"), str):
        emit["native_id"] = emit["native_id"].replace("{kind}", out["kind"])
    for key, spec in (emit.get("attrs") or {}).items():
        if isinstance(spec, dict) and spec.get("var") == "kind":
            emit["attrs"][key] = {"const": out["kind"]}
    return out


# ── vendor packs ─────────────────────────────────────────────────────────────

PACK_KEYS = frozenset({
    "pack", "vendor", "description", "severity_words", "edge_shapes", "envelopes",
    "grammars", "rules", "fixtures", "wanted", "guidance", "labels",
})
#: A frame shape normalised at the edge, before syslog-ng's legacy parser runs. `match`
#: is anchored at the PRI, so it costs one failed anchor on any other frame.
EDGE_SHAPE_KEYS = frozenset({"id", "match", "replace", "no_header", "fidelity", "source"})
#: Characters a shape may not contain: the row is pasted into a syslog-ng `'...'`
#: string, and a backtick there is a config variable.
EDGE_SHAPE_FORBIDDEN_CHARS = ("'", "`", "\n")
PACK_REQUIRED = ("pack", "vendor", "fixtures")
GRAMMAR_KEYS = frozenset({
    "id", "parser_id", "literal", "apps", "pattern", "facility", "event_type",
    "summary", "severity", "native_text", "native_code", "alarm_floor",
    "category", "fidelity", "source", "with_msgid", "fields", "metrics",
})
#: The event-model fields a grammar may state as templates (tracker 387, the rich event
#: model shared with the trap lane: same names, same meaning). Strings only; `metrics`
#: and `guidance` are their own keys.
EVENT_FIELDS = (
    "title", "correlation_key", "audit_user", "audit_action", "audit_source",
    "audit_via", "session_id", "audit_groups", "dump_id",
)
#: Template names that read the record, not the line: the sender's hostname, the
#: inventory device id (the hostname when the registry states none) and the record's
#: event time as its UTC minute (`YYYY-MM-DDTHH:MM`, "" when the record states none).
RESERVED_TEMPLATE_VARS = frozenset({"host", "device", "minute"})
#: A pack label table's name, and the text a label may hold: it is compiled into a VRL
#: string literal, so printable ASCII with no backslash, quote or dollar sign.
_LABEL_TABLE_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_LABEL_TEXT_RE = re.compile(r"[ !#%&(-\[\]-~]{1,96}")
_METRIC_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
GUIDANCE_KEYS = frozenset({"event_types", "impact", "next_checks"})
GRAMMAR_REQUIRED = ("id", "parser_id", "literal", "pattern", "fidelity")
ENVELOPE_KEYS = frozenset({
    "id", "literal", "pattern", "message", "lift", "skip_values", "preserve_as",
    "fidelity", "source",
})
ENVELOPE_REQUIRED = ("id", "literal", "pattern", "message", "preserve_as", "fidelity")
FIXTURE_KEYS = frozenset({
    "name", "hostname", "appname", "severity", "message", "expect", "signal",
    "fidelity", "msgid", "source", "timestamp",
})
FIXTURE_REQUIRED = ("name", "message", "expect", "signal", "fidelity")
WANTED_KEYS = frozenset({"symptom", "why_absent", "kind"})
#: Characters a grammar may not contain: a pattern is pasted into `r'…'` VRL, and
#: Vector interpolates `$` in the raw config text, comments included.
PACK_FORBIDDEN_CHARS = ("'", "$")
_TEMPLATE_VAR_RE = re.compile(r"\{(\w+)(?:\|(\w+))?\}")


def _check_pack_pattern(where: str, spec: dict) -> dict[str, int]:
    """Compile a grammar/envelope pattern; returns its named groups."""
    pat = str(spec["pattern"])
    lit = str(spec["literal"])
    for ch in PACK_FORBIDDEN_CHARS:
        if ch in pat or ch in lit:
            raise BakeError(f"{where}: {ch!r} cannot be compiled into VRL soundly")
    try:
        groups = dict(re.compile(pat).groupindex)
    except re.error as exc:
        raise BakeError(f"{where}: pattern does not compile — {exc}") from exc
    return groups


def _check_group(where: str, name: str, groups: dict[str, int]) -> None:
    if name not in groups:
        raise BakeError(f"{where}: names group {name!r}, which the pattern lacks")


def _check_fidelity(where: str, spec: dict) -> None:
    fid = spec.get("fidelity")
    if fid not in FIDELITY_STATUSES:
        raise BakeError(f"{where}: fidelity {fid!r} not on the ladder")
    if fid == "doc_claimed" and not str(spec.get("source") or "").strip():
        raise BakeError(
            f"{where}: a doc_claimed row must cite the `source` that documents it")


def _bake_grammar(pack: dict, g: dict, seen: set[str]) -> dict:
    where = f"pack {pack['pack']!r} grammar {g.get('id')!r}"
    unknown = sorted(set(g) - GRAMMAR_KEYS)
    if unknown:
        raise BakeError(f"{where}: unknown key(s) {unknown}")
    for k in GRAMMAR_REQUIRED:
        if not g.get(k):
            raise BakeError(f"{where}: missing required key {k!r}")
    gid = f"{pack['pack']}.{g['id']}"
    if gid in seen:
        raise BakeError(f"{where}: duplicate grammar id")
    seen.add(gid)
    groups = _check_pack_pattern(where, g)
    _check_fidelity(where, g)
    labels = pack.get("labels") or {}
    used: set[str] = set()
    for key in ("facility", "event_type", "summary"):
        used |= _check_template(where, key, str(g.get(key) or ""), groups, reserved=False,
                                labels=labels)
    fields = g.get("fields") or {}
    if not isinstance(fields, dict):
        raise BakeError(f"{where}: fields must be a mapping")
    for name, tmpl in fields.items():
        if name not in EVENT_FIELDS:
            raise BakeError(f"{where}: field {name!r} is not one of {EVENT_FIELDS}")
        if not isinstance(tmpl, str) or not tmpl.strip():
            raise BakeError(f"{where}: field {name!r} needs a template")
        used |= _check_template(where, name, tmpl, groups, reserved=True, labels=labels)
    metrics = g.get("metrics") or {}
    if not isinstance(metrics, dict):
        raise BakeError(f"{where}: metrics must be a mapping of name to group")
    baked_metrics: dict[str, Any] = {}
    for name, spec in metrics.items():
        if not _METRIC_NAME_RE.fullmatch(str(name)):
            raise BakeError(f"{where}: metric name {name!r} is not snake_case")
        # `name: group` is a number; `name: {text: group}` keeps the matched text.
        if isinstance(spec, dict):
            if set(spec) != {"text"}:
                raise BakeError(f"{where}: metric {name!r} takes a group or {{text: group}}")
            _check_group(where, str(spec["text"]), groups)
            baked_metrics[str(name)] = {"text": str(spec["text"])}
        else:
            _check_group(where, str(spec), groups)
            baked_metrics[str(name)] = str(spec)
    for key in ("native_text", "native_code"):
        if g.get(key):
            _check_group(where, str(g[key]), groups)
    sev = g.get("severity")
    sev_digit = sev_word = ""
    sev_map: dict[str, int] = {}
    if sev is not None:
        unknown = sorted(set(sev) - {"digit", "word"})
        if unknown or len(sev) != 1:
            raise BakeError(f"{where}: severity takes exactly one of digit | word")
        if "digit" in sev:
            sev_digit = str(sev["digit"])
            _check_group(where, sev_digit, groups)
        else:
            sev_word = str(sev["word"])
            _check_group(where, sev_word, groups)
            sev_map = dict(pack.get("severity_words") or {})
            if not sev_map:
                raise BakeError(f"{where}: severity.word needs pack `severity_words`")
            for word, num in sev_map.items():
                if not isinstance(num, int) or not 0 <= num <= 7:
                    raise BakeError(f"{where}: severity word {word!r} -> {num!r}, not 0..7")
                if not re.fullmatch(r"[A-Za-z0-9_]+", str(word)):
                    raise BakeError(f"{where}: severity word {word!r} is not a plain word")
        floor = g.get("alarm_floor")
        if not isinstance(floor, int) or not 0 <= floor <= 7:
            raise BakeError(
                f"{where}: a severity-bearing grammar must state alarm_floor (0..7): "
                "the worst embedded severity that may alarm on severity ALONE")
    elif g.get("alarm_floor") is not None:
        raise BakeError(f"{where}: alarm_floor without a severity reader")
    apps = [str(a).lower() for a in (g.get("apps") or [])]
    # `with_msgid`: the row reads `<MSGID>: <message>` when the frame carries an RFC 5424
    # MSGID, so one grammar states a tag a sender puts in MSGID in one format and at the
    # head of the message in the other. Severity stays out of it: the admission stamp and
    # the screen read the message alone, and a severity read from a field they never see
    # would make the two disagree about a line.
    with_msgid = g.get("with_msgid", False)
    if not isinstance(with_msgid, bool):
        raise BakeError(f"{where}: with_msgid must be a boolean")
    if with_msgid and sev is not None:
        raise BakeError(f"{where}: a with_msgid grammar cannot read severity")
    if g.get("category") and not g.get("event_type"):
        raise BakeError(f"{where}: a category row needs event_type (its dedup key)")
    return {
        "pack": pack["pack"], "vendor": pack["vendor"] or "", "id": gid,
        "parser_id": g["parser_id"], "literal": g["literal"], "apps": apps,
        "pattern": g["pattern"], "facility": g.get("facility") or "",
        "event_type": g.get("event_type") or "", "summary": g.get("summary") or "",
        "sev_digit": sev_digit, "sev_word": sev_word, "sev_map": sev_map,
        "native_text": g.get("native_text") or "",
        "native_code": g.get("native_code") or "",
        "alarm_floor": g.get("alarm_floor"), "category": g.get("category") or "",
        "fidelity": g["fidelity"], "source": g.get("source") or "",
        **({"with_msgid": True} if with_msgid else {}),
        **({"fields": dict(fields)} if fields else {}),
        **({"metrics": baked_metrics} if baked_metrics else {}),
        **({"guidance": guidance_table(pack)} if pack.get("guidance") else {}),
        **({"labels": {t: dict(labels[t]) for t in sorted(used)}} if used else {}),
    }


def _check_template(where: str, key: str, tmpl: str, groups: dict[str, int],
                    reserved: bool, labels: dict | None = None) -> set[str]:
    """Groups exist (or are a reserved record name), a `{group|table}` names a label
    table the pack states, and `[ ... ]` optional clauses are balanced, flat, and hold a
    group to drop on (syslog_packs.template_parts). Returns the label tables read."""
    if "$" in tmpl:
        raise BakeError(f"{where}: {key} carries a dollar sign: Vector would interpolate it")
    used: set[str] = set()
    for name, table in _TEMPLATE_VAR_RE.findall(tmpl):
        if table:
            if name in RESERVED_TEMPLATE_VARS:
                raise BakeError(f"{where}: {key} reads a record name through a label table")
            if table not in (labels or {}):
                raise BakeError(f"{where}: {key} reads label table {table!r}, "
                                "which the pack does not state")
            used.add(table)
        if reserved and name in RESERVED_TEMPLATE_VARS:
            continue
        _check_group(where, name, groups)
    depth, has_var = 0, False
    for tok in re.finditer(r"\{(\w+(?:\|\w+)?)\}|\[|\]", tmpl):
        if tok.group(0) == "[":
            if depth:
                raise BakeError(f"{where}: {key} nests an optional clause")
            depth, has_var = 1, False
        elif tok.group(0) == "]":
            if not depth:
                raise BakeError(f"{where}: {key} closes a clause it never opened")
            if not has_var:
                raise BakeError(f"{where}: {key} has a clause with no group to drop on")
            depth = 0
        elif depth:
            has_var = True
    if depth:
        raise BakeError(f"{where}: {key} leaves an optional clause open")
    return used


def _check_labels(where: str, labels: object) -> None:
    """`labels: {table: {value: label}}`, vendor-scoped presentation text."""
    if not isinstance(labels, dict) or not labels:
        raise BakeError(f"{where}: labels must be a non-empty mapping of table to entries")
    for table, entries in labels.items():
        if not _LABEL_TABLE_RE.fullmatch(str(table)):
            raise BakeError(f"{where}: label table {table!r} is not snake_case")
        if not isinstance(entries, dict) or not entries:
            raise BakeError(f"{where}: label table {table!r} needs entries")
        for value, label in entries.items():
            if not isinstance(value, str) or not value or not isinstance(label, str):
                raise BakeError(f"{where}: label table {table!r} maps text to text")
            for text in (value, label):
                if not _LABEL_TEXT_RE.fullmatch(text):
                    raise BakeError(f"{where}: label {text!r} is not plain printable text "
                                    "(no quote, backslash or dollar sign)")


def guidance_table(pack: dict) -> dict[str, dict]:
    """event_type -> {impact, next_checks}: what an operator checks first for a fault
    family, stated by the pack (`basis: pack_guidance` on the record). Text only: it
    never moves a signal, so it stays out of PACK_DIGEST."""
    where = f"pack {pack['pack']!r} guidance"
    out: dict[str, dict] = {}
    for entry in pack.get("guidance") or []:
        unknown = sorted(set(entry) - GUIDANCE_KEYS)
        if unknown:
            raise BakeError(f"{where}: unknown key(s) {unknown}")
        ets = entry.get("event_types") or []
        impact = [str(x) for x in entry.get("impact") or []]
        checks = [str(x) for x in entry.get("next_checks") or []]
        if not ets or not impact or not checks:
            raise BakeError(f"{where}: an entry needs event_types, impact and next_checks")
        for text in impact + checks:
            if "$" in text or "\n" in text:
                raise BakeError(f"{where}: {text[:40]!r} carries a dollar sign or newline")
        for et in ets:
            et = str(et)
            if et != et.lower() or et in out:
                raise BakeError(f"{where}: event type {et!r} is not lower case or repeats")
            out[et] = {"impact": impact, "next_checks": checks}
    return out


def _bake_envelope(pack: dict, e: dict, seen: set[str]) -> dict:
    where = f"pack {pack['pack']!r} envelope {e.get('id')!r}"
    unknown = sorted(set(e) - ENVELOPE_KEYS)
    if unknown:
        raise BakeError(f"{where}: unknown key(s) {unknown}")
    for k in ENVELOPE_REQUIRED:
        if not e.get(k):
            raise BakeError(f"{where}: missing required key {k!r}")
    eid = f"{pack['pack']}.{e['id']}"
    if eid in seen:
        raise BakeError(f"{where}: duplicate envelope id")
    seen.add(eid)
    groups = _check_pack_pattern(where, e)
    _check_fidelity(where, e)
    _check_group(where, str(e["message"]), groups)
    lift = dict(e.get("lift") or {})
    for name in lift.values():
        _check_group(where, str(name), groups)
    return {
        "pack": pack["pack"], "id": eid, "literal": e["literal"],
        "pattern": e["pattern"], "message": e["message"], "lift": lift,
        "skip_values": list(e.get("skip_values") or []),
        "preserve_as": e["preserve_as"], "fidelity": e["fidelity"],
        "source": e.get("source") or "",
    }


def edge_shapes(packs: list[dict]) -> list[dict]:
    """The frame shapes every pack states, validated, in pack order. Compiled into
    syslog-ng's core.conf by scripts/gen-syslog-packs.py. The engine never reads a raw
    frame, so these stay out of PACK_DIGEST: a shape moves no signal by itself."""
    seen: set[str] = set()
    out: list[dict] = []
    for pack in packs:
        for row in pack.get("edge_shapes") or []:
            where = f"pack {pack['pack']!r} edge shape {row.get('id')!r}"
            unknown = sorted(set(row) - EDGE_SHAPE_KEYS)
            if unknown:
                raise BakeError(f"{where}: unknown key(s) {unknown}")
            if not row.get("id") or not row.get("match"):
                raise BakeError(f"{where}: `id` and `match` are required")
            sid = f"{pack['pack']}.{row['id']}"
            if sid in seen:
                raise BakeError(f"{where}: duplicate edge shape id")
            seen.add(sid)
            _check_fidelity(where, row)
            match = str(row["match"])
            replace = row.get("replace")
            no_header = bool(row.get("no_header"))
            if (replace is None) == (not no_header):
                raise BakeError(f"{where}: state exactly one of `replace` or `no_header`")
            if not match.startswith("^<") and not match.startswith("^(<"):
                raise BakeError(f"{where}: `match` must be anchored at the PRI")
            for ch in EDGE_SHAPE_FORBIDDEN_CHARS:
                if ch in match or ch in str(replace or ""):
                    raise BakeError(f"{where}: {ch!r} cannot be compiled into syslog-ng soundly")
            try:
                re.compile(match)
            except re.error as exc:
                raise BakeError(f"{where}: `match` does not compile — {exc}") from exc
            out.append({"id": sid, "match": match, "replace": replace,
                        "no_header": no_header, "fidelity": row["fidelity"],
                        "source": row.get("source") or ""})
    return out


def _check_fixture(pack: dict, fx: dict) -> None:
    where = f"pack {pack['pack']!r} fixture {fx.get('name')!r}"
    unknown = sorted(set(fx) - FIXTURE_KEYS)
    if unknown:
        raise BakeError(f"{where}: unknown key(s) {unknown}")
    for k in FIXTURE_REQUIRED:
        if k not in fx:
            raise BakeError(f"{where}: missing required key {k!r}")
    if fx["fidelity"] not in FIDELITY_STATUSES:
        raise BakeError(f"{where}: fidelity {fx['fidelity']!r} not on the ladder")
    if "timestamp" in fx and not isinstance(fx["timestamp"], str):
        # Unquoted, YAML reads a datetime, and the vector suite would get its str().
        raise BakeError(f"{where}: timestamp must be a quoted RFC 3339 string")


def load_packs(packs_dir: str = PACKS_DIR) -> list[dict]:
    """Every pack file, validated: vendor packs first (sorted by name), then the
    vendor-neutral ones (`vendor: null`). First match wins, so a vendor's specific
    grammar always gets the line before a standard one."""
    packs: list[dict] = []
    names: set[str] = set()
    for fname in sorted(os.listdir(packs_dir)) if os.path.isdir(packs_dir) else ():
        if not fname.endswith(".yaml"):
            continue
        with open(os.path.join(packs_dir, fname), encoding="utf-8") as fh:
            pack = yaml.safe_load(fh)
        where = f"pack file {fname!r}"
        if not isinstance(pack, dict):
            raise BakeError(f"{where}: not a mapping")
        unknown = sorted(set(pack) - PACK_KEYS)
        if unknown:
            raise BakeError(f"{where}: unknown key(s) {unknown}")
        for k in PACK_REQUIRED:
            if k not in pack:
                raise BakeError(f"{where}: missing required key {k!r}")
        if pack["pack"] in names:
            raise BakeError(f"{where}: duplicate pack name {pack['pack']!r}")
        names.add(pack["pack"])
        if "labels" in pack:
            _check_labels(where, pack["labels"])
        if not pack.get("fixtures"):
            raise BakeError(f"{where}: a pack with no fixtures proves nothing")
        for fx in pack["fixtures"]:
            _check_fixture(pack, fx)
        for w in pack.get("wanted") or []:
            if set(w) - WANTED_KEYS:
                raise BakeError(f"{where}: unknown `wanted` key(s) {sorted(set(w) - WANTED_KEYS)}")
        packs.append(pack)
    packs.sort(key=lambda p: (p["vendor"] is None, p["pack"]))
    return packs


def pack_tables(packs: list[dict]) -> tuple[list[dict], list[dict]]:
    """(grammars, envelopes) in match order, as they are baked."""
    seen: set[str] = set()
    grammars = [_bake_grammar(p, g, seen) for p in packs for g in p.get("grammars") or []]
    envelopes = [_bake_envelope(p, e, seen) for p in packs for e in p.get("envelopes") or []]
    return grammars, envelopes


def _merge_pack_rows(rows: list[dict], packs: list[dict]) -> list[dict]:
    """A pack's rule rows go immediately BEFORE their lane's generic safety net:
    after every vendor-neutral rule, so a line that classified before still does,
    and before the net, so a typed row answers instead of the alarm."""
    out = list(rows)
    for pack in packs:
        for row in pack.get("rules") or []:
            where = f"pack {pack['pack']!r} rule {row.get('rule_id')!r}"
            if not row.get("fidelity_status"):
                raise BakeError(f"{where}: a pack row must state its fidelity_status")
            # The LAST generic row of the lane is the net: a pack's own below-floor
            # catch-all is `generic` too, and must stay ahead of it.
            anchor = next((i for i in range(len(out) - 1, -1, -1)
                           if out[i].get("lane") == row.get("lane")
                           and out[i].get("generic")), None)
            if anchor is None:
                raise BakeError(f"{where}: lane {row.get('lane')!r} has no generic net")
            out.insert(anchor, row)
    return out


def load(path: str = EVENTS, packs_dir: str = PACKS_DIR) -> tuple[dict, list[dict]]:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    unknown = sorted(set(data) - TOP_KEYS)
    if unknown:
        raise BakeError(f"events.yaml: unknown top-level key(s) {unknown}")
    if not str(data.get("parser_rev") or "").strip():
        raise BakeError("events.yaml: `parser_rev` is required — it is the "
                        "hand-bumped half of every signal's provenance")
    families = data.get("families") or {}
    packs = load_packs(packs_dir)
    rows = _merge_pack_rows(data.get("rules") or [], packs)
    seen: set[str] = set()
    for name, fam in families.items():
        validate_family(name, fam)
    for row in rows:
        validate_row(row, families, seen)
    grammars, envelopes = pack_tables(packs)
    data["_pack_grammars"] = grammars
    data["_pack_envelopes"] = envelopes
    return data, [normalize_row(r) for r in rows]


# ── code generation ──────────────────────────────────────────────────────────

HEADER = '''\
"""GENERATED — DO NOT EDIT. Baked from telemetry-catalog/events.yaml.

    cd telemetry-catalog && python3 bake_rules.py

`telemetry-catalog/` is NOT shipped inside the correlation image (the Dockerfile
copies `src/correlation/` only), so the parser rules are compiled into this
module at development time rather than read from YAML at runtime — a runtime
read would resolve to the real rules in tests and to NOTHING in production.

`test_bake_drift.py` re-bakes and compares, so this file cannot silently drift
from the catalog it was baked from. Edit `events.yaml`, then re-run the bake.
"""

from __future__ import annotations

from typing import Any

from rule_model import Rule, compile_rule, install_fidelity, pack_digest, rules_hash

#: The catalog file this module was baked from.
SOURCE = "telemetry-catalog/events.yaml"

#: HAND-BUMPED in events.yaml on any rule change; rides on every signal.
PARSER_REV = {parser_rev!r}

#: The telemetry-catalog event-family fidelity ladder, as of PARSER_REV — the
#: families that declare a `fidelity_status`. A family the catalog knows but
#: leaves undeclared, and a rule with no family at all, both stamp "code": the
#: grammar exists only in the rule table and the catalog vouches for nothing.
CATALOG_EVENT_FIDELITY: dict[str, str] = {fidelity}

install_fidelity(CATALOG_EVENT_FIDELITY)

#: Vendor-pack syslog grammars, in MATCH ORDER (telemetry-catalog/vendor-packs/).
#: Vector's generated branch and `syslog_packs.PackTable` both run these rows.
SYSLOG_GRAMMARS: tuple[dict[str, Any], ...] = {grammars}

#: Vendor-pack syslog envelope rules, in match order.
SYSLOG_ENVELOPES: tuple[dict[str, Any], ...] = {envelopes}

#: The rule rows, in CLASSIFICATION ORDER. Order is behaviour: the interpreter
#: walks a lane's rules in sequence, first match wins.
_ROWS: tuple[dict[str, Any], ...] = (
'''

FOOTER = '''\
)

RULES: tuple[Rule, ...] = tuple(compile_rule(row) for row in _ROWS)

#: The hash the BAKE computed. `RULES_HASH` recomputes it at import; they must
#: agree, which is what makes a hand-edit of this file impossible to hide.
BAKED_RULES_HASH = {baked!r}
PACK_DIGEST: str = pack_digest(SYSLOG_GRAMMARS, SYSLOG_ENVELOPES)
RULES_HASH: str = rules_hash(RULES, PACK_DIGEST)
'''


#: Grammar keys only the aggregator's Stage B reads: the rich event model.
PRESENTATION_KEYS = frozenset({"fields", "metrics", "guidance"})


def engine_grammar_rows(grammars: Any) -> tuple[dict, ...]:
    """The grammar rows as the engine needs them: no event-model presentation."""
    return tuple({k: v for k, v in g.items() if k not in PRESENTATION_KEYS} for g in grammars)


def render(data: dict, rows: list[dict]) -> str:
    families = data.get("families") or {}
    fidelity = {n: f["fidelity_status"] for n, f in families.items()
                if f.get("fidelity_status") is not None}
    runtime = [r for r in rows if r["lane"] in RUNTIME_LANES]
    # The engine never writes the event model (title, metrics, guidance: Stage B does), so
    # its module carries the grammar rows without them. They are outside the digest either
    # way (rule_model._PACK_CLAIM_KEYS); `engine_grammar_rows` keeps the image small.
    grammars = engine_grammar_rows(data.get("_pack_grammars") or ())
    envelopes = tuple(data.get("_pack_envelopes") or ())
    baked = rules_hash((compile_rule(r) for r in runtime),
                       pack_digest(grammars, envelopes))
    parts = [HEADER.format(
        parser_rev=str(data.get("parser_rev") or ""),
        fidelity=pprint.pformat(fidelity, width=76, sort_dicts=False),
        grammars=pprint.pformat(grammars, width=150, sort_dicts=False),
        envelopes=pprint.pformat(envelopes, width=150, sort_dicts=False),
    )]
    for row in runtime:
        body = pprint.pformat(row, width=150, sort_dicts=False, indent=1)
        parts.append("    " + body.replace("\n", "\n    ") + ",\n")
    parts.append(FOOTER.format(baked=baked))
    return "".join(parts)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the checked-in module is stale (CI guard)")
    ap.add_argument("--out", default=TARGET)
    ap.add_argument("--packs-dir", default=PACKS_DIR,
                    help="vendor-pack directory (a test bakes a synthetic one)")
    args = ap.parse_args(argv)
    try:
        data, rows = load(packs_dir=args.packs_dir)
    except BakeError as exc:
        print(f"events.yaml INVALID: {exc}", file=sys.stderr)
        return 2
    text = render(data, rows)
    if args.check:
        try:
            with open(args.out, encoding="utf-8") as fh:
                current = fh.read()
        except FileNotFoundError:
            print(f"{args.out} does not exist — run bake_rules.py", file=sys.stderr)
            return 1
        if current != text:
            print(f"{args.out} is STALE vs events.yaml — run "
                  "`python3 telemetry-catalog/bake_rules.py`", file=sys.stderr)
            return 1
        n_rt = sum(1 for r in rows if r["lane"] in RUNTIME_LANES)
        print(f"OK: {args.out} matches events.yaml ({n_rt} runtime rules, "
              f"{len(rows) - n_rt} catalog-only)")
        return 0
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {args.out} ({len(rows)} rules, "
          f"{sum(1 for r in rows if r['lane'] in RUNTIME_LANES)} runtime)")
    return 0


if __name__ == "__main__":       # pragma: no cover - CLI
    raise SystemExit(main())
