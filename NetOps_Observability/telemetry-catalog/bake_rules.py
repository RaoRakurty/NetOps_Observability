#!/usr/bin/env python3
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
import sys
from typing import Any

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
EVENTS = os.path.join(HERE, "events.yaml")
TARGET = os.path.abspath(
    os.path.join(HERE, "..", "src", "correlation", "parser_rules.py"))

# The rule model lives with the code it drives; importing it here is what
# guarantees the bake validates against the SAME compiler the runtime uses.
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "src", "correlation")))

from rule_model import LANE_FIELDS, LANE_VARS, RuleError, compile_rule, rules_hash

LANES = ("syslog", "port", "trap", "catalog")
RUNTIME_LANES = ("syslog", "port", "trap")   # what the image actually ships
SOURCES = ("syslog", "trap")
SEVERITIES = ("info", "warn", "high", "crit")
ENTITY_TYPES = ("device", "interface", "device_or_interface")

ROW_KEYS = frozenset({
    "rule_id", "lane", "source", "kind", "entity_type", "family", "vendors",
    "markers", "pattern_src", "state", "state_re", "severity", "generic",
    "shadow", "guard", "extract", "emit",
})
ROW_REQUIRED = ("rule_id", "lane", "source", "kind", "entity_type", "guard", "emit")
EMIT_KEYS = frozenset({
    "kind", "metric", "modality", "entity", "severity", "native_id",
    "content_tag", "tokens", "tokens_fallback", "attrs",
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
    for k in ("generic", "shadow"):
        if k in row and not isinstance(row[k], bool):
            raise BakeError(f"{where}: {k} must be a boolean")
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


def load(path: str = EVENTS) -> tuple[dict, list[dict]]:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    unknown = sorted(set(data) - TOP_KEYS)
    if unknown:
        raise BakeError(f"events.yaml: unknown top-level key(s) {unknown}")
    if not str(data.get("parser_rev") or "").strip():
        raise BakeError("events.yaml: `parser_rev` is required — it is the "
                        "hand-bumped half of every signal's provenance")
    families = data.get("families") or {}
    rows = data.get("rules") or []
    seen: set[str] = set()
    for name, fam in families.items():
        validate_family(name, fam)
    for row in rows:
        validate_row(row, families, seen)
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

from rule_model import Rule, compile_rule, install_fidelity, rules_hash

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
RULES_HASH: str = rules_hash(RULES)
'''


def render(data: dict, rows: list[dict]) -> str:
    families = data.get("families") or {}
    fidelity = {n: f["fidelity_status"] for n, f in families.items()
                if f.get("fidelity_status") is not None}
    runtime = [r for r in rows if r["lane"] in RUNTIME_LANES]
    baked = rules_hash(compile_rule(r) for r in runtime)
    parts = [HEADER.format(
        parser_rev=str(data.get("parser_rev") or ""),
        fidelity=pprint.pformat(fidelity, width=76, sort_dicts=False),
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
    args = ap.parse_args(argv)
    try:
        data, rows = load()
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
