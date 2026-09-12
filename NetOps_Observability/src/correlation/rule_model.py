# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The executable form of a telemetry-catalog parser rule (A3).

WHAT THIS IS. `telemetry-catalog/events.yaml` is the SINGLE SOURCE OF TRUTH for
how a syslog line / SNMP trap becomes a canonical event. Until A3 that file was
a *spec* that `producers.py` mirrored by hand: every family had a hand-written
`if` branch, and the two could drift silently (they did — see `target_scope`).
A3 makes the catalog row the rule the parser actually EXECUTES:

    events.yaml  --bake_rules.py-->  parser_rules.py (generated, checked in)
                                           |
                                           v
                                     producers.classify()   (this model)
                                     parse_events.parse()   (the catalog's own
                                                             conformance reader)

This module is the MODEL + INTERPRETER half: the `Rule` dataclass, a small,
closed DSL for guards / extractions / emission, and a compiler that turns the
YAML forms into closures ONCE at import. It knows nothing about Signals, lanes
or Kafka — `producers.py` owns that — so the catalog's own tooling can import it
without dragging the engine in.

DESIGN CONSTRAINTS (all of them load-bearing):

  * ORDER IS BEHAVIOUR. Rules are evaluated in table order, first match wins,
    exactly like the `if`/`elif` chain they replace. `rules_hash` covers the
    order for that reason.
  * COMPILE ONCE. Every regex, guard tree, template and token spec is compiled
    at import. The hot path does closure calls and dict lookups, never a
    `re.compile` or a spec walk. Parsing is on the ingest hot path (measured at
    35 us/line for the control lane) — the interpreter must not be a tax.
  * LAZY EXTRACTION. A rule row carries every field ANY consumer needs — the
    producer's `attrs`, and the catalog's canonical labels, which are not the
    same set. Extractions are therefore evaluated on demand and memoized per
    event, so the producer never pays for a regex only the catalog reads.
  * NO EVAL, NO CODEGEN AT RUNTIME. The compiler builds closures out of a fixed
    set of node types; an unknown node is a hard error at import, never a
    silently-skipped guard (a skipped guard is a misclassification).
  * UNTRUSTED INPUT (§3). Every field the DSL reads is a device-supplied string.
    Patterns come from the repo, never from the event.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from regex_screen import pattern_screen
from signals import Severity

__all__ = [
    "MISS", "Ctx", "Rule", "RuleError", "compile_guard", "compile_rule",
    "read_var", "rules_hash",
]


class RuleError(ValueError):
    """A malformed rule row. Raised at BAKE/IMPORT time, never per event."""


# ── flags ────────────────────────────────────────────────────────────────────
#
# Spelled out per pattern instead of defaulted, because several of the migrated
# grammars are deliberately case-SENSITIVE (`[Ii]nterface\s+(...)`, the bare
# `Gi|Te|Fa|Po` port shapes, the `MST\d` instance) and a silent IGNORECASE would
# widen them. "" = no flags, "i" = IGNORECASE.
_FLAGS: dict[str, int] = {"": 0, "i": re.IGNORECASE}


def _flags_of(spec: str) -> int:
    try:
        return _FLAGS[spec]
    except KeyError:                                    # pragma: no cover - guard
        raise RuleError(f"unknown regex flag spec {spec!r} (want '' or 'i')") from None


# ── evaluation context ───────────────────────────────────────────────────────


class _Sentinel:
    __slots__ = ()


_MISS = MISS = _Sentinel()
_COMPUTING = _Sentinel()


def read_var(c: Ctx, name: str) -> Any:
    """A var read with the memo hit INLINED.

    `Ctx.var` is the general path (compute-on-first-read); every var a rule
    emits is read three to five times — by the entity id, the native id, the
    tokens and the attrs — and after the first read they are all dict hits. This
    saves the second method call on each of them, which is worth ~15 % of the
    trap lane.
    """
    memo = c.vars
    return memo[name] if name in memo else c.var(name)

#: Fields DERIVED on first use rather than built by the lane — `.upper()` on a
#: 2 KB device string is not free and only a few rules read them.
LAZY_FIELDS = frozenset({"msg_u", "ctoken_msg_u"})

#: The vars each lane SEEDS into the context before any extraction runs. A rule
#: may read them; it may NOT declare an extraction of the same name — the seeded
#: value would win and the grammar would silently never run. The bake refuses it.
LANE_VARS: dict[str, frozenset[str]] = {
    "syslog": frozenset({"host", "ts_ms", "tag", "msg"}),
    "catalog": frozenset({"host", "ts_ms", "tag", "msg"}),
    "port": frozenset({"host", "ts_ms", "msg"}),
    "trap": frozenset({"device", "ts_ms", "oid", "name", "etype", "authed"}),
}

#: The haystacks each lane provides. Declared here so the bake can REFUSE a rule
#: that reads a field its lane never builds — otherwise the mistake would only
#: surface as a KeyError on a production line, which is the worst place to find
#: it. (It also lets the compiler inline `c.base[field]` with no guard: the
#: field is known to exist.)
LANE_FIELDS: dict[str, frozenset[str]] = {
    "syslog": frozenset({"msg", "msg_u", "tag", "ctoken", "ctoken_msg_u"}),
    "catalog": frozenset({"msg", "msg_u", "tag", "ctoken", "ctoken_msg_u"}),
    "port": frozenset({"pctoken", "msg"}),
    "trap": frozenset({"oid", "name", "etype"}),
}


class Ctx:
    """One event, mid-classification: the lane's haystacks + memoized vars.

    `base` holds the fields the lane computed eagerly (they are read by almost
    every rule); `msg_u` and `ctoken_msg_u` are derived here on first use, since
    only a few rules read them and `.upper()` on a 2 KB device string is not
    free. `vars` memoizes extractions for the CURRENT rule only — `enter()`
    clears it, because two rules may name the same var with different grammars.
    """

    __slots__ = ("_sev", "_sev_done", "base", "catalog", "lane_fns", "lane_vars",
                 "sev_fn", "specs", "vars")

    def __init__(
        self,
        base: dict[str, Any],
        lane_vars: dict[str, Any],
        sev_fn: Callable[[Ctx], int | None],
        lane_fns: Mapping[str, Callable[[Ctx], Any]] | None = None,
        *,
        catalog: bool = False,
    ) -> None:
        self.base = base
        self.lane_vars = lane_vars
        # Lane callbacks take the Ctx rather than closing over the event, so a
        # lane can hand over a MODULE-LEVEL constant dict and allocate nothing
        # per event.
        self.lane_fns: Mapping[str, Callable[[Ctx], Any]] = lane_fns or {}
        self.sev_fn = sev_fn
        self._sev: int | None = None
        self._sev_done = False
        # `catalog` selects the CONFORMANCE reading of a rule wherever the
        # executable parser and the canonical-event spec are known to diverge
        # (`scan.target_scope: catalog`). Exactly one such divergence exists and
        # it is pinned by a test — see events.yaml, bgp_adjacency_change.
        self.catalog = catalog
        # Shared, not copied, until a rule matches: `enter` takes the copy, so
        # a line that classifies as nothing never pays for one.
        self.vars: dict[str, Any] = lane_vars
        self.specs: Mapping[str, Callable[[Ctx], Any]] = {}

    def enter(self, specs: Mapping[str, Callable[[Ctx], Any]]) -> None:
        """Bind the extraction table of the rule now being evaluated.

        The lane vars (host/device, ts_ms, tag, msg, …) are SEEDED into the same
        dict as the memoized extractions so a var read is one dict lookup rather
        than a miss-then-fallback. Cleared per rule because two rules may name
        the same var with different grammars.
        """
        self.specs = specs
        self.vars = dict(self.lane_vars)

    def field(self, name: str) -> str:
        base = self.base
        if name in base:
            v = base[name]
            if v is not None:
                return v
        if name == "msg_u":
            v = str(self.base.get("msg", "")).upper()
        elif name == "ctoken_msg_u":
            v = str(self.base.get("ctoken", "")) + " " + self.field("msg_u")
        else:                                           # pragma: no cover - guard
            raise RuleError(f"rule reads unknown field {name!r}")
        self.base[name] = v
        return v

    def var(self, name: str) -> Any:
        """A lane var or a memoized extraction, computed on first read.

        `in` + `[]` rather than `.get(name, _MISS)`: `.get` is a bound-method
        CALL and this is the commonest read on the ingest hot path — measured
        90 -> 64 ns on a hit and 74 -> 41 ns on a miss (tracker 234).
        `try: memo[name] except KeyError` is cheaper still on a hit but 3.5x
        DEARER on a miss, which is exactly what an extraction's first read is.
        `_COMPUTING` doubles as the cycle guard — a spec that reads itself finds
        the sentinel.
        """
        memo = self.vars
        if name in memo:
            v = memo[name]
            if v is _COMPUTING:                         # pragma: no cover - guard
                raise RuleError(f"cyclic extraction for var {name!r}")
            return v
        # SUBSCRIPT, not `.get`: the spec table is bound per rule and every var
        # a rule reads is declared in it, so this lookup always hits — and a
        # bound-method call per var is not free on the ingest hot path (tracker
        # 234). The miss is still a hard error, just raised from the KeyError.
        try:
            spec = self.specs[name]
        except KeyError:                                # pragma: no cover - guard
            raise RuleError(f"rule reads undeclared var {name!r}") from None
        self.vars[name] = _COMPUTING
        val = spec(self)
        self.vars[name] = val
        return val

    def sev(self) -> int | None:
        """The event's severity number, already tested against the anti-firehose
        floor (None = no severity, or below the floor). Computed at most once —
        it is read by the generic-alarm guard AND by its emission."""
        if not self._sev_done:
            self._sev = self.sev_fn(self)
            self._sev_done = True
        return self._sev

    def text(self, ref: str) -> str:
        """A guard/extraction operand: `$name` = a var, anything else a field."""
        if ref.startswith("$"):
            v = self.var(ref[1:])
            return v if isinstance(v, str) else ("" if v is None else str(v))
        return self.field(ref)


Guard = Callable[[Ctx], bool]
Extractor = Callable[[Ctx], Any]


# ── guards ───────────────────────────────────────────────────────────────────


def _one_key(node: Any, what: str) -> tuple[str, Any]:
    if not isinstance(node, dict) or len(node) != 1:
        raise RuleError(f"{what} must be a single-key mapping, got {node!r}")
    return next(iter(node.items()))


def _reader(ref: str) -> Callable[[Ctx], str]:
    """An operand accessor, resolved ONCE at import.

    Deciding "field or `$var`?" per event, on every guard of every rule, is pure
    interpreter tax on the ingest hot path — so the branch is taken here and the
    closure that survives does one dict lookup.
    """
    if ref.startswith("$"):
        name = ref[1:]
        def _var(c: Ctx) -> str:
            memo = c.vars
            v = memo[name] if name in memo else c.var(name)
            if v.__class__ is str:      # the case, for every extraction today
                return v
            return v if isinstance(v, str) else ("" if v is None else str(v))
        return _var
    if ref in LAZY_FIELDS:
        return lambda c: c.field(ref)
    # An eagerly built haystack: one dict index, no method call. `LANE_FIELDS`
    # is what makes that safe — the bake refuses a rule that reads a field its
    # lane does not build.
    return lambda c: c.base[ref]


def _eager(ref: str) -> bool:
    """Is this operand a haystack the lane BUILT, readable with one dict index?

    False for a `$var` (an extraction, resolved through the memo) and for a lazy
    field (`msg_u`, derived on first use) — both need the general reader.
    """
    return not ref.startswith("$") and ref not in LAZY_FIELDS


#: Prefix of the key a screened `re` guard caches its lower-cased haystack
#: under. A private name (not a lane field) so it can never collide with one the
#: catalog declares, and it lives in `base` so the TWELVE port rules that all
#: read `pctoken` fold it once per event rather than once per rule.
_LOW = "\x00low:"

#: A literal screen only pays for itself when its literals are SELECTIVE. Both
#: bounds are the shipped table's own numbers: the interface-name pattern
#: screens to {gi, po, te, fa}, two characters each, which passes nearly every
#: line and so would be pure added work — while the nine port patterns the
#: screen does take have literals of four characters or more.
_SCREEN_MIN_LITERAL = 4
_SCREEN_MAX_LITERALS = 8


def _screen_of(pattern: str) -> tuple[str, ...] | None:
    """A SOUND set of literals a match must contain, or None for no screen.

    `regex_screen.pattern_screen` is the soundness argument (it is the same
    derivation the ingest prefilter is built from): the screen may pass a line
    the regex then rejects, and must NEVER reject one the regex would match.
    Anything it cannot read returns None and the guard keeps running the regex
    on every line — failing OPEN costs microseconds, failing closed would drop
    a signal.

    Screening is worth doing because the port lane's twelve guards are
    alternations with bounded gaps (`A|B[^\n]{0,80}C`), the one shape CPython's
    `re` cannot answer with its literal prescan: it walks the string per
    alternative. Measured over the golden corpus the twelve of them are 53 of
    `port_event_signal`'s 67 us/event (tracker 234).
    """
    lits = pattern_screen(pattern)
    if lits is None or len(lits) > _SCREEN_MAX_LITERALS:
        return None
    if min(len(lit) for lit in lits) < _SCREEN_MIN_LITERAL:
        return None
    # Longest first: the most selective literal decides the common case.
    return tuple(sorted(lits, key=len, reverse=True))


_CONTAINS, _EQ, _IN = 0, 1, 2


def _fused_contains(nodes: Any) -> tuple[tuple[int, str, Any], ...] | None:
    """A homogeneous `any`/`all` of simple EAGER-field tests → one flat table.

    The marker pre-check is the hottest thing the parser does — every rule of a
    lane runs it on every admitted line — and a tree of one-literal closures
    costs a Python call per literal. Fusing a homogeneous `any`/`all` into ONE
    closure with an inline loop is worth roughly a third of the guard cost.
    Returns None (no fusion, keep the general tree) for anything else.
    """
    if not isinstance(nodes, (list, tuple)):
        return None
    out: list[tuple[int, str, Any]] = []
    for n in nodes:
        if not isinstance(n, dict) or len(n) != 1:
            return None
        op, arg = next(iter(n.items()))
        if op not in ("contains", "eq", "equals_any"):
            return None
        if not isinstance(arg, (list, tuple)) or len(arg) != 2:
            return None
        fld = str(arg[0])
        if fld.startswith("$") or fld in LAZY_FIELDS:
            return None
        if op == "contains":
            out.append((_CONTAINS, fld, str(arg[1])))
        elif op == "eq":
            out.append((_EQ, fld, str(arg[1])))
        else:
            out.append((_IN, fld, frozenset(str(v) for v in arg[1])))
    return tuple(out) or None


def _fused_groups(
    nodes: Any, inner: str,
) -> tuple[tuple[tuple[int, str, Any], ...], ...] | None:
    """A TWO-LEVEL homogeneous tree of eager leaf tests → a table of groups.

    `all` whose children are each either a bare leaf or an `any` of them (and
    the `any`/`all` dual) is the commonest NESTED guard shape in the table —
    thirteen of the thirty shipped rules, all of them the "marker AND one of
    these protocol tokens" pre-check that every rule of a lane runs on every
    admitted line. Compiled as a tree that is a Python call per node PLUS one
    per leaf; as a group table it is one call and two inline loops.

    Equivalence is structural, not incidental: a group is the inner node's
    operand list in declaration order, the groups are the outer node's in
    declaration order, and the loops short-circuit exactly where the tree does
    (`all` stops at the first failing group, `any` at the first satisfied one).
    A bare leaf becomes a one-element group, which the same loops evaluate
    identically. Returns None the moment any leaf is not one `_fused_contains`
    accepts, so a lazy field or a `$var` never reaches the flat form.
    """
    if not isinstance(nodes, (list, tuple)) or len(nodes) < 2:
        return None
    groups: list[tuple[tuple[int, str, Any], ...]] = []
    nested = False
    for n in nodes:
        if not isinstance(n, dict) or len(n) != 1:
            return None
        op, arg = next(iter(n.items()))
        if op == inner:
            table = _fused_contains(arg)
            nested = True
        else:
            table = _fused_contains((n,))
        if table is None:
            return None
        groups.append(table)
    # Nothing nested = the FLAT fusion already handles it, with one loop.
    return tuple(groups) if nested else None


def compile_guard(node: Any) -> Guard:
    """A guard-tree node → a closure. Every node type is enumerated here; an
    unrecognized one raises rather than evaluating to False (a guard that
    silently never fires is a deleted branch nobody noticed).

    The closures avoid generator expressions on purpose: `all(g(c) for g in ...)`
    allocates a generator per evaluation, and these run once per rule per line.
    """
    op, arg = _one_key(node, "guard")

    if op == "all":
        fused = _fused_contains(arg)
        if fused is not None:
            table = fused
            def _all_contains(c: Ctx) -> bool:
                base = c.base
                # The kind test is written INTO the loop rather than
                # dispatched through a helper: a call per leaf was the single
                # commonest call in either lane (tracker 234).
                for kind, fld, val in table:
                    text = base[fld]
                    if kind == _CONTAINS:
                        if val not in text:
                            return False
                    elif kind == _EQ:
                        if text != val:
                            return False
                    elif text not in val:
                        return False
                return True
            return _all_contains
        groups = _fused_groups(arg, "any")
        if groups is not None:
            gtable = groups
            # all(any(leaf...), leaf, ...) — the first group that admits NO leaf
            # ends the walk, exactly as the tree's first false child does.
            def _all_of_any(c: Ctx) -> bool:
                base = c.base
                for group in gtable:
                    for kind, fld, val in group:
                        text = base[fld]
                        if (val in text if kind == _CONTAINS else
                                text == val if kind == _EQ else text in val):
                            break
                    else:
                        return False
                return True
            return _all_of_any
        subs = tuple(compile_guard(n) for n in arg)
        def _all(c: Ctx) -> bool:
            for g in subs:
                if not g(c):
                    return False
            return True
        return _all
    if op == "any":
        fused = _fused_contains(arg)
        if fused is not None:
            table = fused
            def _any_contains(c: Ctx) -> bool:
                base = c.base
                for kind, fld, val in table:        # see _all_contains
                    text = base[fld]
                    if kind == _CONTAINS:
                        if val in text:
                            return True
                    elif kind == _EQ:
                        if text == val:
                            return True
                    elif text in val:
                        return True
                return False
            return _any_contains
        groups = _fused_groups(arg, "all")
        if groups is not None:
            gtable = groups
            # any(all(leaf...), leaf, ...) — the first group whose leaves ALL
            # hit ends the walk, exactly as the tree's first true child does.
            def _any_of_all(c: Ctx) -> bool:
                base = c.base
                for group in gtable:
                    for kind, fld, val in group:
                        text = base[fld]
                        if not (val in text if kind == _CONTAINS else
                                text == val if kind == _EQ else text in val):
                            break
                    else:
                        return True
                return False
            return _any_of_all
        subs = tuple(compile_guard(n) for n in arg)
        def _any(c: Ctx) -> bool:
            for g in subs:
                if g(c):
                    return True
            return False
        return _any
    if op == "not":
        sub = compile_guard(arg)
        return lambda c: not sub(c)
    if op == "always":
        fixed = bool(arg)
        return lambda c: fixed
    # Every leaf below reads ONE operand. When that operand is a haystack the
    # lane built eagerly, the read is a dict index and the closure does it
    # itself; going through `_reader` would cost a second Python call per leaf
    # per rule per line — 8 per syslog line measured over the golden corpus
    # (tracker 234). `$var` and lazy-field operands keep the general reader.
    if op == "contains":
        ref, lit = str(arg[0]), str(arg[1])
        if _eager(ref):
            return lambda c: lit in c.base[ref]      # the hot path, fused
        if ref in LAZY_FIELDS:                       # derived on first use
            return lambda c: lit in c.field(ref)
        read = _reader(ref)
        return lambda c: lit in read(c)
    if op == "re":
        ref, pat = str(arg[0]), str(arg[1])
        rx = re.compile(pat, _flags_of(arg[2] if len(arg) > 2 else ""))
        search = rx.search
        if _eager(ref):
            lits = _screen_of(pat)
            if lits is None:
                return lambda c: search(c.base[ref]) is not None
            low_key = _LOW + ref
            def _re_screened(c: Ctx) -> bool:
                # The screen is a NECESSARY condition, so a miss is a decided
                # False; a hit still has to run the regex.
                base = c.base
                if low_key in base:
                    low = base[low_key]
                else:
                    low = base[ref].lower()
                    base[low_key] = low
                for lit in lits:
                    if lit in low:
                        return search(base[ref]) is not None
                return False
            return _re_screened
        read = _reader(ref)
        return lambda c: search(read(c)) is not None
    if op == "eq":
        ref, want = str(arg[0]), str(arg[1])
        if _eager(ref):
            return lambda c: c.base[ref] == want
        read = _reader(ref)
        return lambda c: read(c) == want
    if op == "ne":
        ref, unwanted = str(arg[0]), str(arg[1])
        if _eager(ref):
            return lambda c: c.base[ref] != unwanted
        read = _reader(ref)
        return lambda c: read(c) != unwanted
    if op == "equals_any":
        ref, vals = str(arg[0]), frozenset(str(v) for v in arg[1])
        if _eager(ref):
            return lambda c: c.base[ref] in vals
        read = _reader(ref)
        return lambda c: read(c) in vals
    if op == "not_in":
        ref, vals = str(arg[0]), frozenset(str(v) for v in arg[1])
        if _eager(ref):
            return lambda c: c.base[ref] not in vals
        read = _reader(ref)
        return lambda c: read(c) not in vals
    if op == "truthy":
        ref = str(arg)
        if _eager(ref):
            return lambda c: bool(c.base[ref])
        read = _reader(ref)
        return lambda c: bool(read(c))
    if op == "var_true":
        name = str(arg)
        return lambda c: bool(c.var(name))
    if op == "severity_floor":
        # The anti-firehose floor. Deliberately a CALLBACK into the lane rather
        # than a baked constant: main.py may lower/raise ALARM_SEVERITY_FLOOR
        # from the environment at startup, and a rule that had baked the number
        # would ignore it.
        return lambda c: c.sev() is not None
    raise RuleError(f"unknown guard op {op!r}")


# ── templates ────────────────────────────────────────────────────────────────

_TPL_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?:\|([^}]*))?\}")


def compile_template(tpl: str) -> tuple[Callable[[Ctx], str], tuple[str, ...]]:
    """`"{host}|link|{ifname|-}"` → (renderer, referenced var names).

    `{name}` interpolates the var; `{name|D}` substitutes D when it is empty.
    The var list is returned because the token spec needs it: a token whose
    vars are all-empty is DROPPED rather than rendered into a stub like
    `vlan` with no number (that stub was a real cross-device grounding weld —
    tracker 168).
    """
    parts: list[tuple[str, str, str]] = []   # (literal, var, default)
    names: list[str] = []
    pos = 0
    for m in _TPL_RE.finditer(tpl):
        parts.append((tpl[pos:m.start()], str(m.group(1)), m.group(2) or ""))
        names.append(m.group(1))
        pos = m.end()
    tail = tpl[pos:]

    if not parts:                       # a constant (no placeholders at all)
        return (lambda c: tail), ()
    if len(parts) == 1 and not parts[0][0] and not tail:
        # `"{peer}"` / `"{host}"` — by far the commonest token shape.
        only, dflt = parts[0][1], parts[0][2]

        def render_one(c: Ctx) -> str:
            memo = c.vars
            v = memo[only] if only in memo else c.var(only)
            if v.__class__ is str:
                return v or dflt
            s_ = "" if v is None else (v if isinstance(v, str) else str(v))
            return s_ or dflt
        return render_one, tuple(names)

    def render(c: Ctx) -> str:
        # Straight concatenation, not list+join: these templates are 2-5
        # placeholders long and the list machinery costs more than the copies.
        memo = c.vars
        out = ""
        for lit, name, dflt in parts:
            v = memo[name] if name in memo else c.var(name)
            if v.__class__ is str:
                # EXACT str is what every extraction returns; the general
                # coercion below is kept for the int/bool/None spellings the DSL
                # allows (and for a str SUBCLASS, which `__class__ is` misses).
                s = v
            else:
                s = "" if v is None else (v if isinstance(v, str) else str(v))
            out += lit + (s or dflt)
        return out + tail

    return render, tuple(names)


# ── extractions ──────────────────────────────────────────────────────────────


def _compile_extract_core(spec: Any) -> Extractor:
    op, arg = _one_key(spec, "extraction")

    if op == "const":
        val = arg
        return lambda c: val
    if op == "field":
        return _reader(str(arg))
    if op == "var":
        # The RAW value of another var (bool / int / list survive un-stringified;
        # `field: $x` would coerce them to text).
        name = str(arg)
        def _read(c: Ctx) -> Any:
            memo = c.vars
            return memo[name] if name in memo else c.var(name)
        return _read
    if op == "lane":
        # A value only the lane can compute (the trap content rendering). Kept
        # behind the same lazy `var` machinery, so a lane that never needs it
        # never pays for it.
        name = str(arg)
        return lambda c: c.lane_fns[name](c)
    if op == "vb":
        # First SNMP varbind whose OID equals, or is indexed under, one of these
        # column OIDs (ifName.7 matches the ifName column).
        prefixes = tuple(str(p) for p in arg)
        def _vb(c: Ctx) -> str:
            ev = c.base["ev"]
            if "varbinds" not in ev:
                return ""
            for vb in ev["varbinds"] or ():
                if not isinstance(vb, dict):
                    continue
                oid = str(vb.get("oid") or "")
                for pre in prefixes:
                    if oid == pre or oid.startswith(pre + "."):
                        return str(vb.get("value") or "")
            return ""
        return _vb
    if op == "vbname":
        # First varbind whose MIB-RESOLVED name contains one of these substrings
        # — how a vendor's peer/interface column is found without hardcoding its
        # enterprise OID.
        subs = tuple(str(needle).lower() for needle in arg)
        def _vbname(c: Ctx) -> str:
            ev = c.base["ev"]
            if "varbinds" not in ev:
                return ""
            for vb in ev["varbinds"] or ():
                if not isinstance(vb, dict):
                    continue
                nm = str(vb.get("name") or "").lower()
                if nm:
                    for needle in subs:     # not `any(...)`: no generator frame
                        if needle in nm:
                            return str(vb.get("value") or "")
            return ""
        return _vbname
    if op == "pick":
        # Scan every match of `find`, DROP the ones `reject` matches (anchored),
        # keep the last survivor. This is the vendor "reason in parentheses":
        # Cisco trails "(afi 0)" and Junos "(External AS 65001)" alongside the
        # real reason, so first-match would pick bookkeeping.
        rx = re.compile(str(arg["find"][0]), _flags_of(arg["find"][1]))
        read = _reader(str(arg.get("field", "msg")))
        rej = re.compile(str(arg["reject"][0]), _flags_of(arg["reject"][1]))
        def _pick(c: Ctx) -> str:
            out = ""
            for cand in rx.findall(read(c)):
                if rej.match(cand):
                    continue
                out = cand
            return out
        return _pick
    if op == "ev":
        # Raw event keys, in preference order — the bus may carry a field under
        # several spellings. `base["ev"]` is the untrusted event dict itself.
        keys = tuple(str(k) for k in arg)
        def _ev(c: Ctx) -> str:
            ev = c.base["ev"]
            for k in keys:
                if k in ev:
                    v = ev[k]
                    if v:
                        return str(v)
            return ""
        return _ev
    if op == "re":
        # ordered alternatives: [field, pattern, group, flags]; first hit wins.
        alts = tuple(
            (_reader(a[0]), re.compile(str(a[1]), _flags_of(a[3] if len(a) > 3 else "")),
             int(a[2]) if len(a) > 2 else 1)
            for a in arg
        )
        def _re(c: Ctx) -> str:
            for read, rx, grp in alts:
                m = rx.search(read(c))
                if m:
                    return m.group(grp) or ""
            return ""
        return _re
    if op == "findall":
        ref, pat = str(arg[0]), str(arg[1])
        rx = re.compile(pat, _flags_of(arg[2] if len(arg) > 2 else ""))
        if _eager(ref):
            return lambda c: rx.findall(c.base[ref])
        read = _reader(ref)
        return lambda c: rx.findall(read(c))
    if op == "nth":
        src, idx = str(arg[0]), int(arg[1])
        def _nth(c: Ctx) -> str:
            seq = read_var(c, src)
            if isinstance(seq, list) and len(seq) > idx:
                return str(seq[idx])
            return ""
        return _nth
    if op == "alt":
        alts_ = tuple(_compile_extract_core(sub) for sub in arg)
        def _alt(c: Ctx) -> Any:
            for sub in alts_:
                v = sub(c)
                if v:
                    return v
            return ""
        return _alt
    if op == "bool":
        g = compile_guard(arg)
        return lambda c: bool(g(c))
    if op == "case":
        # Values are TEMPLATES, so a case can compose other vars ("{a}/{b}") as
        # well as name a literal (a value with no braces renders as itself).
        cases = tuple((compile_guard(k["when"]), compile_template(str(k["value"]))[0])
                      for k in arg)
        def _case(c: Ctx) -> Any:
            for g, render in cases:
                if g(c):
                    return render(c)
            return ""
        return _case
    if op == "template":
        render, _names = compile_template(str(arg))
        return render
    if op == "severity_num":
        return lambda c: c.sev()
    if op == "scan":
        # The state primitive. `target` (when it extracts anything) is the
        # TRANSITION TARGET and is classified on its own — a flap INTO
        # Established is an 'up' even though "old state Idle" carries a down
        # token. With no target the whole fallback field is scanned in
        # declaration order (down-beats-up is simply the order it is written).
        tgt = arg.get("target")
        tgt_order = tuple(
            (str(n), re.compile(str(p), _flags_of(f)))
            for n, p, f in arg.get("target_order", arg.get("order", ())))
        order = tuple(
            (str(n), re.compile(str(p), _flags_of(f)))
            for n, p, f in arg.get("order", ()))
        read = _reader(str(arg.get("field", "msg")))
        dflt = str(arg.get("default", "unknown"))
        # A target the EXECUTABLE parser deliberately does not consult; see the
        # `target_scope` note in events.yaml. `all` (the default) = both readers.
        catalog_only = str(arg.get("target_scope", "all")) == "catalog"
        # Whether an unclassifiable target falls back to scanning the whole
        # field (the catalog's `_state_of`) or settles for the default (the
        # producer's `_state_of(tgt)`).
        fallthrough = bool(arg.get("target_fallthrough"))

        def _scan(c: Ctx) -> str:
            if tgt and (c.catalog or not catalog_only):
                t = c.var(tgt)
                if t:
                    text = t if isinstance(t, str) else str(t)
                    for name, rx in tgt_order:
                        if rx.search(text):
                            return name
                    if not fallthrough:
                        return dflt
            text = read(c)
            for name, rx in order:
                if rx.search(text):
                    return name
            return dflt
        return _scan
    raise RuleError(f"unknown extraction op {op!r}")


def compile_extract(spec: Any) -> Extractor:
    """An extraction spec plus its optional post-transforms (`lower`, `slice`)."""
    if not isinstance(spec, dict):
        raise RuleError(f"extraction must be a mapping, got {spec!r}")
    core_keys = [k for k in spec if k not in ("lower", "slice")]
    core = _compile_extract_core({k: spec[k] for k in core_keys})
    lower = bool(spec.get("lower"))
    cut = spec.get("slice")
    if not lower and cut is None:
        return core
    n = int(cut) if cut is not None else 0

    def _post(c: Ctx) -> Any:
        v = core(c)
        if isinstance(v, str):
            if lower:
                v = v.lower()
            if n:
                v = v[:n]
        return v
    return _post


# ── emission ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TokenSpec:
    render: Callable[[Ctx], str]
    names: tuple[str, ...]
    local: bool
    #: The var name when the template is exactly one placeholder (`"{peer}"`),
    #: so the emitter can read it once instead of testing then rendering.
    single: str | None = None


@dataclass(frozen=True)
class Emit:
    """Everything needed to BUILD the output, compiled. Lane-agnostic: the
    producer turns this into a `Signal`, the catalog into a canonical event."""

    kind: str
    metric_name: str
    modality: str
    entity_type: str
    entity_id: Callable[[Ctx], str]
    entity_when: Guard | None
    entity_type_else: str
    entity_id_else: Callable[[Ctx], str] | None
    severity: Callable[[Ctx], Severity]
    native_id: Callable[[Ctx], str]
    content_tag: str | None
    tokens: tuple[TokenSpec, ...]
    #: The var name when the whole token list is one plain `{var}` entry — the
    #: shape of two thirds of the table (`tokens: [{t: '{host}'}]`).
    tokens_only: str | None
    tokens_fallback: str | None
    attrs: tuple[tuple[str, Extractor], ...]
    #: `attrs` split so the emitter can build the dict in ONE pass without a
    #: closure call per plain `{var: x}` entry — which is most of them. Order is
    #: preserved: `attr_plan` is the declared order with a var name or None.
    attr_plan: tuple[tuple[str, str | None, Extractor], ...] = ()
    #: Attr keys that are DROPPED when they extract to nothing (tracker 218).
    #:
    #: An optional varbind is not a field with an empty value — it is a field the
    #: device did not send, and the two must not read alike downstream. Emitting
    #: `admin_status: ''` would claim the agent reported an empty admin status;
    #: omitting the key says, honestly, that the trap carried no ifAdminStatus.
    #:
    #: It is also what keeps such an enrichment ADDITIVE: a rule that already
    #: ships gains the key only on the events that actually carry the varbind, so
    #: every event already classified keeps a byte-identical attrs dict — and
    #: therefore a byte-identical `native_id` and `signal_id`. Empty for every
    #: rule that declares none, which is the whole table but the two link rules,
    #: so the emitter's post-pass is one truthiness test on a slot.
    omit_empty: tuple[str, ...] = ()


_SEV_BY_NAME = {s.value: s for s in Severity}


def _compile_severity(spec: Any, fallback: Severity | None) -> Callable[[Ctx], Severity]:
    if spec is None:
        if fallback is None:
            raise RuleError("rule declares neither emit.severity nor severity")
        return lambda c: fallback
    if isinstance(spec, str):
        sev = _SEV_BY_NAME[spec]
        return lambda c: sev
    if "by_state" in spec:
        table = {str(k): _SEV_BY_NAME[v] for k, v in spec["by_state"].items()}
        dflt = _SEV_BY_NAME[spec.get("default", "warn")]
        var = str(spec.get("var", "state"))
        return lambda c: table.get(str(c.var(var)), dflt)
    if "case" in spec:
        cases = tuple((compile_guard(k["when"]), _SEV_BY_NAME[k["value"]])
                      for k in spec["case"])
        dflt = _SEV_BY_NAME[spec.get("default", "warn")]
        def _case(c: Ctx) -> Severity:
            for g, sev in cases:
                if g(c):
                    return sev
            return dflt
        return _case
    if "from_severity_num" in spec:
        # RFC5424 numeric → the canonical ladder (emerg/alert/crit → CRIT,
        # err → HIGH, warning → WARN; below the floor never reaches here).
        def _num(c: Ctx) -> Severity:
            n = c.sev()
            if n is None:                               # pragma: no cover - guard
                return Severity.WARN
            if n <= 2:
                return Severity.CRIT
            if n == 3:
                return Severity.HIGH
            return Severity.WARN
        return _num
    raise RuleError(f"unknown severity spec {spec!r}")


_DEFAULT_ENTITY = {"type": "device", "id": "{host}"}


def _compile_emit(spec: Any, fallback_sev: Severity | None) -> Emit:
    # `entity` / `native_id` / `metric` are meaningless for a catalog-lane row
    # (it never becomes a Signal), so they default rather than being repeated.
    ent: dict[str, Any] = spec.get("entity") or _DEFAULT_ENTITY
    ent_else: dict[str, Any] | None = ent.get("else")
    tokens: list[TokenSpec] = []
    for t in spec.get("tokens", ()):
        tpl = str(t["t"])
        render, names = compile_template(tpl)
        single = names[0] if (len(names) == 1 and tpl == "{" + names[0] + "}") else None
        tokens.append(TokenSpec(render, names, bool(t.get("local")), single))
    native_render, _ = compile_template(str(spec.get("native_id", "")))
    attrs = tuple((str(k), compile_extract(v))
                  for k, v in spec.get("attrs", {}).items())
    omit_empty = tuple(str(k) for k in spec.get("omit_empty", ()))
    declared = {k for k, _fn in attrs}
    for k in omit_empty:
        if k not in declared:
            raise RuleError(
                f"emit.omit_empty names {k!r}, which the rule does not emit — "
                "a key that is never built cannot be conditionally dropped")
    id_render, _ = compile_template(str(ent["id"]))
    return Emit(
        kind=str(spec["kind"]),
        metric_name=str(spec.get("metric", "")),
        modality=str(spec.get("modality", "control_plane")),
        entity_type=str(ent["type"]),
        entity_id=id_render,
        entity_when=compile_guard(ent["when"]) if "when" in ent else None,
        entity_type_else=str(ent_else["type"]) if ent_else else "",
        entity_id_else=compile_template(str(ent_else["id"]))[0] if ent_else else None,
        severity=_compile_severity(spec.get("severity"), fallback_sev),
        native_id=native_render,
        content_tag=str(spec["content_tag"]) if spec.get("content_tag") else None,
        tokens=tuple(tokens),
        tokens_only=(tokens[0].single
                     if len(tokens) == 1 and not tokens[0].local
                     and tokens[0].single else None),
        tokens_fallback=str(spec["tokens_fallback"]) if spec.get("tokens_fallback") else None,
        attrs=attrs,
        attr_plan=tuple(
            (k, (raw["var"] if isinstance(raw, dict) and set(raw) == {"var"}
                 else None), fn)
            for (k, fn), raw in zip(attrs, spec.get("attrs", {}).values())),
        omit_empty=omit_empty,
    )


# ── the rule ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Rule:
    """One classified branch of the parser, as DATA — now the branch ITSELF.

    Fields split three ways:
      * IDENTITY / provenance (`rule_id`, `lane`, `source`, `kind`, …) — the
        stable metric label and the input to `rules_hash`;
      * SCREEN contract (`markers`, `pattern_src`) — what the ingest pre-filter
        must let through for this rule to be reachable;
      * EXECUTION (`guard_src`, `extract_src`, `emit_src`) — the catalog rows,
        compiled to closures in `__post_init__`.

    The execution half is compiled ONCE, at import: `guard`, `extract` and
    `emit` are the compiled forms and are excluded from equality/repr so two
    rules baked from the same YAML compare equal.
    """

    rule_id: str
    lane: str                          # "syslog" | "port" | "trap" | "catalog"
    source: str                        # wire Source value: "syslog" | "trap"
    kind: str                          # the emitted Signal kind
    entity_type: str                   # "device" | "interface" | "device_or_interface"
    state: str | None = None           # the fixed state, when the rule has one
    state_re: str | None = None        # the regex the rule derives state with
    vendors: tuple[str, ...] = ()      # vendor grammars the rule targets
    markers: tuple[str, ...] = ()      # classification-token literals its guard tests
    pattern_src: str | None = None     # message regex its guard tests (source text)
    flags: int = re.IGNORECASE         # flags `pattern_src` is compiled with
    fidelity_key: str | None = None    # telemetry-catalog events.yaml family
    #: A9 — a ROW-LEVEL fidelity claim, for a rule whose symptom is already a
    #: catalog family but whose OWN grammar is evidenced differently from the
    #: family's other rules. A trap rule for a symptom the syslog rules also
    #: carry is exactly that case: promoting the shared FAMILY would restate the
    #: syslog grammar's evidence, which the trap capture says nothing about. When
    #: set it WINS over the family lookup; when absent nothing changes.
    fidelity_status: str | None = None
    severity: Severity | None = None   # the fixed severity, when the rule has one
    generic: bool = False              # the unclassified safety net
    shadow: bool = False               # evaluated + counted, emits NOTHING (A8)
    guard_src: Any = None
    extract_src: Any = field(default=None, repr=False)
    emit_src: Any = field(default=None, repr=False)
    pattern: re.Pattern | None = field(default=None, compare=False, repr=False)
    guard: Guard | None = field(default=None, compare=False, repr=False)
    #: True when the guard reads an extracted `$var` (and therefore needs the
    #: extraction table bound BEFORE it runs). False for every rule today, which
    #: is what lets the interpreter bind extractions once, on the match, instead
    #: of once per rule per line.
    guard_reads_vars: bool = field(default=False, compare=False, repr=False)
    extract: Mapping[str, Extractor] = field(
        default_factory=dict, compare=False, repr=False)
    emit: Emit | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "guard_reads_vars", _reads_vars(self.guard_src))
        if self.pattern_src is not None:
            object.__setattr__(self, "pattern",
                               re.compile(self.pattern_src, self.flags))
        if self.guard_src is not None:
            object.__setattr__(self, "guard", compile_guard(self.guard_src))
        if self.extract_src:
            object.__setattr__(self, "extract", {
                k: compile_extract(v) for k, v in self.extract_src.items()})
        if self.emit_src is not None:
            object.__setattr__(self, "emit",
                               _compile_emit(self.emit_src, self.severity))

    @property
    def fidelity(self) -> str:
        # Resolved by the owning module (producers) against the baked catalog
        # fidelity map; kept here only so `Rule` stays self-describing. A
        # row-level `fidelity_status` (A9) is the rule's OWN claim and wins over
        # the family's — see the field's note.
        if self.fidelity_status:
            return self.fidelity_status
        return _FIDELITY.get(self.fidelity_key or "", FIDELITY_UNCATALOGUED)

    def digest_fields(self) -> tuple[str, ...]:
        """Everything that MAKES this rule — the input to `rules_hash`.

        `fidelity` is deliberately absent (both the family lookup and the
        row-level `fidelity_status`): it is the catalog's claim about the
        grammar, not the grammar. A catalog promotion must not read as a parser
        edit. `guard_src` / `extract_src` / `emit_src` ARE included — they are
        now the branch body, and an edit to them IS a parser edit.
        """
        return (
            self.rule_id, self.lane, self.source, self.kind, self.entity_type,
            self.state or "", self.state_re or "", ",".join(self.vendors),
            ",".join(self.markers), self.pattern_src or "", str(self.flags),
            self.fidelity_key or "",
            self.severity.value if self.severity is not None else "",
            "1" if self.generic else "0",
            "1" if self.shadow else "0",
            _canon(self.guard_src), _canon(self.extract_src), _canon(self.emit_src),
        )


# The fidelity ladder snapshot, installed by the generated module. A module
# global rather than a Rule field because it is a property of the CATALOG, not
# of the rule, and must not enter `rules_hash` (see `digest_fields`).
FIDELITY_UNCATALOGUED = "code"
_FIDELITY: Mapping[str, str] = {}


def install_fidelity(table: Mapping[str, str]) -> None:
    """Bind the baked `events.yaml` fidelity map (called by `parser_rules`).

    The table is BOUND, not copied: `producers.CATALOG_EVENT_FIDELITY` is the
    same object, so a test that promotes a family in place (proving a promotion
    is not a parser edit) is seen by `Rule.fidelity` too.
    """
    global _FIDELITY
    _FIDELITY = table


def _reads_vars(node: Any) -> bool:
    """Does this spec tree reference a `$var` anywhere?"""
    if isinstance(node, str):
        return node.startswith("$")
    if isinstance(node, Mapping):
        return any(_reads_vars(v) for v in node.values())
    if isinstance(node, (list, tuple)):
        return any(_reads_vars(v) for v in node)
    return False


def _canon(node: Any) -> str:
    """Order-preserving, type-tagged rendering of a spec tree, for the digest.

    `json.dumps` would do, but it is 3x the cost at import and would silently
    coerce a tuple and a list to the same text; the rule table's meaning depends
    on ORDER everywhere, so the rendering is explicit about sequence vs mapping.
    """
    if node is None:
        return "~"
    if isinstance(node, bool):
        return "b1" if node else "b0"
    if isinstance(node, (int, float)):
        return f"n{node}"
    if isinstance(node, str):
        return "s" + node
    if isinstance(node, Mapping):
        return "{" + "\x1d".join(f"{k}\x1c{_canon(v)}" for k, v in node.items()) + "}"
    if isinstance(node, Sequence):
        return "[" + "\x1d".join(_canon(v) for v in node) + "]"
    raise RuleError(f"un-digestable spec node {node!r}")     # pragma: no cover


def rules_hash(rules: Iterable[Rule]) -> str:
    """sha256 over the ORDERED rule table — the machine's "the rules changed".

    Order is part of the identity on purpose: the interpreter evaluates the
    lane's rules in sequence, first match wins, so swapping two rules changes
    what the parser does even though the set is unchanged.
    """
    h = hashlib.sha256()
    for r in rules:
        h.update("\x1f".join(r.digest_fields()).encode("utf-8"))
        h.update(b"\x1e")
    return h.hexdigest()


def compile_rule(row: Mapping[str, Any]) -> Rule:
    """A validated events.yaml rule row (as baked) → a `Rule`."""
    sev = row.get("severity")
    return Rule(
        rule_id=str(row["rule_id"]),
        lane=str(row["lane"]),
        source=str(row["source"]),
        kind=str(row["kind"]),
        entity_type=str(row["entity_type"]),
        state=row.get("state"),
        state_re=row.get("state_re"),
        vendors=tuple(row.get("vendors", ())),
        markers=tuple(row.get("markers", ())),
        pattern_src=row.get("pattern_src"),
        fidelity_key=row.get("family"),
        fidelity_status=row.get("fidelity_status"),
        severity=_SEV_BY_NAME[sev] if sev else None,
        generic=bool(row.get("generic")),
        shadow=bool(row.get("shadow")),
        guard_src=row.get("guard"),
        extract_src=row.get("extract"),
        emit_src=row.get("emit"),
    )
