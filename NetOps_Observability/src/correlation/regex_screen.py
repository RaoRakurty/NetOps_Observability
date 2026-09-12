# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Derive a SOUND literal screen from a regular expression.

WHY THIS EXISTS (P3 change B, docs/scale/P3_AGGREGATION_OPPORTUNITY_2026-08-29
§6.5). On the ratified `t-nominal-2.5k` workload **95.1 % of syslog lines are
fully parsed and then not promoted**: 900,001 raw lines yield 44,280 signals,
and `handle.syslog` costs 789 s. The cheapest honest saving is to decide
"cannot promote" from the raw line BEFORE the classifiers run — which needs a
screen that is *sound*: it may pass a line that goes on to match nothing (a few
microseconds wasted), but it must NEVER reject a line a classifier would have
promoted, because that line would vanish silently.

Hand-writing such a screen is exactly the drift hazard tracker 156 called out
when it built `producers._PORT_EVENT_PREFILTER` from the rules rather than by
hand. This module goes one step further: instead of a union REGEX (measured at
82-99 us per line on real syslog — more than running the twelve rules
individually, because Python's `re` cannot factor a bounded-gap alternation), it
extracts, from each pattern, a set of **literal substrings a match must
contain**, which a screen can test with `str.__contains__` in ~2 us.

THE SOUNDNESS ARGUMENT, in full:

  A regex alternation `A|B|C` matches iff one alternative matches, so a screen
  for the whole pattern is the UNION of a screen per alternative.

  Within one alternative — a concatenation — every element that is NOT inside a
  group and NOT quantified as optional (`?`, `*`, `{0,n}`) is MANDATORY: every
  string the alternative matches contains it. So:

    * a maximal run of literal characters at nesting depth 0, minus a trailing
      character that carries an optional quantifier, is a literal that every
      match contains  ->  {run} is a sound screen for the alternative;
    * a mandatory group whose body is a top-level alternation of pure literals
      (`(low|below)`) contributes the SET of those literals: every match
      contains at least one of them  ->  that set is a sound screen too.

  Any one such candidate suffices; we pick the most selective (longest
  guaranteed literal, fewest alternatives) because selectivity decides how much
  work the screen saves, never whether it is correct.

  If an alternative yields NO candidate — every element is optional, a class, or
  a group we cannot read — the pattern is UNSCREENABLE and this module returns
  None. Callers must then FAIL OPEN (screen disabled, everything passes), which
  costs performance and can never cost a signal.

Case: every literal is returned lower-cased and callers must screen a
lower-cased haystack, which makes the screen equivalent to an IGNORECASE match.
That is strictly more permissive than a case-sensitive pattern, so it stays
sound in the only direction that matters.

Deliberately NOT handled (they make a pattern UNSCREENABLE rather than a wrong
screen): backreferences, conditionals, and anything inside a lookaround — a
lookaround's content is not part of what the match consumes, so treating it as
mandatory would be UNSOUND. `(?:...)` is read; `(?=`, `(?!`, `(?<`, `(?P<...>`
and inline-flag groups are simply not used as candidates.
"""
from __future__ import annotations


def split_alternatives(pattern: str) -> list[str]:
    """Split on TOP-LEVEL `|` only — inside groups and character classes a `|`
    is either a nested alternation (handled when that group is read) or a
    literal."""
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            buf.append(pattern[i:i + 2])
            i += 2
            continue
        if c == "[":
            j = _end_of_class(pattern, i)
            buf.append(pattern[i:j])
            i = j
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    out.append("".join(buf))
    return out


def _end_of_class(pattern: str, start: int) -> int:
    """Index just past the `]` closing the character class opening at `start`."""
    j = start + 1
    if j < len(pattern) and pattern[j] == "^":
        j += 1
    if j < len(pattern) and pattern[j] == "]":   # a leading ] is a literal
        j += 1
    while j < len(pattern) and pattern[j] != "]":
        j += 2 if pattern[j] == "\\" else 1
    return min(j + 1, len(pattern))


def _end_of_group(pattern: str, start: int) -> int:
    """Index just past the `)` closing the group opening at `start`."""
    depth = 1
    j = start + 1
    while j < len(pattern) and depth:
        c = pattern[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            j = _end_of_class(pattern, j)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        j += 1
    return j


def _tokens(alt: str) -> list[tuple[str, str]]:
    """One alternative -> [(kind, value)] at depth 0, quantifiers resolved.

    kind: 'lit'   a MANDATORY run of literal characters
          'group' a MANDATORY group body (still raw pattern text)
          'opt'   an element a match need not contain
          'other' a class / escape class / anchor / dot
    """
    toks: list[tuple[str, str]] = []
    run: list[str] = []
    i = 0
    n = len(alt)

    def flush() -> None:
        if run:
            toks.append(("lit", "".join(run)))
            del run[:]

    def quantify(optional: bool) -> None:
        """Apply a just-read quantifier to the element before it."""
        if run:                      # ...it binds the LAST character only
            last = run.pop()
            flush()
            toks.append(("opt" if optional else "lit", last))
        elif toks and optional:
            toks[-1] = ("opt", toks[-1][1])

    while i < n:
        c = alt[i]
        if c == "\\":
            nxt = alt[i + 1] if i + 1 < n else ""
            if nxt.isalnum():        # \s \d \w \b \1 ... — a class or assertion
                flush()
                toks.append(("other", alt[i:i + 2]))
            else:                    # \. \- \/ ... — an escaped literal
                run.append(nxt)
            i += 2
        elif c == "[":
            flush()
            j = _end_of_class(alt, i)
            toks.append(("other", alt[i:j]))
            i = j
        elif c == "(":
            flush()
            j = _end_of_group(alt, i)
            toks.append(("group", alt[i + 1:j - 1]))
            i = j
        elif c in ".^$":
            flush()
            toks.append(("other", c))
            i += 1
        elif c in "?*":
            quantify(True)
            i += 1
        elif c == "+":
            quantify(False)
            i += 1
        elif c == "{":
            j = alt.find("}", i)
            if j < 0:                # a literal `{`
                run.append(c)
                i += 1
                continue
            quantify(alt[i + 1:j].lstrip().startswith("0"))
            i = j + 1
        else:
            run.append(c)
            i += 1
    flush()
    return toks


# A mandatory group is screened RECURSIVELY: a match of the group matches one of
# its alternatives, so the union of the alternatives' own screens is sound. The
# depth bound is a guard against a pathological nesting, never a real pattern.
_MAX_DEPTH = 12


def _group_screen(group_body: str, depth: int) -> frozenset[str] | None:
    """Screen for a MANDATORY group's body; None when it cannot be read (a
    lookaround, inline flags, a named/conditional group, or an alternative with
    no mandatory element)."""
    body = group_body
    if body.startswith("?"):
        if body.startswith("?:"):
            body = body[2:]
        else:
            # A lookaround is NOT consumed by the match, so treating its content
            # as mandatory would be unsound; flag/named/conditional groups are
            # simply not read. Either way: not a candidate.
            return None
    out: set[str] = set()
    for alt in split_alternatives(body):
        screen = alternative_screen(alt, depth + 1)
        if screen is None:
            return None
        out |= screen
    return frozenset(out) or None


def alternative_screen(alt: str, depth: int = 0) -> frozenset[str] | None:
    """The most selective sound screen for ONE alternative; None if there is
    none (every element optional / unreadable)."""
    if depth > _MAX_DEPTH:
        return None
    candidates: list[frozenset[str]] = []
    for kind, value in _tokens(alt):
        if kind == "lit" and value:
            candidates.append(frozenset({value.lower()}))
        elif kind == "group":
            screen = _group_screen(value, depth)
            if screen:
                candidates.append(screen)
    if not candidates:
        return None
    # Longest GUARANTEED literal first (that is what makes the screen
    # selective), then the fewest alternatives to test.
    return max(candidates, key=lambda s: (min(len(x) for x in s), -len(s)))


def pattern_screen(pattern: str) -> frozenset[str] | None:
    """Literals such that ANY string matching `pattern` contains at least one of
    them (case-insensitively). None when the pattern cannot be screened — the
    caller must then fail OPEN."""
    out: set[str] = set()
    for alt in split_alternatives(pattern):
        screen = alternative_screen(alt)
        if screen is None:
            return None
        out |= screen
    return frozenset(out) or None
