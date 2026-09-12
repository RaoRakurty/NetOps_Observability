#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""tac-purge-forbidden.py — enforce the OUTPUT-ONLY command policy over the corpus.

Owner decision, 2026-09-05, verbatim:

    "Rules in executing commands, any command changing the config should be
     blocked or not even known to Correlix. Any command trying to restart or
     reboot should be unknown to Correlix. TAC usually need outputs to
     understand what is going on, not that we have to execute something and
     change."
    "Ping and traceroute are good examples, should be allowed."
    "Any commands that is touching at daemon level block them."

"Not even known" is the part this script exists for. Refusing a command at merge
time still leaves it sitting in `ai/tac/research/*.yaml`, which is knowledge
Correlix carries. This removes it — from the research corpus, from the merged
taxonomy and from every dialect plan — and keeps only the COUNT, per family and
per dialect, in `forbidden.yaml`'s `census:` block. The count is known; the
command is not.

    python3 scripts/tac-purge-forbidden.py            # purge and rewrite
    python3 scripts/tac-purge-forbidden.py --check    # CI mode: fail if anything
                                                      # forbidden is present
    python3 scripts/tac-purge-forbidden.py --quiet    # counts only

It is IDEMPOTENT: a second run finds nothing and changes nothing, which is what
makes `--check` meaningful. Every failure is LOUD — a policy file that will not
load, a plan left with no baseline, an unwritable file — because a purge that
silently did nothing would report success over a corpus that still carries the
commands (scripts/CLAUDE.md §16.1).

Standard library only (CLAUDE.md §6). The YAML reader, the plan/class emitters
and the dialect table are imported from scripts/tac-merge-research.py so there
is exactly one of each.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TAC = os.path.join(REPO, "src", "backend", "ai", "tac")
FORBIDDEN = os.path.join(TAC, "forbidden.yaml")
RESEARCH_DIR = os.path.join(TAC, "research")
PLANS_DIR = os.path.join(TAC, "plans")
CLASSES = os.path.join(TAC, "classes.yaml")

if HERE not in sys.path:
    sys.path.insert(0, HERE)

import tac_forbidden


def _load_merge_module():
    """Import scripts/tac-merge-research.py, whose file name is not a module name.

    It is the single owner of the YAML subset reader and of the class/plan
    emitters. Re-implementing either here would guarantee drift between the two
    scripts that write the same files.
    """
    path = os.path.join(HERE, "tac-merge-research.py")
    spec = importlib.util.spec_from_file_location("tac_merge_research", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"tac-purge-forbidden: cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MERGE = _load_merge_module()

# A research command entry is always a single-line flow mapping:
#     - {cmd: "show ip bgp summary", intent: bgp.summary}
# which is what makes a SURGICAL line removal possible. A record that is not in
# that shape is reported rather than guessed at.
CMD_LINE_RE = re.compile(r"""^(\s*)- \{cmd: (?:"([^"]*)"|'([^']*)'|([^,}]*))""")
COMMANDS_KEY_RE = re.compile(r"^(\s*)commands:\s*$")


class Tally:
    """What the policy excluded, by family and by dialect. Counts only."""

    def __init__(self) -> None:
        self.by_family = tac_forbidden.empty_counts()
        self.by_dialect: dict[str, dict] = {}
        self.total = 0

    def add(self, dialect: str, family: str) -> None:
        self.by_family[family] += 1
        row = self.by_dialect.setdefault(dialect, tac_forbidden.empty_counts())
        row[family] += 1
        self.total += 1

    def render(self) -> str:
        lines = [f"  excluded by policy: {self.total}"]
        for family in tac_forbidden.FAMILIES:
            lines.append(f"    {family:<8}: {self.by_family[family]}")
        for dialect in sorted(self.by_dialect):
            row = self.by_dialect[dialect]
            total = sum(row.values())
            detail = " · ".join(f"{f} {row[f]}" for f in tac_forbidden.FAMILIES if row[f])
            lines.append(f"    {dialect:<20} {total:>4}  ({detail})")
        return "\n".join(lines)


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as err:
        # An unreadable corpus file is a HARD STOP. Skipping it would report a
        # clean purge over data nobody looked at.
        raise SystemExit(f"tac-purge-forbidden: cannot read {path}: {err}") from err


def write_text(path: str, body: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    except OSError as err:
        raise SystemExit(f"tac-purge-forbidden: cannot write {path}: {err}") from err


def load_policy() -> tac_forbidden.Policy:
    try:
        doc = MERGE.parse_yaml(read_text(FORBIDDEN))
    except MERGE.Refusal as err:
        raise SystemExit(f"tac-purge-forbidden: {FORBIDDEN} does not parse: {err}") from err
    try:
        return tac_forbidden.load_policy(doc)
    except tac_forbidden.PolicyError as err:
        raise SystemExit(f"tac-purge-forbidden: {err}") from err


# ── the research corpus ──────────────────────────────────────────────────────


def research_dialect(path: str, body: str) -> str:
    """The dialect a research file targets, read from its own header."""
    for line in body.split("\n")[:20]:
        for key in ("dialect:", "vendor:"):
            if line.startswith(key):
                return line[len(key):].strip().strip("'\"")
    raise SystemExit(f"tac-purge-forbidden: {path} declares neither `dialect:` nor `vendor:`")


def purge_research(policy: tac_forbidden.Policy, tally: Tally, apply: bool) -> list[str]:
    """Remove every forbidden command entry from ai/tac/research/*.yaml.

    Removal is line-based on purpose: the research files are hand-authored,
    citation-dense documents, and re-emitting them from a parse would rewrite
    thousands of lines nobody asked to change. Every `cmd:` entry in the corpus
    is a single-line flow mapping, which makes the surgical removal exact.
    """
    changed: list[str] = []
    for name in sorted(os.listdir(RESEARCH_DIR)):
        if not name.endswith(".yaml"):
            continue
        path = os.path.join(RESEARCH_DIR, name)
        body = read_text(path)
        dialect = research_dialect(path, body)
        lines = body.split("\n")
        keep: list[str] = []
        removed = 0
        for line in lines:
            match = CMD_LINE_RE.match(line)
            if match is None:
                keep.append(line)
                continue
            command = (match.group(2) or match.group(3) or match.group(4) or "").strip()
            rule = policy.match(dialect, command)
            if rule is None:
                keep.append(line)
                continue
            tally.add(dialect, rule.family)
            removed += 1
        if removed == 0:
            continue
        keep = drop_empty_command_blocks(keep)
        changed.append(f"{name}: {removed} removed")
        if apply:
            write_text(path, "\n".join(keep))
    return changed


def drop_empty_command_blocks(lines: list[str]) -> list[str]:
    """Remove a `commands:` key whose every entry was purged.

    A dangling `commands:` with nothing under it is not a parse error, but it is
    a lie in a reviewed document: it says a record has commands when it has
    none.
    """
    out: list[str] = []
    i = 0
    while i < len(lines):
        match = COMMANDS_KEY_RE.match(lines[i])
        if match is None:
            out.append(lines[i])
            i += 1
            continue
        indent = len(match.group(1))
        j = i + 1
        has_entry = False
        while j < len(lines):
            line = lines[j]
            if not line.strip():
                j += 1
                continue
            if len(line) - len(line.lstrip(" ")) <= indent:
                break
            has_entry = True
            break
        if has_entry:
            out.append(lines[i])
        i += 1
    return out


# ── the merged taxonomy and the dialect plans ────────────────────────────────


def purge_plans(policy: tac_forbidden.Policy, tally: Tally, apply: bool) -> list[str]:
    """Remove every forbidden binding from ai/tac/plans/*.yaml.

    These files are machine-emitted (scripts/tac-merge-research.py), so they are
    parsed, filtered and re-emitted with that script's own writer — the same
    round trip the merge performs, which is what keeps the two idempotent
    together.
    """
    changed: list[str] = []
    for name in sorted(os.listdir(PLANS_DIR)):
        if not name.endswith(".yaml"):
            continue
        slug = name[: -len(".yaml")]
        doc = MERGE.load_plan(slug)
        if doc is None:
            raise SystemExit(f"tac-purge-forbidden: plans/{name} disappeared mid-run")
        drop = []
        for intent, binding in doc["bindings"].items():
            command = str(binding.get("command", ""))
            rule = policy.match(slug, command)
            if rule is not None:
                tally.add(slug, rule.family)
                drop.append(intent)
        if not drop:
            continue
        for intent in drop:
            doc["bindings"].pop(intent, None)
        for key in ("baseline", "optional"):
            doc[key] = [i for i in doc.get(key) or [] if i not in drop]
        if not doc["baseline"]:
            # A plan with no baseline does not load. If the policy ever empties
            # one, that is a decision for a human, not something to paper over.
            raise SystemExit(
                f"tac-purge-forbidden: purging plans/{name} would leave it with no baseline; "
                "the dialect needs a read-only baseline authored before the purge can proceed")
        changed.append(f"{name}: {len(drop)} binding(s) removed")
        if apply:
            write_text(os.path.join(PLANS_DIR, name), MERGE.render_plan(doc))
    return changed


def purge_classes(policy: tac_forbidden.Policy, apply: bool) -> list[str]:
    """classes.yaml carries no commands, so nothing here can be forbidden.

    It is still re-emitted when a purge ran, because the merge's own writer is
    the one that decides the file's shape and the two must agree byte for byte
    or `tac-merge-research.py --check` fails afterwards.
    """
    doc = MERGE.load_classes()
    body = MERGE.render_classes(doc)
    if body == read_text(CLASSES):
        return []
    if apply:
        write_text(CLASSES, body)
    return ["classes.yaml: re-emitted"]


# ── the census ───────────────────────────────────────────────────────────────


def render_census(previous: dict, tally: Tally, generated: str) -> str:
    """The census block, ACCUMULATED.

    A purge removes the commands, so a census that counted only "what this run
    removed" would fall back to zero on the next run and report that the policy
    excluded nothing. The count is therefore cumulative over the life of the
    corpus, which is the number that is actually true.
    """
    by_family = tac_forbidden.empty_counts()
    for family in tac_forbidden.FAMILIES:
        by_family[family] = int(previous.get("by_family", {}).get(family, 0) or 0) + tally.by_family[family]
    rows: dict[str, dict] = {}
    for row in previous.get("by_dialect") or []:
        if not isinstance(row, dict):
            continue
        slug = str(row.get("dialect", "")).strip()
        if not slug:
            continue
        rows[slug] = {f: int(row.get(f, 0) or 0) for f in tac_forbidden.FAMILIES}
    for slug, counts in tally.by_dialect.items():
        bucket = rows.setdefault(slug, tac_forbidden.empty_counts())
        for family in tac_forbidden.FAMILIES:
            bucket[family] += counts[family]

    out = ["census:", f"  generated: {generated}", f"  total: {sum(by_family.values())}",
           "  by_family:"]
    for family in tac_forbidden.FAMILIES:
        out.append(f"    {family}: {by_family[family]}")
    if not rows:
        out.append("  by_dialect: []")
    else:
        out.append("  by_dialect:")
        for slug in sorted(rows):
            counts = rows[slug]
            out.append(f"    - dialect: {slug}")
            for family in tac_forbidden.FAMILIES:
                out.append(f"      {family}: {counts[family]}")
            out.append(f"      total: {sum(counts.values())}")
    return "\n".join(out) + "\n"


def rewrite_census(tally: Tally, previous: dict, generated: str) -> None:
    body = read_text(FORBIDDEN)
    lines = body.split("\n")
    start = None
    for i, line in enumerate(lines):
        if line == "census:":
            start = i
            break
    if start is None:
        raise SystemExit("tac-purge-forbidden: forbidden.yaml carries no `census:` block to update")
    head = "\n".join(lines[:start])
    write_text(FORBIDDEN, head.rstrip("\n") + "\n" + render_census(previous, tally, generated))


def census_is_consistent(previous: dict) -> str:
    """'' when the checked-in census adds up; the complaint otherwise."""
    by_family = previous.get("by_family") or {}
    try:
        total = int(previous.get("total", 0) or 0)
        family_sum = sum(int(by_family.get(f, 0) or 0) for f in tac_forbidden.FAMILIES)
    except (TypeError, ValueError) as err:
        return f"census counts are not integers: {err}"
    if family_sum != total:
        return f"census by_family sums to {family_sum}, but total says {total}"
    dialect_sum = 0
    for row in previous.get("by_dialect") or []:
        if not isinstance(row, dict):
            return "a census by_dialect row is not a mapping"
        try:
            row_total = int(row.get("total", 0) or 0)
            row_sum = sum(int(row.get(f, 0) or 0) for f in tac_forbidden.FAMILIES)
        except (TypeError, ValueError) as err:
            return f"census row counts are not integers: {err}"
        if row_sum != row_total:
            return f"census row {row.get('dialect')!r} sums to {row_sum}, but total says {row_total}"
        dialect_sum += row_total
    if dialect_sum > total:
        return f"census by_dialect sums to {dialect_sum}, more than the total {total}"
    return ""


# ── entry point ──────────────────────────────────────────────────────────────


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="fail if any forbidden command is present; write nothing")
    ap.add_argument("--quiet", action="store_true", help="counts only, no per-file detail")
    ap.add_argument("--generated", default="", help="stamp the census with this date (default: today)")
    args = ap.parse_args(argv)

    policy = load_policy()
    tally = Tally()
    apply = not args.check

    research = purge_research(policy, tally, apply)
    plans = purge_plans(policy, tally, apply)
    classes = purge_classes(policy, apply) if (apply and tally.total) else []

    complaint = census_is_consistent(policy.census)
    generated = args.generated or _today()

    print(f"Output-only command policy {policy.version}")
    print(f"  rules: {len(policy.rules())} ({len(policy.common)} common, "
          f"{len(policy.by_dialect)} dialects) · session-scoped setters: "
          f"{sum(len(v) for v in policy.scopes.values())}")
    print(tally.render())
    if not args.quiet:
        for line in research + plans + classes:
            print(f"    · {line}")

    if args.check:
        failed = False
        if tally.total:
            print("\nFAIL: the corpus still carries commands the owner's 2026-09-05 rule "
                  "excludes. Run `python3 scripts/tac-purge-forbidden.py` to remove them.",
                  file=sys.stderr)
            failed = True
        if complaint:
            print(f"\nFAIL: {complaint}", file=sys.stderr)
            failed = True
        return 1 if failed else 0

    if tally.total:
        rewrite_census(tally, policy.census, generated)
        print(f"  census updated in {os.path.relpath(FORBIDDEN, REPO)}")
    elif complaint:
        print(f"\nFAIL: {complaint}", file=sys.stderr)
        return 1
    else:
        print("  nothing to purge; the corpus already matches the policy")
    return 0


def _today() -> str:
    """Today, in UTC. The census date is a provenance stamp, so it must not
    depend on the timezone of whoever ran the purge."""
    return datetime.datetime.now(tz=datetime.timezone.utc).date().isoformat()


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception as err:  # noqa: BLE001 — the top-level guard must be loud, not silent
        print(f"tac-purge-forbidden: {type(err).__name__}: {err}", file=sys.stderr)
        sys.exit(2)
