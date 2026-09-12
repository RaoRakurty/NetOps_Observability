#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""
spdx-headers.py — stamp and verify the per-file SPDX licence header.

Why this exists
---------------
`LICENSE`, `LICENSING.md` and the per-directory notice files already make every
file's licence *determinable*. They do not make it determinable **from the file
alone**. A single .go file pasted into a bug report, a .py script copied onto a
customer's host, a .tsx component quoted in a blog post — each of those leaves
the repository and arrives somewhere with no map attached, and the reader has no
way to know what they may do with it.

That is what a header fixes, and it is why the owner's 2026-09-04 spec asked for
one. This script is the mechanical sweep that puts it there and keeps it there.

What it writes
--------------
Two comment lines, in the comment syntax of the file's language, as the first
comment in the file:

    SPDX-License-Identifier: <the identifier the licensing map assigns>
    <the copyright line from licensing-policy.json>

The identifier is NOT chosen here. It comes from `licensing-policy.json`:
commercial for anything under a `commercial_paths` entry, the core identifier
for everything else. This script never decides a licence; it only writes down
the decision the policy already records.

What it does NOT touch
----------------------
Third-party code, vendored trees, generated files and verbatim fixtures. That
list lives in `licensing-policy.json` (`header_enforcement.exempt`), NOT in this
file — a sweep script that carries its own exemptions is a second source of
truth, and the two drift. Adding an exemption is a policy edit with a reason
attached, reviewed like any other policy edit.

Idempotence
-----------
Running `--write` twice changes nothing the second time. A file that already
carries the right identifier keeps its existing header and only gains the
copyright line if it is missing; a file that carries the WRONG identifier has
that identifier corrected in place rather than gaining a second header.

Prologues are respected: a `#!` shebang stays on line 1, a Python encoding
cookie stays where the interpreter looks for it, a `"use strict"` directive and
`// @ts-check` stay first in a JavaScript file, and a UTF-8 BOM stays a BOM. Go
files take the header ABOVE any `//go:build` constraint — a line comment is a
legal prefix to a build constraint — and always with a blank line before the
package clause, so a package doc comment stays a package doc comment.

Usage
    python3 scripts/spdx-headers.py --check    # list violations, exit 1
    python3 scripts/spdx-headers.py --write    # fix them
    python3 scripts/spdx-headers.py --check --json

Pure standard library. No network, no running stack. Safe in CI.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
POLICY_PATH = os.path.join(PROJ, "licensing-policy.json")

BOM = "﻿"

SPDX_TAG = "SPDX-License-Identifier:"
SPDX_RE = re.compile(re.escape(SPDX_TAG) + r"\s*([A-Za-z0-9.\-+]+)")

# How many bytes of a file count as "the header region". Matched to the window
# scripts/licensing-gate.py reads, so the two agree by construction about which
# SPDX identifier a file declares.
HEAD_BYTES = 4096

# Comment syntax per extension. Mechanics, not policy — which is why this is
# here and the exemption list is not.
LINE_COMMENT = {
    ".go": "//",
    ".ts": "//",
    ".tsx": "//",
    ".js": "//",
    ".mjs": "//",
    ".py": "#",
    ".sh": "#",
    ".yaml": "#",
    ".yml": "#",
}
BLOCK_COMMENT = {".css": ("/*", "*/")}

# Prologue lines that must stay above the header, per extension family.
_PY_CODING = re.compile(r"^#.*coding[:=]\s*[-\w.]+")
_TS_DIRECTIVE = re.compile(r"^//\s*@ts-(check|nocheck)\b")
_USE_STRICT = re.compile(r"""^["']use strict["'];?\s*$""")


class Violation:
    """One file that does not carry the header the policy assigns it."""

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason

    def __str__(self) -> str:
        return f"{self.path}: {self.reason}"

    def as_dict(self) -> dict:
        return {"path": self.path, "reason": self.reason}


def load_policy() -> dict:
    with open(POLICY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


# ── which files are in scope ─────────────────────────────────────────────────
def excluded_names(policy: dict) -> set[str]:
    return {e["name"] for e in policy["excluded_paths"]["entries"]}


def exempt_patterns(policy: dict) -> list[str]:
    return [e["path"] for e in policy["header_enforcement"]["exempt"]["entries"]]


def is_exempt(relpath: str, patterns: list[str]) -> bool:
    """True when a project-relative path matches an exemption from the policy.

    A pattern is either a literal path, a directory prefix (trailing `/`), or a
    glob. Directory prefixes are matched on path segments so `a/b/` never
    matches `a/bc/d`.
    """
    for pat in patterns:
        if pat.endswith("/"):
            if relpath == pat[:-1] or relpath.startswith(pat):
                return True
        elif relpath == pat or fnmatch.fnmatch(relpath, pat):
            return True
    return False


def in_scope(policy: dict) -> list[str]:
    """Every project-relative path the sweep is responsible for, sorted."""
    he = policy["header_enforcement"]
    exts = tuple(he["source_extensions"])
    skip = excluded_names(policy)
    patterns = exempt_patterns(policy)

    found: list[str] = []
    for root in he["sweep_roots"]:
        base = os.path.join(PROJ, root)
        if not os.path.isdir(base):
            # A root named in the policy that is not on disk is a policy error,
            # not something to skip quietly: the sweep would silently cover
            # less than it claims. Reported by the caller via check_roots().
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in skip)
            for name in sorted(filenames):
                if not name.endswith(exts):
                    continue
                relp = os.path.relpath(os.path.join(dirpath, name), PROJ)
                if is_exempt(relp, patterns):
                    continue
                found.append(relp)
    return sorted(found)


def check_roots(policy: dict) -> list[Violation]:
    """Every sweep root and every exemption must exist. A stale entry means the
    sweep covers less than the policy says it does, which is exactly the kind of
    quiet under-coverage this whole gate exists to prevent."""
    out: list[Violation] = []
    for root in policy["header_enforcement"]["sweep_roots"]:
        if not os.path.isdir(os.path.join(PROJ, root)):
            out.append(Violation(root, "named in header_enforcement.sweep_roots "
                                       "but is not a directory"))
    for entry in policy["header_enforcement"]["exempt"]["entries"]:
        pat = entry["path"]
        if any(ch in pat for ch in "*?["):
            continue  # a glob need not resolve to anything today
        target = os.path.join(PROJ, pat.rstrip("/"))
        if not os.path.exists(target):
            out.append(Violation(pat, "exempted in licensing-policy.json but not "
                                      "on disk; remove the stale exemption"))
    return out


def commercial_dirs(policy: dict) -> list[str]:
    return [e["path"] for e in policy["commercial_paths"]["entries"]]


def expected_identifier(relpath: str, policy: dict) -> str:
    """The identifier the licensing map assigns to this path."""
    for d in commercial_dirs(policy):
        if relpath == d or relpath.startswith(d + "/"):
            return policy["identifiers"]["commercial"]
    return policy["identifiers"]["core"]


# ── rendering and rewriting ──────────────────────────────────────────────────
def header_lines(ext: str, identifier: str, copyright_line: str) -> list[str]:
    """The header, rendered in the comment syntax of `ext`."""
    body = [f"{SPDX_TAG} {identifier}", copyright_line]
    if ext in BLOCK_COMMENT:
        open_, close = BLOCK_COMMENT[ext]
        return [f"{open_} {body[0]}", f"   {body[1]} {close}"]
    marker = LINE_COMMENT[ext]
    return [f"{marker} {line}" for line in body]


def split_prologue(lines: list[str], ext: str) -> int:
    """How many leading lines must stay above the header."""
    i = 0
    if not lines:
        return 0
    if ext in (".py", ".sh", ".ts", ".tsx", ".js", ".mjs") and lines[0].startswith("#!"):
        i = 1
        if ext == ".py" and len(lines) > 1 and _PY_CODING.match(lines[1]):
            i = 2
        return i
    if ext == ".py" and _PY_CODING.match(lines[0]):
        return 1
    if ext in (".ts", ".tsx", ".js", ".mjs"):
        while i < len(lines) and _TS_DIRECTIVE.match(lines[i]):
            i += 1
        if i < len(lines) and _USE_STRICT.match(lines[i]):
            i += 1
    return i


def declared_identifier(text: str) -> str | None:
    """The first SPDX identifier in the header region, or None."""
    found = SPDX_RE.search(text[:HEAD_BYTES])
    return found.group(1) if found else None


def is_compliant(text: str, identifier: str, copyright_line: str) -> bool:
    body = text.removeprefix(BOM)
    head = body[:HEAD_BYTES]
    return declared_identifier(body) == identifier and copyright_line in head


def apply_header(text: str, ext: str, identifier: str, copyright_line: str) -> str:
    """Return `text` carrying the right header. Idempotent."""
    bom = BOM if text.startswith(BOM) else ""
    body = text[len(bom):]
    if is_compliant(body, identifier, copyright_line):
        return bom + body

    newline = "\r\n" if "\r\n" in body[:HEAD_BYTES] else "\n"
    lines = body.split(newline)
    declared = declared_identifier(body)

    if declared is not None:
        # The file already has a header. Correct the identifier in place and add
        # the copyright line beneath it — never stack a second header on top of
        # the first, which is how a sweep run twice produces a mess.
        need_copyright = copyright_line not in body[:HEAD_BYTES]
        out: list[str] = []
        fixed = False
        for idx, line in enumerate(lines):
            if not fixed and SPDX_TAG in line:
                line = SPDX_RE.sub(f"{SPDX_TAG} {identifier}", line, count=1)
                if not need_copyright:
                    out.append(line)
                elif ext not in BLOCK_COMMENT:
                    out.append(line)
                    out.append(f"{LINE_COMMENT[ext]} {copyright_line}")
                else:
                    open_, close = BLOCK_COMMENT[ext]
                    # Only the simple case is repairable without parsing the
                    # comment: the SPDX tag sits on the file's first line, in a
                    # block comment that opens and closes there. Anything else
                    # (a tag buried inside a multi-line block) is reported
                    # instead of guessed at — an unbalanced `*/` would silently
                    # comment out the stylesheet.
                    if idx != 0 or not line.lstrip().startswith(open_) \
                            or close not in line:
                        return bom + body  # unchanged; the caller reports it
                    out.append(line.replace(close, "").rstrip())
                    out.append(f"   {copyright_line} {close}")
                fixed = True
                continue
            out.append(line)
        return bom + newline.join(out)

    cut = split_prologue(lines, ext)
    head = header_lines(ext, identifier, copyright_line)
    rest = lines[cut:]
    # Exactly one blank line between the header and what follows, and none added
    # to a file that is only a header.
    if rest and rest[0].strip() != "":
        rest = [""] + rest
    return bom + newline.join(lines[:cut] + head + rest)


# ── the sweep ────────────────────────────────────────────────────────────────
def scan(policy: dict, write: bool) -> tuple[list[Violation], list[str]]:
    """(violations, files changed). `--check` passes write=False."""
    copyright_line = policy["header_enforcement"]["copyright_line"]
    violations: list[Violation] = check_roots(policy)
    changed: list[str] = []

    for relp in in_scope(policy):
        full = os.path.join(PROJ, relp)
        ext = os.path.splitext(relp)[1]
        identifier = expected_identifier(relp, policy)
        try:
            with open(full, encoding="utf-8", newline="") as fh:
                text = fh.read()
        except UnicodeDecodeError:
            # A file the sweep cannot read is a file the sweep did NOT stamp.
            # Reporting it (rather than continuing) is the §16.1 rule: a
            # sweeper that skips silently reports success it did not earn.
            violations.append(Violation(relp, "is not valid UTF-8, so no header "
                                              "could be read or written"))
            continue
        except OSError as err:
            violations.append(Violation(relp, f"could not be read: {err}"))
            continue

        if is_compliant(text, identifier, copyright_line):
            continue

        if not write:
            declared = declared_identifier(text)
            if declared is None:
                reason = f"carries no {SPDX_TAG} {identifier} header"
            elif declared != identifier:
                reason = (f"declares {declared} but the licensing map assigns "
                          f"{identifier}")
            else:
                reason = f"declares {identifier} but is missing {copyright_line!r}"
            violations.append(Violation(relp, reason))
            continue

        new = apply_header(text, ext, identifier, copyright_line)
        if new == text:
            violations.append(Violation(relp, "could not be rewritten; the header "
                                              "rule does not cover this file"))
            continue
        try:
            with open(full, "w", encoding="utf-8", newline="") as fh:
                fh.write(new)
        except OSError as err:
            violations.append(Violation(relp, f"could not be written: {err}"))
            continue
        changed.append(relp)

    return violations, changed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true",
                      help="list files missing the header and exit 1")
    mode.add_argument("--write", action="store_true", help="stamp the header in place")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    policy = load_policy()
    violations, changed = scan(policy, write=args.write)

    if args.json:
        print(json.dumps({"ok": not violations,
                          "changed": changed,
                          "violations": [v.as_dict() for v in violations]}, indent=2))
        return 1 if violations else 0

    if args.write:
        for relp in changed:
            print(f"stamped {relp}")
        print(f"spdx-headers: stamped {len(changed)} file(s)")

    if violations:
        print(f"spdx-headers: FAIL — {len(violations)} file(s)", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        print("Fix with: python3 scripts/spdx-headers.py --write\n"
              "Exemptions live in licensing-policy.json (header_enforcement.exempt).",
              file=sys.stderr)
        return 1

    if args.check:
        print(f"spdx-headers: PASS ({len(in_scope(policy))} file(s) carry their header)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
