#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""go-shard.py — split ONE Go package's tests into N disjoint `-run` regexes.

WHY THIS EXISTS (CI audit 2026-11-12). The root package `netops/backend` holds
~2,340 tests and runs them serially in one process: 2,301 s of the 39.9-min
`go test -race` step that was the backend PR critical path. No test calls
t.Parallel, so more cores on one runner do not help; splitting the package's
tests across runners does. Each `test-race-root` matrix leg in backend-ci.yml
runs one shard.

Input: the output of `go test [-race] -list '.*' <pkg>` (a file, or stdin) —
one top-level name per line, then an `ok <pkg> <time>` line.

Selection, and why it is safe:
  * Only Test*, Fuzz* and Example* names are sharded: those are what `-run`
    selects (fuzz targets run their seed corpus, examples their output check).
    Benchmark* is dropped — `-run` never runs a benchmark, `-bench` does.
  * Names are de-duplicated and sorted (code-point order), then name i goes to
    shard i mod N. Deterministic for a given listing, and the shards are
    disjoint and together complete BY CONSTRUCTION — tests/test_go_shard.py
    proves both. Every leg lists on the same commit, so every leg sees the same
    listing.
  * The regex is `^(A|B|…)$`: anchored, so `TestFoo` never also selects
    `TestFooBar`; the alternation sits inside a group, so `go test`'s own
    splitter (testing/match.go, which splits a -run pattern on a TOP-LEVEL `|`
    or `/`) leaves it whole; it has one element, so every subtest of a selected
    test runs. Regex metacharacters are escaped although Go identifiers cannot
    contain them — belt and braces for a listing that ever carries one.
  * An empty listing, or a shard that would be empty, is an ERROR (exit 1): a
    leg whose -run matches nothing passes with "no tests to run", which would be
    a green run that tested nothing.

Size, and the choice of approach. A `-run` value is ONE argv string, and Linux
caps a single argument at MAX_ARG_STRLEN (128 KiB) regardless of ARG_MAX. The
whole root package is ~100 KB of names today, so one shard of four is ~25 KB.
The alternatives were rejected: a hash-into-a-small-regex cannot exist (a regex
cannot compute a hash of the name it matches), and a prefix-compressed regex
would make the selection hard to audit. So the regex is written to a FILE
(--out) the job reads into the argument, and the script refuses (exit 1) to
emit one larger than MAX_REGEX_BYTES, naming the fix: raise the shard count.
That failure is loud and happens before any test runs; it can never silently
drop tests.

Usage:
  go test -race -list '.*' . > tests.txt
  go-shard.py --index 0 --total 4 --in tests.txt --out shard.re
"""
from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable

#: Names `-run` selects. Benchmark* is deliberately absent (see module doc).
RUNNABLE = re.compile(r"^(?:Test|Fuzz|Example)\w*$")
#: Lines `go test -list` prints that are not test names.
TRAILER = re.compile(r"^(?:ok|\?|FAIL|---|PASS)\b")
#: Characters RE2 treats as syntax. Escaping a punctuation char with `\` is
#: always legal in RE2, so over-escaping is harmless; under-escaping is not.
_META = set(r"\.+*?()|[]{}^$/")
#: Headroom under the kernel's 128 KiB MAX_ARG_STRLEN for one argv string.
MAX_REGEX_BYTES = 100_000


class ShardError(ValueError):
    """The listing or the request cannot produce a safe shard."""


def parse_listing(lines: Iterable[str]) -> list[str]:
    """Runnable top-level names from `go test -list` output, sorted, unique.

    Benchmarks and the `ok …` trailer are skipped. Anything else that is not a
    runnable name (a stray log line from an init) is ignored: it cannot be a
    test, so sharding it would only produce a pattern that matches nothing."""
    names: set[str] = set()
    for raw in lines:
        line = raw.strip()
        if not line or TRAILER.match(line):
            continue
        if RUNNABLE.match(line):
            names.add(line)
    return sorted(names)


def escape(name: str) -> str:
    return "".join("\\" + c if c in _META else c for c in name)


def shard(names: list[str], index: int, total: int) -> list[str]:
    """The names shard `index` of `total` owns: sorted name i goes to i mod total."""
    if total < 1:
        raise ShardError(f"--total must be >= 1, got {total}")
    if not 0 <= index < total:
        raise ShardError(f"--index must be in [0, {total}), got {index}")
    if not names:
        raise ShardError("the listing holds no runnable test — refusing to emit a "
                         "-run that matches nothing (did `go test -list` fail?)")
    ordered = sorted(set(names))
    mine = [n for i, n in enumerate(ordered) if i % total == index]
    if not mine:
        raise ShardError(f"shard {index}/{total} is empty: {len(ordered)} test(s) "
                         f"cannot fill {total} shards — lower the shard count")
    return mine


def regex(names: list[str]) -> str:
    """`^(A|B|…)$`, anchored and grouped (see module doc)."""
    if not names:
        raise ShardError("cannot build a regex for zero names")
    pattern = "^(" + "|".join(escape(n) for n in names) + ")$"
    size = len(pattern.encode("utf-8"))
    if size > MAX_REGEX_BYTES:
        raise ShardError(f"shard regex is {size} bytes, over the {MAX_REGEX_BYTES}-byte "
                         "single-argument budget — raise the shard count")
    return pattern


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--index", type=int, required=True)
    ap.add_argument("--total", type=int, required=True)
    ap.add_argument("--in", dest="infile", default="-",
                    help="go test -list output (default: stdin)")
    ap.add_argument("--out", default="-", help="where to write the regex (default: stdout)")
    args = ap.parse_args(argv)
    try:
        if args.infile == "-":
            listing = sys.stdin.read().splitlines()
        else:
            with open(args.infile, encoding="utf-8") as fh:
                listing = fh.read().splitlines()
        names = parse_listing(listing)
        mine = shard(names, args.index, args.total)
        pattern = regex(mine)
    except (OSError, ShardError) as exc:
        print(f"go-shard: FAIL — {exc}", file=sys.stderr)
        return 1
    if args.out == "-":
        print(pattern)
    else:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(pattern)
        except OSError as exc:
            print(f"go-shard: FAIL — cannot write {args.out}: {exc}", file=sys.stderr)
            return 1
    print(f"go-shard: shard {args.index}/{args.total}: {len(mine)} of {len(names)} "
          f"runnable test(s), regex {len(pattern.encode('utf-8'))} bytes", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
