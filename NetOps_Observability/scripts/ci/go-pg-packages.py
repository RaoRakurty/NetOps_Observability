#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""go-pg-packages.py — the Go packages the `pg-integration` job must test.

WHY THIS EXISTS (CI audit 2026-11-12, C3). The job ran
`go test -tags=pgintegration -count=1 -p 1 ./...`: 171 packages, one at a
time, 15.4 min, to reach the ~50 database tests that live in a handful of them.
Every other package's tests already run (plain and -race) in the jobs that do
not need a database, so testing them again here bought nothing.

WHICH PACKAGES — and the trap this avoids. "Packages with a
`//go:build pgintegration` file" is NOT the whole set: the DATABASE_URL_TEST
corpus is gated by ENVIRONMENT, not only by build tag, and several of its
packages carry no tagged file at all (internal/metering, internal/users, …:
they `t.Skip` unless the env var is set — and only this job sets it). A
package is therefore selected when any of its `.go` files

  * carries a `//go:build` line naming `pgintegration`, OR
  * names one of the DSN env vars this job exports (ENV_VARS below).

tests/test_backend_ci_speedups.py holds ENV_VARS to the job's real `env:` block,
so adding a DSN to the job without teaching this script fails the build, and it
re-runs this selection to prove every tagged / env-gated file is covered.

Over-selection is harmless (a package mentioned only in a comment just runs its
tests once more); under-selection silently un-runs a tenant-isolation test, so
every ambiguity resolves to "select".

Walk rules mirror `go list ./...`: skip `vendor/`, `testdata/`, directories
starting with `.` or `_`, and nested modules (a directory with its own go.mod).
Output: one `./`-relative package path per line (`.` for the module root),
sorted. An empty selection is an ERROR (exit 1) — a job that tests nothing must
not go green.

Usage (from the module root):  go-pg-packages.py [--root DIR]
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

#: The DSN env vars the pg-integration job exports. Kept equal to the job's
#: `env:` keys by tests/test_backend_ci_speedups.py.
ENV_VARS = ("DATABASE_URL_TEST", "PG_TEST_DSN")
BUILD_TAG = re.compile(r"^//go:build\b.*\bpgintegration\b", re.MULTILINE)
ENV_REF = re.compile("|".join(re.escape(v) for v in ENV_VARS))
SKIP_DIRS = {"vendor", "testdata"}


def _skipped(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith((".", "_"))


def file_needs_pg(text: str) -> bool:
    return bool(BUILD_TAG.search(text) or ENV_REF.search(text))


def select(root: Path) -> list[str]:
    """Sorted `./`-relative package paths under `root` that need the database."""
    root = root.resolve()
    if not (root / "go.mod").is_file():
        raise SystemExit(f"go-pg-packages: FAIL — {root} has no go.mod (run from the module root)")
    picked: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        # prune in place: os.walk honours the edited list
        dirnames[:] = sorted(d for d in dirnames
                             if not _skipped(d) and not (here / d / "go.mod").is_file())
        for fn in filenames:
            if not fn.endswith(".go"):
                continue
            text = (here / fn).read_text(encoding="utf-8", errors="replace")
            if file_needs_pg(text):
                rel = here.relative_to(root).as_posix()
                picked.add("." if rel == "." else f"./{rel}")
                break
    return sorted(picked)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".", help="the Go module root (default: .)")
    args = ap.parse_args(argv)
    try:
        pkgs = select(Path(args.root))
    except OSError as exc:
        print(f"go-pg-packages: FAIL — {exc}", file=sys.stderr)
        return 1
    if not pkgs:
        print("go-pg-packages: FAIL — no package carries a pgintegration build tag or a "
              f"{'/'.join(ENV_VARS)} reference; refusing to run a pg job that tests nothing",
              file=sys.stderr)
        return 1
    print("\n".join(pkgs))
    print(f"go-pg-packages: {len(pkgs)} package(s) need the database", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
