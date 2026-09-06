# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard for the Phase 6 ClickHouse test exclusions (tracker #127).

The Phase 6 integration tests (test_clickhouse_integration.py, and chhttp's Go
twin) deliberately OMIT the spec's Distributed-table and async_insert cases
because the repo uses neither — verified 0 of each at the time (7eec55b8). That
premise is true today and silent tomorrow: nothing stopped a future change from
introducing either feature and inheriting an integration-coverage hole nobody
remembers exists.

This scan makes the premise load-bearing: introducing a Distributed engine or
any async_insert usage trips a test that names the missing coverage, instead of
quietly opening the hole. When one fires, the fix is NOT to delete the guard —
it is to write the integration cases Phase 6 skipped (insert/readback, dedup
token, failure surfacing — see test_clickhouse_integration.py for the shape),
then narrow the guard to whatever is still unused.

Hermetic on purpose: pure source scan, runs in the default suite (unlike the
CH_TEST_URL-gated integration file).
"""
import os
import re
from pathlib import Path

# NetOps_Observability/ (src/correlation/ → src/ → project root)
_ROOT = Path(__file__).resolve().parents[2]

# Everywhere CH DDL, per-query settings, or server config can live.
_SCAN_EXTS = {".go", ".py", ".sql", ".xml", ".yml", ".yaml", ".sh"}
_PRUNE_DIRS = {
    ".git", "node_modules", "data", "build", "dist", "vendor",
    "__pycache__", ".ruff_cache", ".claude", ".mypy_cache",
}
_SELF = Path(__file__).name

# ENGINE = Distributed(...) — anchored on the engine assignment so prose like
# catalog.py's "Distributed/anycast gateway inconsistency" cannot false-positive.
_DISTRIBUTED = re.compile(r"engine\s*=\s*distributed\s*\(", re.IGNORECASE)
# The setting name is distinctive enough to match bare (query param, XML tag,
# SETTINGS clause all contain the literal token).
_ASYNC_INSERT = re.compile(r"async_insert", re.IGNORECASE)


def _scan_files():
    for dirpath, dirnames, filenames in os.walk(_ROOT):
        # In-place prune so os.walk never descends into bulky/generated trees
        # (data/ holds live container state and may not even be readable).
        dirnames[:] = sorted(d for d in dirnames if d not in _PRUNE_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath, name)
            if path.suffix in _SCAN_EXTS and name != _SELF:
                yield path


def _hits(pattern: re.Pattern) -> list[str]:
    out = []
    for path in _scan_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:  # unreadable tracked source is itself a finding
            out.append(f"{path}: UNREADABLE ({exc})")
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                out.append(f"{path.relative_to(_ROOT)}:{i}: {line.strip()[:120]}")
    return out


def test_no_distributed_engines():
    hits = _hits(_DISTRIBUTED)
    assert not hits, (
        "Distributed table engine introduced, but the Phase 6 CH integration "
        "tests deliberately skip every Distributed case because the repo used "
        "none (7eec55b8). Write the Distributed integration coverage first "
        "(test_clickhouse_integration.py / chhttp_integration_test.go), then "
        "update this guard:\n  " + "\n  ".join(hits)
    )


def test_no_async_insert():
    hits = _hits(_ASYNC_INSERT)
    assert not hits, (
        "async_insert introduced, but the Phase 6 CH integration tests "
        "deliberately skip every async_insert case (delayed visibility breaks "
        "their read-back assertions and the dedup-token drill) because the repo "
        "used none (7eec55b8). Write that coverage first, then update this "
        "guard:\n  " + "\n  ".join(hits)
    )
