# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""scripts/ci/go-shard.py splits the root package's tests across the
`test-race-root` matrix in backend-ci.yml (CI audit 2026-11-12, C2).

The properties that make sharding safe, each proved here: the shards are
DISJOINT (no test runs twice, which would also halve the speed-up), COMPLETE
(no test is dropped — a dropped test is a green run that tested nothing),
DETERMINISTIC (every leg computes the same split from the same listing), and the
regex selects exactly its own names under Go's -run semantics (anchored, so
`TestFoo` never drags in `TestFooBar`).
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ci" / "go-shard.py"
_spec = importlib.util.spec_from_file_location("go_shard", SCRIPT)
gs = importlib.util.module_from_spec(_spec)
sys.modules["go_shard"] = gs
_spec.loader.exec_module(gs)

LISTING = """\
TestFoo
TestFooBar
TestAlpha
TestBeta_Sub
TestÜnicode
FuzzParseSpiffeID
ExampleRender
BenchmarkHotPath
TestFoo
ok  \tnetops/backend\t0.412s
"""


def _names(n: int) -> list[str]:
    return [f"TestCase{i:04d}" for i in range(n)]


def _go_selects(pattern: str, name: str) -> bool:
    """Go's -run match for a top-level name: the pattern has one element (no
    top-level `|` or `/`), matched unanchored by regexp — our anchors do the
    anchoring. Python's `re` agrees with RE2 on this subset (literals, escapes,
    one group of alternatives)."""
    return re.search(pattern, name) is not None


def test_parse_keeps_runnable_names_once_and_drops_benchmarks_and_trailer():
    got = gs.parse_listing(LISTING.splitlines())
    assert got == sorted({"TestFoo", "TestFooBar", "TestAlpha", "TestBeta_Sub",
                          "TestÜnicode", "FuzzParseSpiffeID", "ExampleRender"})
    assert "BenchmarkHotPath" not in got


@pytest.mark.parametrize("total", [1, 2, 3, 4, 5, 7, 16])
def test_shards_are_disjoint_and_complete(total):
    names = _names(2340)
    shards = [gs.shard(names, i, total) for i in range(total)]
    seen: list[str] = [n for s in shards for n in s]
    assert len(seen) == len(set(seen)), "a test landed in two shards"
    assert set(seen) == set(names), "a test landed in no shard"
    sizes = [len(s) for s in shards]
    assert max(sizes) - min(sizes) <= 1, "count balance is the documented split"


@pytest.mark.parametrize("total", [2, 4, 6])
def test_each_regex_selects_exactly_its_own_shard(total):
    names = gs.parse_listing(LISTING.splitlines()) + _names(40)
    for i in range(total):
        mine = set(gs.shard(names, i, total))
        pattern = gs.regex(sorted(mine))
        assert {n for n in names if _go_selects(pattern, n)} == mine


def test_anchoring_stops_a_prefix_from_selecting_its_extensions():
    pattern = gs.regex(["TestFoo"])
    assert _go_selects(pattern, "TestFoo")
    assert not _go_selects(pattern, "TestFooBar")
    assert not _go_selects(pattern, "XTestFoo")


def test_the_split_is_stable_across_runs_and_input_order():
    names = _names(500)
    shuffled = list(reversed(names))
    for total in (3, 4):
        for i in range(total):
            a = gs.regex(gs.shard(names, i, total))
            assert a == gs.regex(gs.shard(shuffled, i, total))
            assert a == gs.regex(gs.shard(names, i, total))


def test_a_new_test_moves_only_the_names_after_it():
    """Adding a test re-deals the names sorted after it (index mod N) but never
    loses or duplicates one — completeness holds for every listing."""
    before = _names(100)
    after = sorted(before + ["TestCase0050a"])
    for total in (2, 4):
        union = [n for i in range(total) for n in gs.shard(after, i, total)]
        assert sorted(union) == after


@pytest.mark.parametrize("name", [
    "Test.Dot", "Test+Plus", "Test*Star", "Test?Q", "Test(Paren)", "Test|Pipe",
    "Test[Br]", "Test{Brace}", "Test^Caret", "Test$Dollar", "Test\\Back", "Test/Slash",
])
def test_metacharacters_are_escaped_to_literals(name):
    pattern = gs.regex([name])
    assert _go_selects(pattern, name)
    # the escaped pattern matches the literal only, not what the metachar means
    assert not _go_selects(pattern, name.replace(name[4], "x") + "y")
    body = pattern[2:-2]
    for c in name[4:]:
        if c in gs._META:
            assert "\\" + c in body


def test_the_group_keeps_the_alternation_away_from_gos_splitter():
    """testing/match.go splits -run on a top-level `|` or `/`; inside the group
    neither is top-level, so the whole regex is one element."""
    pattern = gs.regex(["TestA", "TestB"])
    assert pattern == "^(TestA|TestB)$"
    depth = 0
    for c in pattern:
        depth += c == "("
        depth -= c == ")"
        if c in "|/":
            assert depth > 0


def test_an_empty_listing_is_an_error():
    with pytest.raises(gs.ShardError, match="no runnable test"):
        gs.shard([], 0, 4)
    with pytest.raises(gs.ShardError):
        gs.shard(gs.parse_listing(["BenchmarkOnly", "ok  \tnetops/backend\t0.1s"]), 0, 1)


def test_more_shards_than_tests_is_an_error_not_an_empty_green_leg():
    with pytest.raises(gs.ShardError, match="empty"):
        gs.shard(["TestA", "TestB"], 3, 4)


@pytest.mark.parametrize("index, total", [(-1, 4), (4, 4), (0, 0)])
def test_bad_index_or_total_is_an_error(index, total):
    with pytest.raises(gs.ShardError):
        gs.shard(_names(10), index, total)


def test_an_oversized_regex_is_refused_with_the_fix_named():
    huge = [f"Test{'x' * 200}{i:05d}" for i in range(600)]
    with pytest.raises(gs.ShardError, match="raise the shard count"):
        gs.regex(huge)


def test_cli_writes_the_regex_to_a_file_and_fails_closed(tmp_path):
    listing = tmp_path / "tests.txt"
    listing.write_text(LISTING, encoding="utf-8")
    out = tmp_path / "shard.re"
    proc = subprocess.run([sys.executable, "-I", str(SCRIPT), "--index", "1", "--total", "2",
                           "--in", str(listing), "--out", str(out)],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    names = gs.parse_listing(LISTING.splitlines())
    assert out.read_text(encoding="utf-8") == gs.regex(gs.shard(names, 1, 2))
    assert "shard 1/2" in proc.stderr

    empty = tmp_path / "empty.txt"
    empty.write_text("ok  \tnetops/backend\t0.1s\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, "-I", str(SCRIPT), "--index", "0", "--total", "4",
                           "--in", str(empty), "--out", str(tmp_path / "x.re")],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert "FAIL" in proc.stderr
    assert not (tmp_path / "x.re").exists()
