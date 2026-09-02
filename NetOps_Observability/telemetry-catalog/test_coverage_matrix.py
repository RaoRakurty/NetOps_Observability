"""Pytest: the coverage matrix is DERIVED, and its two Go/engine mirrors are true.

`docs/design/telemetry-coverage-matrix.md` is the artifact a design partner is
handed: "does Correlix see an OSPF adjacency loss on Juniper, over SNMP?".  A
coverage claim that outlives the rule behind it is worse than no claim, so this
file proves three things:

  1. DRIFT — the checked-in .md is exactly what `coverage_matrix.py` generates
     from the catalog right now (same shape as the bake's `--check` guard);
  2. MIRRORS — the two tables the matrix cannot read directly, because they live
     in Go and in the engine's hot loop, are re-derived from their sources and
     compared: the collector's RCA metric allowlist and `metric_identity`'s
     bucket→kind branches;
  3. HONESTY — the matrix never counts a severity-floor safety net as coverage,
     and every rule in the catalog appears in it.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

import bake_rules as B
import coverage_matrix as M

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.abspath(os.path.join(HERE, "..", "src", "correlation"))
MAIN_PY = os.path.join(ENGINE, "main.py")


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    return B.load()[1]


@pytest.fixture(scope="module")
def generated() -> str:
    return M.generate()


# ══ 1. drift ═════════════════════════════════════════════════════════════════


def test_the_checked_in_matrix_is_a_fresh_generation(generated):
    with open(M.TARGET, encoding="utf-8") as fh:
        current = fh.read()
    assert current == generated, (
        "docs/design/telemetry-coverage-matrix.md is STALE vs the catalog — run "
        "`python3 telemetry-catalog/coverage_matrix.py`")


def test_the_check_flag_agrees_with_the_test():
    r = subprocess.run([sys.executable, os.path.join(HERE, "coverage_matrix.py"),
                        "--check"], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_generation_is_deterministic():
    """Two generations must be byte-equal, or `--check` is a coin toss."""
    assert M.generate() == M.generate()


# ══ 2. the mirrors ═══════════════════════════════════════════════════════════


def test_the_metric_allowlist_mirror_matches_the_collector():
    """THE GO MIRROR. `METRIC_BUCKET` claims which metric families reach the
    correlation bus. That list lives in Go; if the two disagree the matrix
    advertises an episode lane the collector never forwards (or hides one it
    does)."""
    assert M.METRIC_BUCKET == M.go_metric_buckets(), (
        "coverage_matrix.METRIC_BUCKET has drifted from `rcaMetricFamilies` in "
        "src/backend/collectors/metric_events.go")


def test_the_episode_kind_mirror_matches_metric_identity():
    """THE ENGINE MIRROR. `metric_identity` is the only place a signal_family
    bucket becomes an episode kind. Re-derived from its source rather than
    imported, because importing `main` drags the whole service in."""
    with open(MAIN_PY, encoding="utf-8") as fh:
        src = fh.read()
    start = src.index("def metric_identity(")
    body = src[start:src.index("\ndef ", start + 10)]
    pairs = {fam: kind for fam, _gap, kind in re.findall(
        r'if family == "([a-z_]+)":(.*?)"([a-z_]+_anomaly)"', body, re.DOTALL)}
    assert pairs, "metric_identity no longer has the shape this mirror reads"
    assert pairs == M.EPISODE_KIND, (
        f"coverage_matrix.EPISODE_KIND {M.EPISODE_KIND} has drifted from "
        f"main.metric_identity {pairs}")


def test_every_episode_kind_is_one_the_producer_declares():
    sys.path.insert(0, ENGINE)
    producers = pytest.importorskip("producers")
    for kind in M.EPISODE_KIND.values():
        assert kind in producers.EMITTED_KINDS, kind


# ══ 3. honesty ═══════════════════════════════════════════════════════════════


def test_every_runtime_rule_appears_in_the_matrix(generated, rows):
    """A rule missing from the artifact is coverage the product has and cannot
    show, or (worse) a rule someone forgot when reading the artifact."""
    missing = [r["rule_id"] for r in rows
               if r["lane"] in B.RUNTIME_LANES and r["rule_id"] not in generated]
    assert not missing, f"rules absent from the coverage matrix: {missing}"


def test_the_generic_nets_are_never_counted_as_coverage(generated, rows):
    """The severity-floor nets catch everything by construction; counting one as
    a source would make every symptom look covered."""
    data = M.build(rows, B.load()[0].get("families") or {})
    for kind, slot in data["by_kind"].items():
        for src in ("syslog", "trap"):
            if all(r.get("generic") for r in slot[src]) and slot[src]:
                assert M._sources(kind, slot, data["episode"]) < 2 or \
                    data["episode"].get(kind), (
                        f"{kind}: a generic net was counted as a source")
    assert "safety net, not coverage" in generated


def test_the_summary_counts_are_the_real_counts(generated, rows):
    """The three numbers a design partner reads first must be computed, not
    typed: re-derive them here and match the rendered text."""
    families = B.load()[0].get("families") or {}
    data = M.build(rows, families)
    typed = {k: v for k, v in data["by_kind"].items()
             if any(not r.get("generic") for lst in v.values() for r in lst)}
    multi = [k for k, v in typed.items()
             if M._sources(k, v, data["episode"]) >= 2]
    trap_typed = [k for k, v in typed.items()
                  if any(not r.get("generic") for r in v["trap"])]
    assert f"- **{len(typed)}** typed symptoms" in generated
    assert f"- **{len(multi)}** of them arrive on" in generated
    assert f"- **{len(trap_typed)}** are carried by a typed SNMP-trap rule" in generated
    # The A9 audit's own headline: the trap lane types more than the three
    # families it typed before.
    assert len(trap_typed) > 3, (
        "the A9 trap promotions vanished — the matrix would understate coverage")


def test_the_audit_verdicts_reach_the_artifact(generated):
    """A KEEP-AS-ALARM verdict with no reason in the artifact is an
    undocumented blind spot."""
    assert M.KEEP_AS_ALARM
    for symptom, traps, _indexed, why in M.KEEP_AS_ALARM:
        assert symptom in generated, symptom
        assert len(why) > 80, f"{symptom}: a verdict needs a reason, not a label"
    assert "anti-fabrication rule" in generated
