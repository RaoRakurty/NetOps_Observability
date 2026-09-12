# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Series-cap memory-bound regression tests.

Verified defect (2026-08-14): CORR_MAX_SERIES defaulted to a flat 200 000 for
BOTH bounded series stores (main.SERIES and episodes.EpisodeDetector._state)
while the container defaults to 1280 MiB (CORRELATION_MEM_LIMIT / the
resource_planner floor). Measured with tracemalloc on the real structures:
~7.5 KiB per full-window entry each → ~2.9 GiB at cap, i.e. the process OOMs
at roughly a quarter of the cap and the bound never bounds. These tests pin:

  * the live caps fit the memory budget the process actually has
    (test_live_caps_fit_the_process_memory_budget — the failing-first test);
  * the per-entry footprint model constant against structure growth
    (test_measured_footprint_within_model);
  * derivation semantics (override, scaling, floor, ceiling).
"""

from __future__ import annotations

import gc
import random
import tracemalloc
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

import pytest

import episodes
import main
import series_budget as sb

MIB = 1024 * 1024


# ---------------------------------------------------------------------------
# The failing-first bound: caps × footprint must fit the real budget.
# ---------------------------------------------------------------------------

def test_live_caps_fit_the_process_memory_budget():
    """Worst case (both stores full of full-window entries at cap) must fit the
    series stores' share of the budget this process actually has. Before the
    fix: 200 000 × 2 × ~8 KiB ≈ 3 GiB against 768 MiB — the OOM-killer fires
    long before the cap can do its job."""
    budget = sb.memory_budget_bytes()
    worst = (main.SERIES_MAX + episodes.MAX_SERIES) * sb.PER_SERIES_BYTES
    assert worst <= budget * sb.SERIES_MEM_FRACTION, (
        f"series caps ({main.SERIES_MAX} + {episodes.MAX_SERIES}) imply "
        f"{worst / MIB:.0f} MiB at cap — over the {budget / MIB:.0f} MiB budget's "
        f"{sb.SERIES_MEM_FRACTION:.0%} series share; the cap would OOM before it bounds"
    )


def test_both_stores_share_one_derived_cap():
    assert main.SERIES_MAX == episodes.MAX_SERIES == sb.derive_max_series()


# ---------------------------------------------------------------------------
# Footprint model pin: re-measure the REAL structures. If a field addition
# pushes an entry past the model constant, this fails and forces the constant
# (and therefore the derived cap) to be re-fit.
# ---------------------------------------------------------------------------

def _measure(fill, n):
    gc.collect()
    tracemalloc.start()
    keep = fill(n)
    gc.collect()
    current, _peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del keep
    gc.collect()
    return current / n


def test_measured_footprint_within_model():
    n = 4000
    rng = random.Random(42)

    def fill_legacy(n):
        d = OrderedDict()
        for i in range(n):
            s = main.Series()
            for _ in range(main.WINDOW_SIZE):
                s.push(100.0 + rng.random())
            d[(f"device-{i:07d}", f"interface.{i % 40}.in.octets")] = s
        return d

    def fill_episodes(n):
        det = episodes.EpisodeDetector(max_series=n + 1)
        t0 = datetime(2026, 8, 1, tzinfo=timezone.utc)
        for i in range(n):
            entity = f"i-{i:016x}"
            for j in range(episodes.WINDOW_SIZE):
                det.observe("tenant-a", entity, "if.in.octets",
                            t0 + timedelta(seconds=60 * j), 100.0 + rng.random())
        return det

    per_legacy = _measure(fill_legacy, n)
    per_episode = _measure(fill_episodes, n)
    assert per_legacy <= sb.PER_SERIES_BYTES, (
        f"main.Series entry grew to {per_legacy:.0f} B > model {sb.PER_SERIES_BYTES} B — "
        "re-measure and re-fit series_budget.PER_SERIES_BYTES"
    )
    assert per_episode <= sb.PER_SERIES_BYTES, (
        f"episodes._SeriesState entry grew to {per_episode:.0f} B > model "
        f"{sb.PER_SERIES_BYTES} B — re-measure and re-fit series_budget.PER_SERIES_BYTES"
    )


# ---------------------------------------------------------------------------
# Derivation semantics.
# ---------------------------------------------------------------------------

def test_explicit_series_cap_override_wins():
    # Legacy semantics preserved verbatim: the operator's number is the number.
    assert sb.derive_max_series({"CORR_MAX_SERIES": "123"}) == 123
    assert sb.derive_max_series(
        {"CORR_MAX_SERIES": "300000", "CORR_MEM_BUDGET_BYTES": str(64 * MIB)}
    ) == 300000


def test_explicit_override_fails_fast_on_garbage():
    with pytest.raises(ValueError):
        sb.derive_max_series({"CORR_MAX_SERIES": "many"})
    with pytest.raises(ValueError):
        sb.derive_max_series({"CORR_MEM_BUDGET_BYTES": "lots"})
    with pytest.raises(ValueError):
        sb.derive_max_series({"CORR_MEM_BUDGET_BYTES": "-1"})


def test_cap_scales_with_the_budget():
    small = sb.derive_max_series({"CORR_MEM_BUDGET_BYTES": str(768 * MIB)})
    large = sb.derive_max_series({"CORR_MEM_BUDGET_BYTES": str(4096 * MIB)})
    assert small < large
    # The formula itself: cap × structures × per-entry ≤ fraction × budget.
    for cap, budget in ((small, 768 * MIB), (large, 4096 * MIB)):
        assert cap * sb.SERIES_STRUCTURES * sb.PER_SERIES_BYTES <= budget * sb.SERIES_MEM_FRACTION


def test_cap_ceiling_is_the_historical_default():
    huge = sb.derive_max_series({"CORR_MEM_BUDGET_BYTES": str(1024 * 1024 * MIB)})
    assert huge == sb.MAX_SERIES_CEILING == 200_000


def test_cap_floor_keeps_the_detector_useful():
    tiny = sb.derive_max_series({"CORR_MEM_BUDGET_BYTES": str(64 * MIB)})
    assert tiny == sb.MIN_SERIES_FLOOR


def test_default_budget_matches_the_shipped_container_limit():
    """The fallback budget must equal the shipped compose default.

    This used to assert both sides against a literal, which meant the guard was
    satisfied by editing the number in two places — precisely the drift it
    exists to prevent (768 MiB survived in three independent spots that way).
    It now READS the compose default, so the two can only agree by actually
    agreeing.
    """
    import pathlib
    import re
    compose = pathlib.Path(__file__).resolve().parents[2] / "deployment/docker/docker-compose.yml"
    text = compose.read_text(encoding="utf-8")
    m = re.search(r"mem_limit:\s*\$\{CORRELATION_MEM_LIMIT:-(\d+)m\}", text)
    assert m, "could not find the CORRELATION_MEM_LIMIT compose default"
    shipped = int(m.group(1)) * MIB
    assert sb.DEFAULT_MEM_BUDGET_BYTES == shipped, (
        f"series-budget fallback {sb.DEFAULT_MEM_BUDGET_BYTES // MIB} MiB != "
        f"compose default {shipped // MIB} MiB")
    assert shipped > 768 * MIB, (
        "the retired 768 MiB default cannot hold the ~516.5 s evidence horizon")


# ---------------------------------------------------------------------------
# Behavior below the cap is unchanged: the LRU eviction path still enforces
# whatever cap is in force (guards the wiring, not just the arithmetic).
# ---------------------------------------------------------------------------

def test_series_store_still_bounded_by_the_cap(monkeypatch):
    monkeypatch.setattr(main, "SERIES_MAX", 8)
    main.SERIES.clear()
    try:
        for i in range(50):
            main.score("t", f"dev-{i}", "metric", 1.0)
        assert len(main.SERIES) <= 8
    finally:
        main.SERIES.clear()
