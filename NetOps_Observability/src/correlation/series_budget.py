# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Memory-budget-derived cap for the bounded per-series stores.

Two structures are LRU-bounded by the same cap and can BOTH be at cap with
disjoint key spaces:

  * ``main.SERIES``                       — legacy z-score, keyed (device, metric)
  * ``episodes.EpisodeDetector._state``   — CUSUM episodes, keyed (tenant, entity, metric)

The cap used to default to a flat 200 000 per structure. Measured on the real
structures (tracemalloc over a synthetic fill, python 3.10, 2026-08-14): one
entry with a FULL 200-sample window costs ~7.5 KiB in ``main.SERIES`` and
~7.7 KiB in the episode detector (key strings + dict slot + dataclass + the
200-float deque). At 200 000 entries each that is ~2.9 GiB — against the
service's 768 MiB default container limit (``CORRELATION_MEM_LIMIT`` compose
default == the resource_planner floor). The cgroup OOM-killer would fire at
roughly a QUARTER of the cap, so the "bound" never actually bounded anything.

The cap is therefore derived from the memory budget the process really has.
Eviction behavior below the cap is unchanged; only the numeric cap moves with
the budget. Resolution order:

  1. ``CORR_MAX_SERIES``        — explicit operator override, honored verbatim
                                  (exact legacy semantics, including the
                                  fail-fast ``ValueError`` on a non-integer).
  2. ``CORR_MEM_BUDGET_BYTES``  — explicit budget override (bytes).
  3. the cgroup memory limit    — inside the container this IS the compose
                                  ``mem_limit``, so operator resizes are picked
                                  up with no second knob to forget.
  4. 1280 MiB                   — the shipped default limit (1.25 GiB, qualified).

``test_series_budget.py`` re-measures the real structures and fails if a field
addition pushes an entry past the model constant below — change the constant
only together with a fresh measurement.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

MIB = 1024 * 1024

# Measured worst-case per-entry footprint (full 200-sample window), rounded UP
# from the 2026-08-14 measurement (7 464 B legacy / 7 681 B episodes per entry,
# tracemalloc, n=20 000 synthetic fill). Pinned by test_series_budget.py.
PER_SERIES_BYTES = 8192

# The structures sharing the cap (see module docstring).
SERIES_STRUCTURES = 2

# Worst-case share of the budget the series stores may consume. The remainder
# belongs to the interpreter itself (~120 MiB with FastAPI + aiokafka loaded),
# the CORR_WINDOW_BUFFER signal window (50k+ rows), engine/episode state and
# ClickHouse batch buffers.
SERIES_MEM_FRACTION = 0.35

# Never exceed the historical default; never fall below a floor that keeps the
# detector useful. On absurdly small budgets the floor deliberately wins over
# the fraction (5 000 full entries ≈ 78 MiB across both stores) — a slightly
# oversubscribed detector beats a useless one.
MAX_SERIES_CEILING = 200_000
MIN_SERIES_FLOOR = 5_000

# CORRELATION_MEM_LIMIT compose default / resource_planner floor for this
# service (deployment/docker/docker-compose.yml, scripts/resource_planner.py).
# 1280 MiB = 1.25 GiB, QUALIFIED 2026-08-21 (tracker 165); the retired 768 MiB
# cannot hold the ~516.5 s evidence horizon the engine now contracts for.
#
# This is a MIRROR, used only when the real cgroup limit cannot be read (see
# _cgroup_memory_limit_bytes below, which is the normal path). Correlation must
# not import the planner — that would be a cross-domain dependency (§2) — so the
# two constants are kept honest by a test instead:
# scripts/tests/test_resource_planner.py::test_the_correlation_mirrors_agree.
DEFAULT_MEM_BUDGET_BYTES = 1280 * MIB

_CGROUP_V2_LIMIT = "/sys/fs/cgroup/memory.max"
_CGROUP_V1_LIMIT = "/sys/fs/cgroup/memory/memory.limit_in_bytes"


def _cgroup_memory_limit_bytes() -> int | None:
    """The container's memory limit, or None when unlimited / not in a cgroup."""
    for path in (_CGROUP_V2_LIMIT, _CGROUP_V1_LIMIT):
        try:
            with open(path, encoding="ascii") as f:
                raw = f.read().strip()
        except OSError:
            continue  # that cgroup version isn't mounted here — try the next
        if raw == "max":  # cgroup v2 spelling of "unlimited"
            return None
        try:
            limit = int(raw)
        except ValueError:
            return None
        # cgroup v1 reports "unlimited" as a huge page-rounded sentinel.
        if limit <= 0 or limit >= 1 << 60:
            return None
        return limit
    return None


def memory_budget_bytes(env: Mapping[str, str] | None = None) -> int:
    """The memory budget this process should plan against (bytes)."""
    if env is None:
        env = os.environ
    raw = (env.get("CORR_MEM_BUDGET_BYTES") or "").strip()
    if raw:
        # Fail fast on a malformed override — same boot-time semantics as a
        # malformed CORR_MAX_SERIES, and far louder than silently falling back
        # to a default the operator believes they overrode.
        budget = int(raw)
        if budget <= 0:
            raise ValueError(f"CORR_MEM_BUDGET_BYTES must be positive, got {budget}")
        return budget
    return _cgroup_memory_limit_bytes() or DEFAULT_MEM_BUDGET_BYTES


def derive_max_series(env: Mapping[str, str] | None = None) -> int:
    """The per-structure series cap for this process's memory budget."""
    if env is None:
        env = os.environ
    explicit = (env.get("CORR_MAX_SERIES") or "").strip()
    if explicit:
        return int(explicit)  # operator override — exact legacy semantics
    budget = memory_budget_bytes(env)
    cap = int(budget * SERIES_MEM_FRACTION) // (SERIES_STRUCTURES * PER_SERIES_BYTES)
    return max(MIN_SERIES_FLOOR, min(MAX_SERIES_CEILING, cap))
