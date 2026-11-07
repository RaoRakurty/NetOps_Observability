# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Cumulative counters become per-second rates before the episode detector.

tracker 379 (engine stage [2], metric lane). SNMP Counter32/Counter64 values —
interface octets, errors, discards, FCS errors, BGP FSM transitions — arrive as
the device's running TOTAL (`collectors/metric_events.go buildMetricEvent`), and
the CUSUM detector treated them as gauges: a perfectly steady 1,000 errors/min
opened an episode at sample 23 and never cleared, so every such series raised
one false anomaly per process start and was then blind to a real spike. The
vManage realtime counters (E3) are cumulative too.

What the detector needs is the RATE. Per (tenant, entity, metric, collection
path) — one counter per SOURCE, because SNMP and the controller count from
different bases — the previous sample is kept and each new one becomes
`(v - v_prev) / (t - t_prev)` per second:

  * the first sample of a series SEEDS it and is not scored;
  * a NEGATIVE delta is a counter reset or wrap (device reboot, Counter32
    rollover, a different counter behind the same name): re-seed, not scored —
    guessing the wrap modulus would invent a rate;
  * a sample whose clock does not advance (duplicate, out of order) is dropped.

Each outcome is counted, so nothing is silent. Bounded: an LRU of at most
`max_keys` series; an evicted series simply re-seeds.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime

#: The canonical metric names that carry a RUNNING TOTAL. Pinned against the Go
#: allowlist (`rcaMetricFamilies`, units bytes/errors/discards/fcs_errors/
#: transitions) by test_counter_rate_379.py, so the two cannot drift.
CUMULATIVE_METRICS: frozenset[str] = frozenset({
    "device_if_in_octets", "device_if_out_octets",
    "device_if_in_errors", "device_if_out_errors",
    "device_if_in_discards", "device_if_out_discards",
    "device_if_fcs_errors",
    "device_bgp_fsm_transitions",
})

DEFAULT_MAX_KEYS = 200_000

SEED, RATE, RESET, STALE = "seed", "rate", "reset", "stale"


class CounterRates:
    """Turns successive cumulative samples of one series into a rate."""

    __slots__ = ("_last", "_max_keys", "counts")

    def __init__(self, max_keys: int = DEFAULT_MAX_KEYS) -> None:
        if max_keys <= 0:
            raise ValueError("max_keys must be positive")
        self._max_keys = int(max_keys)
        self._last: OrderedDict[tuple[str, ...], tuple[float, float]] = OrderedDict()
        self.counts = {SEED: 0, RATE: 0, RESET: 0, STALE: 0}

    def observe(self, key: tuple[str, ...], value: float, ts: datetime) -> tuple[str, float | None]:
        """Returns (outcome, rate_per_second); the rate is None unless RATE."""
        t = ts.timestamp()
        prev = self._last.get(key)
        if prev is None:
            return self._seed(key, value, t, SEED)
        pv, pt = prev
        dt = t - pt
        if dt <= 0:
            self._last.move_to_end(key)
            self.counts[STALE] += 1
            return STALE, None           # keep the older (earlier) point
        delta = value - pv
        if delta < 0:
            return self._seed(key, value, t, RESET)
        self._last[key] = (value, t)
        self._last.move_to_end(key)
        self.counts[RATE] += 1
        return RATE, delta / dt

    def _seed(self, key: tuple[str, ...], value: float, t: float, outcome: str) -> tuple[str, None]:
        self._last[key] = (value, t)
        self._last.move_to_end(key)
        if len(self._last) > self._max_keys:
            self._last.popitem(last=False)
        self.counts[outcome] += 1
        return outcome, None

    def __len__(self) -> int:
        return len(self._last)
