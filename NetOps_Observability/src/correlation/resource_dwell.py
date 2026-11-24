# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Stage [1] resource-threshold dwell and busy-poll CPU context (tracker 489,
owner 2026-11-24, ENGINE_SEMVER 3.8.0).

Two rules, both applied at the single window-entry chokepoint
(`main.buffer_signal`), so `corr_signals` — written by every lane BEFORE the
window — keeps every raw raise, and replay (which never comes through
`buffer_signal`) is untouched.

1. DWELL. A device's own CPU / memory THRESHOLD alarm (a trap or syslog row of
   kind ``device_resource_anomaly`` carrying ``attrs.resource`` ∈ {cpu, memory})
   is fault evidence only when no clear for the same (tenant, device, resource)
   arrives within ``CORR_RESOURCE_DWELL_S`` (default 300 s). Lab, 7 days: 92 % of
   the vEdges' critical CPU raises cleared within 120 s (median 4 s) and each one
   opened or padded an object. A raise cleared inside the dwell is SUPPRESSED —
   counted, never buffered. A sustained raise is released ONCE at expiry, with
   its own ts, severity and signal_id (the highest-severity raise of the group,
   earliest on a tie), so the trap and its syslog twin — the same crossing seen
   twice, named ``vedge-20-…`` and ``vEdge-20`` — become one signal: the caller
   keys the device through the tenant's resolver. While a released raise stands
   (no clear yet), further raises pass straight through: the condition is
   already proven. A clear always passes through (a recovery is never a node)
   and ends the condition.

   Bounded (§9): at most ``CORR_RESOURCE_DWELL_MAX`` pending groups and as many
   standing ones; an overflow RELEASES the oldest pending raise early instead of
   dropping it (fail-open: evidence is never lost to the bound), counted.
   Restart: the pending map is process memory and deliberately not persisted —
   a raise pending at a restart is not released (its raw row stays in
   corr_signals); a condition that is still true re-raises on the device's next
   crossing. ``CORR_RESOURCE_DWELL_S=0`` is the kill switch: byte-identical to
   3.7.0 (every raise passes).

2. BUSY-POLL CONTEXT. Some platforms run a poll-mode data plane and report ~100 %
   CPU by design (catalog.BUSY_POLL_PLATFORMS, matched on the registry's model).
   Their CPU signals — threshold alarms and the metric lane's CPU episodes — are
   recast to ``device_cpu_context`` capped at warn: visible in the window and
   evidence lists, but a component made only of context kinds opens no object
   (engine stage [5]) and no template reads the kind, so it never headlines; a
   real fault on the device folds it in. The recast keeps signal_id (kind is not
   part of it).

Pure apart from the injectable clock; tenant-keyed by construction.
"""
from __future__ import annotations

import os
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import replace as dc_replace
from typing import Final

from signals import Severity, Signal, Source

RAISE_KIND: Final = "device_resource_anomaly"
CLEAR_KIND: Final = "device_resource_anomaly_clear"
CPU_CONTEXT_KIND: Final = "device_cpu_context"
THRESHOLD_RESOURCES: Final = frozenset({"cpu", "memory"})
EVENT_SOURCES: Final = frozenset({Source.TRAP, Source.SYSLOG})

PASS: Final = "pass"
HOLD: Final = "hold"

_SEV_RANK: Final = {Severity.INFO: 0, Severity.WARN: 1, Severity.HIGH: 2, Severity.CRIT: 3}


def _env_float(name: str, default: float) -> float:
    try:
        return max(0.0, float(os.environ.get(name, default)))
    except ValueError:
        return default


def _env_int(name: str, default: int, floor: int = 1) -> int:
    try:
        return max(floor, int(os.environ.get(name, default)))
    except ValueError:
        return default


DEFAULT_DWELL_S: Final = 300.0
DEFAULT_MAX: Final = 10_000


def dwell_seconds() -> float:
    """CORR_RESOURCE_DWELL_S, default 300; 0 restores 3.7.0 (no dwell)."""
    return _env_float("CORR_RESOURCE_DWELL_S", DEFAULT_DWELL_S)


def threshold_resource(sig: Signal) -> str | None:
    """'cpu' / 'memory' when `sig` is an event-lane resource-threshold raise or
    clear, else None. The metric lane's CUSUM CPU episodes are NOT threshold
    alarms (they carry no `resource` attr) and are never held."""
    if sig.source not in EVENT_SOURCES or sig.kind not in (RAISE_KIND, CLEAR_KIND):
        return None
    res = str(sig.attrs.get("resource") or "").strip().lower()
    return res if res in THRESHOLD_RESOURCES else None


@dataclass
class _Pending:
    best: Signal
    deadline: float
    raises: int = 1


class ResourceDwell:
    """The per-process dwell gate. `admit` decides at window entry; `due` hands
    back the raises whose dwell expired (call it from the engine loop)."""

    def __init__(self, dwell_s: float | None = None, max_groups: int | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.dwell_s = dwell_seconds() if dwell_s is None else max(0.0, dwell_s)
        self.max_groups = (_env_int("CORR_RESOURCE_DWELL_MAX", DEFAULT_MAX)
                           if max_groups is None else max(1, max_groups))
        self._clock = clock
        self._pending: OrderedDict[tuple[str, str, str], _Pending] = OrderedDict()
        self._standing: OrderedDict[tuple[str, str, str], float] = OrderedDict()
        self._overflow: list[Signal] = []
        self.suppressed = 0          # raises cancelled by a clear inside the dwell
        self.released = 0            # groups released at expiry (one signal each)
        self.folded = 0              # extra raises folded into a pending group (twins, re-raises)
        self.passed_standing = 0     # raises passed while a released condition stands
        self.overflow_released = 0   # pending groups released early by the bound
        self.standing_evicted = 0    # standing entries dropped by the bound

    @property
    def enabled(self) -> bool:
        return self.dwell_s > 0

    def pending_count(self) -> int:
        return len(self._pending)

    def admit(self, sig: Signal, device: str) -> str:
        """PASS (the caller buffers `sig` now) or HOLD (the gate keeps it).
        `device` is the tenant-canonical device key (trap and syslog twins must
        agree on it)."""
        if not self.enabled:
            return PASS
        res = threshold_resource(sig)
        if res is None:
            return PASS
        key = (sig.tenant_id, device or sig.entity_id, res)
        if sig.kind == CLEAR_KIND:
            entry = self._pending.pop(key, None)
            if entry is not None:
                self.suppressed += entry.raises
            self._standing.pop(key, None)
            return PASS
        if key in self._standing:
            self._standing.move_to_end(key)
            self.passed_standing += 1
            return PASS
        entry = self._pending.get(key)
        if entry is not None:
            entry.raises += 1
            self.folded += 1
            if _SEV_RANK[sig.severity] > _SEV_RANK[entry.best.severity]:
                entry.best = sig
            return HOLD
        if len(self._pending) >= self.max_groups:
            okey, old = self._pending.popitem(last=False)
            self._overflow.append(old.best)
            self._mark_standing(okey)
            self.overflow_released += 1
        self._pending[key] = _Pending(best=sig, deadline=self._clock() + self.dwell_s)
        return HOLD

    def due(self) -> list[Signal]:
        """The raises to buffer now: every group whose dwell expired (insertion
        order = deadline order, the dwell being one constant) plus any released
        early by the bound."""
        out, self._overflow = self._overflow, []
        now = self._clock()
        while self._pending:
            key, entry = next(iter(self._pending.items()))
            if entry.deadline > now:
                break
            self._pending.popitem(last=False)
            self._mark_standing(key)
            self.released += 1
            out.append(entry.best)
        return out

    def _mark_standing(self, key: tuple[str, str, str]) -> None:
        self._standing[key] = self._clock()
        self._standing.move_to_end(key)
        while len(self._standing) > self.max_groups:
            self._standing.popitem(last=False)
            self.standing_evicted += 1

    def reset(self) -> None:
        self._pending.clear()
        self._standing.clear()
        self._overflow.clear()

    def metric_lines(self) -> tuple[str, ...]:
        return (
            ("# HELP corr_resource_flap_suppressed_total Device CPU/memory threshold raises "
             "cleared inside the dwell (tracker 489): counted and kept in corr_signals, never "
             "fault evidence."),
            "# TYPE corr_resource_flap_suppressed_total counter",
            f"corr_resource_flap_suppressed_total {self.suppressed}",
            ("# HELP corr_resource_dwell_released_total Sustained CPU/memory threshold raises "
             "released as one signal at dwell expiry."),
            "# TYPE corr_resource_dwell_released_total counter",
            f"corr_resource_dwell_released_total {self.released}",
            ("# HELP corr_resource_dwell_folded_total Extra raises (trap/syslog twins, "
             "re-raises) folded into a pending group."),
            "# TYPE corr_resource_dwell_folded_total counter",
            f"corr_resource_dwell_folded_total {self.folded}",
            ("# HELP corr_resource_dwell_overflow_released_total Pending groups released "
             "early because the bound was reached (fail-open)."),
            "# TYPE corr_resource_dwell_overflow_released_total counter",
            f"corr_resource_dwell_overflow_released_total {self.overflow_released}",
            "# HELP corr_resource_dwell_pending Raises currently inside the dwell.",
            "# TYPE corr_resource_dwell_pending gauge",
            f"corr_resource_dwell_pending {len(self._pending)}",
        )

    def health(self) -> dict:
        return {
            "dwell_s": self.dwell_s,
            "pending": len(self._pending),
            "standing": len(self._standing),
            "suppressed": self.suppressed,
            "released": self.released,
            "folded": self.folded,
            "passed_standing": self.passed_standing,
            "overflow_released": self.overflow_released,
            "standing_evicted": self.standing_evicted,
        }


def is_cpu_signal(sig: Signal) -> bool:
    """A CPU signal of the device-resource kind: an event-lane threshold alarm
    with resource=cpu, or the metric lane's CPU episode (device_cpu_*)."""
    if sig.kind != RAISE_KIND:
        return False
    if str(sig.attrs.get("resource") or "").strip().lower() == "cpu":
        return True
    return sig.source == Source.METRIC and sig.metric_name.startswith("device_cpu")


def recast_busy_poll(sig: Signal, model: str | None, platforms: frozenset[str]) -> Signal:
    """`sig` recast to the CPU-context kind (capped at warn) when it is a CPU
    signal from a busy-poll platform; otherwise `sig` unchanged."""
    if not model or model.strip().lower() not in platforms or not is_cpu_signal(sig):
        return sig
    sev = sig.severity if _SEV_RANK[sig.severity] <= _SEV_RANK[Severity.WARN] else Severity.WARN
    return dc_replace(sig, kind=CPU_CONTEXT_KIND, severity=sev)
