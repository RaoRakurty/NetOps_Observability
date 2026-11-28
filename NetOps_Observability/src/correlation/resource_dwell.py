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

3. POLLED LANES (owner 2026-11-25, ENGINE_SEMVER 3.9.0). A controller relays
   the device's threshold crossings in POLLS (vManage: every 5 min; lab, 7 days:
   mean lag 280 s), so a raise and its clear seconds apart in event time can
   arrive a whole poll apart — arrival time would release them as "sustained".
   For ``Source.CONTROLLER`` the dwell therefore runs on EVENT time:
   * a clear whose event ts lies in [first raise, first raise + dwell] suppresses
     the group, in either delivery order (a poll can carry the clear first —
     the recent clears per key are remembered, bounded);
   * a group is released once the lane's own watermark — the newest event ts seen
     from that observer (one integration), ``observe`` — passes first raise +
     dwell + ``CORR_RESOURCE_DWELL_POLL_MARGIN_S`` (default 120 s = the vManage
     cursor overlap, nms/poll.go: a row landing up to two minutes late is re-read
     by then), or once a clear arrives later than first raise + dwell (it stood);
   * the released signal is stamped at the PROOF time, first raise + dwell (its
     stored signal_id kept, as the H14 clamp does; its own onset kept in
     ``attrs.dwell_onset``): by the time a polled lane can prove 300 s it is
     already ~700 s past the raise, beyond the window's 516.5 s horizon, and an
     unstamped release would be pruned before it ever correlated;
   * a lane that stops advancing (controller silent) releases the group after
     ``dwell + margin + POLL_STALL_S`` of arrival time, counted (fail-open, like
     the bound).
   ``CORR_RESOURCE_DWELL_POLLED=0`` is its kill switch: controller raises pass
   unheld, exactly as in 3.8.0.

Pure apart from the injectable clock; tenant-keyed by construction.
"""
from __future__ import annotations

import os
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import replace as dc_replace
from datetime import datetime, timezone
from typing import Final

from signals import Severity, Signal, Source

RAISE_KIND: Final = "device_resource_anomaly"
CLEAR_KIND: Final = "device_resource_anomaly_clear"
CPU_CONTEXT_KIND: Final = "device_cpu_context"
THRESHOLD_RESOURCES: Final = frozenset({"cpu", "memory"})
EVENT_SOURCES: Final = frozenset({Source.TRAP, Source.SYSLOG})
#: Lanes that deliver in polls, dwelled on event time (3.9.0).
POLLED_SOURCES: Final = frozenset({Source.CONTROLLER})

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
#: vManage's cursor overlap (nms/poll.go vmanageCursorOverlap): a row landing up
#: to this late is re-read, so the lane watermark this far past the dwell proves
#: no clear inside it is still on its way.
DEFAULT_POLL_MARGIN_S: Final = 120.0
#: A polled lane silent this long past dwell + margin (arrival time) releases its
#: pending groups — two default poll intervals (nms/scheduler.go, 5 min).
POLL_STALL_S: Final = 600.0
#: A polled group is never released less than this long (arrival) after its first
#: raise: one poll's records are published within seconds, so a clear later in the
#: same poll is admitted before the group can go.
POLL_SETTLE_S: Final = 30.0
#: Recent clears remembered per polled key (a poll can carry several crossings).
RECENT_CLEARS: Final = 16


def dwell_seconds() -> float:
    """CORR_RESOURCE_DWELL_S, default 300; 0 restores 3.7.0 (no dwell)."""
    return _env_float("CORR_RESOURCE_DWELL_S", DEFAULT_DWELL_S)


def poll_margin_seconds() -> float:
    """CORR_RESOURCE_DWELL_POLL_MARGIN_S, default 120."""
    return _env_float("CORR_RESOURCE_DWELL_POLL_MARGIN_S", DEFAULT_POLL_MARGIN_S)


def polled_enabled() -> bool:
    """CORR_RESOURCE_DWELL_POLLED (default on); 0 restores 3.8.0 for controllers."""
    return os.environ.get("CORR_RESOURCE_DWELL_POLLED", "1").strip().lower() not in (
        "0", "false", "no", "off")


def threshold_resource(sig: Signal, *, polled: bool = True) -> str | None:
    """'cpu' / 'memory' when `sig` is an event-lane (or, with `polled`, a
    controller-relayed) resource-threshold raise or clear, else None. The metric
    lane's CUSUM CPU episodes are NOT threshold alarms (they carry no `resource`
    attr) and are never held."""
    if sig.kind not in (RAISE_KIND, CLEAR_KIND):
        return None
    if sig.source not in EVENT_SOURCES and not (polled and sig.source in POLLED_SOURCES):
        return None
    res = str(sig.attrs.get("resource") or "").strip().lower()
    return res if res in THRESHOLD_RESOURCES else None


@dataclass
class _Pending:
    best: Signal
    deadline: float
    raises: int = 1


@dataclass
class _PolledPending:
    best: Signal
    first_ts: float          # earliest raise's event ts (epoch s)
    lane: tuple[str, str]    # (tenant, observer_id): whose watermark proves it
    settle_at: float         # arrival clock: never released before this
    stall_at: float          # arrival clock: released fail-open after this
    raises: int = 1
    stood: bool = False      # a clear later than first_ts + dwell proved it
    ended: float | None = None  # that clear's event ts (the earliest such)


class ResourceDwell:
    """The per-process dwell gate. `admit` decides at window entry; `due` hands
    back the raises whose dwell expired (call it from the engine loop)."""

    def __init__(self, dwell_s: float | None = None, max_groups: int | None = None,
                 clock: Callable[[], float] = time.monotonic, *,
                 polled: bool | None = None, poll_margin_s: float | None = None) -> None:
        self.dwell_s = dwell_seconds() if dwell_s is None else max(0.0, dwell_s)
        self.max_groups = (_env_int("CORR_RESOURCE_DWELL_MAX", DEFAULT_MAX)
                           if max_groups is None else max(1, max_groups))
        self.polled = polled_enabled() if polled is None else polled
        self.poll_margin_s = (poll_margin_seconds() if poll_margin_s is None
                              else max(0.0, poll_margin_s))
        self._clock = clock
        # Polled lanes (3.9.0): event-time groups, the per-lane watermark and the
        # recent clears, each bounded by max_groups (LRU).
        self._ppending: OrderedDict[tuple[str, str, str], _PolledPending] = OrderedDict()
        self._pstanding: OrderedDict[tuple[str, str, str], float] = OrderedDict()
        self._lane_wm: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._clears: OrderedDict[tuple[str, str, str], tuple[float, ...]] = OrderedDict()
        self.polled_suppressed = 0       # polled raises cancelled by an event-time clear
        self.polled_released = 0         # polled groups released on the lane watermark
        self.polled_stood_released = 0   # polled groups released by a clear past the dwell
        self.polled_stall_released = 0   # polled groups released because the lane stalled
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
        return len(self._pending) + len(self._ppending)

    def observe(self, sig: Signal) -> None:
        """Advance the polled lane's watermark (call for EVERY polled-lane signal
        at window entry, before `admit`): the newest event ts that observer has
        delivered for the tenant."""
        if not (self.enabled and self.polled) or sig.source not in POLLED_SOURCES:
            return
        lane = (sig.tenant_id, sig.observer.observer_id)
        ts = sig.ts.timestamp()
        if ts > self._lane_wm.get(lane, float("-inf")):
            self._lane_wm[lane] = ts
        self._lane_wm.move_to_end(lane)
        while len(self._lane_wm) > self.max_groups:
            self._lane_wm.popitem(last=False)

    def admit(self, sig: Signal, device: str) -> str:
        """PASS (the caller buffers `sig` now) or HOLD (the gate keeps it).
        `device` is the tenant-canonical device key (trap and syslog twins must
        agree on it)."""
        if not self.enabled:
            return PASS
        res = threshold_resource(sig, polled=self.polled)
        if res is None:
            return PASS
        key = (sig.tenant_id, device or sig.entity_id, res)
        if sig.source in POLLED_SOURCES:
            return self._admit_polled(sig, key)
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

    # ── polled lanes (3.9.0): event time ────────────────────────────────────
    def _admit_polled(self, sig: Signal, key: tuple[str, str, str]) -> str:
        ts = sig.ts.timestamp()
        if sig.kind == CLEAR_KIND:
            self._note_clear(key, ts)
            entry = self._ppending.get(key)
            if entry is not None and ts >= entry.first_ts:
                if ts <= entry.first_ts + self.dwell_s:
                    del self._ppending[key]
                    self.polled_suppressed += entry.raises
                else:
                    entry.stood = True      # it stood past the dwell, then cleared
                    entry.ended = ts if entry.ended is None else min(entry.ended, ts)
            standing = self._pstanding.get(key)
            if standing is not None and ts >= standing:
                del self._pstanding[key]
            return PASS
        # A clear already delivered (a poll can carry it first) inside this
        # raise's dwell suppresses it; one past the dwell proves it stood.
        later = [c for c in self._clears.get(key, ()) if c >= ts]
        if later and min(later) <= ts + self.dwell_s:
            self.polled_suppressed += 1
            return HOLD
        standing = self._pstanding.get(key)
        if standing is not None and ts >= standing:
            self._pstanding.move_to_end(key)
            self.passed_standing += 1
            return PASS
        entry = self._ppending.get(key)
        if entry is not None:
            entry.raises += 1
            self.folded += 1
            entry.first_ts = min(entry.first_ts, ts)
            if _SEV_RANK[sig.severity] > _SEV_RANK[entry.best.severity]:
                entry.best = sig
            return HOLD
        if len(self._ppending) >= self.max_groups:
            okey, old = self._ppending.popitem(last=False)
            self._overflow.append(self._stamp(old))
            self._mark_polled_standing(okey, old.first_ts)
            self.overflow_released += 1
        now = self._clock()
        self._ppending[key] = _PolledPending(
            best=sig, first_ts=ts, lane=(sig.tenant_id, sig.observer.observer_id),
            settle_at=now + POLL_SETTLE_S,
            stall_at=now + self.dwell_s + self.poll_margin_s + POLL_STALL_S,
            stood=bool(later), ended=min(later) if later else None)
        return HOLD

    def _note_clear(self, key: tuple[str, str, str], ts: float) -> None:
        seen = self._clears.get(key, ())
        self._clears[key] = tuple(sorted((*seen, ts)))[-RECENT_CLEARS:]
        self._clears.move_to_end(key)
        while len(self._clears) > self.max_groups:
            self._clears.popitem(last=False)

    def _stamp(self, entry: _PolledPending) -> Signal:
        """The released signal at the newest event time the lane PROVES the
        condition still stood — its watermark less the margin (complete up to
        there, no clear seen), no later than the clear that ended it, never before
        first raise + dwell — keeping the stored signal_id and naming its onset."""
        best = entry.best
        still = self._lane_wm.get(entry.lane, float("-inf")) - self.poll_margin_s
        if entry.ended is not None:
            still = min(still, entry.ended)
        proof = max(best.ts.timestamp(), entry.first_ts + self.dwell_s, still)
        onset = datetime.fromtimestamp(entry.first_ts, tz=timezone.utc)
        return dc_replace(
            best, ts=datetime.fromtimestamp(proof, tz=timezone.utc),
            stored_signal_id=str(best.signal_id),
            attrs={**best.attrs, "dwell_onset": onset.isoformat()})

    def _mark_polled_standing(self, key: tuple[str, str, str], first_ts: float) -> None:
        self._pstanding[key] = first_ts
        self._pstanding.move_to_end(key)
        while len(self._pstanding) > self.max_groups:
            self._pstanding.popitem(last=False)
            self.standing_evicted += 1

    def _due_polled(self, now: float) -> list[Signal]:
        out: list[Signal] = []
        for key in list(self._ppending):
            entry = self._ppending[key]
            if now < entry.settle_at:
                continue
            wm = self._lane_wm.get(entry.lane, float("-inf"))
            if entry.stood:
                self.polled_stood_released += 1
            elif wm >= entry.first_ts + self.dwell_s + self.poll_margin_s:
                self.polled_released += 1
            elif now >= entry.stall_at:
                self.polled_stall_released += 1
            else:
                continue
            del self._ppending[key]
            if not entry.stood:
                self._mark_polled_standing(key, entry.first_ts)
            self.released += 1
            out.append(self._stamp(entry))
        return out

    def due(self) -> list[Signal]:
        """The raises to buffer now: every group whose dwell expired (insertion
        order = deadline order, the dwell being one constant) plus any released
        early by the bound, then the polled groups proven on event time."""
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
        if self._ppending:
            out.extend(self._due_polled(now))
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
        self._ppending.clear()
        self._pstanding.clear()
        self._lane_wm.clear()
        self._clears.clear()

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
            f"corr_resource_dwell_pending {self.pending_count()}",
            ("# HELP corr_resource_dwell_polled_total Controller-relayed CPU/memory threshold "
             "groups decided on EVENT time (3.9.0), by outcome."),
            "# TYPE corr_resource_dwell_polled_total counter",
            f'corr_resource_dwell_polled_total{{outcome="suppressed"}} {self.polled_suppressed}',
            f'corr_resource_dwell_polled_total{{outcome="released"}} {self.polled_released}',
            f'corr_resource_dwell_polled_total{{outcome="stood"}} {self.polled_stood_released}',
            f'corr_resource_dwell_polled_total{{outcome="stall_released"}} {self.polled_stall_released}',
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
            "polled": self.polled,
            "poll_margin_s": self.poll_margin_s,
            "polled_pending": len(self._ppending),
            "polled_suppressed": self.polled_suppressed,
            "polled_released": self.polled_released,
            "polled_stood_released": self.polled_stood_released,
            "polled_stall_released": self.polled_stall_released,
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
