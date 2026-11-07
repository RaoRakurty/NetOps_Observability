# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""One signal per BGP session transition, however many trap families report it.

tracker 376. IOS-XE with every BGP trap family enabled sends up to SIX
notifications for ONE transition (RFC 4273 bgpBackwardTransition + cbgp* +
cbgpPeer2*, recorded on the lab 2026-11-01, all within ~0.5 s). Arista does the
same with RFC 4273 + its BGP4-V2 family. Each classifies into the same
`bgp_adjacency_change` on the same `device:peer` entity, but their timestamps
differ by milliseconds, so their `signal_id`s differ and the engine would count
one transition six times (flap counts, proactive heartbeats, evidence volume).

A transition is identified by (tenant, entity, new state): a signal whose
state equals the LAST state emitted for that entity, within `window_s` of it,
is the same transition reported by another family and is collapsed. A real
flap alternates states (down → up → down), so every leg of it still emits,
however fast. Deliberately NOT keyed on the trap OID or rule: the whole point
is that different families describe one event.

Partitioning makes this correct per replica: producers key every topic by
tenant, so one tenant's traps are always consumed by the same replica. A
restart forgets the window, which can let ONE duplicate through — the same
behaviour as before this module, never a lost transition.

Bounded: at most `max_keys` entities are remembered (LRU), and an entry older
than the window can never suppress anything, so eviction never changes an
answer that matters.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime

#: Every family's notification for one transition arrived within 0.45 s on the
#: lab; a 5 s window absorbs agent queueing and receiver batching without
#: approaching a BGP keepalive/hold timescale (a real re-flap to the SAME state
#: needs the opposite transition in between, which resets the entry anyway).
DEFAULT_WINDOW_S = 5.0
DEFAULT_MAX_KEYS = 65_536


class TransitionCollapser:
    """Decides whether a classified transition signal is a NEW transition."""

    __slots__ = ("_last", "_max_keys", "_window_s", "collapsed")

    def __init__(self, window_s: float = DEFAULT_WINDOW_S,
                 max_keys: int = DEFAULT_MAX_KEYS) -> None:
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        if max_keys <= 0:
            raise ValueError("max_keys must be positive")
        self._window_s = float(window_s)
        self._max_keys = int(max_keys)
        self._last: OrderedDict[tuple[str, str], tuple[str, float]] = OrderedDict()
        self.collapsed = 0

    def admit(self, tenant: str, entity_id: str, state: str, ts: datetime) -> bool:
        """True → emit (a new transition); False → collapse (a duplicate report).

        A signal without a state carries no transition identity and is always
        admitted — collapsing on the entity alone could swallow a real event.
        """
        if not state:
            return True
        key = (tenant, entity_id)
        t = ts.timestamp()
        prev = self._last.get(key)
        if prev is not None and prev[0] == state and abs(t - prev[1]) <= self._window_s:
            # Keep the FIRST report's time: a family that keeps re-sending must
            # not stretch the window forever.
            self._last.move_to_end(key)
            self.collapsed += 1
            return False
        self._last[key] = (state, t)
        self._last.move_to_end(key)
        if len(self._last) > self._max_keys:
            self._last.popitem(last=False)
        return True

    def __len__(self) -> int:
        return len(self._last)
