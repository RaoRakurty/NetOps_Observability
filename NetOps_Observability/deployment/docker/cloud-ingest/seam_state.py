# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Seam-state core — pure, provider-neutral state/transition/freshness logic
shared by every hybrid-seam lane (#105 P0).

Providers publish seam state (BGP session, VPN tunnel, link) as point-in-time
observations with real sampling periods and publication delays. The RCA-grade
events are the TRANSITIONS — and their absence: a state observation that has
outlived its freshness budget is honestly `unknown`, never indefinitely "up"
(prompt Phase 6 rule 4). This module owns those semantics so every provider
lane behaves identically:

  observe()  state sample  → down/up transition events (deduped: a repeated
             DOWN sample emits nothing new; flap = ≥3 transitions in 15 min)
  expire()   stale states  → one `unknown` transition per expired key
  counter_delta()           → monotonic-counter deltas with reset handling

Pure + stdlib only, no IO, no wall-clock (callers pass `now`): the poller owns
IO and persists the tracker via to_state()/from_state() so restarts neither
re-announce old transitions nor lose the overlap.

Every emitted event carries `observed_at` (the provider's own sample time) —
correlation uses observation time, never ingest time.
"""
from __future__ import annotations

FLAP_WINDOW_S = 900
FLAP_COUNT = 3


class SeamStateTracker:
    """Tracks (key → state) and emits transition events. Keys are the
    provider-native identity (tunnel outside IP, BGP peer id, VIF id …) —
    NEVER display names, NEVER aggregated across redundant members."""

    def __init__(self) -> None:
        self._state: dict[str, dict] = {}  # key → {state, observed_at, epoch, transitions:[epochs]}

    # ── persistence (poller state file) ──────────────────────────────────────
    def to_state(self) -> dict:
        return {k: dict(v) for k, v in self._state.items()}

    @classmethod
    def from_state(cls, raw: dict | None) -> "SeamStateTracker":
        t = cls()
        for k, v in (raw or {}).items():
            if isinstance(v, dict) and "state" in v:
                t._state[k] = {
                    "state": str(v.get("state", "")),
                    "observed_at": str(v.get("observed_at", "")),
                    "epoch": float(v.get("epoch", 0.0)),
                    "transitions": [float(x) for x in (v.get("transitions") or [])][-6:],
                }
        return t

    # ── core ──────────────────────────────────────────────────────────────────
    def observe(self, key: str, state: str, observed_at: str, now: float) -> list[dict]:
        """One state sample → 0..2 events: a transition when the state changed,
        plus a flap marker when transitions churn. Repeated identical samples
        refresh freshness and emit nothing (idempotent by construction)."""
        state = (state or "unknown").lower()
        prev = self._state.get(key)
        cur = {"state": state, "observed_at": observed_at, "epoch": now,
               "transitions": list(prev["transitions"]) if prev else []}
        events: list[dict] = []
        if prev is None:
            # first sight: record baseline silently — discovering an already-down
            # seam is inventory truth, not a fresh transition we witnessed.
            self._state[key] = cur
            return events
        if prev["state"] != state:
            cur["transitions"] = [t for t in cur["transitions"] if now - t <= FLAP_WINDOW_S]
            cur["transitions"].append(now)
            events.append({
                "key": key, "from": prev["state"], "to": state,
                "observed_at": observed_at,
                "prev_observed_at": prev["observed_at"],
            })
            if len(cur["transitions"]) >= FLAP_COUNT:
                events.append({
                    "key": key, "from": prev["state"], "to": state,
                    "observed_at": observed_at, "flap": True,
                    "transitions_15m": len(cur["transitions"]),
                })
        self._state[key] = cur
        return events

    def expire(self, freshness_s: float, now: float) -> list[dict]:
        """States not re-observed within their freshness budget become
        `unknown` — one event per key, then the key waits for real data."""
        events: list[dict] = []
        for key, v in self._state.items():
            if v["state"] == "unknown":
                continue
            if now - v["epoch"] > freshness_s:
                events.append({
                    "key": key, "from": v["state"], "to": "unknown",
                    "observed_at": v["observed_at"], "stale_after_s": freshness_s,
                })
                v["state"] = "unknown"
                v["epoch"] = now
        return events

    def current(self, key: str) -> str:
        v = self._state.get(key)
        return v["state"] if v else "unknown"


def counter_delta(prev: float | None, cur: float) -> float:
    """Delta for a cumulative counter. A reset (cur < prev) yields the new
    absolute value — never a negative delta, never a fabricated spike."""
    if prev is None or cur < prev:
        return max(cur, 0.0)
    return cur - prev


def material_route_drop(prev: int | None, cur: int) -> bool:
    """Route-count drop worth evidence: uses EXPECTED context (the previous
    observation), not a fixed threshold — 1000→900 and 3→2 are both material,
    1000→995 is not (prompt Phase 11). Zero after non-zero is always material."""
    if prev is None or cur >= prev:
        return False
    if cur == 0:
        return True
    lost = prev - cur
    return lost / prev >= 0.10 or (prev <= 10 and lost >= 1)
