# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Syslog burst detection — long-form severity parity (perf/correctness
defect #5, main.SEVERITY_WEIGHT).

Vector's syslog_normalized passes FortiOS kv.level through VERBATIM
('critical' / 'error' / 'emergency'), but SEVERITY_WEIGHT keyed only the
abbreviated RFC 3164 forms ('crit' / 'err' / 'emerg') — so 50 FortiGate
level=critical lines in 60s scored weight 0 and the burst finding silently
never fired, while identical Cisco 'crit' traffic did. These tests were
written FAILING against that map and pin the fix:

  * the owner fixture: 50 level=critical events in 60s → the burst finding
  * long-form/short-form weight parity, plus 'panic'/'emerg' parity with the
    aggregator's severity reconcile map
"""

from __future__ import annotations

import asyncio

import pytest

import main


def run(coro):
    return asyncio.run(coro)


class FakeCH:
    def __init__(self):
        self.rows: list[dict] = []

    async def insert(self, table, rows, dedup_token=""):
        self.rows.extend({"_table": table, **r} for r in rows)
        return True


@pytest.fixture()
def burst_env(monkeypatch):
    ch = FakeCH()
    monkeypatch.setattr(main, "ch", ch)
    # Isolate the burst tracker from the signal-extraction lanes (they have
    # their own tests) and from the registry surface.
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", False)
    monkeypatch.setattr(main, "verified_tenant",
                        lambda claimed, identity, lane, **kw: "t1")
    main.SYSLOG_BUCKET.clear()
    yield ch
    main.SYSLOG_BUCKET.clear()


def _findings(ch):
    return [r for r in ch.rows
            if r["_table"] == "netops.findings" and r["kind"] == "correlation"]


def test_fifty_fortigate_critical_events_fire_the_burst_finding(burst_env):
    """The owner fixture: 50 level=critical in 60s MUST cross the threshold
    (weight 6 × events ≥ SYSLOG_THRESHOLD=30). Pre-fix weight was 0 → silent."""
    ch = burst_env

    async def scenario():
        for i in range(50):
            await main.handle_syslog(
                {"hostname": "fw-dallas-1", "severity": "critical",
                 "message": f"log_id=0100032002 level=critical event {i}"})

    run(scenario())
    found = _findings(ch)
    assert found, "50 critical events in 60s produced NO burst finding"
    assert found[0]["device"] == "fw-dallas-1"
    assert found[0]["score"] >= main.SYSLOG_THRESHOLD


def test_long_form_error_severity_scores(burst_env):
    ch = burst_env

    async def scenario():
        for _ in range(10):   # 10 × 5 = 50 ≥ 30
            await main.handle_syslog({"hostname": "fw2", "severity": "error"})

    run(scenario())
    assert _findings(ch), "long-form 'error' must weigh like 'err'"


def test_long_short_form_parity():
    w = main.SEVERITY_WEIGHT
    assert w["critical"] == w["crit"] == 6
    assert w["error"] == w["err"] == 5
    assert w["emergency"] == w["emerg"] == 8
    assert w["warn"] == w["warning"] == 3
    assert w["information"] == w["informational"] == w["info"] == 1
    # aggregator parity: PRI-0 short keywords 'emerg' AND 'panic' are the most
    # severe class (the sysint reconcile maps both to critical).
    assert w["panic"] == w["emerg"] == 8


def test_informational_flood_still_does_not_fire(burst_env):
    """Parity must not break the noise floor: 25 information-level lines score
    25 < 30 — no burst finding for chatty-but-healthy devices."""
    ch = burst_env

    async def scenario():
        for _ in range(25):
            await main.handle_syslog({"hostname": "fw3", "severity": "information"})

    run(scenario())
    assert not _findings(ch)
