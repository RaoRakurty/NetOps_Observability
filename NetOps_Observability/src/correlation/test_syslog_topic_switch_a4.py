# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""A4 — the pre-screened syslog lane is a per-deployment SWITCH, default OFF.

`CORR_SYSLOG_TOPIC` may point the syslog lane at the vector-PRE-SCREENED
`netops.syslog.control` feed instead of the raw `netops.syslog` one. What is
gated here is that it changes NOTHING until someone sets it, that when set it
moves EXACTLY that one entry, and that the lane dispatch follows the switch —
a TOPICS-only swap would subscribe to the new topic and then drop every line on
the floor, because `_handle_lane` would match no branch for it.

The switch is deliberately not a default: pointing the engine at a pre-screened
feed changes which lines can ever become evidence, so it is an accuracy and an
accounting change and needs a release-qualify leg (INVARIANTS §10) plus a Read
ACL for the correlation principal on whatever topic it names.
"""
from __future__ import annotations

import asyncio

import main

RAW = "netops.syslog"
SCREENED = "netops.syslog.control"


def test_the_default_topic_list_is_unchanged():
    assert main.CORR_SYSLOG_TOPIC == RAW
    assert main.TOPICS[:len(main.LANE_TOPICS)] == main.LANE_TOPICS
    assert RAW in main.TOPICS and SCREENED not in main.TOPICS
    # the 12 network lanes, in their original order, plus the evidence lanes
    assert len(main.LANE_TOPICS) == 12
    assert main.TOPICS == main.LANE_TOPICS + list(main.CORR_EVIDENCE_TOPICS)


def test_the_override_swaps_exactly_that_one_entry():
    swapped = main.apply_syslog_topic(main.TOPICS, SCREENED)
    assert len(swapped) == len(main.TOPICS)
    moved = [(a, b) for a, b in zip(main.TOPICS, swapped) if a != b]
    assert moved == [(RAW, SCREENED)]
    # …and it is idempotent + a no-op for the default value.
    assert main.apply_syslog_topic(main.TOPICS, RAW) == main.TOPICS
    assert main.apply_syslog_topic(swapped, SCREENED) == swapped


def test_the_lane_dispatch_follows_the_switch(monkeypatch):
    """The half a TOPICS-only edit would have missed: whichever topic the
    switch names must reach `handle_syslog`, and nothing else may."""
    seen: list[dict] = []

    async def fake_handle_syslog(ev: dict) -> None:
        seen.append(ev)

    monkeypatch.setattr(main, "handle_syslog", fake_handle_syslog)
    monkeypatch.setattr(main, "CORR_SYSLOG_TOPIC", SCREENED)
    asyncio.run(main._handle_lane(SCREENED, {"hostname": "r1"}))
    assert len(seen) == 1
    # the raw topic is no longer this deployment's syslog lane: it matches no
    # branch, so it is a no-op rather than a silently mis-routed lane.
    asyncio.run(main._handle_lane(RAW, {"hostname": "r1"}))
    assert len(seen) == 1
