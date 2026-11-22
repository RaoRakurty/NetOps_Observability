# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 429(a): consume under a backlog must let offloaded engine work run.

The CI hang this pins (2026-11-14, 2026-11-19, 2026-11-22): in
`test_consume_poll_cadence::test_polls_continue_while_engine_digests_backlog`
the one-shot engine_cycle sat in `await loop.run_in_executor(...)` (the
run_window offload) for 10 s while consume served 800,396 scripted polls, about
80 k/s — the rate of a loop thread that shares the GIL with nobody. The offload
thread was waiting for the GIL and losing every race for it: consume's
cooperative `asyncio.sleep(0)` makes the loop's next select() a zero-timeout
syscall, the GIL is released and retaken within microseconds, and a waiting
thread restarts its switch-interval timer on each release it loses (CPython's
convoy, bpo-7946), so it never forces a switch. Whether it ever wins depends on
wake-up latency, which is why the hang showed on CI runners and never here.

The GIL race cannot be reproduced deterministically, so this file models it
exactly at the boundary that matters: an executor whose worker may START a job
only while the loop thread is blocked in the selector (timeout > 0) — the only
moment a starved thread reliably takes the GIL. Under that model the pre-fix
consume loop (always `sleep(0)`) never lets the job start; the fix
(`main._consume_yield_delay`) does, within one switch interval.
"""
from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import ClassVar

import main
from test_consume_poll_cadence import FakeConsumer, _cancel, _msg


class SelectorGatedExecutor(ThreadPoolExecutor):
    """A worker can start a job only while the loop thread blocks in select()."""

    def __init__(self) -> None:
        super().__init__(max_workers=1, thread_name_prefix="gated-offload")
        self.loop_blocked = threading.Event()
        self.stop = threading.Event()
        self.started = threading.Event()

    def submit(self, fn, /, *args, **kwargs):
        def gated():
            while not self.loop_blocked.wait(0.01):
                if self.stop.is_set():
                    raise RuntimeError("gated executor stopped before the job could start")
            self.started.set()
            return fn(*args, **kwargs)

        return super().submit(gated)


def _gate_selector(loop: asyncio.AbstractEventLoop, ex: SelectorGatedExecutor) -> None:
    """Open the gate for exactly as long as the loop thread is blocked."""
    sel = loop._selector  # type: ignore[attr-defined]  # BaseSelectorEventLoop
    real = sel.select

    def select(timeout=None):
        blocking = timeout is None or timeout > 0
        if blocking:
            ex.loop_blocked.set()
        try:
            return real(timeout)
        finally:
            if blocking:
                ex.loop_blocked.clear()

    sel.select = select


def _drive(monkeypatch, *, handoff_s: float, wait_s: float) -> tuple[bool, int]:
    """Consume an endless buffered backlog while one offloaded job waits.

    Returns (job finished within wait_s, polls served)."""
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_N", 10**9)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_S", 10**9)
    monkeypatch.setattr(main, "CORR_CONSUME_YIELD_EVERY_N", 5)
    monkeypatch.setattr(main, "CORR_CONSUME_GIL_HANDOFF_S", handoff_s)
    monkeypatch.setattr(main, "_CONSUME_LAST_HANDOFF", 0.0)
    ex = SelectorGatedExecutor()
    monkeypatch.setattr(main, "_OFFLOAD_EXECUTOR", ex)
    polls = [0]

    async def fake_handle(topic, event):
        sum(range(50))

    monkeypatch.setattr(main, "handle", fake_handle)

    class Backlog(FakeConsumer):
        created: ClassVar[list] = []

        async def __anext__(self):
            polls[0] += 1
            return _msg(polls[0])  # buffered fast path: never waits on a broker

    monkeypatch.setattr(main, "AIOKafkaConsumer", Backlog)

    async def scenario() -> bool:
        _gate_selector(asyncio.get_running_loop(), ex)
        consume_task = asyncio.create_task(main.consume())
        # Let consume reach its backlog loop before the work is offloaded.
        while polls[0] < 50:
            await asyncio.sleep(0)
        job = asyncio.create_task(main._offload(lambda: "ranked"))
        # A timer wait, not a spin: while consume is runnable the selector is
        # polled with timeout 0, so only consume's own yield can block it.
        await asyncio.wait({job}, timeout=wait_s)
        finished = job.done() and not job.cancelled() and job.result() == "ranked"
        ex.stop.set()
        ex.loop_blocked.set()        # let a parked worker see `stop` and leave
        await _cancel(consume_task)
        if not job.done():
            job.cancel()
        await asyncio.gather(job, return_exceptions=True)
        return finished

    try:
        return asyncio.run(scenario()), polls[0]
    finally:
        ex.shutdown(wait=True, cancel_futures=True)


def test_the_model_reproduces_the_hang_without_the_handoff(monkeypatch):
    """The pre-fix shape, deterministically: a consume loop that only ever
    yields with sleep(0) never blocks, so the starved worker never starts."""
    finished, polls = _drive(monkeypatch, handoff_s=0.0, wait_s=1.0)
    assert not finished, "the model must reproduce the 429(a) hang with the hand-off off"
    assert polls > 1000, f"consume must have been spinning on its backlog (polls={polls})"


def test_consume_hands_the_gil_to_waiting_offload_work(monkeypatch):
    """The fix: with offloaded work waiting, consume's yield blocks briefly and
    the job runs — while the backlog keeps being served."""
    before = main.CONSUME_GIL_HANDOFFS
    finished, polls = _drive(monkeypatch, handoff_s=0.001, wait_s=5.0)
    assert finished, "offloaded work never ran while consume drained a backlog (tracker 429(a))"
    assert main.CONSUME_GIL_HANDOFFS > before
    assert polls > 50


def test_handoff_only_while_offload_work_is_waiting(monkeypatch):
    monkeypatch.setattr(main, "CORR_CONSUME_GIL_HANDOFF_S", 0.001)
    monkeypatch.setattr(main, "_CONSUME_LAST_HANDOFF", 0.0)
    monkeypatch.setattr(main, "_OFFLOAD_PENDING", {})
    monkeypatch.setattr(main, "_OFFLOAD_RUNNING", {})
    assert main._consume_yield_delay(now=100.0) == 0.0, "idle plane: a plain loop yield"
    monkeypatch.setattr(main, "_OFFLOAD_PENDING", {1: 99.0})
    assert main._consume_yield_delay(now=100.0) == 0.001, "queued work: hand the GIL over"
    monkeypatch.setattr(main, "_OFFLOAD_PENDING", {})
    monkeypatch.setattr(main, "_OFFLOAD_RUNNING", {1: 99.0})
    switch = main.sys.getswitchinterval()
    assert main._consume_yield_delay(now=100.0 + switch / 2) == 0.0, (
        "at most one hand-off per switch interval: consume keeps its share")
    assert main._consume_yield_delay(now=100.0 + switch * 1.01) == 0.001, "running work: again"


def test_handoff_disabled_by_zero(monkeypatch):
    monkeypatch.setattr(main, "CORR_CONSUME_GIL_HANDOFF_S", 0.0)
    monkeypatch.setattr(main, "_CONSUME_LAST_HANDOFF", 0.0)
    monkeypatch.setattr(main, "_OFFLOAD_PENDING", {1: 1.0})
    assert main._consume_yield_delay(now=100.0) == 0.0


def test_handoffs_are_counted_in_offload_stats_and_metrics(monkeypatch):
    monkeypatch.setattr(main, "CONSUME_GIL_HANDOFFS", 7)
    assert main.offload_stats()["gil_handoffs_total"] == 7
    resp = asyncio.run(main.metrics_exposition())
    body = resp.body.decode() if hasattr(resp, "body") else str(resp)
    assert "corr_offload_gil_handoffs_total 7" in body.splitlines()
