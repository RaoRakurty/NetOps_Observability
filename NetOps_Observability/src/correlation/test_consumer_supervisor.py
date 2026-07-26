"""Consumer-supervisor resilience (§10) — run with: python3 -m pytest test_consumer_supervisor.py

Pins the 2026-07-14 live incident: the supervisor logged "restarting in 1s"
and then awaited consumer.stop() UNBOUNDED against a crash-looping broker —
stop() hung forever and the engine consumed nothing for 5.5 hours while the
process looked healthy. The guarantee under test: no broker-facing await can
wedge the supervisor; a hung stop() or start() is abandoned on a bounded
timeout and a FRESH consumer always follows.
"""
import asyncio
from typing import ClassVar

import main


class FakeConsumer:
    """Scriptable AIOKafkaConsumer stand-in. Behavior keyed by instance index."""

    def __init__(self, *topics, **kwargs):
        self.created.append(self)
        self.index = len(self.created)

    async def start(self):
        return None

    async def stop(self):
        return None

    def __aiter__(self):
        return self

    async def __anext__(self):
        await asyncio.sleep(3600)  # healthy consumer idles; test cancels


async def _run_until(event: asyncio.Event, timeout: float) -> bool:
    task = asyncio.create_task(main.consume())
    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
        return True
    except asyncio.TimeoutError:
        return False
    finally:
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=1.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass


def test_hung_stop_never_wedges_the_supervisor(monkeypatch):
    """First consumer's handler dies AND its stop() hangs forever — the exact
    live wedge. A second consumer must still come up."""
    monkeypatch.setattr(main, "CONSUMER_STOP_TIMEOUT_S", 0.1)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 0.3)

    async def scenario() -> bool:
        reached_second = asyncio.Event()

        class Scripted(FakeConsumer):
            created: ClassVar[list] = []

            async def start(self):
                if self.index == 2:
                    reached_second.set()

            async def stop(self):
                if self.index == 1:
                    await asyncio.sleep(3600)  # the hang

            async def __anext__(self):
                if self.index == 1:
                    raise RuntimeError("handler blew up (CH insert failed)")
                await asyncio.sleep(3600)

        monkeypatch.setattr(main, "AIOKafkaConsumer", Scripted)
        return await _run_until(reached_second, timeout=5.0)

    assert asyncio.run(scenario()), "supervisor wedged on hung consumer.stop()"


def test_hung_start_never_wedges_the_supervisor(monkeypatch):
    """start() against a wedged broker must time out and retry, not block forever."""
    monkeypatch.setattr(main, "CONSUMER_STOP_TIMEOUT_S", 0.1)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 0.3)

    async def scenario() -> bool:
        reached_second = asyncio.Event()

        class Scripted(FakeConsumer):
            created: ClassVar[list] = []

            async def start(self):
                if self.index == 1:
                    await asyncio.sleep(3600)  # broker never answers
                reached_second.set()

        monkeypatch.setattr(main, "AIOKafkaConsumer", Scripted)
        return await _run_until(reached_second, timeout=5.0)

    assert asyncio.run(scenario()), "supervisor wedged on hung consumer.start()"


def test_offsets_commit_only_after_handling(monkeypatch):
    """Tracker #126 (write-integrity criterion 8): offsets advance ONLY behind
    the handler. A handled message commits (batched); a message whose handler
    dies before returning is NEVER committed past — the restart replays it."""
    monkeypatch.setattr(main, "CONSUMER_STOP_TIMEOUT_S", 0.2)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 0.3)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_N", 1)   # commit every message
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_S", 0.0)
    monkeypatch.setattr(main, "CORR_QUARANTINE_BURST_MAX", 10_000)

    class Msg:
        topic, partition, offset = "netops.metrics", 0, 0
        # RAW wire bytes: the consumer is built with NO value_deserializer so a
        # malformed payload fails inside the per-event try, not above it.
        value: ClassVar[bytes] = b'{"k": 1}'

    commits: list[int] = []
    handled: list[int] = []

    async def fake_handle(topic, event):
        handled.append(1)
        if len(handled) == 3:
            # Simulate death BEFORE the outcome is durable — this message's
            # offset must not be committed. (CancelledError passes straight
            # through the per-event isolation, like a real crash/shutdown.)
            raise asyncio.CancelledError()

    monkeypatch.setattr(main, "handle", fake_handle)

    async def scenario() -> bool:
        done = asyncio.Event()

        class Scripted(FakeConsumer):
            created: ClassVar[list] = []

            def __init__(self, *topics, **kwargs):
                super().__init__(*topics, **kwargs)
                assert kwargs.get("enable_auto_commit") is False, (
                    "#126: auto-commit must be OFF")
                self.sent = 0

            async def commit(self):
                commits.append(len(handled))

            async def __anext__(self):
                self.sent += 1
                if self.sent > 3:
                    done.set()
                    await asyncio.sleep(3600)
                return Msg()

        monkeypatch.setattr(main, "AIOKafkaConsumer", Scripted)
        task = asyncio.create_task(main.consume())
        try:
            await asyncio.wait_for(task, timeout=5.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        return True

    assert asyncio.run(scenario())
    # Messages 1 and 2 were handled and committed; message 3's handler died
    # mid-flight, so no commit may reflect it as handled.
    assert commits, "handled messages must commit"
    assert max(commits) == 2, (
        f"an unhandled message's offset leaked into a commit: {commits}")
