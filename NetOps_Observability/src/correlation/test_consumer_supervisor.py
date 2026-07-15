"""Consumer-supervisor resilience (§10) — run with: python3 -m pytest test_consumer_supervisor.py

Pins the 2026-07-14 live incident: the supervisor logged "restarting in 1s"
and then awaited consumer.stop() UNBOUNDED against a crash-looping broker —
stop() hung forever and the engine consumed nothing for 5.5 hours while the
process looked healthy. The guarantee under test: no broker-facing await can
wedge the supervisor; a hung stop() or start() is abandoned on a bounded
timeout and a FRESH consumer always follows.
"""
import asyncio

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
            created = []

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
            created = []

            async def start(self):
                if self.index == 1:
                    await asyncio.sleep(3600)  # broker never answers
                reached_second.set()

        monkeypatch.setattr(main, "AIOKafkaConsumer", Scripted)
        return await _run_until(reached_second, timeout=5.0)

    assert asyncio.run(scenario()), "supervisor wedged on hung consumer.start()"
