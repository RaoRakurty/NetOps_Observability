"""Optional evidence lanes must never gate the REQUIRED subscription.

THE MEASURED OUTAGE (2026-09-02, and the same shape on 2026-08-16). The engine
subscribed to all 13 topics as ONE set. `netops.security` — an OPTIONAL
evidence lane (T2b, `CORR_EVIDENCE_TOPICS`) whose producer was off and whose
topic broker auto-create would not make — did not exist. aiokafka's
``consumer.start()`` -> ``_wait_topics()`` -> ``_wait_on_metadata()`` raised
``UnknownTopicOrPartitionError`` (2026-08-16: ``TopicAuthorizationFailedError``,
the Read ACL being absent), the supervisor caught it, backed off and restarted
every 60 s. ONE absent optional topic starved ALL TWELVE required lanes for
~3 hours — and /healthz answered ``{"status": "ok"}`` throughout, because that
field was a literal.

THE CONTRACT PINNED HERE:

  1. PARTITION — ``consumer.start()`` is asked ONLY about ``REQUIRED_TOPICS``.
     ``_wait_topics`` is all-or-nothing, so anything in the subscription at
     start time can veto the engine; the optional lanes are therefore resolved
     afterwards and can veto nothing.
  2. DROP, LOUDLY — an optional topic that is absent or unauthorized is dropped
     with ONE structured error line naming the topic and the reason, a /healthz
     field, and a ``corr_evidence_topic_dropped{topic,reason}`` gauge. The
     engine consumes the rest.
  3. FAIL-LOUD, NAMED — a REQUIRED topic that is absent/unauthorized keeps the
     restart-loop behaviour, but the log line now says WHICH topic and WHY
     (the old traceback named neither for an authorization failure).
  4. RECOVER WITHOUT A RESTART — dropped lanes are re-probed on a bounded,
     jittered interval and re-subscribed the moment they appear.
  5. HEALTH MUST NOT LIE — ``status`` is "ok" only while the required
     subscription is live; a restarting consumer reads "degraded". Tracker 174
     is preserved: the sidecar still answers HTTP 200, so nothing here can flap
     the Docker healthcheck.

Run: python3 -m pytest test_optional_lane_subscription.py
"""

from __future__ import annotations

import asyncio
import logging
from typing import ClassVar

import pytest

import main

# ── fakes ────────────────────────────────────────────────────────────────────


class FakeCluster:
    """The two metadata surfaces `probe_topics` reads — mirrors aiokafka's
    ClusterMetadata: a topic the principal cannot Describe reports no
    partitions AND appears in `unauthorized_topics`."""

    def __init__(self, present: set[str], unauthorized: set[str]) -> None:
        self.present = set(present)
        self.unauthorized_topics = set(unauthorized)

    def partitions_for_topic(self, topic: str):
        return {0} if topic in self.present else None


class FakeClient:
    """Minimal AIOKafkaClient stand-in: tracked-topic set + a metadata refresh
    that resolves immediately. `refreshes` counts round trips so the re-probe
    cadence is assertable."""

    def __init__(self, cluster: FakeCluster) -> None:
        self.cluster = cluster
        self.tracked: set[str] = set()
        self.refreshes = 0

    def _done(self):
        fut = asyncio.get_event_loop().create_future()
        fut.set_result(True)
        return fut

    def add_topic(self, topic: str):
        self.tracked.add(topic)
        return self._done()

    def force_metadata_update(self):
        self.refreshes += 1
        return self._done()


class FakeConsumer:
    """Scriptable AIOKafkaConsumer stand-in (the test_consumer_supervisor
    pattern) plus the `_client` metadata surface the probe uses."""

    created: ClassVar[list] = []
    present: ClassVar[set[str]] = set()
    unauthorized: ClassVar[set[str]] = set()
    start_error: ClassVar[BaseException | None] = None

    def __init__(self, *topics, **kwargs):
        type(self).created.append(self)
        self.index = len(type(self).created)
        self.subscriptions: list[tuple[str, ...]] = []
        self._client = FakeClient(FakeCluster(type(self).present,
                                              type(self).unauthorized))

    # -- subscription ---------------------------------------------------
    def subscribe(self, topics=(), pattern=None, listener=None):
        self.subscriptions.append(tuple(topics))
        self.listener = listener

    @property
    def subscribed(self) -> tuple[str, ...]:
        return self.subscriptions[-1] if self.subscriptions else ()

    def partitions_for_topic(self, topic):
        return {0}

    # -- lifecycle ------------------------------------------------------
    async def start(self):
        err = type(self).start_error
        if err is not None:
            raise err

    async def stop(self):
        return None

    async def commit(self, offsets=None):
        return None

    def __aiter__(self):
        return self

    async def __anext__(self):
        await asyncio.sleep(3600)   # healthy consumer idles; the test cancels


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    """Module-level subscription state is exactly the kind of cross-test
    residue conftest already guards for the window and the batcher."""
    dropped = dict(main.EVIDENCE_TOPICS_DROPPED)
    subscribed = list(main.SUBSCRIBED_TOPICS)
    main.EVIDENCE_TOPICS_DROPPED.clear()
    main.SUBSCRIBED_TOPICS[:] = list(main.TOPICS)
    monkeypatch.setattr(main, "CONSUMER_RUNNING", False)
    monkeypatch.setattr(main, "CONSUMER_STARTS", 0)
    monkeypatch.setattr(main, "CONSUMER_START_FAILURES", 0)
    monkeypatch.setattr(main, "CONSUMER_RESTARTS", 0)
    monkeypatch.setattr(main, "CONSUMER_LAST_ERROR", "")
    monkeypatch.setattr(main, "EVIDENCE_TOPIC_REPROBES", 0)
    monkeypatch.setattr(main, "EVIDENCE_TOPIC_RESUBSCRIBES", 0)
    monkeypatch.setattr(main, "CONSUMER_STOP_TIMEOUT_S", 0.2)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 1.0)
    monkeypatch.setattr(main, "CORR_TOPIC_PROBE_TIMEOUT_S", 1.0)
    FakeConsumer.created = []
    FakeConsumer.present = set(main.TOPICS)
    FakeConsumer.unauthorized = set()
    FakeConsumer.start_error = None
    yield
    main.EVIDENCE_TOPICS_DROPPED.clear()
    main.EVIDENCE_TOPICS_DROPPED.update(dropped)
    main.SUBSCRIBED_TOPICS[:] = subscribed


async def _run_consume(*, seconds: float) -> None:
    """Drive main.consume() for a bounded slice of time, then cancel it."""
    task = asyncio.create_task(main.consume())
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=seconds)
    except asyncio.TimeoutError:
        pass
    finally:
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=1.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass


# ── the partition itself ─────────────────────────────────────────────────────


def test_required_and_optional_partition_the_declared_topics():
    """No lane may fall out of the split, and TOPICS itself is unchanged —
    the declared set is what the T2b removability contract reads."""
    assert main.REQUIRED_TOPICS + list(main.OPTIONAL_TOPICS) == main.TOPICS
    assert not set(main.REQUIRED_TOPICS) & set(main.OPTIONAL_TOPICS)
    # The twelve core lanes are REQUIRED; the evidence bus is OPTIONAL.
    assert set(main.REQUIRED_TOPICS) == set(
        main.apply_syslog_topic(list(main.LANE_TOPICS), main.CORR_SYSLOG_TOPIC))
    assert set(main.OPTIONAL_TOPICS) == set(main.CORR_EVIDENCE_TOPICS) - set(
        main.LANE_TOPICS)
    # Every registered evidence class's topic is OPTIONAL — that is what makes
    # a class removable at run time. Read from the registry, so a class added
    # or deleted later needs no edit here.
    import signals
    for topic in signals.EVIDENCE_TOPICS:
        assert topic in main.OPTIONAL_TOPICS, topic
    assert "netops.security" in main.OPTIONAL_TOPICS
    assert "netops.bgp" in main.OPTIONAL_TOPICS


def test_the_syslog_lane_is_required_whichever_topic_it_names(monkeypatch):
    """A4's switch moves WHICH topic is required, never whether it is."""
    swapped = main.apply_syslog_topic(list(main.LANE_TOPICS),
                                      "netops.syslog.control")
    assert "netops.syslog.control" in swapped
    assert "netops.syslog" not in swapped


# ── pure classification ──────────────────────────────────────────────────────


def test_classify_names_absent_unauthorized_and_present():
    got = main.classify_topic_metadata(
        ["a", "b", "c"], known=["a"], unauthorized=["b"])
    assert got == {"b": "unauthorized", "c": "absent"}


def test_unauthorized_wins_over_absent():
    """A broker that denies Describe also reports no partitions. Calling that
    'absent' sends an operator to `kafka-topics --create` for an ACL problem —
    the 2026-08-16 shape."""
    assert main.classify_topic_metadata(
        ["x"], known=[], unauthorized=["x"]) == {"x": "unauthorized"}


def test_probe_topics_reads_the_same_metadata_start_would(monkeypatch):
    consumer = FakeConsumer()
    consumer._client = FakeClient(FakeCluster({"netops.flows"}, {"netops.security"}))

    async def go():
        return await main.probe_topics(
            consumer, ("netops.flows", "netops.security", "netops.gone"),
            timeout=1.0)

    got = asyncio.run(go())
    assert got == {"netops.security": "unauthorized", "netops.gone": "absent"}
    # Every probed topic is asked about BY NAME — a "give me everything"
    # metadata request omits topics the principal cannot Describe, which is
    # what makes unauthorized reportable at all.
    assert consumer._client.tracked == {
        "netops.flows", "netops.security", "netops.gone"}
    assert consumer._client.refreshes == 1


# ── 1 + 2: an absent / unauthorized optional lane never blocks the engine ────


@pytest.mark.parametrize("reason", ["absent", "unauthorized"])
def test_optional_lane_missing_starts_the_rest_and_reports_the_drop(
        monkeypatch, caplog, reason):
    """THE REGRESSION. The engine must come up on the twelve required lanes and
    say — once, structurally — that the evidence lane is not grounded."""
    optional = main.OPTIONAL_TOPICS[0]
    # Exactly ONE optional lane is missing; every other lane (required AND
    # optional) resolves. Written this way so the assertions below stay about
    # one drop however many evidence classes are registered.
    others = [t for t in main.OPTIONAL_TOPICS if t != optional]
    FakeConsumer.present = set(main.TOPICS) - {optional}
    FakeConsumer.unauthorized = {optional} if reason == "unauthorized" else set()
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)
    monkeypatch.setattr(main, "CORR_EVIDENCE_REPROBE_S", 3600.0)

    with caplog.at_level(logging.INFO, logger="correlation"):
        asyncio.run(_run_consume(seconds=0.5))

    # The consumer came up ONCE — no restart loop.
    assert len(FakeConsumer.created) == 1, (
        "an optional lane restarted the supervisor — the outage is back")
    assert main.CONSUMER_STARTS == 1 and main.CONSUMER_START_FAILURES == 0

    # start() was asked ONLY about the required lanes (leg 1 of the contract:
    # _wait_topics is all-or-nothing, so nothing optional may be in it).
    first = FakeConsumer.created[0].subscriptions[0]
    assert set(first) == set(main.REQUIRED_TOPICS)
    assert optional not in first
    # ...and no re-subscribe added it back, because it is not there.
    assert optional not in FakeConsumer.created[0].subscribed
    assert set(main.SUBSCRIBED_TOPICS) == set(main.TOPICS) - {optional}

    # ONE structured error line naming topic + reason + the grounding verdict.
    drops = [r for r in caplog.records
             if r.levelno >= logging.ERROR and "optional lane DROPPED" in r.getMessage()]
    assert len(drops) == 1, f"expected exactly one drop line, got {len(drops)}"
    msg = drops[0].getMessage()
    assert f"topic={optional}" in msg and f"reason={reason}" in msg
    assert "evidence lane NOT grounded" in msg

    # /healthz + /metrics carry it.
    payload = asyncio.run(main.health())
    assert payload["ingest"]["evidence_subscription"]["dropped"] == {optional: reason}
    assert payload["ingest"]["evidence_subscription"]["subscribed"] == others
    assert payload["consumer"]["subscription"]["optional_dropped"] == {optional: reason}
    assert payload["consumer"]["subscription"]["subscribed"] == (
        list(main.REQUIRED_TOPICS) + others)
    text = main._metrics_text(payload)
    assert (f'corr_evidence_topic_dropped{{topic="{optional}",reason="{reason}"}} 1'
            in text)

    # A dropped OPTIONAL lane is NOT an unhealthy engine — reporting it as one
    # would recreate the defect from the other side.
    assert payload["status"] == "ok" or not main.CONSUMER_RUNNING


def test_a_dropped_optional_lane_alone_does_not_degrade_health(monkeypatch):
    monkeypatch.setattr(main, "CONSUMER_RUNNING", True)
    monkeypatch.setattr(main, "CONSUMER_STARTS", 1)
    main.EVIDENCE_TOPICS_DROPPED["netops.security"] = "absent"
    assert main.subscription_health() == ("ok", [])


def test_all_optional_lanes_present_needs_no_extra_rebalance(monkeypatch):
    """When nothing is dropped the consumer still ends up on the full set —
    and when EVERYTHING is dropped it must not re-subscribe at all (a needless
    subscribe() costs the group a rebalance on every restart)."""
    FakeConsumer.present = set(main.TOPICS)
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)
    monkeypatch.setattr(main, "CORR_EVIDENCE_REPROBE_S", 3600.0)
    asyncio.run(_run_consume(seconds=0.5))
    c = FakeConsumer.created[0]
    assert list(c.subscribed) == list(main.TOPICS)
    assert len(c.subscriptions) == 2, "one build-time subscribe + one add"
    assert main.EVIDENCE_TOPICS_DROPPED == {}

    FakeConsumer.created = []
    FakeConsumer.present = set(main.REQUIRED_TOPICS)
    asyncio.run(_run_consume(seconds=0.5))
    assert len(FakeConsumer.created[0].subscriptions) == 1, (
        "dropping every optional lane must not re-subscribe")


# ── 3: a REQUIRED topic stays fail-loud, but NAMED ───────────────────────────


def test_required_topic_absent_is_fail_loud_and_names_the_topic(
        monkeypatch, caplog):
    """Unchanged behaviour (raise -> backoff -> retry); what is new is that the
    line says WHICH topic and WHY. aiokafka raises
    UnknownTopicOrPartitionError() with no arguments at all."""
    from aiokafka.errors import UnknownTopicOrPartitionError

    missing = "netops.probes"
    FakeConsumer.present = set(main.TOPICS) - {missing}
    FakeConsumer.start_error = UnknownTopicOrPartitionError()
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)

    with caplog.at_level(logging.INFO, logger="correlation"):
        asyncio.run(_run_consume(seconds=0.7))

    lines = [r.getMessage() for r in caplog.records
             if r.levelno >= logging.ERROR and "REQUIRED lane unavailable" in r.getMessage()]
    assert lines, "the required-topic failure was not named"
    assert any(f"topic={missing}" in ln and "reason=absent" in ln for ln in lines)
    assert any("consumes NOTHING" in ln for ln in lines)

    # Fail-loud: the supervisor retried (more than one consumer built) and the
    # failure is counted for /healthz.
    assert main.CONSUMER_START_FAILURES >= 1
    assert main.CONSUMER_STARTS == 0
    assert not main.CONSUMER_RUNNING


def test_required_topic_unauthorized_names_the_topic_and_the_acl(
        monkeypatch, caplog):
    """The 2026-08-16 half: authorization failures named the error class, never
    the topic."""
    from aiokafka.errors import TopicAuthorizationFailedError

    denied = "netops.snmptrap"
    FakeConsumer.present = set(main.TOPICS) - {denied}
    FakeConsumer.unauthorized = {denied}
    FakeConsumer.start_error = TopicAuthorizationFailedError(denied)
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)

    with caplog.at_level(logging.INFO, logger="correlation"):
        asyncio.run(_run_consume(seconds=0.7))

    lines = [r.getMessage() for r in caplog.records
             if "REQUIRED lane unavailable" in r.getMessage()]
    assert any(f"topic={denied}" in ln and "reason=unauthorized" in ln
               for ln in lines)
    assert any("apply-acls.sh" in ln for ln in lines), (
        "the line must name the remedy, not just the fault")


def test_a_broker_fault_is_not_blamed_on_a_topic(monkeypatch, caplog):
    """Every required topic resolves but start() failed anyway — the line must
    say 'broker/transport fault', not invent a missing topic."""
    FakeConsumer.present = set(main.TOPICS)
    FakeConsumer.start_error = OSError("connection refused")
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)

    with caplog.at_level(logging.INFO, logger="correlation"):
        asyncio.run(_run_consume(seconds=0.7))

    assert any("broker/transport fault" in r.getMessage() for r in caplog.records)
    assert not any("REQUIRED lane unavailable" in r.getMessage()
                   for r in caplog.records)


# ── 4: re-probe re-subscribes without a restart ──────────────────────────────


def test_reprobe_resubscribes_when_the_topic_appears(monkeypatch, caplog):
    """A security lane enabled at 14:00 must start grounding at ~14:01, not at
    the next restart of a service that has no reason to restart."""
    optional = main.OPTIONAL_TOPICS[0]
    others = [t for t in main.OPTIONAL_TOPICS if t != optional]
    FakeConsumer.present = set(main.TOPICS) - {optional}
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)
    monkeypatch.setattr(main, "CORR_EVIDENCE_REPROBE_S", 0.05)
    monkeypatch.setattr(main, "CORR_EVIDENCE_REPROBE_JITTER", 0.0)

    async def scenario():
        task = asyncio.create_task(main.consume())
        try:
            # up on the required lanes, with the optional one dropped
            for _ in range(200):
                await asyncio.sleep(0.01)
                if main.EVIDENCE_TOPICS_DROPPED:
                    break
            assert main.EVIDENCE_TOPICS_DROPPED == {optional: "absent"}
            # the operator turns the lane on / the topic is created
            FakeConsumer.created[0]._client.cluster.present.add(optional)
            for _ in range(400):
                await asyncio.sleep(0.01)
                if optional in main.SUBSCRIBED_TOPICS:
                    break
        finally:
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

    with caplog.at_level(logging.INFO, logger="correlation"):
        asyncio.run(scenario())

    assert optional in main.SUBSCRIBED_TOPICS, "the recovered lane was not re-subscribed"
    assert main.EVIDENCE_TOPICS_DROPPED == {}
    assert len(FakeConsumer.created) == 1, "recovery must NOT need a restart"
    # The re-subscribe rebuilds the set as REQUIRED + every undropped OPTIONAL
    # in declaration order — the recovered lane goes back to ITS place, not to
    # the end (a stable order keeps the group's assignment stable).
    assert list(FakeConsumer.created[0].subscribed) == (
        list(main.REQUIRED_TOPICS) + list(main.OPTIONAL_TOPICS))
    assert optional in main.OPTIONAL_TOPICS and set(others) < set(main.OPTIONAL_TOPICS)
    assert main.EVIDENCE_TOPIC_REPROBES >= 1
    assert main.EVIDENCE_TOPIC_RESUBSCRIBES >= 1
    assert any(f"optional lane RECOVERED: topic={optional}" in r.getMessage()
               for r in caplog.records)


def test_a_standing_drop_is_not_relogged_on_every_reprobe(monkeypatch, caplog):
    """A standing condition must not become log spam — the drop is announced
    when it happens and again only if the REASON changes."""
    main.EVIDENCE_TOPICS_DROPPED.clear()
    with caplog.at_level(logging.INFO, logger="correlation"):
        main._note_dropped_lanes({"netops.security": "absent"})
        main._note_dropped_lanes({"netops.security": "absent"})
        main._note_dropped_lanes({"netops.security": "absent"})
        assert len([r for r in caplog.records
                    if "optional lane DROPPED" in r.getMessage()]) == 1
        # a CHANGED reason is news again (absent -> the ACL now denies it)
        main._note_dropped_lanes({"netops.security": "unauthorized"})
    lines = [r.getMessage() for r in caplog.records
             if "optional lane DROPPED" in r.getMessage()]
    assert len(lines) == 2 and "reason=unauthorized" in lines[1]


def test_reprobe_delay_is_bounded_and_jittered():
    """§9: a retry cadence with no jitter is N replicas hitting the
    coordinator's metadata path in lockstep."""
    lo = main._reprobe_delay(rnd=lambda: 0.0)
    hi = main._reprobe_delay(rnd=lambda: 1.0)
    mid = main._reprobe_delay(rnd=lambda: 0.5)
    j = main.CORR_EVIDENCE_REPROBE_JITTER
    assert lo == pytest.approx(main.CORR_EVIDENCE_REPROBE_S * (1 - j))
    assert hi == pytest.approx(main.CORR_EVIDENCE_REPROBE_S * (1 + j))
    assert mid == pytest.approx(main.CORR_EVIDENCE_REPROBE_S)
    assert lo >= 1.0, "the period must never collapse to a hot loop"


def test_a_failing_reprobe_never_kills_the_consumer(monkeypatch):
    """§10: the re-probe is a side channel. A broker hiccup in it must cost a
    log line, not the twelve required lanes."""
    optional = main.OPTIONAL_TOPICS[0]
    FakeConsumer.present = set(main.TOPICS) - {optional}
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)
    monkeypatch.setattr(main, "CORR_EVIDENCE_REPROBE_S", 0.05)
    monkeypatch.setattr(main, "CORR_EVIDENCE_REPROBE_JITTER", 0.0)

    calls = {"n": 0}
    real_probe = main.probe_topics

    async def flaky(consumer, topics, *, timeout):
        calls["n"] += 1
        if calls["n"] > 1:
            raise OSError("metadata refresh failed")
        return await real_probe(consumer, topics, timeout=timeout)

    monkeypatch.setattr(main, "probe_topics", flaky)

    async def scenario():
        task = asyncio.create_task(main.consume())
        try:
            # `_reprobe_delay` floors the period at 1s (never a hot loop), so
            # three probes = the resolve + two ticks.
            for _ in range(400):
                await asyncio.sleep(0.01)
                if calls["n"] >= 3:
                    break
        finally:
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

    asyncio.run(scenario())
    assert calls["n"] >= 3, "the re-probe stopped after its first failure"
    assert len(FakeConsumer.created) == 1, "a failed re-probe restarted the consumer"
    assert main.EVIDENCE_TOPICS_DROPPED == {optional: "absent"}


# ── 5: health must not lie ───────────────────────────────────────────────────


def test_health_is_ok_only_while_the_required_subscription_is_live(monkeypatch):
    # never attempted (unit tests, and the window before lifespan starts the
    # task): "ok" — the sidecar's 503 "starting" already covers that window.
    assert main.subscription_health() == ("ok", [])
    # started and consuming
    monkeypatch.setattr(main, "CONSUMER_STARTS", 1)
    monkeypatch.setattr(main, "CONSUMER_RUNNING", True)
    assert main.subscription_health() == ("ok", [])
    # THE OUTAGE: the loop is restarting, so the engine consumes nothing.
    monkeypatch.setattr(main, "CONSUMER_RUNNING", False)
    monkeypatch.setattr(main, "CONSUMER_RESTARTS", 5)
    status, reasons = main.subscription_health()
    assert status == "degraded" and reasons == ["consumer_not_running"]
    # start() failing every 60s without ever succeeding is the same lie.
    monkeypatch.setattr(main, "CONSUMER_STARTS", 0)
    monkeypatch.setattr(main, "CONSUMER_RESTARTS", 0)
    monkeypatch.setattr(main, "CONSUMER_START_FAILURES", 3)
    assert main.subscription_health()[0] == "degraded"


def test_healthz_and_metrics_report_a_dead_consumer(monkeypatch):
    monkeypatch.setattr(main, "CONSUMER_STARTS", 1)
    monkeypatch.setattr(main, "CONSUMER_RESTARTS", 4)
    monkeypatch.setattr(main, "CONSUMER_START_FAILURES", 4)
    monkeypatch.setattr(main, "CONSUMER_RUNNING", False)
    monkeypatch.setattr(main, "CONSUMER_LAST_ERROR",
                        "UnknownTopicOrPartitionError: absent")

    payload = asyncio.run(main.health())
    assert payload["status"] == "degraded"
    assert payload["health_reasons"] == ["consumer_not_running"]
    sub = payload["consumer"]["subscription"]
    assert sub["running"] is False and sub["restarts"] == 4
    assert sub["last_error"] == "UnknownTopicOrPartitionError: absent"

    text = main._metrics_text(payload)
    assert "corr_consumer_running 0" in text
    assert "corr_consumer_restarts_total 4" in text
    assert "corr_consumer_start_failures_total 4" in text
    assert "corr_health_degraded 1" in text


def test_the_sidecar_stays_reachable_when_degraded(monkeypatch):
    """TRACKER 174 IS NOT REVERSED. Degradation lives in the BODY; the sidecar
    still answers HTTP 200, which is all the compose healthcheck tests — so a
    consumer restart loop can never flap a container (the self-inflicted
    restart mid-storm that 174 exists to prevent)."""
    import json

    monkeypatch.setattr(main, "CONSUMER_STARTS", 1)
    monkeypatch.setattr(main, "CONSUMER_RESTARTS", 2)
    monkeypatch.setattr(main, "CONSUMER_RUNNING", False)
    monkeypatch.setattr(main, "_HEALTH_SNAPSHOT", None)
    main._publish_health_snapshot()
    status, _ctype, body = main._sidecar_response("/healthz")
    assert status == 200, "a degraded consumer must not make health UNREACHABLE"
    assert json.loads(body)["status"] == "degraded"
