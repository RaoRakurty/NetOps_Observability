# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""A REQUIRED lane the broker REFUSES must be an explicit, observable refusal.

THE DEFECT (tracker 309). The scale-miniladder nightly carried
``aiokafka.errors.TopicAuthorizationFailedError: [Error 29] ...
netops.controller_events`` out of the correlation engine, and NOTHING judged it:
not the harness, not a vmalert rule, not ``scripts/deploy-qualify.sh``. The
2026-09-02 work had already made the *optional* evidence lanes fully observable —
a drop map, a ``corr_evidence_topic_dropped{topic,reason}`` gauge, a /healthz
field and a warning rule — but the REQUIRED lanes, the ones whose refusal stops
the engine dead, had only:

  * a log line re-emitted on EVERY supervision round (so a standing
    misconfiguration read as a wall of identical tracebacks), and
  * two aggregate gauges (``corr_consumer_running`` /
    ``corr_consumer_start_failures_total``) that say the engine is consuming
    nothing and cannot say WHICH lane or WHOSE ACL.

THE CONTRACT PINNED HERE:

  1. ONCE, NAMED — one structured error line per newly-unavailable topic, naming
     the topic, the reason AND the principal the broker refused; re-logged only
     if the reason changes, never on every retry.
  2. A PER-TOPIC GAUGE — ``corr_required_topic_unavailable{topic,reason}``,
     present only while the refusal stands, plus the always-published
     ``corr_required_topic_unavailable_count`` (0 is a positive statement; the
     labelled gauge's absence is not).
  3. DEGRADED, AND SAID SO — /healthz status is "degraded" and the reasons name
     the lane. Tracker 174 is preserved: the sidecar still answers HTTP 200.
  4. RETRACTED ON RECOVERY — a successful ``start()`` clears the map, so neither
     the gauge nor the alert can outlive the fix.
  5. NOT A LANE FAULT, NOT A LANE CLAIM — a broker/transport failure with every
     required topic resolving must leave the map EMPTY.

Run: python3 -m pytest test_required_lane_authorization_309.py
"""

from __future__ import annotations

import asyncio
import logging
from typing import ClassVar

import pytest

import main

CONTROLLER = "netops.controller_events"


# ── fakes (the test_optional_lane_subscription.py shapes) ────────────────────


class FakeCluster:
    """aiokafka's ClusterMetadata surfaces `probe_topics` reads: a topic the
    principal cannot Describe reports NO partitions AND appears in
    `unauthorized_topics`."""

    def __init__(self, present: set[str], unauthorized: set[str]) -> None:
        self.present = set(present)
        self.unauthorized_topics = set(unauthorized)

    def partitions_for_topic(self, topic: str):
        return {0} if topic in self.present else None


class FakeClient:
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
    """Scriptable AIOKafkaConsumer stand-in. `start_error` may be a single
    exception or a LIST consumed one per instance, which is how the
    refuse-then-recover case is driven."""

    created: ClassVar[list] = []
    present: ClassVar[set[str]] = set()
    unauthorized: ClassVar[set[str]] = set()
    start_error: ClassVar[object] = None

    def __init__(self, *topics, **kwargs):
        type(self).created.append(self)
        self.index = len(type(self).created)
        self.subscriptions: list[tuple[str, ...]] = []
        self._client = FakeClient(FakeCluster(type(self).present,
                                              type(self).unauthorized))

    def subscribe(self, topics=(), pattern=None, listener=None):
        self.subscriptions.append(tuple(topics))
        self.listener = listener

    def partitions_for_topic(self, topic):
        return {0}

    async def start(self):
        err = type(self).start_error
        if isinstance(err, list):
            err = err[self.index - 1] if self.index - 1 < len(err) else None
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
    """`REQUIRED_TOPICS_UNAVAILABLE` is module-level state exactly like the
    evidence drop map — a residue here would degrade every later test's health."""
    saved = dict(main.REQUIRED_TOPICS_UNAVAILABLE)
    dropped = dict(main.EVIDENCE_TOPICS_DROPPED)
    subscribed = list(main.SUBSCRIBED_TOPICS)
    main.REQUIRED_TOPICS_UNAVAILABLE.clear()
    main.EVIDENCE_TOPICS_DROPPED.clear()
    main.SUBSCRIBED_TOPICS[:] = list(main.TOPICS)
    monkeypatch.setattr(main, "CONSUMER_RUNNING", False)
    monkeypatch.setattr(main, "CONSUMER_STARTS", 0)
    monkeypatch.setattr(main, "CONSUMER_START_FAILURES", 0)
    monkeypatch.setattr(main, "CONSUMER_RESTARTS", 0)
    monkeypatch.setattr(main, "CONSUMER_LAST_ERROR", "")
    monkeypatch.setattr(main, "CONSUMER_STOP_TIMEOUT_S", 0.2)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 1.0)
    monkeypatch.setattr(main, "CORR_TOPIC_PROBE_TIMEOUT_S", 1.0)
    monkeypatch.setattr(main, "CORR_EVIDENCE_REPROBE_S", 3600.0)
    FakeConsumer.created = []
    FakeConsumer.present = set(main.TOPICS)
    FakeConsumer.unauthorized = set()
    FakeConsumer.start_error = None
    yield
    main.REQUIRED_TOPICS_UNAVAILABLE.clear()
    main.REQUIRED_TOPICS_UNAVAILABLE.update(saved)
    main.EVIDENCE_TOPICS_DROPPED.clear()
    main.EVIDENCE_TOPICS_DROPPED.update(dropped)
    main.SUBSCRIBED_TOPICS[:] = subscribed


async def _run_consume(*, seconds: float) -> None:
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


def _deny(topic: str):
    """The exact failure the nightly logged: Error 29 on ONE required lane."""
    from aiokafka.errors import TopicAuthorizationFailedError

    FakeConsumer.present = set(main.TOPICS) - {topic}
    FakeConsumer.unauthorized = {topic}
    FakeConsumer.start_error = TopicAuthorizationFailedError(topic)


# ── 0: the lane in the defect really is REQUIRED ─────────────────────────────


def test_the_controller_events_lane_is_a_required_lane():
    """If it were optional the 2026-09-02 drop-and-re-probe path would already
    own it and this whole change would be aimed at the wrong half."""
    assert CONTROLLER in main.LANE_TOPICS
    assert CONTROLLER in main.REQUIRED_TOPICS
    assert CONTROLLER not in main.OPTIONAL_TOPICS


# ── the principal, so the refusal names WHO ──────────────────────────────────


def test_the_principal_is_the_dn_the_acl_matrix_grants():
    """The broker sees a full DN (apply-acls.sh grants `User:CN=spiffe://…/sa/
    correlation`; there are no ssl.principal.mapping.rules), so a refusal line
    that said "correlation" would not be greppable against the matrix."""
    assert main.kafka_principal("/certs/svid/correlation.crt") == (
        "User:CN=spiffe://netops/ns/default/sa/correlation")
    # a nested path and a name with dots resolve to the basename's stem
    assert main.kafka_principal("/tls/svid/vector-router.crt").endswith(
        "/vector-router")


def test_no_svid_means_the_broker_really_does_see_anonymous():
    """The plaintext baseline is not a missing value to paper over — ANONYMOUS
    is what the broker authorizes, and the ACL matrix names it explicitly."""
    assert main.kafka_principal("") == "User:ANONYMOUS"


def test_an_explicit_override_wins():
    assert main.kafka_principal("/certs/svid/correlation.crt",
                                "User:CN=other") == "User:CN=other"


# ── 1 + 2 + 3: named once, gauged, degraded ──────────────────────────────────


def test_a_refused_required_lane_is_named_gauged_and_degrades_health(
        monkeypatch, caplog):
    """THE REGRESSION. One line, one gauge, one honest health verdict."""
    _deny(CONTROLLER)
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)

    with caplog.at_level(logging.INFO, logger="correlation"):
        asyncio.run(_run_consume(seconds=0.7))

    # (a) the log line names topic, reason AND principal
    lines = [r.getMessage() for r in caplog.records
             if r.levelno >= logging.ERROR
             and "REQUIRED lane unavailable" in r.getMessage()]
    assert lines, "the refusal was not logged as an error"
    assert any(f"topic={CONTROLLER}" in ln and "reason=unauthorized" in ln
               and f"principal={main.KAFKA_PRINCIPAL}" in ln for ln in lines)
    assert any("apply-acls.sh" in ln for ln in lines), \
        "the line must name the remedy, not only the fault"

    # ONCE, not once per supervision round: the loop retried (start_failures > 1
    # is possible) and the line must not have been repeated for it.
    assert len(lines) == 1, (
        f"the standing refusal was re-logged {len(lines)} times — a "
        "misconfiguration must not become log spam")

    # (b) the per-topic gauge plus the always-present count
    assert main.REQUIRED_TOPICS_UNAVAILABLE == {CONTROLLER: "unauthorized"}
    payload = asyncio.run(main.health())
    text = main._metrics_text(payload)
    assert (f'corr_required_topic_unavailable{{topic="{CONTROLLER}",'
            'reason="unauthorized"} 1') in text
    assert "corr_required_topic_unavailable_count 1" in text

    # (c) health is degraded and SAYS WHICH LANE
    assert payload["status"] == "degraded"
    assert payload["health_reasons"][0] == "consumer_not_running"
    assert f"required_lane_unauthorized:{CONTROLLER}" in payload["health_reasons"]
    sub = payload["consumer"]["subscription"]
    assert sub["required_unavailable"] == {CONTROLLER: "unauthorized"}
    assert sub["principal"] == main.KAFKA_PRINCIPAL
    assert CONTROLLER in sub["required"]


def test_an_absent_required_lane_uses_the_same_surfaces(monkeypatch, caplog):
    """The remedy differs (kafka-init, not the ACL matrix), so the reason has to
    reach the gauge label — one machinery, two reasons."""
    from aiokafka.errors import UnknownTopicOrPartitionError

    FakeConsumer.present = set(main.TOPICS) - {"netops.probes"}
    FakeConsumer.start_error = UnknownTopicOrPartitionError()
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)

    with caplog.at_level(logging.INFO, logger="correlation"):
        asyncio.run(_run_consume(seconds=0.7))

    assert main.REQUIRED_TOPICS_UNAVAILABLE == {"netops.probes": "absent"}
    text = main._metrics_text(asyncio.run(main.health()))
    assert ('corr_required_topic_unavailable{topic="netops.probes",'
            'reason="absent"} 1') in text


def test_a_reason_change_is_news_again_but_a_standing_refusal_is_not(caplog):
    """The `_note_dropped_lanes` discipline, applied to the required half:
    announce on change, stay quiet otherwise. absent -> unauthorized is a
    DIFFERENT remedy, so it must be said."""
    with caplog.at_level(logging.INFO, logger="correlation"):
        for _ in range(3):
            main._note_required_lane_failures({CONTROLLER: "absent"})
        first = [r.getMessage() for r in caplog.records
                 if "REQUIRED lane unavailable" in r.getMessage()]
        assert len(first) == 1
        main._note_required_lane_failures({CONTROLLER: "unauthorized"})
    lines = [r.getMessage() for r in caplog.records
             if "REQUIRED lane unavailable" in r.getMessage()]
    assert len(lines) == 2 and "reason=unauthorized" in lines[1]


# ── 4: retracted on recovery, so the alert cannot outlive the fix ────────────


def test_the_refusal_is_retracted_the_moment_start_succeeds(monkeypatch, caplog):
    """An operator applies the ACL matrix; the very next supervision round joins.
    A gauge (and therefore an alert) that survived that would be the noise that
    gets the rule muted."""
    from aiokafka.errors import TopicAuthorizationFailedError

    FakeConsumer.present = set(main.TOPICS)
    FakeConsumer.unauthorized = set()
    # first consumer is refused, the second (after the ACL lands) comes up
    FakeConsumer.start_error = [TopicAuthorizationFailedError(CONTROLLER), None]
    # the refusal must be OBSERVABLE on the first round, so make the probe agree
    FakeConsumer.present = set(main.TOPICS) - {CONTROLLER}
    FakeConsumer.unauthorized = {CONTROLLER}
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)

    async def scenario():
        """Returns the health payload CAPTURED WHILE THE CONSUMER IS LIVE.

        Cancelling `consume()` clears CONSUMER_RUNNING on the way out (that is
        the supervisor's own contract), so a post-cancel assertion would be
        asserting about a stopped engine, not a recovered one."""
        task = asyncio.create_task(main.consume())
        try:
            for _ in range(300):
                await asyncio.sleep(0.01)
                if main.REQUIRED_TOPICS_UNAVAILABLE:
                    break
            assert main.REQUIRED_TOPICS_UNAVAILABLE == {
                CONTROLLER: "unauthorized"}
            # the matrix is applied: the lane resolves for the next consumer
            FakeConsumer.present = set(main.TOPICS)
            FakeConsumer.unauthorized = set()
            for _ in range(600):
                await asyncio.sleep(0.01)
                if main.CONSUMER_RUNNING:
                    break
            assert main.CONSUMER_RUNNING, "the consumer never recovered"
            return await main.health()
        finally:
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

    with caplog.at_level(logging.INFO, logger="correlation"):
        payload = asyncio.run(scenario())

    assert main.CONSUMER_STARTS == 1, "start() never succeeded"
    assert main.REQUIRED_TOPICS_UNAVAILABLE == {}, \
        "the refusal outlived the fix — the gauge would keep the alert firing"
    assert any(f"REQUIRED lane available again: topic={CONTROLLER}"
               in r.getMessage() for r in caplog.records)
    assert payload["status"] == "ok" and payload["health_reasons"] == []
    text = main._metrics_text(payload)
    assert "corr_required_topic_unavailable{" not in text, \
        "the labelled gauge must be ABSENT when healthy"
    # …but the count is ALWAYS published, which is what lets a gate tell
    # "nothing is wrong" from "this build has no such gauge".
    assert "corr_required_topic_unavailable_count 0" in text


# ── 5: a broker fault must not be blamed on a lane ──────────────────────────


def test_a_broker_fault_claims_no_lane(monkeypatch, caplog):
    """Every required topic resolves and start() failed anyway. A per-topic gauge
    that guessed here would send the operator to the ACL matrix for a broker
    outage — worse than no gauge."""
    FakeConsumer.present = set(main.TOPICS)
    FakeConsumer.start_error = OSError("connection refused")
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)

    with caplog.at_level(logging.INFO, logger="correlation"):
        asyncio.run(_run_consume(seconds=0.7))

    assert main.REQUIRED_TOPICS_UNAVAILABLE == {}
    text = main._metrics_text(asyncio.run(main.health()))
    assert "corr_required_topic_unavailable{" not in text
    assert "corr_required_topic_unavailable_count 0" in text
    assert any("broker/transport fault" in r.getMessage()
               for r in caplog.records)


def test_a_stale_lane_claim_is_dropped_when_the_fault_changes_shape(caplog):
    """A refusal followed by a pure broker fault must RETRACT the lane claim —
    the map is a statement about NOW."""
    main._note_required_lane_failures({CONTROLLER: "unauthorized"})
    assert main.REQUIRED_TOPICS_UNAVAILABLE
    main._note_required_lane_failures({})
    assert main.REQUIRED_TOPICS_UNAVAILABLE == {}


# ── 3 (the other half): tracker 174 is not reversed ─────────────────────────


def test_the_sidecar_still_answers_200_while_a_lane_is_refused(monkeypatch):
    """Degradation lives in the BODY. If a refused lane could flap the container
    healthcheck, a broker ACL gap would become a restart storm."""
    import json

    monkeypatch.setattr(main, "CONSUMER_STARTS", 0)
    monkeypatch.setattr(main, "CONSUMER_START_FAILURES", 3)
    monkeypatch.setattr(main, "CONSUMER_RUNNING", False)
    main.REQUIRED_TOPICS_UNAVAILABLE[CONTROLLER] = "unauthorized"
    monkeypatch.setattr(main, "_HEALTH_SNAPSHOT", None)
    main._publish_health_snapshot()
    status, _ctype, body = main._sidecar_response("/healthz")
    assert status == 200
    doc = json.loads(body)
    assert doc["status"] == "degraded"
    assert f"required_lane_unauthorized:{CONTROLLER}" in doc["health_reasons"]


# ── the gauge's cardinality is bounded by construction ──────────────────────


def test_the_gauge_cardinality_is_bounded_by_the_required_set():
    """At most one series per REQUIRED lane, and the reason label takes one of
    three fixed values — no broker-supplied string can widen it."""
    for topic in main.REQUIRED_TOPICS:
        main.REQUIRED_TOPICS_UNAVAILABLE[topic] = "unauthorized"
    text = main._metrics_text(asyncio.run(main.health()))
    series = [ln for ln in text.splitlines()
              if ln.startswith("corr_required_topic_unavailable{")]
    assert len(series) == len(set(main.REQUIRED_TOPICS))
    assert f"corr_required_topic_unavailable_count {len(series)}" in text
