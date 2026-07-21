"""F-36: no Kafka produce failure may be silent.

kafka-python's send() is fire-and-forget — the poller's 17 call sites discarded
the returned future, so a record that exhausted retries=5 disappeared with no
log, no counter and no cycle-level signal. These tests pin the guarantee that
the wrapper observes the delivery RESULT.
"""
import pytest

import ingest_metrics
import producer_guard


class _Future:
    """Minimal kafka-python Future: errbacks fire on failure."""

    def __init__(self):
        self._errbacks = []

    def add_errback(self, fn):
        self._errbacks.append(fn)
        return self

    def fail(self, exc):
        for fn in self._errbacks:
            fn(exc)


class _Producer:
    def __init__(self, *, send_raises=None):
        self.sent = []
        self.futures = []
        self.flushed = 0
        self._send_raises = send_raises

    def send(self, topic, value, **kw):
        if self._send_raises is not None:
            raise self._send_raises
        self.sent.append((topic, value))
        fut = _Future()
        self.futures.append(fut)
        return fut

    def flush(self, timeout=None):
        self.flushed += 1


@pytest.fixture(autouse=True)
def _clean_metrics():
    ingest_metrics.reset()
    yield
    ingest_metrics.reset()


def test_successful_send_counts_nothing_as_failed():
    g = producer_guard.GuardedProducer(_Producer())
    g.send("netops.cloud", {"a": 1})
    assert g.sent_count == 1
    assert g.failed_count == 0
    assert ingest_metrics.produce_failures() == {}


def test_delivery_failure_is_counted_logged_and_metered(capsys):
    inner = _Producer()
    g = producer_guard.GuardedProducer(inner)
    g.send("netops.cloud", {"a": 1})
    inner.futures[0].fail(RuntimeError("KafkaTimeoutError: no brokers"))

    assert g.failed_count == 1
    assert "KafkaTimeoutError" in g.last_error
    assert ingest_metrics.produce_failures() == {"netops.cloud": 1}
    out = capsys.readouterr().out
    assert "kafka produce FAILED" in out
    assert "netops.cloud" in out


def test_synchronous_send_error_never_escapes_into_a_lane():
    """A buffer-full / metadata timeout raises from send() itself. A poll lane
    must not die of it — but it must not be invisible either."""
    g = producer_guard.GuardedProducer(_Producer(send_raises=BufferError("full")))
    assert g.send("netops.cloudcosts", {"a": 1}) is None
    assert g.failed_count == 1
    assert ingest_metrics.produce_failures() == {"netops.cloudcosts": 1}


def test_repeated_failures_are_rate_limited_but_all_counted(capsys):
    inner = _Producer()
    g = producer_guard.GuardedProducer(inner, log_every_s=3600.0)
    for _ in range(50):
        g.send("netops.cloud", {"a": 1})
    for fut in inner.futures:
        fut.fail(RuntimeError("boom"))

    assert g.failed_count == 50                       # every loss counted
    assert capsys.readouterr().out.count("kafka produce FAILED") == 1  # one log
    assert ingest_metrics.produce_failures()["netops.cloud"] == 50


def test_flush_error_propagates_to_the_caller():
    """cost.py's checkpoint hold-back depends on seeing the flush failure."""

    class _Boom(_Producer):
        def flush(self, timeout=None):
            raise TimeoutError("broker unreachable")

    g = producer_guard.GuardedProducer(_Boom())
    with pytest.raises(TimeoutError):
        g.flush(5)


def test_unknown_attributes_pass_through():
    class _P(_Producer):
        def partitions_for(self, topic):
            return {0, 1}

    g = producer_guard.GuardedProducer(_P())
    assert g.partitions_for("netops.cloud") == {0, 1}


def test_metrics_exposition_carries_the_produce_failure_counter():
    inner = _Producer()
    g = producer_guard.GuardedProducer(inner)
    g.send("netops.cloud", {"a": 1})
    inner.futures[0].fail(RuntimeError("boom"))
    text = ingest_metrics.render()
    assert 'netops_cloud_ingest_produce_failures_total{topic="netops.cloud"} 1' in text
