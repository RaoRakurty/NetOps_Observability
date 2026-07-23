"""Write/consume durability (F-38, F-40, F-42, F-39, F-44, F-43, F-45).

One defect repeated: a write or an event fails and the failure is discarded, so
data loss is indistinguishable from a quiet network. Each test here pins the
counter or the tolerance that makes the loss visible or unnecessary:

  * F-38 — a rejected ClickHouse insert is counted per table (19 of 20 call
    sites used to throw the boolean away; the archive could grow holes while
    live RCA looked perfect).
  * F-40 — a handler exception costs ONE event, not the ten-topic consumer,
    and the payload survives for inspection.
  * F-42 — unparseable flow records are counted (flows_received counts
    ACCEPTED flows, so 100% parse failure read as "quiet network").
  * F-39 — the syslog lane has intake observability at all.
  * F-44 — metrics_dropped is split by cause.
  * F-43 — a topology export that DISAPPEARS ages into stale, never fresh.
  * F-45 — the correlation state maps are bounded.
"""
import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

import main
from episodes import EpisodeDetector


def run(coro):
    return asyncio.run(coro)


class RejectingCH:
    """ClickHouse that rejects every insert (the 4xx schema-drift shape)."""

    def __init__(self, ok: bool = False):
        self.ok = ok
        self.calls: list[str] = []

    async def insert(self, table, rows, dedup_token="") -> bool:
        self.calls.append(table)
        return self.ok


class ExplodingCH:
    async def insert(self, table, rows, dedup_token="") -> bool:
        raise TimeoutError("clickhouse unreachable")


@pytest.fixture(autouse=True)
def _clean_state():
    main.CH_INSERT_FAILURES.clear()
    main._CH_FAIL_LOG_LAST.clear()
    main.HANDLER_FAILURES.clear()
    main._QUARANTINE_LOG_LAST.clear()
    main.QUARANTINE.clear()
    main.SYSLOG_BUCKET.clear()
    yield
    main.CH_INSERT_FAILURES.clear()
    main.HANDLER_FAILURES.clear()
    main.QUARANTINE.clear()
    main.SYSLOG_BUCKET.clear()


# ── F-38: no ClickHouse write is lost silently ───────────────────────────────

def test_rejected_insert_is_counted_per_table(monkeypatch):
    monkeypatch.setattr(main, "ch", RejectingCH())
    assert run(main.ch_insert("netops.corr_signals_archive", [{"a": 1}])) is False
    assert run(main.ch_insert("netops.corr_signals_archive", [{"a": 2}])) is False
    assert run(main.ch_insert("netops.findings", [{"a": 3}])) is False
    assert main.CH_INSERT_FAILURES == {
        "netops.corr_signals_archive": 2, "netops.findings": 1,
    }


def test_successful_insert_counts_nothing(monkeypatch):
    monkeypatch.setattr(main, "ch", RejectingCH(ok=True))
    assert run(main.ch_insert("netops.corr_objects", [{"a": 1}])) is True
    assert main.CH_INSERT_FAILURES == {}


def test_transport_exception_is_counted_and_re_raised(monkeypatch):
    """Re-raised on purpose: the consumer's quarantine keeps the payload, so a
    ClickHouse outage does not silently eat the event."""
    monkeypatch.setattr(main, "ch", ExplodingCH())
    with pytest.raises(TimeoutError):
        run(main.ch_insert("netops.corr_signals", [{"a": 1}], lane="syslog"))
    assert main.CH_INSERT_FAILURES == {"netops.corr_signals": 1}


def test_repeated_failures_log_rate_limited_but_count_exactly(monkeypatch, caplog):
    # A RECONSTRUCTABLE table (source of truth is replayable) keeps the bool
    # contract: a rejected insert is counted and returned False, not raised.
    # corr_signals_archive is not in CH_CRITICAL_TABLES.
    table = "netops.corr_signals_archive"
    monkeypatch.setattr(main, "ch", RejectingCH())
    monkeypatch.setattr(main, "CH_FAIL_LOG_EVERY_S", 3600.0)
    with caplog.at_level("WARNING"):
        for _ in range(25):
            assert run(main.ch_insert(table, [{"a": 1}])) is False
    assert main.CH_INSERT_FAILURES[table] == 25
    assert sum("clickhouse write LOST" in r.message for r in caplog.records) == 1


def test_rejected_critical_write_raises_so_the_offset_is_not_advanced(monkeypatch):
    # An RCA-critical table (causality-bearing) must NOT silently return False on
    # a rejected write — that let the ~19 callers who ignored the bool advance
    # the Kafka offset past a lost causal record. It now raises CHInsertRejected,
    # which the consumer turns into a durable quarantine (constraint #7).
    monkeypatch.setattr(main, "ch", RejectingCH())
    for table in sorted(main.CH_CRITICAL_TABLES):
        with pytest.raises(main.CHInsertRejected):
            run(main.ch_insert(table, [{"a": 1}]))
    # Counted, too — the metric still moves.
    assert main.CH_INSERT_FAILURES["netops.corr_signals"] >= 1


def test_metrics_exposition_carries_the_insert_failure_counter(monkeypatch):
    monkeypatch.setattr(main, "ch", RejectingCH())
    run(main.ch_insert("netops.corr_signals_archive", [{"a": 1}]))
    text = run(main.metrics_exposition()).body.decode()
    assert 'corr_ch_insert_failures_total{table="netops.corr_signals_archive"} 1' in text


# ── F-40: one poison event costs one event ───────────────────────────────────

class _PoisonConsumer:
    """Yields a poison record, then a good one, then idles."""

    created: list = []

    def __init__(self, *topics, **kw):
        _PoisonConsumer.created.append(self)
        self._msgs = iter([
            _Msg("netops.syslog", {"boom": True}),
            _Msg("netops.metrics", {"ok": True}),
        ])

    async def start(self):
        return None

    async def stop(self):
        return None

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._msgs)
        except StopIteration:
            await asyncio.sleep(3600)
            raise StopAsyncIteration


class _Msg:
    def __init__(self, topic, value, partition=0, offset=0):
        self.topic = topic
        self.value = value
        self.partition = partition
        self.offset = offset


def test_poison_event_does_not_tear_down_the_consumer(monkeypatch):
    """The event that raises is quarantined; the NEXT event still processes,
    on the same consumer instance (no restart, no lost batch)."""
    _PoisonConsumer.created = []
    handled: list[str] = []

    async def fake_handle(topic, event):
        if topic == "netops.syslog":
            raise TypeError("unexpected field shape")
        handled.append(topic)

    monkeypatch.setattr(main, "AIOKafkaConsumer", _PoisonConsumer)
    monkeypatch.setattr(main, "handle", fake_handle)

    async def scenario():
        task = asyncio.create_task(main.consume())
        await asyncio.sleep(0.2)
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=1.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    run(scenario())
    assert handled == ["netops.metrics"]          # the good event still landed
    assert len(_PoisonConsumer.created) == 1      # no consumer restart
    assert main.HANDLER_FAILURES == {"netops.syslog": 1}


class _AllPoisonConsumer(_PoisonConsumer):
    """Every record fails — the "dependency is down" shape, not one bad event."""

    created: list = []

    def __init__(self, *topics, **kw):
        _AllPoisonConsumer.created.append(self)
        self._msgs = iter([_Msg("netops.metrics", {"i": i}) for i in range(50)])


def test_a_run_of_failures_restarts_the_consumer_instead_of_eating_the_stream(monkeypatch):
    """One poison event is tolerated; a broken ClickHouse must apply
    backpressure through the supervisor rather than quarantine everything."""
    _AllPoisonConsumer.created = []
    monkeypatch.setattr(main, "AIOKafkaConsumer", _AllPoisonConsumer)
    monkeypatch.setattr(main, "CORR_QUARANTINE_BURST_MAX", 5)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 1.0)

    async def always_raises(topic, event):
        raise TimeoutError("clickhouse unreachable")

    monkeypatch.setattr(main, "handle", always_raises)

    async def scenario():
        task = asyncio.create_task(main.consume())
        await asyncio.sleep(0.2)
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=1.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    run(scenario())
    assert main.HANDLER_FAILURES["netops.metrics"] == 5   # stopped at the burst cap
    assert len(_AllPoisonConsumer.created) == 1           # handed back to the supervisor


def test_deadletter_payload_is_kept_for_inspection():
    """DeadLetter was counted and logged, but the offending record was dropped —
    so "why did this device stop producing signals" was unanswerable."""
    main.keep_deadletter_payload("trap", {"oid": "1.3.6.1.4.1", "device": "r7"},
                                 ValueError("no observer"))
    rec = main.QUARANTINE[-1]
    assert rec["topic"] == "deadletter:trap"
    assert "1.3.6.1.4.1" in rec["payload"]


def test_quarantine_preserves_the_payload():
    main.quarantine_event("netops.flows", {"src": "10.0.0.1", "bytes": 4}, ValueError("nope"))
    assert main.HANDLER_FAILURES["netops.flows"] == 1
    rec = main.QUARANTINE[-1]
    assert rec["topic"] == "netops.flows"
    assert "ValueError: nope" == rec["error"]
    assert "10.0.0.1" in rec["payload"]           # reproducible, not just a trace


def test_quarantine_is_bounded(monkeypatch):
    """A poison PRODUCER (every event bad) must not become an OOM."""
    for i in range(main.CORR_QUARANTINE_MAX + 50):
        main.quarantine_event("netops.cloud", {"i": i}, ValueError("nope"))
    assert len(main.QUARANTINE) == main.CORR_QUARANTINE_MAX
    assert main.HANDLER_FAILURES["netops.cloud"] == main.CORR_QUARANTINE_MAX + 50


def test_quarantine_writes_a_dead_letter_file_when_configured(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(tmp_path))
    main.quarantine_event("netops.snmptrap", {"oid": "1.3.6"}, KeyError("k"))
    written = (tmp_path / "corr-deadletter.ndjson").read_text()
    assert "1.3.6" in written
    assert "netops.snmptrap" in written


def test_dead_letter_file_is_size_capped(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(tmp_path))
    monkeypatch.setattr(main, "CORR_DLQ_MAX_BYTES", 200)
    for i in range(50):
        main.quarantine_event("netops.cloud", {"payload": "x" * 100, "i": i}, ValueError("v"))
    assert (tmp_path / "corr-deadletter.ndjson").stat().st_size < 1000


def test_unwritable_dlq_never_raises(monkeypatch):
    monkeypatch.setattr(main, "CORR_DLQ_DIR", "/proc/definitely/not/writable")
    before = main.QUARANTINE_WRITE_FAILURES
    main.quarantine_event("netops.cloud", {"a": 1}, ValueError("v"))
    assert main.QUARANTINE_WRITE_FAILURES == before + 1
    assert len(main.QUARANTINE) == 1              # in-memory copy still kept


# ── F-42 / F-39: intake observability ────────────────────────────────────────

def test_unparseable_flow_is_counted(monkeypatch):
    monkeypatch.setattr(main, "ch", RejectingCH(ok=True))
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "FLOW_CORRELATION_ENABLED", True)
    before_ok, before_bad = main.FLOWS_RECEIVED, main.FLOWS_DROPPED
    run(main.handle_flow({"totally": "unparseable"}))
    assert main.FLOWS_DROPPED == before_bad + 1
    assert main.FLOWS_RECEIVED == before_ok      # received means ACCEPTED


def test_syslog_intake_is_counted_before_any_filtering(monkeypatch):
    monkeypatch.setattr(main, "ch", RejectingCH(ok=True))
    before = main.SYSLOG_RECEIVED
    # severity 'debug' has weight 0 → the handler returns early; intake must
    # still be counted or a broken Vector route looks like a quiet night.
    run(main.handle_syslog({"hostname": "leaf1", "severity": "debug", "message": "x"}))
    assert main.SYSLOG_RECEIVED == before + 1


# ── F-44: metrics_dropped names its cause ────────────────────────────────────

def test_metric_drop_causes_are_separately_counted(monkeypatch):
    monkeypatch.setattr(main, "ch", RejectingCH(ok=True))
    base = (main.METRICS_DROPPED_NO_VALUE, main.METRICS_DROPPED_NO_IDENTITY,
            main.METRICS_DROPPED_STALE_TS, main.METRICS_DROPPED)
    now = datetime.now(timezone.utc)

    run(main.handle_metric({"device": "r1", "metric": "device_cpu_percent"}))          # no value
    run(main.handle_metric({"metric": "device_cpu_percent", "value": 1.0}))            # no identity
    run(main.handle_metric({                                                            # stale clock
        "device": "wan-r2", "metric": "device_cpu_percent", "value": 1.0,
        "signal_family": "device_resource",
        "ts": (now - timedelta(seconds=main.METRIC_MAX_AGE_S + 600)).isoformat(),
    }))

    assert main.METRICS_DROPPED_NO_VALUE == base[0] + 1
    assert main.METRICS_DROPPED_NO_IDENTITY == base[1] + 1
    assert main.METRICS_DROPPED_STALE_TS == base[2] + 1
    # the legacy total stays the sum, so existing alerts keep working
    assert main.METRICS_DROPPED == base[3] + 3


# ── F-43: a vanished topology export is stale, not fresh ─────────────────────

def test_missing_enrichment_files_age_into_stale(monkeypatch, tmp_path):
    seams = tmp_path / "seams.json"
    seams.write_text("[]")
    monkeypatch.setattr(main, "SEAM_ENRICHMENT_FILE", str(seams))
    monkeypatch.setattr(main, "TOPO_LINKS_FILE", str(tmp_path / "topology_links.json"))
    monkeypatch.setattr(main, "CORR_TOPO_STALE_S", 180.0)
    monkeypatch.setattr(main, "_TOPO_LAST_SEEN_WALL", None)

    now = datetime.now(timezone.utc)
    assert main._topology_stale(now) is False          # fresh export

    seams.unlink()                                      # the exporter dies
    assert main._topology_stale(now) is False           # inside the grace window
    later = now + timedelta(seconds=400)
    assert main._topology_stale(later) is True          # ages exactly like frozen


def test_frozen_file_is_still_stale(monkeypatch, tmp_path):
    seams = tmp_path / "seams.json"
    seams.write_text("[]")
    old = datetime.now(timezone.utc) - timedelta(seconds=3600)
    os.utime(seams, (old.timestamp(), old.timestamp()))
    monkeypatch.setattr(main, "SEAM_ENRICHMENT_FILE", str(seams))
    monkeypatch.setattr(main, "TOPO_LINKS_FILE", str(tmp_path / "nope.json"))
    monkeypatch.setattr(main, "_TOPO_LAST_SEEN_WALL", None)
    assert main._topology_stale(datetime.now(timezone.utc)) is True


# ── F-45: bounded state ──────────────────────────────────────────────────────

def test_episode_detector_state_is_bounded():
    det = EpisodeDetector(max_series=50)
    now = datetime.now(timezone.utc)
    for i in range(500):
        det.observe("t", f"ephemeral-{i}", "cpu", now + timedelta(seconds=i), 1.0)
    assert len(det._state) <= 50
    assert det.evicted >= 450


def test_episode_detector_keeps_the_recently_active_series():
    det = EpisodeDetector(max_series=3)
    now = datetime.now(timezone.utc)
    for i in range(3):
        det.observe("t", f"e{i}", "cpu", now, 1.0)
    det.observe("t", "e0", "cpu", now + timedelta(seconds=1), 1.0)   # LRU touch
    det.observe("t", "new", "cpu", now + timedelta(seconds=2), 1.0)  # forces eviction
    assert ("t", "e0", "cpu") in det._state
    assert ("t", "e1", "cpu") not in det._state


def test_legacy_series_map_is_bounded(monkeypatch):
    monkeypatch.setattr(main, "SERIES_MAX", 20)
    main.SERIES.clear()
    for i in range(200):
        main.score(f"dev-{i}", "cpu", 1.0)
    assert len(main.SERIES) <= 20


def test_syslog_bucket_key_set_is_swept(monkeypatch):
    """The key is the device-supplied (spoofable) syslog hostname — per-host
    lists were pruned, the key set never was."""
    monkeypatch.setattr(main, "ch", None)
    monkeypatch.setattr(main, "SYSLOG_SWEEP_EVERY_S", 0.0)
    old = main.time.time() - 10 * main.SYSLOG_WINDOW
    for i in range(100):
        main.SYSLOG_BUCKET[f"spoofed-{i}"] = [(old, 3)]
    run(main.handle_syslog({"hostname": "real1", "severity": "err", "message": "x"}))
    assert len(main.SYSLOG_BUCKET) == 1
    assert "real1" in main.SYSLOG_BUCKET


def test_dedup_token_derived_from_kafka_coordinate(monkeypatch):
    # Phase 3: a critical-table insert carries insert_deduplication_token derived
    # from the message coordinate, stable across a retry so ClickHouse dedups.
    sent = []

    class CaptureCH:
        async def insert(self, table, rows, dedup_token=""):
            sent.append((table, dedup_token))
            return True

    monkeypatch.setattr(main, "ch", CaptureCH())
    main.set_dedup_coord("netops.probes", 3, 104857)
    run(main.ch_insert("netops.corr_signals", [{"a": 1}]))
    run(main.ch_insert("netops.corr_objects", [{"a": 1}]))
    # a non-critical table gets NO token (its engine/source-of-truth handles it)
    run(main.ch_insert("netops.corr_signals_archive", [{"a": 1}]))

    assert sent[0] == ("netops.corr_signals", "netops.probes:3:104857:netops.corr_signals:0")
    assert sent[1] == ("netops.corr_objects", "netops.probes:3:104857:netops.corr_objects:1")
    assert sent[2][1] == ""  # non-critical: no token

    # RETRY/redelivery of the SAME message re-derives the SAME tokens.
    sent.clear()
    main.set_dedup_coord("netops.probes", 3, 104857)
    run(main.ch_insert("netops.corr_signals", [{"a": 1}]))
    assert sent[0][1] == "netops.probes:3:104857:netops.corr_signals:0"
