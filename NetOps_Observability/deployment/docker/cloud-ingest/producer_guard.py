# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Delivery-checked Kafka producer wrapper for the cloud-ingest poller.

kafka-python's `send()` is asynchronous: it returns a future and NEVER raises
for a delivery failure. Every lane in this service called `producer.send(...)`
and discarded that future, so a record that exhausted `retries=5` (broker down
past the retry budget, message too large, topic authorization revoked,
serialization error) vanished with no log, no counter and no cycle-level
signal — the poller's own logs would still read "cloudtrail changes produced
count=42" for 42 records nobody ever received.

This wrapper is the one place that observes the delivery RESULT:

  * per-record errback → structured error log (rate-limited per topic so a
    broker outage cannot turn into a log flood) + a bounded counter;
  * a synchronous failure of `send()` itself (buffer full / metadata timeout)
    is caught, counted and logged, never raised into a poll lane;
  * `failed_count` lets a caller bracket a batch and VERIFY delivery before it
    advances a checkpoint past those records (see cost.py's day checkpoint).

Labels stay bounded (topic only — never a tenant, account or payload), matching
the ingest_metrics honesty contract.

Scale P0 — tenant partition keying: this wrapper is ALSO the single choke
point where every record this service produces gets its Kafka message key.
The correlation tier scales horizontally by tenant-keyed co-partitioning:
every producer on the bus must key each record by the event's tenant
("global" when untenanted) so one tenant's events land on ONE partition of
every topic. kafka-python's DefaultPartitioner is the Java-compatible murmur2
— the same hash Vector's sinks use (librdkafka `murmur2_random`) — so keying
here, with no partitioner override, lands on the same partition NUMBER as
every other producer. A caller may pass an explicit `key=`; otherwise the key
derives from `value["tenant_id"]`. Never key by account/resource/region —
high-cardinality keys scatter a tenant across partitions and break
co-partitioning.

stdlib-only; the wrapped object only has to provide send()/flush().
"""
from __future__ import annotations

import json
import threading
import time

import ingest_metrics

# One error log per topic per interval: a broker outage fails every record in
# the batch, and 10k identical lines drown the one line that explains it.
LOG_EVERY_S = 30.0


def tenant_key(value) -> bytes:
    """The Kafka message key for one record: its tenant, "global" fallback.

    Mirrors the platform-wide keying rule (Vector lanes, the Go bus-bridge
    producers): key = tenant_id, empty/absent → "global" (the same fold the
    correlation consumer's canon_tenant applies)."""
    tenant = ""
    if isinstance(value, dict):
        tenant = str(value.get("tenant_id") or "")
    return (tenant or "global").encode("utf-8")


class GuardedProducer:
    """Wraps a KafkaProducer so no produce failure can be silent.

    Deliberately NOT a subclass: the lanes only use send()/flush(), and a thin
    explicit surface keeps the fake producers in the tests valid.
    """

    def __init__(self, producer, *, log_every_s: float = LOG_EVERY_S) -> None:
        self._producer = producer
        self._log_every_s = log_every_s
        self._lock = threading.Lock()
        self._failed = 0
        self._sent = 0
        self._last_log: dict[str, float] = {}
        self._last_error = ""

    # ── counters ─────────────────────────────────────────────────────────────

    @property
    def failed_count(self) -> int:
        """Records whose delivery is known to have FAILED (monotonic)."""
        with self._lock:
            return self._failed

    @property
    def sent_count(self) -> int:
        """Records handed to the producer (monotonic)."""
        with self._lock:
            return self._sent

    @property
    def last_error(self) -> str:
        with self._lock:
            return self._last_error

    # ── the produce path ─────────────────────────────────────────────────────

    def send(self, topic, value, **kw):
        """Produce one record and register a delivery-result callback.

        Returns the underlying future (None when the send could not even be
        enqueued) — no existing caller inspects it, but a caller that wants
        synchronous certainty can.
        """
        with self._lock:
            self._sent += 1
        # Scale P0: tenant partition key (see the module docstring). Derived
        # here so every lane — current and future — is keyed without each
        # call site remembering to; an explicit key= wins.
        if "key" not in kw:
            kw["key"] = tenant_key(value)
        try:
            fut = self._producer.send(topic, value, **kw)
        except Exception as exc:  # noqa: BLE001 — a produce error never kills a lane
            self._note_failure(topic, exc)
            return None
        add_errback = getattr(fut, "add_errback", None)
        if callable(add_errback):
            add_errback(lambda exc, _t=topic: self._note_failure(_t, exc))
        return fut

    def flush(self, timeout=None):
        """Block until buffered records are acknowledged. Propagates the
        underlying timeout error: a caller that flushes before advancing a
        checkpoint MUST see it (cost.py F-37)."""
        return self._producer.flush(timeout)

    def __getattr__(self, name):
        # Anything else the lanes may reach for (partitions_for, metrics, ...)
        # passes through unchanged.
        return getattr(self._producer, name)

    # ── failure accounting ───────────────────────────────────────────────────

    def _note_failure(self, topic, exc) -> None:
        topic = str(topic)
        detail = f"{type(exc).__name__}: {exc}"[:200]
        now = time.monotonic()
        with self._lock:
            self._failed += 1
            self._last_error = detail
            due = (now - self._last_log.get(topic, -1e9)) >= self._log_every_s
            if due:
                self._last_log[topic] = now
            failed = self._failed
        ingest_metrics.record_produce_failure(topic)
        if due:
            print(json.dumps({
                "ts": time.time(), "service": "cloud-ingest",
                "component": "producer",
                "msg": "kafka produce FAILED — record lost",
                "topic": topic, "error": detail, "failed_total": failed,
            }), flush=True)
