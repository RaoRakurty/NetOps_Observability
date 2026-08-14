"""Commit 2 — correlation metric-lane intake tests.

Proves the netops.metrics → device_telemetry contract the platform architecture
requires (Layer 1 A/D/F + Layer 4 A of the test program):

  * canonical MetricEvent identity resolution (interface / bgp / resource)
  * RCA signal carries the right observer/modality/collection provenance + identity
  * malformed events are DROPPED and counted, never turned into signals
  * timestamp skew/staleness is rejected (the onset budget must be trustworthy)

These run without a live ClickHouse: a fake CH captures inserted rows and the
episode detector is driven by a synthetic EpisodeEvent so the test asserts the
intake contract, not CUSUM tuning (covered by test_episodes/test_anomaly).
"""
import asyncio
import unittest
from datetime import datetime, timedelta, timezone

import main
from episodes import EpisodeEvent
from signals import EntityType


class FakeCH:
    """Captures rows handed to insert() so tests can assert the canonical row."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def insert(self, table: str, rows, dedup_token="") -> None:
        for r in rows:
            self.rows.append({"_table": table, **r})


def run(coro):
    return asyncio.run(coro)


def iface_event(**over):
    ev = {
        "observer_type": "device",
        "modality_class": "device_telemetry",
        "collection_path": "snmp_poll",
        "device": "leaf1",
        "vendor": "arista",
        "if_name": "Ethernet1",
        "index": "1",
        "signal_family": "interface",
        "metric": "device_if_in_errors",
        "value": 5,
        "unit": "errors",
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    ev.update(over)
    return ev


class MetricIdentityTest(unittest.TestCase):
    def test_interface_identity(self):
        out = main.metric_identity(iface_event())
        self.assertIsNotNone(out)
        entity_id, etype, _kind, tokens = out
        self.assertEqual(entity_id, "leaf1:Ethernet1")
        self.assertEqual(etype, EntityType.INTERFACE)
        self.assertIn("leaf1", tokens)
        self.assertIn("Ethernet1", tokens)

    def test_interface_falls_back_to_index(self):
        out = main.metric_identity(iface_event(if_name="", index="7"))
        self.assertEqual(out[0], "leaf1:7")

    def test_bgp_identity_maps_to_peer(self):
        out = main.metric_identity(
            {"device": "leaf2", "signal_family": "bgp", "peer": "10.0.0.5",
             "metric": "device_bgp_peer_state", "value": 6}
        )
        self.assertEqual(out[0], "leaf2:10.0.0.5")
        self.assertEqual(out[1], EntityType.DEVICE)

    def test_resource_identity_is_device(self):
        out = main.metric_identity(
            {"device": "wan-r2", "signal_family": "device_resource",
             "metric": "device_cpu_percent", "value": 12}
        )
        self.assertEqual(out[0], "wan-r2")

    def test_missing_device_or_identity_returns_none(self):
        self.assertIsNone(main.metric_identity(iface_event(device="")))
        self.assertIsNone(main.metric_identity(iface_event(if_name="", index="")))
        self.assertIsNone(main.metric_identity(
            {"device": "x", "signal_family": "wat", "metric": "m", "value": 1}))


class HandleMetricTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ch = FakeCH()
        main.ch = self.ch
        main.CORR_SIGNALS_ENABLED = True
        # reset counters
        main.METRICS_RECEIVED = main.METRICS_ACCEPTED = main.METRICS_DROPPED = 0
        main.DEVICE_TELEMETRY_SIGNALS = 0
        # Force a deterministic episode onset regardless of CUSUM internals.
        self._orig_observe = main.DETECTOR.observe
        main.DETECTOR.observe = self._fake_observe

    def tearDown(self):
        main.DETECTOR.observe = self._orig_observe

    def _fake_observe(self, tenant, entity_id, metric, ts, value, clock_quality="unknown"):
        return EpisodeEvent(
            phase="onset", key=(tenant, entity_id, metric), onset_ts=ts,
            onset_uncertainty_s=30.0, value=value, baseline=0.0,
            deviation=8.0, peak_deviation=8.0, integral=100.0,
        )

    async def test_valid_interface_event_creates_device_telemetry_signal(self):
        await main.handle_metric(iface_event())
        await main.SIGNAL_BATCH.flush()  # drain the batched write path
        self.assertEqual(main.METRICS_RECEIVED, 1)
        self.assertEqual(main.METRICS_ACCEPTED, 1)
        self.assertEqual(main.METRICS_DROPPED, 0)
        self.assertEqual(main.DEVICE_TELEMETRY_SIGNALS, 1)
        sig_rows = [r for r in self.ch.rows if r["_table"] == "netops.corr_signals"]
        self.assertEqual(len(sig_rows), 1)
        row = sig_rows[0]
        # Single canonical contract: provenance + identity all present & correct.
        self.assertEqual(row["observer_type"], "device")
        self.assertEqual(row["modality_class"], "device_telemetry")
        self.assertEqual(row["collection_path"], "snmp_poll")
        self.assertEqual(row["entity_type"], "interface")
        self.assertEqual(row["entity_id"], "leaf1:Ethernet1")
        self.assertEqual(row["observer_id"], "leaf1")
        self.assertEqual(row["metric_name"], "device_if_in_errors")

    async def test_bgp_event_carries_peer_identity(self):
        await main.handle_metric(
            {"device": "leaf2", "signal_family": "bgp", "peer": "10.0.0.5",
             "collection_path": "snmp_poll", "metric": "device_bgp_peer_state",
             "value": 1, "ts": datetime.now(timezone.utc).isoformat()})
        await main.SIGNAL_BATCH.flush()  # drain the batched write path
        sig = next(r for r in self.ch.rows if r["_table"] == "netops.corr_signals")
        self.assertEqual(sig["entity_id"], "leaf2:10.0.0.5")
        self.assertEqual(sig["modality_class"], "device_telemetry")

    async def test_missing_value_dropped_no_signal(self):
        await main.handle_metric(iface_event(value=None))
        self.assertEqual(main.METRICS_DROPPED, 1)
        self.assertEqual(main.DEVICE_TELEMETRY_SIGNALS, 0)
        self.assertEqual(self.ch.rows, [])

    async def test_bool_value_is_not_numeric(self):
        # bool is a subclass of int — must be rejected, not scored as 0/1.
        await main.handle_metric(iface_event(value=True))
        self.assertEqual(main.METRICS_DROPPED, 1)

    async def test_missing_identity_dropped(self):
        await main.handle_metric(iface_event(device=""))
        self.assertEqual(main.METRICS_DROPPED, 1)
        self.assertEqual(self.ch.rows, [])

    async def test_future_timestamp_rejected(self):
        future = (datetime.now(timezone.utc) + timedelta(seconds=600)).isoformat()
        await main.handle_metric(iface_event(ts=future))
        self.assertEqual(main.METRICS_DROPPED, 1)
        self.assertEqual(self.ch.rows, [])

    async def test_stale_timestamp_rejected(self):
        stale = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        await main.handle_metric(iface_event(ts=stale))
        self.assertEqual(main.METRICS_DROPPED, 1)


if __name__ == "__main__":
    unittest.main()
