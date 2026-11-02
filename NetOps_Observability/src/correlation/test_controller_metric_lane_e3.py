# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""E3 — a controller's canonical device_* samples on netops.metrics.

The NMS runtime forwards vManage real-time interface / CPU / memory samples to
the metric lane with the integration's tenant and collection_path
via_controller (backend nms_scheduler.go nmsEmitMetricEvents). This proves the
engine keeps both: the tenant claim stands (the metric lane is not
registry-anchored and a controller-only device is in no registry), and the
signal lands in the controller authority bucket, so a relayed counter never
pairs with the controller's other evidence as an independent witness.
"""
import unittest
from datetime import datetime, timezone

import main
from episodes import EpisodeEvent
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from verdicts import witness_of


class FakeCH:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def insert(self, table: str, rows, dedup_token="") -> None:
        for r in rows:
            self.rows.append({"_table": table, **r})


def controller_event(**over):
    ev = {
        "observer_type": "controller",
        "modality_class": "device_telemetry",
        "collection_path": "via_controller",
        "device": "ctl-vmanage-4ebbc8f4bc3c",
        "vendor": "vmanage",
        "if_name": "GigabitEthernet2",
        "signal_family": "interface",
        "metric": "device_if_oper_status",
        "value": 2,
        "unit": "state",
        "tenant_id": "t_retail",
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    ev.update(over)
    return ev


class ControllerMetricLaneTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ch = FakeCH()
        self._saved = (main.ch, main.CORR_SIGNALS_ENABLED)
        main.ch = self.ch
        main.CORR_SIGNALS_ENABLED = True
        main.METRICS_RECEIVED = main.METRICS_ACCEPTED = main.METRICS_DROPPED = 0
        self._orig_observe = main.DETECTOR.observe
        main.DETECTOR.observe = self._fake_observe

    def tearDown(self):
        main.DETECTOR.observe = self._orig_observe
        main.ch, main.CORR_SIGNALS_ENABLED = self._saved

    def _fake_observe(self, tenant, entity_id, metric, ts, value, clock_quality="unknown"):
        return EpisodeEvent(phase="onset", key=(tenant, entity_id, metric), onset_ts=ts,
                            onset_uncertainty_s=30.0, value=value, baseline=1.0,
                            deviation=8.0, peak_deviation=8.0, integral=100.0)

    async def test_the_integration_tenant_and_controller_path_survive(self):
        await main.handle_metric(controller_event())
        await main.SIGNAL_BATCH.flush()
        self.assertEqual(main.METRICS_ACCEPTED, 1)
        self.assertEqual(main.METRICS_DROPPED, 0)
        rows = [r for r in self.ch.rows if r["_table"] == "netops.corr_signals"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["tenant_id"], "t_retail", "the integration's tenant claim must stand")
        self.assertEqual(row["collection_path"], "via_controller")
        self.assertEqual(row["entity_type"], "interface")
        self.assertEqual(row["entity_id"], "ctl-vmanage-4ebbc8f4bc3c:GigabitEthernet2",
                         "the same '<device>:<ifName>' entity an SNMP sample of that device would bind")

    def test_a_via_controller_witness_is_in_the_controller_authority_bucket(self):
        sig = Signal(
            tenant_id="t_retail", ts=datetime.now(timezone.utc), source=Source.METRIC,
            kind="if_metric_anomaly",
            observer=Observer(observer_id="ctl-vmanage-4ebbc8f4bc3c", observer_type=ObserverType.DEVICE,
                              collection_path="via_controller"),
            modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.INTERFACE,
            entity_id="ctl-vmanage-4ebbc8f4bc3c:GigabitEthernet2", severity=Severity.HIGH,
            native_id="e3|1",
        )
        self.assertEqual(witness_of(sig).authority, "via_controller")
