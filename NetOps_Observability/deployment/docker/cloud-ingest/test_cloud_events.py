# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Contract tests for the shared cloud MetricEvent shape (cloud_events.py).

The Vector metrics lane silently DROPS an event missing any contract field, and
three provider pollers (AWS/Azure/GCP) feed that one lane — so their event
schemas must be provably identical. These tests pin that:

  * the builder emits exactly the documented field set, for every provider;
  * the REAL AWS path (cloudmetrics.poll) and REAL Azure path (azure.poll_metrics)
    emit that same set — i.e. both are wired to the shared builder;
  * AWS == Azure == GCP key sets;
  * no provider hand-rolls a divergent event dict (anti-drift source guard);
  * a missing field is a loud ValueError, not a silent drop.

Run: python3 -m pytest test_cloud_events.py
"""
import datetime as dt
import json
import pathlib
import unittest

import cloud_events

from cloud_events import (CHANGE_EVENT_FIELDS, HEALTH_EVENT_FIELDS,
                          METRIC_EVENT_FIELDS, change_event, health_event,
                          metric_event)

HERE = pathlib.Path(__file__).resolve().parent


def _one(vendor: str) -> dict:
    return metric_event(vendor=vendor, device="d", index="i", metric="cloud_cpu_util",
                        value=1.0, unit="percent", ts="2026-07-15T00:00:00Z")


class TestBuilder(unittest.TestCase):
    def test_exact_field_set_per_provider(self):
        for v in ("aws", "azure", "gcp"):
            self.assertEqual(set(_one(v).keys()), set(METRIC_EVENT_FIELDS),
                             f"{v} builder drifted from the contract")

    def test_all_providers_identical_key_sets(self):
        aws, az, g = _one("aws").keys(), _one("azure").keys(), _one("gcp").keys()
        self.assertEqual(set(aws), set(az))
        self.assertEqual(set(az), set(g))

    def test_collection_path_per_provider(self):
        self.assertEqual(_one("aws")["collection_path"], "cloudwatch_api")
        self.assertEqual(_one("azure")["collection_path"], "azure_monitor_api")
        self.assertEqual(_one("gcp")["collection_path"], "gcp_monitoring_api")

    def test_neutral_fields_are_provider_blind(self):
        aws, az = _one("aws"), _one("azure")
        for f in ("observer_type", "modality_class", "signal_family"):
            self.assertEqual(aws[f], az[f])

    def test_value_zero_is_valid(self):
        # 0.0 is a real datapoint (status-check-failed=0), never rejected.
        ev = metric_event(vendor="aws", device="d", index="i", metric="m",
                          value=0.0, unit="count", ts="t")
        self.assertEqual(ev["value"], 0.0)

    def test_missing_field_raises(self):
        for bad in ({"device": ""}, {"index": ""}, {"ts": ""}, {"metric": ""}):
            kw = dict(vendor="aws", device="d", index="i", metric="m",
                      value=1.0, unit="count", ts="t")
            kw.update(bad)
            with self.assertRaises(ValueError):
                metric_event(**kw)

    def test_bool_value_rejected(self):
        with self.assertRaises(ValueError):
            metric_event(vendor="aws", device="d", index="i", metric="m",
                         value=True, unit="count", ts="t")  # type: ignore[arg-type]


def _change(vendor: str) -> dict:
    return change_event(provider=vendor, tenant="t", resource_id="r", region="reg",
                        severity="medium", metric_name="Modify", ts="2026-07-15T00:00:00Z",
                        account="acct", attrs={"actor": "u"})


def _health(vendor: str) -> dict:
    return health_event(provider=vendor, tenant="t", resource_id="r", region="reg",
                        severity="crit", state="Unavailable", ts="2026-07-15T00:00:00Z",
                        account="acct")


class TestControlPlaneContract(unittest.TestCase):
    def test_change_event_identical_across_providers(self):
        aws, az, g = _change("aws"), _change("azure"), _change("gcp")
        self.assertEqual(set(aws), set(CHANGE_EVENT_FIELDS))
        self.assertEqual(set(aws), set(az))
        self.assertEqual(set(az), set(g))

    def test_health_event_identical_across_providers(self):
        aws, az, g = _health("aws"), _health("azure"), _health("gcp")
        self.assertEqual(set(aws), set(HEALTH_EVENT_FIELDS))
        self.assertEqual(set(aws), set(az))
        self.assertEqual(set(az), set(g))

    def test_routing_fields_top_level_not_only_in_attrs(self):
        # provider + account must be readable WITHOUT digging into the label bag.
        ev = _change("azure")
        self.assertEqual(ev["provider"], "azure")
        self.assertEqual(ev["account"], "acct")
        # kept in attrs too (back-compat), but the top-level is the routing truth.
        self.assertEqual(ev["attrs"]["provider"], "azure")

    def test_bad_severity_rejected(self):
        with self.assertRaises(ValueError):
            change_event(provider="aws", tenant="t", resource_id="r", region="reg",
                         severity="BOGUS", metric_name="m", ts="t")


class _FakeCW:
    """Minimal CloudWatch stub for cloudmetrics.poll (real AWS path)."""
    def get_metric_data(self, MetricDataQueries, StartTime, EndTime, ScanBy):  # noqa: N803
        results = []
        for q in MetricDataQueries:
            results.append({"Id": q["Id"], "Values": [42.0],
                            "Timestamps": [dt.datetime(2026, 7, 15, tzinfo=dt.timezone.utc)]})
        return {"MetricDataResults": results}


class TestRealAWSPath(unittest.TestCase):
    def test_aws_poll_emits_contract_fields(self):
        import cloudmetrics
        captured: list[dict] = []
        orig = cloudmetrics._post
        cloudmetrics._post = lambda events: captured.extend(events)  # noqa: SLF001
        try:
            n = cloudmetrics.poll(_FakeCW(), [{
                "resource_id": "i-0abc", "resource_name": "web01", "power_state": "running"}])
        finally:
            cloudmetrics._post = orig  # noqa: SLF001
        self.assertGreater(n, 0)
        for ev in captured:
            self.assertEqual(set(ev.keys()), set(METRIC_EVENT_FIELDS))
            self.assertEqual(ev["vendor"], "aws")
            self.assertEqual(ev["collection_path"], "cloudwatch_api")


class TestRealAzurePath(unittest.TestCase):
    def test_azure_poll_emits_contract_fields(self):
        import urllib.request

        import azure
        captured: list[dict] = []

        def fake_get_json(url, tok):
            # Every aggregation key present so any AZ_METRICS entry resolves.
            return {"value": [{"timeseries": [{"data": [{
                "average": 5.0, "total": 5.0, "minimum": 1.0, "maximum": 5.0,
                "timeStamp": "2026-07-15T00:00:00Z"}]}]}]}

        class _Resp:
            def read(self):
                return b""

        def fake_urlopen(req, timeout=0, context=None):
            for line in (req.data or b"").decode().splitlines():
                captured.append(json.loads(line))
            return _Resp()

        orig_get, orig_open = azure._get_json, urllib.request.urlopen  # noqa: SLF001
        azure._get_json = fake_get_json  # noqa: SLF001
        urllib.request.urlopen = fake_urlopen
        try:
            azure.poll_metrics("tok", [{
                "name": "web01", "resource_id": "/subscriptions/s/rg/vm",
                "power_state": "running"}])
        finally:
            azure._get_json = orig_get  # noqa: SLF001
            urllib.request.urlopen = orig_open
        self.assertGreater(len(captured), 0)
        for ev in captured:
            self.assertEqual(set(ev.keys()), set(METRIC_EVENT_FIELDS))
            self.assertEqual(ev["vendor"], "azure")
            self.assertEqual(ev["collection_path"], "azure_monitor_api")


class TestNoHandRolledEvents(unittest.TestCase):
    def test_no_provider_hand_rolls_the_event_dict(self):
        # Anti-drift: the emit path must go through the shared builder. A raw
        # "observer_type": literal in a provider poller means a divergent shape
        # can be reintroduced without the builder's validation.
        for fn in ("azure.py", "gcp.py", "cloudmetrics.py"):
            src = (HERE / fn).read_text()
            self.assertNotIn('"observer_type"', src,
                             f"{fn} hand-rolls a MetricEvent — route it through cloud_events.metric_event")
        # Change/health events must also go through the shared builders so every
        # provider stays key-identical (the exact drift that split AWS/Azure/GCP).
        for fn in ("azure.py", "gcp.py", "poller.py"):
            src = (HERE / fn).read_text()
            for lit in ('"kind": "cloud_change"', '"kind": "cloud_resource_health"'):
                self.assertNotIn(lit, src,
                                 f"{fn} hand-rolls {lit} — route it through cloud_events.change_event/health_event")


class TestClockSkewEvent(unittest.TestCase):
    def test_clock_skew_event_shape(self):
        ev = cloud_events.clock_skew_event(
            provider="aws", tenant="acme", family="lb", region="us-east-1",
            skew_s=-2400.0, tolerance_s=900.0, ts="2026-07-17T00:00:00Z",
            account="123456789012", sample_resource="app/billing-alb/0a1b2c",
        )
        self.assertEqual(ev["kind"], "clock_skew")
        self.assertEqual(ev["resource_id"], "aws/lb")   # the LANE, never a guessed device
        self.assertEqual(ev["severity"], "warn")
        self.assertEqual(ev["value"], -2400.0)
        self.assertEqual(ev["metric_name"], "clock_skew_s")
        self.assertEqual(ev["attrs"]["direction"], "behind")
        self.assertEqual(ev["attrs"]["tolerance_s"], 900.0)
        self.assertEqual(ev["attrs"]["sample_resource"], "app/billing-alb/0a1b2c")
        # Routing fields are top-level like every other netops.cloud event.
        self.assertEqual(ev["provider"], "aws")
        self.assertEqual(ev["tenant_id"], "acme")

    def test_clock_skew_event_requires_family(self):
        with self.assertRaises(ValueError):
            cloud_events.clock_skew_event(
                provider="aws", tenant="acme", family=" ", region="r",
                skew_s=1.0, tolerance_s=1.0, ts="2026-07-17T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
