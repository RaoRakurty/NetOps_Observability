"""AWS CloudWatch → the platform's CANONICAL metric lane (Service View counters).

Design decision (deliberate): continuous cloud metric VALUES do NOT go to the
evidence store (corr_signals is fault-triggered and anti-noise). They ride the
same lane the SNMP collector uses — MetricEvent NDJSON → Vector metrics_in
(:8690) → netops.metrics → VictoriaMetrics (display values for the Service View
counters) AND the correlation engine's CUSUM episode detector (so an ANOMALY in
a cloud metric becomes evidence automatically, exactly like a device metric).

One provider integration, two products: live counters and live evidence.

Metrics polled per EC2 instance (5-min CloudWatch resolution, free tier):
  CPUUtilization        → cloud_cpu_util        (percent)
  NetworkIn / NetworkOut→ cloud_net_in/out_bytes(bytes)
  StatusCheckFailed     → cloud_status_check    (count; >0 = provider says the
                          instance is impaired — the provider-health signal)

Provenance: observer_type=cloud_provider, modality_class=device_telemetry,
collection_path=cloudwatch_api. That modality is INDEPENDENT of active_probe,
so provider health + a synthetic app check can co-confirm a cloud app fault —
the gap that made cloud verdicts un-confirmable before.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import urllib.request

import cloud_events

METRICS_SINK = os.environ.get("METRIC_EVENT_SINK_URL", "http://vector-aggregator:8690/")
PERIOD_S = int(os.environ.get("CW_PERIOD_S", "300"))

# CloudWatch metric name → (canonical platform metric, unit, statistic)
CW_METRICS = {
    "CPUUtilization": ("cloud_cpu_util", "percent", "Average"),
    "NetworkIn": ("cloud_net_in_bytes", "bytes", "Sum"),
    "NetworkOut": ("cloud_net_out_bytes", "bytes", "Sum"),
    # Composite AND its parts. The composite says "something broke"; the parts
    # say WHOSE fault it is — _System = AWS's (host/hypervisor/network),
    # _Instance = the customer's (OS/kernel/resource exhaustion). That blame
    # boundary is the whole reason a NOC opens the console (audit P1-1).
    "StatusCheckFailed": ("cloud_status_check_failed", "count", "Maximum"),
    "StatusCheckFailed_System": ("cloud_status_check_failed_system", "count", "Maximum"),
    "StatusCheckFailed_Instance": ("cloud_status_check_failed_instance", "count", "Maximum"),
    # Burstable-instance brownout is invisible without the credit balance: a
    # t-class host at 0 credits crawls while CPUUtilization reads a calm ~20%
    # (the throttled ceiling). The lab fleet is t3 — this is a live blind spot,
    # not a nice-to-have (audit P1-13).
    "CPUCreditBalance": ("cloud_cpu_credit_balance", "count", "Average"),
}


def _post(events: list[dict]) -> None:
    if not events:
        return
    body = "\n".join(json.dumps(e) for e in events).encode()
    req = urllib.request.Request(METRICS_SINK, data=body,
                                 headers={"Content-Type": "application/x-ndjson"})
    urllib.request.urlopen(req, timeout=10).read()  # noqa: S310 - operator-configured sink


def poll(cw, instances: list[dict], provider: str = "aws") -> int:
    """One CloudWatch cycle → MetricEvents on the canonical metric lane.

    ``instances`` is the discovered inventory ([{resource_id, resource_name,
    app_name, private_ips}, …]). Returns the number of metric events emitted.
    """
    if not instances:
        return 0
    # NEVER read the in-flight bucket. CloudWatch's newest period is still
    # filling; for Sum statistics (NetworkIn/Out) that returns a FRACTION of the
    # true value — which, fed to the CUSUM detector, manufactures false
    # "traffic collapsed" evidence on healthy instances, on a schedule
    # (audit 2026-07-13, P0-2). End the window one full period in the past.
    now = dt.datetime.now(dt.timezone.utc)
    end = now - dt.timedelta(seconds=PERIOD_S)
    start = end - dt.timedelta(seconds=PERIOD_S * 3)

    queries, meta = [], {}
    for i, inst in enumerate(instances):
        rid = inst.get("resource_id") or ""
        if not rid.startswith("i-"):
            continue
        # A stopped instance publishes no CloudWatch data. Polling it wastes
        # queries and — worse — makes "stopped" indistinguishable from "broken".
        # The lifecycle state carries that truth instead (audit P1-2).
        if str(inst.get("power_state") or "").lower() not in ("", "running"):
            continue
        for j, (cw_name, (_canon, _unit, stat)) in enumerate(CW_METRICS.items()):
            qid = f"q{i}_{j}"
            meta[qid] = (inst, cw_name)
            queries.append({
                "Id": qid,
                "MetricStat": {
                    "Metric": {"Namespace": "AWS/EC2", "MetricName": cw_name,
                               "Dimensions": [{"Name": "InstanceId", "Value": rid}]},
                    "Period": PERIOD_S, "Stat": stat,
                },
                "ReturnData": True,
            })
    if not queries:
        return 0

    events: list[dict] = []
    # GetMetricData caps at 500 queries per call.
    for chunk in (queries[k:k + 500] for k in range(0, len(queries), 500)):
        resp = cw.get_metric_data(MetricDataQueries=chunk, StartTime=start, EndTime=end,
                                  ScanBy="TimestampDescending")
        for r in resp.get("MetricDataResults", []):
            vals, times = r.get("Values") or [], r.get("Timestamps") or []
            if not vals:
                continue  # no datapoint in the window — absent, never zero
            inst, cw_name = meta[r["Id"]]
            canon, unit, _stat = CW_METRICS[cw_name]
            events.append(cloud_events.metric_event(
                vendor=provider,
                # The instance IS the device for this lane; its private IP is what
                # the Service View / path graph already binds apps to.
                device=inst.get("resource_name") or inst["resource_id"],
                index=inst["resource_id"], metric=canon, value=float(vals[0]),
                unit=unit, ts=times[0].astimezone(dt.timezone.utc).isoformat()))
    _post(events)
    return len(events)
