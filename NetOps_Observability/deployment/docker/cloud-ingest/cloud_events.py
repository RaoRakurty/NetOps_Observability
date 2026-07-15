"""Shared cloud MetricEvent builder (AWS / Azure / GCP) — one source of the shape.

The Vector `cloud_metrics_only` transform filters on ``signal_family == "cloud_resource"``
and the metrics lane (Vector metrics_in :8690 → netops.metrics → VictoriaMetrics +
the correlation CUSUM detector) keys the series on an EXACT field set. An event
missing any field is silently DROPPED — a whole GCP series once vanished that way
(azure.py/gcp.py comments, 2026-07-15).

Three provider pollers emit into that one lane, so they MUST emit the identical
shape. This builder is the single source of that shape; ``test_cloud_events.py``
asserts AWS == Azure == GCP produce equal key sets. Requiring the fields here
turns a silent drop into a loud ValueError at emit time.

stdlib-only (the whole cloud-ingest posture): no third-party import.
"""
from __future__ import annotations

# The canonical MetricEvent field set (order = the documented contract). Every
# provider fills the SAME keys; the series is provider-blind downstream.
METRIC_EVENT_FIELDS: tuple[str, ...] = (
    "observer_type", "modality_class", "collection_path", "device", "vendor",
    "index", "signal_family", "metric", "value", "unit", "ts",
)

# collection_path is the ONE field that legitimately varies by provider — it
# records WHICH provider API produced the value. Everything else is neutral.
COLLECTION_PATHS: dict[str, str] = {
    "aws": "cloudwatch_api",
    "azure": "azure_monitor_api",
    "gcp": "gcp_monitoring_api",
}

# Fixed provenance for this lane (see cloudmetrics.py header): a provider-read
# device metric. modality_class is INDEPENDENT of active_probe, so provider
# health + a synthetic check can co-confirm a cloud fault.
_OBSERVER_TYPE = "cloud_provider"
_MODALITY_CLASS = "device_telemetry"
_SIGNAL_FAMILY = "cloud_resource"


def metric_event(
    *,
    vendor: str,
    device: str,
    index: str,
    metric: str,
    value: float,
    unit: str,
    ts: str,
    collection_path: str = "",
) -> dict:
    """Build one canonical cloud MetricEvent.

    All identifying fields are required and validated: a blank required field is
    exactly what the Vector filter drops silently, so we reject it loudly here
    instead. ``value`` may be 0.0 (a real datapoint — e.g. status-check-failed=0)
    but must be numeric.
    """
    cp = collection_path or COLLECTION_PATHS.get(vendor, "")
    required = {
        "vendor": vendor, "collection_path": cp, "device": device,
        "index": index, "metric": metric, "unit": unit, "ts": ts,
    }
    for name, val in required.items():
        if not isinstance(val, str) or not val.strip():
            raise ValueError(f"cloud metric_event: missing/blank {name!r}")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("cloud metric_event: value must be numeric")
    return {
        "observer_type": _OBSERVER_TYPE,
        "modality_class": _MODALITY_CLASS,
        "collection_path": cp,
        "device": device,
        "vendor": vendor,
        "index": index,
        "signal_family": _SIGNAL_FAMILY,
        "metric": metric,
        "value": float(value),
        "unit": unit,
        "ts": ts,
    }
