# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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


# ── netops.cloud control-plane events (change / health) ──────────────────────
# These ride Kafka netops.cloud (not the field-filtered Vector metrics lane), but
# the SAME normalization discipline applies: AWS/Azure/GCP historically buried the
# ROUTING fields (provider, account) in the `attrs` bag and disagreed on which
# top-level keys they set. The correlation ingest reads top-level `provider`
# (app_producers.py), so these builders promote provider + account to top-level
# (never buried) while keeping them in `attrs` too for back-compat, and guarantee
# the three providers emit an IDENTICAL top-level key set. `attrs` is the
# provider-specific DIMENSION bag — legitimately varies, not part of the contract.

# Canonical top-level fields common to every cloud control-plane event.
CHANGE_EVENT_FIELDS: tuple[str, ...] = (
    "kind", "tenant_id", "provider", "account", "resource_id", "region",
    "severity", "metric_name", "observed_at", "ts", "attrs",
)
HEALTH_EVENT_FIELDS: tuple[str, ...] = (
    "kind", "tenant_id", "provider", "account", "resource_id", "region",
    "severity", "state", "observed_at", "ts", "attrs",
)

_VALID_SEVERITY = frozenset(("info", "low", "medium", "warn", "high", "crit"))


def _base_cloud_event(kind: str, *, provider: str, tenant: str, resource_id: str,
                      region: str, severity: str, ts: str, account: str,
                      attrs: dict | None) -> dict:
    if not provider.strip():
        raise ValueError("cloud event: missing provider")
    if severity not in _VALID_SEVERITY:
        raise ValueError(f"cloud event: bad severity {severity!r}")
    dims = dict(attrs or {})
    # Routing fields stay in attrs too (back-compat) but are NOT the truth there.
    dims.setdefault("provider", provider)
    dims.setdefault("account", account)
    return {
        "kind": kind,
        "tenant_id": tenant,
        "provider": provider,
        "account": account,
        "resource_id": resource_id,
        "region": region,
        "severity": severity,
        "observed_at": ts,
        "ts": ts,
        "attrs": dims,
    }


def change_event(*, provider: str, tenant: str, resource_id: str, region: str,
                 severity: str, metric_name: str, ts: str, account: str = "",
                 attrs: dict | None = None) -> dict:
    """A CloudChangeEvent (kind=cloud_change) — a control-plane mutation. Routing
    fields top-level; attrs carries provider-specific dimensions."""
    ev = _base_cloud_event("cloud_change", provider=provider, tenant=tenant,
                           resource_id=resource_id, region=region, severity=severity,
                           ts=ts, account=account, attrs=attrs)
    ev["metric_name"] = metric_name
    return ev


def health_event(*, provider: str, tenant: str, resource_id: str, region: str,
                 severity: str, state: str, ts: str, account: str = "",
                 attrs: dict | None = None) -> dict:
    """A CloudHealthEvent (kind=cloud_resource_health) — a provider-declared
    resource-health state. `state` is promoted top-level (a routing fact)."""
    ev = _base_cloud_event("cloud_resource_health", provider=provider, tenant=tenant,
                           resource_id=resource_id, region=region, severity=severity,
                           ts=ts, account=account, attrs=attrs)
    ev["state"] = state
    return ev


PROVIDER_EVENT_CATEGORIES = frozenset(
    ("issue", "scheduledChange", "accountNotification"))


def provider_event(*, provider: str, tenant: str, event_arn: str, region: str,
                   service: str, category: str, status: str, summary: str,
                   ts: str, account: str = "",
                   attrs: dict | None = None) -> dict:
    """A provider-declared incident/maintenance event (kind=provider_event,
    Wave 5 #16 — the AWS Health lane; other providers' service-health lanes
    emit the same shape). The provider's OWN event id (arn) is the resource
    identity — stable across updates, so a status change (open→closed) folds
    onto the same signal downstream and the latest observation wins.

    severity derives from the provider's category: an active issue is high,
    a scheduled change warns, an account notification informs."""
    if not event_arn.strip():
        raise ValueError("provider_event: missing event_arn")
    if not service.strip():
        raise ValueError("provider_event: missing service")
    cat = category if category in PROVIDER_EVENT_CATEGORIES else "issue"
    severity = {"issue": "high", "scheduledChange": "warn",
                "accountNotification": "info"}[cat]
    dims = dict(attrs or {})
    dims.update({
        "service": service,
        "category": cat,
        "status": status,
        "summary": summary[:300],
        "event_arn": event_arn,
    })
    ev = _base_cloud_event("provider_event", provider=provider, tenant=tenant,
                           resource_id=event_arn, region=region,
                           severity=severity, ts=ts, account=account,
                           attrs=dims)
    ev["metric_name"] = "provider_event"
    ev["value"] = 1.0
    return ev


def clock_skew_event(*, provider: str, tenant: str, family: str, region: str,
                     skew_s: float, tolerance_s: float, ts: str,
                     account: str = "", sample_resource: str = "") -> dict:
    """A clock-skew meta-finding (kind=clock_skew, log-time standard S5/R5):
    an ingest LANE whose records' own event time disagrees with the poller's
    receive clock beyond the family tolerance. The entity is the lane
    (provider/family), never a guessed device; the sample resource_id of the
    triggering record rides in attrs for the investigation. The POLLER
    throttles emission per lane — this builder is pure."""
    if not family.strip():
        raise ValueError("clock_skew event: missing family")
    direction = "ahead" if skew_s > 0 else "behind"
    ev = _base_cloud_event(
        "clock_skew", provider=provider, tenant=tenant,
        resource_id=f"{provider or 'cloud'}/{family}", region=region,
        severity="warn", ts=ts, account=account,
        attrs={
            "clock_skew_s": skew_s,
            "tolerance_s": tolerance_s,
            "direction": direction,
            "lane": family,
            "sample_resource": sample_resource,
        },
    )
    ev["metric_name"] = "clock_skew_s"
    ev["value"] = skew_s
    return ev
