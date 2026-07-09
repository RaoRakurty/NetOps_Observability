"""LB / proxy / ingress telemetry contract (#98 Phase 5) — vendor-neutral
normalization of application-edge events into the CANONICAL kinds the catalog
already consumes. NOT APM: no traces, no spans, no in-process agents — the
load balancer / reverse proxy / ingress reporting its own request outcomes.

Vocabulary (existing catalog kinds — deliberately no third vocabulary):

  * ``lb_5xx``               — 5xx family; the reason code carries specificity
                               (http_5xx / bad_gateway / backend_unavailable /
                               gateway_timeout)
  * ``lb_target_unhealthy``  — backend pool / member / target-group health
  * ``app_error_rate_high``  — declared error-rate anomaly at the app edge
  * ``app_latency_high``     — declared latency anomaly at the app edge
  * ``lb_4xx_high``          — high 4xx rate. Deliberately consumed by NO
                               outage signature (INTENTIONAL_BLIND): a 401/403/
                               404 spike is an auth/config/client indicator,
                               not provider-outage evidence — it must never
                               help confirm one.

Modality: ``device_telemetry`` — the app-edge device reporting its own
counters. That keeps this lane INDEPENDENT of active_probe (synthetics) and
passive_flow (flow anomalies) in the verdict gate without widening the core
modality taxonomy; ``attrs.lane = "app_gateway"`` marks the sub-lane.

Threshold policy: rate/latency kinds require the event to DECLARE the anomaly
(``anomaly: true`` plus the measured/baseline fields) — detection belongs to
the emitting collector or an upstream baseline, not to this normalizer
(no new statistical system here). Discrete 5xx / backend-health events map
directly.

One raw event → at most ONE semantic signal (single emission — an event that
is both 503 and backend-unavailable is ONE observation and must never become
two evidence streams). ``native_id`` carries the raw event id when supplied.

Zero trust (§3): tenant comes from the caller (topic handler enforces
default-closed tenancy); every field is optional-defensive; nothing here
executes or trusts payload content beyond typed extraction.
"""
from __future__ import annotations

from datetime import datetime

from flow_app_attribution import normalize_app
from producers import parse_event_ts
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

LB_KINDS: frozenset[str] = frozenset({
    "lb_5xx", "lb_target_unhealthy", "app_error_rate_high",
    "app_latency_high", "lb_4xx_high",
})

_5XX_REASON = {502: "bad_gateway", 503: "backend_unavailable", 504: "gateway_timeout"}


def _num(ev: dict, key: str) -> float | None:
    v = ev.get(key)
    return float(v) if isinstance(v, (int, float)) else None


def _truthy(ev: dict, key: str) -> bool:
    return bool(ev.get(key))


def classify_lb_event(ev: dict) -> tuple[str | None, str | None, Severity]:
    """One raw app-edge event → (kind, reason, severity); (None, None, INFO)
    when the event is healthy / carries nothing actionable."""
    reason = str(ev.get("reason") or "").strip()
    status = ev.get("status_code")
    status = int(status) if isinstance(status, (int, float)) else None

    # backend / pool / target health — service-side evidence, strongest form.
    if reason in ("backend_pool_down", "pool_member_down", "target_group_unhealthy") \
            or _truthy(ev, "backend_pool_down") or _truthy(ev, "target_unhealthy"):
        return "lb_target_unhealthy", reason or "target_group_unhealthy", Severity.HIGH

    if status is not None and 500 <= status <= 599:
        return "lb_5xx", _5XX_REASON.get(status, "http_5xx"), Severity.HIGH

    if (status is not None and 400 <= status <= 499) or reason == "http_4xx_high":
        # auth/config/client-side indicator — never outage-confirming.
        return "lb_4xx_high", "http_4xx_high", Severity.WARN

    if _truthy(ev, "anomaly"):
        if reason in ("upstream_connect_fail", "connection_reset_high", "request_drop_high"):
            return "lb_5xx", reason, Severity.HIGH
        err = _num(ev, "error_rate")
        if err is not None:
            return "app_error_rate_high", reason or "error_rate_high", Severity.HIGH
        if _num(ev, "latency_ms") is not None or _num(ev, "p95_latency_ms") is not None \
                or _num(ev, "p99_latency_ms") is not None:
            return "app_latency_high", reason or "latency_high", Severity.WARN
    return None, None, Severity.INFO


def normalize_lb_event(ev: dict, tenant: str, ingest_ts: datetime) -> Signal | None:
    """One vendor-neutral app-edge event → at most one canonical Signal.

    App identity is generic: explicit app fields → normalized slug; else the
    target host (honest fallback, same policy as the synthetic lane). Grounding
    tokens mirror the app-experience vocabulary (bare slug + app:<slug>) so LB
    evidence co-locates with synthetic and app-attributed flow evidence on ONE
    application-impact object."""
    kind, reason, severity = classify_lb_event(ev)
    if kind is None:
        return None

    app = normalize_app(str(ev.get("app_name") or ev.get("app") or ""))
    service = str(ev.get("service_name") or ev.get("service_id") or "")
    host = str(ev.get("host") or ev.get("target_host") or ev.get("domain") or "")
    if not app and not host and not service:
        return None  # nothing to ground on — an ungroundable event is noise
    entity_id = app or normalize_app(service) or host
    entity_type = EntityType.APP if app else EntityType.SERVICE

    lb_name = str(ev.get("lb_name") or ev.get("lb_device_id") or
                  ev.get("gateway_name") or ev.get("ingress_name") or "")
    pool = str(ev.get("backend_pool") or ev.get("target_group") or "")
    site = str(ev.get("site_id") or ev.get("region") or "")
    ts = parse_event_ts(ev.get("ts") or ev.get("timestamp")) or ingest_ts

    # NO tenant token — grounding tokens are co-location keys and the window is
    # single-tenant by construction; a tenant-wide token would merge unrelated
    # apps into one object (see synthetic_normalize.py, same rule).
    tokens: list[str] = [entity_id]
    if app:
        tokens += [f"app:{app}"]
    if service:
        tokens += [f"service:{normalize_app(service)}"]
    if host:
        tokens += [host, f"host:{host}"]
    if lb_name:
        tokens += [f"lb:{lb_name}"]
    if pool:
        tokens += [f"backend_pool:{pool}"]
    if site:
        tokens += [f"site:{site}"]

    attrs: dict = {
        "lane": "app_gateway",
        "raw_kind": str(ev.get("source") or "lb"),
        "vendor": str(ev.get("vendor") or "generic"),
        "product": str(ev.get("product") or ""),
        "reason": reason,
    }
    for key in ("status_code", "method", "path", "route", "host",
                "request_count", "error_count", "error_rate",
                "latency_ms", "p95_latency_ms", "p99_latency_ms",
                "backend_pool", "target_group", "pool_member", "upstream_host",
                "vip", "backend_ip", "backend_port",
                "baseline_error_rate", "site_id", "region"):
        if ev.get(key) not in (None, ""):
            attrs[key] = ev[key]
    if app:
        attrs["app_name"] = app
    if service:
        attrs["service_name"] = service

    raw_id = str(ev.get("raw_event_id") or ev.get("event_id") or "")
    native = raw_id or f"lb|{lb_name or 'edge'}|{entity_id}|{kind}|{int(ts.timestamp() * 1000)}"

    return Signal(
        tenant_id=tenant,
        ts=ts,
        source=Source.METRIC,                 # app-edge device telemetry lane
        kind=kind,
        observer=Observer(
            observer_id=lb_name or f"app-edge:{str(ev.get('collector') or 'generic')}",
            observer_type=ObserverType.DEVICE,
            location=site,
            collection_path="via_aggregator",
            clock_quality="unknown",
        ),
        modality_class=ModalityClass.DEVICE_TELEMETRY,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        native_id=native,
        entity_tokens=tuple(tokens),
        service_id=entity_id,
        metric_name=f"app_edge[{attrs['raw_kind']}]",
        value=float(attrs.get("error_rate") or attrs.get("status_code") or 1.0),
        attrs=attrs,
    )
