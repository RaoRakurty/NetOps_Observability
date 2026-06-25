"""Cloud App Observability signal producers — #81 P3G Phase 1.

Cloud App Observability is an EVIDENCE PRODUCER for the existing correlation
engine, NOT a separate RCA system. Cloud health / change / flow / metric / policy
observations become canonical Signals (source=cloud) that flow into corr_signals
and are correlated, grounded and verdicted by the SAME engine (#67). Additive —
the probe / syslog / metric / flow lanes are untouched.

Honest by construction:
  * Every cloud signal carries the mandatory observer block. All cloud-API
    observations from one account/region share ONE observer_id (a single cloud
    vantage, collection_path=via_cloud_api) — so the engine's independence gate
    applies and a cloud-only picture CANNOT confirm on its own (the design's
    "single-plane evidence → suspected at best"). Confirmation still needs a
    second independent observer (a probe, the underlay, the firewall…).
  * The cloud plane maps onto the engine's EXISTING modality vocabulary — no new
    ModalityClass: health/metric → device_telemetry, flow/lb → passive_flow,
    change/audit/security_policy → control_plane.

Pure + deterministic (no IO, no wall-clock); main.py owns tenancy + persistence.
"""

from __future__ import annotations

from datetime import datetime

from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

# kind → (modality_class, observer_type, default entity_type). The design's cloud
# evidence types are corr_signals `kind`s under source=cloud.
CLOUD_KINDS: dict[str, tuple[ModalityClass, ObserverType, EntityType]] = {
    "cloud_health":           (ModalityClass.DEVICE_TELEMETRY, ObserverType.CLOUD_API, EntityType.APP),
    "cloud_resource_health":  (ModalityClass.DEVICE_TELEMETRY, ObserverType.CLOUD_API, EntityType.CLOUD_RESOURCE),
    "cloud_metric":           (ModalityClass.DEVICE_TELEMETRY, ObserverType.CLOUD_API, EntityType.CLOUD_RESOURCE),
    "database_metric":        (ModalityClass.DEVICE_TELEMETRY, ObserverType.CLOUD_API, EntityType.CLOUD_RESOURCE),
    "cloud_flow_log":         (ModalityClass.PASSIVE_FLOW,     ObserverType.FLOW_EXPORTER, EntityType.APP),
    "cloud_lb_log":           (ModalityClass.PASSIVE_FLOW,     ObserverType.CLOUD_API, EntityType.APP),
    "cloud_change":           (ModalityClass.CONTROL_PLANE,    ObserverType.CLOUD_API, EntityType.CLOUD_RESOURCE),
    "cloud_audit":            (ModalityClass.CONTROL_PLANE,    ObserverType.CLOUD_API, EntityType.CLOUD_RESOURCE),
    "security_policy_change": (ModalityClass.CONTROL_PLANE,    ObserverType.CLOUD_API, EntityType.CLOUD_RESOURCE),
}


def cloud_observer(account: str, region: str, obs_type: ObserverType) -> Observer:
    """One cloud vantage per (account, region). Shared observer_id across kinds so
    the independence gate treats the cloud plane as a single observer."""
    return Observer(
        observer_id=f"cloud:{account or 'unknown'}:{region or 'unknown'}",
        observer_type=obs_type,
        location=region,
        trust_domain="cloud_tenant",
        collection_path="via_cloud_api",
        clock_quality="unknown",
    )


def cloud_signal(
    tenant_id: str,
    ts: datetime,
    kind: str,
    *,
    app: str = "",
    resource_id: str = "",
    account: str = "",
    region: str = "",
    severity: Severity = Severity.WARN,
    metric_name: str = "",
    value: float = 0.0,
    baseline: float = 0.0,
    deviation: float = 0.0,
    entity_tokens: tuple[str, ...] = (),
    attrs: dict | None = None,
) -> Signal:
    """Build one canonical cloud Signal. entity is the app (app-centric kinds) or
    the cloud resource. entity_tokens carry app+resource so the engine can ground
    a cloud signal to an app/resource node. Deterministic id via native_id."""
    if kind not in CLOUD_KINDS:
        raise ValueError(f"unknown cloud signal kind: {kind!r}")
    modality, obs_type, default_entity = CLOUD_KINDS[kind]

    if default_entity is EntityType.APP and app:
        entity_type, entity_id = EntityType.APP, app
    elif resource_id:
        entity_type, entity_id = EntityType.CLOUD_RESOURCE, resource_id
    elif app:
        entity_type, entity_id = EntityType.APP, app
    else:
        raise ValueError("cloud_signal needs an app or resource_id")

    tokens = tuple(entity_tokens) or tuple(t for t in (app, resource_id) if t)
    native = f"{kind}|{account}|{region}|{entity_id}|{metric_name}"
    merged_attrs = {
        **(attrs or {}),
        "account": account,
        "region": region,
    }
    if app:
        merged_attrs["app"] = app
    if resource_id:
        merged_attrs["resource_id"] = resource_id

    return Signal(
        tenant_id=tenant_id,
        ts=ts,
        source=Source.CLOUD,
        kind=kind,
        observer=cloud_observer(account, region, obs_type),
        modality_class=modality,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        native_id=native,
        entity_tokens=tokens,
        site=region,
        service_id=app or None,
        metric_name=metric_name,
        value=value,
        baseline=baseline,
        deviation=deviation,
        attrs=merged_attrs,
    )
