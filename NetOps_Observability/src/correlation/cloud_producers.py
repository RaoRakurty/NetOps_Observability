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

from producers import parse_event_ts
from signals import (
    DeadLetter,
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
    # Aggregated ACCEPT-flow volume per ENI (audit P1-6): observed traffic as
    # evidence, one rollup per ENI per scan — never per-flow firehose.
    "cloud_flow_volume":      (ModalityClass.PASSIVE_FLOW,     ObserverType.FLOW_EXPORTER, EntityType.CLOUD_RESOURCE),
    "cloud_lb_log":           (ModalityClass.PASSIVE_FLOW,     ObserverType.CLOUD_API, EntityType.APP),
    "cloud_change":           (ModalityClass.CONTROL_PLANE,    ObserverType.CLOUD_API, EntityType.CLOUD_RESOURCE),
    "cloud_audit":            (ModalityClass.CONTROL_PLANE,    ObserverType.CLOUD_API, EntityType.CLOUD_RESOURCE),
    "security_policy_change": (ModalityClass.CONTROL_PLANE,    ObserverType.CLOUD_API, EntityType.CLOUD_RESOURCE),
    # IPsec / IKE tunnel status from the ENTERPRISE VPN gateway (strongSwan/charon
    # or a cloud VPN gateway's own telemetry). CONTROL_PLANE, but observed by the
    # gateway itself — a CONTROLLER observer that is INDEPENDENT of the cloud API
    # (different observer_id, see cloud_observer). That independence is the point:
    # a tunnel-down seen by the gateway control plane AND app impact seen by an
    # active probe are two observers, so an IPsec outage can reach a CONFIRMED
    # verdict instead of the cloud-only "suspected" ceiling. Entity is the seam
    # (the tunnel), tokens carry the CIDRs/apps behind it.
    "ipsec_tunnel_status":    (ModalityClass.CONTROL_PLANE,    ObserverType.CONTROLLER, EntityType.CLOUD_RESOURCE),
    # The gateway's own OFF-TUNNEL reachability check to the peer's public
    # address (rides the default route, not the tunnel). When this is down the
    # transport UNDER the tunnel is dead — the root of the ipsec-underlay-down
    # signature (owner directive 2026-07-13). ACTIVE_PROBE (it is a measurement,
    # not a state report), same independent ipsec:<gw> observer as tunnel state.
    "ipsec_underlay_status":  (ModalityClass.ACTIVE_PROBE,     ObserverType.CONTROLLER, EntityType.CLOUD_RESOURCE),
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


def ipsec_gateway_observer(gateway_id: str, location: str) -> Observer:
    """The ENTERPRISE VPN gateway reporting its own IKE/IPsec state. Deliberately a
    DIFFERENT observer_id namespace than cloud_observer (`ipsec:<gw>` vs
    `cloud:<acct>:<region>`) and a different trust domain, so the independence gate
    counts it as a second, independent witness alongside cloud-API health/flow —
    which is what lets an IPsec outage confirm instead of staying 'suspected'.
    Collected directly at the gateway (not via the cloud API), so fate-sharing
    analysis does not collapse it into the cloud plane."""
    return Observer(
        observer_id=f"ipsec:{gateway_id or 'unknown'}",
        observer_type=ObserverType.CONTROLLER,
        location=location,
        trust_domain="enterprise",
        collection_path="direct",
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
    gateway_id: str = "",
) -> Signal:
    """Build one canonical cloud Signal. entity is the app (app-centric kinds) or
    the cloud resource. entity_tokens carry app+resource so the engine can ground
    a cloud signal to an app/resource node. Deterministic id via native_id.

    gateway_id (IPsec kinds only): the reporting VPN gateway, which selects the
    independent ipsec:<gw> observer instead of the shared cloud:<acct>:<region> one.
    """
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

    observer = (
        ipsec_gateway_observer(gateway_id or entity_id, region)
        if kind in ("ipsec_tunnel_status", "ipsec_underlay_status")
        else cloud_observer(account, region, obs_type)
    )
    return Signal(
        tenant_id=tenant_id,
        ts=ts,
        source=Source.CLOUD,
        kind=kind,
        observer=observer,
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


# ── wire adapter (netops.cloud topic → Signal) ───────────────────────────────

_SEVERITY_ALIASES: dict[str, Severity] = {
    "info": Severity.INFO, "informational": Severity.INFO, "notice": Severity.INFO,
    "debug": Severity.INFO, "ok": Severity.INFO, "low": Severity.INFO,
    "warn": Severity.WARN, "warning": Severity.WARN, "minor": Severity.WARN, "medium": Severity.WARN,
    "high": Severity.HIGH, "error": Severity.HIGH, "err": Severity.HIGH, "major": Severity.HIGH,
    "crit": Severity.CRIT, "critical": Severity.CRIT, "fatal": Severity.CRIT, "emergency": Severity.CRIT,
}


def _parse_severity(raw: object) -> Severity:
    """Wire severity token → canonical Severity (default WARN). Tolerant of the
    common vendor/cloud spellings; an unknown token is WARN, never a crash."""
    return _SEVERITY_ALIASES.get(str(raw or "").strip().lower(), Severity.WARN)


def _coerce_float(raw: object) -> float:
    """Best-effort numeric coercion for value/baseline/deviation; non-numeric → 0.0
    (booleans are NOT numbers here)."""
    if raw is None or isinstance(raw, bool):
        return 0.0
    if isinstance(raw, (int, float)):
        return float(raw)
    try:
        return float(str(raw))
    except (TypeError, ValueError):
        return 0.0


def cloud_signal_from_event(ev: dict, tenant: str, ingest_ts: datetime) -> Signal:
    """Wire event off the `netops.cloud` topic → one canonical cloud Signal.

    The runtime ingestion adapter for cloud_signal(): validates the wire dict and
    delegates to the pure builder. Raises DeadLetter on a malformed event (unknown
    kind / no entity) so the consumer parks + counts it rather than guessing —
    provenance is never invented (§10 no silent failures). Tenancy is the CALLER's
    job (a cloud event carries an explicit tenant_id; there is no device to infer
    it from), so this takes the already-resolved `tenant`.
    """
    kind = str(ev.get("kind") or "").strip()
    if kind not in CLOUD_KINDS:
        raise DeadLetter(f"unknown cloud kind: {kind!r}")
    app = str(ev.get("app") or "").strip()
    resource_id = str(ev.get("resource_id") or "").strip()
    if not app and not resource_id:
        raise DeadLetter(f"cloud event {kind!r} carries neither app nor resource_id")
    raw_tokens = ev.get("entity_tokens")
    tokens = tuple(str(t) for t in raw_tokens if t) if isinstance(raw_tokens, (list, tuple)) else ()
    raw_attrs = ev.get("attrs")
    attrs = raw_attrs if isinstance(raw_attrs, dict) else None
    try:
        return cloud_signal(
            tenant,
            parse_event_ts(ev.get("ts")) or ingest_ts,
            kind,
            app=app,
            resource_id=resource_id,
            account=str(ev.get("account") or ""),
            region=str(ev.get("region") or ""),
            severity=_parse_severity(ev.get("severity")),
            metric_name=str(ev.get("metric_name") or ev.get("metric") or ""),
            value=_coerce_float(ev.get("value")),
            baseline=_coerce_float(ev.get("baseline")),
            deviation=_coerce_float(ev.get("deviation")),
            entity_tokens=tokens,
            attrs=attrs,
            gateway_id=str(ev.get("gateway_id") or ""),
        )
    except ValueError as exc:  # cloud_signal's own guards → dead-letter, not a crash
        raise DeadLetter(str(exc)) from exc
