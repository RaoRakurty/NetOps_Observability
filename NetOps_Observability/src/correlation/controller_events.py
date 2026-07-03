"""controller_events.py — NMS controller-event producer (P4).

Turns a normalized ControllerEvent (from the Go connector framework, arriving on
the netops.controller_events topic) into a correlation Signal on the
MANAGEMENT_PLANE modality. This is the seam where vendor-controller intelligence
becomes RCA evidence — WITHOUT any change to the correlation engine itself: a
controller event is just another Signal, and because management_plane is its own
modality, the independence gate automatically caps a lone controller witness at
"suspected" (controller-alone-cannot-confirm, for free).

Vendor-neutral by construction: this maps the NORMALIZED kinds
(controller_tunnel_state, controller_bfd_down, controller_policy_change, …), not
per-vendor payloads — the Go transformers already normalized those. So one code
path covers Meraki / vManage / Catalyst / NDFC / Versa / Prime alike.
"""
from __future__ import annotations

from datetime import datetime, timezone

from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

# Normalized controller event_type → the entity axis it scopes. Anything not
# listed scopes to the device.
_ENTITY_BY_KIND = {
    "controller_tunnel_state": EntityType.PATH,
    "controller_bfd_down": EntityType.PATH,
    "controller_control_connection_loss": EntityType.DEVICE,
    "controller_device_unreachable": EntityType.DEVICE,
    "controller_policy_change": EntityType.DEVICE,
    "controller_health_score": EntityType.SITE,
    "controller_alarm": EntityType.DEVICE,
    "controller_topology_context": EntityType.DEVICE,
    "controller_inventory_context": EntityType.DEVICE,
}

_SEVERITY = {"info": Severity.INFO, "warn": Severity.WARN, "high": Severity.HIGH, "crit": Severity.CRIT}


def _parse_ts(raw: object, fallback: datetime) -> datetime:
    if isinstance(raw, (int, float)) and raw > 0:
        # epoch millis or seconds
        v = float(raw)
        if v > 1e12:
            v /= 1000.0
        return datetime.fromtimestamp(v, tz=timezone.utc)
    if isinstance(raw, str) and raw:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                dt = datetime.strptime(raw, fmt)
                return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return fallback


def controller_event_to_signal(ev: dict, ingest_ts: datetime) -> Signal | None:
    """Map one normalized controller event → a management-plane Signal.

    Returns None if the event lacks the identity needed to correlate (no tenant,
    or no device/site/tunnel to bind to) — we never emit an unbindable signal.
    """
    tenant = str(ev.get("tenant_id") or "").strip()
    if not tenant:
        return None
    kind = str(ev.get("normalized_event_type") or "controller_alarm").strip()
    source_system = str(ev.get("source_system") or "controller").strip()

    device = str(ev.get("device_id") or ev.get("device_name") or "").strip()
    site = str(ev.get("site_id") or "").strip()
    tunnel = str(ev.get("tunnel_id") or "").strip()
    iface = str(ev.get("interface_name") or "").strip()

    # Bind to the most specific entity available.
    entity_type = _ENTITY_BY_KIND.get(kind, EntityType.DEVICE)
    if entity_type == EntityType.PATH:
        entity_id = tunnel or device
    elif entity_type == EntityType.SITE:
        entity_id = site or device
    else:
        entity_id = device or site
    if not entity_id:
        return None  # nothing to correlate against

    ts = _parse_ts(ev.get("event_time"), ingest_ts)
    ts_ms = int(ts.timestamp() * 1000)
    severity = _SEVERITY.get(str(ev.get("severity") or "warn").lower(), Severity.WARN)

    # The controller is the witness; the collection path is via_controller so the
    # independence/fate-sharing analysis knows this did NOT come straight from the
    # device (it came through the vendor's management plane).
    observer = Observer(
        observer_id=f"{source_system}:{ev.get('integration_id') or ''}",
        observer_type=ObserverType.CONTROLLER,
        collection_path="via_controller",
        clock_quality="unknown",
    )

    tokens = tuple(t for t in (device, site, tunnel, iface) if t)
    return Signal(
        tenant_id=tenant,
        ts=ts,
        source=Source.CONTROLLER,
        kind=kind,
        observer=observer,
        modality_class=ModalityClass.MANAGEMENT_PLANE,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        native_id=f"{source_system}|{kind}|{entity_id}|{ev.get('event_id') or ts_ms}",
        entity_tokens=tokens or (entity_id,),
        site=site,
        metric_name=kind,
        attrs={
            "source_system": source_system,
            "vendor": ev.get("vendor") or "",
            "product": ev.get("product") or "",
            "message": ev.get("message") or "",
            "evidence_role": ev.get("evidence_role") or "supporting",
            "authority": "vendor_controller",
            "event_type": ev.get("event_type") or "",
            "interface_name": iface,
            "tunnel_id": tunnel,
            **({"correlation_hints": ev["correlation_hints"]} if ev.get("correlation_hints") else {}),
        },
    )
