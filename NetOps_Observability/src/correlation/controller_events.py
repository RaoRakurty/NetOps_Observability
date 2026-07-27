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
    cap_label,
    cap_text,
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
    # ── wireless (#128 Phase 3): device_id carries the CANONICAL wireless
    # entity id (ap-<id> / ap-<id>:radioN / wlc-<id>:<member>) stamped by the
    # Go synthesis (nms/wireless_events.go), so binding is direct and the
    # rank-1 containment grounding works from the id structure alone.
    "wireless_ap_down": EntityType.ACCESS_POINT,
    "wireless_ap_up": EntityType.ACCESS_POINT,
    "wireless_ap_join_flap": EntityType.ACCESS_POINT,
    "wireless_radio_down": EntityType.RADIO,
    "wireless_radio_up": EntityType.RADIO,
    "wireless_wlc_member_failover": EntityType.WIRELESS_CONTROLLER,
    "wireless_channel_util_high": EntityType.RADIO,
    "wireless_interference": EntityType.RADIO,
    "wireless_noise_high": EntityType.RADIO,
    "wireless_coverage_low_rssi": EntityType.RADIO,
    "wireless_radar_event": EntityType.RADIO,
    "wireless_retry_rate_high": EntityType.RADIO,
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
                dt = datetime.strptime(raw, fmt)  # noqa: DTZ007 — the "Z" format parses naive; made aware on the next line
                return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return fallback


def _bounded_hints(hints: object) -> object:
    """Bound the free-form `correlation_hints` blob (audit PIPE-MED-11).

    It is the ONE field the normalized-event contract deliberately leaves open, so
    it is the one a vendor payload can make arbitrarily large — and it was passed
    through verbatim into attrs. A dict is bounded key-by-key (string values capped
    at the free-text class, and the KEY COUNT bounded, since keys become JSON
    object members in a ClickHouse String); anything else is stringified and capped.
    Truncation is recorded by cap_text's counter/log, never silent (§10)."""
    if isinstance(hints, dict):
        out: dict = {}
        for k in sorted(hints)[:_MAX_HINT_KEYS]:
            v = hints[k]
            key = cap_label(k, where="controller", field_name="correlation_hints.key")
            # Label class, not free text: a hint is an IDENTIFIER the RCA joins on
            # ("which BFD session", "which policy id"), and the whole attrs blob
            # has a 4 KB budget that 32 free-text values would blow on its own.
            out[key] = (cap_label(v, where="controller", field_name=f"correlation_hints.{key}")
                        if isinstance(v, str) else v)
        if len(hints) > _MAX_HINT_KEYS:
            out["_hints_truncated"] = len(hints) - _MAX_HINT_KEYS
        return out
    if isinstance(hints, (list, tuple)):
        return [cap_label(v, where="controller", field_name="correlation_hints[]")
                if isinstance(v, str) else v for v in hints[:_MAX_HINT_KEYS]]
    return cap_text(hints, where="controller", field_name="correlation_hints")


# A hints blob is CONTEXT, not a payload channel: 16 identifier-sized keys is
# generous for "which BFD session / which policy id" and fits inside the 4 KB
# ATTRS_MAX_BYTES budget alongside the fixed fields, so the model-level attrs
# shrinker stays a backstop rather than routine.
_MAX_HINT_KEYS = 16


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
            # Untrusted-string caps (audit PIPE-MED-11): a controller event is a
            # vendor payload the Go connector normalized in SHAPE but not in SIZE,
            # and every field below lands in a ClickHouse String / OpenSearch doc.
            "source_system": cap_label(source_system, where="controller", field_name="source_system"),
            "vendor": cap_label(ev.get("vendor") or "", where="controller", field_name="vendor"),
            "product": cap_label(ev.get("product") or "", where="controller", field_name="product"),
            "message": cap_text(ev.get("message") or "", where="controller", field_name="message"),
            "evidence_role": cap_label(ev.get("evidence_role") or "supporting",
                                       where="controller", field_name="evidence_role"),
            "authority": "vendor_controller",
            "event_type": cap_label(ev.get("event_type") or "", where="controller", field_name="event_type"),
            "interface_name": cap_label(iface, where="controller", field_name="interface_name"),
            "tunnel_id": cap_label(tunnel, where="controller", field_name="tunnel_id"),
            **({"correlation_hints": _bounded_hints(ev["correlation_hints"])}
               if ev.get("correlation_hints") else {}),
        },
    )
