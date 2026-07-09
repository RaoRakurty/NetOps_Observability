"""Synthetic probe → semantic application-experience normalization.

The EXTERNAL Digital-Experience lane — deliberately NOT APM (no traces, spans,
RUM, or code-level instrumentation; see docs/application-experience-correlation.md).

`collectors/synthetics.go` measures a SaaS/app endpoint from the outside
(HTTP/TCP/ICMP, per-phase timings, status code, cert expiry) and forwards a
`ProbeEvent` onto `netops.probes`. The generic probe path (`producers.probe_signals`)
turns that into `probe_loss` / `probe_rtt_anomaly` PATH signals — great for
*network path* correlation, but the app-tier signatures key on SEMANTIC kinds
(`synthetic_http_fail`, `synthetic_tls_fail`, `synthetic_http_5xx`, …). This
module bridges that gap: one synthetic outcome → at most one semantic
application-experience Signal whose `kind` an `sig.ent.app.*` template can match,
with `raw_kind` preserving the original probe kind (backward compatible — the
generic path is untouched).

Pure + deterministic (no IO, no wall-clock, no randomness) — the same event
always yields the same signal, so it round-trips under replay.

Boundary rules (kept honest):
  * Emits ONLY on a problem (fail / cert-expiring / high-latency). A healthy
    check produces no semantic signal — same anti-noise stance as `probe_loss`.
  * The semantic signal is `active_probe` modality from ONE vantage observer, so
    by itself it can only ever reach `suspected` — confirmation still needs an
    independent second modality (a passive-flow collapse or an LB/app 5xx),
    exactly as the verdict gate demands. This module never relaxes that.
"""

from __future__ import annotations

import os
from datetime import datetime

from producers import parse_event_ts, probe_host
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    ProbeAuthority,
    ProbeScope,
    Severity,
    Signal,
    Source,
)

# ── semantic application-experience kinds (the vocabulary app signatures match) ──
SYNTHETIC_HTTP_FAIL = "synthetic_http_fail"
SYNTHETIC_HTTP_LATENCY_HIGH = "synthetic_http_latency_high"
SYNTHETIC_DNS_FAIL = "synthetic_dns_fail"
SYNTHETIC_TCP_CONNECT_FAIL = "synthetic_tcp_connect_fail"
SYNTHETIC_TLS_FAIL = "synthetic_tls_fail"
SYNTHETIC_CERT_EXPIRING = "synthetic_cert_expiring"
SYNTHETIC_CERT_EXPIRED = "synthetic_cert_expired"
SYNTHETIC_HTTP_5XX = "synthetic_http_5xx"
SYNTHETIC_HTTP_4XX = "synthetic_http_4xx"
SYNTHETIC_TIMEOUT = "synthetic_timeout"
SYNTHETIC_ICMP_LOSS = "synthetic_icmp_loss"
SYNTHETIC_TCP_PROBE_FAIL = "synthetic_tcp_probe_fail"

SEMANTIC_KINDS: frozenset[str] = frozenset({
    SYNTHETIC_HTTP_FAIL, SYNTHETIC_HTTP_LATENCY_HIGH, SYNTHETIC_DNS_FAIL,
    SYNTHETIC_TCP_CONNECT_FAIL, SYNTHETIC_TLS_FAIL, SYNTHETIC_CERT_EXPIRING,
    SYNTHETIC_CERT_EXPIRED, SYNTHETIC_HTTP_5XX, SYNTHETIC_HTTP_4XX,
    SYNTHETIC_TIMEOUT, SYNTHETIC_ICMP_LOSS, SYNTHETIC_TCP_PROBE_FAIL,
})

# ── failure reason codes (RCA-narrative metadata, not the matching key) ──────────
FAILURE_REASONS: frozenset[str] = frozenset({
    "dns_failure", "tcp_connect_timeout", "tcp_connect_refused",
    "tls_handshake_failure", "certificate_expired", "certificate_expiring",
    "http_4xx", "http_5xx", "http_timeout", "ttfb_timeout", "response_timeout",
    "reset_by_peer", "icmp_unreachable", "unknown_synthetic_failure",
})

# Latency / cert thresholds — config-tunable (defaults conservative).
_LATENCY_HIGH_MS = float(os.getenv("CORR_SYNTHETIC_LATENCY_HIGH_MS", "3000"))
_CERT_WARN_DAYS = float(os.getenv("CORR_SYNTHETIC_CERT_WARN_DAYS", "14"))
_ICMP_LOSS_PCT = float(os.getenv("CORR_SYNTHETIC_ICMP_LOSS_PCT", "50"))

# Built-in SaaS host → canonical app map (opportunistic app attach — Task 4).
# TODO(per-app-flow-attribution): this is a small demo-grade map; full attribution
# comes from the appid/ fusion layer resolving flows/sessions to apps (design P2).
# Extend at runtime via CORR_SAAS_HOST_MAP="host=app,host=app".
_BUILTIN_SAAS_HOSTS: dict[str, str] = {
    "teams.microsoft.com": "microsoft_teams",
    "teams.live.com": "microsoft_teams",
    "outlook.office365.com": "microsoft_o365",
    "login.microsoftonline.com": "microsoft_o365",
    "slack.com": "slack",
    "app.slack.com": "slack",
    "zoom.us": "zoom",
    "salesforce.com": "salesforce",
    "login.salesforce.com": "salesforce",
    "meet.google.com": "google_meet",
}


def _saas_map() -> dict[str, str]:
    out = dict(_BUILTIN_SAAS_HOSTS)
    raw = os.getenv("CORR_SAAS_HOST_MAP", "")
    for pair in raw.split(","):
        host, _, app = pair.partition("=")
        host, app = host.strip().lower(), app.strip()
        if host and app:
            out[host] = app
    return out


def resolve_app(ev: dict, host: str) -> tuple[str, str]:
    """(app_name, app_id) for this check. Prefers explicit identity carried on the
    event (future per-flow attribution), falls back to the SaaS host map, else the
    host itself (honest — we never invent a friendlier name than we can justify)."""
    app_name = str(ev.get("app_name") or ev.get("app") or "").strip()
    app_id = str(ev.get("app_id") or "").strip()
    if not app_name:
        app_name = _saas_map().get(host.lower(), "")
    return app_name, app_id


def classify_synthetic(ev: dict) -> tuple[str | None, str | None, Severity]:
    """Map one raw synthetic outcome → (semantic_kind, reason_code, severity).

    Returns (None, None, INFO) for a healthy check (no signal emitted). Pure over
    the fields `collectors/synthetics.go` puts on the wire; every field is optional
    and the function degrades gracefully when only `ok`/`loss_pct` are present
    (older collectors), producing coarse-but-correct kinds."""
    check = str(ev.get("kind") or "").lower()          # http | tcp | icmp
    ok = bool(ev.get("ok"))
    fail_class = str(ev.get("fail_class") or "").lower()
    status = ev.get("status_code")
    status = int(status) if isinstance(status, (int, float)) else None
    cert_days = ev.get("cert_days_to_expiry")
    cert_days = float(cert_days) if isinstance(cert_days, (int, float)) else None
    total_ms = ev.get("total_ms") or ev.get("rtt_ms")
    total_ms = float(total_ms) if isinstance(total_ms, (int, float)) else None
    loss = float(ev.get("loss_pct") or 0.0)

    if check == "http":
        if not ok:
            if fail_class == "dns":
                return SYNTHETIC_DNS_FAIL, "dns_failure", Severity.HIGH
            if fail_class == "tls":
                return SYNTHETIC_TLS_FAIL, "tls_handshake_failure", Severity.HIGH
            if fail_class == "connect_refused":
                return SYNTHETIC_TCP_CONNECT_FAIL, "tcp_connect_refused", Severity.HIGH
            if fail_class in ("connect_timeout", "timeout"):
                return SYNTHETIC_TIMEOUT, "http_timeout", Severity.HIGH
            if fail_class == "reset":
                return SYNTHETIC_HTTP_FAIL, "reset_by_peer", Severity.HIGH
            if status is not None and status >= 500:
                return SYNTHETIC_HTTP_5XX, "http_5xx", Severity.HIGH
            if status is not None and status >= 400:
                return SYNTHETIC_HTTP_4XX, "http_4xx", Severity.WARN
            return SYNTHETIC_HTTP_FAIL, "unknown_synthetic_failure", Severity.HIGH
        # ok=True (2xx/3xx): still surface cert risk + gray latency.
        if cert_days is not None and cert_days < 0:
            return SYNTHETIC_CERT_EXPIRED, "certificate_expired", Severity.HIGH
        if cert_days is not None and cert_days <= _CERT_WARN_DAYS:
            return SYNTHETIC_CERT_EXPIRING, "certificate_expiring", Severity.WARN
        if total_ms is not None and total_ms >= _LATENCY_HIGH_MS:
            return SYNTHETIC_HTTP_LATENCY_HIGH, "response_timeout", Severity.WARN
        return None, None, Severity.INFO

    if check == "tcp":
        if not ok:
            reason = "tcp_connect_refused" if fail_class == "connect_refused" else "tcp_connect_timeout"
            return SYNTHETIC_TCP_CONNECT_FAIL, reason, Severity.HIGH
        return None, None, Severity.INFO

    if check == "icmp":
        if not ok or loss >= _ICMP_LOSS_PCT:
            return SYNTHETIC_ICMP_LOSS, "icmp_unreachable", Severity.HIGH
        return None, None, Severity.INFO

    # Unknown check type that failed → a generic TCP-style probe failure.
    if not ok:
        return SYNTHETIC_TCP_PROBE_FAIL, "unknown_synthetic_failure", Severity.HIGH
    return None, None, Severity.INFO


def synthetic_app_signal(
    ev: dict, tenant: str, ingest_ts: datetime,
) -> Signal | None:
    """Build the semantic application-experience Signal for one synthetic event,
    or None for a healthy check. The generic `probe_signals` path still runs
    alongside this (backward compatibility) — this is an ADDITIONAL lane.

    The signal grounds onto the application entity: entity_id is the resolved app
    (else the host), and entity_tokens carry app:/saas:/host:/target:/tenant:/site:
    so it co-locates with app-identity enrichment and any app-attributed flow."""
    kind, reason, severity = classify_synthetic(ev)
    if kind is None:
        return None

    raw_kind = str(ev.get("kind") or "")
    prober = str(ev.get("prober") or "synthetics")
    target = str(ev.get("target") or "")
    if not target:
        return None
    host = probe_host(target)
    app_name, app_id = resolve_app(ev, host)
    site = str(ev.get("site_id") or ev.get("site") or "")
    device = str(ev.get("device_id") or "")
    ts = parse_event_ts(ev.get("ts")) or ingest_ts

    entity_id = app_name or host
    entity_type = EntityType.APP if app_name else EntityType.SERVICE

    # Correlation tokens (grounding join keys). Bare `host`/`app` tokens mirror the
    # containment rung used elsewhere so a flow/identity sharing them attaches.
    tokens: list[str] = [host, f"host:{host}", f"target:{target}", f"tenant:{tenant}"]
    if app_name:
        tokens += [app_name, f"app:{app_name}", f"saas:{app_name}"]
    if site:
        tokens.append(f"site:{site}")
    if device:
        tokens.append(f"device:{device}")

    # Semantic-signal metadata (Task 2/6). Only what's present — never invented.
    attrs: dict = {
        "raw_kind": raw_kind,
        "signal_class": "active_probe",
        "synthetic_source": "synthetic",
        "check_type": raw_kind,
        "target": target,
        "target_url": target,
        "host": host,
        "reason": reason,
        # External customer-facing DEM probe → a TRUSTED, customer-path witness so
        # it can pair with an independent modality to confirm (never self/lab).
        "probe_authority": ProbeAuthority.HIGH.value,
        "probe_scope": ProbeScope.CUSTOMER_PATH.value,
    }
    if app_name:
        attrs["app_name"] = app_name
    if app_id:
        attrs["app_id"] = app_id
    if site:
        attrs["site_id"] = site
    if device:
        attrs["device_id"] = device
    for src_key, dst_key in (
        ("status_code", "status_code"), ("method", "method"), ("path", "path"),
        ("dns_ms", "dns_ms"), ("tcp_connect_ms", "tcp_connect_ms"),
        ("tls_ms", "tls_ms"), ("ttfb_ms", "ttfb_ms"), ("total_ms", "total_ms"),
        ("cert_days_to_expiry", "cert_days_to_expiry"),
        ("cert_subject", "cert_subject"), ("cert_issuer", "cert_issuer"),
        ("fail_class", "fail_class"),
    ):
        if ev.get(src_key) is not None and ev.get(src_key) != "":
            attrs[dst_key] = ev[src_key]

    observer = Observer(
        observer_id=prober,
        observer_type=ObserverType.VANTAGE_AGENT,
        location=site,
        trust_domain="enterprise",
        collection_path="direct",
        clock_quality="unknown",
    )
    return Signal(
        tenant_id=tenant,
        ts=ts,
        source=Source.PROBE,               # active-probe lane; `synthetic_source` attr marks the sub-lane
        kind=kind,
        observer=observer,
        modality_class=ModalityClass.ACTIVE_PROBE,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        native_id=f"{prober}|{host}|{kind}|{int(ts.timestamp() * 1000)}",
        entity_tokens=tuple(tokens),
        service_id=app_name or host,
        metric_name=f"synthetic[{raw_kind}]",
        value=1.0,
        attrs=attrs,
    )
