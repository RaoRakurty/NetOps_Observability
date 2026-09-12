# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""verification_producer.py — Active Verification evidence lane (RCA spec item 8).

Turns one normalized check result from the Go verify engine (arriving on the
netops.verification topic) into a correlation Signal on the ACTIVE_VERIFICATION
modality. This is the seam where the platform's bounded, READ-ONLY interrogation
of an implicated device becomes RCA evidence — WITHOUT any change to the
correlation engine itself: a verification result is just another Signal, and
because active_verification is its own modality class, the independence gate can
count a device's own answer as a second source against a probe/flow witness.

Semantics (mirrors the spec):
  * a FAILING or UNREACHABLE check  → kind ``active_verification_result``
    (corroborating; attrs.corroborates_kinds names what it corroborates)
  * a PASSING check                 → kind ``active_verification_healthy``
    (REFUTING; attrs.refutes_kinds feeds scoring's contradiction path)
  * a SKIPPED check                 → no signal (budget exhaustion or a missing
    credential is an operational fact, not evidence about the device)

Trust is marked honestly (verdicts.witness_of): a device answer over its
management channel (verify_method ssh/snmp) is authoritative-leaning and may
anchor a confirming pair; a platform-executed reachability probe (tcp) is
support-only. Everything on the wire is validated fail-closed — an untenanted,
unbindable, or unknown-status record is dropped, never guessed.
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

VERIFICATION_RESULT_KIND = "active_verification_result"
VERIFICATION_HEALTHY_KIND = "active_verification_healthy"

# The ONLY kinds a verification check may claim to corroborate or refute.
# Mirrors the backend's closed check table (verify_engine.go). Zero-trust on the
# wire: anything outside this vocabulary is silently dropped from the claim —
# a compromised or buggy producer can weaken a verification's effect, never
# widen it into vocabulary it has no business touching.
REFUTABLE_KINDS: frozenset[str] = frozenset({
    "link_state_change",
    "bgp_adjacency_change",
    "ospf_adjacency_change",
    "routing_adjacency_change",
    "bgp_state_anomaly",
    "device_restart",
    "device_alarm",
    # Troubleshooting modules (verify_modules.go): interface deep-dive
    # (if_errors/if_crc) and the recent-change detector (config_change).
    "if_errors",
    "if_crc",
    "config_change",
})
CORROBORABLE_KINDS: frozenset[str] = REFUTABLE_KINDS

_STATUSES = frozenset({"pass", "fail", "unreachable", "skipped"})
_METHODS = frozenset({"ssh", "snmp", "tcp"})
_OBSERVED_MAX = 500  # attrs are bounded (ATTRS_MAX_BYTES); keep raw output small


def _clean_text(raw: object, cap: int) -> str:
    """Sanitize device output for storage/logs (§8): printable chars only,
    hard length cap. Device output is untrusted input."""
    s = str(raw or "")
    cleaned = "".join(ch if ch.isprintable() or ch in " \t" else " " for ch in s)
    return cleaned[:cap]


def _kinds_claim(ev: dict, key: str, allowed: frozenset[str]) -> list[str]:
    raw = ev.get(key)
    if not isinstance(raw, (list, tuple)):
        return []
    return sorted({str(k) for k in raw[:16] if isinstance(k, str)} & allowed)


def _parse_ts(raw: object, fallback: datetime) -> datetime:
    if isinstance(raw, (int, float)) and raw > 0:
        v = float(raw)
        if v > 1e12:  # epoch millis
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


def verification_signal_from_event(ev: dict, ingest_ts: datetime) -> Signal | None:
    """Map one normalized verification check result → a Signal, or None when
    the record is not admissible evidence (no tenant, no device to bind to,
    unknown status, or a skipped check)."""
    tenant = str(ev.get("tenant_id") or "").strip()
    if not tenant:
        return None
    status = str(ev.get("status") or "").strip().lower()
    if status not in _STATUSES or status == "skipped":
        return None
    check = str(ev.get("check") or "").strip()
    if not check:
        return None
    device_id = str(ev.get("device_id") or "").strip()
    device_name = str(ev.get("device_name") or "").strip()
    entity_id = device_id or device_name
    if not entity_id:
        return None  # nothing to correlate against — never guess a binding

    method = str(ev.get("method") or "").strip().lower()
    if method not in _METHODS:
        method = ""  # fail-closed: unknown method is treated as weakest trust
    run_id = str(ev.get("run_id") or "").strip()
    site = str(ev.get("site") or "").strip()
    ts = _parse_ts(ev.get("ts"), ingest_ts)

    healthy = status == "pass"
    kind = VERIFICATION_HEALTHY_KIND if healthy else VERIFICATION_RESULT_KIND
    severity = Severity.INFO if healthy else Severity.HIGH

    attrs: dict = {
        "check": _clean_text(check, 64),
        "verify_method": method,
        "verify_status": status,
        "observed": _clean_text(ev.get("observed"), _OBSERVED_MAX),
        "run_id": _clean_text(run_id, 64),
        "trigger": _clean_text(ev.get("trigger"), 16),
        "verification_trust": "device_answer" if method in ("ssh", "snmp") else "platform_probe",
    }
    command = _clean_text(ev.get("command"), 120)
    if command:
        attrs["command"] = command
    corr_id = _clean_text(ev.get("correlation_id"), 64)
    if corr_id:
        attrs["verified_for"] = corr_id
    if healthy:
        refutes = _kinds_claim(ev, "refutes_kinds", REFUTABLE_KINDS)
        if refutes:
            attrs["refutes_kinds"] = refutes
    else:
        corroborates = _kinds_claim(ev, "corroborates_kinds", CORROBORABLE_KINDS)
        if corroborates:
            attrs["corroborates_kinds"] = corroborates

    if method in ("ssh", "snmp"):
        # The DEVICE is the witness: it answered about its own state; the verify
        # engine is transport (direct), exactly like a Telegraf SNMP poll. This
        # keeps the independence gate honest — a device can never corroborate
        # its own passive telemetry through verification.
        observer = Observer(
            observer_id=entity_id,
            observer_type=ObserverType.DEVICE,
            collection_path="direct",
            clock_quality="unknown",
        )
    else:
        # A reachability probe is measured BY the platform executor — the
        # platform is the witness, and every such probe shares its fate
        # (agent_host) so two reach checks can never corroborate each other.
        observer = Observer(
            observer_id="verifier:api",
            observer_type=ObserverType.PLATFORM,
            collection_path="direct",
            clock_quality="ntp",
        )
        attrs["agent_host"] = "api"

    tokens = tuple(dict.fromkeys(t for t in (device_id, device_name) if t))
    return Signal(
        tenant_id=tenant,
        ts=ts,
        source=Source.VERIFICATION,
        kind=kind,
        observer=observer,
        modality_class=ModalityClass.ACTIVE_VERIFICATION,
        entity_type=EntityType.DEVICE,
        entity_id=entity_id,
        severity=severity,
        native_id=f"verify|{run_id}|{check}|{entity_id}|{status}",
        entity_tokens=tokens or (entity_id,),
        site=site,
        metric_name=check,
        attrs=attrs,
    )
