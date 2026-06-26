"""Application-identity signal producer — #81 Fusion Layer Phase 5 (P5a).

App identity is the answer to *"WHICH application is this traffic?"*, produced by
the Go fusion layer (`appid.FuseObservations` → `FusedIdentity`, persisted to
ClickHouse `app_identities`). P5 brings that fused identity into the correlation
engine so an RCA object can NAME the applications it affects, with explainable
provenance and honest "unknown".

Architectural contract (AD-5 — "NO separate app RCA"):
  * Identity is **ENRICHMENT, not a fault.** A fused identity attaches to objects
    the engine ALREADY formed from real faults (a path/device/flow problem); it
    must NEVER seed an object on its own. That is why every identity signal is
    `severity=INFO` on a `CONTROL_PLANE` (classification/assertion) modality — the
    engine's P5c integration treats `source=app_identity` as enrichment that rides
    existing objects, never as a fault that opens one.
  * **One platform fusion vantage.** All identity signals share a single
    `observer_id` (the fusion engine), so the independence gate treats identity as
    a single derived observer: identity by itself can corroborate WHICH app is
    impacted but can NEVER, alone, confirm a fault verdict. Confirmation still
    needs an independent fault observer (probe / underlay / firewall).
  * **Vocabulary reused, not extended** (AD-2): `EntityType.APP` and
    `ModalityClass.CONTROL_PLANE` already exist; identity adds no new enum but its
    own `Source.APP_IDENTITY` (so it is filterable and never mistaken for a fault).

Pure + deterministic (no IO, no wall-clock); main.py owns tenancy + persistence
(the P5b consumer). Mirrors `cloud_producers.py` exactly.
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

# The single identity "kind" on source=app_identity. One assertion type: "this
# scope was identified as application X (with this band/state/provenance)".
APP_IDENTITY_KIND = "app_identity"

# Allowed confidence bands / resolution states — mirror the Go fusion vocabulary
# (`appid/identity.go` ConfidenceBand + ResolutionState). A present-but-unknown
# value is a producer contract violation → dead-letter (never silently coerced;
# provenance is not guessed). An ABSENT value falls back to the honest default.
_BANDS: frozenset[str] = frozenset(
    {"unresolved", "low", "medium", "high", "authoritative"})
_STATES: frozenset[str] = frozenset(
    {"observed", "fused", "inferred", "conflicted", "unknown"})
_DEFAULT_BAND = "unresolved"
_DEFAULT_STATE = "unknown"


def identity_observer() -> Observer:
    """The one platform fusion vantage. A single observer_id across all identity
    signals so the independence gate treats fused identity as ONE derived
    observer — it can name the affected app but cannot self-confirm a fault."""
    return Observer(
        observer_id="appid:fusion",
        observer_type=ObserverType.PLATFORM,
        location="",
        trust_domain="platform",
        collection_path="via_aggregator",
        clock_quality="unknown",
    )


def app_identity_signal(
    tenant_id: str,
    ts: datetime,
    *,
    app: str,
    band: str = _DEFAULT_BAND,
    state: str = _DEFAULT_STATE,
    canonical_app_id: str = "",
    provider: str = "",
    component: str = "",
    evidence_score: int = 0,
    sources: tuple[str, ...] = (),
    fusion_version: str = "",
    catalog_version: int = 0,
    dst_ip: str = "",
    dst_port: int = 0,
    proto: str = "",
    flow_id: str = "",
    session_id: str = "",
    entity_tokens: tuple[str, ...] = (),
    attrs: dict | None = None,
) -> Signal:
    """Build one canonical application-identity Signal from a fused identity.

    `app` is the resolved application name (entity). `entity_tokens` default to the
    app plus the scope's destination / flow id, so the signal grounds onto the SAME
    nodes a flow/network fault touches — that shared token is the join that lets an
    object NAME its affected app. Provenance (band/state/score/sources/version) is
    carried in attrs, not re-derived. Deterministic id via native_id.
    """
    if not app:
        raise ValueError("app_identity_signal needs an app (the resolved entity)")
    if band not in _BANDS:
        raise ValueError(f"invalid confidence band: {band!r}")
    if state not in _STATES:
        raise ValueError(f"invalid resolution state: {state!r}")

    # The scope key that makes this identity about ONE thing (session > flow > dst).
    scope = session_id or flow_id or dst_ip or app
    native = f"{APP_IDENTITY_KIND}|{app}|{scope}|{fusion_version}"

    tokens = tuple(entity_tokens) or tuple(
        t for t in (app, dst_ip, flow_id, session_id) if t)

    merged_attrs: dict = {
        **(attrs or {}),
        "band": band,
        "state": state,
        "evidence_score": int(evidence_score),
    }
    if canonical_app_id:
        merged_attrs["canonical_app_id"] = canonical_app_id
    if provider:
        merged_attrs["provider"] = provider
    if component:
        merged_attrs["component"] = component
    if sources:
        merged_attrs["sources"] = list(sources)
    if fusion_version:
        merged_attrs["fusion_version"] = fusion_version
    if catalog_version:
        merged_attrs["catalog_version"] = int(catalog_version)
    if dst_ip:
        merged_attrs["dst_ip"] = dst_ip
    if dst_port:
        merged_attrs["dst_port"] = int(dst_port)
    if proto:
        merged_attrs["proto"] = proto
    if flow_id:
        merged_attrs["flow_id"] = flow_id
    if session_id:
        merged_attrs["session_id"] = session_id

    return Signal(
        tenant_id=tenant_id,
        ts=ts,
        source=Source.APP_IDENTITY,
        kind=APP_IDENTITY_KIND,
        observer=identity_observer(),
        modality_class=ModalityClass.CONTROL_PLANE,
        entity_type=EntityType.APP,
        entity_id=app,
        # Identity is an assertion, NEVER a fault — INFO so it can never seed an
        # object; it only enriches one the engine already formed.
        severity=Severity.INFO,
        native_id=native,
        entity_tokens=tokens,
        service_id=app,
        attrs=merged_attrs,
    )


# ── wire adapter (netops.app.identities.v1 topic → Signal) ────────────────────


def _coerce_int(raw: object) -> int:
    """Best-effort non-negative int (evidence_score / port); non-numeric → 0."""
    if raw is None or isinstance(raw, bool):
        return 0
    try:
        return int(float(raw))
    except (TypeError, ValueError):
        return 0


def app_identity_from_event(ev: dict, tenant: str, ingest_ts: datetime) -> Signal:
    """Wire event off the identity topic → one canonical identity Signal.

    The runtime ingestion adapter for app_identity_signal(): validates the wire
    dict and delegates to the pure builder. Raises DeadLetter on a malformed event
    (no app, or a present-but-invalid band/state) so the P5b consumer parks +
    counts it rather than guessing — provenance is never invented (§10). Tenancy is
    the CALLER's job (an identity event carries an explicit tenant_id; there is no
    device to infer it from), so this takes the already-resolved `tenant`.
    """
    app = str(ev.get("app") or ev.get("canonical_app") or "").strip()
    if not app:
        raise DeadLetter("app identity event carries no app")

    # Absent band/state → honest default; present-but-invalid → dead-letter.
    band = str(ev.get("band") or _DEFAULT_BAND).strip().lower()
    state = str(ev.get("state") or _DEFAULT_STATE).strip().lower()
    if band not in _BANDS:
        raise DeadLetter(f"invalid confidence band: {band!r}")
    if state not in _STATES:
        raise DeadLetter(f"invalid resolution state: {state!r}")

    raw_sources = ev.get("sources")
    sources = tuple(str(s) for s in raw_sources if s) if isinstance(
        raw_sources, (list, tuple)) else ()
    raw_tokens = ev.get("entity_tokens")
    tokens = tuple(str(t) for t in raw_tokens if t) if isinstance(
        raw_tokens, (list, tuple)) else ()
    raw_attrs = ev.get("attrs")
    attrs = raw_attrs if isinstance(raw_attrs, dict) else None

    try:
        return app_identity_signal(
            tenant,
            parse_event_ts(ev.get("ts") or ev.get("fused_at")) or ingest_ts,
            app=app,
            band=band,
            state=state,
            canonical_app_id=str(ev.get("canonical_app_id") or ""),
            provider=str(ev.get("provider") or ""),
            component=str(ev.get("component") or ""),
            evidence_score=_coerce_int(ev.get("evidence_score")),
            sources=sources,
            fusion_version=str(ev.get("fusion_version") or ""),
            catalog_version=_coerce_int(ev.get("catalog_version")),
            dst_ip=str(ev.get("dst_ip") or ""),
            dst_port=_coerce_int(ev.get("dst_port")),
            proto=str(ev.get("proto") or ""),
            flow_id=str(ev.get("flow_id") or ""),
            session_id=str(ev.get("session_id") or ""),
            entity_tokens=tokens,
            attrs=attrs,
        )
    except ValueError as exc:  # builder guards → dead-letter, not a crash
        raise DeadLetter(str(exc)) from exc
