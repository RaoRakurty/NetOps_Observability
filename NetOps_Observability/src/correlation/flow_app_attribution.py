# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Bounded per-application passive-flow attribution (#98 Phase 4).

Production flow anomalies ground on the exporting interface (`<sampler>:if<N>`)
— correct for network RCA, invisible to application RCA. This module adds the
SECOND grounding, honestly bounded: a raw flow record is attributed to an
application only when an actual attribution source says so, and the source +
confidence ride the resulting signal. No attribution → no app token → the flow
stays infrastructure-grounded (never pretend an interface drop is app-specific).

Attribution levels, best source wins (design doc
docs/passive-flow-app-attribution.md):

  1. ``explicit_config``  — the record itself carries app identity
     (``app_name``/``app``/``application``/``app_id``; e.g. IPFIX appId or an
     exporter that stamps applications). Confidence: high.
  2. ``appid_fusion``     — the destination IP joins a recent fused identity
     from the #81 appid lane (netops.app.identities → AppIdentityIndex).
     Confidence: high for an ``authoritative`` band, medium for
     ``corroborated``, low otherwise.
  3. ``prefix_mapping``   — operator-defined CIDR→app catalog
     (``CORR_APP_PREFIX_MAP="13.107.64.0/18=microsoft_teams,..."``).
     Confidence: medium. NOT a public SaaS IP feed — customer-defined only.

Hostname/SNI mapping (the synthetic lane's Level 3) does not apply to NetFlow
records — they carry no names; DNS/SNI flow enrichment is future work.

Only ``high``/``medium`` attribution creates app-grounded evidence
(CONFIRMING_CONFIDENCE); ``low`` is dropped — low-confidence attribution must
never help confirm an outage. Cross-tenant isolation is structural: the
identity index is keyed by tenant, and lookups never cross it.

Pure + deterministic; the only state is the explicit AppIdentityIndex.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from datetime import datetime, timedelta

# confidence per source (band-dependent for fusion)
_FUSION_BAND_CONFIDENCE = {"authoritative": "high", "corroborated": "medium"}
CONFIRMING_CONFIDENCE: frozenset[str] = frozenset({"high", "medium"})

_INDEX_TTL_S = float(os.getenv("CORR_APPID_INDEX_TTL_S", "3600"))
_INDEX_MAX_PER_TENANT = int(os.getenv("CORR_APPID_INDEX_MAX", "10000"))


@dataclass(frozen=True)
class Attribution:
    app: str            # normalized app slug (the grounding entity/token)
    source: str         # explicit_config | appid_fusion | prefix_mapping
    confidence: str     # high | medium | low

    @property
    def confirming(self) -> bool:
        return self.confidence in CONFIRMING_CONFIDENCE


def normalize_app(name: str) -> str:
    """App display name → grounding slug (the synthetic lane's vocabulary:
    'Microsoft Teams' → 'microsoft_teams'). Never invents — empty stays empty."""
    return "_".join(str(name).strip().lower().split())


class AppIdentityIndex:
    """Bounded per-tenant ``dst_ip → (app, band, ts)`` view of the fused
    identity lane, maintained by handle_app_identity. TTL'd so a stale identity
    can never attribute tomorrow's flows (time-window honesty), size-capped so
    a hostile/buggy feed cannot grow memory unbounded (§9 bounded queues)."""

    def __init__(self, ttl_s: float = _INDEX_TTL_S,
                 max_per_tenant: int = _INDEX_MAX_PER_TENANT) -> None:
        self._ttl = timedelta(seconds=ttl_s)
        self._cap = max_per_tenant
        self._by_tenant: dict[str, dict[str, tuple[str, str, datetime]]] = {}

    def observe(self, tenant: str, dst_ip: str, app: str, band: str,
                ts: datetime) -> None:
        if not tenant or not dst_ip or not app:
            return
        ips = self._by_tenant.setdefault(tenant, {})
        if len(ips) >= self._cap and dst_ip not in ips:
            # evict the stalest entry — O(n) but only on cap pressure
            oldest = min(ips, key=lambda k: ips[k][2])
            del ips[oldest]
        ips[dst_ip] = (normalize_app(app), band, ts)

    def lookup(self, tenant: str, dst_ip: str, now: datetime) -> tuple[str, str] | None:
        """(app, band) for a live identity of this tenant's dst_ip, else None.
        NEVER consults another tenant's identities."""
        entry = self._by_tenant.get(tenant, {}).get(dst_ip)
        if entry is None:
            return None
        app, band, ts = entry
        if now - ts > self._ttl:
            return None
        return app, band


def _prefix_map() -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]]:
    out = []
    for pair in os.getenv("CORR_APP_PREFIX_MAP", "").split(","):
        cidr, _, app = pair.partition("=")
        cidr, app = cidr.strip(), normalize_app(app)
        if not cidr or not app:
            continue
        try:
            out.append((ipaddress.ip_network(cidr, strict=False), app))
        except ValueError:
            continue  # a malformed operator entry must not kill the flow path
    return out


def _flow_field(ev: dict, *names: str) -> str:
    for n in names:
        v = ev.get(n)
        if v not in (None, ""):
            return str(v)
    return ""


def resolve_flow_app(record: dict, tenant: str, index: AppIdentityIndex,
                     now: datetime) -> Attribution | None:
    """Best available attribution for one raw flow record, or None (keep the
    flow infrastructure-grounded). Levels in strict priority order."""
    # L1 — explicit app identity on the record itself.
    explicit = _flow_field(record, "app_name", "app", "application", "service_name")
    if explicit:
        return Attribution(app=normalize_app(explicit),
                           source="explicit_config", confidence="high")
    dst = _flow_field(record, "dst_addr", "DstAddr", "dst_ip")
    if not dst:
        return None
    # L2 — appid fusion join by destination IP (tenant-scoped, TTL'd).
    hit = index.lookup(tenant, dst, now)
    if hit is not None:
        app, band = hit
        return Attribution(app=app, source="appid_fusion",
                           confidence=_FUSION_BAND_CONFIDENCE.get(band, "low"))
    # L3 (hostname/SNI) — not applicable to NetFlow records (no names on wire).
    # L4 — operator-defined prefix catalog.
    try:
        ip = ipaddress.ip_address(dst)
    except ValueError:
        return None
    for net, app in _prefix_map():
        if ip.version == net.version and ip in net:
            return Attribution(app=app, source="prefix_mapping", confidence="medium")
    return None
