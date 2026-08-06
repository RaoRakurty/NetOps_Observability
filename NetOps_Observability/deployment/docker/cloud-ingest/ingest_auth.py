"""Ingest credential for the cloud-ingest producers (F-08, SEC-013.1).

WHY THIS EXISTS. F-08 put Basic auth on all four vector-aggregator ingest
sources and converted the four GO call sites that post to them. cloud-ingest is
PYTHON, posts to metrics_in (:8690), and was missed. The gap was invisible for
as long as the deployed aggregator predated the auth config; the moment the
credential was seeded and the aggregator recreated (2026-07-22), every cloud
metric began returning 401 and being dropped — with the only symptom a
rate-limited WARN in Vector's own log.

SEC-013.1 scoped the credential PER LANE (a compromised metrics credential
must not open the bus bridge): each lane's token comes from
INGEST_TOKEN_<LANE>, falling back to the shared INGEST_TOKEN so a
pre-SEC-013 deployment is bit-for-bit unchanged until per-lane tokens are
provisioned.

Mirrors collectors/ingest_auth.go exactly, including its deliberate quirks:
an EMPTY token sends NO header rather than an empty password (the documented
upgrade window — Vector is the fail-closed half of the pair), and an UNKNOWN
lane name sends nothing, so a typo fails loud as a 401 instead of silently
borrowing another lane's credential.

stdlib only, matching the rest of this service.
"""

from __future__ import annotations

import base64
import os

LANE_TRAPS = "traps"
LANE_PROBES = "probes"
LANE_METRICS = "metrics"
LANE_BUS = "bus"

_LANE_ENV = {
    LANE_TRAPS: "INGEST_TOKEN_TRAPS",
    LANE_PROBES: "INGEST_TOKEN_PROBES",
    LANE_METRICS: "INGEST_TOKEN_METRICS",
    LANE_BUS: "INGEST_TOKEN_BUS",
}

_USER = os.environ.get("INGEST_USER") or "netops-ingest"
_SHARED = os.environ.get("INGEST_TOKEN") or ""
_TOKENS = {
    lane: (os.environ.get(env) or _SHARED) for lane, env in _LANE_ENV.items()
}


def ingest_auth_header(lane: str = LANE_METRICS) -> dict[str, str]:
    """Return the lane's Authorization header, or {} when no token applies."""
    token = _TOKENS.get(lane, "")
    if not token:
        return {}
    raw = f"{_USER}:{token}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}


def with_ingest_auth(headers: dict[str, str] | None = None, lane: str = LANE_METRICS) -> dict[str, str]:
    """Merge the lane's ingest credential into an outbound header dict.

    cloud-ingest's only lane today is metrics — the default keeps the four
    existing call sites correct; a future probe/bus producer must pass its
    lane explicitly.
    """
    out = dict(headers or {})
    out.update(ingest_auth_header(lane))
    return out


def ingest_ssl_context():
    """SSL context for the mTLS ingest lanes (SEC-013.2), or None on the
    plaintext baseline.

    Mirrors the Go side's fail-closed posture (kafka_security_kwargs in the
    correlation service is the sibling): all three of INGEST_TLS_CA / _CRT /
    _KEY set → verify the aggregator against the mesh CA and present this
    service's SVID; none set → None (plain http, unchanged); a PARTIAL set
    refuses to start rather than silently downgrading — a downgrade here
    reads as "the cloud lanes are quiet today".
    """
    import ssl

    ca = os.environ.get("INGEST_TLS_CA") or ""
    crt = os.environ.get("INGEST_TLS_CRT") or ""
    key = os.environ.get("INGEST_TLS_KEY") or ""
    if not (ca or crt or key):
        return None
    if not (ca and crt and key):
        raise RuntimeError(
            "INGEST_TLS_CA, INGEST_TLS_CRT and INGEST_TLS_KEY must be set "
            f"together (got ca={bool(ca)} crt={bool(crt)} key={bool(key)}) — "
            "refusing a partial TLS config")
    ctx = ssl.create_default_context(cafile=ca)
    ctx.load_cert_chain(crt, key)
    return ctx


# Built once at import, like the tokens: a broken TLS config fails the boot
# loudly, not the Nth poll cycle.
INGEST_SSL_CONTEXT = ingest_ssl_context()
