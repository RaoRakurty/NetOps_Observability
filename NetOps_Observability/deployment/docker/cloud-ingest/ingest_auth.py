"""Ingest credential for the cloud-ingest producers (F-08).

WHY THIS EXISTS. F-08 put Basic auth on all four vector-aggregator ingest
sources and converted the four GO call sites that post to them. cloud-ingest is
PYTHON, posts to metrics_in (:8690) and probe_in (:8689), and was missed. The
gap was invisible for as long as the deployed aggregator predated the auth
config; the moment the credential was seeded and the aggregator recreated
(2026-07-22), every cloud metric and probe event began returning 401 and being
dropped — with the only symptom a rate-limited WARN in Vector's own log.

Mirrors collectors/ingest_auth.go exactly, including its deliberate quirk: an
EMPTY token sends NO header rather than an empty password. That is the
documented upgrade window, in which Vector has not yet been reconfigured. Vector
is the fail-closed half of the pair, so an unauthenticated client can never
reach an unauthenticated collector by accident.

stdlib only, matching the rest of this service.
"""

from __future__ import annotations

import base64
import os

_USER = os.environ.get("INGEST_USER") or "netops-ingest"
_TOKEN = os.environ.get("INGEST_TOKEN") or ""


def ingest_auth_header() -> dict[str, str]:
    """Return the Authorization header, or {} when no token is configured."""
    if not _TOKEN:
        return {}
    raw = f"{_USER}:{_TOKEN}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}


def with_ingest_auth(headers: dict[str, str] | None = None) -> dict[str, str]:
    """Merge the ingest credential into an outbound header dict."""
    out = dict(headers or {})
    out.update(ingest_auth_header())
    return out
