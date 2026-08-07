"""tls_ident.py — mTLS peer identity for the correlation service (APP-001).

The correlation API is cross-tenant capable (reads run at
tenant_scope=__all__), so transport encryption alone is insufficient: the
LLD (§6.14.2) requires the server to know WHICH workload is calling and to
accept the Go api as the only full-access client. uvicorn 0.30 does not
implement the ASGI TLS extension, so the peer certificate never reaches the
app on its own. This module closes that gap with two small, separable pieces:

  * IdentityH11Protocol — uvicorn's h11 protocol, extended to read the peer
    certificate's SPIFFE URI SAN at connection_made and publish it in a
    per-connection registry keyed by (client_ip, client_port) — exactly the
    tuple every request scope carries as scope["client"], for the lifetime
    of that TCP connection and no longer. h11 (pure Python) is deliberate:
    the protocol class is a documented uvicorn extension point, and this
    service's request rate is one proxying client plus a 30s scrape.

  * PeerIdentityMiddleware — pure-ASGI middleware enforcing the identity
    policy per request:
      - full-access identities (CORR_TLS_ALLOWED_URIS): every path;
      - monitor identities (CORR_TLS_MONITOR_URIS): /metrics and /healthz
        only (victoria's scraper, and this container's own healthcheck);
      - anything else: 403 before the route runs.
    The TLS handshake (ssl_cert_reqs=CERT_REQUIRED in tls_serve.py) has
    already rejected certificates outside the mesh CA; this layer narrows
    "any mesh workload" down to named identities — §3 zero trust, no
    implicit trust between services.

Dormant by default: the middleware enforces nothing unless allowed URIs are
configured, so the plaintext baseline (base compose CMD) is unchanged.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

from uvicorn.protocols.http.h11_impl import H11Protocol

# Live TCP connections: (client_ip, client_port) -> SPIFFE URI ("" when the
# peer certificate carries no URI SAN). Single event loop — no locking needed.
_PEERS: dict[tuple[str, int], str] = {}

# Paths a monitor-scoped identity may reach: the scrape surface and liveness.
MONITOR_PATHS = ("/metrics", "/healthz")


def _peer_spiffe_uri(transport) -> str:
    """The SPIFFE URI SAN of the connection's client certificate, "" if the
    connection is not TLS, presented no certificate, or has no URI SAN."""
    ssl_object = transport.get_extra_info("ssl_object")
    if ssl_object is None:
        return ""
    cert = ssl_object.getpeercert()
    if not cert:
        return ""
    for kind, value in cert.get("subjectAltName", ()):
        if kind == "URI" and value.startswith("spiffe://"):
            return value
    return ""


class IdentityH11Protocol(H11Protocol):
    """H11Protocol that records the peer's SPIFFE identity per connection."""

    def connection_made(self, transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        if self.client is not None:
            _PEERS[tuple(self.client)] = _peer_spiffe_uri(transport)

    def connection_lost(self, exc) -> None:
        if self.client is not None:
            _PEERS.pop(tuple(self.client), None)
        super().connection_lost(exc)


def peer_identity(scope) -> str:
    """The SPIFFE URI of the request's client connection ("" if unknown)."""
    client = scope.get("client")
    if client is None:
        return ""
    return _PEERS.get(tuple(client), "")


def _csv_env(name: str) -> frozenset[str]:
    return frozenset(v.strip() for v in os.environ.get(name, "").split(",") if v.strip())


class PeerIdentityMiddleware:
    """Enforce the workload-identity policy on every http request.

    allowed: full access. monitor: MONITOR_PATHS only. Empty allowed set =
    enforcement off (the plaintext baseline). Unknown/absent identity while
    enforcement is on = 403 — fail closed, never open (§3).
    """

    def __init__(self, app, allowed: Iterable[str] | None = None, monitor: Iterable[str] | None = None):
        self.app = app
        self.allowed = frozenset(allowed) if allowed is not None else _csv_env("CORR_TLS_ALLOWED_URIS")
        self.monitor = frozenset(monitor) if monitor is not None else _csv_env("CORR_TLS_MONITOR_URIS")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.allowed:
            await self.app(scope, receive, send)
            return
        identity = peer_identity(scope)
        if identity in self.allowed:
            await self.app(scope, receive, send)
            return
        if identity in self.monitor and scope.get("path", "") in MONITOR_PATHS:
            await self.app(scope, receive, send)
            return
        # 403, not 401: the transport authenticated the caller; this identity
        # is simply not authorized for this path. Log the denial — a silent
        # 403 on the api→correlation hop looks exactly like "findings stopped".
        import logging

        logging.getLogger("correlation.tls").warning(
            "peer identity %r denied for %s %s",
            identity or "<none>",
            scope.get("method", "?"),
            scope.get("path", "?"),
        )
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"detail":"workload identity not authorized"}',
            }
        )
