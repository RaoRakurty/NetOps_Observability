# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""test_tls_ident.py — regression guards for APP-001 workload identity.

The correlation API is cross-tenant capable, so the thing these tests defend
is precise: with enforcement on, ONLY the named api identity reaches data
paths, monitor identities reach exactly /metrics + /healthz, and an unknown
or absent identity is refused — while the plaintext baseline (no allowlist
configured) behaves exactly as before the feature existed.
"""

import asyncio

import tls_ident
from tls_ident import (
    _PEERS,
    MONITOR_PATHS,
    IdentityH11Protocol,
    PeerIdentityMiddleware,
    peer_identity,
)

API = "spiffe://netops/ns/default/sa/api"
VICTORIA = "spiffe://netops/ns/default/sa/victoria"
ROGUE = "spiffe://netops/ns/default/sa/goflow2"


def _scope(path="/findings", client=("172.18.0.9", 55001)):
    return {"type": "http", "method": "GET", "path": path, "client": client}


class _App:
    """Records whether the wrapped app ran."""

    def __init__(self):
        self.ran = False

    async def __call__(self, scope, receive, send):
        self.ran = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _invoke(mw, scope):
    sent = []

    async def send(message):
        sent.append(message)

    await mw(scope, None, send)
    return sent


def _status(sent):
    return sent[0]["status"]


def _run(coro):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


def setup_function(_):
    _PEERS.clear()


# ── the registry: connection lifecycle ──────────────────────────────────────


class _FakeTLSTransport:
    """Just enough transport for connection_made: an ssl_object whose peer
    certificate carries a SPIFFE URI SAN."""

    def __init__(self, uri):
        self._uri = uri

    def get_extra_info(self, name, default=None):
        if name != "ssl_object":
            return default
        uri = self._uri

        class _SSL:
            def getpeercert(self):
                if uri is None:
                    return None
                return {"subjectAltName": (("DNS", "api"), ("URI", uri))}

        return _SSL()


def _protocol_with_client(client):
    # Bypass H11Protocol.__init__ (it wants config/server state); the two
    # overridden methods only touch .client and the module registry.
    p = IdentityH11Protocol.__new__(IdentityH11Protocol)
    p.client = client
    return p


def test_registry_tracks_connection_lifetime(monkeypatch):
    p = _protocol_with_client(("10.0.0.7", 41000))
    # Isolate the uvicorn base-class halves — only the registry is under test.
    monkeypatch.setattr(tls_ident.H11Protocol, "connection_made", lambda self, t: None)
    monkeypatch.setattr(tls_ident.H11Protocol, "connection_lost", lambda self, e: None)
    p.connection_made(_FakeTLSTransport(API))
    assert peer_identity(_scope(client=("10.0.0.7", 41000))) == API
    p.connection_lost(None)
    assert peer_identity(_scope(client=("10.0.0.7", 41000))) == ""


def test_certificate_without_uri_san_registers_empty(monkeypatch):
    p = _protocol_with_client(("10.0.0.8", 41001))
    monkeypatch.setattr(tls_ident.H11Protocol, "connection_made", lambda self, t: None)
    monkeypatch.setattr(tls_ident.H11Protocol, "connection_lost", lambda self, e: None)

    class _NoUri(_FakeTLSTransport):
        def get_extra_info(self, name, default=None):
            if name != "ssl_object":
                return default

            class _SSL:
                def getpeercert(self):
                    return {"subjectAltName": (("DNS", "something"),)}

            return _SSL()

    p.connection_made(_NoUri(None))
    assert peer_identity(_scope(client=("10.0.0.8", 41001))) == ""


# ── the middleware: policy ──────────────────────────────────────────────────


def test_enforcement_off_when_unconfigured():
    """The plaintext baseline must be bit-for-bit unchanged: no allowlist,
    no identity, request passes."""
    inner = _App()
    mw = PeerIdentityMiddleware(inner, allowed=(), monitor=())
    sent = _run(_invoke(mw, _scope()))
    assert inner.ran and _status(sent) == 200


def test_api_identity_reaches_data_paths():
    _PEERS[("172.18.0.9", 55001)] = API
    inner = _App()
    mw = PeerIdentityMiddleware(inner, allowed=[API], monitor=[VICTORIA])
    sent = _run(_invoke(mw, _scope("/findings")))
    assert inner.ran and _status(sent) == 200


def test_monitor_identity_scoped_to_monitor_paths():
    _PEERS[("172.18.0.9", 55001)] = VICTORIA
    for path in MONITOR_PATHS:
        inner = _App()
        mw = PeerIdentityMiddleware(inner, allowed=[API], monitor=[VICTORIA])
        sent = _run(_invoke(mw, _scope(path)))
        assert inner.ran and _status(sent) == 200, path
    # ...and NOT the cross-tenant data surface.
    inner = _App()
    mw = PeerIdentityMiddleware(inner, allowed=[API], monitor=[VICTORIA])
    sent = _run(_invoke(mw, _scope("/findings")))
    assert not inner.ran and _status(sent) == 403


def test_unknown_identity_fails_closed():
    """A mesh workload that is not on the list — a compromised collector,
    say — completed the handshake but must not reach ANY path (§3)."""
    _PEERS[("172.18.0.9", 55001)] = ROGUE
    for path in ("/findings", "/deadletters", "/metrics"):
        inner = _App()
        mw = PeerIdentityMiddleware(inner, allowed=[API], monitor=[VICTORIA])
        sent = _run(_invoke(mw, _scope(path)))
        assert not inner.ran and _status(sent) == 403, path


def test_absent_identity_fails_closed_when_enforcing():
    """No registry entry for the connection (should be impossible under
    tls_serve.py, but fail closed, never open)."""
    inner = _App()
    mw = PeerIdentityMiddleware(inner, allowed=[API], monitor=[VICTORIA])
    sent = _run(_invoke(mw, _scope("/findings", client=("1.2.3.4", 1))))
    assert not inner.ran and _status(sent) == 403


def test_non_http_scopes_pass_through():
    inner = _App()
    mw = PeerIdentityMiddleware(inner, allowed=[API], monitor=[])

    async def send(message):
        return None

    _run(mw({"type": "lifespan"}, None, send))
    assert inner.ran
