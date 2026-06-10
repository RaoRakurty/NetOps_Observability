"""Real L7 session generator — genuine application bytes.

Opens real client sessions so true L7 traffic crosses the wire:
  - https / http : real TCP connect + TLS + GET (stdlib http.client / ssl)
  - dns          : real UDP DNS query (stdlib)
  - quic         : best-effort UDP/443 initial (real QUIC needs aioquic; when
                   absent we send a UDP/443 datagram so the 5-tuple is genuine)
  - ntp          : real NTP client request
These produce actual flows a real exporter sees, and exercise DNS/TLS/HTTP for
realism. Bounded + best-effort: failures are expected (public endpoints, lab
egress) and never crash the run.
"""
from __future__ import annotations

import http.client
import random
import socket
import ssl
import struct
import time

from .catalog import App
from .flow import realize
from .sender import RateLimiter

_TLS = ssl.create_default_context()
_TLS.check_hostname = False
_TLS.verify_mode = ssl.CERT_NONE


def _http_get(host_ip: str, port: int, use_tls: bool, timeout: float = 4.0) -> int:
    try:
        if use_tls:
            conn = http.client.HTTPSConnection(host_ip, port, timeout=timeout, context=_TLS)
        else:
            conn = http.client.HTTPConnection(host_ip, port, timeout=timeout)
        conn.request("GET", "/", headers={"User-Agent": "tgen/0.1", "Host": "example.com"})
        r = conn.getresponse()
        _ = r.read(4096)
        conn.close()
        return 1
    except Exception:
        return 0


def _dns_query(server_ip: str, timeout: float = 2.0) -> int:
    # minimal A query for example.com
    txid = random.randint(0, 0xFFFF)
    q = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for part in ("example", "com"):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(q, (server_ip, 53))
        s.recvfrom(2048)
        s.close()
        return 1
    except Exception:
        return 0


def _ntp(server_ip: str, timeout: float = 2.0) -> int:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x1b" + 47 * b"\0", (server_ip, 123))
        s.recvfrom(256)
        s.close()
        return 1
    except Exception:
        return 0


def _udp443(host_ip: str) -> int:
    # QUIC initial-ish: a UDP/443 datagram (real 5-tuple; not a full handshake)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.sendto(b"\xc0" + bytes(random.getrandbits(8) for _ in range(64)), (host_ip, 443))
        s.close()
        return 1
    except Exception:
        return 0


def run_sessions(apps: list[App], rate: float, duration: int, rnd: random.Random) -> dict:
    rl = RateLimiter(rate=max(rate, 0.5), burst=max(rate, 4))
    end = time.monotonic() + duration if duration else None
    stats = {"ok": 0, "fail": 0}
    weights = [a.weight for a in apps]
    while end is None or time.monotonic() < end:
        app = rnd.choices(apps, weights=weights, k=1)[0]
        f = realize(app, rnd)
        rl.take(1)
        if app.l7 in ("https", "tls"):
            ok = _http_get(f.dst_ip, f.dst_port or 443, use_tls=True)
        elif app.l7 == "http":
            ok = _http_get(f.dst_ip, f.dst_port or 80, use_tls=False)
        elif app.l7 == "dns":
            ok = _dns_query(f.dst_ip)
        elif app.l7 == "ntp":
            ok = _ntp(f.dst_ip)
        elif app.l7 == "quic":
            ok = _udp443(f.dst_ip)
        else:
            ok = _udp443(f.dst_ip)
        stats["ok" if ok else "fail"] += 1
    return stats
