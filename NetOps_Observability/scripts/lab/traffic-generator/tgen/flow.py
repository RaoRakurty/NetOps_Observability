"""Flow realization — turn a catalog App into concrete bidirectional flows.

A `Flow` is the OTG-style unit: endpoints + L4 + a byte/packet/timing profile.
The encoders (IPFIX/NetFlow/sFlow) and the packet/L7 generators all consume it,
so an app is defined once and rendered many ways.
"""
from __future__ import annotations

import ipaddress
import os
import random
import time
import zlib
from dataclasses import dataclass

from .catalog import App, CLIENT_PREFIXES

PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}
# Completed TCP conversation: FIN+SYN+PSH+ACK seen across the flow.
TCP_FLAGS_FULL = 0x1B

# Finite population: a real enterprise has hundreds of clients talking to a
# handful of endpoints per SaaS, with repeat conversations — not a fresh IP per
# flow. Unbounded randomization made (src,dst) cardinality ≈ flow count, which
# renders "top talkers" meaningless and blows up GROUP BY src,dst downstream.
CLIENT_POOL = int(os.getenv("TGEN_CLIENTS", "254"))
SERVERS_PER_APP = int(os.getenv("TGEN_SERVERS_PER_APP", "6"))

_POOLS: dict[tuple, list[str]] = {}


def _pool(prefixes: tuple[str, ...], size: int, salt: str) -> list[str]:
    """Deterministic host pool, identical across worker processes (stable seed)."""
    key = (prefixes, size, salt)
    hosts = _POOLS.get(key)
    if hosts is None:
        prnd = random.Random(zlib.crc32(repr(key).encode()))
        hosts = [_host_in(prnd.choice(prefixes), prnd) for _ in range(max(size, 1))]
        _POOLS[key] = hosts
    return hosts


def _pick_skewed(hosts: list[str], rnd: random.Random) -> str:
    # quadratic skew toward the head of the pool → stable heavy hitters
    return hosts[min(int(rnd.random() ** 2 * len(hosts)), len(hosts) - 1)]


@dataclass
class Flow:
    app: str
    category: str
    proto: int                 # IANA L4 (6/17/1)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    fwd_bytes: int
    fwd_pkts: int
    rev_bytes: int
    rev_pkts: int
    tcp_flags: int
    start_ms: int
    end_ms: int
    l7: str

    @property
    def in_if(self) -> int:
        return 10

    @property
    def out_if(self) -> int:
        return 12


def _host_in(prefix: str, rnd: random.Random) -> str:
    net = ipaddress.ip_network(prefix, strict=False)
    if net.num_addresses <= 2:
        return str(net.network_address)
    # pick a usable host (avoid network/broadcast for large nets)
    off = rnd.randint(1, min(net.num_addresses - 2, 1 << 16))
    return str(net.network_address + off)


def _span(lo_hi: tuple[int, int], rnd: random.Random) -> int:
    lo, hi = lo_hi
    if hi <= lo:
        return lo
    # log-ish skew toward the lower end (most flows are small)
    x = rnd.random() ** 2
    return int(lo + x * (hi - lo))


def realize(app: App, rnd: random.Random, now_ms: int | None = None) -> Flow:
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    proto = PROTO_NUM["icmp"] if app.name == "ICMP-Ping" else PROTO_NUM[app.proto]
    src = _pick_skewed(_pool(CLIENT_PREFIXES, CLIENT_POOL, "clients"), rnd)
    dst = _pick_skewed(_pool(app.dst_prefixes, SERVERS_PER_APP, app.name), rnd)
    sport = rnd.randint(1024, 65535)
    dport = rnd.choice(app.dst_ports) if app.dst_ports != (0,) else 0
    dur = _span(app.dur_ms, rnd)
    end = now_ms - rnd.randint(0, 2000)
    start = end - max(dur, 1)
    fb = _span(app.fwd_bytes, rnd)
    rb = _span(app.rev_bytes, rnd) if not app.bidir_media else fb + rnd.randint(-fb // 5, fb // 5)
    fp = max(1, _span(app.fwd_pkts, rnd))
    rp = max(1, _span(app.rev_pkts, rnd))
    flags = TCP_FLAGS_FULL if proto == 6 else 0
    return Flow(
        app=app.name, category=app.category, proto=proto,
        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        fwd_bytes=fb, fwd_pkts=fp, rev_bytes=max(rb, 0), rev_pkts=rp,
        tcp_flags=flags, start_ms=start, end_ms=end, l7=app.l7,
    )
