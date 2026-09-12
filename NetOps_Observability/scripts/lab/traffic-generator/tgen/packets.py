# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Real L2–L4 packet generator (raw sockets).

Crafts and transmits genuine IPv4 TCP/UDP/ICMP frames so a real exporter on the
path samples them. Uses an AF_INET raw socket with IP_HDRINCL (needs
CAP_NET_RAW). This is the Ostinato/OTG dataplane equivalent — packets only, no
session state. For real L7 *sessions* (handshakes, TLS, HTTP) see l7.py.
"""
from __future__ import annotations

import random
import socket
import time

from .catalog import App
from .flow import realize
from .framebuild import ipv4_l4
from .sender import RateLimiter


class RawPacketGen:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.tx = 0

    def send_flow_packets(self, app: App, rnd: random.Random, max_pkts: int = 8) -> int:
        """Emit a handful of real packets representing one flow of `app`."""
        f = realize(app, rnd)
        n = min(max_pkts, max(1, f.fwd_pkts // 50 + 1))
        # average forward packet payload
        payload = max(0, min(1400, f.fwd_bytes // max(f.fwd_pkts, 1) - 40))
        pkt = ipv4_l4(f.src_ip, f.dst_ip, f.proto, f.src_port, f.dst_port,
                      payload_len=payload, flags=f.tcp_flags or 0x18)
        sent = 0
        for _ in range(n):
            try:
                self.sock.sendto(pkt, (f.dst_ip, 0))
                sent += 1
            except OSError:
                break
        self.tx += sent
        return sent

    def run(self, apps: list[App], pps: int, duration: int, rnd: random.Random) -> None:
        rl = RateLimiter(rate=max(pps, 1), burst=max(pps, 64))
        weights = [a.weight for a in apps]
        end = time.monotonic() + duration if duration else None
        while end is None or time.monotonic() < end:
            app = rnd.choices(apps, weights=weights, k=1)[0]
            rl.take(1)
            self.send_flow_packets(app, rnd)
