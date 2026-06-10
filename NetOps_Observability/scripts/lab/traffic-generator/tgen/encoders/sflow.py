"""sFlow v5 encoder — flow samples carrying a sampled packet header.

XDR-encoded (big-endian, 4-byte aligned). Each flow sample embeds a raw
Ethernet+IPv4+L4 header (format 1) which collectors decode to recover the flow.
NOTE: sFlow models *sampled packets*, so byte/packet totals come from the
sampling_rate × sample_pool, not exact counters — we set a realistic rate.
"""
from __future__ import annotations

import ipaddress
import struct

from ..flow import Flow
from ..framebuild import sampled_header

SAMPLING_RATE = 1024


def _pad(b: bytes) -> bytes:
    r = len(b) % 4
    return b + (b"\x00" * (4 - r) if r else b"")


class SflowEncoder:
    def __init__(self, agent_ip: str = "172.40.40.10", sub_agent: int = 0):
        self.agent = ipaddress.IPv4Address(agent_ip).packed
        self.sub_agent = sub_agent
        self._seq = 0
        self._pool = 0

    def _raw_header_record(self, f: Flow) -> bytes:
        hdr, frame_len = sampled_header(f, header_bytes=64)
        body = struct.pack("!IIII", 1, frame_len, 0, len(hdr)) + _pad(hdr)
        # flow record: data_format=1 (raw packet header), length, body
        return struct.pack("!II", 1, len(body)) + body

    def _flow_sample(self, f: Flow) -> bytes:
        self._seq += 1
        self._pool += SAMPLING_RATE
        rec = self._raw_header_record(f)
        source_id = (0 << 24) | (f.in_if & 0xFFFFFF)
        body = struct.pack("!IIIIIIII",
                           self._seq, source_id, SAMPLING_RATE, self._pool, 0,
                           f.in_if, f.out_if, 1) + rec
        # sample: type=1 (flow sample), length, body
        return struct.pack("!II", 1, len(body)) + body

    def encode(self, flows: list[Flow]) -> bytes:
        samples = b"".join(self._flow_sample(f) for f in flows)
        uptime = 0
        header = struct.pack("!II", 5, 1) + self.agent + struct.pack("!III",
                                                                     self.sub_agent, self._seq, uptime)
        header += struct.pack("!I", len(flows))
        return header + samples
