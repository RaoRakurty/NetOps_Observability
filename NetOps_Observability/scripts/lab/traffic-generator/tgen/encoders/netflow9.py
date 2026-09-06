# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""NetFlow v9 (RFC 3954) encoder.

Header(20) + (periodic template FlowSet 0) + a data FlowSet. Field types are the
standard NetFlow v9 types goflow2 understands. NetFlow v9 timestamps are
sysUptime-relative (FIRST_SWITCHED/LAST_SWITCHED in ms since boot), so we keep a
synthetic boot epoch and a packet count for the header.
"""
from __future__ import annotations

import ipaddress
import struct
import time

from ..flow import Flow

TEMPLATE_ID = 256
# (type, length) — NetFlow v9 field types.
_FIELDS = [
    (8, 4),    # IPV4_SRC_ADDR
    (12, 4),   # IPV4_DST_ADDR
    (7, 2),    # L4_SRC_PORT
    (11, 2),   # L4_DST_PORT
    (4, 1),    # PROTOCOL
    (6, 1),    # TCP_FLAGS
    (1, 4),    # IN_BYTES
    (2, 4),    # IN_PKTS
    (10, 2),   # INPUT_SNMP
    (14, 2),   # OUTPUT_SNMP
    (21, 4),   # LAST_SWITCHED (ms since boot)
    (22, 4),   # FIRST_SWITCHED (ms since boot)
]
_REC_LEN = sum(l for _, l in _FIELDS)


def _template_flowset() -> bytes:
    rec = struct.pack("!HH", TEMPLATE_ID, len(_FIELDS))
    for t, l in _FIELDS:
        rec += struct.pack("!HH", t, l)
    return struct.pack("!HH", 0, 4 + len(rec)) + rec


class NetflowV9Encoder:
    def __init__(self, source_id: int = 1, template_every: int = 20):
        self.source_id = source_id
        self.template_every = max(1, template_every)
        self._boot = time.time()
        self._seq = 0           # packet sequence (header)
        self._since_tmpl = template_every

    def _uptime_ms(self) -> int:
        return int((time.time() - self._boot) * 1000) & 0xFFFFFFFF

    def _record(self, src, dst, sp, dp, proto, flags, octets, pkts, inif, outif, first, last) -> bytes:
        return (
            ipaddress.IPv4Address(src).packed +
            ipaddress.IPv4Address(dst).packed +
            struct.pack("!HHBB", sp, dp, proto, flags) +
            struct.pack("!II", octets & 0xFFFFFFFF, pkts & 0xFFFFFFFF) +
            struct.pack("!HH", inif, outif) +
            struct.pack("!II", last & 0xFFFFFFFF, first & 0xFFFFFFFF)
        )

    def _flow_records(self, f: Flow, up: int) -> list[bytes]:
        # map absolute ms to uptime-relative window
        dur = max(f.end_ms - f.start_ms, 1)
        last = up
        first = up - dur if up - dur > 0 else 0
        recs = [self._record(f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.proto,
                             f.tcp_flags, f.fwd_bytes, f.fwd_pkts, f.in_if, f.out_if, first, last)]
        if f.rev_bytes > 0:
            recs.append(self._record(f.dst_ip, f.src_ip, f.dst_port, f.src_port, f.proto,
                                     f.tcp_flags, f.rev_bytes, f.rev_pkts, f.out_if, f.in_if, first, last))
        return recs

    def encode(self, flows: list[Flow]) -> bytes:
        up = self._uptime_ms()
        records = b"".join(r for f in flows for r in self._flow_records(f, up))
        n = sum(1 + (1 if f.rev_bytes > 0 else 0) for f in flows)
        body = b""
        count = n
        if self._since_tmpl >= self.template_every:
            body += _template_flowset()
            self._since_tmpl = 0
            count += 1  # the template counts as a flowset record in v9 'count'
        else:
            self._since_tmpl += 1
        body += struct.pack("!HH", TEMPLATE_ID, 4 + len(records)) + records
        header = struct.pack("!HHIIII", 9, count, up, int(time.time()), self._seq, self.source_id)
        self._seq += 1  # v9 sequence counts EXPORT PACKETS
        return header + body
