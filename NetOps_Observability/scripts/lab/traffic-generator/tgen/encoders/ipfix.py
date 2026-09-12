# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""IPFIX (RFC 7011) encoder.

Emits an IPFIX message: 16-byte header + (periodic template set) + a data set
of flow records. Field IDs are standard IANA Information Elements so goflow2
parses them into the platform's flow schema. A directional flow is sent as the
forward record (src→dst) and an optional reverse record (dst→src) so the
by-direction / conversation views are realistic.

Template (id 256), per record:
  sourceIPv4Address(8)        4
  destinationIPv4Address(12)  4
  sourceTransportPort(7)      2
  destinationTransportPort(11)2
  protocolIdentifier(4)       1
  tcpControlBits(6)           1
  octetDeltaCount(1)          4
  packetDeltaCount(2)         4
  ingressInterface(10)        4
  egressInterface(14)         4
  flowStartMilliseconds(152)  8
  flowEndMilliseconds(153)    8
"""
from __future__ import annotations

import ipaddress
import struct
import time

from ..flow import Flow

TEMPLATE_ID = 256
_FIELDS = [
    (8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1),
    (1, 4), (2, 4), (10, 4), (14, 4), (152, 8), (153, 8),
]
_REC_LEN = sum(l for _, l in _FIELDS)


def _template_set() -> bytes:
    # Set header: setId=2 (template), length. Template record: id, fieldCount, fields.
    rec = struct.pack("!HH", TEMPLATE_ID, len(_FIELDS))
    for fid, flen in _FIELDS:
        rec += struct.pack("!HH", fid, flen)
    set_len = 4 + len(rec)
    return struct.pack("!HH", 2, set_len) + rec


def _record(src_ip: str, dst_ip: str, sport: int, dport: int, proto: int,
            flags: int, octets: int, pkts: int, in_if: int, out_if: int,
            start_ms: int, end_ms: int) -> bytes:
    return (
        ipaddress.IPv4Address(src_ip).packed +
        ipaddress.IPv4Address(dst_ip).packed +
        struct.pack("!HHBB", sport, dport, proto, flags) +
        struct.pack("!II", octets & 0xFFFFFFFF, pkts & 0xFFFFFFFF) +
        struct.pack("!II", in_if, out_if) +
        struct.pack("!QQ", start_ms, end_ms)
    )


class IpfixEncoder:
    """Stateful: re-sends the template every `template_every` messages."""

    def __init__(self, domain_id: int = 1, template_every: int = 20):
        self.domain = domain_id
        self.template_every = max(1, template_every)
        self._seq = 0
        self._since_tmpl = template_every  # force a template on the first message

    def _flow_records(self, f: Flow) -> list[bytes]:
        recs = [_record(f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.proto,
                        f.tcp_flags, f.fwd_bytes, f.fwd_pkts, f.in_if, f.out_if,
                        f.start_ms, f.end_ms)]
        if f.rev_bytes > 0:
            recs.append(_record(f.dst_ip, f.src_ip, f.dst_port, f.src_port, f.proto,
                                f.tcp_flags, f.rev_bytes, f.rev_pkts, f.out_if, f.in_if,
                                f.start_ms, f.end_ms))
        return recs

    def encode(self, flows: list[Flow]) -> bytes:
        """One IPFIX message carrying all `flows` (fwd+rev records)."""
        records = b"".join(r for f in flows for r in self._flow_records(f))
        body = b""
        if self._since_tmpl >= self.template_every:
            body += _template_set()
            self._since_tmpl = 0
        else:
            self._since_tmpl += 1
        # Data set: setId = template id, length, records.
        data_set = struct.pack("!HH", TEMPLATE_ID, 4 + len(records)) + records
        body += data_set
        export_time = int(time.time())
        msg_len = 16 + len(body)
        n_records = sum(1 + (1 if f.rev_bytes > 0 else 0) for f in flows)
        header = struct.pack("!HHIII", 10, msg_len, export_time, self._seq, self.domain)
        self._seq += n_records  # IPFIX seq counts records exported
        return header + body
