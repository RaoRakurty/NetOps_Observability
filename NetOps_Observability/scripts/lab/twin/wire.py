"""Wire encoders/decoders for the twin's UDP lanes (tracker 152, fidelity
wave — design §4.4/§4.5).

SNMPv2c trap BER + NetFlow v5 + IPFIX (RFC 7011, template 256), all stdlib
`struct` work with a decode counterpart so every encoder is round-trip
unit-tested against its own decoder (and, for traps, shaped after the exact
TLV walk `collectors/snmptrap.go` performs).

Why hand-rolled v2c BER and not pysnmp (design §4.4 said "prefer snmpsim's
notification originator"): the trap ENCODER must also run on the twin HOST
(hostname-fidelity mode sends traps from `twin.py` itself to the published
:162 — no twin container required, which is what keeps every T1-core scenario
runnable with zero overlay), and the host carries no pysnmp. A v2c trap is ~60
lines of deterministic TLV framing with no crypto — the §6 concern (hand-
rolled USM auth/priv crypto) does not arise because the twin emits v2c only;
the receiver records v2c `authenticated=false` and attribution rides the
community + sysName path (`trapIdentityTrusted`, M4). v3 trap emission, if a
story ever needs `authenticated=true` evidence, is a later item and WILL use
pysnmp inside the twin container — never hand-rolled USM.

NetFlow v5 / IPFIX layouts are lifted from the proven in-repo generator
`scripts/lab/flowgen/flowgen.py` (design §4.5: "extend flowgen, not a new
dependency"), made deterministic (caller-supplied sequence numbers and flow
tuples; no `random` here).

This module is a LAB TOOL outside the product dependency graph (design §4.1);
nothing here is imported by src/backend or src/correlation.
"""
from __future__ import annotations

import socket
import struct
import time

# ── BER primitives ──────────────────────────────────────────────────────────

TAG_INT = 0x02
TAG_OCTETSTR = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQ = 0x30
TAG_IPADDR = 0x40
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_TRAP_V2_PDU = 0xA7

SYSUPTIME_OID = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
SYSNAME_OID = "1.3.6.1.2.1.1.5.0"

# Standard notification OIDs (RFC 3418 / RFC 4273) — the exact values
# `src/correlation/producers.py` classifies on.
TRAP_COLDSTART = "1.3.6.1.6.3.1.1.5.1"
TRAP_WARMSTART = "1.3.6.1.6.3.1.1.5.2"
TRAP_LINKDOWN = "1.3.6.1.6.3.1.1.5.3"
TRAP_LINKUP = "1.3.6.1.6.3.1.1.5.4"
TRAP_BGP_ESTABLISHED = "1.3.6.1.2.1.15.7.1"
TRAP_BGP_BACKWARD = "1.3.6.1.2.1.15.7.2"

# Varbind column OIDs the trap producer reads the affected entity from.
VB_IFINDEX = "1.3.6.1.2.1.2.2.1.1"
VB_IFDESCR = "1.3.6.1.2.1.2.2.1.2"
VB_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"
VB_BGP_PEER_ADDR = "1.3.6.1.2.1.15.3.1.7"


class WireError(ValueError):
    """Malformed input to an encoder, or an undecodable packet."""


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(body)) + body


def _encode_int(v: int, tag: int = TAG_INT) -> bytes:
    if tag == TAG_INT:
        # two's-complement signed
        n = max(1, (v.bit_length() + 8) // 8)
        return _tlv(tag, v.to_bytes(n, "big", signed=True))
    # application unsigned types (TimeTicks/Counter/Gauge): minimal unsigned,
    # a leading 0x00 pad when the top bit is set (BER positive-INTEGER form).
    if v < 0:
        raise WireError(f"unsigned BER type {tag:#x} cannot encode {v}")
    body = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(tag, body)


def _encode_oid(oid: str) -> bytes:
    try:
        arcs = [int(a) for a in oid.split(".")]
    except ValueError as exc:
        raise WireError(f"bad OID {oid!r}") from exc
    if len(arcs) < 2:
        raise WireError(f"OID {oid!r} needs at least two arcs")
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.insert(0, 0x80 | (arc & 0x7F))
            arc >>= 7
        body += chunk
    return _tlv(TAG_OID, bytes(body))


def _encode_value(tag: int, value) -> bytes:
    if tag == TAG_OID:
        return _encode_oid(str(value))
    if tag == TAG_OCTETSTR:
        return _tlv(TAG_OCTETSTR, str(value).encode())
    if tag == TAG_IPADDR:
        return _tlv(TAG_IPADDR, socket.inet_aton(str(value)))
    if tag in (TAG_INT, TAG_TIMETICKS, TAG_COUNTER32, TAG_GAUGE32):
        return _encode_int(int(value), tag)
    if tag == TAG_NULL:
        return _tlv(TAG_NULL, b"")
    raise WireError(f"unsupported varbind tag {tag:#x}")


def encode_trap_v2c(community: str, uptime_ticks: int, trap_oid: str,
                    varbinds: list[tuple[str, int, object]],
                    request_id: int = 1) -> bytes:
    """One SNMPv2c Trap-PDU datagram. `varbinds` are (oid, tag, value) and
    ride AFTER the two mandatory bindings (sysUpTime.0, snmpTrapOID.0) that
    SNMPv2-MIB requires and the Go receiver checks for."""
    vb_list = [
        _tlv(TAG_SEQ, _encode_oid(SYSUPTIME_OID)
             + _encode_int(uptime_ticks & 0xFFFFFFFF, TAG_TIMETICKS)),
        _tlv(TAG_SEQ, _encode_oid(SNMP_TRAP_OID) + _encode_oid(trap_oid)),
    ]
    for oid, tag, value in varbinds:
        vb_list.append(_tlv(TAG_SEQ, _encode_oid(oid)
                            + _encode_value(tag, value)))
    pdu = (_encode_int(request_id) + _encode_int(0) + _encode_int(0)
           + _tlv(TAG_SEQ, b"".join(vb_list)))
    msg = (_encode_int(1)                      # version: 1 = SNMPv2c
           + _tlv(TAG_OCTETSTR, community.encode())
           + _tlv(TAG_TRAP_V2_PDU, pdu))
    return _tlv(TAG_SEQ, msg)


# ── BER decode (round-trip tests + a host-side sanity tool) ─────────────────

def _read_tlv(buf: bytes, off: int) -> tuple[int, bytes, int]:
    if off + 2 > len(buf):
        raise WireError("truncated TLV")
    tag = buf[off]
    ln = buf[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or off + n > len(buf):
            raise WireError("bad long-form length")
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    if off + ln > len(buf):
        raise WireError("TLV overruns packet")
    return tag, buf[off:off + ln], off + ln


def _decode_oid(body: bytes) -> str:
    if not body:
        raise WireError("empty OID")
    arcs = [body[0] // 40, body[0] % 40]
    acc = 0
    for b in body[1:]:
        acc = (acc << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(acc)
            acc = 0
    return ".".join(str(a) for a in arcs)


def _decode_value(tag: int, body: bytes):
    if tag == TAG_OID:
        return _decode_oid(body)
    if tag == TAG_OCTETSTR:
        return body.decode(errors="replace")
    if tag == TAG_IPADDR:
        return socket.inet_ntoa(body)
    if tag == TAG_INT:
        return int.from_bytes(body, "big", signed=True)
    if tag in (TAG_TIMETICKS, TAG_COUNTER32, TAG_GAUGE32):
        return int.from_bytes(body, "big")
    if tag == TAG_NULL:
        return None
    return body


def decode_trap_v2c(pkt: bytes) -> dict:
    """Decode one v2c trap datagram — mirrors the readTLV walk in
    `collectors/snmptrap.go` so the round-trip test proves the receiver-side
    shape, not just self-consistency."""
    tag, msg, _ = _read_tlv(pkt, 0)
    if tag != TAG_SEQ:
        raise WireError("not a SEQUENCE")
    off = 0
    base = len(pkt) - len(msg)  # decode inside msg via absolute offsets

    def nxt(o: int) -> tuple[int, bytes, int]:
        t, b, e = _read_tlv(msg, o)
        return t, b, e

    tag, ver, off = nxt(off)
    if tag != TAG_INT or int.from_bytes(ver, "big", signed=True) != 1:
        raise WireError("not SNMPv2c")
    tag, comm, off = nxt(off)
    if tag != TAG_OCTETSTR:
        raise WireError("bad community")
    tag, pdu, off = nxt(off)
    if tag != TAG_TRAP_V2_PDU:
        raise WireError(f"pdu tag {tag:#x} is not SNMPv2-Trap-PDU")
    del base
    p = 0
    tag, rid, p = _read_tlv(pdu, p)
    tag, _est, p = _read_tlv(pdu, p)
    tag, _eidx, p = _read_tlv(pdu, p)
    tag, vbs, p = _read_tlv(pdu, p)
    if tag != TAG_SEQ:
        raise WireError("bad varbind list")
    varbinds: list[dict] = []
    v = 0
    while v < len(vbs):
        tag, one, v = _read_tlv(vbs, v)
        if tag != TAG_SEQ:
            raise WireError("bad varbind")
        o = 0
        t2, oid_body, o = _read_tlv(one, o)
        if t2 != TAG_OID:
            raise WireError("varbind without OID")
        t3, val_body, o = _read_tlv(one, o)
        varbinds.append({"oid": _decode_oid(oid_body), "tag": t3,
                         "value": _decode_value(t3, val_body)})
    out = {
        "version": "v2c",
        "community": comm.decode(errors="replace"),
        "request_id": int.from_bytes(rid, "big", signed=True),
        "varbinds": varbinds,
        "trap_oid": "",
        "uptime_ticks": -1,
    }
    for vb in varbinds:
        if vb["oid"] == SNMP_TRAP_OID and not out["trap_oid"]:
            out["trap_oid"] = str(vb["value"])
        if vb["oid"] == SYSUPTIME_OID and out["uptime_ticks"] < 0:
            out["uptime_ticks"] = int(vb["value"])
    return out


# ── NetFlow v5 (flowgen layout, deterministic) ──────────────────────────────

def _ip2int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def encode_netflow_v5(flows: list[dict], uptime_ms: int, seq: int,
                      unix_secs: int | None = None) -> bytes:
    """`flows` entries need: src, dst, sport, dport, proto, pkts, octets,
    in_if, out_if and optional src_as/dst_as/tcp_flags/first_ms/last_ms."""
    if not 1 <= len(flows) <= 30:
        raise WireError(f"NetFlow v5 carries 1..30 records, got {len(flows)}")
    now = time.time() if unix_secs is None else float(unix_secs)
    secs = int(now)
    nsecs = int((now - secs) * 1e9)
    hdr = struct.pack("!HHIIIIBBH", 5, len(flows), uptime_ms & 0xFFFFFFFF,
                      secs, nsecs, seq & 0xFFFFFFFF, 0, 0, 0)
    body = b""
    for f in flows:
        first = int(f.get("first_ms", max(uptime_ms - 30000, 0))) & 0xFFFFFFFF
        last = int(f.get("last_ms", uptime_ms)) & 0xFFFFFFFF
        body += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            _ip2int(f["src"]), _ip2int(f["dst"]), 0,
            int(f["in_if"]) & 0xFFFF, int(f["out_if"]) & 0xFFFF,
            int(f["pkts"]), int(f["octets"]), first, last,
            int(f["sport"]), int(f["dport"]),
            0, int(f.get("tcp_flags", 0)), int(f["proto"]), 0,
            int(f.get("src_as", 0)) & 0xFFFF, int(f.get("dst_as", 0)) & 0xFFFF,
            24, 24, 0)
    return hdr + body


def decode_netflow_v5(pkt: bytes) -> dict:
    if len(pkt) < 24:
        raise WireError("short NetFlow v5 header")
    (ver, count, uptime, secs, _nsecs, seq, _et, _eid,
     _smp) = struct.unpack("!HHIIIIBBH", pkt[:24])
    if ver != 5:
        raise WireError(f"not NetFlow v5 (version {ver})")
    if len(pkt) != 24 + count * 48:
        raise WireError("NetFlow v5 length does not match record count")
    flows = []
    for i in range(count):
        off = 24 + i * 48
        (src, dst, _nh, in_if, out_if, pkts, octets, first, last, sport,
         dport, _pad, tcp_flags, proto, _tos, src_as, dst_as, _sm, _dm,
         _p2) = struct.unpack("!IIIHHIIIIHHBBBBHHBBH", pkt[off:off + 48])
        flows.append({
            "src": socket.inet_ntoa(struct.pack("!I", src)),
            "dst": socket.inet_ntoa(struct.pack("!I", dst)),
            "sport": sport, "dport": dport, "proto": proto,
            "pkts": pkts, "octets": octets, "in_if": in_if,
            "out_if": out_if, "src_as": src_as, "dst_as": dst_as,
            "tcp_flags": tcp_flags, "first_ms": first, "last_ms": last,
        })
    return {"version": 5, "uptime_ms": uptime, "unix_secs": secs,
            "seq": seq, "flows": flows}


# ── IPFIX (RFC 7011) — template 256, same field set as flowgen ──────────────

IPFIX_TEMPLATE_ID = 256
# (IE id, length): sourceIPv4Address, destinationIPv4Address,
# sourceTransportPort, destinationTransportPort, protocolIdentifier,
# octetDeltaCount, packetDeltaCount, ingressInterface, egressInterface,
# bgpSourceAsNumber, bgpDestinationAsNumber
IPFIX_FIELDS = [
    (8, 4), (12, 4), (7, 2), (11, 2), (4, 1),
    (1, 8), (2, 8), (10, 4), (14, 4), (16, 4), (17, 4),
]


def _ipfix_template_set() -> bytes:
    fields = b"".join(struct.pack("!HH", fid, flen)
                      for fid, flen in IPFIX_FIELDS)
    tmpl = struct.pack("!HH", IPFIX_TEMPLATE_ID, len(IPFIX_FIELDS)) + fields
    return struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl


def encode_ipfix(flows: list[dict], seq: int, domain: int,
                 with_template: bool, export_secs: int | None = None) -> bytes:
    body = b""
    for f in flows:
        body += struct.pack(
            "!IIHHBQQIIII",
            _ip2int(f["src"]), _ip2int(f["dst"]),
            int(f["sport"]), int(f["dport"]), int(f["proto"]),
            int(f["octets"]), int(f["pkts"]),
            int(f["in_if"]), int(f["out_if"]),
            int(f.get("src_as", 0)), int(f.get("dst_as", 0)))
    sets = b""
    if with_template:
        sets += _ipfix_template_set()
    if body:
        sets += struct.pack("!HH", IPFIX_TEMPLATE_ID, 4 + len(body)) + body
    secs = int(time.time()) if export_secs is None else int(export_secs)
    hdr = struct.pack("!HHIII", 10, 16 + len(sets), secs,
                      seq & 0xFFFFFFFF, domain)
    return hdr + sets


def decode_ipfix(pkt: bytes) -> dict:
    if len(pkt) < 16:
        raise WireError("short IPFIX header")
    ver, length, secs, seq, domain = struct.unpack("!HHIII", pkt[:16])
    if ver != 10:
        raise WireError(f"not IPFIX (version {ver})")
    if length != len(pkt):
        raise WireError("IPFIX length mismatch")
    off = 16
    template: list[tuple[int, int]] = []
    flows: list[dict] = []
    while off < len(pkt):
        set_id, set_len = struct.unpack("!HH", pkt[off:off + 4])
        if set_len < 4 or off + set_len > len(pkt):
            raise WireError("bad IPFIX set length")
        body = pkt[off + 4:off + set_len]
        if set_id == 2:  # template set
            tid, nf = struct.unpack("!HH", body[:4])
            if tid != IPFIX_TEMPLATE_ID:
                raise WireError(f"unexpected template id {tid}")
            template = [struct.unpack("!HH", body[4 + i * 4:8 + i * 4])
                        for i in range(nf)]
        elif set_id == IPFIX_TEMPLATE_ID:
            rec_len = struct.calcsize("!IIHHBQQIIII")
            n = len(body) // rec_len
            for i in range(n):
                (src, dst, sport, dport, proto, octets, pkts, in_if, out_if,
                 sas, das) = struct.unpack(
                    "!IIHHBQQIIII", body[i * rec_len:(i + 1) * rec_len])
                flows.append({
                    "src": socket.inet_ntoa(struct.pack("!I", src)),
                    "dst": socket.inet_ntoa(struct.pack("!I", dst)),
                    "sport": sport, "dport": dport, "proto": proto,
                    "octets": octets, "pkts": pkts,
                    "in_if": in_if, "out_if": out_if,
                    "src_as": sas, "dst_as": das,
                })
        off += set_len
    return {"version": 10, "export_secs": secs, "seq": seq,
            "domain": domain, "template": template, "flows": flows}
