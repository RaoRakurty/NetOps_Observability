"""L2–L4 frame builder — Ethernet + IPv4 + TCP/UDP/ICMP.

Shared by the sFlow encoder (which embeds a sampled packet header) and the raw
packet generator. Correct IP + L4 checksums (so a real exporter / capture reads
them as valid frames).
"""
from __future__ import annotations

import ipaddress
import struct

from .flow import Flow


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _mac(seed: int) -> bytes:
    # locally-administered unicast MAC derived from a seed
    return bytes([0x02, 0x00, (seed >> 24) & 0xFF, (seed >> 16) & 0xFF, (seed >> 8) & 0xFF, seed & 0xFF])


def ipv4_l4(src_ip: str, dst_ip: str, proto: int, sport: int, dport: int,
            payload_len: int, flags: int = 0x18, ttl: int = 62) -> bytes:
    """IPv4 header + L4 header (+ zero payload of payload_len), with checksums."""
    src = ipaddress.IPv4Address(src_ip).packed
    dst = ipaddress.IPv4Address(dst_ip).packed
    payload = b"\x00" * max(0, payload_len)

    if proto == 6:  # TCP
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, (5 << 4), flags, 65535, 0, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(l4) + len(payload))
        csum = _csum(pseudo + l4 + payload)
        l4 = l4[:16] + struct.pack("!H", csum) + l4[18:]
    elif proto == 17:  # UDP
        ulen = 8 + len(payload)
        l4 = struct.pack("!HHHH", sport, dport, ulen, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 17, ulen)
        csum = _csum(pseudo + l4 + payload)
        l4 = l4[:6] + struct.pack("!H", csum or 0xFFFF)
    elif proto == 1:  # ICMP echo request
        icmp = struct.pack("!BBHHH", 8, 0, 0, sport & 0xFFFF, dport & 0xFFFF)
        csum = _csum(icmp + payload)
        l4 = icmp[:2] + struct.pack("!H", csum) + icmp[4:]
    else:
        l4 = struct.pack("!HH", sport, dport)

    total = 20 + len(l4) + len(payload)
    ihl = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x1234, 0x4000, ttl, proto, 0) + src + dst
    ipcsum = _csum(ihl)
    ihl = ihl[:10] + struct.pack("!H", ipcsum) + ihl[12:]
    return ihl + l4 + payload


def ethernet(src_ip: str, dst_ip: str, inner: bytes) -> bytes:
    dmac = _mac(int(ipaddress.IPv4Address(dst_ip)))
    smac = _mac(int(ipaddress.IPv4Address(src_ip)))
    return dmac + smac + struct.pack("!H", 0x0800) + inner


def sampled_header(f: Flow, header_bytes: int = 64) -> tuple[bytes, int]:
    """Build a representative Ethernet+IP+L4 frame for a flow; return (header
    slice up to header_bytes, original frame length) for sFlow."""
    inner = ipv4_l4(f.src_ip, f.dst_ip, f.proto, f.src_port, f.dst_port, payload_len=0, flags=f.tcp_flags or 0x18)
    frame = ethernet(f.src_ip, f.dst_ip, inner)
    # original frame length ≈ average per-packet size of the forward direction
    avg = max(64, f.fwd_bytes // max(f.fwd_pkts, 1))
    return frame[:header_bytes], avg
