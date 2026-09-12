#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""bmp-synthetic-session.py — a synthetic RFC 7854 BMP router, on the wire.

WHAT THIS IS
    A standalone Python 3 (stdlib only) client that opens ONE TCP session to a
    BMP receiver and pushes real, hand-assembled RFC 7854 frames:

        Initiation  (§4.3)  → sysName / sysDescr, so the session is identifiable
        Peer Up     (§4.4)  → one monitored BGP peer, with both BGP OPENs
        Route Monitoring (§4.6) × N → one BGP UPDATE (RFC 4271 §4.3) each
        Termination (§4.5)  → an explicit administrative close

    It is the MOCK TELEMETRY STREAM the platform's test rules require (root
    CLAUDE.md §11): it proves a receiver end to end — parse, attribution,
    storage, bogon screening — without a router, a lab, or a second vendor.

WHAT THIS IS NOT
    Not a BGP speaker. It never establishes a BGP session, never answers a
    KEEPALIVE, and never reads anything the receiver sends back. It writes
    frames and closes. A receiver that only works against this is not proven
    against a real router — it is proven against RFC 7854's byte layout.

SAFETY / SHIP RULES (root CLAUDE.md §8, §16.1, §16.5)
    * No secrets, no credentials, no hostnames baked in — every target is an
      argument, and the defaults are loopback + RFC 5737 documentation space.
    * Every socket operation is BOUNDED (connect timeout, send timeout). A
      wedged receiver cannot hang this script forever.
    * No failure is swallowed: any socket error exits non-zero with the reason
      on stderr. A partial send is an error, not a silent short write.
    * It prints exactly what it put on the wire (type, length, and the
      prefixes/AS paths carried), so the run is auditable after the fact.

ATTRIBUTION (why a run can be refused)
    The receiver resolves the session's REMOTE ADDRESS through the device
    inventory and DISCONNECTS a source it cannot attribute to a tenant. So the
    address this script's packets arrive FROM must exist as a device row. From
    a container host that is usually the docker bridge gateway, not 127.0.0.1.
    A refused run shows up here as an immediate EOF/reset, and in the
    receiver's log as "source address is not a known device".

EXAMPLES
    # default proof set: one clean prefix + two bogons, to a local receiver
    python3 scripts/bmp-synthetic-session.py --host 127.0.0.1 --port 11019

    # a different monitored peer, held open longer
    python3 scripts/bmp-synthetic-session.py --peer-asn 64512 --hold 30

    # only announce what you name (repeatable; PREFIX[,ASN[,ASN...]])
    python3 scripts/bmp-synthetic-session.py --announce 8.8.8.0/24,65001,15169

EXIT CODES
    0 = every frame written and the session closed cleanly
    1 = a socket, argument or encoding error (reason on stderr)
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import sys
import time

# ── RFC 7854 §4.1 message types ─────────────────────────────────────────────
MSG_ROUTE_MONITORING = 0
MSG_PEER_UP = 3
MSG_INITIATION = 4
MSG_TERMINATION = 5

BMP_VERSION = 3
BMP_COMMON_HEADER_LEN = 6

# ── RFC 7854 §4.3/§4.5 information TLV types ────────────────────────────────
TLV_STRING = 0
TLV_SYSDESCR = 1
TLV_SYSNAME = 2
TLV_TERM_REASON = 1  # Termination reuses type 1 as a 2-octet reason code

# ── RFC 4271 §4.1 BGP framing / §4.3 path attributes ────────────────────────
BGP_MARKER = b"\xff" * 16
BGP_HEADER_LEN = 19
BGP_MSG_OPEN = 1
BGP_MSG_UPDATE = 2

ATTR_FLAG_TRANSITIVE = 0x40  # well-known transitive
ATTR_ORIGIN = 1
ATTR_AS_PATH = 2
ATTR_NEXT_HOP = 3

ORIGIN_IGP = 0
AS_SEG_SEQUENCE = 2

# Bounds (§9): this is a client, but a client still refuses to build a frame
# that no receiver would accept.
MAX_FRAME_BYTES = 1 << 20  # the receiver's MaxMessageSize
MAX_ANNOUNCEMENTS = 64
CONNECT_TIMEOUT_S = 10.0
SEND_TIMEOUT_S = 10.0

# The default proof set. Deliberately: ONE prefix that is not a bogon, and TWO
# that are — one RFC 5737 documentation block, one RFC 1918 private block — so a
# passing run distinguishes "the screen matched everything" from "the screen
# matched the reserved blocks".
DEFAULT_ANNOUNCEMENTS = [
    ("8.8.8.0/24", [65001, 15169]),  # global unicast, delegated: NOT a bogon
    ("192.0.2.0/24", [65001]),  # RFC 5737 TEST-NET-1: bogon
    ("10.0.0.0/8", [65001]),  # RFC 1918 private-use: bogon
]


class SendError(Exception):
    """A frame could not be put on the wire. Always fatal, never retried here."""


# ── frame builders (bytes in, bytes out — no IO, no state) ──────────────────


def bmp_frame(msg_type: int, payload: bytes) -> bytes:
    """Wrap a payload in the RFC 7854 §4.1 common header (version, length, type).

    The length field counts the header itself, which is the field a receiver
    uses as its read budget — so it is computed, never assumed.
    """
    total = BMP_COMMON_HEADER_LEN + len(payload)
    if total > MAX_FRAME_BYTES:
        raise SendError(f"refusing to send a {total}-octet frame (ceiling {MAX_FRAME_BYTES})")
    return struct.pack("!BIB", BMP_VERSION, total, msg_type) + payload


def per_peer_header(
    peer_addr: str, peer_asn: int, bgp_id: str, flags: int = 0, timestamp: int | None = None
) -> bytes:
    """Build the 42-octet per-peer header (RFC 7854 §4.2).

    flags=0 means: IPv4 peer address (V clear), pre-policy Adj-RIB-In (L clear),
    4-octet AS_PATH encoding (A clear), Adj-RIB-In not -Out (O clear). The A bit
    is what tells the receiver how wide the AS_PATH ASNs are, so it and
    ``as_path_attr`` below must agree.
    """
    addr = ipaddress.ip_address(peer_addr)
    if addr.version == 4:
        addr_field = b"\x00" * 12 + addr.packed
    else:
        addr_field = addr.packed
        flags |= 0x80  # V: the address field is IPv6
    if timestamp is None:
        timestamp = int(time.time())
    return (
        struct.pack("!BB", 0, flags)  # peer type: global instance
        + b"\x00" * 8  # route distinguisher
        + addr_field
        + struct.pack("!I", peer_asn)
        + ipaddress.ip_address(bgp_id).packed
        + struct.pack("!II", timestamp, 0)
    )


def info_tlv(tlv_type: int, value: bytes) -> bytes:
    """One information TLV: 2-octet type, 2-octet length, value."""
    return struct.pack("!HH", tlv_type, len(value)) + value


def bgp_message(msg_type: int, body: bytes) -> bytes:
    """Wrap a BGP body in the 19-octet RFC 4271 §4.1 header."""
    return BGP_MARKER + struct.pack("!HB", BGP_HEADER_LEN + len(body), msg_type) + body


def bgp_open(asn: int, bgp_id: str, hold_time: int = 180) -> bytes:
    """A minimal, well-formed BGP OPEN (RFC 4271 §4.2), no optional parameters.

    The receiver skips the OPENs by their own length field rather than parsing
    them, but a malformed one would still desynchronize the Peer Up frame — so
    this builds a real OPEN, not padding.
    """
    if not 0 <= asn <= 0xFFFF:
        # The 2-octet MyAS field cannot carry a 4-byte ASN; a real speaker sends
        # AS_TRANS here plus a capability. We refuse rather than truncate.
        raise SendError(f"OPEN MyAS {asn} does not fit the 2-octet field; use an ASN <= 65535")
    return struct.pack("!BHH", 4, asn, hold_time) + ipaddress.ip_address(bgp_id).packed + b"\x00"


def path_attribute(code: int, value: bytes, flags: int = ATTR_FLAG_TRANSITIVE) -> bytes:
    """One non-extended-length path attribute (RFC 4271 §4.3)."""
    if len(value) > 0xFF:
        raise SendError(f"attribute {code} is {len(value)} octets; this builder emits short-form only")
    return struct.pack("!BBB", flags, code, len(value)) + value


def as_path_attr(as_path: list[int]) -> bytes:
    """AS_PATH as a single AS_SEQUENCE of 4-octet ASNs (matches the A flag clear)."""
    if not as_path:
        return path_attribute(ATTR_AS_PATH, b"")  # legal: an empty path (iBGP)
    if len(as_path) > 0xFF:
        raise SendError(f"AS_PATH of {len(as_path)} hops exceeds one segment's 255-ASN count")
    body = struct.pack("!BB", AS_SEG_SEQUENCE, len(as_path))
    for asn in as_path:
        if not 0 <= asn <= 0xFFFFFFFF:
            raise SendError(f"ASN {asn} is outside the 4-octet range")
        body += struct.pack("!I", asn)
    return path_attribute(ATTR_AS_PATH, body)


def nlri(prefix: str) -> bytes:
    """Encode one prefix in BGP NLRI form: length in BITS, then only the
    significant octets (RFC 4271 §4.3)."""
    net = ipaddress.ip_network(prefix, strict=True)
    bits = net.prefixlen
    octets = (bits + 7) // 8
    return struct.pack("!B", bits) + net.network_address.packed[:octets]


def bgp_update_body(withdrawn: bytes, attrs: bytes, announced: bytes) -> bytes:
    """Assemble a BGP UPDATE body (everything after the BGP header)."""
    return (
        struct.pack("!H", len(withdrawn))
        + withdrawn
        + struct.pack("!H", len(attrs))
        + attrs
        + announced
    )


def initiation_frame(sysname: str, sysdescr: str) -> bytes:
    payload = info_tlv(TLV_SYSDESCR, sysdescr.encode("utf-8"))
    payload += info_tlv(TLV_SYSNAME, sysname.encode("utf-8"))
    return bmp_frame(MSG_INITIATION, payload)


def peer_up_frame(
    peer_addr: str,
    peer_asn: int,
    local_addr: str,
    local_asn: int,
    peer_bgp_id: str,
    local_bgp_id: str,
    local_port: int = 179,
    remote_port: int = 45000,
) -> bytes:
    """Peer Up (RFC 7854 §4.4): the local address/ports plus both BGP OPENs
    (sent, then received)."""
    local = ipaddress.ip_address(local_addr)
    local_field = b"\x00" * 12 + local.packed if local.version == 4 else local.packed
    payload = per_peer_header(peer_addr, peer_asn, peer_bgp_id)
    payload += local_field
    payload += struct.pack("!HH", local_port, remote_port)
    payload += bgp_message(BGP_MSG_OPEN, bgp_open(local_asn, local_bgp_id))  # sent
    payload += bgp_message(BGP_MSG_OPEN, bgp_open(peer_asn, peer_bgp_id))  # received
    return bmp_frame(MSG_PEER_UP, payload)


def route_monitoring_frame(
    peer_addr: str, peer_asn: int, peer_bgp_id: str, prefix: str, as_path: list[int], next_hop: str
) -> bytes:
    """Route Monitoring (RFC 7854 §4.6) carrying one announcement."""
    attrs = path_attribute(ATTR_ORIGIN, struct.pack("!B", ORIGIN_IGP))
    attrs += as_path_attr(as_path)
    attrs += path_attribute(ATTR_NEXT_HOP, ipaddress.ip_address(next_hop).packed)
    body = bgp_update_body(b"", attrs, nlri(prefix))
    payload = per_peer_header(peer_addr, peer_asn, peer_bgp_id)
    payload += bgp_message(BGP_MSG_UPDATE, body)
    return bmp_frame(MSG_ROUTE_MONITORING, payload)


def termination_frame(reason: int = 0) -> bytes:
    """Termination (RFC 7854 §4.5). Reason 0 = administratively closed."""
    return bmp_frame(MSG_TERMINATION, info_tlv(TLV_TERM_REASON, struct.pack("!H", reason)))


# ── the session ─────────────────────────────────────────────────────────────


def send_frame(sock: socket.socket, label: str, frame: bytes, detail: str = "") -> None:
    """Write one frame, or fail loudly. sendall is used so a short write is an
    error rather than a silently truncated BMP message."""
    try:
        sock.sendall(frame)
    except OSError as exc:
        raise SendError(f"{label}: {exc}") from exc
    suffix = f"  {detail}" if detail else ""
    print(f"  -> {label:<18} {len(frame):>5} octets{suffix}", flush=True)


def parse_announcement(spec: str) -> tuple[str, list[int]]:
    """Parse ``PREFIX[,ASN[,ASN...]]`` into (prefix, as_path)."""
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if not parts:
        raise argparse.ArgumentTypeError("empty --announce value")
    prefix = parts[0]
    try:
        ipaddress.ip_network(prefix, strict=True)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{prefix!r} is not a valid network: {exc}") from exc
    path: list[int] = []
    for raw in parts[1:]:
        try:
            asn = int(raw)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{raw!r} is not an ASN") from exc
        if not 0 <= asn <= 0xFFFFFFFF:
            raise argparse.ArgumentTypeError(f"ASN {asn} is outside the 4-octet range")
        path.append(asn)
    return prefix, path


def run(args: argparse.Namespace) -> int:
    announcements = (
        [parse_announcement(a) for a in args.announce] if args.announce else DEFAULT_ANNOUNCEMENTS
    )
    if len(announcements) > MAX_ANNOUNCEMENTS:
        print(
            f"refusing {len(announcements)} announcements (ceiling {MAX_ANNOUNCEMENTS})",
            file=sys.stderr,
        )
        return 1

    print(f"BMP synthetic session -> {args.host}:{args.port}")
    print(
        f"  router sysName={args.sysname!r}  monitored peer {args.peer_ip} AS{args.peer_asn}"
        f"  local {args.local_ip} AS{args.local_asn}"
    )

    try:
        sock = socket.create_connection((args.host, args.port), timeout=CONNECT_TIMEOUT_S)
    except OSError as exc:
        print(f"connect to {args.host}:{args.port} failed: {exc}", file=sys.stderr)
        return 1

    with sock:
        sock.settimeout(SEND_TIMEOUT_S)
        try:
            send_frame(
                sock,
                "Initiation",
                initiation_frame(args.sysname, args.sysdescr),
                f"sysName={args.sysname!r}",
            )
            send_frame(
                sock,
                "Peer Up",
                peer_up_frame(
                    args.peer_ip,
                    args.peer_asn,
                    args.local_ip,
                    args.local_asn,
                    args.peer_ip,
                    args.local_ip,
                ),
                f"peer {args.peer_ip} AS{args.peer_asn} <- local {args.local_ip} AS{args.local_asn}",
            )
            for prefix, as_path in announcements:
                path_text = " ".join(str(a) for a in as_path) or "(empty)"
                send_frame(
                    sock,
                    "Route Monitoring",
                    route_monitoring_frame(
                        args.peer_ip, args.peer_asn, args.peer_ip, prefix, as_path, args.next_hop
                    ),
                    f"announce {prefix}  origin=igp  as_path=[{path_text}]  next_hop={args.next_hop}",
                )

            if args.hold > 0:
                print(f"  .. holding the session open for {args.hold}s", flush=True)
                time.sleep(args.hold)

            send_frame(
                sock, "Termination", termination_frame(0), "reason=0 (administratively closed)"
            )
        except SendError as exc:
            # A refused session shows up here: the receiver disconnects an
            # unattributable source, so the very first write fails.
            print(f"send failed: {exc}", file=sys.stderr)
            print(
                "hint: the receiver disconnects a source address that matches no device row — "
                "check the receiver's log for 'source address is not a known device'",
                file=sys.stderr,
            )
            return 1

    print("session closed cleanly")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Send a synthetic RFC 7854 BMP session (Initiation, Peer Up, "
        "Route Monitoring, Termination) to a BMP receiver.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1", help="BMP receiver host")
    ap.add_argument("--port", type=int, default=11019, help="BMP receiver TCP port")
    ap.add_argument("--sysname", default="bmp-proof", help="Initiation sysName TLV")
    ap.add_argument(
        "--sysdescr",
        default="synthetic BMP sender (scripts/bmp-synthetic-session.py)",
        help="Initiation sysDescr TLV",
    )
    ap.add_argument("--peer-ip", default="192.0.2.1", help="monitored BGP peer address")
    ap.add_argument("--peer-asn", type=int, default=65001, help="monitored BGP peer ASN")
    ap.add_argument("--local-ip", default="192.0.2.2", help="local (router-side) address")
    ap.add_argument("--local-asn", type=int, default=65000, help="local (router-side) ASN")
    ap.add_argument("--next-hop", default="192.0.2.1", help="NEXT_HOP for every announcement")
    ap.add_argument(
        "--announce",
        action="append",
        metavar="PREFIX[,ASN...]",
        help="announcement to send (repeatable). Omit for the default proof set: "
        + ", ".join(p for p, _ in DEFAULT_ANNOUNCEMENTS),
    )
    ap.add_argument(
        "--hold", type=float, default=5.0, help="seconds to hold the session open before Termination"
    )
    args = ap.parse_args(argv)

    if not 1 <= args.port <= 65535:
        ap.error(f"--port {args.port} is not a TCP port")
    if args.hold < 0 or args.hold > 3600:
        ap.error("--hold must be between 0 and 3600 seconds")
    for name, value in (("--peer-ip", args.peer_ip), ("--local-ip", args.local_ip), ("--next-hop", args.next_hop)):
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            ap.error(f"{name}: {exc}")
    for name, value in (("--peer-asn", args.peer_asn), ("--local-asn", args.local_asn)):
        if not 0 <= value <= 0xFFFF:
            ap.error(f"{name} must fit the BGP OPEN 2-octet MyAS field (0..65535)")

    try:
        return run(args)
    except SendError as exc:
        print(f"frame construction failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
