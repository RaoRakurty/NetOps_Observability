#!/usr/bin/env python3
"""flowgen — multi-protocol flow telemetry generator for the NetOps stack.

Emits realistic **NetFlow v5**, **IPFIX**, and **sFlow v5** datagrams to goflow2's
listeners so the Flows tab shows live NetFlow/IPFIX/sFlow data. Pure stdlib
(socket/struct/random) — no third-party deps, matching the project's constraints.

The clos-multivendor fabric is virtual (cEOS/SR Linux have no ASIC), so its sFlow
only ever produces counter-samples, never per-flow records — goflow2 can't turn
those into rows. This generator stands in for real exporters so the analytics
pipeline (goflow2 -> vector -> redpanda -> vector-router -> ClickHouse) has data.

Run on the stack host (sends to the published goflow2 ports), or as a container
on the stack's docker network (point --host at goflow2). Defaults assume the
goflow2 ports are reachable on 127.0.0.1.

  python3 flowgen.py --host 127.0.0.1 --eps 40

goflow2 tags the records by wire format: NETFLOW_V5 / IPFIX / SFLOW_5. sFlow
records carry a per-device agent address (172.40.40.x) so they attribute to the
fabric devices; NetFlow/IPFIX sampler_address is the sender IP unless you front
this with source spoofing (out of scope — the UI panels group by flow 5-tuple).
"""
import argparse
import os
import random
import socket
import struct
import time

# Fabric-ish device agent addresses (used as sFlow agent / exporter identity).
DEVICE_AGENTS = [
    "172.40.40.11", "172.40.40.12",            # spine1/2
    "172.40.40.21", "172.40.40.22",            # leaf1/2
    "172.40.40.23", "172.40.40.24",            # leaf3/4
    "172.40.40.31", "172.40.40.32",            # wan-r1/2
    "172.40.40.51", "172.40.40.52",            # lan-sw1/2
    "172.40.40.41",                            # dmz-fw
]

# Subnets we synthesize conversations between (internal + a few "internet" peers).
INTERNAL_NETS = ["10.10.10.", "172.16.100.", "172.40.40.", "10.20.10.", "10.20.20."]
EXTERNAL_HOSTS = [
    "8.8.8.8", "1.1.1.1", "140.82.121.4", "151.101.1.140",
    "52.94.236.248", "13.107.42.14", "199.232.0.0", "208.67.222.222",
]

# proto -> (number, common dst ports)
PROTOS = [
    (6, [22, 80, 443, 3389, 8080, 5432, 6379, 9092]),   # TCP
    (17, [53, 123, 514, 161, 6343, 4789, 500]),          # UDP
    (1, [0]),                                            # ICMP
]


def rand_ip(net=None):
    if net is None:
        if random.random() < 0.35:
            return random.choice(EXTERNAL_HOSTS)
        net = random.choice(INTERNAL_NETS)
    return net + str(random.randint(2, 250))


def gen_flow():
    """One synthetic conversation as a dict of normalized fields."""
    proto, ports = random.choice(PROTOS)
    src = rand_ip(random.choice(INTERNAL_NETS))
    dst = rand_ip()
    sport = random.randint(1024, 65535) if proto != 1 else 0
    dport = random.choice(ports) if proto != 1 else 0
    pkts = random.randint(1, 8000)
    # average packet size by protocol, with jitter
    avg = {6: 800, 17: 300, 1: 84}[proto]
    octets = pkts * random.randint(int(avg * 0.5), int(avg * 1.5))
    return {
        "src": src, "dst": dst, "sport": sport, "dport": dport,
        "proto": proto, "pkts": pkts, "octets": octets,
        "in_if": random.randint(1, 48), "out_if": random.randint(1, 48),
        "src_as": random.choice([0, 64512, 65001, 13335, 15169, 16509]),
        "dst_as": random.choice([0, 64512, 65002, 13335, 15169, 32934]),
        "tcp_flags": random.choice([0x02, 0x10, 0x18, 0x14]) if proto == 6 else 0,
    }


# --------------------------------------------------------------------------- #
# NetFlow v5
# --------------------------------------------------------------------------- #
def netflow_v5_packet(flows, uptime_ms, seq):
    now = time.time()
    secs = int(now)
    nsecs = int((now - secs) * 1e9)
    hdr = struct.pack("!HHIIIIBBH", 5, len(flows), uptime_ms & 0xFFFFFFFF,
                      secs, nsecs, seq, 0, 0, 0)
    body = b""
    for f in flows:
        first = (uptime_ms - random.randint(1000, 60000)) & 0xFFFFFFFF
        last = uptime_ms & 0xFFFFFFFF
        body += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            ip2int(f["src"]), ip2int(f["dst"]), 0,
            f["in_if"], f["out_if"], f["pkts"], f["octets"],
            first, last, f["sport"], f["dport"],
            0, f["tcp_flags"], f["proto"], 0,
            f["src_as"], f["dst_as"], 24, 24, 0,
        )
    return hdr + body


# --------------------------------------------------------------------------- #
# IPFIX (RFC 7011) — one IPv4 template (id 256) + data records
# --------------------------------------------------------------------------- #
IPFIX_TEMPLATE_ID = 256
# (IE id, length) — sourceIPv4Address, destinationIPv4Address, sourceTransportPort,
# destinationTransportPort, protocolIdentifier, octetDeltaCount, packetDeltaCount,
# ingressInterface, egressInterface, bgpSourceAsNumber, bgpDestinationAsNumber
IPFIX_FIELDS = [
    (8, 4), (12, 4), (7, 2), (11, 2), (4, 1),
    (1, 8), (2, 8), (10, 4), (14, 4), (16, 4), (17, 4),
]


def ipfix_template_set():
    fields = b"".join(struct.pack("!HH", fid, flen) for fid, flen in IPFIX_FIELDS)
    # template record: template_id(2), field_count(2), fields...
    tmpl = struct.pack("!HH", IPFIX_TEMPLATE_ID, len(IPFIX_FIELDS)) + fields
    set_len = 4 + len(tmpl)
    return struct.pack("!HH", 2, set_len) + tmpl


def ipfix_data_set(flows):
    body = b""
    for f in flows:
        body += struct.pack(
            "!IIHHB QQ II",
            ip2int(f["src"]), ip2int(f["dst"]), f["sport"], f["dport"],
            f["proto"], f["octets"], f["pkts"], f["in_if"], f["out_if"],
        )
        body += struct.pack("!II", f["src_as"], f["dst_as"])
    set_len = 4 + len(body)
    return struct.pack("!HH", IPFIX_TEMPLATE_ID, set_len) + body


def ipfix_packet(flows, seq, domain, with_template):
    sets = b""
    if with_template:
        sets += ipfix_template_set()
    sets += ipfix_data_set(flows)
    length = 16 + len(sets)
    hdr = struct.pack("!HHIII", 10, length, int(time.time()), seq, domain)
    return hdr + sets


# --------------------------------------------------------------------------- #
# sFlow v5 — flow sample carrying a raw ethernet/IP/L4 header for goflow2
# --------------------------------------------------------------------------- #
def _l4_header(f):
    if f["proto"] == 6:   # TCP
        return struct.pack("!HHIIBBHHH", f["sport"], f["dport"], 0, 0,
                           0x50, f["tcp_flags"], 65535, 0, 0)
    if f["proto"] == 17:  # UDP
        return struct.pack("!HHHH", f["sport"], f["dport"], 8, 0)
    return struct.pack("!BBHI", 8, 0, 0, 0)  # ICMP echo-ish


def _raw_frame(f):
    l4 = _l4_header(f)
    ip_total = 20 + len(l4)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total, random.randint(0, 65535),
                     0x4000, 64, f["proto"], 0,
                     socket.inet_aton(f["src"]), socket.inet_aton(f["dst"]))
    eth = struct.pack("!6s6sH",
                      bytes(random.randint(0, 255) for _ in range(6)),
                      bytes(random.randint(0, 255) for _ in range(6)),
                      0x0800)
    return eth + ip + l4


def _sflow_flow_record(f):
    frame = _raw_frame(f)
    sampled_len = max(len(frame), min(f["octets"], 1514))
    header = struct.pack("!IIII", 1, sampled_len, 0, len(frame))  # proto=ethernet
    padded = frame + b"\x00" * ((4 - len(frame) % 4) % 4)
    record_data = header + padded
    return struct.pack("!II", 1, len(record_data)) + record_data  # type=1 raw header


def sflow_packet(agent, flows, seq):
    samples = b""
    n = 0
    for f in flows:
        rec = _sflow_flow_record(f)
        fs = struct.pack("!IIIIIIII",
                         seq + n, 0, random.choice([1000, 4096, 8192]),
                         random.randint(1, 1 << 20), 0,
                         f["in_if"], f["out_if"], 1) + rec
        samples += struct.pack("!II", 1, len(fs)) + fs  # sample_type=1 flow_sample
        n += 1
    # sFlow v5 datagram header: version, agent addr-type(1=IPv4), agent(4),
    # sub-agent-id, sequence, uptime(ms), num_samples
    hdr = struct.pack("!II4sIIII", 5, 1, socket.inet_aton(agent),
                      0, seq, int(time.time() * 1000) & 0xFFFFFFFF, n)
    return hdr + samples


# --------------------------------------------------------------------------- #
def ip2int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def main():
    ap = argparse.ArgumentParser(description="Multi-protocol flow generator")
    ap.add_argument("--host", default=os.environ.get("FLOWGEN_HOST", "127.0.0.1"),
                    help="goflow2 host (default 127.0.0.1)")
    ap.add_argument("--netflow-port", type=int, default=2055)
    ap.add_argument("--ipfix-port", type=int, default=4739)
    ap.add_argument("--sflow-port", type=int, default=6343)
    ap.add_argument("--eps", type=float, default=float(os.environ.get("FLOWGEN_EPS", "40")),
                    help="approx flow records per second across all protocols")
    ap.add_argument("--once", action="store_true", help="send one batch and exit")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    uptime0 = time.time()
    nf_seq = ipfix_seq = sf_seq = 0
    tick = 0
    batch = max(1, int(args.eps))  # flows per ~1s tick

    print(f"flowgen -> {args.host} nf:{args.netflow_port} ipfix:{args.ipfix_port} "
          f"sflow:{args.sflow_port} ~{args.eps} eps", flush=True)
    while True:
        flows = [gen_flow() for _ in range(batch)]
        # split: ~40% netflow v5, ~30% ipfix, ~30% sflow
        nf = flows[: int(batch * 0.4)]
        ix = flows[int(batch * 0.4): int(batch * 0.7)]
        sf = flows[int(batch * 0.7):]
        uptime_ms = int((time.time() - uptime0) * 1000)

        if nf:
            try:
                sock.sendto(netflow_v5_packet(nf, uptime_ms, nf_seq),
                            (args.host, args.netflow_port))
                nf_seq += len(nf)
            except OSError as e:
                print("netflow send error:", e, flush=True)
        if ix:
            try:
                sock.sendto(ipfix_packet(ix, ipfix_seq, 1, with_template=(tick % 20 == 0)),
                            (args.host, args.ipfix_port))
                ipfix_seq += len(ix)
            except OSError as e:
                print("ipfix send error:", e, flush=True)
        if sf:
            # group sflow by a random device agent for per-device attribution
            for agent in random.sample(DEVICE_AGENTS, k=min(3, len(DEVICE_AGENTS))):
                part = [f for f in sf if random.random() < 0.4] or sf[:2]
                try:
                    sock.sendto(sflow_packet(agent, part, sf_seq),
                                (args.host, args.sflow_port))
                    sf_seq += len(part)
                except OSError as e:
                    print("sflow send error:", e, flush=True)

        tick += 1
        if args.once:
            break
        time.sleep(1.0)


if __name__ == "__main__":
    main()
