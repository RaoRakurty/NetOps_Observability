"""Fidelity-wave wire encoders: every encoder round-trips through its own
decoder (the trap decoder mirrors the Go receiver's TLV walk, so the trap
test proves the receiver-side shape), and the payload builders emit exactly
the varbinds `src/correlation/producers.py` classifies on."""
import pytest
import wire
from emitters import (
    TRAP_NAME_TO_OID,
    UdpLanes,
    build_flow_packets,
    build_trap_bytes,
    flows_from_seed,
)

# ── SNMPv2c trap BER ────────────────────────────────────────────────────────

def test_trap_linkdown_round_trip():
    item = {"trap": "linkDown", "device": "edge-a1", "ifindex": 3,
            "ifname": "Ethernet3", "ifdescr": "Ethernet3"}
    pkt = build_trap_bytes(item, "twx-r1-", "public", 4242)
    d = wire.decode_trap_v2c(pkt)
    assert d["community"] == "public"
    assert d["trap_oid"] == wire.TRAP_LINKDOWN
    assert d["uptime_ticks"] == 4242
    by_oid = {vb["oid"]: vb["value"] for vb in d["varbinds"]}
    # the exact entity varbinds producers._trap_interface reads
    assert by_oid[f"{wire.VB_IFINDEX}.3"] == 3
    assert by_oid[f"{wire.VB_IFNAME}.3"] == "Ethernet3"
    assert by_oid[f"{wire.VB_IFDESCR}.3"] == "Ethernet3"
    # sysName rescue varbind carries the run-prefixed device name
    assert by_oid[wire.SYSNAME_OID] == "twx-r1-edge-a1"
    # SNMPv2 mandatory bindings come FIRST (the Go receiver checks order)
    assert d["varbinds"][0]["oid"] == wire.SYSUPTIME_OID
    assert d["varbinds"][1]["oid"] == wire.SNMP_TRAP_OID


def test_trap_bgp_backward_carries_peer_address():
    item = {"trap": "bgpBackwardTransition", "device": "br-b1",
            "peer_ip": "203.0.113.1"}
    pkt = build_trap_bytes(item, "twx-r1-", "twincomm", 1)
    d = wire.decode_trap_v2c(pkt)
    assert d["trap_oid"] == wire.TRAP_BGP_BACKWARD
    assert d["community"] == "twincomm"
    by_oid = {vb["oid"]: vb["value"] for vb in d["varbinds"]}
    assert by_oid[f"{wire.VB_BGP_PEER_ADDR}.203.0.113.1"] == "203.0.113.1"


def test_trap_coldstart_minimal_and_all_names_mapped():
    pkt = build_trap_bytes({"trap": "coldStart", "device": "d"},
                           "twx-r1-", "public", 0)
    assert wire.decode_trap_v2c(pkt)["trap_oid"] == wire.TRAP_COLDSTART
    for name, oid in TRAP_NAME_TO_OID.items():
        p = build_trap_bytes({"trap": name, "device": "d", "ifindex": 1,
                              "peer_ip": "192.0.2.1"}, "x-", "c", 9)
        assert wire.decode_trap_v2c(p)["trap_oid"] == oid


def test_trap_unknown_name_refused():
    with pytest.raises(ValueError, match="unknown trap"):
        build_trap_bytes({"trap": "sunspots", "device": "d"}, "x-", "c", 0)


def test_ber_long_form_length():
    # >127-byte community forces the long-form length path both ways
    pkt = build_trap_bytes({"trap": "coldStart", "device": "d" * 100},
                           "x-", "c" * 200, 0)
    assert wire.decode_trap_v2c(pkt)["community"] == "c" * 200


# ── NetFlow v5 ──────────────────────────────────────────────────────────────

def test_netflow_v5_round_trip():
    flows = flows_from_seed("seed-a", 7)
    pkt = wire.encode_netflow_v5(flows, uptime_ms=99000, seq=1234)
    d = wire.decode_netflow_v5(pkt)
    assert d["seq"] == 1234 and len(d["flows"]) == 7
    for sent, got in zip(flows, d["flows"]):
        for k in ("src", "dst", "sport", "dport", "proto", "pkts",
                  "octets", "in_if", "out_if", "tcp_flags"):
            assert got[k] == sent[k], k


def test_netflow_v5_record_cap():
    with pytest.raises(wire.WireError):
        wire.encode_netflow_v5(flows_from_seed("s", 31), 0, 0)


# ── IPFIX ───────────────────────────────────────────────────────────────────

def test_ipfix_round_trip_with_template():
    flows = flows_from_seed("seed-b", 5)
    pkt = wire.encode_ipfix(flows, seq=77, domain=3, with_template=True)
    d = wire.decode_ipfix(pkt)
    assert d["domain"] == 3 and d["seq"] == 77
    assert d["template"] == wire.IPFIX_FIELDS
    assert len(d["flows"]) == 5
    for sent, got in zip(flows, d["flows"]):
        for k in ("src", "dst", "sport", "dport", "proto", "pkts", "octets"):
            assert got[k] == sent[k], k


# ── flow item expansion + exporter chunking ────────────────────────────────

def test_flows_from_seed_is_deterministic():
    assert flows_from_seed("k", 10) == flows_from_seed("k", 10)
    assert flows_from_seed("k", 10) != flows_from_seed("k2", 10)


def test_build_flow_packets_chunks_and_counts():
    item = {"flow_seed": "s", "count": 65}
    pkts, n = build_flow_packets(item, "netflow5", seq=0, domain=1,
                                 uptime_ms=1000)
    assert n == 65 and len(pkts) == 3            # 30 + 30 + 5
    total = sum(len(wire.decode_netflow_v5(p)["flows"]) for p in pkts)
    assert total == 65
    # sequence numbers advance per record across packets
    assert wire.decode_netflow_v5(pkts[1])["seq"] == 30
    pkts_ix, n_ix = build_flow_packets(item, "ipfix", seq=0, domain=1,
                                       uptime_ms=1000)
    assert n_ix == 65 and len(pkts_ix) == 4      # 20×3 + 5, template inline
    assert all(wire.decode_ipfix(p)["template"] for p in pkts_ix)


def test_udp_lanes_skips_flows_without_source_ip():
    lanes = UdpLanes(trap_target=("127.0.0.1", 162), flow_host=None,
                     community="public")
    trap_item = {"lane": "trap", "trap": "coldStart", "device": "d",
                 "tenant": "t"}
    flow_item = {"lane": "flows", "device": "d", "tenant": "t",
                 "count": 4, "flow_seed": "s"}
    dgs, n = lanes.build_item(trap_item, "twx-x-")
    assert n == 1 and dgs[0][1:3] == ("127.0.0.1", 162)
    assert lanes.build_item(flow_item, "twx-x-") is None   # loud-skip path


def test_udp_lanes_source_ip_flow_delivery():
    lanes = UdpLanes(flow_host="198.19.255.9", flow_protocol="netflow5",
                     src_ips={"edge-a1": "198.19.0.1"})
    item = {"lane": "flows", "device": "edge-a1", "tenant": "t",
            "count": 3, "flow_seed": "s"}
    dgs, n = lanes.build_item(item, "twx-x-")
    assert n == 3 and len(dgs) == 1
    src, host, port, payload = dgs[0]
    assert (src, host, port) == ("198.19.0.1", "198.19.255.9", 2055)
    assert wire.decode_netflow_v5(payload)["flows"]
