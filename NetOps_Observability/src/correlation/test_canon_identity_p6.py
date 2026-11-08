# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P6 PR-D — canon.py + the EntityResolver extensions (NOT wired).

Plan: docs/design/P6_CANONICALISATION_PLAN_2026-11-07.md. Tracker 374 D1/D2/D4/D5.
The tenant-isolation corpus is in test_identity_canon_isolation.py.

What is pinned here:
  * per-vendor interface vectors (Cisco IOS/IOS-XE, IOS-XR, NX-OS, Junos, Nokia
    SR OS + SR Linux, Arista, SONiC, vEdge, Huawei/Comware, HP ProCurve);
  * DRIFT: the Go `ifaceAlias` table and `canonIface` algorithm
    (src/backend/topology_view.go) — parsed from the source — are a strict subset
    of the Python port, value for value and output for output;
  * the resolver's collision drop, digit-only rule, generic-hostname guard and
    management-IP hostname (the lab's cEDGE-81 logs under 192.168.222.106);
  * canonicalize: D1/D2/D4/D5 rewrites against the RECORDED E7 fixtures, outcome
    taxonomy, native_id / signal_id untouched, attrs a new dict, idempotence,
    row-order independence, and no exception on hostile or oversized input.
"""
from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import string
from dataclasses import replace
from datetime import datetime, timezone

import pytest

import canon as C
import producers as P
from canon import (
    ABSTAIN_AMBIGUOUS,
    ABSTAIN_CONFLICT,
    ABSTAIN_GENERIC,
    ABSTAIN_UNKNOWN,
    CANON_ATTR,
    EXTRA_IFACE_ALIAS,
    GO_IFACE_ALIAS,
    IFACE_ABSTAIN,
    IFACE_ALIAS,
    OUTCOMES,
    REWRITTEN,
    UNCHANGED,
    canon_iface_key,
    canonical_peer,
    canonicalize,
    canonicalize_detailed,
)
from controller_events import controller_event_to_signal
from engine import build_nodes
from entity_resolver import (
    EMPTY_RESOLVER,
    GENERIC_HOSTNAMES,
    EntityResolver,
    _unique_map,
    identity_resolver_for,
)
from signals import (
    DeadLetter,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

HERE = os.path.dirname(os.path.abspath(__file__))
GO_TOPOLOGY_VIEW = os.path.join(HERE, "..", "backend", "topology_view.go")
GOLDEN_PEER = os.path.join(HERE, "..", "backend", "nms", "testdata", "source_parity",
                           "vmanage_20.6.controller_events_peer_in_inventory.json")
TRAPS = os.path.join(HERE, "fixtures", "source_parity", "traps_cedge81_bgp_20261101.jsonl")
SYSLOG = os.path.join(HERE, "fixtures", "source_parity", "syslog_cedge81_20261101.jsonl")

TENANT = "t_lab"
DEVICE = "cedge-81-11060ae2"
CEDGE81_MGMT = "192.168.222.106"
PEER = "192.168.200.34"
RFC_BACKWARD = "1.3.6.1.2.1.15.7.2"
INGEST = datetime(2026, 11, 1, 17, 5, tzinfo=timezone.utc)
TS = datetime(2026, 11, 1, 17, 0, 1, tzinfo=timezone.utc)

M = C.IFINDEX_MARKER_PREFIX
A = IFACE_ABSTAIN

# (vendor, raw name, vendor_hint, expected key)
IFACE_VECTORS: list[tuple[str, str, str | None, str]] = [
    # Cisco IOS / IOS-XE (long ↔ short CLI spellings meet)
    ("cisco-ios", "GigabitEthernet0/1", None, "gi0/1"),
    ("cisco-ios", "Gi0/1", None, "gi0/1"),
    ("cisco-ios", "GigabitEthernet1", None, "gi1"),
    ("cisco-ios", "GigabitEthernet0/0/0.100", None, "gi0/0/0.100"),
    ("cisco-ios", "TenGigabitEthernet1/0/1", None, "te1/0/1"),
    ("cisco-ios", "Te1/0/1", None, "te1/0/1"),
    ("cisco-ios", "TwoGigabitEthernet1/0/1", None, "tw1/0/1"),
    ("cisco-ios", "Tw1/0/1", None, "tw1/0/1"),
    ("cisco-ios", "FiveGigabitEthernet1/0/1", None, "fi1/0/1"),
    ("cisco-ios", "FiftyGigabitEthernet1/0/1", None, "fi1/0/1"),
    ("cisco-ios", "FiftyGigE1/0/1", None, "fi1/0/1"),
    ("cisco-ios", "TwentyFiveGigE1/0/1", None, "twe1/0/1"),
    ("cisco-ios", "Twe1/0/1", None, "twe1/0/1"),
    ("cisco-ios", "FortyGigabitEthernet1/1/1", None, "fo1/1/1"),
    ("cisco-ios", "HundredGigE1/0/49", None, "hu1/0/49"),
    ("cisco-ios", "FastEthernet0/1", None, "fa0/1"),
    ("cisco-ios", "Fa0/1", None, "fa0/1"),
    ("cisco-ios", "AppGigabitEthernet1/0/1", None, "ap1/0/1"),
    ("cisco-ios", "Ap1/0/1", None, "ap1/0/1"),
    ("cisco-ios", "Port-channel10", None, "po10"),
    ("cisco-ios", "Po10", None, "po10"),
    ("cisco-ios", "Loopback0", None, "lo0"),
    ("cisco-ios", "Lo0", None, "lo0"),
    ("cisco-ios", "Tunnel100", None, "tu100"),
    ("cisco-ios", "Tu100", None, "tu100"),
    ("cisco-ios", "Vlan10", None, "vl10"),
    ("cisco-ios", "Vl10", None, "vl10"),
    ("cisco-ios", "Serial0/0/0:1", None, "se0/0/0:1"),
    ("cisco-ios", "Null0", None, "nu0"),
    ("cisco-ios", "GigabitEthernet 0/1", None, "gi0/1"),
    # Cisco IOS-XR
    ("cisco-xr", "MgmtEth0/RP0/CPU0/0", None, "ma0/rp0/cpu0/0"),
    ("cisco-xr", "Mg0/RP0/CPU0/0", None, "ma0/rp0/cpu0/0"),
    ("cisco-xr", "TenGigE0/0/0/0", None, "te0/0/0/0"),
    ("cisco-xr", "HundredGigE0/0/0/1", None, "hu0/0/0/1"),
    ("cisco-xr", "Hu0/0/0/1", None, "hu0/0/0/1"),
    ("cisco-xr", "FourHundredGigE0/0/0/2", None, "fh0/0/0/2"),
    ("cisco-xr", "FH0/0/0/2", None, "fh0/0/0/2"),
    ("cisco-xr", "TwoHundredGigE0/0/0/3", None, "th0/0/0/3"),
    ("cisco-xr", "Th0/0/0/3", None, "th0/0/0/3"),
    ("cisco-xr", "TwentyFiveGigE0/0/0/4", None, "twe0/0/0/4"),
    ("cisco-xr", "TF0/0/0/4", None, "twe0/0/0/4"),
    ("cisco-xr", "Bundle-Ether1", None, "be1"),
    ("cisco-xr", "BE1", None, "be1"),
    ("cisco-xr", "Bundle-Ether1.100", None, "be1.100"),
    # Cisco NX-OS
    ("cisco-nxos", "Ethernet1/1", None, "et1/1"),
    ("cisco-nxos", "Eth1/1", None, "et1/1"),
    ("cisco-nxos", "port-channel10", None, "po10"),
    ("cisco-nxos", "mgmt0", None, "ma0"),
    ("cisco-nxos", "Vlan100", None, "vl100"),
    # Juniper Junos (logical units are kept: ge-0/0/0.0 is not ge-0/0/0)
    ("juniper", "ge-0/0/0", None, "ge0/0/0"),
    ("juniper", "ge-0/0/0.0", None, "ge0/0/0.0"),
    ("juniper", "xe-1/2/3.100", None, "xe1/2/3.100"),
    ("juniper", "et-0/0/1", None, "et0/0/1"),
    ("juniper", "ae0.0", None, "ae0.0"),
    ("juniper", "lo0.0", None, "lo0.0"),
    ("juniper", "em0", None, "em0"),
    ("juniper", "fxp0", None, "fxp0"),
    # Nokia SR OS (ifDescr → first comma-separated field) and SR Linux
    ("nokia-sros", '1/1/1, 10/100/Gig Ethernet SFP, "to-core"', None, "1/1/1"),
    ("nokia-sros", "1/1/1", None, "1/1/1"),
    ("nokia-sros", "1/1/c1/1, 100-Gig Ethernet", None, "1/1/c1/1"),
    ("nokia-sros", "lag-1", None, "lag1"),
    ("nokia-sros", "system", None, "system"),
    ("nokia-srl", "ethernet-1/1", None, "et1/1"),
    ("nokia-srl", "ethernet-1/1.0", None, "et1/1.0"),
    ("nokia-srl", "mgmt0", None, "ma0"),
    ("nokia-srl", "lo0", None, "lo0"),
    # Arista EOS
    ("arista", "Ethernet1", None, "et1"),
    ("arista", "Et1", None, "et1"),
    ("arista", "Ethernet49/1", None, "et49/1"),
    ("arista", "Management1", None, "ma1"),
    ("arista", "Ma1", None, "ma1"),
    ("arista", "Port-Channel10", None, "po10"),
    ("arista", "Vxlan1", None, "vx1"),
    ("arista", "Vx1", None, "vx1"),
    # SONiC: default names key; alias-mode names cannot be solved by string
    ("sonic", "Ethernet0", "sonic", "et0"),
    ("sonic", "Ethernet124", "sonic", "et124"),
    ("sonic", "Ethernet0.10", "sonic", "et0.10"),
    ("sonic", "PortChannel0001", "sonic", "po0001"),
    ("sonic", "Loopback0", "sonic", "lo0"),
    ("sonic", "Vlan100", "sonic", "vl100"),
    ("sonic", "eth0", "sonic", "et0"),
    ("sonic", "etp1", "sonic", A),
    ("sonic", "fortyGigE0/0", "sonic", A),
    ("sonic", "Eth1/1", "SONiC", A),
    # Cisco SD-WAN vEdge (Viptela OS)
    ("vedge", "ge0/0", None, "ge0/0"),
    ("vedge", "ge0/1.10", None, "ge0/1.10"),
    ("vedge", "loopback0", None, "lo0"),
    ("vedge", "eth0", None, "et0"),
    # Huawei VRP / HPE Comware
    ("huawei", "XGigabitEthernet0/0/1", None, "xge0/0/1"),
    ("huawei", "XGE0/0/1", None, "xge0/0/1"),
    ("huawei", "Eth-Trunk1", None, "ethtrunk1"),
    ("comware", "Bridge-Aggregation1", None, "bagg1"),
    ("comware", "BAGG1", None, "bagg1"),
    # HP ProCurve: digit-only names are ifIndex candidates, never keys alone
    ("procurve", "1", None, M + "1"),
    ("procurve", "48", None, M + "48"),
    ("procurve", "Trk1", None, "trk1"),
    # never a key
    ("abstain", "unknown", None, A),
    ("abstain", "Unknown", None, A),
    ("abstain", "2001:db8::1", None, A),
    ("abstain", "10.0.0.1", None, A),
    ("abstain", "Gi0/1" + chr(0), None, A),
    ("abstain", "G" + chr(0xED) + "gabitEthernet1", None, A),
    ("abstain", "Gi" + "0" * 200, None, A),
    ("abstain", "---", None, A),
    ("abstain", "12345678901", None, A),
    ("abstain", "", None, ""),
    ("abstain", "   ", None, ""),
]


@pytest.mark.parametrize("vendor,name,hint,want", IFACE_VECTORS,
                         ids=[f"{v}:{n[:24]!r}" for v, n, _, _ in IFACE_VECTORS])
def test_interface_vectors(vendor: str, name: str, hint: str | None, want: str) -> None:
    assert canon_iface_key(name, hint) == want


def test_vector_coverage_per_vendor() -> None:
    """≥ 40 cases across the vendors the owner rule names (multi-vendor-fixes)."""
    per: dict[str, int] = {}
    for vendor, *_ in IFACE_VECTORS:
        per[vendor.split("-")[0]] = per.get(vendor.split("-")[0], 0) + 1
    assert sum(per.values()) >= 40
    for v in ("cisco", "juniper", "nokia", "arista", "sonic", "vedge", "procurve"):
        assert per.get(v, 0) >= 3, (v, per)


def test_keys_are_fixed_points() -> None:
    """Idempotence of the key itself: canon(canon(x)) == canon(x), markers too."""
    for _, name, hint, _ in IFACE_VECTORS:
        k = canon_iface_key(name, hint)
        assert canon_iface_key(k, hint) == k, (name, k)


def test_alias_table_is_closed() -> None:
    """No canonical value is itself a key that maps elsewhere (which would break
    the fixed point), and every key is pure a-z (the prefix alphabet)."""
    for k, v in IFACE_ALIAS.items():
        assert re.fullmatch(r"[a-z]+", k) and re.fullmatch(r"[a-z]+", v), (k, v)
        assert IFACE_ALIAS.get(v, v) == v, (k, v)


# ── DRIFT: the Go source is the authority for the entries it has ─────────────

def _go_source() -> str:
    with open(GO_TOPOLOGY_VIEW, encoding="utf-8") as fh:
        return fh.read()


def _go_alias_table() -> dict[str, str]:
    src = _go_source()
    m = re.search(r"var ifaceAlias = map\[string\]string\{(.*?)\n\}", src, re.DOTALL)
    assert m, "ifaceAlias not found in topology_view.go — the drift test lost its anchor"
    body = re.sub(r"//[^\n]*", "", m.group(1))
    pairs = re.findall(r'"([^"]*)"\s*:\s*"([^"]*)"', body)
    # every non-blank line is one entry: a shape the regex did not read fails loudly
    lines = [ln for ln in body.splitlines() if ln.strip()]
    assert len(pairs) == len(lines), "unparsed line in the Go ifaceAlias table"
    return dict(pairs)


def _go_canon_iface(s: str, table: dict[str, str]) -> str:
    """Line-for-line reference of Go canonIface over the PARSED Go table."""
    s = s.strip().lower()
    if s == "":
        return ""
    d = next((i for i, r in enumerate(s) if "0" <= r <= "9"), -1)
    prefix, rest = (s, "") if d < 0 else (s[:d], s[d:])
    prefix = "".join(r for r in prefix if "a" <= r <= "z")
    return table.get(prefix, prefix) + rest


def test_go_alias_table_is_mirrored_verbatim() -> None:
    go = _go_alias_table()
    assert len(go) >= 20
    assert dict(GO_IFACE_ALIAS) == go, "Go ifaceAlias changed: mirror it in canon.GO_IFACE_ALIAS"


def test_python_table_is_a_superset_with_equal_values() -> None:
    go = _go_alias_table()
    for k, v in go.items():
        assert IFACE_ALIAS.get(k) == v, (k, v, IFACE_ALIAS.get(k))
    assert not set(EXTRA_IFACE_ALIAS) & set(go), "an EXTRA entry shadows a Go entry"


def test_go_canon_iface_algorithm_is_unchanged() -> None:
    """The port mirrors these exact Go expressions; if canonIface is rewritten the
    port must be re-reviewed."""
    src = _go_source()
    for needle in ("strings.ToLower(strings.TrimSpace(s))",
                   "return r >= '0' && r <= '9'",
                   "if r >= 'a' && r <= 'z' {",
                   "if c, ok := ifaceAlias[prefix]; ok {",
                   "return prefix + rest"):
        assert needle in src, needle


def test_python_key_equals_go_canon_iface_wherever_go_has_the_spelling() -> None:
    """Byte-identical to Go for every vector whose prefix is a Go-table spelling or
    unknown to both tables — the vendor additions are the ONLY divergence."""
    go = _go_alias_table()
    corpus = [n for _, n, _, _ in IFACE_VECTORS] + [
        "Ethernet1", "Et1", "GigabitEthernet0/1", "Gi0/1", "ethernet-1/1", "ge-0/0/0",
        "Port-Channel1", "Bundle-Ether7", "Management0", "Serial1/0", "Tunnel9", "lo0",
        "TwentyFiveGigabitEthernet1/0/1", "FortyGigE1/0/1", "HundredGigabitEthernet1/0/1"]
    compared = 0
    for name in corpus:
        py = canon_iface_key(name)
        if py in ("", A) or C.is_ifindex_marker(py):
            continue  # Python abstains/marks where Go has no notion of it
        low = name.strip().lower()
        d = next((i for i, r in enumerate(low) if "0" <= r <= "9"), len(low))
        prefix = "".join(r for r in low[:d] if "a" <= r <= "z")
        if "," in name or prefix in EXTRA_IFACE_ALIAS:
            continue  # SR OS ifDescr split / a vendor spelling Go lacks
        assert py == _go_canon_iface(name, go), name
        compared += 1
    assert compared >= 60, compared
    # the examples documented on the Go function
    for raw, want in (("Ethernet1", "et1"), ("Et1", "et1"), ("GigabitEthernet0/1", "gi0/1"),
                      ("Gi0/1", "gi0/1"), ("ethernet-1/1", "et1/1"), ("ge-0/0/0", "ge0/0/0")):
        assert canon_iface_key(raw) == want == _go_canon_iface(raw, go)


# ── canonical_peer ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,want", [
    ("192.168.200.34", "192.168.200.34"),
    (" 10.0.0.1 ", "10.0.0.1"),
    ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ("2001:db8::1", "2001:db8::1"),
    ("[2001:db8::1]", "2001:db8::1"),
    ("::ffff:10.0.0.1", "10.0.0.1"),
    ("fe80::1%eth0", "fe80::1%eth0"),
    ("pe-vpn200-parity", ""),
    ("10.0.0.256", ""),
    ("010.0.0.1", ""),
    ("", ""),
    ("1" * 100, ""),
    (chr(0x661) + chr(0x660) + ".0.0.1", ""),
])
def test_canonical_peer(raw: str, want: str) -> None:
    assert canonical_peer(raw) == want


def test_canonical_peer_rejects_non_strings() -> None:
    for raw in (None, 167772161, b"10.0.0.1", ["10.0.0.1"], {"ip": "10.0.0.1"}):
        assert canonical_peer(raw) == ""


# ── the resolver extensions ──────────────────────────────────────────────────

def _lab_raw(tenant: str = TENANT) -> dict:
    return {
        "devices": {tenant: [
            {"tenant_id": tenant, "device": DEVICE, "name": "cEDGE-81", "mgmt_ip": CEDGE81_MGMT},
            {"tenant_id": tenant, "device": "r2", "name": "core-r2", "mgmt_ip": "2001:db8:0::2"},
            {"tenant_id": tenant, "device": "sw-hp", "name": "hp-edge", "mgmt_ip": "10.9.9.9"},
            {"tenant_id": tenant, "device": "router", "name": "router", "mgmt_ip": "10.9.9.10"},
        ]},
        "interface_ips": {tenant: [
            {"tenant_id": tenant, "device": DEVICE, "ip": "192.168.200.33",
             "ifname": "GigabitEthernet3"},
        ]},
        "ifindex": {tenant: [
            {"tenant_id": tenant, "device": DEVICE, "ifindex": "1", "ifname": "GigabitEthernet1"},
            {"tenant_id": tenant, "device": DEVICE, "ifindex": "2", "ifname": "GigabitEthernet2"},
            {"tenant_id": tenant, "device": DEVICE, "ifindex": "5", "ifname": "GigabitEthernet5"},
            # a 5G and a 50G port that collapse onto one key → never merged
            {"tenant_id": tenant, "device": DEVICE, "ifindex": "7",
             "ifname": "FiveGigabitEthernet1/0/1"},
            {"tenant_id": tenant, "device": DEVICE, "ifindex": "8",
             "ifname": "FiftyGigabitEthernet1/0/1"},
            *({"tenant_id": tenant, "device": "sw-hp", "ifindex": str(i), "ifname": str(i)}
              for i in range(1, 49)),
            # a digit-named port whose digits are ALSO a different port's ifIndex
            {"tenant_id": tenant, "device": "sw-odd", "ifindex": "9", "ifname": "9"},
            {"tenant_id": tenant, "device": "sw-odd", "ifindex": "10", "ifname": "11"},
            {"tenant_id": tenant, "device": "sw-odd", "ifindex": "11", "ifname": "Trk1"},
        ]},
    }


def _lab() -> EntityResolver:
    return identity_resolver_for(_lab_raw(), TENANT)


def test_resolver_collision_drops_the_key_never_picks() -> None:
    r = _lab()
    assert r.iface_key_status(DEVICE, "fi1/0/1") == "ambiguous"
    assert r.ifname_for_key(DEVICE, "fi1/0/1") is None
    assert r.iface_key_status(DEVICE, "gi1") == "ok"
    assert r.ifname_for_key(DEVICE, "gi1") == "GigabitEthernet1"
    assert r.iface_key_status(DEVICE, "gi9") == "unknown"
    # the same key on two DIFFERENT devices is no collision
    two = EntityResolver.from_rows([], [], [
        {"device": "a", "ifindex": "1", "ifname": "Ethernet1"},
        {"device": "b", "ifindex": "1", "ifname": "Et1"}])
    assert two.iface_key_status("a", "et1") == two.iface_key_status("b", "et1") == "ok"


def test_resolver_ifname_set_per_device() -> None:
    r = _lab()
    assert r.ifnames("sw-hp") == frozenset(str(i) for i in range(1, 49))
    assert "GigabitEthernet3" in r.ifnames(DEVICE)          # from the interface-IP rows
    assert r.ifnames("nope") == frozenset() == r.ifnames(None)


def test_resolve_device_by_id_name_and_management_ip() -> None:
    r = _lab()
    assert r.resolve_device(DEVICE) == (DEVICE, "ok")
    assert r.resolve_device("CEDGE-81") == (DEVICE, "ok")
    assert r.resolve_device(CEDGE81_MGMT) == (DEVICE, "ok")       # cEDGE-81's syslog hostname
    assert r.resolve_device("192.168.200.33") == (DEVICE, "ok")   # an interface address
    assert r.resolve_device("2001:DB8::2") == ("r2", "ok")         # IPv6, other notation
    assert r.resolve_device("[2001:db8:0:0::2]") == ("r2", "ok")
    assert r.device_for_hostname(CEDGE81_MGMT) == DEVICE
    assert r.resolve_device("nobody") == (None, "unknown")
    assert r.resolve_device("") == (None, "unknown")
    assert r.resolve_device(None) == (None, "unknown")


@pytest.mark.parametrize("host", ["router", "Router", "localhost", "LOCALHOST.localdomain",
                                  "switch", "unknown", "127.0.0.1", "::1", "0.0.0.0",
                                  "fe80::1", "224.0.0.5", "255.255.255.255"])
def test_generic_hostname_never_resolves(host: str) -> None:
    """The inventory even HOLDS a device named "router": still never bound."""
    r = _lab()
    assert r.resolve_device(host) == (None, "generic")


def test_generic_list_is_lower_case() -> None:
    assert all(h == h.lower() for h in GENERIC_HOSTNAMES)


def test_name_and_address_pointing_at_two_devices_is_ambiguous() -> None:
    r = EntityResolver.from_rows([
        {"device": "a", "name": "10.0.0.2", "mgmt_ip": "10.0.0.1"},
        {"device": "b", "name": "b", "mgmt_ip": "10.0.0.2"}], [], [])
    assert r.resolve_device("10.0.0.2") == (None, "ambiguous")
    assert r.resolve_device("10.0.0.1") == ("a", "ok")


def test_ambiguous_names_and_addresses_drop() -> None:
    r = EntityResolver.from_rows([
        {"device": "a", "name": "edge", "mgmt_ip": "10.0.0.1"},
        {"device": "b", "name": "EDGE", "mgmt_ip": "10.0.0.1"}], [], [])
    assert r.resolve_device("edge") == (None, "ambiguous")
    assert r.resolve_device("10.0.0.1") == (None, "ambiguous")
    assert r.resolve_device("a") == ("a", "ok")


def test_legacy_resolver_is_byte_identical() -> None:
    """Existing fields and lookups: unchanged by the additive API."""
    devices = [{"device": "leaf1", "name": "Leaf-1", "mgmt_ip": "10.70.245.1"}]
    ips = [{"device": "leaf1", "ip": "10.0.12.1", "ifname": "Ethernet1"}]
    idx = [{"device": "leaf1", "ifindex": 1, "ifname": "Ethernet1"}]
    r = EntityResolver.from_rows(devices, ips, idx)
    assert r.tenant is None
    assert dict(r.ip_to_device) == {"10.70.245.1": "leaf1", "10.0.12.1": "leaf1"}
    assert dict(r.ip_to_iface) == {"10.0.12.1": "leaf1:Ethernet1"}
    assert dict(r.ifindex_to_name) == {("leaf1", "1"): "Ethernet1"}
    assert dict(r.name_to_device) == {"leaf1": "leaf1", "leaf-1": "leaf1"}
    assert r.coverage() == {"ips": 2, "iface_ips": 1, "ifindexes": 1}
    assert r.canonical_device("LEAF-1") == "leaf1"
    assert _unique_map([("k", "a"), ("k", "b"), ("j", "c")]) == {"j": "c"}
    assert EMPTY_RESOLVER.resolve_device("x") == (None, "unknown")


# ── canonicalize ─────────────────────────────────────────────────────────────

def _sig(source: Source, kind: str, etype: EntityType, eid: str, attrs: dict | None = None,
         tokens: tuple[str, ...] = (), tenant: str = TENANT) -> Signal:
    return Signal(
        tenant_id=tenant, ts=TS, source=source, kind=kind,
        observer=Observer(observer_id="obs", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=etype, entity_id=eid,
        severity=Severity.HIGH, native_id=f"{source.value}|{kind}|{eid}",
        entity_tokens=tokens or (eid,), attrs=dict(attrs or {}))


def _syslog(message: str, host: str = CEDGE81_MGMT) -> Signal:
    """A syslog line through the PRODUCTION parser. The recorded cEDGE-81 fixture
    holds no BGP/link line (E7 docstring), so the MESSAGE here is synthetic; the
    hostname is the box's recorded one."""
    tag = message.split(":", 1)[0]
    sig = P.syslog_control_signal({"appname": tag, "facility": "local7", "hostname": host,
                                   "message": message, "timestamp": "2026-11-01T17:00:01Z"},
                                  TENANT, INGEST)
    assert sig is not None, message
    return sig


def _rfc_trap() -> Signal:
    with open(TRAPS, encoding="utf-8") as fh:
        rec = next(json.loads(ln) for ln in fh if ln.strip() and RFC_BACKWARD in ln)
    sig = P.trap_control_signal({**rec, "device": DEVICE}, TENANT, INGEST)
    assert sig is not None
    return sig


def _controller_peer_in_inventory() -> Signal:
    with open(GOLDEN_PEER, encoding="utf-8") as fh:
        ev = json.load(fh)[0]
    sig = controller_event_to_signal(ev, INGEST)
    assert sig is not None
    return sig


def test_recorded_syslog_fixture_logs_under_the_management_ip() -> None:
    with open(SYSLOG, encoding="utf-8") as fh:
        hosts = {json.loads(ln)["hostname"] for ln in fh if ln.strip()}
    assert hosts == {CEDGE81_MGMT}
    assert _lab().device_for_hostname(CEDGE81_MGMT) == DEVICE


def test_d1_d2_syslog_bgp_meets_the_trap_and_controller_session() -> None:
    """One session, three lanes, ONE node once canonicalised: syslog (host-level,
    hostname = management IP), the router's own RFC 4273 trap, and the controller
    whose peer nms/identity.go rewrote to an inventory id (D5)."""
    r = _lab()
    syslog = _syslog(f"%BGP-5-ADJCHANGE: neighbor {PEER} vpn vrf 200 Down BGP Notification sent")
    trap = _rfc_trap()
    ctl = _controller_peer_in_inventory()
    assert syslog.entity_id == CEDGE81_MGMT
    assert ctl.entity_id == f"{DEVICE}:pe-vpn200-parity"
    assert len(build_nodes((syslog, trap, ctl))) == 3          # today: three nodes

    out = [canonicalize(s, r) for s in (syslog, trap, ctl)]
    assert [o for _, o in out] == [REWRITTEN, UNCHANGED, REWRITTEN]
    ids = {s.entity_id for s, _ in out}
    assert ids == {f"{DEVICE}:{PEER}"} == {trap.entity_id}
    assert len(build_nodes(tuple(s for s, _ in out))) == 1     # canonicalised: one node
    cs = out[0][0]
    assert cs.attrs[CANON_ATTR] == {"raw": CEDGE81_MGMT, "basis": "device:ip+peer:ip"}
    assert cs.entity_tokens == (DEVICE, PEER)
    assert out[2][0].attrs[CANON_ATTR] == {"raw": f"{DEVICE}:pe-vpn200-parity",
                                           "basis": "peer:controller_hint"}


def test_d1_unknown_host_keeps_host_level_binding() -> None:
    sig = _syslog(f"%BGP-5-ADJCHANGE: neighbor {PEER} Down", host="10.99.99.99")
    out, outcome = canonicalize(sig, _lab())
    assert out is sig and outcome == ABSTAIN_UNKNOWN


def test_d1_generic_host_abstains() -> None:
    sig = _syslog(f"%BGP-5-ADJCHANGE: neighbor {PEER} Down", host="router")
    out, outcome = canonicalize(sig, _lab())
    assert out is sig and outcome == ABSTAIN_GENERIC


def test_d1_ipv6_peer_is_compressed() -> None:
    sig = _sig(Source.SYSLOG, "bgp_adjacency_change", EntityType.DEVICE, "cEDGE-81",
               {"peer": "2001:0db8:0:0:0:0:0:0034"})
    out, outcome = canonicalize(sig, _lab())
    assert outcome == REWRITTEN and out.entity_id == f"{DEVICE}:2001:db8::34"


def test_d1_non_ip_peer_rewrites_the_device_only() -> None:
    sig = _sig(Source.SYSLOG, "bgp_adjacency_change", EntityType.DEVICE, "cEDGE-81",
               {"peer": "pe-1"})
    res = canonicalize_detailed(sig, _lab())
    assert res.outcome == REWRITTEN and res.signal.entity_id == DEVICE
    assert ("peer", ABSTAIN_UNKNOWN) in res.axes


def test_ospf_syslog_stays_host_level() -> None:
    """D1 is BGP only (an OSPF Nbr is a router-id, ospfNbrTable an IP): D2 only."""
    sig = _sig(Source.SYSLOG, "ospf_adjacency_change", EntityType.DEVICE, CEDGE81_MGMT,
               {"peer": "10.0.0.2"})
    out, outcome = canonicalize(sig, _lab())
    assert outcome == REWRITTEN and out.entity_id == DEVICE


def test_d5_conflicting_controller_peer_abstains() -> None:
    sig = _sig(Source.CONTROLLER, "bgp_adjacency_change", EntityType.DEVICE,
               f"{DEVICE}:10.0.0.1", {"peer_id": "10.0.0.1",
                                      "correlation_hints": {"controller_peer_id": "10.0.0.2"}})
    out, outcome = canonicalize(sig, _lab())
    assert out is sig and outcome == ABSTAIN_CONFLICT


def test_d5_controller_only_device_keeps_its_id() -> None:
    """A device the resolver does not know (controller-only) keeps its inventory id
    verbatim; the peer is still put back to its address."""
    sig = _sig(Source.CONTROLLER, "bgp_adjacency_change_clear", EntityType.DEVICE,
               "ctl-only-1:pe-9", {"peer_id": "pe-9",
                                   "correlation_hints": {"controller_peer_id": "10.0.0.9"}})
    out, outcome = canonicalize(sig, _lab())
    assert outcome == REWRITTEN and out.entity_id == "ctl-only-1:10.0.0.9"


def test_trap_ipv6_peer_is_compressed() -> None:
    sig = _sig(Source.TRAP, "bgp_adjacency_change", EntityType.DEVICE,
               f"{DEVICE}:2001:0db8:0000:0000:0000:0000:0000:0001",
               {"peer": "2001:0db8:0000:0000:0000:0000:0000:0001"})
    out, outcome = canonicalize(sig, _lab())
    assert outcome == REWRITTEN and out.entity_id == f"{DEVICE}:2001:db8::1"


def test_controller_device_kinds_are_never_resolved() -> None:
    """Controller device kinds bind `device or site`: a site id must never be read
    as a hostname."""
    sig = _sig(Source.CONTROLLER, "controller_device_unreachable", EntityType.DEVICE, "cEDGE-81")
    out, outcome = canonicalize(sig, _lab())
    assert out is sig and outcome == UNCHANGED


def test_d4_interface_spellings_meet_across_lanes() -> None:
    r = _lab()
    syslog = _syslog("%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1, "
                     "changed state to down")
    trap = _sig(Source.TRAP, "link_state_change", EntityType.INTERFACE, f"{DEVICE}:Gi1",
                {"interface": "Gi1"}, (DEVICE,))
    ctl = _sig(Source.CONTROLLER, "link_state_change", EntityType.INTERFACE,
               f"{DEVICE}:GigabitEthernet1", {"interface_name": "GigabitEthernet1"})
    out = [canonicalize(s, r) for s in (syslog, trap, ctl)]
    assert {s.entity_id for s, _ in out} == {f"{DEVICE}:gi1"}
    assert all(o == REWRITTEN for _, o in out)
    assert out[0][0].entity_tokens == (DEVICE,)
    assert out[0][0].attrs["interface"] == "GigabitEthernet1"   # display name kept


def test_d4_ipv6_host_and_colon_port_split_by_the_interface_attr() -> None:
    r = _lab()
    sig = _sig(Source.SYSLOG, "link_state_change", EntityType.INTERFACE,
               "2001:db8::2:Serial0/0/0:1", {"interface": "Serial0/0/0:1"})
    out, outcome = canonicalize(sig, r)
    assert outcome == REWRITTEN and out.entity_id == "r2:se0/0/0:1"
    # without the attr a multi-colon id cannot be split: abstain, never guess
    bare = _sig(Source.SYSLOG, "link_state_change", EntityType.INTERFACE,
                "2001:db8::2:Serial0/0/0:1")
    assert canonicalize(bare, r) == (bare, ABSTAIN_UNKNOWN)


def test_d4_collision_abstains() -> None:
    sig = _sig(Source.TRAP, "link_state_change", EntityType.INTERFACE,
               f"{DEVICE}:Fi1/0/1", {"interface": "Fi1/0/1"})
    res = canonicalize_detailed(sig, _lab())
    assert res.signal is sig and res.outcome == ABSTAIN_AMBIGUOUS
    assert ("iface", ABSTAIN_AMBIGUOUS) in res.axes


def test_d4_digit_only_rule() -> None:
    r = _lab()
    # an ifIndex on a named-port box → the port's key
    cisco = _sig(Source.TRAP, "link_state_change", EntityType.INTERFACE, f"{DEVICE}:5",
                 {"interface": "5"})
    out, outcome = canonicalize(cisco, r)
    assert outcome == REWRITTEN and out.entity_id == f"{DEVICE}:gi5"
    assert out.attrs[CANON_ATTR]["basis"] == "iface:ifindex"
    # HP ProCurve: "5" IS the port's name — kept as is, never re-read as ifIndex
    hp = _sig(Source.TRAP, "link_state_change", EntityType.INTERFACE, "sw-hp:5",
              {"interface": "5"})
    assert canonicalize(hp, r) == (hp, UNCHANGED)
    hp_by_name = _sig(Source.SYSLOG, "link_state_change", EntityType.INTERFACE, "hp-edge:5",
                      {"interface": "5"})
    out, outcome = canonicalize(hp_by_name, r)
    assert outcome == REWRITTEN and out.entity_id == "sw-hp:5"
    # digits that are a port NAME and a DIFFERENT port's ifIndex → ambiguous
    odd = _sig(Source.TRAP, "link_state_change", EntityType.INTERFACE, "sw-odd:11",
               {"interface": "11"})
    assert canonicalize(odd, r) == (odd, ABSTAIN_AMBIGUOUS)
    # digits nobody knows → abstain, never a key by themselves
    lost = _sig(Source.TRAP, "link_state_change", EntityType.INTERFACE, f"{DEVICE}:42",
                {"interface": "42"})
    assert canonicalize(lost, r) == (lost, ABSTAIN_UNKNOWN)


def test_d4_placeholder_port_keeps_raw_but_device_still_resolves() -> None:
    sig = _sig(Source.SYSLOG, "link_state_change", EntityType.INTERFACE,
               f"{CEDGE81_MGMT}:unknown", {"interface": "unknown"})
    res = canonicalize_detailed(sig, _lab())
    assert res.outcome == REWRITTEN and res.signal.entity_id == f"{DEVICE}:unknown"
    assert dict(res.axes) == {"device": REWRITTEN, "iface": ABSTAIN_UNKNOWN}


def test_d4_generic_host_never_canonicalises_the_port() -> None:
    sig = _sig(Source.SYSLOG, "link_state_change", EntityType.INTERFACE, "router:Gi1",
               {"interface": "Gi1"})
    assert canonicalize(sig, _lab()) == (sig, ABSTAIN_GENERIC)


def test_d4_sonic_alias_mode_abstains_via_vendor_attr() -> None:
    sig = _sig(Source.CONTROLLER, "link_state_change", EntityType.INTERFACE, "r2:etp1",
               {"interface_name": "etp1", "vendor": "sonic"})
    res = canonicalize_detailed(sig, _lab())
    assert res.signal is sig and dict(res.axes)["iface"] == ABSTAIN_UNKNOWN


def test_non_event_lanes_and_entity_types_are_untouched() -> None:
    r = _lab()
    for src in (Source.METRIC, Source.FLOW, Source.PROBE, Source.CLOUD):
        sig = _sig(src, "x", EntityType.INTERFACE, "cEDGE-81:Gi1", {"interface": "Gi1"})
        assert canonicalize(sig, r) == (sig, UNCHANGED)
    path = _sig(Source.CONTROLLER, "controller_bfd_down", EntityType.PATH, "a|b@ci-1")
    assert canonicalize(path, r) == (path, UNCHANGED)


def test_identity_fields_are_never_touched_and_attrs_is_a_new_dict() -> None:
    r = _lab()
    for sig in (_syslog(f"%BGP-5-ADJCHANGE: neighbor {PEER} Down"),
                _controller_peer_in_inventory(),
                _sig(Source.TRAP, "link_state_change", EntityType.INTERFACE,
                     f"{DEVICE}:Gi1", {"interface": "Gi1"})):
        before_attrs = dict(sig.attrs)
        out, outcome = canonicalize(sig, r)
        assert outcome == REWRITTEN
        assert out is not sig and out.attrs is not sig.attrs
        assert sig.attrs == before_attrs and CANON_ATTR not in sig.attrs  # input untouched
        assert out.native_id == sig.native_id
        assert out.signal_id == sig.signal_id
        for f in ("tenant_id", "ts", "source", "kind", "observer", "modality_class",
                  "entity_type", "severity", "site", "metric_name", "value"):
            assert getattr(out, f) == getattr(sig, f), f
        assert {k: v for k, v in out.attrs.items() if k != CANON_ATTR} == before_attrs


def test_rehydrated_signal_keeps_its_stored_id() -> None:
    sig = replace(_syslog(f"%BGP-5-ADJCHANGE: neighbor {PEER} Down"),
                  stored_signal_id="00000000-0000-0000-0000-000000000001")
    out, outcome = canonicalize(sig, _lab())
    assert outcome == REWRITTEN and str(out.signal_id) == "00000000-0000-0000-0000-000000000001"


def _battery() -> list[Signal]:
    return [
        _syslog(f"%BGP-5-ADJCHANGE: neighbor {PEER} Down"),
        _syslog("%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet2, "
                "changed state to up"),
        _syslog(f"%BGP-5-ADJCHANGE: neighbor {PEER} Down", host="router"),
        _rfc_trap(),
        _controller_peer_in_inventory(),
        _sig(Source.TRAP, "link_state_change", EntityType.INTERFACE, f"{DEVICE}:5",
             {"interface": "5"}),
        _sig(Source.TRAP, "link_state_change", EntityType.INTERFACE, "sw-hp:7",
             {"interface": "7"}),
        _sig(Source.SYSLOG, "link_state_change", EntityType.INTERFACE,
             f"{CEDGE81_MGMT}:unknown", {"interface": "unknown"}),
        _sig(Source.SYSLOG, "device_alarm", EntityType.DEVICE, "core-r2"),
        _sig(Source.TRAP, "link_state_change", EntityType.INTERFACE,
             f"{DEVICE}:Fi1/0/1", {"interface": "Fi1/0/1"}),
        _syslog(f"%BGP-5-ADJCHANGE: neighbor {PEER} Down", host="10.99.99.99"),
    ]


def test_idempotent() -> None:
    r = _lab()
    for sig in _battery():
        once, _ = canonicalize(sig, r)
        twice, outcome = canonicalize(once, r)
        assert twice == once and twice is once, sig.entity_id
        assert outcome in (UNCHANGED, ABSTAIN_UNKNOWN, ABSTAIN_GENERIC, ABSTAIN_AMBIGUOUS)


def test_row_order_independent() -> None:
    raw = _lab_raw()
    want = [canonicalize_detailed(s, identity_resolver_for(raw, TENANT)) for s in _battery()]
    rng = random.Random(374)
    for _ in range(25):
        shuffled = {sec: {t: rng.sample(rows, len(rows)) for t, rows in by.items()}
                    for sec, by in raw.items()}
        r = identity_resolver_for(shuffled, TENANT)
        got = [canonicalize_detailed(s, r) for s in _battery()]
        assert [(g.signal, g.outcome, g.axes, g.basis) for g in got] == \
               [(w.signal, w.outcome, w.axes, w.basis) for w in want]


def test_outcome_taxonomy_is_closed() -> None:
    r = _lab()
    seen = {canonicalize(s, r)[1] for s in _battery()}
    seen.add(canonicalize(_battery()[0], EMPTY_RESOLVER)[1])
    assert seen <= set(OUTCOMES)
    assert seen == set(OUTCOMES), set(OUTCOMES) - seen


def test_unscoped_or_foreign_resolver_is_refused() -> None:
    sig = _syslog(f"%BGP-5-ADJCHANGE: neighbor {PEER} Down")
    legacy = EntityResolver.from_rows(_lab_raw()["devices"][TENANT], [], [])
    assert legacy.tenant is None
    assert canonicalize(sig, legacy) == (sig, ABSTAIN_CONFLICT)
    assert canonicalize(sig, None) == (sig, ABSTAIN_CONFLICT)
    other = identity_resolver_for(_lab_raw("t_other"), "t_other")
    assert canonicalize(sig, other) == (sig, ABSTAIN_CONFLICT)


def test_oversized_rewrite_abstains_instead_of_truncating() -> None:
    long_dev = "d" * 250
    r = identity_resolver_for({"devices": {TENANT: [
        {"tenant_id": TENANT, "device": long_dev, "name": "short"}]}}, TENANT)
    sig = _sig(Source.SYSLOG, "bgp_adjacency_change", EntityType.DEVICE, "short",
               {"peer": "2001:db8::1"})
    res = canonicalize_detailed(sig, r)
    assert res.signal is sig and res.outcome == ABSTAIN_CONFLICT
    assert ("length", ABSTAIN_CONFLICT) in res.axes


# ── hostile input never raises ───────────────────────────────────────────────

RLO = chr(0x202E)  # right-to-left override: display spoofing
_HOSTILE = ["", " ", ":", "::", ":::", "a:", ":a", chr(0), chr(0) + ":" + chr(0), RLO + ":evil",
            "localhost", "%s%s%n", "{host}", "../../etc/passwd", "a" * 256, ":" * 256,
            "1" * 256, "[" * 64, "Gi0/1, " * 40, chr(0xFF) * 100,
            "global:x", "tenant:t", "2001:db8::1", "::ffff:1.2.3.4", "fe80::1%" + "z" * 80]


def test_hostile_strings_never_raise() -> None:
    r = _lab()
    rng = random.Random(1103)
    alphabet = string.printable + chr(0xE9) + chr(0x661) + RLO + chr(0)
    samples = list(_HOSTILE) + ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 300)))
                                for _ in range(300)]
    attr_values: list[object] = [None, 7, 3.5, ["x"], {"a": 1}, b"x", True]
    for i, s in enumerate(samples):
        assert isinstance(canon_iface_key(s), str)
        assert isinstance(canon_iface_key(s, s), str)
        assert isinstance(canonical_peer(s), str)
        assert isinstance(r.resolve_device(s)[1], str)
        weird = attr_values[i % len(attr_values)]
        for src, kind, et, attrs in (
                (Source.SYSLOG, "bgp_adjacency_change", EntityType.DEVICE, {"peer": s}),
                (Source.SYSLOG, "bgp_adjacency_change", EntityType.DEVICE, {"peer": weird}),
                (Source.TRAP, "link_state_change", EntityType.INTERFACE, {"interface": s}),
                (Source.TRAP, "link_state_change", EntityType.INTERFACE, {"interface": weird}),
                (Source.CONTROLLER, "bgp_adjacency_change", EntityType.DEVICE,
                 {"peer_id": s, "correlation_hints": {"controller_peer_id": s}}),
                (Source.CONTROLLER, "bgp_adjacency_change", EntityType.DEVICE,
                 {"peer_id": weird, "correlation_hints": weird}),
                (Source.SYSLOG, "device_alarm", EntityType.DEVICE, {CANON_ATTR: weird}),
                (Source.SYSLOG, "device_alarm", EntityType.DEVICE, {CANON_ATTR: {"raw": s}})):
            eid = s if s.strip() else "x"
            try:
                sig = _sig(src, kind, et, eid, attrs)
            except DeadLetter:  # the MODEL refused it (e.g. a global: token) — not canon input
                continue
            out, outcome = canonicalize(sig, r)
            assert outcome in OUTCOMES
            assert out.native_id == sig.native_id and out.signal_id == sig.signal_id


def test_oversized_inputs_are_bounded() -> None:
    assert canon_iface_key("Gi" + "1" * 5000) == IFACE_ABSTAIN
    assert canonical_peer("1" * 5000) == ""
    assert _lab().resolve_device("x" * 5000) == (None, "unknown")


def test_ipaddress_is_the_only_peer_authority() -> None:
    """Every non-empty canonical_peer output parses back to the same address."""
    for raw in ("10.1.2.3", "2001:DB8::A", "::ffff:192.0.2.1", "[fe80::1]"):
        out = canonical_peer(raw)
        assert out and canonical_peer(out) == out
        ipaddress.ip_address(out.split("%")[0])
