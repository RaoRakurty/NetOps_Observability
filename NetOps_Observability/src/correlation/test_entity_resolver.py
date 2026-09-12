# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""EntityResolver (C7.1) — the IP/ifIndex → correlation-entity bridge.

Properties under test: every lookup resolves real data; an unresolved OR ambiguous
endpoint returns None (abstain, never guess); tenant scoping unions a tenant's rows
with global and never crosses tenants.
"""
from entity_resolver import EMPTY_RESOLVER, EntityResolver, _unique_map


def _resolver():
    return EntityResolver.from_rows(
        devices=[
            {"tenant_id": "", "device": "leaf1", "name": "leaf1", "mgmt_ip": "10.70.245.1"},
            {"tenant_id": "", "device": "leaf2", "name": "leaf2", "mgmt_ip": "10.70.245.2"},
        ],
        interface_ips=[
            {"tenant_id": "", "device": "leaf1", "ip": "10.0.12.1", "ifname": "Ethernet1"},
            {"tenant_id": "", "device": "leaf2", "ip": "10.0.12.2", "ifname": "Ethernet1"},
        ],
        ifindex=[
            {"tenant_id": "", "device": "leaf1", "ifindex": "1", "ifname": "Ethernet1"},
            {"tenant_id": "", "device": "leaf1", "ifindex": "2", "ifname": "Ethernet2"},
        ],
    )


def test_mgmt_and_interface_ip_resolve_to_device():
    r = _resolver()
    assert r.device_for_ip("10.70.245.1") == "leaf1"      # mgmt IP
    assert r.device_for_ip("10.0.12.2") == "leaf2"        # interface IP also → device
    assert r.device_for_ip("203.0.113.9") is None         # unknown → abstain
    assert r.device_for_ip(None) is None


def test_interface_ip_resolves_to_device_iface():
    r = _resolver()
    assert r.iface_for_ip("10.0.12.1") == "leaf1:Ethernet1"
    assert r.iface_for_ip("10.70.245.1") is None          # mgmt IP has no interface name
    assert r.iface_for_ip("203.0.113.9") is None


def test_ifindex_resolves_to_name_and_device_iface():
    r = _resolver()
    assert r.ifname("leaf1", "2") == "Ethernet2"
    assert r.ifname("leaf1", 1) == "Ethernet1"            # int ifIndex coerced
    assert r.device_iface("leaf1", "1") == "leaf1:Ethernet1"
    assert r.ifname("leaf1", "99") is None                # unknown port → abstain
    assert r.device_iface("leaf2", "1") is None           # leaf2 has no ifIndex rows
    assert r.ifname(None, "1") is None and r.ifname("leaf1", "") is None


def test_ambiguous_ip_resolves_to_none_never_guesses():
    # the SAME IP claimed by two devices is unresolvable — drop it, never pick one.
    r = EntityResolver.from_rows(
        devices=[
            {"device": "a", "mgmt_ip": "10.0.0.9"},
            {"device": "b", "mgmt_ip": "10.0.0.9"},
        ],
        interface_ips=[], ifindex=[],
    )
    assert r.device_for_ip("10.0.0.9") is None


def test_unique_map_drops_conflicts_keeps_unique_order_independent():
    assert _unique_map([("k", "v"), ("k", "v")]) == {"k": "v"}     # same value OK
    assert _unique_map([("k", "v1"), ("k", "v2")]) == {}           # conflict dropped
    assert _unique_map([("", "v"), ("k", "")]) == {}               # empties ignored
    # order independence: conflict drops regardless of which came first.
    assert _unique_map([("k", "v2"), ("k", "v1")]) == {}


def test_empty_resolver_abstains_everywhere():
    assert EMPTY_RESOLVER.device_for_ip("10.0.0.1") is None
    assert EMPTY_RESOLVER.iface_for_ip("10.0.0.1") is None
    assert EMPTY_RESOLVER.device_iface("d", "1") is None
    assert EMPTY_RESOLVER.coverage() == {"ips": 0, "iface_ips": 0, "ifindexes": 0}


def test_coverage_counts_populated_maps():
    assert _resolver().coverage() == {"ips": 4, "iface_ips": 2, "ifindexes": 2}


def test_loader_tenant_scoping_unions_global_never_crosses(tmp_path, monkeypatch):
    # The zero-leak property: a tenant resolves its OWN rows ∪ global, and NEVER
    # another tenant's — even when both name the same kind of resource.
    import json

    import main
    f = tmp_path / "entity_resolver.json"
    f.write_text(json.dumps({
        "devices": [
            {"tenant_id": "t_a", "device": "a1", "mgmt_ip": "10.0.0.1"},
            {"tenant_id": "t_b", "device": "b1", "mgmt_ip": "10.0.0.2"},
            {"tenant_id": "", "device": "g1", "mgmt_ip": "10.0.0.3"},
        ],
        "interface_ips": [], "ifindex": [],
    }))
    monkeypatch.setattr(main, "ENTITY_RESOLVER_FILE", str(f))
    monkeypatch.setattr(main, "_er_mtime", -1.0)  # force a re-read of the patched file

    ra = main.entity_resolver_for("t_a")
    assert ra.device_for_ip("10.0.0.1") == "a1"   # own row
    assert ra.device_for_ip("10.0.0.3") == "g1"   # ∪ global
    assert ra.device_for_ip("10.0.0.2") is None   # NEVER tenant b's row

    rb = main.entity_resolver_for("t_b")
    assert rb.device_for_ip("10.0.0.2") == "b1"
    assert rb.device_for_ip("10.0.0.1") is None   # NEVER tenant a's row
