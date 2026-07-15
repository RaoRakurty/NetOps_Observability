"""Azure topology-mapping tests — run with: python3 -m pytest test_azure_topology.py

Exercises the pure map_topology() core against representative ARM API JSON, asserting
it produces the SAME schema aws-topology.json uses (vpcs / subnets / nodes / edges) and
that route-table facts map to the right canonical egress kinds.
"""
from __future__ import annotations

import azure_topology as azt

SUB = "sub-123"
VNET_ID = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-prod"
RT_ID = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/routeTables/udr-app"
GW_ID = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkGateways/vgw-prod"
SNET_APP_ID = f"{VNET_ID}/subnets/snet-app"
GW_SUBNET_ID = f"{VNET_ID}/subnets/GatewaySubnet"


def _sample():
    vnets = [{
        "id": VNET_ID, "name": "vnet-prod",
        "properties": {
            "addressSpace": {"addressPrefixes": ["10.30.0.0/16", "10.40.0.0/16"]},
            "subnets": [
                {"id": SNET_APP_ID, "name": "snet-app", "properties": {
                    "addressPrefix": "10.30.1.0/24",
                    "routeTable": {"id": RT_ID},
                }},
                {"id": GW_SUBNET_ID, "name": "GatewaySubnet", "properties": {
                    "addressPrefix": "10.30.255.0/27",
                }},
            ],
        },
    }]
    route_tables = [{
        "id": RT_ID, "name": "udr-app",
        "properties": {"routes": [
            {"name": "default-to-fw", "properties": {
                "addressPrefix": "0.0.0.0/0",
                "nextHopType": "VirtualAppliance",
                "nextHopIpAddress": "10.30.1.4",
            }},
            {"name": "onprem-via-gw", "properties": {
                "addressPrefix": "10.0.0.0/8",
                "nextHopType": "VirtualNetworkGateway",
            }},
            {"name": "intra", "properties": {
                "addressPrefix": "10.30.0.0/16",
                "nextHopType": "VnetLocal",  # not an egress edge
            }},
        ]},
    }]
    gateways = [{
        "id": GW_ID, "name": "vgw-prod",
        "properties": {
            "gatewayType": "Vpn",
            "ipConfigurations": [{"properties": {"subnet": {"id": GW_SUBNET_ID}}}],
        },
    }]
    return vnets, route_tables, gateways, []


def test_schema_matches_aws_shape():
    vnets, rts, gws, ers = _sample()
    topo = azt.map_topology(vnets, rts, gws, ers, SUB, "westeurope")
    assert set(topo) == {"provider", "account_id", "region", "vpcs", "subnets", "nodes", "edges"}
    assert topo["provider"] == "azure"
    assert topo["account_id"] == SUB
    # Multi-prefix VNet → two vpc rows sharing the id (so subnet containment works).
    prod = [v for v in topo["vpcs"] if v["id"] == VNET_ID]
    assert {v["cidr"] for v in prod} == {"10.30.0.0/16", "10.40.0.0/16"}
    # Both subnets present, each with its CIDR.
    by_id = {s["id"]: s for s in topo["subnets"]}
    assert by_id[SNET_APP_ID]["cidr"] == "10.30.1.0/24"


def test_route_facts_map_to_canonical_kinds():
    vnets, rts, gws, ers = _sample()
    topo = azt.map_topology(vnets, rts, gws, ers, SUB, "westeurope")
    edges = {(e["destination"], e["to_kind"]): e for e in topo["edges"]}

    # VirtualAppliance UDR → an NVA edge pointing at the next-hop IP.
    assert ("0.0.0.0/0", "nva") in edges
    assert edges[("0.0.0.0/0", "nva")]["to"] == "10.30.1.4"
    assert edges[("0.0.0.0/0", "nva")]["route_table_name"] == "udr-app"

    # VirtualNetworkGateway UDR → the VNet's actual gateway resource, kind vpn_gateway.
    assert ("10.0.0.0/8", "vpn_gateway") in edges
    assert edges[("10.0.0.0/8", "vpn_gateway")]["to"] == GW_ID

    # VnetLocal is intra-VNet — never an egress edge.
    assert all(e["destination"] != "10.30.0.0/16" for e in topo["edges"])

    # Nodes: the NVA (by IP) + the VPN gateway are present with the right kinds.
    kinds = {n["id"]: n["kind"] for n in topo["nodes"]}
    assert kinds.get("10.30.1.4") == "nva"
    assert kinds.get(GW_ID) == "vpn_gateway"


def test_subnet_without_udr_has_no_edge():
    vnets, rts, gws, ers = _sample()
    topo = azt.map_topology(vnets, rts, gws, ers, SUB, "westeurope")
    # GatewaySubnet carries no routeTable → only system routes → no egress edge.
    assert all(e["from_subnet"] != GW_SUBNET_ID for e in topo["edges"])


def test_expressroute_gateway_and_circuit_kinds():
    vnets, rts, gws, _ = _sample()
    gws = [{
        "id": GW_ID, "name": "ergw-prod",
        "properties": {"gatewayType": "ExpressRoute",
                       "ipConfigurations": [{"properties": {"subnet": {"id": GW_SUBNET_ID}}}]},
    }]
    ers = [{"id": "/circuits/er-1", "name": "er-weu", "properties": {}}]
    topo = azt.map_topology(vnets, rts, gws, ers, SUB, "westeurope")
    kinds = {n["id"]: n["kind"] for n in topo["nodes"]}
    assert kinds.get(GW_ID) == "expressroute_gateway"
    assert kinds.get("/circuits/er-1") == "dx"
    # The VirtualNetworkGateway route now resolves to the ER gateway kind.
    er_edge = [e for e in topo["edges"] if e["destination"] == "10.0.0.0/8"][0]
    assert er_edge["to_kind"] == "expressroute_gateway"


def test_empty_subscription_degrades_to_empty_topology():
    topo = azt.map_topology([], [], [], [], SUB, "westeurope")
    assert topo["vpcs"] == [] and topo["subnets"] == [] and topo["edges"] == [] and topo["nodes"] == []
