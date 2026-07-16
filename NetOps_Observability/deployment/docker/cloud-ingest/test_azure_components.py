"""Azure component-inventory tests (cloud-network-overview P0).

Fixture-driven ARM JSON, no live calls — pins VNet/subnet tagging, status
honesty (missing/unknown provider state → not_measured, never green), key
metrics, and seam-endpoint tagging (design §4a). collect() is exercised with a
fake get_json to prove per-family isolation."""
from __future__ import annotations

import azure_components as az

R = "westus2"
SUB = "sub-1"
VNET = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-a"
SUBNET = VNET + "/subnets/web"


def test_load_balancer_provisioning_and_vnet_tagging():
    lb = {"id": "/x/loadBalancers/lb1", "name": "lb1", "location": R,
          "sku": {"name": "Standard"},
          "properties": {"provisioningState": "Succeeded",
                         "frontendIPConfigurations": [
                             {"properties": {"subnet": {"id": SUBNET}}}],
                         "backendAddressPools": [{}, {}]}}
    r = az.parse_load_balancers([lb], R)[0]
    assert r["resource_type"] == "network:loadBalancer"
    assert r["status"] == "healthy"
    assert r["status_reason"] == "provisioningState=Succeeded"
    assert r["vpc_id"] == VNET
    assert r["subnet_ids"] == [SUBNET]
    assert r["key_metric_value"] == 2.0


def test_load_balancer_missing_state_is_not_measured():
    r = az.parse_load_balancers([{"id": "/x/lb2", "name": "lb2", "properties": {}}], R)[0]
    assert r["status"] == "not_measured"
    assert "no provisioningState" in r["status_reason"]


def test_app_gateway_operational_state_wins():
    gw = {"id": "/x/agw1", "name": "agw1",
          "properties": {"operationalState": "Stopped", "provisioningState": "Succeeded",
                         "gatewayIPConfigurations": [
                             {"properties": {"subnet": {"id": SUBNET}}}],
                         "firewallPolicy": {"id": "/x/wafpol"}}}
    r = az.parse_app_gateways([gw], R)[0]
    assert r["status"] == "down"           # Stopped beats Succeeded provisioning
    assert r["vpc_id"] == VNET
    assert r["attrs"]["waf_enabled"] == "true"


def test_front_door_filtered_to_frontdoor_skus():
    profiles = [
        {"id": "/x/fd1", "name": "fd1", "sku": {"name": "Premium_AzureFrontDoor"},
         "properties": {"resourceState": "Active"}},
        {"id": "/x/cdn1", "name": "cdn1", "sku": {"name": "Standard_Microsoft"},
         "properties": {"resourceState": "Active"}},
    ]
    rows = az.parse_front_door_profiles(profiles)
    assert len(rows) == 1
    assert rows[0]["resource_type"] == "cdn:frontdoorProfile"
    assert rows[0]["region"] == "global"
    assert rows[0]["status"] == "healthy"


def test_nsg_rule_count_and_multi_vnet_attachment():
    nsg = {"id": "/x/nsg1", "name": "nsg1",
           "properties": {"provisioningState": "Succeeded",
                          "securityRules": [{}, {}, {}],
                          "subnets": [{"id": SUBNET},
                                      {"id": VNET.replace("vnet-a", "vnet-b") + "/subnets/db"}]}}
    r = az.parse_nsgs([nsg], R)[0]
    assert r["resource_type"] == "network:networkSecurityGroup"
    assert r["key_metric_value"] == 3.0
    assert len(r["attached_vpc_ids"]) == 2  # spans two VNets → both tagged


def test_dns_zone_is_not_measured_with_record_metric():
    z = {"id": "/x/z1", "name": "corp.example.com",
         "properties": {"numberOfRecordSets": 7, "zoneType": "Public"}}
    r = az.parse_dns_zones([z])[0]
    assert r["status"] == "not_measured"
    assert r["key_metric_value"] == 7.0
    assert r["region"] == "global"


def test_vnet_gateway_seam_tagging():
    gw = {"id": "/x/vgw1", "name": "vgw1", "location": R,
          "properties": {"provisioningState": "Succeeded", "gatewayType": "Vpn",
                         "ipConfigurations": [
                             {"properties": {"subnet": {"id": VNET + "/subnets/GatewaySubnet"}}}]}}
    r = az.parse_vnet_gateways([gw], R)[0]
    assert r["resource_type"] == "network:virtualNetworkGateway"
    assert r["status"] == "healthy"
    assert r["vpc_id"] == VNET
    assert r["attached_vpc_ids"] == [VNET]
    assert r["attached_regions"] == [R]


def test_vnet_peering_states_and_endpoints():
    remote = VNET.replace("vnet-a", "vnet-remote")
    vnet = {"id": VNET, "name": "vnet-a", "location": R,
            "properties": {"virtualNetworkPeerings": [
                {"id": VNET + "/virtualNetworkPeerings/p1", "name": "p1",
                 "properties": {"peeringState": "Connected",
                                "remoteVirtualNetwork": {"id": remote}}},
                {"id": VNET + "/virtualNetworkPeerings/p2", "name": "p2",
                 "properties": {"peeringState": "Disconnected",
                                "remoteVirtualNetwork": {"id": remote}}},
            ]}}
    rows = az.parse_vnet_peerings([vnet], R)
    assert [r["status"] for r in rows] == ["healthy", "down"]
    assert sorted(rows[0]["attached_vpc_ids"]) == sorted([VNET, remote])


def test_er_circuit_provisioning_states():
    c = {"id": "/x/er1", "name": "er1", "location": R,
         "properties": {"serviceProviderProvisioningState": "Provisioned",
                        "serviceProviderProperties": {"peeringLocation": "Silicon Valley",
                                                      "bandwidthInMbps": 200}}}
    r = az.parse_er_circuits([c], R)[0]
    assert r["resource_type"] == "network:expressRouteCircuit"
    assert r["status"] == "healthy"
    assert "Silicon Valley" in r["attached_regions"]
    missing = az.parse_er_circuits([{"id": "/x/er2", "name": "er2", "properties": {}}], R)[0]
    assert missing["status"] == "not_measured"


def test_collect_family_isolation():
    """One failing ARM family degrades that family only — the rest still land.
    (403 = non-transient: the retry wrapper re-raises immediately.)"""
    import urllib.error

    def get_json(url: str) -> dict:
        if "loadBalancers" in url:
            raise urllib.error.HTTPError(url, 403, "forbidden", None, None)
        if "virtualNetworks?" in url:
            return {"value": [{"id": VNET, "name": "vnet-a",
                               "properties": {"virtualNetworkPeerings": []}}]}
        if "dnszones" in url:
            return {"value": [{"id": "/x/z", "name": "z.example.",
                               "properties": {"numberOfRecordSets": 1}}]}
        return {"value": []}

    rows, errors = az.collect(get_json, SUB, R)
    assert "load_balancers" in errors
    assert any(r["resource_type"] == "network:dnszone" for r in rows)
