"""GCP component-inventory tests (cloud-network-overview P0).

Fixture-driven compute/DNS JSON, no live calls — pins VPC/subnet tagging,
status honesty (unmeasured backend health / unknown states → not_measured,
never green), the per-network firewall-rule roll-up (anti-flood), and the seam
endpoints' tagging (design §4a)."""
from __future__ import annotations

import gcp_components as gc

P = "proj-1"
NET = f"projects/{P}/global/networks/vpc-a"
NET_URL = f"https://www.googleapis.com/compute/v1/{NET}"
SUBNET = f"projects/{P}/regions/us-west1/subnetworks/web"
SUBNET_URL = f"https://www.googleapis.com/compute/v1/{SUBNET}"


def test_forwarding_rule_network_tagging_and_no_fake_health():
    items = {"regions/us-west1": {"forwardingRules": [
        {"name": "fr-1", "loadBalancingScheme": "INTERNAL", "IPAddress": "10.0.0.5",
         "network": NET_URL, "subnetwork": SUBNET_URL, "target": ""}]}}
    r = gc.parse_forwarding_rules(items, P)[0]
    assert r["resource_type"] == "compute:forwardingRule"
    assert r["region"] == "us-west1"
    assert r["vpc_id"] == NET
    assert r["subnet_ids"] == [SUBNET]
    assert r["status"] == "not_measured"
    assert r["private_ips"] == ["10.0.0.5"]  # INTERNAL scheme → private


def test_backend_service_health_rollup():
    items = {"global": {"backendServices": [
        {"name": "bs-1", "protocol": "HTTP", "network": NET_URL},
        {"name": "bs-2", "protocol": "HTTP"}]}}
    rid1 = f"projects/{P}/global/backendServices/bs-1"
    rows = gc.parse_backend_services(items, {rid1: (2, 2)}, P)
    by_name = {r["resource_name"]: r for r in rows}
    assert by_name["bs-1"]["status"] == "healthy"
    assert by_name["bs-1"]["key_metric_value"] == 2.0
    assert by_name["bs-1"]["vpc_id"] == NET
    # No getHealth read this cycle → honestly not_measured, metric absent.
    assert by_name["bs-2"]["status"] == "not_measured"
    assert "key_metric_name" not in by_name["bs-2"]


def test_backend_service_all_unhealthy_is_down():
    items = {"global": {"backendServices": [{"name": "bs-1"}]}}
    rid = f"projects/{P}/global/backendServices/bs-1"
    assert gc.parse_backend_services(items, {rid: (0, 3)}, P)[0]["status"] == "down"


def test_backend_health_bounded_by_cap():
    calls = []

    def post_json(url, body):
        calls.append(url)
        return {"healthStatus": [{"healthState": "HEALTHY"}]}

    items = {"global": {"backendServices": [
        {"name": f"bs-{i}", "backends": [{"group": "g1"}, {"group": "g2"}]}
        for i in range(10)]}}
    out = gc.backend_health(post_json, items, P, cap=5)
    assert len(calls) == 5                       # never more than the cap
    assert len(out) <= 10


def test_firewall_rules_roll_up_to_one_row_per_network():
    fws = ([{"name": f"allow-{i}", "network": NET_URL} for i in range(40)]
           + [{"name": "deny-x", "network": NET_URL.replace("vpc-a", "vpc-b"),
               "disabled": True}])
    rows = gc.parse_firewall_rulesets(fws, P)
    assert len(rows) == 2                        # anti-flood: per network, not per rule
    by_vpc = {r["vpc_id"]: r for r in rows}
    assert by_vpc[NET]["key_metric_value"] == 40.0
    assert by_vpc[NET]["status"] == "not_measured"
    assert by_vpc[NET.replace("vpc-a", "vpc-b")]["attrs"]["disabled_rules"] == "1"


def test_cloud_armor_policy_rule_count():
    r = gc.parse_security_policies([{"name": "edge-policy", "rules": [{}, {}]}], P)[0]
    assert r["resource_type"] == "compute:securityPolicy"
    assert r["status"] == "not_measured"
    assert r["key_metric_value"] == 2.0


def test_dns_zone_private_networks_tagged():
    z = {"name": "corp", "dnsName": "corp.example.", "visibility": "private",
         "privateVisibilityConfig": {"networks": [
             {"networkUrl": NET_URL},
             {"networkUrl": NET_URL.replace("vpc-a", "vpc-b")}]}}
    r = gc.parse_dns_zones([z], P)[0]
    assert r["resource_type"] == "dns:managedZone"
    assert r["status"] == "not_measured"
    assert r["vpc_id"] == NET
    assert len(r["attached_vpc_ids"]) == 2


def test_router_bgp_rollup_and_nat_rows():
    items = {"regions/us-west1": {"routers": [
        {"name": "rtr-1", "network": NET_URL,
         "nats": [{"name": "nat-1"}]}]}}
    rid = f"projects/{P}/regions/us-west1/routers/rtr-1"
    rows = gc.parse_routers(items, {rid: ["up", "down"]}, P)
    by_type = {r["resource_type"]: r for r in rows}
    assert by_type["compute:router"]["status"] == "degraded"   # 1/2 peers up
    assert by_type["compute:router"]["key_metric_value"] == 1.0
    assert by_type["compute:cloudNat"]["status"] == "not_measured"
    assert by_type["compute:cloudNat"]["vpc_id"] == NET
    # Router not read this cycle → honestly not_measured.
    unread = gc.parse_routers(items, {}, P)
    assert unread[0]["status"] == "not_measured"


def test_vpn_tunnel_states_and_seam_tagging():
    items = {"regions/us-west1": {"vpnTunnels": [
        {"name": "t-up", "status": "ESTABLISHED", "peerIp": "9.9.9.9"},
        {"name": "t-down", "status": "NEGOTIATION_FAILURE",
         "detailedStatus": "peer did not respond"},
        {"name": "t-new", "status": "SOME_FUTURE_STATE"}]}}
    rows = gc.parse_vpn_tunnels(items, P)
    by_name = {r["resource_name"]: r for r in rows}
    assert by_name["t-up"]["status"] == "healthy"
    assert by_name["t-down"]["status"] == "down"
    assert "peer did not respond" in by_name["t-down"]["status_reason"]
    assert by_name["t-new"]["status"] == "not_measured"  # unknown state ≠ green
    assert by_name["t-up"]["attached_regions"] == ["us-west1"]


def test_vpn_gateway_is_seam_endpoint():
    items = {"regions/us-west1": {"vpnGateways": [{"name": "gw-1", "network": NET_URL}]}}
    r = gc.parse_vpn_gateways(items, P)[0]
    assert r["attached_vpc_ids"] == [NET]
    assert r["status"] == "not_measured"        # the tunnels carry the state


def test_vpc_peering_endpoints():
    nets = [{"name": "vpc-a", "peerings": [
        {"name": "to-b", "state": "ACTIVE",
         "network": NET_URL.replace("vpc-a", "vpc-b")},
        {"name": "to-c", "state": "INACTIVE",
         "network": NET_URL.replace("vpc-a", "vpc-c")}]}]
    rows = gc.parse_vpc_peerings(nets, P)
    assert [r["status"] for r in rows] == ["healthy", "down"]
    assert NET in rows[0]["attached_vpc_ids"]
    assert NET.replace("vpc-a", "vpc-b") in rows[0]["attached_vpc_ids"]


def test_collect_family_isolation():
    """One failing API family degrades that family only (403 → no retries)."""
    import urllib.error

    def get_json(url: str) -> dict:
        if "forwardingRules" in url:
            raise urllib.error.HTTPError(url, 403, "forbidden", None, None)
        if "/global/networks" in url and "managedZones" not in url:
            return {"items": [{"name": "vpc-a", "peerings": [
                {"name": "p", "state": "ACTIVE", "network": NET_URL}]}]}
        if "managedZones" in url:
            return {"managedZones": [{"name": "z", "dnsName": "z.example."}]}
        return {}

    def post_json(url, body):
        raise AssertionError("no backend services → no getHealth calls")

    rows, errors = gc.collect(get_json, post_json, P)
    assert "forwarding_rules" in errors
    assert any(r["resource_type"] == "dns:managedZone" for r in rows)
    assert any(r["resource_type"] == "compute:vpcPeering" for r in rows)
