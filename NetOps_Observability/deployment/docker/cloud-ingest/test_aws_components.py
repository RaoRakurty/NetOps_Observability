"""AWS component-inventory tests (cloud-network-overview P0).

Fixture-driven, no live cloud calls — pins the parse contract for every new
component family: VPC/subnet tagging, STATUS HONESTY (a missing provider
signal is not_measured, NEVER healthy), the type's key metric, and the seam
endpoints' attached-VPC/region tagging (design §4a)."""
from __future__ import annotations

import aws_components as ac
from components_common import component_row

R = "us-west-2"


# ── load balancers ────────────────────────────────────────────────────────────

LB = {
    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-west-2:1:loadbalancer/app/web/abc",
    "LoadBalancerName": "web",
    "State": {"Code": "active"},
    "VpcId": "vpc-1",
    "Type": "application",
    "Scheme": "internet-facing",
    "DNSName": "web-1.elb.amazonaws.com",
    "AvailabilityZones": [{"SubnetId": "subnet-a"}, {"SubnetId": "subnet-b"}],
}


def test_lb_healthy_when_all_targets_healthy():
    rows = ac.parse_load_balancers([LB], {LB["LoadBalancerArn"]: (3, 3)}, R)
    r = rows[0]
    assert r["resource_type"] == "elbv2:loadbalancer"
    assert r["status"] == "healthy"
    assert "3/3" in r["status_reason"]
    assert r["vpc_id"] == "vpc-1"
    assert r["subnet_ids"] == ["subnet-a", "subnet-b"]
    assert (r["key_metric_name"], r["key_metric_value"], r["key_metric_unit"]) == \
        ("healthy_targets", 3.0, "targets")


def test_lb_degraded_and_down_from_target_health():
    assert ac.parse_load_balancers([LB], {LB["LoadBalancerArn"]: (1, 3)}, R)[0]["status"] == "degraded"
    assert ac.parse_load_balancers([LB], {LB["LoadBalancerArn"]: (0, 3)}, R)[0]["status"] == "down"


def test_lb_without_target_health_uses_state_only_and_omits_metric():
    r = ac.parse_load_balancers([LB], {}, R)[0]
    assert r["status"] == "healthy"  # LB State.Code=active is a real signal
    assert "target health not measured" in r["status_reason"]
    assert "key_metric_name" not in r  # absence stays absence, never zero


def test_lb_unknown_state_is_not_measured_never_green():
    lb = dict(LB, State={"Code": "some-new-state"})
    r = ac.parse_load_balancers([lb], {}, R)[0]
    assert r["status"] == "not_measured"


# ── WAF / SG / Route 53: no health signal → not_measured ─────────────────────

def test_waf_is_not_measured():
    r = ac.parse_web_acls([{"ARN": "arn:waf/acl1", "Name": "edge-acl", "Id": "x"}],
                          R, "REGIONAL")[0]
    assert r["resource_type"] == "wafv2:webacl"
    assert r["status"] == "not_measured"
    assert r["attrs"]["waf_scope"] == "regional"


def test_waf_cloudfront_scope_is_global_region():
    r = ac.parse_web_acls([{"ARN": "a", "Name": "n"}], "us-east-1", "CLOUDFRONT")[0]
    assert r["region"] == "global"


def test_security_group_rule_count_and_vpc():
    sg = {"GroupId": "sg-1", "GroupName": "web-sg", "VpcId": "vpc-1",
          "IpPermissions": [{}, {}], "IpPermissionsEgress": [{}],
          "Tags": [{"Key": "app", "Value": "shop"}]}
    r = ac.parse_security_groups([sg], R, "123")[0]
    assert r["resource_type"] == "ec2:securitygroup"
    assert r["vpc_id"] == "vpc-1"
    assert r["status"] == "not_measured"
    assert r["key_metric_value"] == 3.0
    assert r["confidence"] == "confirmed"  # app tag honoured like instances


def test_hosted_zone_record_count():
    z = {"Id": "/hostedzone/Z123", "Name": "corp.example.",
         "ResourceRecordSetCount": 14, "Config": {"PrivateZone": True}}
    r = ac.parse_hosted_zones([z])[0]
    assert r["resource_id"] == "Z123"
    assert r["region"] == "global"
    assert r["status"] == "not_measured"
    assert r["key_metric_value"] == 14.0
    assert r["attrs"]["private_zone"] == "true"


# ── NAT / IGW ─────────────────────────────────────────────────────────────────

def test_nat_gateway_states():
    base = {"NatGatewayId": "nat-1", "VpcId": "vpc-1", "SubnetId": "subnet-a",
            "NatGatewayAddresses": [{"PublicIp": "3.3.3.3"}]}
    assert ac.parse_nat_gateways([dict(base, State="available")], R)[0]["status"] == "healthy"
    failed = ac.parse_nat_gateways(
        [dict(base, State="failed", FailureMessage="port exhaustion")], R)[0]
    assert failed["status"] == "down"
    assert "port exhaustion" in failed["status_reason"]
    assert failed["vpc_id"] == "vpc-1" and failed["subnet_ids"] == ["subnet-a"]
    assert ac.parse_nat_gateways([dict(base, State="deleted")], R) == []


def test_igw_detached_is_not_measured_not_down():
    attached = {"InternetGatewayId": "igw-1",
                "Attachments": [{"VpcId": "vpc-1", "State": "available"}]}
    detached = {"InternetGatewayId": "igw-2", "Attachments": []}
    ra = ac.parse_internet_gateways([attached], R)[0]
    rd = ac.parse_internet_gateways([detached], R)[0]
    assert ra["status"] == "healthy" and ra["attached_vpc_ids"] == ["vpc-1"]
    assert rd["status"] == "not_measured"
    assert "not attached" in rd["status_reason"]


# ── seam endpoints (§4a) ──────────────────────────────────────────────────────

SEAMS = {
    "vpn": [{"vpn_id": "vpn-1", "tgw_id": "tgw-1", "vgw_id": "vgw-1", "cgw_id": "cgw-1",
             "tunnels": [{"outside_ip": "1.1.1.1", "status": "up"},
                         {"outside_ip": "2.2.2.2", "status": "down"}]},
            {"vpn_id": "vpn-2", "tgw_id": "", "vgw_id": "vgw-2", "cgw_id": "cgw-2",
             "tunnels": []}],
    "dx_connections": [{"connection_id": "dxcon-1", "state": "available",
                        "bandwidth": "1Gbps", "hosted": False}],
}


def test_vpn_connection_tunnel_rollup_and_seam_tagging():
    rows = ac.parse_vpn_connections(SEAMS, R, {"vgw-1": "vpc-9"})
    by_id = {r["resource_id"]: r for r in rows}
    one = by_id["vpn-1"]
    assert one["resource_type"] == "ec2:vpnconnection"
    assert one["status"] == "degraded"          # 1/2 tunnels up
    assert one["key_metric_value"] == 1.0
    assert one["attached_vpc_ids"] == ["vpc-9"]  # the VPC the seam joins
    assert one["attached_regions"] == [R]
    # No tunnel telemetry → not_measured, never green.
    assert by_id["vpn-2"]["status"] == "not_measured"
    assert "key_metric_name" not in by_id["vpn-2"]


def test_dx_connection_state():
    r = ac.parse_dx_connections(SEAMS, R)[0]
    assert r["resource_type"] == "directconnect:connection"
    assert r["status"] == "healthy"
    assert r["attached_regions"] == [R]


def test_vpn_gateway_attachments():
    vgw = {"VpnGatewayId": "vgw-1", "State": "available",
           "VpcAttachments": [{"VpcId": "vpc-1", "State": "attached"},
                              {"VpcId": "vpc-2", "State": "detaching"}]}
    r = ac.parse_vpn_gateways([vgw], R)[0]
    assert r["status"] == "healthy"
    assert r["attached_vpc_ids"] == ["vpc-1"]  # only the attached one


def test_tgw_and_attachments_tag_joined_vpcs():
    tgws = [{"TransitGatewayId": "tgw-1", "State": "available"}]
    atts = [{"TransitGatewayAttachmentId": "tgw-attach-1", "TransitGatewayId": "tgw-1",
             "ResourceType": "vpc", "ResourceId": "vpc-1", "State": "available"},
            {"TransitGatewayAttachmentId": "tgw-attach-2", "TransitGatewayId": "tgw-1",
             "ResourceType": "vpn", "ResourceId": "vpn-1", "State": "failed"}]
    rows = ac.parse_transit_gateways(tgws, atts, R)
    by_id = {r["resource_id"]: r for r in rows}
    assert by_id["tgw-1"]["attached_vpc_ids"] == ["vpc-1"]
    assert by_id["tgw-1"]["key_metric_value"] == 2.0
    assert by_id["tgw-attach-1"]["status"] == "healthy"
    assert by_id["tgw-attach-1"]["vpc_id"] == "vpc-1"
    assert by_id["tgw-attach-2"]["status"] == "down"
    assert by_id["tgw-attach-2"]["attrs"]["attachment_type"] == "vpn"


# ── schema guard ──────────────────────────────────────────────────────────────

def test_component_row_rejects_invented_status():
    r = component_row(region=R, resource_id="x", resource_type="t",
                      status="totally-fine")
    assert r["status"] == "not_measured"  # unknown vocabulary never reads green
