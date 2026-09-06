# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""AWS network-component inventory (cloud-network-overview P0, design §5+§4a).

Extends discovery beyond ec2:instance to every network component, one row per
component with provider · region · VPC · subnet · type · status · the type's
key metric. Pure parse functions (fixture-testable, no live calls) over a
collect() orchestrator with per-family isolation: one family failing degrades
that family only, never the poll cycle.

STATUS SOURCES (real provider signals only — never a default):
  load balancer   LB State.Code + describe_target_health roll-up
  NAT gateway     NatGateway.State (+ FailureMessage)
  internet GW     attachment state (detached is honestly not_measured, not down)
  VPN connection  per-tunnel VgwTelemetry (reused from seam_aws.discover_seams)
  VPN gateway     VpnGateway.State
  DX connection   connectionState (reused from seam_aws.discover_seams)
  transit GW      TransitGateway.State; attachments: their own State
  WAF / SG / R53  no health signal exists → not_measured (unknown ≠ green)

SEAM ENDPOINTS (§4a): VPN/DX/TGW rows carry attached_vpc_ids/attached_regions
so lateral links are discoverable, not assumed.
"""
from __future__ import annotations

from botocore.config import Config

import seam_aws
from components_common import (DEGRADED, DOWN, HEALTHY, NOT_MEASURED, PAGE_CAP,
                               component_row, truncate)

# Bounded + resilient boto3 posture (CLAUDE.md §9): explicit connect/read
# timeouts, standard-mode retries (exponential backoff + jitter built in).
BOTO_CFG = Config(connect_timeout=10, read_timeout=25,
                  retries={"max_attempts": 3, "mode": "standard"})


def _tags(raw) -> dict:
    return {t["Key"]: t["Value"] for t in (raw or [])}


def _pages(client, op: str, key: str, **kw) -> list:
    """Page-capped describe (inventory, never an unbounded read).

    Falls back to a single direct call when the operation has NO paginator.

    Audit F-41, observed live for 167 consecutive cycles:
        "aws component families degraded"
        {"seam_endpoints": "Operation cannot be paginated: describe_vpn_gateways"}

    ec2:DescribeVpnGateways is one of the handful of EC2 operations botocore
    does not model as pageable (it returns the full set in one response and has
    no NextToken), so get_paginator() raises OperationNotPageableError before a
    single request goes out. The seam_endpoints family therefore produced ZERO
    rows on every cycle since it shipped — VPN gateways, VPN connections, DX
    connections and transit gateways were all missing from the inventory — and
    the only symptom was a log line nothing alerted on.

    can_paginate() is botocore's own answer to "is this op pageable", so this
    stays correct for every other operation and for any future one.
    """
    can_paginate = getattr(client, "can_paginate", None)
    if can_paginate is not None and not can_paginate(op):
        resp = getattr(client, op)(**kw)
        return list(resp.get(key, []))
    out: list = []
    for i, page in enumerate(client.get_paginator(op).paginate(**kw)):
        if i >= PAGE_CAP:
            break
        out.extend(page.get(key, []))
    return out


# ── load balancers + target health ───────────────────────────────────────────

def parse_load_balancers(lbs: list, tg_health: dict, region: str) -> list:
    """One row per ELBv2 load balancer. tg_health maps LoadBalancerArn →
    (healthy, total) target counts, absent when target health could not be
    read — in which case the row's status comes from the LB state alone and
    the key metric is honestly absent."""
    rows = []
    for lb in lbs:
        arn = lb.get("LoadBalancerArn", "")
        state = str((lb.get("State") or {}).get("Code", "")).lower()
        azs = lb.get("AvailabilityZones") or []
        health = tg_health.get(arn)
        if health is not None:
            healthy, total = health
            if total == 0:
                status, reason = DEGRADED, f"state={state}; no registered targets"
            elif healthy == total:
                status, reason = HEALTHY, f"state={state}; targets {healthy}/{total} healthy"
            elif healthy == 0:
                status, reason = DOWN, f"state={state}; all {total} targets unhealthy"
            else:
                status, reason = DEGRADED, f"state={state}; targets {healthy}/{total} healthy"
            if state == "failed":
                status, reason = DOWN, f"state={state}"
            metric = ("healthy_targets", healthy, "targets")
        else:
            status = {"active": HEALTHY, "failed": DOWN,
                      "provisioning": DEGRADED, "active_impaired": DEGRADED}.get(state, NOT_MEASURED)
            reason = f"state={state}; target health not measured" if state else "no state returned"
            metric = None
        rows.append(component_row(
            region=region, resource_id=arn, arn_or_uri=arn,
            resource_type="elbv2:loadbalancer",
            resource_name=lb.get("LoadBalancerName", ""),
            vpc_id=lb.get("VpcId", ""),
            subnet_ids=[a.get("SubnetId", "") for a in azs],
            status=status, status_reason=reason, key_metric=metric,
            attrs={"lb_type": lb.get("Type", ""), "scheme": lb.get("Scheme", ""),
                   "dns_name": lb.get("DNSName", "")}))
    return truncate(rows, "elbv2:loadbalancer")


def target_health_by_lb(elbv2) -> dict:
    """LoadBalancerArn → (healthy, total) across the LB's target groups.
    Bounded (page caps); a failing target-group read drops only that group."""
    counts: dict[str, list[int]] = {}
    for tg in _pages(elbv2, "describe_target_groups", "TargetGroups"):
        lbs = tg.get("LoadBalancerArns") or []
        if not lbs:
            continue
        try:
            ths = elbv2.describe_target_health(
                TargetGroupArn=tg["TargetGroupArn"]).get("TargetHealthDescriptions", [])
        except Exception:  # noqa: BLE001 - one TG's failure = that TG unmeasured, not fabricated
            continue
        healthy = sum(1 for t in ths
                      if str((t.get("TargetHealth") or {}).get("State", "")).lower() == "healthy")
        for arn in lbs:
            c = counts.setdefault(arn, [0, 0])
            c[0] += healthy
            c[1] += len(ths)
    return {arn: (c[0], c[1]) for arn, c in counts.items()}


# ── WAF web ACLs ─────────────────────────────────────────────────────────────

def parse_web_acls(acls: list, region: str, scope: str) -> list:
    """WAF has no health signal — every row is honestly not_measured."""
    rows = []
    for a in acls:
        rows.append(component_row(
            region="global" if scope == "CLOUDFRONT" else region,
            resource_id=a.get("ARN", "") or a.get("Id", ""),
            arn_or_uri=a.get("ARN", ""),
            resource_type="wafv2:webacl", resource_name=a.get("Name", ""),
            status=NOT_MEASURED, status_reason="WAF exposes no health signal",
            attrs={"waf_scope": scope.lower()}))
    return truncate(rows, "wafv2:webacl")


# ── security groups ──────────────────────────────────────────────────────────

def parse_security_groups(sgs: list, region: str, account: str = "") -> list:
    rows = []
    for sg in sgs:
        gid = sg.get("GroupId", "")
        n_rules = len(sg.get("IpPermissions") or []) + len(sg.get("IpPermissionsEgress") or [])
        rows.append(component_row(
            region=region, resource_id=gid,
            arn_or_uri=f"arn:aws:ec2:{region}:{account}:security-group/{gid}" if account else gid,
            resource_type="ec2:securitygroup",
            resource_name=_tags(sg.get("Tags")).get("Name", sg.get("GroupName", "")),
            vpc_id=sg.get("VpcId", ""),
            status=NOT_MEASURED, status_reason="security groups expose no health signal",
            key_metric=("rule_count", n_rules, "rules"),
            tags=_tags(sg.get("Tags"))))
    return truncate(rows, "ec2:securitygroup")


# ── Route 53 hosted zones ────────────────────────────────────────────────────

def parse_hosted_zones(zones: list) -> list:
    rows = []
    for z in zones:
        zid = str(z.get("Id", "")).rsplit("/", 1)[-1]
        cfg = z.get("Config") or {}
        rows.append(component_row(
            region="global", resource_id=zid,
            resource_type="route53:hostedzone", resource_name=z.get("Name", ""),
            status=NOT_MEASURED, status_reason="hosted zones expose no health signal",
            key_metric=("record_count", int(z.get("ResourceRecordSetCount", 0) or 0), "records"),
            attrs={"private_zone": str(bool(cfg.get("PrivateZone", False))).lower()}))
    return truncate(rows, "route53:hostedzone")


# ── NAT / Internet gateways ──────────────────────────────────────────────────

def parse_nat_gateways(nats: list, region: str) -> list:
    rows = []
    for n in nats:
        state = str(n.get("State", "")).lower()
        if state in ("deleted", "deleting"):
            continue
        status = {"available": HEALTHY, "pending": DEGRADED, "failed": DOWN}.get(state, NOT_MEASURED)
        reason = f"state={state}"
        if n.get("FailureMessage"):
            reason += f"; {n['FailureMessage']}"
        rows.append(component_row(
            region=region, resource_id=n.get("NatGatewayId", ""),
            resource_type="ec2:natgateway",
            resource_name=_tags(n.get("Tags")).get("Name", n.get("NatGatewayId", "")),
            vpc_id=n.get("VpcId", ""), subnet_ids=[n.get("SubnetId", "")],
            status=status, status_reason=reason,
            public_ips=[a.get("PublicIp", "") for a in n.get("NatGatewayAddresses") or []],
            tags=_tags(n.get("Tags"))))
    return truncate(rows, "ec2:natgateway")


def parse_internet_gateways(igws: list, region: str) -> list:
    rows = []
    for g in igws:
        atts = [a for a in (g.get("Attachments") or []) if a.get("VpcId")]
        attached = [a["VpcId"] for a in atts if str(a.get("State", "")).lower() in ("available", "attached")]
        if attached:
            status, reason = HEALTHY, f"attached to {', '.join(attached)}"
        else:
            # detached ≠ broken; it is also not measured-healthy.
            status, reason = NOT_MEASURED, "not attached to any VPC"
        rows.append(component_row(
            region=region, resource_id=g.get("InternetGatewayId", ""),
            resource_type="ec2:internetgateway",
            resource_name=_tags(g.get("Tags")).get("Name", g.get("InternetGatewayId", "")),
            vpc_id=attached[0] if attached else "",
            status=status, status_reason=reason,
            attached_vpc_ids=attached, tags=_tags(g.get("Tags"))))
    return truncate(rows, "ec2:internetgateway")


# ── seam endpoints: VPN / DX / TGW (design §4a) ──────────────────────────────

def parse_vpn_gateways(vgws: list, region: str) -> list:
    rows = []
    for g in vgws:
        state = str(g.get("State", "")).lower()
        if state in ("deleted", "deleting"):
            continue
        attached = [a.get("VpcId", "") for a in (g.get("VpcAttachments") or [])
                    if str(a.get("State", "")).lower() == "attached"]
        rows.append(component_row(
            region=region, resource_id=g.get("VpnGatewayId", ""),
            resource_type="ec2:vpngateway",
            resource_name=_tags(g.get("Tags")).get("Name", g.get("VpnGatewayId", "")),
            status=HEALTHY if state == "available" else (DEGRADED if state == "pending" else NOT_MEASURED),
            status_reason=f"state={state}",
            attached_vpc_ids=attached, attached_regions=[region],
            vpc_id=attached[0] if attached else "",
            tags=_tags(g.get("Tags"))))
    return truncate(rows, "ec2:vpngateway")


def parse_vpn_connections(seams: dict, region: str, vgw_vpc: dict | None = None) -> list:
    """VPN connections from seam_aws.discover_seams() output — the SAME
    per-tunnel VgwTelemetry truth the seam lane tracks (one seam model, reused,
    never a parallel one). Status = tunnel roll-up: all up → healthy, some →
    degraded, none → down; no telemetry → not_measured."""
    rows = []
    vgw_vpc = vgw_vpc or {}
    for v in seams.get("vpn", []):
        tunnels = v.get("tunnels") or []
        up = sum(1 for t in tunnels if t.get("status") == "up")
        if not tunnels:
            status, reason, metric = NOT_MEASURED, "no tunnel telemetry returned", None
        elif up == len(tunnels):
            status, reason = HEALTHY, f"tunnels {up}/{len(tunnels)} up"
            metric = ("tunnels_up", up, "tunnels")
        elif up == 0:
            status, reason = DOWN, f"all {len(tunnels)} tunnels down"
            metric = ("tunnels_up", up, "tunnels")
        else:
            status, reason = DEGRADED, f"tunnels {up}/{len(tunnels)} up"
            metric = ("tunnels_up", up, "tunnels")
        attached = [x for x in (v.get("tgw_id", ""), v.get("vgw_id", ""),
                                vgw_vpc.get(v.get("vgw_id", ""), "")) if x]
        rows.append(component_row(
            region=region, resource_id=v.get("vpn_id", ""),
            resource_type="ec2:vpnconnection", resource_name=v.get("vpn_id", ""),
            status=status, status_reason=reason, key_metric=metric,
            attached_vpc_ids=[vgw_vpc.get(v.get("vgw_id", ""), "")],
            attached_regions=[region],
            attrs={"tgw_id": v.get("tgw_id", ""), "vgw_id": v.get("vgw_id", ""),
                   "cgw_id": v.get("cgw_id", "")}))
    return truncate(rows, "ec2:vpnconnection")


def parse_dx_connections(seams: dict, region: str) -> list:
    rows = []
    for c in seams.get("dx_connections", []):
        state = c.get("state", "")
        status = {"available": HEALTHY, "down": DOWN,
                  "ordering": DEGRADED, "requested": DEGRADED, "pending": DEGRADED}.get(
                      state, NOT_MEASURED)
        rows.append(component_row(
            region=region, resource_id=c.get("connection_id", ""),
            resource_type="directconnect:connection",
            resource_name=c.get("connection_id", ""),
            status=status, status_reason=f"connectionState={state}" if state else "no state returned",
            attached_regions=[region],
            attrs={"bandwidth": c.get("bandwidth", ""), "hosted": str(c.get("hosted", False)).lower()}))
    return truncate(rows, "directconnect:connection")


def parse_transit_gateways(tgws: list, attachments: list, region: str) -> list:
    """TGWs + their attachments. Each attachment is tagged with the VPC it
    joins (ResourceType=vpc), so the lateral links are discoverable (§4a)."""
    rows = []
    att_vpcs: dict[str, list[str]] = {}
    for a in attachments:
        if str(a.get("ResourceType", "")).lower() == "vpc" and a.get("ResourceId"):
            att_vpcs.setdefault(a.get("TransitGatewayId", ""), []).append(a["ResourceId"])
    for g in tgws:
        state = str(g.get("State", "")).lower()
        if state in ("deleted", "deleting"):
            continue
        tid = g.get("TransitGatewayId", "")
        rows.append(component_row(
            region=region, resource_id=tid,
            resource_type="ec2:transitgateway",
            resource_name=_tags(g.get("Tags")).get("Name", tid),
            status=HEALTHY if state == "available" else (
                DEGRADED if state in ("pending", "modifying") else NOT_MEASURED),
            status_reason=f"state={state}",
            attached_vpc_ids=att_vpcs.get(tid, []), attached_regions=[region],
            key_metric=("attachments", len([a for a in attachments
                                            if a.get("TransitGatewayId") == tid]), "attachments"),
            tags=_tags(g.get("Tags"))))
    for a in attachments:
        state = str(a.get("State", "")).lower()
        if state in ("deleted", "deleting"):
            continue
        rows.append(component_row(
            region=region, resource_id=a.get("TransitGatewayAttachmentId", ""),
            resource_type="ec2:tgw-attachment",
            resource_name=_tags(a.get("Tags")).get("Name", a.get("TransitGatewayAttachmentId", "")),
            status=HEALTHY if state == "available" else (
                DOWN if state == "failed" else
                DEGRADED if state in ("pending", "initiating", "modifying") else NOT_MEASURED),
            status_reason=f"state={state}",
            vpc_id=a.get("ResourceId", "") if str(a.get("ResourceType", "")).lower() == "vpc" else "",
            attached_vpc_ids=[a["ResourceId"]] if str(a.get("ResourceType", "")).lower() == "vpc"
            and a.get("ResourceId") else [],
            attached_regions=[region],
            attrs={"tgw_id": a.get("TransitGatewayId", ""),
                   "attachment_type": a.get("ResourceType", "")},
            tags=_tags(a.get("Tags"))))
    return truncate(rows, "ec2:transitgateway")


# ── orchestrator ─────────────────────────────────────────────────────────────

def collect(session, region: str, account: str = "") -> tuple[list, dict]:
    """All AWS network-component rows for one region. Per-family isolation:
    a family that fails is recorded in errors and skipped — the rest of the
    inventory (and the poll cycle) survives. Returns (rows, errors)."""
    rows: list = []
    errors: dict = {}

    def family(name: str, fn) -> None:
        try:
            rows.extend(fn())
        except Exception as exc:  # noqa: BLE001 - family isolation
            errors[name] = str(exc)[:160]

    ec2 = session.client("ec2", region_name=region, config=BOTO_CFG)
    elbv2 = session.client("elbv2", region_name=region, config=BOTO_CFG)

    family("load_balancers", lambda: parse_load_balancers(
        _pages(elbv2, "describe_load_balancers", "LoadBalancers"),
        target_health_by_lb(elbv2), region))
    family("security_groups", lambda: parse_security_groups(
        _pages(ec2, "describe_security_groups", "SecurityGroups"), region, account))
    family("nat_gateways", lambda: parse_nat_gateways(
        _pages(ec2, "describe_nat_gateways", "NatGateways"), region))
    family("internet_gateways", lambda: parse_internet_gateways(
        _pages(ec2, "describe_internet_gateways", "InternetGateways"), region))

    def _wafs() -> list:
        waf = session.client("wafv2", region_name=region, config=BOTO_CFG)
        out = parse_web_acls(waf.list_web_acls(Scope="REGIONAL").get("WebACLs", []),
                             region, "REGIONAL")
        if region == "us-east-1":  # CLOUDFRONT scope only exists in us-east-1
            out += parse_web_acls(waf.list_web_acls(Scope="CLOUDFRONT").get("WebACLs", []),
                                  region, "CLOUDFRONT")
        return out
    family("waf_web_acls", _wafs)

    def _zones() -> list:
        r53 = session.client("route53", region_name=region, config=BOTO_CFG)
        zones, marker = [], None
        for _ in range(PAGE_CAP):
            kw = {"Marker": marker} if marker else {}
            resp = r53.list_hosted_zones(**kw)
            zones.extend(resp.get("HostedZones", []))
            if not resp.get("IsTruncated"):
                break
            marker = resp.get("NextMarker")
        return parse_hosted_zones(zones)
    family("route53_zones", _zones)

    # Seam endpoints — reuse the seam lane's discovery (one seam model, §4a).
    def _seams() -> list:
        seams = seam_aws.discover_seams(session)
        vgws = _pages(ec2, "describe_vpn_gateways", "VpnGateways")
        vgw_vpc = {g.get("VpnGatewayId", ""): next(
            (a.get("VpcId", "") for a in (g.get("VpcAttachments") or [])
             if str(a.get("State", "")).lower() == "attached"), "") for g in vgws}
        tgws = _pages(ec2, "describe_transit_gateways", "TransitGateways")
        atts = _pages(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments")
        return (parse_vpn_gateways(vgws, region)
                + parse_vpn_connections(seams, region, vgw_vpc)
                + parse_dx_connections(seams, region)
                + parse_transit_gateways(tgws, atts, region))
    family("seam_endpoints", _seams)

    return rows, errors
