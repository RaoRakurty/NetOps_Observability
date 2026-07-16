"""Cloud discovery — REAL inventory + in-cloud topology from the provider APIs.

Two outputs, both derived from live API reads (never hand-written, never invented):

  1. <FIXTURES_DIR>/aws.json      — the cloud INVENTORY the API serves to Service View
                                    (EC2 instances, their private IPs, ENIs and app tags).
  2. <FIXTURES_DIR>/aws-topology.json — the in-cloud EGRESS TOPOLOGY, derived from the
                                    ROUTE TABLES. Which edge a subnet's traffic actually
                                    leaves by (Internet Gateway / NAT Gateway / an NVA's
                                    ENI / a VPC endpoint) is a FACT recorded in the route
                                    table — so we read it rather than assuming. This is
                                    what lets the RCA path draw "app → cloud edge" for
                                    both the private (IPsec) and internet-bound paths.

The cloud edge for a given destination is whatever the subnet's route table says:
  0.0.0.0/0 -> igw-*   ⇒ Internet Gateway
  0.0.0.0/0 -> nat-*   ⇒ NAT Gateway
  0.0.0.0/0 -> eni-*   ⇒ a network virtual appliance (our strongSwan IPsec NVA)
  <on-prem> -> eni-*   ⇒ the IPsec NVA (the private/tunnelled path)
"""
import datetime as dt
import json
import os

import boto3

import aws_components

REGION = os.environ.get("AWS_REGION", "us-west-2")
# Live snapshots belong in a RUNTIME dir (a gitignored data/ mount), never the
# git-tracked cloud-fixtures. CLOUD_RUNTIME_OUT is the new knob; the legacy
# CLOUD_FIXTURES_OUT keeps existing deployments working unchanged.
FIXTURES_DIR = (os.environ.get("CLOUD_RUNTIME_OUT")
                or os.environ.get("CLOUD_FIXTURES_OUT", "/fixtures"))
# Tag keys the attribution resolver already understands (cloud/resolve.go).
APP_TAG_KEYS = ("app", "application", "app_name", "app-name", "service", "workload")


def _tags(raw) -> dict:
    return {t["Key"]: t["Value"] for t in (raw or [])}


def _pages(client, op: str, key: str, **kw) -> list:
    """Every page of a describe_* call (audit P1-9: single-page reads silently
    truncate inventory past ~1000 objects — truncated inventory is wrong
    attribution, not just missing rows)."""
    return [item for page in client.get_paginator(op).paginate(**kw) for item in page.get(key, [])]


def discover_aws(ec2) -> tuple[dict, dict]:
    vpcs = _pages(ec2, "describe_vpcs", "Vpcs")
    account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]

    subnets = {s["SubnetId"]: s for s in _pages(ec2, "describe_subnets", "Subnets")}
    rts = _pages(ec2, "describe_route_tables", "RouteTables")
    igws = _pages(ec2, "describe_internet_gateways", "InternetGateways")
    nats = _pages(ec2, "describe_nat_gateways", "NatGateways")

    # ENI -> the instance it belongs to, so an eni-* route target resolves to a real
    # appliance node (our NVA) rather than an opaque id.
    eni_owner = {}
    for eni in _pages(ec2, "describe_network_interfaces", "NetworkInterfaces"):
        att = eni.get("Attachment") or {}
        if att.get("InstanceId"):
            eni_owner[eni["NetworkInterfaceId"]] = att["InstanceId"]

    resources, nodes, edges = [], [], []
    instances = {}

    for res in _pages(ec2, "describe_instances", "Reservations"):
        for inst in res["Instances"]:
            if inst["State"]["Name"] in ("terminated", "shutting-down"):
                continue
            tags = _tags(inst.get("Tags"))
            iid = inst["InstanceId"]
            instances[iid] = inst
            resources.append({
                "region": REGION,
                "zone": inst.get("Placement", {}).get("AvailabilityZone", ""),
                "resource_id": iid,
                "resource_arn_or_uri": f"arn:aws:ec2:{REGION}:{account}:instance/{iid}",
                "resource_type": "ec2:instance",
                "resource_name": tags.get("Name", iid),
                # Lifecycle truth: a STOPPED instance is not a broken one. Without
                # this the product cannot tell "you turned it off" from "it died"
                # (audit 2026-07-13, P1-2) — and 2 of 3 lab hosts are stopped.
                "power_state": (inst.get("State") or {}).get("Name", ""),
                # Network context (cloud-network-overview P0): the VPC is the
                # segregation axis — every component carries it, instances too.
                "vpc_id": inst.get("VpcId", ""),
                "subnet_ids": [s for s in [inst.get("SubnetId", "")] if s],
                "instance_type": inst.get("InstanceType", ""),
                "private_ips": [ip for ip in [inst.get("PrivateIpAddress")] if ip],
                "public_ips": [ip for ip in [inst.get("PublicIpAddress")] if ip],
                "network_interface_ids": [n["NetworkInterfaceId"] for n in inst.get("NetworkInterfaces", [])],
                "tags": tags,
                "owner": tags.get("owner", ""),
                "env": tags.get("environment", tags.get("env", "")),
                "source": "cloud_api",
                "confidence": "confirmed" if any(k in tags for k in APP_TAG_KEYS) else "strong",
            })
            nodes.append({
                "id": iid, "kind": "instance", "name": tags.get("Name", iid),
                "subnet_id": inst.get("SubnetId", ""),
                "private_ip": inst.get("PrivateIpAddress", ""),
                "app": next((tags[k] for k in APP_TAG_KEYS if k in tags), ""),
            })

    for igw in igws:
        nodes.append({"id": igw["InternetGatewayId"], "kind": "internet_gateway",
                      "name": _tags(igw.get("Tags")).get("Name", igw["InternetGatewayId"])})
    for nat in nats:
        nodes.append({"id": nat["NatGatewayId"], "kind": "nat_gateway",
                      "name": _tags(nat.get("Tags")).get("Name", nat["NatGatewayId"]),
                      "subnet_id": nat.get("SubnetId", "")})

    # Subnets with NO explicit route-table association implicitly use the VPC's
    # MAIN route table. Collecting only explicit associations left every such
    # subnet with ZERO egress edges — a hole in the path graph exactly where the
    # default route lives (audit 2026-07-13, P1-8).
    explicit = {a["SubnetId"] for rt in rts for a in rt.get("Associations", [])
                if a.get("SubnetId")}
    subnets_by_vpc: dict[str, list[str]] = {}
    for sid, sn in subnets.items():
        subnets_by_vpc.setdefault(sn.get("VpcId", ""), []).append(sid)

    # THE ROUTE TABLES: the authoritative statement of how a subnet egresses.
    for rt in rts:
        rt_id = rt["RouteTableId"]
        rt_name = _tags(rt.get("Tags")).get("Name", rt_id)
        assoc = [a["SubnetId"] for a in rt.get("Associations", []) if a.get("SubnetId")]
        is_main = any(a.get("Main") for a in rt.get("Associations", []))
        if is_main:
            # the main table serves every subnet in the VPC that named no other
            assoc = sorted(set(assoc) | {
                sid for sid in subnets_by_vpc.get(rt.get("VpcId", ""), [])
                if sid not in explicit
            })
        for route in rt.get("Routes", []):
            dst = route.get("DestinationCidrBlock") or route.get("DestinationPrefixListId")
            if not dst:
                continue
            gw = route.get("GatewayId", "") or ""
            target, kind = "", ""
            if gw.startswith("igw-"):
                target, kind = gw, "internet_gateway"
            elif gw.startswith("vpce-"):
                target, kind = gw, "vpc_endpoint"
            # HYBRID EDGES — these were silently dropped. For a product whose
            # story is hybrid connectivity, losing the VPN/Direct-Connect edge
            # meant the path graph had no idea how traffic left for on-prem.
            elif gw.startswith("vgw-"):
                target, kind = gw, "vpn_gateway"          # AWS Site-to-Site VPN / DX
            elif route.get("TransitGatewayId"):
                target, kind = route["TransitGatewayId"], "transit_gateway"
            elif route.get("VpcPeeringConnectionId"):
                target, kind = route["VpcPeeringConnectionId"], "vpc_peering"
            elif route.get("EgressOnlyInternetGatewayId"):
                target, kind = route["EgressOnlyInternetGatewayId"], "egress_only_igw"
            elif route.get("CarrierGatewayId"):
                target, kind = route["CarrierGatewayId"], "carrier_gateway"
            elif route.get("LocalGatewayId"):
                target, kind = route["LocalGatewayId"], "local_gateway"   # Outposts
            elif route.get("NatGatewayId"):
                target, kind = route["NatGatewayId"], "nat_gateway"
            elif route.get("NetworkInterfaceId"):
                eni = route["NetworkInterfaceId"]
                # Resolve the ENI to its instance: an NVA is a real box, not an id.
                target = eni_owner.get(eni, eni)
                kind = "nva"  # network virtual appliance (our IPsec device)
            elif gw == "local":
                continue  # intra-VPC, not an edge
            else:
                continue

            # A BLACKHOLE route means its target is gone and traffic to this CIDR
            # is being silently discarded — a live, actionable fault sitting in a
            # field we already fetch. Carry it; never render it as a working edge.
            state = route.get("State", "active")
            for subnet_id in assoc:
                edges.append({
                    "from_subnet": subnet_id,
                    "from_subnet_name": _tags(subnets.get(subnet_id, {}).get("Tags")).get("Name", subnet_id),
                    "to": target,
                    "to_kind": kind,
                    "destination": dst,
                    "state": state,
                    "via_route_table": rt_id,
                    "route_table_name": rt_name,
                })

    # "collection" = the live-poller provenance stamp (contract pinned by
    # cloud/provider_test.go): the API derives the UI's "Live telemetry" vs
    # "Demo tenant" badge from it — an unstamped file reads as a hand fixture.
    inventory = {
        "provider": "aws", "account_id": account,
        "collection": {"mode": "live_poller",
                       "collected_at": dt.datetime.now(dt.timezone.utc).isoformat()},
        "resources": resources,
    }
    topology = {
        "provider": "aws", "account_id": account, "region": REGION,
        "vpcs": [{"id": v["VpcId"], "cidr": v["CidrBlock"]} for v in vpcs],
        "subnets": [{"id": s_id, "cidr": s["CidrBlock"],
                     "name": _tags(s.get("Tags")).get("Name", s_id)}
                    for s_id, s in subnets.items()],
        "nodes": nodes,
        # Every edge is a ROUTE-TABLE FACT: subnet --(destination)--> egress target.
        "edges": edges,
    }
    return inventory, topology


def write_json(path: str, obj: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def run() -> tuple[int, int]:
    os.makedirs(FIXTURES_DIR, exist_ok=True)
    session = boto3.Session(region_name=REGION)
    ec2 = session.client("ec2", region_name=REGION, config=aws_components.BOTO_CFG)
    inventory, topology = discover_aws(ec2)
    # Network components as first-class resources (P0): LB/WAF/SG/DNS/NAT/IGW +
    # the seam endpoints (VPN/DX/TGW). Per-family isolation inside collect() —
    # a degraded family is logged, the rest of the inventory still lands.
    comp_rows, comp_errors = aws_components.collect(session, REGION,
                                                    inventory.get("account_id", ""))
    inventory["resources"].extend(comp_rows)
    if comp_errors:
        print(json.dumps({"service": "cloud-ingest",
                          "msg": "aws component families degraded",
                          "errors": comp_errors}), flush=True)
    write_json(os.path.join(FIXTURES_DIR, "aws.json"), inventory)
    write_json(os.path.join(FIXTURES_DIR, "aws-topology.json"), topology)
    return len(inventory["resources"]), len(topology["edges"])


def instances_snapshot() -> list[dict]:
    """The discovered EC2 instances (resource_id / name / app / private_ips) —
    what the CloudWatch metric lane polls per-instance metrics for. Read from the
    fixture the run() above just wrote, so there is ONE inventory truth."""
    path = os.path.join(FIXTURES_DIR, "aws.json")
    try:
        with open(path, encoding="utf-8") as fh:
            inv = json.load(fh)
    except (OSError, ValueError):
        return []
    return [r for r in inv.get("resources", [])
            if str(r.get("resource_id", "")).startswith("i-")]


if __name__ == "__main__":
    r, e = run()
    print(json.dumps({"discovered_resources": r, "route_edges": e}))
