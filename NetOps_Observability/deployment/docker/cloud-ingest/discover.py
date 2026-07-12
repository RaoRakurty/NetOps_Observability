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
import json
import os

import boto3

REGION = os.environ.get("AWS_REGION", "us-west-2")
FIXTURES_DIR = os.environ.get("CLOUD_FIXTURES_OUT", "/fixtures")
# Tag keys the attribution resolver already understands (cloud/resolve.go).
APP_TAG_KEYS = ("app", "application", "app_name", "app-name", "service", "workload")


def _tags(raw) -> dict:
    return {t["Key"]: t["Value"] for t in (raw or [])}


def discover_aws(ec2) -> tuple[dict, dict]:
    vpcs = ec2.describe_vpcs()["Vpcs"]
    account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]

    subnets = {s["SubnetId"]: s for s in ec2.describe_subnets()["Subnets"]}
    rts = ec2.describe_route_tables()["RouteTables"]
    igws = ec2.describe_internet_gateways()["InternetGateways"]
    nats = ec2.describe_nat_gateways().get("NatGateways", [])

    # ENI -> the instance it belongs to, so an eni-* route target resolves to a real
    # appliance node (our NVA) rather than an opaque id.
    eni_owner = {}
    for eni in ec2.describe_network_interfaces()["NetworkInterfaces"]:
        att = eni.get("Attachment") or {}
        if att.get("InstanceId"):
            eni_owner[eni["NetworkInterfaceId"]] = att["InstanceId"]

    resources, nodes, edges = [], [], []
    instances = {}

    for res in ec2.describe_instances()["Reservations"]:
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

    # THE ROUTE TABLES: the authoritative statement of how a subnet egresses.
    for rt in rts:
        rt_id = rt["RouteTableId"]
        rt_name = _tags(rt.get("Tags")).get("Name", rt_id)
        assoc = [a["SubnetId"] for a in rt.get("Associations", []) if a.get("SubnetId")]
        for route in rt.get("Routes", []):
            dst = route.get("DestinationCidrBlock") or route.get("DestinationPrefixListId")
            if not dst:
                continue
            target, kind = "", ""
            if route.get("GatewayId", "").startswith("igw-"):
                target, kind = route["GatewayId"], "internet_gateway"
            elif route.get("GatewayId", "").startswith("vpce-"):
                target, kind = route["GatewayId"], "vpc_endpoint"
            elif route.get("NatGatewayId"):
                target, kind = route["NatGatewayId"], "nat_gateway"
            elif route.get("NetworkInterfaceId"):
                eni = route["NetworkInterfaceId"]
                # Resolve the ENI to its instance: an NVA is a real box, not an id.
                target = eni_owner.get(eni, eni)
                kind = "nva"  # network virtual appliance (our IPsec device)
            elif route.get("GatewayId") == "local":
                continue  # intra-VPC, not an edge
            else:
                continue
            for subnet_id in assoc:
                edges.append({
                    "from_subnet": subnet_id,
                    "from_subnet_name": _tags(subnets.get(subnet_id, {}).get("Tags")).get("Name", subnet_id),
                    "to": target,
                    "to_kind": kind,
                    "destination": dst,
                    "via_route_table": rt_id,
                    "route_table_name": rt_name,
                })

    inventory = {"provider": "aws", "account_id": account, "resources": resources}
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
    ec2 = boto3.client("ec2", region_name=REGION)
    inventory, topology = discover_aws(ec2)
    write_json(os.path.join(FIXTURES_DIR, "aws.json"), inventory)
    write_json(os.path.join(FIXTURES_DIR, "aws-topology.json"), topology)
    return len(inventory["resources"]), len(topology["edges"])


if __name__ == "__main__":
    r, e = run()
    print(json.dumps({"discovered_resources": r, "route_edges": e}))
