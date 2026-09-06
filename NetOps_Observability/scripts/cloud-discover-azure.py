#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Azure discovery — REAL inventory + in-cloud egress topology, from the Azure APIs.

Mirror of cloud-ingest/discover.py (AWS). Two outputs into CLOUD_FIXTURES_DIR:
  azure.json           — inventory (VMs, private/public IPs, tags) for Service View
  azure-topology.json  — egress topology from the ROUTE TABLES (UDRs): which edge a
                         subnet actually leaves by. Azure's next-hop types map to the
                         same node kinds as AWS: VirtualAppliance ⇒ our IPsec NVA,
                         Internet ⇒ the internet edge, VirtualNetworkGateway ⇒ native VPN/ER.

Runs on the HOST because it uses the operator's `az login` session. To run it as a
daemon (in the cloud-ingest container) an Azure service principal is needed — an
identity grant only the owner can make; see BUILD_LOG.
"""
import json
import os
import subprocess
import sys

FIXTURES_DIR = os.environ.get("CLOUD_FIXTURES_DIR",
                              "/home/rao/Projects/NetOps_Observability/NetOps_Observability/"
                              "deployment/docker/cloud-fixtures")
RG = os.environ.get("AZURE_RG", "correlix-faultlab")
LOCATION = os.environ.get("AZURE_LOCATION", "westus2")
SUBSCRIPTION = os.environ.get("AZURE_SUBSCRIPTION", "8d0f8a4e-c36e-4265-821f-d6df48123c24")
APP_TAG_KEYS = ("app", "application", "app_name", "app-name", "service", "workload")

# Azure next-hop type -> the node kind the RCA path renders.
NEXT_HOP_KIND = {
    "VirtualAppliance": "nva",              # our strongSwan IPsec device
    "Internet": "internet_gateway",         # Azure's implicit internet edge
    "VirtualNetworkGateway": "vpn_gateway",  # native VPN / ExpressRoute
    "VnetLocal": "",                        # intra-VNet, not an edge
    "None": "blackhole",
}


def az(*args) -> object:
    env = dict(os.environ, REQUESTS_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt")
    out = subprocess.run(["az", *args, "-o", "json"], capture_output=True, text=True,
                         env=env, timeout=180, check=False)
    if out.returncode != 0:
        raise RuntimeError(f"az {' '.join(args)}: {out.stderr.strip()[:200]}")
    return json.loads(out.stdout or "null")


def write_json(path: str, obj: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def main() -> int:
    vms = az("vm", "list", "-g", RG, "-d") or []
    nics = {n["id"]: n for n in (az("network", "nic", "list", "-g", RG) or [])}
    rts = az("network", "route-table", "list", "-g", RG) or []
    vnets = az("network", "vnet", "list", "-g", RG) or []

    resources, nodes, edges = [], [], []

    for vm in vms:
        tags = vm.get("tags") or {}
        priv, pub = [], []
        for ref in (vm.get("networkProfile", {}).get("networkInterfaces") or []):
            nic = nics.get(ref["id"])
            if not nic:
                continue
            for cfg in nic.get("ipConfigurations", []):
                if cfg.get("privateIPAddress"):
                    priv.append(cfg["privateIPAddress"])
        if vm.get("publicIps"):
            pub = [ip for ip in str(vm["publicIps"]).split(",") if ip]
        resources.append({
            "region": vm.get("location", LOCATION),
            "resource_id": vm["name"],
            "resource_arn_or_uri": vm["id"],
            "resource_type": "compute:virtualMachine",
            "resource_name": vm["name"],
            "private_ips": priv,
            "public_ips": pub,
            "tags": tags,
            "owner": tags.get("owner", ""),
            "env": tags.get("environment", tags.get("env", "")),
            "source": "cloud_api",
            "confidence": "confirmed" if any(k in tags for k in APP_TAG_KEYS) else "strong",
        })
        nodes.append({"id": vm["name"], "kind": "instance", "name": vm["name"],
                      "private_ip": priv[0] if priv else "",
                      "app": next((tags[k] for k in APP_TAG_KEYS if k in tags), "")})

    # THE ROUTE TABLES (UDRs) — the authoritative egress statement per subnet.
    for rt in rts:
        rt_name = rt["name"]
        subnets = [s["id"].rsplit("/", 1)[-1] for s in (rt.get("subnets") or [])]
        for route in (rt.get("routes") or []):
            kind = NEXT_HOP_KIND.get(route.get("nextHopType", ""), "")
            if not kind:
                continue
            target = route.get("nextHopIpAddress") or route.get("nextHopType")
            for subnet in subnets:
                edges.append({
                    "from_subnet": subnet,
                    "from_subnet_name": subnet,
                    "to": target,
                    "to_kind": kind,
                    "destination": route.get("addressPrefix", ""),
                    "via_route_table": rt_name,
                    "route_table_name": rt_name,
                })

    inventory = {"provider": "azure", "account_id": SUBSCRIPTION, "resources": resources}
    topology = {
        "provider": "azure", "account_id": SUBSCRIPTION, "region": LOCATION,
        "vpcs": [{"id": v["name"], "cidr": (v.get("addressSpace", {}).get("addressPrefixes") or [""])[0]}
                 for v in vnets],
        "subnets": [{"id": s["name"], "cidr": s.get("addressPrefix", ""), "name": s["name"]}
                    for v in vnets for s in (v.get("subnets") or [])],
        "nodes": nodes,
        "edges": edges,
    }
    os.makedirs(FIXTURES_DIR, exist_ok=True)
    write_json(os.path.join(FIXTURES_DIR, "azure.json"), inventory)
    write_json(os.path.join(FIXTURES_DIR, "azure-topology.json"), topology)
    print(json.dumps({"discovered_resources": len(resources), "route_edges": len(edges)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
