# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Azure in-cloud NETWORK topology → the platform's canonical topology schema.

The Azure twin of discover.py's AWS route-table discovery. It reads the VNet /
subnet / route-table / gateway control plane via the Azure ARM REST API (Reader
role, $0 — these are describe reads) and writes azure-topology.json in the SAME
schema aws-topology.json uses, so src/backend/cloud/topology.go loads it with no
change and the Cloud tab renders AWS and Azure identically:

    vpcs     = VNets            [{id, cidr, name}]   (one row per address prefix)
    subnets  = VNet subnets     [{id, cidr, name}]
    nodes    = gateways / NVAs  [{id, kind, name}]   (vpn_gateway / expressroute_gateway / nva)
    edges    = route-table facts [{from_subnet, to, to_kind, destination, state,
                                   via_route_table, route_table_name}]

The route table is the authoritative statement of how a subnet egresses on Azure
too — a User-Defined Route's nextHopType (VirtualAppliance → an NVA's IP,
VirtualNetworkGateway → the VPN/ER gateway, Internet → default egress) is a FACT
we read rather than assume. Subnets whose only routes are Azure's implicit SYSTEM
routes carry no UDR and therefore no explicit egress edge — an honest gap, never a
guessed one.

Deliberately stdlib-only (urllib) and SELF-CONTAINED (its own token/_get_json so a
concurrent edit to azure.py can never change its behaviour): the ARM API is plain
REST and client-credentials auth is one form POST — no SDK, no container rebuild.
Auth: service principal (AZURE_CLIENT_ID/SECRET/TENANT_ID), Reader role. Cost: $0.
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.parse
import urllib.request

TENANT_ID = os.environ.get("AZURE_TENANT_ID", "")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")
SUBSCRIPTION = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
REGION = os.environ.get("AZURE_REGION", "westus2")
ARM = "https://management.azure.com"
API = "2023-09-01"  # Microsoft.Network resource api-version

# The lab MITMs egress TLS (Versa); urllib needs an explicit CA context, unlike
# boto3's AWS_CA_BUNDLE. Same knob azure.py uses; system store when unset.
_CA = (os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
       or os.environ.get("AWS_CA_BUNDLE") or "")
_SSL = ssl.create_default_context(cafile=_CA) if _CA else ssl.create_default_context()


def configured() -> bool:
    return bool(TENANT_ID and CLIENT_ID and CLIENT_SECRET and SUBSCRIPTION)


def _post_json(url: str, data: bytes, headers: dict) -> dict:
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=15, context=_SSL) as r:  # noqa: S310 - fixed AAD host
        return json.loads(r.read() or b"{}")


def _get_json(url: str, token: str) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=20, context=_SSL) as r:  # noqa: S310 - fixed ARM host
        return json.loads(r.read() or b"{}")


def token() -> str:
    """Client-credentials token for ARM. One form POST — no SDK required."""
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://management.azure.com/.default",
    }).encode()
    out = _post_json(
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
        body, {"Content-Type": "application/x-www-form-urlencoded"})
    return out.get("access_token", "")


def _paged(url: str, tok: str) -> list[dict]:
    """Every page of an ARM list call (nextLink), so a large network is never
    silently truncated (the same discipline discover.py's _pages enforces)."""
    out: list[dict] = []
    while url:
        res = _get_json(url, tok)
        out.extend(res.get("value", []))
        url = res.get("nextLink") or ""
    return out


# nextHopType → (our canonical to_kind, whether the target is the gateway of the VNet)
# VnetLocal / VirtualNetwork / None are intra-VNet or drops — not an egress edge.
_NEXT_HOP_KIND = {
    "VirtualAppliance": "nva",
    "VirtualNetworkGateway": "vpn_gateway",
    "Internet": "internet",
}


def build_topology(tok: str) -> dict:
    """Pull the VNet / subnet / route-table / gateway control plane and map it to
    the canonical topology schema. Pure w.r.t. the token — no writes."""
    vnets = _paged(
        f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Network"
        f"/virtualNetworks?api-version={API}", tok)
    route_tables = _paged(
        f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Network"
        f"/routeTables?api-version={API}", tok)
    gateways = _paged(
        f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Network"
        f"/virtualNetworkGateways?api-version={API}", tok)
    er_circuits = _paged(
        f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Network"
        f"/expressRouteCircuits?api-version={API}", tok)

    return map_topology(vnets, route_tables, gateways, er_circuits, SUBSCRIPTION, REGION)


def _prefixes(props: dict, *keys: str) -> list[str]:
    """A property may carry a single addressPrefix or a list addressPrefixes."""
    out: list[str] = []
    single = props.get("addressPrefix")
    if single:
        out.append(single)
    for k in keys:
        for p in props.get(k, []) or []:
            if p and p not in out:
                out.append(p)
    return out


def map_topology(vnets: list[dict], route_tables: list[dict], gateways: list[dict],
                 er_circuits: list[dict], subscription: str, region: str) -> dict:
    """Pure mapping (Azure API JSON → topology schema) — the unit-tested core."""
    # Route tables by lowercased id, so a subnet's routeTable.id resolves.
    rt_by_id = {str(rt.get("id", "")).lower(): rt for rt in route_tables}
    # Gateway of each VNet: a route's VirtualNetworkGateway hop points at the VNet's
    # own gateway. Azure gateways reference their VNet via the gateway ipConfig subnet.
    gw_of_vnet: dict[str, dict] = {}
    for gw in gateways:
        vnet_id = _gateway_vnet_id(gw)
        if vnet_id:
            gw_of_vnet.setdefault(vnet_id.lower(), gw)

    vpcs: list[dict] = []
    subnets: list[dict] = []
    edges: list[dict] = []
    nodes: list[dict] = []
    seen_nodes: set[str] = set()

    def add_node(node_id: str, kind: str, name: str) -> None:
        if node_id and node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({"id": node_id, "kind": kind, "name": name or node_id})

    # Gateways as nodes (VPN vs ExpressRoute).
    for gw in gateways:
        gtype = str((gw.get("properties", {}) or {}).get("gatewayType", "")).lower()
        kind = "expressroute_gateway" if gtype == "expressroute" else "vpn_gateway"
        add_node(str(gw.get("id", "")), kind, gw.get("name", ""))
    for cir in er_circuits:
        add_node(str(cir.get("id", "")), "dx", cir.get("name", ""))

    for vnet in vnets:
        vnet_id = str(vnet.get("id", ""))
        vnet_name = vnet.get("name", "") or vnet_id
        props = vnet.get("properties", {}) or {}
        addr = (props.get("addressSpace", {}) or {}).get("addressPrefixes", []) or []
        # One vpc row per address prefix (same id) — multi-prefix VNets group right.
        for cidr in addr:
            vpcs.append({"id": vnet_id, "cidr": cidr, "name": vnet_name})
        if not addr:
            vpcs.append({"id": vnet_id, "cidr": "", "name": vnet_name})

        gw_for_vnet = gw_of_vnet.get(vnet_id.lower())
        for sn in props.get("subnets", []) or []:
            sn_id = str(sn.get("id", ""))
            sn_props = sn.get("properties", {}) or {}
            sn_cidrs = _prefixes(sn_props, "addressPrefixes")
            subnets.append({"id": sn_id, "cidr": sn_cidrs[0] if sn_cidrs else "",
                            "name": sn.get("name", "") or sn_id})

            rt_ref = str((sn_props.get("routeTable") or {}).get("id", "")).lower()
            rt = rt_by_id.get(rt_ref)
            if not rt:
                continue  # only system routes — an honest no-UDR gap
            rt_name = rt.get("name", "") or rt_ref
            for route in (rt.get("properties", {}) or {}).get("routes", []) or []:
                rp = route.get("properties", {}) or {}
                dst = rp.get("addressPrefix", "")
                hop = str(rp.get("nextHopType", ""))
                kind = _NEXT_HOP_KIND.get(hop)
                if not dst or not kind:
                    continue  # VnetLocal / VirtualNetwork / None — not an egress edge
                if kind == "nva":
                    target = rp.get("nextHopIpAddress", "") or f"{rt_name}:{dst}"
                    add_node(target, "nva", f"NVA {target}")
                elif kind == "vpn_gateway":
                    if gw_for_vnet is None:
                        continue  # a VNet-GW route with no gateway resource — skip
                    target = str(gw_for_vnet.get("id", ""))
                    gtype = str((gw_for_vnet.get("properties", {}) or {}).get("gatewayType", "")).lower()
                    kind = "expressroute_gateway" if gtype == "expressroute" else "vpn_gateway"
                else:  # internet
                    target = "internet"
                    add_node(target, "internet", "Internet")
                edges.append({
                    "from_subnet": sn_id,
                    "from_subnet_name": sn.get("name", "") or sn_id,
                    "to": target,
                    "to_kind": kind,
                    "destination": dst,
                    "state": "active",
                    "via_route_table": str(rt.get("id", "")),
                    "route_table_name": rt_name,
                })

    return {
        "provider": "azure", "account_id": subscription, "region": region,
        "vpcs": vpcs, "subnets": subnets, "nodes": nodes, "edges": edges,
    }


def _gateway_vnet_id(gw: dict) -> str:
    """A VNet gateway's ipConfigurations reference a subnet in its VNet; the VNet id
    is that subnet id trimmed at '/subnets/'. Returns '' when unresolvable."""
    for cfg in (gw.get("properties", {}) or {}).get("ipConfigurations", []) or []:
        sub = str(((cfg.get("properties", {}) or {}).get("subnet") or {}).get("id", ""))
        marker = "/subnets/"
        if marker in sub:
            return sub.split(marker, 1)[0]
    return ""


def write_topology(tok: str, fixtures_dir: str) -> int:
    """Discover and REWRITE azure-topology.json (poller-written, never a hand
    fixture). Returns the number of route edges — the honest 'how much did we map'
    signal the poller logs, mirroring discover.run()."""
    topo = build_topology(tok)
    os.makedirs(fixtures_dir, exist_ok=True)
    path = os.path.join(fixtures_dir, "azure-topology.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(topo, f, indent=2)
    os.replace(tmp, path)
    return len(topo["edges"])


if __name__ == "__main__":
    if not configured():
        print(json.dumps({"error": "azure not configured"}))
    else:
        n = write_topology(token(), os.environ.get("CLOUD_FIXTURES_OUT", "/fixtures"))
        print(json.dumps({"route_edges": n}))
