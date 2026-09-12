# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Azure network-component inventory (cloud-network-overview P0, design §5+§4a).

The Azure twin of aws_components.py. Pure mapping functions (ARM list JSON →
component rows, fixture-testable) over a collect() orchestrator that takes an
injected `get_json(url)` — stdlib-urllib posture, same as azure.py; credential
handling stays entirely with the caller.

STATUS SOURCES (real provider signals only):
  load balancer / NSG / NAT GW / VNet GW   provisioningState (the ARM lifecycle
                                           truth: Succeeded/Failed/Updating)
  application gateway                      operationalState (Running/Stopped)
  VNet peering                             peeringState (Connected/Disconnected)
  ExpressRoute circuit                     serviceProviderProvisioningState
  Front Door / DNS zone                    no health signal → not_measured

SEAM ENDPOINTS (§4a): VNet gateways, peerings and ER circuits carry
attached_vpc_ids/attached_regions so lateral links are discoverable.
"""
from __future__ import annotations

import urllib.parse

from components_common import (DEGRADED, DOWN, HEALTHY, NOT_MEASURED, PAGE_CAP,
                               component_row, retrying, truncate)

ARM = "https://management.azure.com"
API_NET = "2023-09-01"   # Microsoft.Network
API_DNS = "2018-05-01"   # Microsoft.Network/dnszones
API_CDN = "2023-05-01"   # Microsoft.Cdn (Front Door profiles)

# How many per-resource GETs the VNet-gateway family may issue per cycle
# (gateways cannot be listed subscription-wide; ids come from /resources).
GATEWAY_GET_CAP = 25


def _vnet_of_subnet(subnet_id: str) -> str:
    """A subnet ARM id is <vnet-id>/subnets/<name>; the VNet id is the prefix."""
    marker = "/subnets/"
    if marker in subnet_id:
        return subnet_id.split(marker, 1)[0]
    return ""


def _provisioning_status(props: dict) -> tuple[str, str]:
    ps = str(props.get("provisioningState", ""))
    if not ps:
        return NOT_MEASURED, "no provisioningState returned"
    status = {"succeeded": HEALTHY, "failed": DOWN,
              "updating": DEGRADED, "deleting": DEGRADED}.get(ps.lower(), NOT_MEASURED)
    return status, f"provisioningState={ps}"


def _location(res: dict, default_region: str) -> str:
    return res.get("location") or default_region


# ── pure mappers ─────────────────────────────────────────────────────────────

def parse_load_balancers(lbs: list, region: str) -> list:
    rows = []
    for lb in lbs:
        props = lb.get("properties", {}) or {}
        status, reason = _provisioning_status(props)
        subnet_ids = []
        for fe in props.get("frontendIPConfigurations", []) or []:
            sn = str(((fe.get("properties", {}) or {}).get("subnet") or {}).get("id", ""))
            if sn:
                subnet_ids.append(sn)
        pools = props.get("backendAddressPools", []) or []
        rows.append(component_row(
            region=_location(lb, region), resource_id=str(lb.get("id", "")),
            resource_type="network:loadBalancer", resource_name=lb.get("name", ""),
            vpc_id=_vnet_of_subnet(subnet_ids[0]) if subnet_ids else "",
            subnet_ids=subnet_ids, status=status, status_reason=reason,
            key_metric=("backend_pools", len(pools), "pools"),
            tags=lb.get("tags") or {},
            attrs={"sku": ((lb.get("sku") or {}).get("name", ""))}))
    return truncate(rows, "network:loadBalancer")


def parse_app_gateways(agws: list, region: str) -> list:
    rows = []
    for gw in agws:
        props = gw.get("properties", {}) or {}
        op = str(props.get("operationalState", ""))
        if op:
            status = {"running": HEALTHY, "stopped": DOWN,
                      "starting": DEGRADED, "stopping": DEGRADED}.get(op.lower(), NOT_MEASURED)
            reason = f"operationalState={op}"
        else:
            status, reason = _provisioning_status(props)
        subnet_ids = [str(((c.get("properties", {}) or {}).get("subnet") or {}).get("id", ""))
                      for c in props.get("gatewayIPConfigurations", []) or []]
        subnet_ids = [s for s in subnet_ids if s]
        pools = props.get("backendAddressPools", []) or []
        waf = bool((props.get("webApplicationFirewallConfiguration") or {}).get("enabled")
                   or props.get("firewallPolicy"))
        rows.append(component_row(
            region=_location(gw, region), resource_id=str(gw.get("id", "")),
            resource_type="network:applicationGateway", resource_name=gw.get("name", ""),
            vpc_id=_vnet_of_subnet(subnet_ids[0]) if subnet_ids else "",
            subnet_ids=subnet_ids, status=status, status_reason=reason,
            key_metric=("backend_pools", len(pools), "pools"),
            tags=gw.get("tags") or {}, attrs={"waf_enabled": str(waf).lower()}))
    return truncate(rows, "network:applicationGateway")


def parse_front_door_profiles(profiles: list) -> list:
    """Microsoft.Cdn profiles filtered to Front Door SKUs — global entry points."""
    rows = []
    for p in profiles:
        sku = str((p.get("sku") or {}).get("name", ""))
        if "frontdoor" not in sku.lower():
            continue
        props = p.get("properties", {}) or {}
        rs = str(props.get("resourceState", ""))
        if rs:
            status = {"active": HEALTHY, "disabled": DOWN,
                      "creating": DEGRADED, "deleting": DEGRADED}.get(rs.lower(), NOT_MEASURED)
            reason = f"resourceState={rs}"
        else:
            status, reason = NOT_MEASURED, "no resourceState returned"
        rows.append(component_row(
            region="global", resource_id=str(p.get("id", "")),
            resource_type="cdn:frontdoorProfile", resource_name=p.get("name", ""),
            status=status, status_reason=reason,
            tags=p.get("tags") or {}, attrs={"sku": sku}))
    return truncate(rows, "cdn:frontdoorProfile")


def parse_nsgs(nsgs: list, region: str) -> list:
    rows = []
    for nsg in nsgs:
        props = nsg.get("properties", {}) or {}
        status, reason = _provisioning_status(props)
        subnet_ids = [str(s.get("id", "")) for s in props.get("subnets", []) or []]
        vnets = sorted({_vnet_of_subnet(s) for s in subnet_ids if _vnet_of_subnet(s)})
        rows.append(component_row(
            region=_location(nsg, region), resource_id=str(nsg.get("id", "")),
            resource_type="network:networkSecurityGroup", resource_name=nsg.get("name", ""),
            vpc_id=vnets[0] if vnets else "", subnet_ids=subnet_ids,
            status=status, status_reason=reason,
            key_metric=("rule_count", len(props.get("securityRules", []) or []), "rules"),
            attached_vpc_ids=vnets if len(vnets) > 1 else [],
            tags=nsg.get("tags") or {}))
    return truncate(rows, "network:networkSecurityGroup")


def parse_dns_zones(zones: list) -> list:
    rows = []
    for z in zones:
        props = z.get("properties", {}) or {}
        rows.append(component_row(
            region="global", resource_id=str(z.get("id", "")),
            resource_type="network:dnszone", resource_name=z.get("name", ""),
            status=NOT_MEASURED, status_reason="DNS zones expose no health signal",
            key_metric=("record_count", int(props.get("numberOfRecordSets", 0) or 0), "records"),
            tags=z.get("tags") or {},
            attrs={"zone_type": props.get("zoneType", "")}))
    return truncate(rows, "network:dnszone")


def parse_nat_gateways(nats: list, region: str) -> list:
    rows = []
    for n in nats:
        props = n.get("properties", {}) or {}
        status, reason = _provisioning_status(props)
        subnet_ids = [str(s.get("id", "")) for s in props.get("subnets", []) or []]
        rows.append(component_row(
            region=_location(n, region), resource_id=str(n.get("id", "")),
            resource_type="network:natGateway", resource_name=n.get("name", ""),
            vpc_id=_vnet_of_subnet(subnet_ids[0]) if subnet_ids else "",
            subnet_ids=subnet_ids, status=status, status_reason=reason,
            tags=n.get("tags") or {}))
    return truncate(rows, "network:natGateway")


def parse_vnet_gateways(gws: list, region: str) -> list:
    """VNet gateways (VPN / ExpressRoute) — seam endpoints, tagged with the
    VNet they serve (via their ipConfigurations' subnet)."""
    rows = []
    for gw in gws:
        props = gw.get("properties", {}) or {}
        status, reason = _provisioning_status(props)
        vnet = ""
        for cfg in props.get("ipConfigurations", []) or []:
            sn = str(((cfg.get("properties", {}) or {}).get("subnet") or {}).get("id", ""))
            if sn:
                vnet = _vnet_of_subnet(sn)
                break
        rows.append(component_row(
            region=_location(gw, region), resource_id=str(gw.get("id", "")),
            resource_type="network:virtualNetworkGateway", resource_name=gw.get("name", ""),
            vpc_id=vnet, status=status, status_reason=reason,
            attached_vpc_ids=[vnet], attached_regions=[_location(gw, region)],
            tags=gw.get("tags") or {},
            attrs={"gateway_type": props.get("gatewayType", ""),
                   "vpn_type": props.get("vpnType", "")}))
    return truncate(rows, "network:virtualNetworkGateway")


def parse_vnet_peerings(vnets: list, region: str) -> list:
    """One row per VNet peering — the lateral VNet↔VNet link itself (§4a).
    peeringState is a REAL connectivity signal: Disconnected means the link is
    gone even though both VNets are fine."""
    rows = []
    for vnet in vnets:
        vid = str(vnet.get("id", ""))
        props = vnet.get("properties", {}) or {}
        for peer in props.get("virtualNetworkPeerings", []) or []:
            pp = peer.get("properties", {}) or {}
            state = str(pp.get("peeringState", ""))
            status = {"connected": HEALTHY, "disconnected": DOWN,
                      "initiated": DEGRADED}.get(state.lower(), NOT_MEASURED)
            remote = str((pp.get("remoteVirtualNetwork") or {}).get("id", ""))
            rows.append(component_row(
                region=_location(vnet, region), resource_id=str(peer.get("id", "")),
                resource_type="network:vnetPeering", resource_name=peer.get("name", ""),
                vpc_id=vid, status=status,
                status_reason=f"peeringState={state}" if state else "no peeringState returned",
                attached_vpc_ids=[vid, remote]))
    return truncate(rows, "network:vnetPeering")


def parse_er_circuits(circuits: list, region: str) -> list:
    rows = []
    for c in circuits:
        props = c.get("properties", {}) or {}
        sps = str(props.get("serviceProviderProvisioningState", ""))
        status = {"provisioned": HEALTHY, "notprovisioned": DOWN,
                  "provisioning": DEGRADED, "deprovisioning": DEGRADED}.get(
                      sps.lower(), NOT_MEASURED)
        loc = str((props.get("serviceProviderProperties") or {}).get("peeringLocation", ""))
        rows.append(component_row(
            region=_location(c, region), resource_id=str(c.get("id", "")),
            resource_type="network:expressRouteCircuit", resource_name=c.get("name", ""),
            status=status,
            status_reason=f"serviceProviderProvisioningState={sps}" if sps
            else "no provisioning state returned",
            attached_regions=[r for r in (_location(c, region), loc) if r],
            tags=c.get("tags") or {},
            attrs={"peering_location": loc,
                   "bandwidth_mbps": str((props.get("serviceProviderProperties") or {})
                                         .get("bandwidthInMbps", ""))}))
    return truncate(rows, "network:expressRouteCircuit")


# ── orchestrator ─────────────────────────────────────────────────────────────

def collect(get_json, subscription: str, region: str) -> tuple[list, dict]:
    """All Azure network-component rows for one subscription. get_json(url) is
    injected (already authenticated); wrapped here with bounded retry+backoff.
    Per-family isolation — one ARM family failing degrades that family only."""
    g = retrying(get_json)
    rows: list = []
    errors: dict = {}

    def paged(url: str) -> list:
        out: list = []
        for _ in range(PAGE_CAP):
            res = g(url)
            out.extend(res.get("value", []))
            url = res.get("nextLink") or ""
            if not url:
                break
        return out

    def sub_list(rtype: str, api: str) -> list:
        return paged(f"{ARM}/subscriptions/{subscription}/providers/{rtype}?api-version={api}")

    def family(name: str, fn) -> None:
        try:
            rows.extend(fn())
        except Exception as exc:  # noqa: BLE001 - family isolation
            errors[name] = str(exc)[:160]

    family("load_balancers", lambda: parse_load_balancers(
        sub_list("Microsoft.Network/loadBalancers", API_NET), region))
    family("app_gateways", lambda: parse_app_gateways(
        sub_list("Microsoft.Network/applicationGateways", API_NET), region))
    family("front_door", lambda: parse_front_door_profiles(
        sub_list("Microsoft.Cdn/profiles", API_CDN)))
    family("nsgs", lambda: parse_nsgs(
        sub_list("Microsoft.Network/networkSecurityGroups", API_NET), region))
    family("dns_zones", lambda: parse_dns_zones(
        sub_list("Microsoft.Network/dnszones", API_DNS)))
    family("nat_gateways", lambda: parse_nat_gateways(
        sub_list("Microsoft.Network/natGateways", API_NET), region))
    family("vnet_peerings", lambda: parse_vnet_peerings(
        sub_list("Microsoft.Network/virtualNetworks", API_NET), region))
    family("er_circuits", lambda: parse_er_circuits(
        sub_list("Microsoft.Network/expressRouteCircuits", API_NET), region))

    # VNet gateways cannot be listed subscription-wide: ids via the generic
    # /resources filter (the same path azure.poll_seams uses), then a bounded
    # number of per-resource GETs.
    def _vnet_gws() -> list:
        flt = urllib.parse.quote("resourceType eq 'Microsoft.Network/virtualNetworkGateways'")
        ids: list[str] = []
        url = f"{ARM}/subscriptions/{subscription}/resources?$filter={flt}&api-version=2021-04-01"
        for _ in range(PAGE_CAP):
            res = g(url)
            ids.extend(str(r.get("id", "")) for r in res.get("value", []) if r.get("id"))
            url = res.get("nextLink") or ""
            if not url:
                break
        gws = [g(f"{ARM}{rid}?api-version={API_NET}") for rid in ids[:GATEWAY_GET_CAP]]
        return parse_vnet_gateways(gws, region)
    family("vnet_gateways", _vnet_gws)

    return rows, errors
