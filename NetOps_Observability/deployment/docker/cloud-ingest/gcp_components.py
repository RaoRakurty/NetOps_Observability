# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""GCP network-component inventory (cloud-network-overview P0, design §5+§4a).

The GCP third of the component-inventory triad (aws_components /
azure_components). Pure mapping functions over injected getters (get_json /
post_json — already authenticated; credential handling stays with the caller,
same posture as gcp.py).

STATUS SOURCES (real provider signals only):
  backend service    backendServices.getHealth roll-up (bounded), else not_measured
  VPN tunnel         tunnel.status (ESTABLISHED / NEGOTIATION_FAILURE / …)
  VPC peering        peering.state (ACTIVE / INACTIVE)
  Cloud Router       getRouterStatus BGP peer roll-up (bounded), else not_measured
  forwarding rule / Cloud Armor / firewall set / DNS zone / Cloud NAT / VPN GW
                     no free health signal → not_measured (unknown ≠ green)

ANTI-FLOOD (binding): VPC firewall RULES are rolled up to ONE resource row per
network (compute:firewallRuleSet) with rule counts — never one row per rule.

SEAM ENDPOINTS (§4a): VPN gateways/tunnels and peerings carry
attached_vpc_ids/attached_regions so lateral links are discoverable.
"""
from __future__ import annotations

from components_common import (DEGRADED, DOWN, HEALTHY, NOT_MEASURED, PAGE_CAP,
                               component_row, retrying, truncate)

COMPUTE = "https://compute.googleapis.com/compute/v1"
DNS_API = "https://dns.googleapis.com/dns/v1"

# Bounded per-resource status reads per cycle (getHealth / getRouterStatus are
# per-resource calls; past the cap the remainder stays honestly not_measured).
HEALTH_CALL_CAP = 30
ROUTER_STATUS_CAP = 10


def rel_path(url: str) -> str:
    """A GCP selfLink URL → the stable resource path (projects/…). Public:
    gcp.py uses it to give instances the same network-context identifiers."""
    marker = "/projects/"
    if marker in url:
        return "projects/" + url.split(marker, 1)[1]
    return url


_rel_path = rel_path  # internal alias used throughout the mappers


def _scope_region(scope: str) -> tuple[str, str]:
    """Aggregated-list scope key ('regions/us-west1' | 'zones/us-west1-b' |
    'global') → (region, zone)."""
    part = scope.split("/")[-1]
    if scope.startswith("zones/"):
        return part.rsplit("-", 1)[0], part
    if scope == "global":
        return "global", ""
    return part, ""


# ── pure mappers ─────────────────────────────────────────────────────────────

def parse_forwarding_rules(items_by_scope: dict, project: str) -> list:
    rows = []
    for scope, wrap in (items_by_scope or {}).items():
        region, _ = _scope_region(scope)
        for fr in wrap.get("forwardingRules") or []:
            scheme = str(fr.get("loadBalancingScheme", ""))
            ip = fr.get("IPAddress", "")
            external = scheme.startswith("EXTERNAL")
            name = fr.get("name", "")
            loc = "global" if region == "global" else f"regions/{region}"
            rows.append(component_row(
                region=region, resource_id=f"projects/{project}/{loc}/forwardingRules/{name}",
                resource_type="compute:forwardingRule", resource_name=name,
                vpc_id=_rel_path(fr.get("network", "")),
                subnet_ids=[_rel_path(fr["subnetwork"])] if fr.get("subnetwork") else [],
                status=NOT_MEASURED,
                status_reason="forwarding rules expose no health signal",
                public_ips=[ip] if ip and external else [],
                private_ips=[ip] if ip and not external else [],
                tags=fr.get("labels") or {},
                attrs={"scheme": scheme, "target": _rel_path(fr.get("target", "")
                                                             or fr.get("backendService", ""))}))
    return truncate(rows, "compute:forwardingRule")


def parse_backend_services(items_by_scope: dict, health: dict, project: str) -> list:
    """health maps backend-service resource path → (healthy, total) backend
    instances, absent when getHealth was not (or could not be) read."""
    rows = []
    for scope, wrap in (items_by_scope or {}).items():
        region, _ = _scope_region(scope)
        for bs in wrap.get("backendServices") or []:
            name = bs.get("name", "")
            loc = "global" if region == "global" else f"regions/{region}"
            rid = f"projects/{project}/{loc}/backendServices/{name}"
            h = health.get(rid)
            if h is not None:
                healthy, total = h
                if total == 0:
                    status, reason, metric = DEGRADED, "no backends registered", ("healthy_backends", 0, "backends")
                elif healthy == total:
                    status, reason = HEALTHY, f"backends {healthy}/{total} healthy"
                    metric = ("healthy_backends", healthy, "backends")
                elif healthy == 0:
                    status, reason = DOWN, f"all {total} backends unhealthy"
                    metric = ("healthy_backends", 0, "backends")
                else:
                    status, reason = DEGRADED, f"backends {healthy}/{total} healthy"
                    metric = ("healthy_backends", healthy, "backends")
            else:
                status, reason, metric = NOT_MEASURED, "backend health not read this cycle", None
            rows.append(component_row(
                region=region, resource_id=rid,
                resource_type="compute:backendService", resource_name=name,
                vpc_id=_rel_path(bs.get("network", "")),
                status=status, status_reason=reason, key_metric=metric,
                attrs={"protocol": bs.get("protocol", ""),
                       "security_policy": _rel_path(bs.get("securityPolicy", ""))}))
    return truncate(rows, "compute:backendService")


def backend_health(post_json, items_by_scope: dict, project: str,
                   cap: int = HEALTH_CALL_CAP) -> dict:
    """getHealth per (backend service, group), bounded by cap total calls.
    Returns {resource_path: (healthy, total)} for services actually measured;
    an unmeasured service is simply absent (→ not_measured downstream)."""
    out: dict = {}
    calls = 0
    for scope, wrap in (items_by_scope or {}).items():
        region, _ = _scope_region(scope)
        for bs in wrap.get("backendServices") or []:
            name = bs.get("name", "")
            loc = "global" if region == "global" else f"regions/{region}"
            rid = f"projects/{project}/{loc}/backendServices/{name}"
            groups = [b.get("group", "") for b in bs.get("backends") or [] if b.get("group")]
            if not groups:
                out[rid] = (0, 0)
                continue
            healthy = total = 0
            measured = False
            for grp in groups:
                if calls >= cap:
                    break
                calls += 1
                try:
                    res = post_json(f"{COMPUTE}/{rid}/getHealth", {"group": grp})
                except Exception:  # noqa: BLE001 - one group's failure = unmeasured, not fabricated
                    continue
                measured = True
                for st in res.get("healthStatus") or []:
                    total += 1
                    if str(st.get("healthState", "")).upper() == "HEALTHY":
                        healthy += 1
            if measured:
                out[rid] = (healthy, total)
    return out


def parse_security_policies(policies: list, project: str) -> list:
    """Cloud Armor policies — one row each, rule count as the key metric."""
    rows = []
    for p in policies:
        name = p.get("name", "")
        rows.append(component_row(
            region="global",
            resource_id=f"projects/{project}/global/securityPolicies/{name}",
            resource_type="compute:securityPolicy", resource_name=name,
            status=NOT_MEASURED, status_reason="Cloud Armor exposes no health signal",
            key_metric=("rule_count", len(p.get("rules") or []), "rules"),
            attrs={"policy_type": p.get("type", "")}))
    return truncate(rows, "compute:securityPolicy")


def parse_firewall_rulesets(firewalls: list, project: str) -> list:
    """VPC firewall rules rolled up to ONE row per network (anti-flood rule):
    the component is 'this VPC's firewall', its key metric the rule count."""
    by_net: dict[str, dict] = {}
    for fw in firewalls:
        net = _rel_path(fw.get("network", "")) or f"projects/{project}/global/networks/unknown"
        acc = by_net.setdefault(net, {"rules": 0, "disabled": 0})
        acc["rules"] += 1
        if fw.get("disabled"):
            acc["disabled"] += 1
    rows = []
    for net, acc in sorted(by_net.items()):
        net_name = net.rsplit("/", 1)[-1]
        rows.append(component_row(
            region="global", resource_id=f"{net}/firewallRules",
            resource_type="compute:firewallRuleSet",
            resource_name=f"{net_name} firewall rules",
            vpc_id=net,
            status=NOT_MEASURED, status_reason="firewall rules expose no health signal",
            key_metric=("rule_count", acc["rules"], "rules"),
            attrs={"disabled_rules": acc["disabled"]}))
    return truncate(rows, "compute:firewallRuleSet")


def parse_dns_zones(zones: list, project: str) -> list:
    rows = []
    for z in zones:
        name = z.get("name", "")
        nets = [_rel_path(str((n or {}).get("networkUrl", "")))
                for n in ((z.get("privateVisibilityConfig") or {}).get("networks") or [])]
        rows.append(component_row(
            region="global", resource_id=f"projects/{project}/managedZones/{name}",
            resource_type="dns:managedZone",
            resource_name=z.get("dnsName", "") or name,
            vpc_id=nets[0] if nets else "",
            status=NOT_MEASURED, status_reason="DNS zones expose no health signal",
            attached_vpc_ids=nets if len(nets) > 1 else [],
            tags=z.get("labels") or {},
            attrs={"visibility": z.get("visibility", "")}))
    return truncate(rows, "dns:managedZone")


def parse_routers(items_by_scope: dict, router_status: dict, project: str) -> list:
    """Cloud Routers + their Cloud NAT configs. router_status maps router
    resource path → list of peer-status strings from getRouterStatus (absent =
    not read this cycle → honestly not_measured)."""
    rows = []
    for scope, wrap in (items_by_scope or {}).items():
        region, _ = _scope_region(scope)
        for r in wrap.get("routers") or []:
            name = r.get("name", "")
            rid = f"projects/{project}/regions/{region}/routers/{name}"
            net = _rel_path(r.get("network", ""))
            peers = router_status.get(rid)
            if peers is None:
                status, reason = NOT_MEASURED, "router status not read this cycle"
                metric = None
            elif not peers:
                status, reason, metric = NOT_MEASURED, "router has no BGP peers", None
            else:
                up = sum(1 for p in peers if p == "up")
                metric = ("bgp_peers_up", up, "peers")
                if up == len(peers):
                    status, reason = HEALTHY, f"BGP peers {up}/{len(peers)} up"
                elif up == 0:
                    status, reason = DOWN, f"all {len(peers)} BGP peers down"
                else:
                    status, reason = DEGRADED, f"BGP peers {up}/{len(peers)} up"
            rows.append(component_row(
                region=region, resource_id=rid,
                resource_type="compute:router", resource_name=name,
                vpc_id=net, status=status, status_reason=reason, key_metric=metric,
                attached_regions=[region]))
            for nat in r.get("nats") or []:
                rows.append(component_row(
                    region=region, resource_id=f"{rid}/nats/{nat.get('name', '')}",
                    resource_type="compute:cloudNat", resource_name=nat.get("name", ""),
                    vpc_id=net, status=NOT_MEASURED,
                    status_reason="Cloud NAT health requires metered metrics",
                    attrs={"router": name}))
    return truncate(rows, "compute:router")


def parse_vpn_gateways(items_by_scope: dict, project: str) -> list:
    rows = []
    for scope, wrap in (items_by_scope or {}).items():
        region, _ = _scope_region(scope)
        for gw in wrap.get("vpnGateways") or []:
            name = gw.get("name", "")
            net = _rel_path(gw.get("network", ""))
            rows.append(component_row(
                region=region,
                resource_id=f"projects/{project}/regions/{region}/vpnGateways/{name}",
                resource_type="compute:vpnGateway", resource_name=name,
                vpc_id=net, status=NOT_MEASURED,
                status_reason="gateway itself has no state; tunnels carry it",
                attached_vpc_ids=[net], attached_regions=[region],
                tags=gw.get("labels") or {}))
    return truncate(rows, "compute:vpnGateway")


def parse_vpn_tunnels(items_by_scope: dict, project: str) -> list:
    """VPN tunnels — the honest seam-state carrier: tunnel.status is a live
    IKE/data-plane fact from the provider."""
    rows = []
    for scope, wrap in (items_by_scope or {}).items():
        region, _ = _scope_region(scope)
        for t in wrap.get("vpnTunnels") or []:
            name = t.get("name", "")
            st = str(t.get("status", ""))
            status = {
                "ESTABLISHED": HEALTHY,
                "NEGOTIATION_FAILURE": DOWN, "REJECTED": DOWN, "FAILED": DOWN,
                "NO_INCOMING_PACKETS": DEGRADED, "FIRST_HANDSHAKE": DEGRADED,
                "PROVISIONING": DEGRADED, "WAITING_FOR_FULL_CONFIG": DEGRADED,
                "NETWORK_ERROR": DOWN, "AUTHORIZATION_ERROR": DOWN,
                "STOPPED": DOWN, "DEPROVISIONING": DEGRADED, "ALLOCATING_RESOURCES": DEGRADED,
            }.get(st.upper(), NOT_MEASURED)
            reason = f"status={st}" if st else "no tunnel status returned"
            if t.get("detailedStatus"):
                reason += f"; {str(t['detailedStatus'])[:120]}"
            rows.append(component_row(
                region=region,
                resource_id=f"projects/{project}/regions/{region}/vpnTunnels/{name}",
                resource_type="compute:vpnTunnel", resource_name=name,
                status=status, status_reason=reason,
                attached_regions=[region],
                attrs={"peer_ip": t.get("peerIp", ""),
                       "vpn_gateway": _rel_path(t.get("vpnGateway", ""))}))
    return truncate(rows, "compute:vpnTunnel")


def parse_vpc_peerings(networks: list, project: str) -> list:
    """One row per VPC peering (§4a lateral link). peering.state ACTIVE/
    INACTIVE is the provider's own connectivity verdict."""
    rows = []
    for net in networks:
        name = net.get("name", "")
        self_path = f"projects/{project}/global/networks/{name}"
        for p in net.get("peerings") or []:
            state = str(p.get("state", ""))
            status = {"active": HEALTHY, "inactive": DOWN}.get(state.lower(), NOT_MEASURED)
            remote = _rel_path(p.get("network", ""))
            rows.append(component_row(
                region="global", resource_id=f"{self_path}/peerings/{p.get('name', '')}",
                resource_type="compute:vpcPeering", resource_name=p.get("name", ""),
                vpc_id=self_path,
                status=status,
                status_reason=f"state={state}" if state else "no peering state returned",
                attached_vpc_ids=[self_path, remote]))
    return truncate(rows, "compute:vpcPeering")


# ── orchestrator ─────────────────────────────────────────────────────────────

def collect(get_json, post_json, project: str) -> tuple[list, dict]:
    """All GCP network-component rows for one project. Getters are injected
    (already authenticated), wrapped with bounded retry+backoff. Per-family
    isolation — one API family failing degrades that family only."""
    g = retrying(get_json)
    rows: list = []
    errors: dict = {}

    def aggregated(kind: str) -> dict:
        items: dict = {}
        url = f"{COMPUTE}/projects/{project}/aggregated/{kind}?returnPartialSuccess=true"
        for _ in range(PAGE_CAP):
            res = g(url)
            for scope, wrap in (res.get("items") or {}).items():
                if scope in items:
                    for k, v in wrap.items():
                        if isinstance(v, list):
                            items[scope].setdefault(k, []).extend(v)
                else:
                    items[scope] = wrap
            nxt = res.get("nextPageToken")
            if not nxt:
                break
            url = url.split("&pageToken=")[0] + "&pageToken=" + nxt
        return items

    def listed(url: str, key: str) -> list:
        out: list = []
        for _ in range(PAGE_CAP):
            res = g(url)
            out.extend(res.get(key) or [])
            nxt = res.get("nextPageToken")
            if not nxt:
                break
            url = url.split("&pageToken=")[0] + ("&" if "?" in url else "?") + "pageToken=" + nxt
        return out

    def family(name: str, fn) -> None:
        try:
            rows.extend(fn())
        except Exception as exc:  # noqa: BLE001 - family isolation
            errors[name] = str(exc)[:160]

    family("forwarding_rules", lambda: parse_forwarding_rules(
        aggregated("forwardingRules"), project))

    def _backends() -> list:
        items = aggregated("backendServices")
        try:
            health = backend_health(post_json, items, project)
        except Exception:  # noqa: BLE001 - health is best-effort; inventory survives
            health = {}
        return parse_backend_services(items, health, project)
    family("backend_services", _backends)

    family("security_policies", lambda: parse_security_policies(
        listed(f"{COMPUTE}/projects/{project}/global/securityPolicies", "items"), project))
    family("firewall_rulesets", lambda: parse_firewall_rulesets(
        listed(f"{COMPUTE}/projects/{project}/global/firewalls", "items"), project))
    family("dns_zones", lambda: parse_dns_zones(
        listed(f"{DNS_API}/projects/{project}/managedZones", "managedZones"), project))

    def _routers() -> list:
        items = aggregated("routers")
        status: dict = {}
        calls = 0
        for scope, wrap in items.items():
            region, _ = _scope_region(scope)
            for r in wrap.get("routers") or []:
                if calls >= ROUTER_STATUS_CAP:
                    break
                rid = f"projects/{project}/regions/{region}/routers/{r.get('name', '')}"
                calls += 1
                try:
                    res = g(f"{COMPUTE}/{rid}/getRouterStatus")
                except Exception:  # noqa: BLE001 - unmeasured, never fabricated
                    continue
                status[rid] = [str(p.get("status", "")).lower()
                               for p in (res.get("result") or {}).get("bgpPeerStatus") or []]
        return parse_routers(items, status, project)
    family("routers_nat", _routers)

    family("vpn_gateways", lambda: parse_vpn_gateways(aggregated("vpnGateways"), project))
    family("vpn_tunnels", lambda: parse_vpn_tunnels(aggregated("vpnTunnels"), project))
    family("vpc_peerings", lambda: parse_vpc_peerings(
        listed(f"{COMPUTE}/projects/{project}/global/networks", "items"), project))

    return rows, errors
