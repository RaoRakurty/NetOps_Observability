"""Causal/OSI layer taxonomy (G4 / C4).

Every signal kind maps to a CAUSAL LAYER — the practitioner's bottom-up stack
(device → physical → link → network → transport → service → application). Lower
layers cause upper ones, so the layer ordering is a causal-direction prior (§4.3
vote #3) AND the axis the RCA Layer-Stack UI renders (root → symptom → impact).

This is FINER than the entity-type layer the engine used before: `link_state_change`
and `isis_adjacency_change` are both DEVICE-entity signals (same entity-type layer →
the vote abstained), but they are L2 vs L3 — a real causal ordering this map recovers.

Pure + deterministic. An unmapped kind returns None → the layer prior abstains for it
(honest; never a guessed layer). osi_label is for display only (device-health has no
OSI layer; service/application both render as L7).
"""
from __future__ import annotations

from enum import IntEnum


class CausalLayer(IntEnum):
    """Ordered bottom-up: a lower value is a lower (more root-ward) layer."""
    # RF = -1 (#128 Q1, owner-approved 2026-07-26): the air itself — channel
    # utilization, interference, noise, coverage — CAUSES wireless link
    # symptoms, so it sits below everything. -1 (not a renumber) deliberately:
    # every existing layer keeps its integer, so the direction prior and every
    # stored snapshot replay unchanged. If a second sub-physical layer ever
    # appears, THAT is the engine-major sparse renumber (report §5 B1 option c).
    RF = -1           # wireless spectrum conditions — below the wireless PHY
    DEVICE = 0        # device/infra health (CPU, memory, fans, PSU) — no OSI layer
    PHYSICAL = 1      # L1: optics, transceiver power, FCS/CRC at the line
    LINK = 2          # L2: link state, LLDP/CDP, STP, MAC, interface counters
    NETWORK = 3       # L3: IGP/BGP adjacency, routes, reachability
    TRANSPORT = 4     # L4: TCP health, probe loss/latency, flow volume
    SERVICE = 5       # L7 infra: DNS, TLS, load-balancer
    APPLICATION = 6   # L7 app: HTTP 5xx, app timeout


_OSI_LABEL = {
    CausalLayer.RF: "RF",
    CausalLayer.DEVICE: "device", CausalLayer.PHYSICAL: "L1", CausalLayer.LINK: "L2",
    CausalLayer.NETWORK: "L3", CausalLayer.TRANSPORT: "L4",
    CausalLayer.SERVICE: "L7", CausalLayer.APPLICATION: "L7",
}

# kind → CausalLayer. Keyed on the ONSET kind; `_clear` suffix is stripped before lookup.
_KIND_LAYER: dict[str, CausalLayer] = {
    # device / infra health
    "device_resource_anomaly": CausalLayer.DEVICE,
    "metric_anomaly": CausalLayer.DEVICE,
    # physical (L1)
    "optics_power_low": CausalLayer.PHYSICAL,
    "if_errors": CausalLayer.PHYSICAL,
    "fcs_error": CausalLayer.PHYSICAL,
    # link (L2)
    "link_state_change": CausalLayer.LINK,
    "lldp_neighbor_change": CausalLayer.LINK,
    "cdp_neighbor_change": CausalLayer.LINK,
    "stp_topology_change": CausalLayer.LINK,
    "mac_flap": CausalLayer.LINK,
    "evpn_mac_move": CausalLayer.LINK,   # EVPN MAC mobility (overlay) — an L2 event
    "if_metric_anomaly": CausalLayer.LINK,
    "if_util_high": CausalLayer.LINK,
    # network (L3)
    "bgp_adjacency_change": CausalLayer.NETWORK,
    "bgp_state_anomaly": CausalLayer.NETWORK,
    "bgp_route_churn": CausalLayer.NETWORK,   # tracker 184 (session/table churn)
    "bgp_path_change": CausalLayer.NETWORK,
    "ospf_adjacency_change": CausalLayer.NETWORK,
    "isis_adjacency_change": CausalLayer.NETWORK,
    "vtep_state_change": CausalLayer.NETWORK,   # VXLAN VTEP/underlay reachability (L3)
    "route_withdrawal": CausalLayer.NETWORK,
    # FHRP (HSRP/VRRP) first-hop gateway redundancy — an L3 reachability event:
    # a lower-layer link/tracked-object fault (L2) can trigger it, and it causes
    # L4/service impact, so NETWORK orders it correctly between the two.
    "fhrp_state_change": CausalLayer.NETWORK,
    # transport (L4) — reachability/latency/volume across the path
    "probe_loss": CausalLayer.TRANSPORT,
    "probe_rtt_anomaly": CausalLayer.TRANSPORT,
    "flow_volume_anomaly": CausalLayer.TRANSPORT,
    "tunnel_degraded": CausalLayer.TRANSPORT,
    "qos_drops": CausalLayer.TRANSPORT,
    # service / application (L7)
    "dns_latency_high": CausalLayer.SERVICE,
    "dns_failure_rate": CausalLayer.SERVICE,
    "tls_handshake_fail": CausalLayer.SERVICE,
    "synthetic_http_fail": CausalLayer.APPLICATION,
    "http_error_rate": CausalLayer.APPLICATION,
    "app_timeout": CausalLayer.APPLICATION,
    # cloud app observability (#81 P3G) — cloud signals on the same causal stack so
    # a cloud resource/db symptom orders BELOW the app symptom it causes. Config
    # mutations (cloud_change/cloud_audit/security_policy_change) are INTENTIONALLY
    # unmapped — a change has no fixed causal layer → layer prior abstains, onset
    # ordering decides (like device_alarm).
    "cloud_health": CausalLayer.APPLICATION,        # app health symptom (L7)
    "cloud_lb_log": CausalLayer.SERVICE,            # load-balancer access (L7 infra)
    "cloud_resource_health": CausalLayer.SERVICE,   # LB/compute/resource health
    "cloud_metric": CausalLayer.SERVICE,            # resource metric
    "database_metric": CausalLayer.SERVICE,         # DB/cache/queue dependency
    "cloud_flow_log": CausalLayer.TRANSPORT,        # cloud flow (L4)
    # `device_alarm` (the #80 generic-alarm catch-all) is INTENTIONALLY unmapped:
    # a generic alarm has no known causal layer, so the layer prior abstains for it
    # (honest, never a guess). Its absence here is by design, NOT a coverage gap.
    # ── wireless (#128 Phase 3, docs/Wireslessdesign.md §16/§17) ─────────────
    # RF (-1): conditions of the air itself — they CAUSE link symptoms.
    "wireless_channel_util_high": CausalLayer.RF,
    "wireless_interference": CausalLayer.RF,
    "wireless_noise_high": CausalLayer.RF,
    "wireless_coverage_low_rssi": CausalLayer.RF,
    "wireless_radar_event": CausalLayer.RF,       # DFS: spectrum event forces a channel change
    # AP/radio hardware placements.
    "wireless_ap_down": CausalLayer.DEVICE,       # the AP as an infra device
    "wireless_ap_up": CausalLayer.DEVICE,
    "wireless_radio_down": CausalLayer.PHYSICAL,  # the radio IS the wireless PHY
    "wireless_radio_up": CausalLayer.PHYSICAL,
    # Association-plane symptoms (L2 of the air interface).
    "wireless_ap_join_flap": CausalLayer.LINK,    # CAPWAP join churn
    "wireless_retry_rate_high": CausalLayer.LINK, # the LINK symptom RF congestion causes
    "wireless_assoc_failure_rate": CausalLayer.LINK,
    "wireless_roam_storm": CausalLayer.LINK,
    "wireless_client_disconnect_storm": CausalLayer.LINK,
    "wireless_ap_oversubscribed": CausalLayer.LINK,
    # Onboarding failures land at the layer of the TERMINAL PHASE (report §16):
    # a DHCP failure must order below the app symptom it causes and correlate
    # with the DHCP server, not the AP — distinct kinds per phase make the
    # static layer map sufficient (no dynamic layering needed).
    "wireless_onboarding_assoc_failure": CausalLayer.LINK,
    "wireless_onboarding_auth_failure": CausalLayer.LINK,   # 802.1X/PSK at the edge (AAA health is its own signal)
    "wireless_onboarding_key_failure": CausalLayer.LINK,    # 4-way handshake
    "wireless_onboarding_dhcp_failure": CausalLayer.NETWORK,
    "wireless_onboarding_dns_failure": CausalLayer.SERVICE,
    # `wireless_wlc_member_failover` is INTENTIONALLY unmapped: a member
    # failover has no fixed causal layer (a redundancy event, not a fault
    # layer) — the prior abstains, onset ordering decides. By design.
}


def layer_of(kind: str) -> CausalLayer | None:
    """Causal layer for a signal kind, or None if unmapped (prior abstains)."""
    if not kind:
        return None
    base = kind.removesuffix("_clear")
    return _KIND_LAYER.get(base)


def osi_label(layer: CausalLayer | None) -> str:
    """Display label for the layer-stack UI ('L1'…'L7' / 'device'); '' when unknown."""
    return _OSI_LABEL.get(layer, "") if layer is not None else ""
