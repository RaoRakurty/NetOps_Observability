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
    DEVICE = 0        # device/infra health (CPU, memory, fans, PSU) — no OSI layer
    PHYSICAL = 1      # L1: optics, transceiver power, FCS/CRC at the line
    LINK = 2          # L2: link state, LLDP/CDP, STP, MAC, interface counters
    NETWORK = 3       # L3: IGP/BGP adjacency, routes, reachability
    TRANSPORT = 4     # L4: TCP health, probe loss/latency, flow volume
    SERVICE = 5       # L7 infra: DNS, TLS, load-balancer
    APPLICATION = 6   # L7 app: HTTP 5xx, app timeout


_OSI_LABEL = {
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
    "if_metric_anomaly": CausalLayer.LINK,
    "if_util_high": CausalLayer.LINK,
    # network (L3)
    "bgp_adjacency_change": CausalLayer.NETWORK,
    "bgp_state_anomaly": CausalLayer.NETWORK,
    "bgp_path_change": CausalLayer.NETWORK,
    "ospf_adjacency_change": CausalLayer.NETWORK,
    "isis_adjacency_change": CausalLayer.NETWORK,
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
    # `device_alarm` (the #80 generic-alarm catch-all) is INTENTIONALLY unmapped:
    # a generic alarm has no known causal layer, so the layer prior abstains for it
    # (honest, never a guess). Its absence here is by design, NOT a coverage gap.
}


def layer_of(kind: str) -> CausalLayer | None:
    """Causal layer for a signal kind, or None if unmapped (prior abstains)."""
    if not kind:
        return None
    base = kind[:-6] if kind.endswith("_clear") else kind
    return _KIND_LAYER.get(base)


def osi_label(layer: CausalLayer | None) -> str:
    """Display label for the layer-stack UI ('L1'…'L7' / 'device'); '' when unknown."""
    return _OSI_LABEL.get(layer, "") if layer is not None else ""
