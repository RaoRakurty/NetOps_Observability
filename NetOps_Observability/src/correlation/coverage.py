"""Catalog self-coverage reports (#80 §5) — the engine's report about its own
rule-base, so coverage growth is MEASURED, not guessed.

Two static reports (the dynamic companion — the undetermined-frequency feed over
corr_objects — lives in the API/reports layer where the object history is):

  * ``dead_template_kinds`` — kinds a signature REQUIRES that no producer EMITS:
    a template that can never fire (the early-catalog failure mode). The CI gate
    (test_coverage.py) asserts these are all in ``KNOWN_PENDING`` — the documented
    v0-theoretical templates awaiting Layer-2 collection (#73) — so a NEW dead
    template (a signature whose kind nothing emits) fails the build.
  * ``blind_spot_kinds`` — kinds producers EMIT that no signature consumes: rule-
    base blind spots (informational). Some are intentional (``device_alarm`` is the
    generic catch-all by design; ``lldp_neighbor_change`` is corroboration-only).

This converts "how do we know what's missing" from a guess into a deterministic
report the engine produces about itself.
"""
from __future__ import annotations

from catalog import Catalog
from producers import EMITTED_KINDS

# Emitted-but-unconsumed kinds that are INTENTIONALLY required by no signature.
INTENTIONAL_BLIND: frozenset[str] = frozenset({
    "device_alarm",              # the #80 §4 generic catch-all — matches no signature by design
    "lldp_neighbor_change",      # supporting / corroborating evidence only
    "device_restart",            # contributing lifecycle context
    "routing_adjacency_change",  # generic fallback for an unscoped ADJCHANGE
})

# Consumed-but-unemitted kinds from the v0 THEORETICAL templates (wan-congestion,
# routing-instability, physical-degradation, dns-impairment, cloud-region,
# tunnel-mtu-blackhole) — pending Layer-2 collection (#73). A NEW signature
# requiring an unemitted kind NOT in here fails the CI gate (the discipline this
# whole exercise is meant to enforce: don't author a signature whose kind nothing
# emits — fix Layer 2 first, or add it here with a tracker reference).
KNOWN_PENDING: frozenset[str] = frozenset({
    "app_large_transfer_fail", "bgp_path_change", "bgp_peer_flap",
    "cloud_gw_anomaly", "cloud_health_event", "dns_failure_rate", "dns_latency_high",
    "if_crc", "if_discards", "if_errors", "if_util_high", "lb_5xx",
    "optical_power_low", "path_change", "probe_latency_departure", "qos_drops",
    "tunnel_degraded", "tunnel_down", "tunnel_flap",  # synthetic_http_fail now EMITTED (synthetic_normalize.py)
    # v1 NOC catalog (owner failure-signature spec 2026-07-02, midnight-noc-
    # questions.md) — the catalog deliberately leads Layer-2 ingestion; these
    # attach as their collectors land (#73 build order; change-timeline kinds
    # like config_change/deploy_event are build-order-① of the capability map).
    "app_conn_fail", "app_error_rate_high", "app_latency_high", "arp_fail",
    "cert_expired", "cert_expiry_warning", "client_onboarding_fail",
    "cloud_flow_reject", "config_change", "deploy_event", "dhcp_fail",
    "dhcp_relay_fail", "dhcp_scope_util_high", "dns_answer_mismatch",
    "dns_failover_event", "ecmp_member_loss", "evpn_route_missing",
    "flow_asymmetry", "flow_drop_at_nat", "fqdn_probe_fail",
    "fw_ha_state_change", "fw_policy_mismatch", "fw_session_drop", "fw_sync_fail",
    "k8s_endpoints_empty", "k8s_event", "k8s_pod_not_ready",
    "lb_target_unhealthy", "mac_table_missing", "nat_alloc_fail",
    "nat_table_high", "nat_translation_change", "policy_diff_block",
    "route_advertisement_change", "route_count_drop", "route_missing_nexthop",
    "route_prefix_missing", "route_table_blackhole", "tls_handshake_fail",
    "vlan_reachability_fail", "vni_reachability_fail",
    "waf_block_spike", "waf_rule_match",
    # Wave 2 v0 (failure-signature-catalog-wave2.md) — same catalog-leads-
    # ingestion contract.
    "arp_ownership_flip", "duplicate_ip_detected", "errdisable_event",
    "fhrp_dual_active", "fw_probe_denied", "interconnect_peer_unreachable",
    "ipsec_negotiation_fail", "ipsec_sa_rekey_fail", "k8s_ip_alloc_fail",
    "k8s_pod_pending", "mesh_cert_rotation_fail", "mtls_handshake_fail",
    "private_dns_missing", "sdwan_control_down", "subnet_capacity_exhausted",
    # Wave 3 (failure-signature-catalog-wave3.md) + backlog promotions.
    "broadcast_storm", "cloud_nat_alloc_fail", "dns_forward_ruleset_gap",
    "dns_forwarding_loop", "flow_timeout", "fw_ha_sync_fail",
    "fw_session_owner_mismatch", "lb_probe_semantics_mismatch",
    "mac_move_spike", "macsec_or_vlan_mismatch", "pac_fetch_fail",
    "proxy_fail", "size_dependent_loss", "snat_member_hotspot",
    "swg_health_degraded", "tcp_retransmit_high", "waf_body_limit_hit",
    "waf_oversize_block", "wpad_lookup_fail",
    # Port Intelligence / physical-layer catalog (#94, port-intelligence.md) —
    # optics/DOM/lane/coherent/fiber-path kinds; Layer-2 producers land in the
    # module's P3 (SNMP ENTITY-SENSOR + gNMI/OpenConfig + vendor DOM adapters).
    "carrier_freq_offset_high", "cassette_type_mismatch", "coherent_input_power_low",
    "coherent_osnr_low", "connector_pinout_conflict", "crossconnect_endpoint_mismatch",
    "dom_lane_bias_anomaly", "dom_rx_power_abnormal", "dom_rx_power_low",
    "dom_temperature_high", "edfa_gain_tilt", "edfa_saturation",
    "fec_corrected_rate_high", "fiber_path_budget_exceeded", "fiber_path_polarity_conflict",
    "interop_mode_mismatch", "label_record_conflict", "lane_divergence_high",
    "lane_group_dark", "lane_group_others_normal", "lane_map_swapped",
    "lane_rx_absent_subset", "link_down_no_light", "link_flap", "link_flap_on_insert",
    "lldp_neighbor_mismatch", "mode_descriptor_mismatch", "mpo_gender_mismatch",
    "mpo_missing_fibers", "mpo_polarity_mismatch", "mpo_row_flip",
    "multi_channel_power_skew", "mux_demux_insertion_loss_high", "neighbor_unexpected",
    "optical_frequency_mismatch", "pam4_lane_ber_divergence", "pam4_lane_skew_high",
    "parallel_lane_map_anomaly", "part_number_not_qualified", "pcs_deskew_fault",
    "pcs_local_fault", "pcs_remote_fault", "prefec_ber_rising",
    "roadm_filter_edge_penalty", "rx_margin_low", "single_lane_rx_absent",
    "single_lane_tx_fail", "thermal_margin_low", "transceiver_unsupported",
    # NMS vendor-controller intelligence (design nms-integration-framework.md) —
    # the transformers (P2) + producer (P4) normalize these; the catalog leads
    # the live BUS wiring (P3: poll/webhook → netops.controller_events consumer),
    # so they attach the moment a controller is connected.
    "controller_tunnel_state", "controller_bfd_down",
    "controller_control_connection_loss", "controller_device_unreachable",
    "controller_policy_change",
})


def consumed_kinds(catalog: Catalog) -> frozenset[str]:
    """Every signal kind any enabled signature references — requires clauses AND
    discriminator 'absent' clauses (alternations expanded). A discriminator that
    names an unemitted kind never fires, so it counts as consumed too."""
    out: set[str] = set()
    for t in catalog.enabled_templates():
        for c in t.requires:
            out |= set(c.kinds())
        for d in t.discriminators:
            out |= set(d.absent.kinds())
    return frozenset(out)


def dead_template_kinds(catalog: Catalog) -> frozenset[str]:
    """Required/referenced kinds that NO producer emits — templates that cannot
    fire (or discriminators that can never trigger)."""
    return consumed_kinds(catalog) - EMITTED_KINDS


def blind_spot_kinds(catalog: Catalog) -> frozenset[str]:
    """Emitted kinds NO signature consumes (rule-base blind spots), minus the
    intentional generic/supporting ones — candidates for a new signature."""
    return EMITTED_KINDS - consumed_kinds(catalog) - INTENTIONAL_BLIND


def coverage_report(catalog: Catalog) -> dict:
    """Machine-readable self-coverage summary (for /internal/healthz, CI logs,
    and the backlog generator)."""
    return {
        "emitted_kinds": sorted(EMITTED_KINDS),
        "consumed_kinds": sorted(consumed_kinds(catalog)),
        "dead_template_kinds": sorted(dead_template_kinds(catalog)),
        "pending_dead_templates": sorted(dead_template_kinds(catalog) & KNOWN_PENDING),
        "blind_spot_kinds": sorted(blind_spot_kinds(catalog)),
    }
