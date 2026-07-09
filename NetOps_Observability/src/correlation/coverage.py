"""Catalog self-coverage reports (#80 §5) — the engine's report about its own
rule-base, so coverage growth is MEASURED, not guessed.

The core contract this module gates (first boundary of the verified path
``producer kind → semantic kind → signature consumer``): every kind a signature
references must either be EMITTED by a producer or be a *declared, classified*
gap. Two gap classes exist and they are NOT the same problem:

  * ``COLLECTION_PENDING`` — no current collector observes the phenomenon at
    all. Fixing it requires new collection capability (Layer-2, #73). Allowed,
    but reported.
  * ``NORMALIZATION_PENDING`` — a collector ALREADY observes the phenomenon,
    but nothing maps it to the semantic kind the signature expects (vocabulary
    mismatch / missing normalizer). These are bugs-in-waiting: the data exists
    and the RCA path is silently dark. Each entry is a temporary, structurally
    complete allowlist record (producer + observed_as + ticket) and the CI gate
    (test_coverage.py) fails on any undeclared or under-documented one.

The old flat ``KNOWN_PENDING`` treated both as one bag — that masked the
synthetic-app gap (#98): synthetics.go was observing HTTP/TLS/DNS failures
while the app signatures' kinds went unemitted. Kept only as a deprecated
compatibility view (the union).

Classification vocabulary (``classify_kind`` / ``coverage_report``):
  fully_connected · collection_pending · normalization_pending ·
  orphan_producer · dead_template · intentional_blind
"""
from __future__ import annotations

from catalog import Catalog
from producers import EMITTED_KINDS

# ── intentional blind spots ──────────────────────────────────────────────────
# Emitted-but-unconsumed kinds that are INTENTIONALLY required by no signature.
# Structured: every entry says why it is allowed to stay unconsumed.
INTENTIONAL_BLIND: dict[str, dict] = {
    "device_alarm": {
        "reason": "the #80 §4 generic catch-all — matches no signature by design",
        "owner": "correlix", "date_added": "2026-06-20",
    },
    "lldp_neighbor_change": {
        "reason": "supporting / corroborating evidence only",
        "owner": "correlix", "date_added": "2026-06-20",
    },
    "device_restart": {
        "reason": "contributing lifecycle context",
        "owner": "correlix", "date_added": "2026-06-20",
    },
    "routing_adjacency_change": {
        "reason": "generic fallback for an unscoped ADJCHANGE",
        "owner": "correlix", "date_added": "2026-06-20",
    },
}
INTENTIONAL_BLIND_KINDS: frozenset[str] = frozenset(INTENTIONAL_BLIND)


# ── normalization gaps (phenomenon OBSERVED, semantic kind NOT emitted) ───────
# Every entry is a claim with evidence: `producer` names the component that
# already observes the phenomenon and `observed_as` says in what form (an
# emitted generic kind, a metric family, a store). An entry here is a TEMPORARY
# allow — it must carry a ticket and the CI gate enforces structural
# completeness so these cannot silently rot. When the normalizer lands, the
# kind becomes emitted and the staleness test forces the entry's removal
# (exactly what happened to synthetic_http_fail & co. in #98).
_NORM_FIELDS = ("producer", "observed_as", "reason", "owner", "ticket", "date_added")
NORMALIZATION_PENDING: dict[str, dict] = {
    "probe_latency_departure": {
        "producer": "prober (STAMP + synthetics)",
        "observed_as": ["probe_rtt_anomaly"],
        "reason": "latency departure is observed and emitted under the generic "
                  "probe vocabulary; signatures reference the older kind name",
        "owner": "correlix", "ticket": "#73", "date_added": "2026-07-09",
    },
    "cloud_health_event": {
        "producer": "handle_cloud (netops.cloud lane)",
        "observed_as": ["cloud_health"],
        "reason": "provider health IS emitted as cloud_health; signature "
                  "vocabulary predates the cloud lane (#81 P3G) — alias or "
                  "re-key the template",
        "owner": "correlix", "ticket": "#81", "date_added": "2026-07-09",
    },
    "tls_handshake_fail": {
        "producer": "synthetics (collectors/synthetics.go)",
        "observed_as": ["synthetic_tls_fail"],
        "reason": "TLS handshake failure is observed per check and emitted as "
                  "the #98 semantic kind; v1 templates use the older name",
        "owner": "correlix", "ticket": "#98", "date_added": "2026-07-09",
    },
    "cert_expired": {
        "producer": "synthetics (collectors/synthetics.go)",
        "observed_as": ["synthetic_cert_expired"],
        "reason": "cert expiry is observed (cert_days_to_expiry on the wire) "
                  "and emitted as the #98 semantic kind; v1 templates use the "
                  "older name",
        "owner": "correlix", "ticket": "#98", "date_added": "2026-07-09",
    },
    "cert_expiry_warning": {
        "producer": "synthetics (collectors/synthetics.go)",
        "observed_as": ["synthetic_cert_expiring"],
        "reason": "same phenomenon as synthetic_cert_expiring under an older name",
        "owner": "correlix", "ticket": "#98", "date_added": "2026-07-09",
    },
    "fqdn_probe_fail": {
        "producer": "synthetics (collectors/synthetics.go)",
        "observed_as": ["synthetic_dns_fail"],
        "reason": "FQDN resolution failure is observed per HTTP check "
                  "(fail_class=dns) and emitted as synthetic_dns_fail",
        "owner": "correlix", "ticket": "#98", "date_added": "2026-07-09",
    },
    "tunnel_down": {
        "producer": "tunnels pipeline (ClickHouse netops.tunnels)",
        "observed_as": ["netops.tunnels rows (IPsec/SD-WAN state, live view)"],
        "reason": "tunnel state IS collected and rendered; no producer turns "
                  "state transitions into signals",
        "owner": "correlix", "ticket": "#73", "date_added": "2026-07-09",
    },
    "tunnel_degraded": {
        "producer": "tunnels pipeline (ClickHouse netops.tunnels)",
        "observed_as": ["netops.tunnels rows (loss/latency columns)"],
        "reason": "tunnel quality IS collected; no signal producer",
        "owner": "correlix", "ticket": "#73", "date_added": "2026-07-09",
    },
    "tunnel_flap": {
        "producer": "tunnels pipeline (ClickHouse netops.tunnels)",
        "observed_as": ["netops.tunnels rows (state history)"],
        "reason": "flap is derivable from collected state history; no producer",
        "owner": "correlix", "ticket": "#73", "date_added": "2026-07-09",
    },
    "if_errors": {
        "producer": "SNMP/gNMI collectors (device_if_* metrics)",
        "observed_as": ["device_if_in_errors / device_if_out_errors (VictoriaMetrics)"],
        "reason": "interface error counters ARE polled and rendered on boards; "
                  "no anomaly producer emits the signal kind",
        "owner": "correlix", "ticket": "#73", "date_added": "2026-07-09",
    },
    "if_discards": {
        "producer": "SNMP/gNMI collectors (device_if_* metrics)",
        "observed_as": ["device_if_in_discards / device_if_out_discards (VictoriaMetrics)"],
        "reason": "discard counters ARE polled; no anomaly producer",
        "owner": "correlix", "ticket": "#73", "date_added": "2026-07-09",
    },
    "if_util_high": {
        "producer": "SNMP/gNMI collectors (device_if_* metrics)",
        "observed_as": ["device_if_in_octets / device_if_speed utilization (VictoriaMetrics)"],
        "reason": "utilization is computed live on every dashboard; no "
                  "threshold producer emits the signal kind",
        "owner": "correlix", "ticket": "#73", "date_added": "2026-07-09",
    },
    "bgp_peer_flap": {
        "producer": "SNMP/gNMI collectors (device_bgp_* metrics)",
        "observed_as": ["device_bgp_peer_state / device_bgp_established (VictoriaMetrics)"],
        "reason": "BGP session state IS polled (BGP4-MIB profile); flap "
                  "detection over it is not produced as a signal",
        "owner": "correlix", "ticket": "#73", "date_added": "2026-07-09",
    },
    "dns_latency_high": {
        "producer": "synthetics (collectors/synthetics.go)",
        "observed_as": ["dns_ms phase timing on ProbeEvent (#98 enrichment)"],
        "reason": "DNS resolution latency is measured per HTTP check; no "
                  "threshold normalization emits the signal kind",
        "owner": "correlix", "ticket": "#98", "date_added": "2026-07-09",
    },
    "flow_asymmetry": {
        "producer": "flow pipeline (goflow2 → ClickHouse netops.flows)",
        "observed_as": ["netops.flows bidirectional records"],
        "reason": "flows ARE collected with both directions; asymmetry "
                  "detection over them is not produced as a signal",
        "owner": "correlix", "ticket": "#73", "date_added": "2026-07-09",
    },
}


# ── collection gaps (phenomenon NOT observed by any current collector) ────────
# Grouped by provenance to stay readable at ~130 kinds; expanded to structured
# per-kind entries so report/tests treat both pending classes uniformly.
def _group(reason: str, ticket: str, date_added: str, kinds: list[str]) -> dict[str, dict]:
    return {
        k: {"producer": None, "reason": reason, "owner": "correlix",
            "ticket": ticket, "date_added": date_added}
        for k in kinds
    }


COLLECTION_PENDING: dict[str, dict] = {
    # v0 theoretical templates (wan-congestion, routing-instability, physical-
    # degradation, dns-impairment, cloud-region, tunnel-mtu-blackhole) awaiting
    # Layer-2 collection. NOTE: if_crc stays here (FCS/CRC OIDs are a known
    # SNMP-profile coverage gap — [[netops-snmp-baseline-audit]]); path_change
    # stays here because the traceroute collector is opt-in dormant and its
    # results do not reach the bus yet.
    **_group("v0-theoretical template; Layer-2 collection pending (#73)",
             "#73", "2026-06-20", [
        "app_large_transfer_fail", "bgp_path_change", "cloud_gw_anomaly",
        "dns_failure_rate", "if_crc", "lb_5xx", "optical_power_low",
        "path_change", "qos_drops",
    ]),
    # v1 NOC catalog (owner failure-signature spec 2026-07-02, midnight-noc-
    # questions.md) — the catalog deliberately leads Layer-2 ingestion; these
    # attach as their collectors land (#73 build order; change-timeline kinds
    # like config_change/deploy_event are build-order-① of the capability map).
    **_group("v1 NOC catalog leads ingestion; collector pending (#73 build order)",
             "#73", "2026-07-02", [
        "app_conn_fail", "app_error_rate_high", "app_latency_high", "arp_fail",
        "client_onboarding_fail", "cloud_flow_reject", "config_change",
        "deploy_event", "dhcp_fail", "dhcp_relay_fail", "dhcp_scope_util_high",
        "dns_answer_mismatch", "dns_failover_event", "ecmp_member_loss",
        "evpn_route_missing", "flow_drop_at_nat", "fw_ha_state_change",
        "fw_policy_mismatch", "fw_session_drop", "fw_sync_fail",
        "k8s_endpoints_empty", "k8s_event", "k8s_pod_not_ready",
        "lb_target_unhealthy", "mac_table_missing", "nat_alloc_fail",
        "nat_table_high", "nat_translation_change", "policy_diff_block",
        "route_advertisement_change", "route_count_drop", "route_missing_nexthop",
        "route_prefix_missing", "route_table_blackhole",
        "vlan_reachability_fail", "vni_reachability_fail",
        "waf_block_spike", "waf_rule_match",
    ]),
    # Wave 2 v0 (failure-signature-catalog-wave2.md) — same catalog-leads-
    # ingestion contract.
    **_group("wave-2 v0 catalog; collector pending (#73)",
             "#73", "2026-07-02", [
        "arp_ownership_flip", "duplicate_ip_detected", "errdisable_event",
        "fhrp_dual_active", "fw_probe_denied", "interconnect_peer_unreachable",
        "ipsec_negotiation_fail", "ipsec_sa_rekey_fail", "k8s_ip_alloc_fail",
        "k8s_pod_pending", "mesh_cert_rotation_fail", "mtls_handshake_fail",
        "private_dns_missing", "sdwan_control_down", "subnet_capacity_exhausted",
    ]),
    # Wave 3 (failure-signature-catalog-wave3.md) + backlog promotions.
    **_group("wave-3 v0 catalog; collector pending (#73)",
             "#73", "2026-07-02", [
        "broadcast_storm", "cloud_nat_alloc_fail", "dns_forward_ruleset_gap",
        "dns_forwarding_loop", "flow_timeout", "fw_ha_sync_fail",
        "fw_session_owner_mismatch", "lb_probe_semantics_mismatch",
        "mac_move_spike", "macsec_or_vlan_mismatch", "pac_fetch_fail",
        "proxy_fail", "size_dependent_loss", "snat_member_hotspot",
        "swg_health_degraded", "tcp_retransmit_high", "waf_body_limit_hit",
        "waf_oversize_block", "wpad_lookup_fail",
    ]),
    # Port Intelligence / physical-layer catalog (#94, port-intelligence.md) —
    # optics/DOM/lane/coherent/fiber-path kinds; Layer-2 producers land in the
    # module's P3 (SNMP ENTITY-SENSOR + gNMI/OpenConfig + vendor DOM adapters).
    **_group("port-intelligence physical-layer kind; DOM/optics producers land in #94 P3",
             "#94", "2026-07-05", [
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
    ]),
    # NMS vendor-controller intelligence (design nms-integration-framework.md) —
    # the transformers (P2) + producer (P4) normalize these; the catalog leads
    # the live BUS wiring (P3: poll/webhook → netops.controller_events consumer),
    # so they attach the moment a controller is connected.
    **_group("NMS controller-intelligence kind; attaches when a controller is connected (P3 wiring)",
             "#nms-framework", "2026-07-06", [
        "controller_tunnel_state", "controller_bfd_down",
        "controller_control_connection_loss", "controller_device_unreachable",
        "controller_policy_change",
    ]),
}

# DEPRECATED compatibility view — the flat union the pre-#98 gate used. Do not
# add to this; add a classified entry above. Removed once no caller remains.
KNOWN_PENDING: frozenset[str] = frozenset(COLLECTION_PENDING) | frozenset(NORMALIZATION_PENDING)


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
    return EMITTED_KINDS - consumed_kinds(catalog) - INTENTIONAL_BLIND_KINDS


def orphan_producer_kinds(catalog: Catalog) -> frozenset[str]:
    """Emitted kinds consumed by NO reasoning path and not declared intentional:
    collection effort whose output nothing uses. CI-gated (a new collector kind
    must gain a signature, a normalizer consumer, or an INTENTIONAL_BLIND entry)."""
    return blind_spot_kinds(catalog)


def classify_kind(kind: str, catalog: Catalog) -> str:
    """One classification per kind (the report vocabulary). Precedence:
    connection beats declaration — an emitted+consumed kind is fully_connected
    even if a stale pending entry still lists it (the staleness test then fails
    the build to force the entry's removal)."""
    emitted = kind in EMITTED_KINDS
    consumed = kind in consumed_kinds(catalog)
    if emitted and consumed:
        return "fully_connected"
    if emitted:
        return "intentional_blind" if kind in INTENTIONAL_BLIND_KINDS else "orphan_producer"
    if consumed:
        if kind in NORMALIZATION_PENDING:
            return "normalization_pending"
        if kind in COLLECTION_PENDING:
            return "collection_pending"
        return "dead_template"
    return "unknown"  # neither emitted nor consumed — not part of the contract


def normalization_gap_message(kind: str) -> str:
    """The CI failure text for an (attempted or declared) normalization gap —
    explicit that this is a vocabulary/mapping bug, not missing collection."""
    entry = NORMALIZATION_PENDING.get(kind, {})
    producer = entry.get("producer", "<unknown producer>")
    observed = entry.get("observed_as", [])
    return (
        f"Semantic kind {kind!r} is expected by signatures. The phenomenon "
        f"appears to be observed by producer {producer} as {observed}, but no "
        f"producer emits the semantic kind. This is a NORMALIZATION gap "
        f"(vocabulary/mapping mismatch), not a collection gap — fix the "
        f"normalizer/alias, do not add a collector."
    )


def coverage_report(catalog: Catalog) -> dict:
    """Machine-readable self-coverage summary (for /internal/healthz, CI logs,
    and the backlog generator). Original keys preserved; classified views added."""
    consumed = consumed_kinds(catalog)
    dead = dead_template_kinds(catalog)
    classes: dict[str, str] = {
        k: classify_kind(k, catalog) for k in sorted(EMITTED_KINDS | consumed)
    }
    return {
        "emitted_kinds": sorted(EMITTED_KINDS),
        "consumed_kinds": sorted(consumed),
        "dead_template_kinds": sorted(dead),
        "pending_dead_templates": sorted(dead & KNOWN_PENDING),
        "blind_spot_kinds": sorted(blind_spot_kinds(catalog)),
        # classified views (#98 follow-up: the two pending classes are different
        # problems and are never reported as one bag again)
        "kind_classes": classes,
        "fully_connected": sorted(k for k, c in classes.items() if c == "fully_connected"),
        "collection_pending": sorted(k for k, c in classes.items() if c == "collection_pending"),
        "normalization_pending": sorted(k for k, c in classes.items() if c == "normalization_pending"),
        "orphan_producer": sorted(k for k, c in classes.items() if c == "orphan_producer"),
        "dead_template": sorted(k for k, c in classes.items() if c == "dead_template"),
        "intentional_blind": sorted(k for k, c in classes.items() if c == "intentional_blind"),
    }
