"""Signature confirmability audit (#98 Phase 3) — for every enabled signature,
compute the MAXIMUM verdict it can realistically reach with the producers that
exist today, and why.

The coverage gate (coverage.py) validates the first contract boundary — every
referenced kind has a producer or a classified gap. This module validates the
next one: *can the signature actually reach its intended verdict?* A template
can be fully "covered" and still be stuck at suspected forever because its only
corroborators share one modality class, or because the second modality grounds
on an entity the app object never joins (the passive-flow/interface problem).

"Demo-ready" has a precise meaning here: real collector-shaped input can travel
the actual pipeline and reach the expected verdict with correct evidence
independence. The audit does NOT weaken any verdict rule to look better —
it reports the gate the engine actually applies (verdicts.py: ≥2 independent
modality classes to confirm).

Run ``python3 confirmability.py`` to write build/reports/
signature_confirmability.{json,md} + producer_signature_reconciliation.md.
"""
from __future__ import annotations

import json
from pathlib import Path

from catalog import Catalog, Template, builtin_catalog
from coverage import (
    COLLECTION_PENDING,
    EMITTED_KINDS,
    NORMALIZATION_PENDING,
    classify_kind,
)
from signals import EVIDENCE_CLASS_BY_KIND, ModalityClass

# ── kind → modality class of its PRODUCTION producer ─────────────────────────
# The audit's ground truth for evidence-independence math. Completeness is
# CI-enforced (test_confirmability: every emitted kind must be mapped) so a new
# producer kind cannot enter unclassified; correctness is by review against the
# emit site (each entry mirrors the ModalityClass its producer stamps).
KIND_MODALITY: dict[str, ModalityClass] = {
    # active-probe lane (prober STAMP/synthetics; synthetic_normalize.py)
    "probe_loss": ModalityClass.ACTIVE_PROBE,
    "probe_rtt_anomaly": ModalityClass.ACTIVE_PROBE,
    "synthetic_http_fail": ModalityClass.ACTIVE_PROBE,
    "synthetic_http_5xx": ModalityClass.ACTIVE_PROBE,
    "synthetic_http_4xx": ModalityClass.ACTIVE_PROBE,
    "synthetic_http_latency_high": ModalityClass.ACTIVE_PROBE,
    "synthetic_tls_fail": ModalityClass.ACTIVE_PROBE,
    "synthetic_dns_fail": ModalityClass.ACTIVE_PROBE,
    "synthetic_tcp_connect_fail": ModalityClass.ACTIVE_PROBE,
    "synthetic_timeout": ModalityClass.ACTIVE_PROBE,
    "synthetic_icmp_loss": ModalityClass.ACTIVE_PROBE,
    "synthetic_tcp_probe_fail": ModalityClass.ACTIVE_PROBE,
    "synthetic_cert_expired": ModalityClass.ACTIVE_PROBE,
    "synthetic_cert_expiring": ModalityClass.ACTIVE_PROBE,
    # passive-flow lane
    "flow_volume_anomaly": ModalityClass.PASSIVE_FLOW,
    "cloud_flow_log": ModalityClass.PASSIVE_FLOW,
    # cloud-edge fault lane: LB 5xx, WAF block, DNS NXDOMAIN are PASSIVE_FLOW
    # cloud-API observations (mirrors cloud_producers.CLOUD_KINDS). Consumed by
    # the P2 path-causality attributor AND the dependency-graph attribution
    # signatures (sig.ent.app.edge-*); registered here so the audit's
    # independence math counts a cloud-edge fault as a real (passive_flow)
    # witness rather than an unclassified kind.
    "cloud_lb_log": ModalityClass.PASSIVE_FLOW,
    "cloud_waf_log": ModalityClass.PASSIVE_FLOW,
    "cloud_dns_log": ModalityClass.PASSIVE_FLOW,
    # control-plane lane (syslog/trap/route events)
    "bgp_adjacency_change": ModalityClass.CONTROL_PLANE,
    # tracker 184 — BGP session churn / prefix pressure, from the device's own
    # syslog: the same observer class as the adjacency change it corroborates.
    "bgp_route_churn": ModalityClass.CONTROL_PLANE,
    "ospf_adjacency_change": ModalityClass.CONTROL_PLANE,
    "isis_adjacency_change": ModalityClass.CONTROL_PLANE,
    "routing_adjacency_change": ModalityClass.CONTROL_PLANE,
    "link_state_change": ModalityClass.CONTROL_PLANE,
    "stp_topology_change": ModalityClass.CONTROL_PLANE,
    "mac_flap": ModalityClass.CONTROL_PLANE,
    "evpn_mac_move": ModalityClass.CONTROL_PLANE,
    "vtep_state_change": ModalityClass.CONTROL_PLANE,
    "fhrp_state_change": ModalityClass.CONTROL_PLANE,
    "device_restart": ModalityClass.CONTROL_PLANE,
    "device_alarm": ModalityClass.CONTROL_PLANE,
    "lldp_neighbor_change": ModalityClass.CONTROL_PLANE,
    "cloud_change": ModalityClass.CONTROL_PLANE,
    "cloud_audit": ModalityClass.CONTROL_PLANE,
    # IPsec/IKE tunnel state from the enterprise VPN gateway — control plane, but
    # an observer independent of the cloud API (ipsec:<gw>), so it corroborates.
    "ipsec_tunnel_status": ModalityClass.CONTROL_PLANE,
    # The gateway's off-tunnel check to the peer's public address — an active
    # measurement of the underlay (rides the default route, not the tunnel).
    "ipsec_underlay_status": ModalityClass.ACTIVE_PROBE,
    # device-telemetry lane (metric episodes; cloud health)
    "if_metric_anomaly": ModalityClass.DEVICE_TELEMETRY,
    "bgp_state_anomaly": ModalityClass.DEVICE_TELEMETRY,
    "device_resource_anomaly": ModalityClass.DEVICE_TELEMETRY,
    # Provider-reported cloud resource health/utilization (CloudWatch / Azure
    # Monitor). DEVICE_TELEMETRY: an INDEPENDENT observer class from the active
    # probes, so provider health + a synthetic app check can co-confirm a cloud
    # app fault — the gap that made cloud verdicts un-confirmable.
    "cloud_resource_anomaly": ModalityClass.DEVICE_TELEMETRY,
    "cloud_health": ModalityClass.DEVICE_TELEMETRY,
    # app-edge lane (#98 P5 — LB/proxy/ingress reporting its own counters;
    # attrs.lane="app_gateway", independent of probes and flows in the gate)
    "lb_5xx": ModalityClass.DEVICE_TELEMETRY,
    "lb_target_unhealthy": ModalityClass.DEVICE_TELEMETRY,
    "app_error_rate_high": ModalityClass.DEVICE_TELEMETRY,
    "app_latency_high": ModalityClass.DEVICE_TELEMETRY,
    "lb_4xx_high": ModalityClass.DEVICE_TELEMETRY,
    # NMS controller lane (management plane — corroborating, never self-confirming)
    "controller_tunnel_state": ModalityClass.MANAGEMENT_PLANE,
    "controller_bfd_down": ModalityClass.MANAGEMENT_PLANE,
    "controller_control_connection_loss": ModalityClass.MANAGEMENT_PLANE,
    "controller_device_unreachable": ModalityClass.MANAGEMENT_PLANE,
    "controller_policy_change": ModalityClass.MANAGEMENT_PLANE,
    # Wireless state-transition lane (#128 — nms/wireless_events.go stamps
    # management_plane via_controller).
    "wireless_ap_down": ModalityClass.MANAGEMENT_PLANE,
    "wireless_ap_up": ModalityClass.MANAGEMENT_PLANE,
    "wireless_ap_join_flap": ModalityClass.MANAGEMENT_PLANE,
    "wireless_radio_down": ModalityClass.MANAGEMENT_PLANE,
    "wireless_radio_up": ModalityClass.MANAGEMENT_PLANE,
    # clock-skew meta-finding (log-time standard S5/R5): the PLATFORM is the
    # witness (it compared origin vs receive clocks) — management-plane, and
    # never engine-buffered, so it cannot lend a confirming plane to a fault.
    "clock_skew": ModalityClass.MANAGEMENT_PLANE,
    # active-verification lane (RCA spec item 8 — the verify engine's bounded
    # read-only check battery; verification_producer.py). Its own modality so
    # a device answer can be the independence gate's second source.
    "active_verification_result": ModalityClass.ACTIVE_VERIFICATION,
    "active_verification_healthy": ModalityClass.ACTIVE_VERIFICATION,
}

# Evidence-class bus lanes (T2b) register DECLARATIVELY: their modality is the
# one their `EvidenceClassSpec` stamps, read from the same registry the intake
# adapter reads, so the audit's independence math and the runtime Signal can
# never disagree. No class is named here — adding or removing a class is a
# registry edit, and this loop is unchanged either way.
KIND_MODALITY.update(
    {kind: spec.modality for kind, spec in EVIDENCE_CLASS_BY_KIND.items()})

# Kinds whose PRODUCTION signals can ground on an application/service entity
# (app:/host: tokens) so they can co-locate on an app-impact object. The
# synthetic lane resolves app identity (synthetic_normalize.resolve_app).
# flow_volume_anomaly joined in #98 Phase 4: flow_app_attribution.py +
# main._flush_flow_aggregator emit an app-grounded anomaly WHEN a confirming
# attribution source names the app (explicit metadata / appid fusion /
# operator prefix map) — unattributed flows stay interface-grounded and do
# not count toward app confirmation.
APP_GROUNDABLE_KINDS: frozenset[str] = frozenset(
    k for k in KIND_MODALITY if k.startswith("synthetic_")
) | frozenset({
    "flow_volume_anomaly",
    # app-edge lane (#98 P5): lb_normalize grounds on the app/service entity
    # with app:<slug> tokens by construction.
    "lb_5xx", "lb_target_unhealthy", "app_error_rate_high", "app_latency_high",
    "lb_4xx_high",
    # cloud lane: cloud_health is emitted ON the app entity (cloud_signal:
    # entity_type=app), and the edge-device fault kinds (LB access 5xx / WAF
    # block / SG-NACL reject / DNS failure) reach the app through the Service
    # Dependency Map — cloud_dependency.py builds tier→app RouteRelations +
    # flow-observed PathObservations that main.path_graph_inventory() merges
    # into the grounding view, so the device fault and the app symptom share ONE
    # object (plus cloud_signal's own app entity_tokens when the ingest event
    # names the app). This supersedes the earlier cloud_waf_log exclusion (the
    # web ACL grounds on a CLOUD_RESOURCE): the dependency edge is what carries
    # it to the app now, grounding-gated exactly like flow_volume_anomaly above —
    # a device fault with no dependency edge to the app stays resource-grounded
    # and does not count toward app confirmation.
    "cloud_health", "cloud_lb_log", "cloud_waf_log", "cloud_dns_log",
    "cloud_flow_log",
})

# App-impact domains whose objects ground on app/service entities, so a second
# modality only helps them if its producer can reach that entity.
APP_DOMAINS: frozenset[str] = frozenset({"ent.app"})

# Structured, ticketed exceptions for the P0 gate: matchable p0 signatures that
# cannot reach confirmed today and are ALLOWED to ship in that state, each with
# an owner and a target resolution. Anything not listed fails CI.
DEMO_CONFIRMABILITY_EXCEPTIONS: dict[str, dict] = {
    "sig.ent.wireless.ap-software-fault": {
        "reason": "this family is diagnosed by the ABSENCE of the second "
                  "witness — the uplink port staying up is what separates an "
                  "AP-side fault from power/cable. Its only positive evidence "
                  "is therefore the controller (management plane), and the "
                  "suspected cap is the honest ceiling by construction",
        "owner": "correlix",
        "date_added": "2026-07-26",
        "target_resolution": "wireless Phase 9 (live validation): an active "
                             "reach probe against the AP mgmt address can be "
                             "the confirming second modality once a real AP "
                             "exists to validate the probe path against",
    },
    "sig.ent.wireless.wlc-failover": {
        "reason": "a controller failover's only witness today IS the management "
                  "plane (the WLC reporting its own member states), so the "
                  "verdict correctly caps at suspected — the report's B2 "
                  "finding: controller-alone-cannot-confirm is by design, and "
                  "for THIS fault family the second witness does not exist "
                  "until AP-uplink switch telemetry or an AP-join storm from "
                  "a second observer corroborates",
        "owner": "correlix",
        "date_added": "2026-07-26",
        "target_resolution": "wireless Phase 4+: corroborate via the AP-join "
                             "flap burst on device_telemetry (uplink switch "
                             "ports of re-joining APs) or a platform probe "
                             "against the failed member's mgmt address",
    },
    "sig.ent.cloud.region-degradation": {
        "reason": "became MATCHABLE via the #98 P5 lb_5xx lane, but its "
                  "required control_plane modality has no producer path among "
                  "its referenced kinds (cloud_gw_anomaly collection-pending; "
                  "cloud_health_event is a declared normalization gap — the "
                  "phenomenon flows as cloud_health) → verdict caps at suspected",
        "owner": "correlix",
        "date_added": "2026-07-09",
        "target_resolution": "resolve the cloud_health_event vocabulary mismatch "
                             "(NORMALIZATION_PENDING #81) or add a control-plane "
                             "witness kind to the template",
    },
    "sig.ent.fabric.spine-leaf-path-degradation": {
        "reason": "demands device_telemetry + active_probe, but its telemetry "
                  "witnesses (if_errors/if_crc) are a NORMALIZATION gap — the "
                  "counters are polled into VictoriaMetrics yet no producer "
                  "emits the signal kinds, so the verdict caps at suspected",
        "owner": "correlix",
        "date_added": "2026-07-09",
        "target_resolution": "if_errors/if_discards anomaly producer (#73; "
                             "NORMALIZATION_PENDING entries in coverage.py)",
    },
}


def _clause_kinds(t: Template, optional: bool) -> list[frozenset[str]]:
    return [c.kinds() for c in t.requires if c.optional is optional]


def audit_template(t: Template) -> dict:
    """One signature's confirmability row (see module docstring for semantics)."""
    required = _clause_kinds(t, optional=False)
    optional = _clause_kinds(t, optional=True)
    all_kinds: frozenset[str] = frozenset().union(*required, *optional) if (required or optional) else frozenset()
    available = all_kinds & EMITTED_KINDS
    missing = all_kinds - EMITTED_KINDS

    matchable = all(clause & EMITTED_KINDS for clause in required)
    modalities = {KIND_MODALITY[k] for k in available if k in KIND_MODALITY}

    # required_modalities is a verdict CAP in the engine (scoring.py →
    # verdicts.assess over ALL matched signals, optional clauses included):
    # a demanded modality with no producer path among the referenced kinds
    # means the signature can match but never confirm.
    req_modalities_ok = all(
        any(KIND_MODALITY.get(k) is m for k in available)
        for m in t.required_modalities
    )

    # Independence math mirrors verdicts.py conservatively: confirmation needs
    # ≥2 distinct modality classes. For app-domain signatures the 2nd modality
    # must additionally come from a kind that can ground on the app entity.
    app_domain = t.domain in APP_DOMAINS
    groundable_modalities = {
        KIND_MODALITY[k] for k in available
        if k in KIND_MODALITY and (not app_domain or k in APP_GROUNDABLE_KINDS)
    }
    effective_modalities = groundable_modalities if app_domain else modalities

    if not matchable:
        max_verdict = "not_matchable"
        if any(k in NORMALIZATION_PENDING for k in missing):
            status = "normalization_pending"
        elif any(k in COLLECTION_PENDING for k in missing):
            status = "collection_pending"
        else:
            status = "not_matchable"
    elif not req_modalities_ok:
        # matches, but a demanded modality has no producer path → verdict capped.
        max_verdict, status = "suspected", "modality_mismatch"
    elif len(effective_modalities) >= 2:
        max_verdict, status = "confirmed", "confirmable_now"
    elif len(modalities) >= 2 and app_domain:
        # a 2nd modality EXISTS but cannot reach the app entity — the honest
        # passive-flow/interface finding this audit exists to surface.
        max_verdict, status = "suspected", "entity_mismatch"
    else:
        max_verdict, status = "suspected", "suspected_only"

    return {
        "signature_id": t.id,
        "signature_name": t.title,
        "priority": t.demo_priority,
        "domain": t.domain,
        "required_kinds": sorted(frozenset().union(*required)) if required else [],
        "optional_kinds": sorted(frozenset().union(*optional)) if optional else [],
        "available_kinds": sorted(available),
        "missing_kinds": sorted(missing),
        "pending_collection_kinds": sorted(missing & frozenset(COLLECTION_PENDING)),
        "pending_normalization_kinds": sorted(missing & frozenset(NORMALIZATION_PENDING)),
        "producer_classes_available": sorted(m.value for m in modalities),
        "app_groundable_classes": sorted(m.value for m in groundable_modalities) if app_domain else None,
        "max_possible_verdict": max_verdict,
        "status": status,
        "demo_ready": status == "confirmable_now",
    }


def audit(catalog: Catalog | None = None) -> list[dict]:
    cat = catalog or builtin_catalog()
    return [audit_template(t) for t in cat.enabled_templates()]


def reconciliation(catalog: Catalog | None = None) -> list[dict]:
    """Producer → kind → consumer table (report section A)."""
    cat = catalog or builtin_catalog()
    consumers: dict[str, list[str]] = {}
    for t in cat.enabled_templates():
        for c in t.requires:
            for k in c.kinds():
                consumers.setdefault(k, []).append(t.id)
    rows = []
    for kind in sorted(EMITTED_KINDS | frozenset(consumers)):
        rows.append({
            "kind": kind,
            "emitted": kind in EMITTED_KINDS,
            "modality": KIND_MODALITY[kind].value if kind in KIND_MODALITY else None,
            "app_groundable": kind in APP_GROUNDABLE_KINDS,
            "consuming_signatures": sorted(set(consumers.get(kind, []))),
            "class": classify_kind(kind, cat),
        })
    return rows


def _md_table(rows: list[dict], cols: list[str]) -> str:
    head = "| " + " | ".join(cols) + " |\n|" + "|".join("---" for _ in cols) + "|\n"
    body = ""
    for r in rows:
        body += "| " + " | ".join(
            ", ".join(v) if isinstance(v := r.get(c), list) else str(v)
            for c in cols
        ) + " |\n"
    return head + body


def write_reports(out_dir: str = "build/reports") -> list[str]:
    cat = builtin_catalog()
    rows, recon = audit(cat), reconciliation(cat)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []

    j = out / "signature_confirmability.json"
    j.write_text(json.dumps({"signatures": rows, "reconciliation": recon}, indent=1))
    written.append(str(j))

    by_status: dict[str, int] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    md = out / "signature_confirmability.md"
    md.write_text(
        "# Signature confirmability\n\n"
        f"Status counts: `{json.dumps(by_status, sort_keys=True)}`\n\n"
        "## Signatures\n\n"
        + _md_table(rows, ["signature_id", "priority", "status", "max_possible_verdict",
                           "producer_classes_available", "pending_collection_kinds",
                           "pending_normalization_kinds"])
        + "\n## Producer ↔ signature reconciliation\n\n"
        + _md_table(recon, ["kind", "emitted", "modality", "app_groundable",
                            "class", "consuming_signatures"])
    )
    written.append(str(md))
    return written


if __name__ == "__main__":
    for path in write_reports():
        print(path)
