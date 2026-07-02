"""Failure-signature catalog — hypothesis templates as DATA (#67 §4.5).

The catalog is the engine's rule base: declarative predicates authored by
practitioners, validated on load, versioned as a content hash, and CI-gated by
per-signature replay fixtures (research C7: the catalog is a CI-tested
versioned artifact, never loose JSON).

Storage of record is Postgres ``corr_hypothesis_templates`` (tenant '' = the
built-in set below; tenants may shadow ids). This module owns the SPEC: schema
validation (a malformed template is rejected at load, never half-evaluated),
the canonical content hash that snapshots pin as ``catalog_version`` (replay
contract, research C6), and the built-in starter set.

Template anatomy (mirrors the owner's plain-English authoring format):
  requires        → the evidence chain (coverage = satisfied/total)
  discriminators  → the look-alike killers; violation tanks the score AND
                    force-evaluates the named competitor
  required_modalities → per-fault-class demand fed to the verdict gate (③)
  applies_when    → optional topology guard (seam redundancy model — groups,
                    cloud-ingestion.md §4)
  verdict         → layer + OWNER + first steps (Recommended Actions panel)
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from signals import EntityType, ModalityClass

CATALOG_SCHEMA_VERSION = 1


class Clause(BaseModel):
    """One evidence predicate. ``kind`` accepts alternation ('qos_drops|if_discards');
    a signal satisfies the clause if its kind is one of the tokens and every
    present constraint holds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str = Field(min_length=1)
    entity_type: EntityType | None = None
    min_deviation: float | None = Field(default=None, ge=0)
    role: str | None = None          # topology role (primary/fallback/wan_edge) — scored when ctx known
    optional: bool = False

    @field_validator("kind")
    @classmethod
    def _kind_tokens_nonempty(cls, v: str) -> str:
        if any(not t.strip() for t in v.split("|")):
            raise ValueError(f"empty alternation token in kind {v!r}")
        return v

    def kinds(self) -> frozenset[str]:
        return frozenset(t.strip() for t in self.kind.split("|"))


class Discriminator(BaseModel):
    """Look-alike killer: if the 'absent' clause IS present in evidence, this
    template is contradicted (score ×0.2) and ``else_prefer`` must be scored
    as a competitor — competing hypotheses by construction, never collapsed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    absent: Clause                   # the thing that must NOT be in evidence
    within_s: float = Field(default=600.0, gt=0)
    else_prefer: str = Field(min_length=1)


class Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    owner: Literal["netops", "carrier", "cloud_provider", "app_team",
                   "colo_provider", "isp", "sdwan_vendor"]
    layer: str = Field(min_length=1)            # "L1/L2", "L3/L4", ...
    first_steps: tuple[str, ...] = Field(min_length=1, max_length=5)


class AppliesWhen(BaseModel):
    """Topology guard. Unknown topology context ⇒ the template still applies
    but is marked topology_unverified — skipping hypotheses because we lack a
    seam inventory would hide real explanations (fail-open on applicability,
    fail-closed stays where it belongs: edges and verdicts)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    redundancy_model: tuple[str, ...] | None = None  # e.g. ("active_standby", "active_active")


# External seam-facing taxonomy for the v1 NOC catalog (owner spec 2026-07-02,
# docs/design/research/midnight-noc-questions.md): which of the five operational
# seams a fault family lives on, and where it can occur at all. These are
# METADATA for attribution/UX/AI narration — grounding and verdict gating stay
# with the engine's seam inventory and the independence rules (unchanged).
Seam = Literal["LAN", "WAN_SDWAN", "DC_FABRIC", "CARRIER_INTERCONNECT", "CLOUD_APP"]
DeploymentScope = Literal["onprem_only", "cloud_only", "hybrid"]


class Template(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^sig\.[a-z0-9_.-]+$")  # namespaced: sig.<persona>.<domain>.<name>
    title: str = Field(min_length=1)
    domain: str = Field(pattern=r"^(ent|sp)\.[a-z-]+$")
    version: int = Field(default=1, ge=1)
    enabled: bool = True
    requires: tuple[Clause, ...] = Field(min_length=1)
    discriminators: tuple[Discriminator, ...] = ()
    required_modalities: tuple[ModalityClass, ...] = ()
    applies_when: AppliesWhen | None = None
    direction_expect: str = ""
    verdict: Verdict
    # ---- v1 NOC-catalog fields (all optional — the pre-v1 templates omit them).
    seams: tuple[Seam, ...] = ()
    deployment_scope: DeploymentScope = "hybrid"
    # The voice contract (owner wording rules): a precise evidence-based line
    # for the NOC operator, and a plain-English impact line for a manager.
    # Neither may overclaim — they describe the fault FAMILY, the tier label is
    # supplied by the verdict gate at match time.
    operator_phrase: str = ""
    manager_phrase: str = ""
    blast_radius: str = ""                     # likely scope in operational terms
    false_positives: tuple[str, ...] = ()      # common look-alikes to disclose
    composition_hints: tuple[str, ...] = ()    # higher-level incidents this rolls into
    demo_priority: Literal["p0", "p1", "p2"] = "p0"

    @field_validator("requires")
    @classmethod
    def _at_least_one_mandatory(cls, v: tuple[Clause, ...]) -> tuple[Clause, ...]:
        if all(c.optional for c in v):
            raise ValueError("template needs >=1 non-optional requires clause")
        return v


class Catalog(BaseModel):
    model_config = ConfigDict(frozen=True)

    templates: tuple[Template, ...]

    @field_validator("templates")
    @classmethod
    def _checks(cls, v: tuple[Template, ...]) -> tuple[Template, ...]:
        ids = [t.id for t in v]
        if len(ids) != len(set(ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate template ids: {dupes}")
        # discriminator targets must resolve inside the catalog AND must not
        # form a contradiction cycle that flip-flops scoring (lint, C7).
        known = set(ids)
        for t in v:
            for d in t.discriminators:
                if d.else_prefer not in known:
                    raise ValueError(f"{t.id}: else_prefer {d.else_prefer!r} not in catalog")
                if d.else_prefer == t.id:
                    raise ValueError(f"{t.id}: discriminator prefers itself")
            # v1 NOC-catalog lint: a template that declares seams opted into the
            # voice contract — both phrasings are mandatory, and a confirmable
            # template must not be confirmable from a single evidence plane
            # (the verdict gate enforces ≥2 modalities at runtime regardless;
            # this catches an author FORGETTING to declare the second one).
            if t.seams:
                if not t.operator_phrase.strip() or not t.manager_phrase.strip():
                    raise ValueError(f"{t.id}: seam-tagged template needs operator_phrase and manager_phrase")
                if len(t.required_modalities) == 1 and len({k for c in t.requires for k in c.kinds()}) < 2:
                    raise ValueError(f"{t.id}: confirmable template needs evidence beyond a single kind/plane")
        return v

    def enabled_templates(self) -> tuple[Template, ...]:
        return tuple(t for t in self.templates if t.enabled)

    def get(self, template_id: str) -> Template | None:
        for t in self.templates:
            if t.id == template_id:
                return t
        return None

    def version_hash(self) -> str:
        """Canonical content hash → ``corr_objects.catalog_version``. Stable
        across process restarts and dict ordering; changes iff an enabled
        template's content changes (replay contract)."""
        canon = json.dumps(
            [t.model_dump(mode="json") for t in sorted(self.enabled_templates(), key=lambda t: t.id)],
            sort_keys=True, separators=(",", ":"),
        )
        digest = hashlib.sha256(f"v{CATALOG_SCHEMA_VERSION}|{canon}".encode()).hexdigest()
        return f"cat-{digest[:12]}"


def load_catalog(raw: list[dict]) -> Catalog:
    """Validate raw template dicts (from PG rows or the built-in set) into a
    Catalog. Raises pydantic.ValidationError with the offending template —
    a bad catalog never half-loads."""
    return Catalog(templates=tuple(Template(**t) for t in raw))


# ---------------------------------------------------------------------------
# Built-in starter set (tenant_id = ''). Six signatures from the design §4.5,
# namespaced per the persona/domain segmentation (owner, 2026-06-11). These
# exercise the full machinery and SHOW the authoring shape; the practitioner
# catalog replaces/extends them at P3 — same schema, hot-reloaded from PG.
# ---------------------------------------------------------------------------

BUILTIN_TEMPLATES: list[dict] = [
    {
        "id": "sig.ent.wan-edge.congestion",
        "title": "WAN edge congestion",
        "domain": "ent.wan-edge",
        "requires": [
            {"kind": "if_util_high", "entity_type": "interface", "role": "wan_edge"},
            {"kind": "probe_loss|probe_latency_departure", "entity_type": "segment", "min_deviation": 3.0},
            {"kind": "qos_drops|if_discards", "entity_type": "interface", "optional": True},
        ],
        "required_modalities": ["device_telemetry", "active_probe"],
        "discriminators": [
            {"absent": {"kind": "bgp_path_change"}, "within_s": 600,
             "else_prefer": "sig.ent.wan-edge.routing-instability"},
            {"absent": {"kind": "if_errors", "min_deviation": 3.0},
             "else_prefer": "sig.ent.middle-mile.physical-degradation"},
        ],
        "direction_expect": "interface -> path -> service",
        "verdict": {
            "owner": "netops", "layer": "L3/L4",
            "first_steps": [
                "Check QoS queue drops per class on the WAN edge",
                "Compare utilization vs CIR on the affected circuit",
                "Look for a traffic shift: routing change or new top-talker",
            ],
        },
    },
    {
        "id": "sig.ent.wan-edge.routing-instability",
        "title": "Routing instability / path churn",
        "domain": "ent.wan-edge",
        "requires": [
            {"kind": "bgp_path_change|bgp_peer_flap"},
            {"kind": "probe_latency_departure|path_change", "entity_type": "segment", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            {"absent": {"kind": "if_errors", "min_deviation": 3.0},
             "else_prefer": "sig.ent.middle-mile.physical-degradation"},
        ],
        "direction_expect": "control-plane -> path -> service",
        "verdict": {
            "owner": "netops", "layer": "L3",
            "first_steps": [
                "Identify what triggered the path change (peer flap, policy push, prefix withdrawal)",
                "Check whether the new path violates latency/geo expectations",
                "Dampen or pin the route if churn is ongoing",
            ],
        },
    },
    {
        "id": "sig.ent.middle-mile.physical-degradation",
        "title": "Circuit/optics physical degradation",
        "domain": "ent.middle-mile",
        "requires": [
            {"kind": "if_errors|if_crc|optical_power_low", "entity_type": "interface", "min_deviation": 3.0},
            {"kind": "probe_loss", "entity_type": "segment", "optional": True},
        ],
        "required_modalities": ["device_telemetry"],
        "discriminators": [
            {"absent": {"kind": "if_util_high", "min_deviation": 3.0},
             "else_prefer": "sig.ent.wan-edge.congestion"},
        ],
        "direction_expect": "physical -> path -> service",
        "verdict": {
            "owner": "carrier", "layer": "L1/L2",
            "first_steps": [
                "Pull light levels / error counters on the cross-connect interface",
                "Shift traffic to a healthy group member if one exists",
                "Open the carrier ticket with timestamped error deltas",
            ],
        },
    },
    {
        "id": "sig.ent.internet.dns-impairment",
        "title": "DNS resolution impairment",
        "domain": "ent.internet",
        "requires": [
            {"kind": "dns_latency_high|dns_failure_rate"},
            {"kind": "synthetic_http_fail", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            {"absent": {"kind": "probe_loss", "min_deviation": 3.0},
             "else_prefer": "sig.ent.wan-edge.congestion"},
        ],
        "direction_expect": "dns -> service",
        "verdict": {
            "owner": "isp", "layer": "DNS/L7",
            "first_steps": [
                "Compare resolver health: local forwarder vs upstream vs public resolver",
                "Check whether failures are domain-scoped (SaaS-side) or global (resolver-side)",
                "Fail over to the secondary resolver path",
            ],
        },
    },
    {
        "id": "sig.ent.cloud.region-degradation",
        "title": "Cloud region / backbone degradation",
        "domain": "ent.cloud",
        "requires": [
            {"kind": "probe_latency_departure|probe_loss", "entity_type": "segment", "min_deviation": 3.0},
            # NOT optional: assigning cloud-provider blame without any cloud-side
            # witness is exactly the over-claim this engine refuses — probe loss
            # alone matches too many failure modes (caught by fixture battle:
            # the MTU scenario's probe_loss gave this template full coverage).
            {"kind": "lb_5xx|cloud_gw_anomaly|cloud_health_event"},
        ],
        "required_modalities": ["active_probe", "control_plane"],
        "discriminators": [
            {"absent": {"kind": "if_util_high", "min_deviation": 3.0},
             "else_prefer": "sig.ent.wan-edge.congestion"},
            {"absent": {"kind": "if_errors", "min_deviation": 3.0},
             "else_prefer": "sig.ent.middle-mile.physical-degradation"},
        ],
        "direction_expect": "cloud-seam -> service",
        "verdict": {
            "owner": "cloud_provider", "layer": "L3 (provider)",
            "first_steps": [
                "Compare probes into the same region from a second vantage (multi-site divergence)",
                "Check the provider health dashboard / personal health API for the region",
                "Shift latency-sensitive traffic to an alternate region if architecture allows",
            ],
        },
    },
    {
        # #81 — hybrid private-connectivity outage: Direct Connect / IPSec tunnel
        # between on-prem and the cloud goes down → BGP drops, routes withdraw,
        # the cloud app is unreachable FROM corporate (often still fine from the
        # internet). Matches the real cloud signal kinds (cloud_change = DX/VPN
        # state, cloud_flow_log = boundary REJECT, cloud_health = unreachable),
        # corroborated by a customer-path probe. Without this, the bare probe_loss
        # mis-matched 'dia-egress-latency' (a latency signature) — see the
        # discriminator added there.
        "id": "sig.ent.cloud.private-connectivity-down",
        "title": "Private connectivity to cloud down (Direct Connect / IPSec)",
        "domain": "ent.cloud",
        "requires": [
            # the root: a DX virtual-interface / VPN tunnel state change.
            {"kind": "cloud_change|cloud_audit"},
            # the impact: traffic rejected at the boundary, or the app unreachable.
            {"kind": "cloud_flow_log|cloud_health"},
            # independent customer-path witness (lifts to a confirmable verdict).
            {"kind": "probe_loss|probe_rtt_anomaly", "optional": True},
        ],
        # confirmation needs the control-plane change AND an independent probe —
        # a cloud-only picture (one vantage) stays suspected (verdict gate).
        "required_modalities": ["control_plane", "active_probe"],
        "direction_expect": "cloud-seam -> service",
        "verdict": {
            "owner": "carrier", "layer": "L3 (private connectivity — DX / IPSec)",
            "first_steps": [
                "Check the Direct Connect virtual interface + its BGP session (idle/withdrawn routes)",
                "Check the backup IPSec tunnel (phase-1/phase-2, DPD) to the on-prem SD-WAN edge",
                "Verify route propagation on-prem↔VPC; fail traffic to the alternate path if one exists",
                "Confirm the cloud app is reachable from the internet (isolates connectivity vs app fault)",
            ],
        },
    },
    {
        "id": "sig.ent.wan-edge.tunnel-mtu-blackhole",
        "title": "Tunnel MTU blackhole",
        "domain": "ent.wan-edge",
        "requires": [
            {"kind": "tunnel_degraded|tunnel_flap", "entity_type": "path"},
            {"kind": "synthetic_http_fail|app_large_transfer_fail"},
            {"kind": "probe_loss", "entity_type": "segment", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            {"absent": {"kind": "tunnel_down"},
             "else_prefer": "sig.ent.wan-edge.routing-instability"},
        ],
        "direction_expect": "tunnel -> session -> service",
        "verdict": {
            "owner": "netops", "layer": "Tunnel/L4",
            "first_steps": [
                "Test with DF-bit pings at descending sizes across the tunnel (find the real PMTU)",
                "Check for ICMP type-3/code-4 being filtered along the underlay",
                "Clamp TCP MSS on the tunnel interface as immediate mitigation",
            ],
        },
    },
    # -----------------------------------------------------------------------
    # P3 signatures (2026-06-14) — authored from REAL observed lab objects, not
    # theory. These use the engine's actual emitted vocabulary (probe_rtt_anomaly
    # / probe_loss on path, bgp_adjacency_change / bgp_state_anomaly on device,
    # link_state_change + if_metric_anomaly on interface), so live correlation
    # objects finally match a signature instead of falling to the alphabetical
    # evidence_missing tie-break. Seeds: object 60e00be9 (DIA seam), the orphaned
    # wan-r2 BGP anomaly, and link+interface co-faults.
    # -----------------------------------------------------------------------
    {
        "id": "sig.ent.middle-mile.dia-egress-latency",
        "title": "ISP / DIA egress latency",
        "domain": "ent.middle-mile",
        "requires": [
            # Multi-vantage RTT/loss to a shared target across the DIA seam. The
            # ≥2-observer demand is enforced by the verdict gate, not the clause.
            {"kind": "probe_rtt_anomaly|probe_loss", "entity_type": "path"},
            # The corroborating WAN egress interface witness that lifts a probe-
            # only suspicion to a confirmable, second-modality verdict.
            {"kind": "if_metric_anomaly", "entity_type": "interface", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            # Routing churn at the edge is a different fault — if BGP is moving,
            # this isn't pure egress latency.
            {"absent": {"kind": "bgp_adjacency_change|bgp_state_anomaly"}, "within_s": 600,
             "else_prefer": "sig.ent.wan-edge.bgp-peer-flap"},
            # #81 — a cloud DX/VPN state change present means this isn't ISP egress
            # latency at all; it's a private-connectivity outage. Yield to it so a
            # tunnel-down (probe_loss only, no real latency) stops reading as latency.
            {"absent": {"kind": "cloud_change|cloud_audit"}, "within_s": 600,
             "else_prefer": "sig.ent.cloud.private-connectivity-down"},
        ],
        "direction_expect": "path-egress -> service",
        "verdict": {
            "owner": "isp", "layer": "L3 (DIA / provider egress)",
            "first_steps": [
                "Compare the two vantage points to the same target across the DIA boundary — shared RTT/loss departure points at the ISP egress, not the host",
                "Check the WAN egress interface for utilization/error counters in the same window",
                "Open the ISP ticket with per-target RTT/loss deltas, timestamps, and the DIA seam id",
            ],
        },
    },
    {
        # Multi-plane DIA egress fault: the customer-path probe AND an independent
        # control-plane witness (BGP flap) BOTH degrade on the same seam. This is a
        # MORE-confirmed, more-specific hypothesis than either single-plane sibling
        # (dia-egress-latency = probe only; bgp-peer-flap = control-plane only), so
        # when both planes corroborate it wins on coverage (2/2 required, no
        # contradiction) and confirms via the cross-modality pair — the trusted
        # customer-path probe corroborating the control-plane fault (decision: a
        # probe alone never confirms; here it confirms ONLY alongside the independent
        # BGP witness, which verdicts.assess enforces). When only ONE plane is
        # present this signature is half-covered and loses to its single-plane
        # siblings, so it never disturbs their behavior.
        "id": "sig.ent.middle-mile.dia-egress-corroborated",
        "title": "DIA egress fault — probe + control-plane corroborated",
        "domain": "ent.middle-mile",
        "requires": [
            {"kind": "probe_rtt_anomaly|probe_loss", "entity_type": "path"},
            {"kind": "bgp_adjacency_change|bgp_state_anomaly", "entity_type": "device"},
        ],
        "required_modalities": ["active_probe", "control_plane"],
        "direction_expect": "path-egress -> control-plane -> service",
        "verdict": {
            "owner": "isp", "layer": "L3 (DIA / provider egress)",
            "first_steps": [
                "Confirm both witnesses share the DIA seam: the probe RTT/loss departure point and the flapping BGP peer are the same provider egress",
                "Check the WAN egress interface and the peer session for the same window (hold-timer expiry vs link bounce)",
                "Open the ISP ticket with the per-target RTT/loss deltas, the BGP flap timestamps, and the DIA seam id",
            ],
        },
    },
    {
        "id": "sig.ent.wan-edge.bgp-peer-flap",
        "title": "BGP peer flap",
        "domain": "ent.wan-edge",
        "requires": [
            # Adjacency-change (syslog, control_plane) or BGP-MIB state anomaly
            # (device_telemetry) — either witnesses the flap.
            {"kind": "bgp_adjacency_change|bgp_state_anomaly", "entity_type": "device"},
            # Optional downstream impact: host pressure, route-driven loss, or a
            # co-incident link event.
            {"kind": "device_resource_anomaly|probe_loss|link_state_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A flap with a concurrent link-down is really a link fault dragging
            # the session — prefer the L1/L2 explanation.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "control-plane -> route -> service",
        "verdict": {
            "owner": "netops", "layer": "L3 (routing)",
            "first_steps": [
                "Identify the peer and the flap trigger (hold-timer expiry, interface bounce, policy push, prefix withdrawal)",
                "Check the peering interface/link state and the underlay for the same window",
                "Dampen the session or pin the route if churn continues; escalate to the peer owner if the neighbor is external",
            ],
        },
    },
    {
        "id": "sig.ent.access.local-link-fault",
        "title": "Local link fault",
        "domain": "ent.access",
        "requires": [
            # The L1/L2 state transition AND a same-interface counter anomaly —
            # two planes on one port. (Same-interface co-location is the engine's
            # grounding job; the scorer needs both kinds present.)
            {"kind": "link_state_change", "entity_type": "interface"},
            {"kind": "if_metric_anomaly", "entity_type": "interface"},
        ],
        "required_modalities": ["control_plane", "device_telemetry"],
        "direction_expect": "interface(L1/L2) -> device -> service",
        "verdict": {
            "owner": "netops", "layer": "L1/L2",
            "first_steps": [
                "Check interface counters (errors/discards/flap count) and the transceiver/cable on the affected port",
                "Correlate the link-state syslog timestamp with the interface metric anomaly on the same interface",
                "If the port is an uplink, verify the peer side and fail over to a redundant member if available",
            ],
        },
    },
    # -----------------------------------------------------------------------
    # C5 signatures (2026-06-23) — the classic L2/L3 enterprise/DC fault families
    # the design enumerates (dedicated IGP, STP/loop, FHRP failover, MAC-flap). Each
    # is a Layer-3 DROP-IN: grounding (Layer 1) and the verdict gate are unchanged;
    # the Layer-2 signal `kind`s already arrive from the syslog/trap producers
    # (ospf/isis/stp via syslog_control_signal; fhrp_state_change + mac_flap added in
    # the same change). Single-modality control-plane evidence reaches `suspected`;
    # an independent off-box/SNMP witness lifts each to `confirmed` (verdicts.assess).
    # A coincident link-down deliberately defers the IGP/FHRP cause to local-link-fault
    # (the link drags the session); MAC-flap defers to STP when topology is also churning.
    # -----------------------------------------------------------------------
    {
        "id": "sig.ent.access.ospf-adjacency-flap",
        "title": "OSPF adjacency flap",
        "domain": "ent.access",
        "requires": [
            {"kind": "ospf_adjacency_change", "entity_type": "device"},
            # Independent corroboration: host pressure, route-driven loss, an interface
            # counter anomaly, or a co-incident link event on the adjacency.
            {"kind": "if_metric_anomaly|device_resource_anomaly|probe_loss|link_state_change",
             "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A flap with a concurrent link-down is a link fault dragging the IGP —
            # prefer the L1/L2 explanation.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "control-plane -> route -> service",
        "verdict": {
            "owner": "netops", "layer": "L3 (IGP)",
            "first_steps": [
                "Identify the OSPF neighbor and the flap trigger (dead-timer expiry, MTU mismatch, area/auth change, interface bounce)",
                "Check the adjacency interface and the underlay link for the same window",
                "If the neighbor is stuck in EXSTART/EXCHANGE, verify ip mtu on both ends; stabilize the interface if it is flapping",
            ],
        },
    },
    {
        "id": "sig.ent.fabric.isis-adjacency-flap",
        "title": "IS-IS adjacency flap (fabric IGP)",
        "domain": "ent.fabric",
        "requires": [
            {"kind": "isis_adjacency_change", "entity_type": "device"},
            # A vanished LLDP peer / interface counter anomaly / host pressure / link
            # event corroborates a real adjacency loss (LLDP is same-plane, so it
            # supports but does not by itself confirm — that needs a 2nd modality).
            {"kind": "if_metric_anomaly|device_resource_anomaly|lldp_neighbor_change|link_state_change",
             "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "control-plane -> route -> service",
        "verdict": {
            "owner": "netops", "layer": "L2/L3 (IS-IS fabric IGP)",
            "first_steps": [
                "Identify the IS-IS neighbor (system-id) and the level (L1/L2) that dropped, and the trigger (hold-timer expiry, MTU mismatch, level/area mismatch, interface bounce)",
                "Check the adjacency interface and its LLDP neighbor for the same window — a vanished LLDP peer corroborates a real link event",
                "Verify level and area config match on both ends; stabilize the interface if it is flapping",
            ],
        },
    },
    {
        "id": "sig.ent.access.stp-topology-change",
        "title": "STP topology change / L2 loop",
        "domain": "ent.access",
        "requires": [
            {"kind": "stp_topology_change", "entity_type": "interface"},
            # The loop's fingerprint — a broadcast/unknown-unicast storm (interface
            # util/discards) or a co-incident MAC flap — and the independent 2nd
            # modality that lifts a lone topology change to a confirmable loop.
            {"kind": "if_metric_anomaly|if_util_high|mac_flap", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A topology change WITH a coincident link transition is normal STP
            # reconvergence after a real link event — prefer the link fault.
            {"absent": {"kind": "link_state_change"}, "within_s": 120,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "interface(L2) -> bridge-domain -> service",
        "verdict": {
            "owner": "netops", "layer": "L2 (STP)",
            "first_steps": [
                "Find the port(s) cycling root/designated and whether topology-change notifications recur (a loop, not a one-off reconvergence)",
                "Check for a broadcast/unknown-unicast storm and MAC flapping in the same VLAN/window",
                "Verify BPDU guard / root guard on edge ports; shut the offending loop port and confirm the storm clears",
            ],
        },
    },
    {
        "id": "sig.ent.access.fhrp-failover",
        "title": "First-hop redundancy failover (HSRP/VRRP)",
        "domain": "ent.access",
        "requires": [
            {"kind": "fhrp_state_change", "entity_type": "device", "role": "fhrp_group"},
            # The gateway-reachability blip during the election (off-box probe), or the
            # tracked uplink's counter anomaly — the independent witness that confirms
            # real impact and distinguishes an election from a benign config event.
            {"kind": "probe_loss|probe_rtt_anomaly|if_metric_anomaly", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A real uplink/cable pull (link down) is a link fault, not an FHRP
            # election — prefer the L1/L2 explanation.
            {"absent": {"kind": "link_state_change"}, "within_s": 120,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "device -> gateway -> service",
        "verdict": {
            "owner": "netops", "layer": "L2/L3 (FHRP)",
            "first_steps": [
                "Confirm which member is Active/Master now and why the prior forwarder demoted (priority/preempt, tracked object/interface down, timer expiry)",
                "Check the standby uplink and any tracked interface for a coincident flap in the same window",
                "If failover is flapping, add priority hysteresis / fix the tracked object and verify preempt delay",
            ],
        },
    },
    {
        "id": "sig.ent.access.mac-flap",
        "title": "MAC flapping / move storm",
        "domain": "ent.access",
        "requires": [
            {"kind": "mac_flap", "entity_type": "device"},
            # The L2 instability shows up as an interface counter/util anomaly on the
            # oscillating ports — the independent second modality.
            {"kind": "if_metric_anomaly|if_util_high", "entity_type": "interface", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # If STP is also churning, the MAC moves are a SYMPTOM of the topology
            # change — prefer the STP signature as the root.
            {"absent": {"kind": "stp_topology_change"}, "within_s": 120,
             "else_prefer": "sig.ent.access.stp-topology-change"},
        ],
        "direction_expect": "interface(L2) -> bridge-domain -> service",
        "verdict": {
            "owner": "netops", "layer": "L2 (MAC)",
            "first_steps": [
                "Identify the flapping MAC, its VLAN, and the two ports it oscillates between",
                "Determine whether it is a physical loop, a dual-homed host / NIC-teaming misconfig, or a duplicate MAC",
                "Shut or isolate one of the two ports; confirm the flap stops and MAC learning stabilizes",
            ],
        },
    },
    # -----------------------------------------------------------------------
    # P3 overlay signatures (2026-06-24, #80) — the TWO emergent DC-overlay causes
    # the fault matrix marks SIG (everything else self-describing rides generic
    # ingestion). Layer-2 kinds emitted by the P2 producer branches: vtep_state_change
    # (NX-OS %NVE BFD), evpn_mac_move (Arista dup-MAC / NX-OS HMM / L2FM VXLAN loop).
    # -----------------------------------------------------------------------
    {
        "id": "sig.ent.fabric.vtep-unreachable",
        "title": "VTEP unreachable (VXLAN underlay → overlay)",
        "domain": "ent.fabric",
        "requires": [
            {"kind": "vtep_state_change", "entity_type": "device"},
            # The emergent angle: an underlay reachability/routing loss to the remote
            # VTEP loopback, or the overlay traffic impact — an independent witness
            # (probe = active_probe, if_metric = device_telemetry) confirms real blackhole.
            {"kind": "bgp_adjacency_change|ospf_adjacency_change|isis_adjacency_change|probe_loss|if_metric_anomaly",
             "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A local link-down dragging the VTEP is a link fault, not an overlay-
            # reachability fault — prefer the L1/L2 explanation.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "underlay -> vtep -> overlay-service",
        "verdict": {
            "owner": "netops", "layer": "L3 (VXLAN underlay / VTEP)",
            "first_steps": [
                "Confirm underlay reachability to the remote VTEP loopback (ping/BFD) and which VTEP went unreachable",
                "Check the underlay IGP/BGP to that loopback and the source NVE interface in the same window",
                "If the loopback is reachable but the tunnel is down, check NVE source-interface, VNI-to-VRF mapping, and BFD-for-VXLAN config",
            ],
        },
    },
    {
        "id": "sig.ent.fabric.evpn-l2-loop",
        "title": "EVPN L2 loop / MAC-mobility storm across VTEPs",
        "domain": "ent.fabric",
        "requires": [
            {"kind": "evpn_mac_move", "entity_type": "device"},
            # The loop's fingerprint — a broadcast/util storm or tenant-path loss —
            # and the independent 2nd modality that confirms real overlay impact.
            {"kind": "if_metric_anomaly|if_util_high|probe_loss", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "direction_expect": "mac-mobility(overlay) -> bridge-domain(VNI) -> tenant-service",
        "verdict": {
            "owner": "netops", "layer": "L2 (EVPN overlay)",
            "first_steps": [
                "Identify the duplicated/blacklisted MAC, its VLAN/VNI, and the two VTEPs (or VTEP+port) it oscillates between",
                "Determine whether it is a dual-homed host / NIC-teaming or ESI multihoming misconfig, a back-door L2 path bridging two VTEPs, or a genuine duplicate MAC",
                "Break the loop (shut the back-door port / fix the ESI or multihoming config); confirm MAC mobility settles and the blacklist clears",
            ],
        },
    },
    # ------------------------------------------------------------------
    # v1 NOC catalog (owner failure-signature spec, 2026-07-02 — see
    # docs/design/research/midnight-noc-questions.md). P0 additions first;
    # entries reuse existing signal kinds wherever an equivalent exists and
    # introduce new kinds only where Layer 2 has no vocabulary yet (those
    # signatures attach as soon as the collectors emit the kind — the catalog
    # deliberately leads ingestion). Every entry carries the voice contract
    # (operator_phrase / manager_phrase) and its seam/deployment taxonomy.
    # De-duplicated against the pre-v1 set: local-link-fault, bgp-peer-flap
    # and dia-egress-latency(+corroborated) already existed and are NOT
    # re-implemented here.
    {
        "id": "sig.ent.access.vlan-trunk-mismatch",
        "title": "VLAN missing/pruned on trunk",
        "domain": "ent.access",
        "seams": ["LAN", "DC_FABRIC"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "vlan_reachability_fail|arp_fail", "entity_type": "device"},
            {"kind": "mac_table_missing|config_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A full physical link down explains every VLAN — prefer the link fault.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "trunk(VLAN) -> bridge-domain -> segment-service",
        "verdict": {
            "owner": "netops", "layer": "L2 (VLAN/trunk)",
            "first_steps": [
                "Compare the intended VLAN inventory against the trunk's allowed VLAN list on both ends",
                "Check ARP/MAC learning for the affected VLAN only — other VLANs on the same trunk should be clean",
                "Diff recent config changes on the trunk path (pruning, allowed-list edits, VTP)",
            ],
        },
        "operator_phrase": "Suspected VLAN/trunk mismatch. Impact is VLAN-specific while the physical path stays up — check trunk allowed lists and recent config diffs.",
        "manager_phrase": "Only a subset of network segments appears affected, suggesting a configuration or trunking issue rather than a full site outage.",
        "blast_radius": "one VLAN / segment on the shared trunk path",
        "false_positives": ["unused VLAN", "stale inventory", "endpoints moved", "STP blocking intentionally"],
        "composition_hints": ["access-segment incident when combined with STP churn on the same path"],
    },
    {
        "id": "sig.ent.access.dhcp-scope-exhaustion",
        "title": "DHCP pool exhausted or DHCP path failure",
        "domain": "ent.access",
        "seams": ["LAN"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "dhcp_fail|dhcp_scope_util_high", "entity_type": "device"},
            {"kind": "client_onboarding_fail", "optional": True},
            {"kind": "dhcp_relay_fail", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Broad L3 loss (static clients failing too) is a path fault, not DHCP.
            {"absent": {"kind": "probe_loss"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "dhcp-service -> new-clients -> segment",
        "verdict": {
            "owner": "netops", "layer": "L2/L3 (DHCP)",
            "first_steps": [
                "Check DHCP scope utilization and lease table for the affected segment",
                "Verify relay / ip helper configuration on the first-hop gateway",
                "Compare new-client onboarding failures against existing-client health (exhaustion hits new clients first)",
            ],
        },
        "operator_phrase": "Likely DHCP exhaustion or DHCP path issue — new clients fail to onboard while existing leases keep working.",
        "manager_phrase": "The issue appears to affect new device connectivity more than existing sessions.",
        "blast_radius": "new clients on the affected segment/site",
        "false_positives": ["client supplicant issues", "NAC denial", "wireless authentication failure"],
    },
    {
        "id": "sig.ent.access.dns-local-resolver-failure",
        "title": "Local DNS resolver failure",
        "domain": "ent.access",
        "seams": ["LAN", "CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "dns_failure_rate|dns_latency_high", "entity_type": "device"},
            {"kind": "synthetic_http_fail|fqdn_probe_fail"},
            {"kind": "device_resource_anomaly", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            # If raw IP paths are ALSO losing packets, this is a path fault, not DNS.
            {"absent": {"kind": "probe_loss"}, "within_s": 300,
             "else_prefer": "sig.ent.internet.dns-impairment"},
        ],
        "direction_expect": "resolver -> name-resolution -> app-access",
        "verdict": {
            "owner": "netops", "layer": "L7 (DNS)",
            "first_steps": [
                "Compare FQDN probes against IP probes to the same targets — DNS-only failure means IP paths stay clean",
                "Check resolver health (CPU/memory, cache, forwarders) and SERVFAIL/NXDOMAIN rates",
                "Diff recent DNS configuration changes and confirm which client population shares the failing resolver",
            ],
        },
        "operator_phrase": "Application reachability appears DNS-related, not pure network loss — FQDN probes fail while IP paths stay comparatively clean.",
        "manager_phrase": "The application may be reachable, but name resolution is preventing users from connecting normally.",
        "blast_radius": "clients sharing the failing resolver",
        "false_positives": ["application endpoint removed", "CDN change", "split-horizon DNS expectation", "expired DNS record"],
        "composition_hints": ["DNS incident when FQDN probes fail and IP probes pass across sites"],
    },
    {
        "id": "sig.ent.wan-edge.sdwan-tunnel-degraded",
        "title": "SD-WAN tunnel loss/jitter/latency",
        "domain": "ent.wan-edge",
        "seams": ["WAN_SDWAN"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "tunnel_degraded|tunnel_flap", "entity_type": "path"},
            {"kind": "probe_loss|probe_rtt_anomaly"},
            {"kind": "path_change|if_errors|if_util_high", "optional": True},
        ],
        "required_modalities": ["active_probe", "control_plane"],
        "discriminators": [
            # Tunnel fully down is the MTU-blackhole / hard-down family.
            {"absent": {"kind": "tunnel_down"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.tunnel-mtu-blackhole"},
            # Large-transfer/HTTP failures with a degraded tunnel are the MTU
            # signature's fingerprint (small probes pass, big frames die).
            {"absent": {"kind": "synthetic_http_fail|app_large_transfer_fail"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.tunnel-mtu-blackhole"},
        ],
        "direction_expect": "underlay -> overlay-tunnel -> branch-service",
        "verdict": {
            "owner": "sdwan_vendor", "layer": "L3/L4 (SD-WAN overlay)",
            "first_steps": [
                "Check underlay circuit loss/latency for the same window — overlay SLA symptoms usually follow the underlay",
                "Review SD-WAN SLA class state and any path-steering events for the affected branch",
                "Diff recent SD-WAN policy commits before blaming the carrier",
            ],
        },
        "operator_phrase": "Likely SD-WAN path degradation — overlay SLA symptoms align with underlay loss/latency on the same path.",
        "manager_phrase": "Branch traffic appears degraded because the WAN path is unstable or has shifted to a lower-quality path.",
        "blast_radius": "branches riding the degraded tunnel/path",
        "false_positives": ["application-side slowness", "backup circuit intentionally preferred", "scheduled carrier maintenance"],
        "composition_hints": ["WAN/ISP egress incident with DIA latency + SaaS slowness on the same egress"],
    },
    {
        "id": "sig.ent.middle-mile.private-interconnect-bgp-down",
        "title": "Private cloud interconnect BGP down",
        "domain": "ent.middle-mile",
        "seams": ["CARRIER_INTERCONNECT", "CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "bgp_adjacency_change|bgp_state_anomaly", "entity_type": "device"},
            {"kind": "probe_loss|route_count_drop"},
            {"kind": "cloud_health|cloud_change", "optional": True},
            {"kind": "tunnel_flap", "optional": True},
        ],
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            # If the session is fine and only prefixes are missing, prefer the
            # missing-prefix family (BGP up, partial reachability).
            {"absent": {"kind": "route_prefix_missing"}, "within_s": 300,
             "else_prefer": "sig.ent.middle-mile.private-interconnect-missing-prefix"},
        ],
        "direction_expect": "interconnect(control-plane) -> cloud-private-prefixes -> hybrid-service",
        "verdict": {
            "owner": "carrier", "layer": "L3 (private interconnect)",
            "first_steps": [
                "Validate BGP state on BOTH the on-prem edge and the cloud side (attachment/VIF/peering state)",
                "Check the provider circuit and VLAN attachment state plus any provider maintenance events",
                "Confirm whether a backup VPN path activated and what it is carrying",
            ],
        },
        "operator_phrase": "Likely private cloud interconnect control-plane issue — BGP/session evidence aligns with cloud private-prefix reachability loss.",
        "manager_phrase": "The private connection to the cloud appears impaired, which may affect services that depend on private cloud connectivity.",
        "blast_radius": "services on cloud private prefixes behind the interconnect",
        "false_positives": ["cloud route table issue while BGP is up", "planned maintenance", "monitoring peer mismatch"],
        "composition_hints": ["private interconnect incident with BGP flap + missing prefixes + private-probe failures"],
    },
    {
        "id": "sig.ent.middle-mile.private-interconnect-missing-prefix",
        "title": "Private interconnect missing cloud prefix",
        "domain": "ent.middle-mile",
        "seams": ["CARRIER_INTERCONNECT", "CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "route_prefix_missing|route_count_drop", "entity_type": "device"},
            {"kind": "probe_loss", "entity_type": "path"},
            {"kind": "cloud_change|cloud_audit", "optional": True},
            {"kind": "route_advertisement_change", "optional": True},
        ],
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            # Session actually down → the bgp-down family owns it.
            {"absent": {"kind": "bgp_adjacency_change|bgp_state_anomaly"}, "within_s": 300,
             "else_prefer": "sig.ent.middle-mile.private-interconnect-bgp-down"},
        ],
        "direction_expect": "route-exchange -> affected-prefix -> cloud-subnet-service",
        "verdict": {
            "owner": "netops", "layer": "L3 (route exchange)",
            "first_steps": [
                "Compare on-prem advertised/received routes with the cloud route tables and interconnect peer routes",
                "Confirm unaffected prefixes remain reachable (partial reachability is the tell)",
                "Check cloud-side route propagation and any custom route-advertisement change in the window",
            ],
        },
        "operator_phrase": "BGP is up, but routing evidence suggests the affected cloud prefix is missing or not being advertised/installed — compare advertised and received routes on both edges.",
        "manager_phrase": "The private cloud connection is not fully down. Impact appears limited to specific cloud networks because routing information is missing or incomplete.",
        "blast_radius": "specific cloud subnets/VPCs behind the missing prefix",
        "false_positives": ["security group/NACL block", "subnet decommissioned", "overlapping route preference", "stale inventory"],
    },
    {
        "id": "sig.ent.fabric.evpn-route-missing",
        "title": "EVPN/VXLAN route missing (control-plane gap)",
        "domain": "ent.fabric",
        "seams": ["DC_FABRIC"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "evpn_route_missing|vni_reachability_fail", "entity_type": "device"},
            {"kind": "bgp_adjacency_change|evpn_mac_move", "optional": True},
            {"kind": "arp_fail", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # VTEP itself unreachable is the underlay family.
            {"absent": {"kind": "vtep_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.fabric.vtep-unreachable"},
        ],
        "direction_expect": "evpn-control-plane -> VNI/VRF -> tenant-east-west",
        "verdict": {
            "owner": "netops", "layer": "L2/L3 (EVPN overlay)",
            "first_steps": [
                "Check EVPN MAC/IP (Type-2) and prefix (Type-5) route presence for the affected VNI/VRF",
                "Verify VTEP reachability and BGP EVPN peer state — underlay clean means control-plane gap",
                "Review ARP-suppression and VNI mapping consistency on the affected leaves",
            ],
        },
        "operator_phrase": "Suspected EVPN/VXLAN control-plane gap for the affected VNI/VRF — routes missing while the underlay stays clean.",
        "manager_phrase": "The issue appears isolated to a specific data center network segment rather than the entire fabric.",
        "blast_radius": "one tenant/VRF/VNI's east-west traffic",
        "false_positives": ["tenant decommission", "stale VNI", "intended route filtering", "endpoint mobility"],
    },
    {
        "id": "sig.ent.fabric.spine-leaf-path-degradation",
        "title": "Leaf/spine fabric path degradation",
        "domain": "ent.fabric",
        "seams": ["DC_FABRIC"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "if_errors|if_crc|link_state_change", "entity_type": "interface"},
            # Rack-to-rack PATH probes — segment/WAN probes belong to the
            # middle-mile physical-degradation family, not the fabric.
            {"kind": "probe_loss|probe_rtt_anomaly", "entity_type": "path"},
            {"kind": "ecmp_member_loss|lldp_neighbor_change", "optional": True},
            {"kind": "bgp_adjacency_change|ospf_adjacency_change|isis_adjacency_change", "optional": True},
        ],
        "required_modalities": ["device_telemetry", "active_probe"],
        "direction_expect": "fabric-link -> leaf/spine-path -> multi-rack-services",
        "verdict": {
            "owner": "netops", "layer": "L1-L3 (fabric path)",
            "first_steps": [
                "Identify the degraded fabric link/ECMP member and confirm rack-to-rack probe loss follows the leaf/spine topology",
                "Check optics/error counters with a fresh baseline on the suspect links",
                "Verify routing adjacency stability across the affected path before draining the member",
            ],
        },
        "operator_phrase": "Likely data center fabric path degradation — impact follows leaf/spine topology, not a single application.",
        "manager_phrase": "A data center network path appears degraded, potentially affecting multiple services that share that fabric path.",
        "blast_radius": "multiple racks/services sharing the degraded fabric path",
        "false_positives": ["single server NIC issue", "app cluster imbalance", "storage latency"],
    },
    {
        "id": "sig.ent.security.fw-ha-failover-drift",
        "title": "Firewall HA failover or policy/session drift",
        "domain": "ent.security",
        "seams": ["LAN", "DC_FABRIC", "WAN_SDWAN", "CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "fw_ha_state_change|fw_sync_fail", "entity_type": "device"},
            {"kind": "fw_session_drop|probe_loss|synthetic_http_fail"},
            {"kind": "fw_policy_mismatch|nat_translation_change", "optional": True},
            {"kind": "flow_asymmetry", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Pure routing failure explains impact without the firewall.
            {"absent": {"kind": "bgp_adjacency_change"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.routing-instability"},
        ],
        "direction_expect": "fw-ha-pair -> stateful-sessions -> transiting-services",
        "verdict": {
            "owner": "netops", "layer": "L4 (firewall state)",
            "first_steps": [
                "Check HA role state and config/session sync between the pair",
                "Compare NAT translation tables and policy hit logs before vs after the failover",
                "Look for asymmetric flows — state mismatch after failover drops one direction first",
            ],
        },
        "operator_phrase": "Suspected firewall HA/state issue — traffic impact aligns with a failover or policy/session divergence between the pair.",
        "manager_phrase": "Traffic disruption appears related to firewall high-availability behavior or policy/session state after a failover or change.",
        "blast_radius": "sessions transiting the firewall pair",
        "false_positives": ["expected failover during maintenance", "app deploy", "route reconvergence", "stale firewall logs"],
        "composition_hints": ["firewall state/NAT incident with asymmetric flows + NAT change"],
    },
    {
        "id": "sig.ent.security.nat-snat-exhaustion",
        "title": "NAT/SNAT exhaustion",
        "domain": "ent.security",
        "seams": ["WAN_SDWAN", "CLOUD_APP", "DC_FABRIC"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "nat_alloc_fail|nat_table_high", "entity_type": "device"},
            {"kind": "synthetic_http_fail|app_conn_fail"},
            {"kind": "if_util_high|flow_drop_at_nat", "optional": True},
        ],
        "required_modalities": ["device_telemetry"],
        "discriminators": [
            # A full interface/path outage is not an exhaustion pattern.
            {"absent": {"kind": "link_state_change|tunnel_down"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "nat-boundary -> outbound-connections -> external-dependencies",
        "verdict": {
            "owner": "netops", "layer": "L4 (NAT/translation)",
            "first_steps": [
                "Check NAT/SNAT utilization and port-allocation failure counters",
                "Identify top talkers and destination concentration consuming the pool",
                "Confirm failures are connection-level (retries sometimes succeed) rather than full path-down",
            ],
        },
        "operator_phrase": "Likely NAT capacity/translation exhaustion — failures are connection-level and intermittent, not full path-down.",
        "manager_phrase": "Outbound connectivity appears constrained by translation capacity, causing intermittent failures rather than a full outage.",
        "blast_radius": "outbound connections through the exhausted NAT boundary",
        "false_positives": ["destination-side rate limiting", "proxy issue", "DNS failure", "firewall deny policy"],
    },
    {
        "id": "sig.ent.app.lb-target-health-failure",
        "title": "Load balancer targets unhealthy",
        "domain": "ent.app",
        "seams": ["CLOUD_APP", "DC_FABRIC"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "lb_target_unhealthy|lb_5xx", "entity_type": "service"},
            {"kind": "synthetic_http_fail|app_error_rate_high"},
            {"kind": "config_change|deploy_event", "optional": True},
            {"kind": "app_latency_high", "optional": True},
        ],
        "required_modalities": ["device_telemetry", "active_probe"],
        "discriminators": [
            # If the VIP itself is unreachable at L3, it is a path problem.
            {"absent": {"kind": "probe_loss"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.congestion"},
        ],
        "direction_expect": "lb-front-door -> target-pool -> application",
        "verdict": {
            "owner": "app_team", "layer": "L7 (LB/backend health)",
            "first_steps": [
                "Check target-group health and the health-check path/port the LB is probing",
                "Correlate with recent deployments or scaling events on the backend pool",
                "Verify security policy is not blocking the health-check source",
            ],
        },
        "operator_phrase": "Load balancer is reachable, but backend target health is degraded — the front door is up with an unhealthy pool behind it.",
        "manager_phrase": "The front door of the service is reachable, but the systems behind it are not healthy enough to serve traffic reliably.",
        "blast_radius": "the service behind the affected VIP/target pool",
        "false_positives": ["health-check path misconfigured", "intentional scale-in", "maintenance", "WAF blocking before target"],
        "composition_hints": ["app/backend readiness incident with empty Kubernetes endpoints"],
    },
    {
        "id": "sig.ent.app.dns-failover-wrong-target",
        "title": "DNS failover wrong target or stale record",
        "domain": "ent.app",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "dns_answer_mismatch|dns_failover_event", "entity_type": "service"},
            {"kind": "synthetic_http_fail|app_error_rate_high"},
            {"kind": "config_change", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            # Resolver itself failing is the resolver family, not a wrong answer.
            {"absent": {"kind": "dns_failure_rate|dns_latency_high"}, "within_s": 300,
             "else_prefer": "sig.ent.access.dns-local-resolver-failure"},
        ],
        "direction_expect": "dns-answer -> endpoint-selection -> user-population",
        "verdict": {
            "owner": "app_team", "layer": "L7 (DNS steering)",
            "first_steps": [
                "Compare DNS answers across resolvers/regions against the intended healthy endpoint",
                "Check DNS health-check state, TTLs and any recent record change",
                "Identify whether impact follows a resolver/region/record boundary",
            ],
        },
        "operator_phrase": "Suspected DNS failover or stale record issue — resolution differs from the expected healthy endpoint for part of the user population.",
        "manager_phrase": "Some users may be sent to the wrong or unhealthy service endpoint due to DNS or failover behavior.",
        "blast_radius": "users behind the resolvers/regions receiving the wrong answer",
        "false_positives": ["client DNS cache", "ISP resolver cache", "expected geo-routing", "CDN steering"],
    },
    # ---- v1 P1 additions in the recommended initial ENABLED set ----------
    {
        "id": "sig.ent.cloud.sg-nacl-block",
        "title": "Security group/NACL blocks traffic",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "demo_priority": "p1",
        "requires": [
            {"kind": "cloud_flow_reject|policy_diff_block", "entity_type": "service"},
            {"kind": "synthetic_http_fail|probe_loss"},
            {"kind": "cloud_change|cloud_audit|config_change", "optional": True},
        ],
        "required_modalities": ["passive_flow", "active_probe"],
        "discriminators": [
            {"absent": {"kind": "lb_target_unhealthy"}, "within_s": 300,
             "else_prefer": "sig.ent.app.lb-target-health-failure"},
        ],
        "direction_expect": "security-policy -> denied-flow -> app-path",
        "verdict": {
            "owner": "netops", "layer": "L3/L4 (cloud security policy)",
            "first_steps": [
                "Check flow logs for REJECT records on the exact failing 5-tuple",
                "Diff SG/NACL/firewall policy changes in the incident window",
                "Confirm the required ports/sources against the intended security design",
            ],
        },
        "operator_phrase": "Suspected cloud security policy block — flow or policy evidence indicates traffic is denied before reaching the service.",
        "manager_phrase": "A cloud network security rule may be blocking the affected application path.",
        "blast_radius": "the specific source/destination/port paths the rule denies",
        "false_positives": ["host firewall", "app not listening", "route table issue"],
    },
    {
        "id": "sig.ent.cloud.route-table-blackhole",
        "title": "Cloud route table blackhole",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP", "CARRIER_INTERCONNECT"],
        "deployment_scope": "hybrid",
        "demo_priority": "p1",
        "requires": [
            {"kind": "route_table_blackhole|route_missing_nexthop", "entity_type": "service"},
            {"kind": "probe_loss|cloud_flow_log"},
            {"kind": "cloud_change|route_advertisement_change", "optional": True},
        ],
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            {"absent": {"kind": "cloud_flow_reject"}, "within_s": 300,
             "else_prefer": "sig.ent.cloud.sg-nacl-block"},
        ],
        "direction_expect": "route-domain -> affected-subnet -> workloads",
        "verdict": {
            "owner": "netops", "layer": "L3 (cloud routing)",
            "first_steps": [
                "Compare the affected subnet's route table (next hops, propagation) against a healthy one",
                "Check TGW/VNet attachment routes and recent route changes",
                "Run the cloud reachability/connectivity test on the failing path",
            ],
        },
        "operator_phrase": "Likely cloud route table issue — impact follows a specific subnet or route domain while others stay reachable.",
        "manager_phrase": "A cloud routing change or missing route appears to be isolating part of the environment.",
        "blast_radius": "one subnet/AZ/VPC route domain",
        "false_positives": ["security group block", "service endpoint policy", "private DNS issue"],
    },
    {
        "id": "sig.ent.cloud.k8s-service-endpoint-empty",
        "title": "Kubernetes Service has no healthy endpoints",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP", "DC_FABRIC"],
        "deployment_scope": "hybrid",
        "demo_priority": "p1",
        "requires": [
            {"kind": "k8s_endpoints_empty|k8s_pod_not_ready", "entity_type": "service"},
            {"kind": "synthetic_http_fail|lb_5xx"},
            {"kind": "deploy_event|k8s_event", "optional": True},
        ],
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            {"absent": {"kind": "dns_failure_rate"}, "within_s": 300,
             "else_prefer": "sig.ent.access.dns-local-resolver-failure"},
        ],
        "direction_expect": "k8s-service -> pod-readiness -> app-path",
        "verdict": {
            "owner": "app_team", "layer": "L7 (Kubernetes readiness)",
            "first_steps": [
                "Check the Service's endpoint list and pod readiness in the affected namespace",
                "Correlate with the rollout/deploy timeline (image pull, crash loops, scale-to-zero)",
                "Verify the ingress path still selects the right Service and port",
            ],
        },
        "operator_phrase": "Kubernetes service has no healthy endpoints — the network front door is up, but no ready backend pods are available.",
        "manager_phrase": "The application routing layer is reachable, but the application instances behind it are not ready to serve traffic.",
        "blast_radius": "the workloads behind the affected Service/ingress",
        "false_positives": ["intentional scale-down", "wrong namespace", "stale service selector"],
        "composition_hints": ["app/backend readiness incident with LB target health failure"],
    },
    {
        "id": "sig.ent.security.waf-rule-false-positive",
        "title": "WAF blocks legitimate app traffic",
        "domain": "ent.security",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "demo_priority": "p1",
        "requires": [
            {"kind": "waf_block_spike|waf_rule_match", "entity_type": "service"},
            {"kind": "app_error_rate_high|synthetic_http_fail"},
            {"kind": "config_change", "optional": True},
        ],
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            {"absent": {"kind": "lb_target_unhealthy"}, "within_s": 300,
             "else_prefer": "sig.ent.app.lb-target-health-failure"},
        ],
        "direction_expect": "waf-rule -> blocked-requests -> user-population",
        "verdict": {
            "owner": "app_team", "layer": "L7 (WAF)",
            "first_steps": [
                "Review WAF rule matches for the affected URI/method/user-agent/source pattern",
                "Correlate the block spike with recent WAF rule updates",
                "Confirm the backend never received the blocked requests (403 at the edge, silence behind it)",
            ],
        },
        "operator_phrase": "Suspected WAF false positive — WAF logs show legitimate requests matching a blocking rule after a rule update.",
        "manager_phrase": "Some valid user requests may be blocked by an application security rule.",
        "blast_radius": "requests matching the offending rule (URI/source/user-agent subset)",
        "false_positives": ["real attack traffic", "expired auth token", "backend authorization failure"],
    },
    {
        "id": "sig.ent.app.tls-cert-expired",
        "title": "TLS certificate expired, mismatch, or SNI issue",
        "domain": "ent.app",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "demo_priority": "p1",
        "requires": [
            {"kind": "tls_handshake_fail|cert_expired", "entity_type": "service"},
            {"kind": "synthetic_http_fail"},
            {"kind": "config_change|cert_expiry_warning", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            # If plain reachability is also failing, it is a path fault, not TLS.
            {"absent": {"kind": "probe_loss"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.congestion"},
        ],
        "direction_expect": "tls-handshake -> secure-session -> users",
        "verdict": {
            "owner": "app_team", "layer": "L6 (TLS)",
            "first_steps": [
                "Check certificate expiry, SAN/CN and chain on the failing endpoint",
                "Verify the LB listener certificate and SNI behavior after any recent rotation",
                "Confirm only HTTPS is affected while the underlying path stays clean",
            ],
        },
        "operator_phrase": "Likely TLS certificate or SNI mismatch — HTTPS negotiation fails before the application can respond, while the path itself is clean.",
        "manager_phrase": "Users may be blocked because the secure connection or certificate validation is failing.",
        "blast_radius": "HTTPS clients of the affected endpoint",
        "false_positives": ["client trust store issue", "middlebox TLS inspection", "DNS wrong target"],
    },
]

# v1 P1 backlog — valid, validated catalog entries shipped DISABLED (owner spec:
# "add as valid catalog entries, avoid destabilizing the engine"). Enable per
# family as Layer-2 signal kinds land for them. Kept in a separate list so the
# enabled-set version hash and the fixture-coverage test are unaffected.
P1_BACKLOG_TEMPLATES: list[dict] = [
    {
        "id": f"sig.{sid}", "title": title, "domain": domain, "enabled": False,
        "seams": list(seams), "deployment_scope": scope, "demo_priority": "p1",
        "requires": [{"kind": req} for req in reqs],
        "required_modalities": list(mods),
        "direction_expect": direction,
        "verdict": {"owner": owner, "layer": layer, "first_steps": list(steps)},
        "operator_phrase": op, "manager_phrase": mgr,
        "false_positives": list(fps),
    }
    for (sid, title, domain, seams, scope, reqs, mods, direction, owner, layer, steps, op, mgr, fps) in [
        ("ent.wan-edge.path-asymmetry-return-drop", "Asymmetric routing / return-path drop", "ent.wan-edge",
         ("WAN_SDWAN", "CARRIER_INTERCONNECT", "CLOUD_APP"), "hybrid",
         ("flow_one_directional", "return_path_drop|fw_state_mismatch"), ("passive_flow",),
         "forward-path -> return-path -> sessions", "netops", "L3/L4 (path symmetry)",
         ("Compare forward and return paths using flows, firewall state and route tables",
          "Check for a BGP path change or NAT state loss that split the paths"),
         "Suspected asymmetric routing or return-path drop — one direction of the flow succeeds while the return path does not.",
         "Traffic appears to reach part of the path, but responses are not returning correctly.",
         ("host firewall", "app not listening", "SYN rate limiting", "incomplete flow collection")),
        ("ent.wan-edge.qos-policing-drop", "QoS/policing drops", "ent.wan-edge",
         ("WAN_SDWAN",), "hybrid",
         ("qos_drops|if_discards", "probe_rtt_anomaly|probe_loss"), ("device_telemetry",),
         "qos-class -> prioritized-traffic -> voice/video", "netops", "L2/L3 (QoS)",
         ("Check QoS counters, policer drops and DSCP markings on the WAN edge",
          "Compare circuit utilization against committed rate for the affected class"),
         "Likely QoS or policing drops for the affected traffic class — data rides fine while voice/video degrades.",
         "Performance degradation appears concentrated in prioritized traffic classes such as voice or video.",
         ("endpoint codec issue", "conferencing provider issue", "Wi-Fi impairment")),
        ("ent.wan-edge.sdwan-policy-misroute", "SD-WAN policy sends traffic to wrong path", "ent.wan-edge",
         ("WAN_SDWAN", "CLOUD_APP"), "hybrid",
         ("sdwan_policy_change|path_change", "app_latency_high|probe_rtt_anomaly"), ("control_plane",),
         "sdwan-policy -> path-selection -> app-traffic", "sdwan_vendor", "L3/L4 (SD-WAN policy)",
         ("Review SD-WAN policy, app identification and path preference for the affected app class",
          "Compare the selected path's quality against the intended one"),
         "Suspected SD-WAN policy misroute — app traffic is using a different path than expected after a policy change.",
         "Traffic for the affected application may be taking a suboptimal route due to policy behavior.",
         ("DPI/app-ID misclassification", "expected failover", "provider brownout")),
        ("ent.fabric.mlag-vpc-peerlink-issue", "MLAG/vPC peer-link inconsistency", "ent.fabric",
         ("DC_FABRIC",), "onprem_only",
         ("mlag_peerlink_issue|mlag_keepalive_fail", "mac_flap|lacp_inconsistent"), ("control_plane",),
         "mlag-pair -> dual-homed-endpoints -> services", "netops", "L2 (MLAG/vPC)",
         ("Check peer-link and keepalive state plus consistency checks on the pair",
          "Look for orphan-port logs and MAC moves on dual-homed endpoints"),
         "Suspected MLAG/vPC inconsistency affecting dual-homed connectivity — intermittent impact on paired endpoints.",
         "A data center redundancy pair may be inconsistent, causing intermittent connectivity for attached systems.",
         ("server NIC teaming issue", "maintenance", "hypervisor vSwitch issue")),
        ("ent.fabric.lacp-member-blackhole", "LACP member blackholing", "ent.fabric",
         ("DC_FABRIC", "LAN"), "onprem_only",
         ("lacp_member_bad|if_errors", "probe_loss|flow_partial_loss"), ("device_telemetry",),
         "bundle-member -> hashed-flows -> partial-loss", "netops", "L2 (LACP)",
         ("Check per-member counters and LACP state on the bundle",
          "Drain the suspect member and retest the failing flows"),
         "Suspected LACP member blackhole — some flows hash onto a bad bundle member, so loss is partial and flow-dependent.",
         "A redundant link group may have one unhealthy member causing intermittent rather than total failure.",
         ("ECMP path issue", "server NIC issue", "sampling bias")),
        ("ent.fabric.storage-network-latency", "Storage/iSCSI/NFS network degradation", "ent.fabric",
         ("DC_FABRIC",), "hybrid",
         ("storage_latency_high|tcp_retransmit_high", "app_latency_high|vm_datastore_warning"), ("device_telemetry",),
         "storage-path -> datastore -> VM/app", "netops", "L2-L4 (storage network)",
         ("Check the storage VLAN/path for drops, MTU mismatch and retransmits",
          "Compare array-side latency against network path latency"),
         "Storage network path degradation is suspected — application slowness aligns with storage latency or retransmits.",
         "Application performance may be affected by storage connectivity rather than the application tier itself.",
         ("array-side IO saturation", "backup jobs", "VM snapshot consolidation")),
        ("ent.cloud.nat-gateway-route-misconfig", "Cloud NAT route/IGW issue", "ent.cloud",
         ("CLOUD_APP",), "cloud_only",
         ("cloud_egress_fail|route_missing_nexthop", "cloud_flow_log|cloud_health"), ("control_plane",),
         "private-subnet -> nat/igw -> external-dependencies", "netops", "L3 (cloud egress)",
         ("Check the subnet route table, NAT gateway and IGW path for the affected subnets",
          "Pull VPC flow logs for no-route/reject records"),
         "Suspected cloud egress routing or NAT path issue for private subnets — outbound fails while inbound may still work.",
         "Cloud workloads in private networks may be unable to reach external dependencies.",
         ("destination rate limit", "proxy requirement", "missing IAM endpoint permission")),
        ("ent.cloud.nat-connection-limit", "Cloud NAT connection exhaustion", "ent.cloud",
         ("CLOUD_APP",), "cloud_only",
         ("cloud_nat_alloc_fail", "app_conn_fail|flow_timeout"), ("control_plane",),
         "cloud-nat -> outbound-connections -> dependencies", "netops", "L4 (cloud NAT)",
         ("Check NAT allocation metrics, connection distribution and destination concentration",
          "Review scale-out options and application connection reuse"),
         "Likely cloud NAT connection exhaustion — outbound failures appear capacity-related and intermittent.",
         "Cloud workloads may be hitting outbound connection limits, causing intermittent external dependency failures.",
         ("API provider throttling", "service mesh egress policy", "DNS resolver failure")),
        ("ent.cloud.az-specific-service-impact", "AZ-local impairment", "ent.cloud",
         ("CLOUD_APP",), "cloud_only",
         ("az_health_degraded", "lb_target_unhealthy|probe_loss"), ("control_plane",),
         "one-az -> zonal-dependencies -> service", "cloud_provider", "AZ (zonal)",
         ("Compare LB target health and instance health BY availability zone",
          "Check zonal subnet routes/NAT and the provider's zonal status"),
         "Suspected AZ-local impact — one availability zone is measurably less healthy than the others.",
         "Impact appears localized to one cloud availability zone, so redundancy may reduce but not eliminate user impact.",
         ("uneven deployment", "autoscaling imbalance", "app shard issue")),
        ("ent.cloud.k8s-coredns-failure", "Kubernetes CoreDNS failure", "ent.cloud",
         ("CLOUD_APP",), "hybrid",
         ("k8s_dns_fail", "k8s_pod_restart|dns_latency_high"), ("control_plane",),
         "coredns -> service-discovery -> app-to-app", "app_team", "L7 (cluster DNS)",
         ("Check CoreDNS pod health, restarts and the kube-dns service endpoints",
          "Measure in-cluster DNS latency and SERVFAIL rates"),
         "Suspected Kubernetes DNS issue — pods are failing to resolve service or external names while workloads stay healthy.",
         "Applications may be healthy, but service discovery inside the cluster is failing.",
         ("application wrong hostname", "external DNS outage", "namespace search path issue")),
        ("ent.cloud.k8s-network-policy-deny", "Kubernetes NetworkPolicy/CNI blocks pod traffic", "ent.cloud",
         ("CLOUD_APP",), "hybrid",
         ("k8s_policy_deny|cni_deny", "k8s_event|config_change"), ("control_plane",),
         "network-policy -> pod-to-pod -> app-components", "app_team", "L3/L4 (CNI policy)",
         ("Check NetworkPolicy selectors and CNI deny logs for the affected namespace/labels",
          "Confirm pods are healthy and endpoints present while traffic is blocked"),
         "Suspected Kubernetes network policy or CNI enforcement issue — pods are healthy, but traffic between them appears blocked.",
         "An internal cluster security/network policy may be preventing application components from communicating.",
         ("wrong service selector", "app port mismatch", "pod readiness issue")),
        ("ent.app.idp-auth-dependency-failure", "Identity provider / OAuth / JWKS dependency failure", "ent.app",
         ("CLOUD_APP",), "cloud_only",
         ("auth_fail_spike|jwks_fetch_fail", "app_error_rate_high"), ("control_plane",),
         "idp-dependency -> auth/tokens -> logins", "app_team", "L7 (identity)",
         ("Check IdP status, OIDC/JWKS endpoints and the app's auth error logs",
          "Verify DNS/egress to the IdP and recent auth configuration changes"),
         "Suspected identity/auth dependency issue — the application is reachable, but login or token validation is failing.",
         "The service may be available, but users cannot authenticate due to an identity provider or auth dependency issue.",
         ("password/credential issue", "expired client secret", "conditional access policy change")),
        ("ent.app.backend-timeout", "Backend slow behind load balancer", "ent.app",
         ("CLOUD_APP", "DC_FABRIC"), "hybrid",
         ("lb_target_response_slow|app_latency_high", "app_error_rate_high|synthetic_http_fail"), ("device_telemetry",),
         "lb -> backend-response-time -> users", "app_team", "L7 (backend latency)",
         ("Check LB target response time, backend saturation and DB latency",
          "Correlate with the deployment timeline"),
         "Backend timeout is likely — the front-end path is reachable, but backend response time is exceeding limits.",
         "The service is reachable, but backend components are responding too slowly.",
         ("NAT exhaustion", "WAF block", "client-side timeout too low")),
        ("ent.app.db-dependency-saturation", "Database dependency saturation looks like network issue", "ent.app",
         ("CLOUD_APP", "DC_FABRIC"), "hybrid",
         ("db_saturation|db_latency_high", "app_error_rate_high|app_latency_high"), ("device_telemetry",),
         "db-dependency -> app-latency -> users", "app_team", "L7 (database)",
         ("Check DB CPU, connections, IO wait and slow queries against the app error timeline",
          "Confirm network probes on the DB path are cleaner than the DB metrics"),
         "Database dependency saturation is suspected — network probes are cleaner than application/database latency.",
         "The user-facing slowdown appears tied to a backend database dependency, not primarily the network.",
         ("storage network latency", "firewall idle timeout", "app memory leak")),
        ("ent.security.proxy-swg-egress-failure", "Proxy/SWG egress outage", "ent.security",
         ("WAN_SDWAN", "CLOUD_APP"), "hybrid",
         ("proxy_fail|swg_health_degraded", "synthetic_http_fail|dns_failure_rate"), ("control_plane",),
         "proxy-path -> saas/internet -> users", "netops", "L7 (secure web gateway)",
         ("Check proxy/SWG health, PAC file and TLS inspection errors",
          "Run a direct-bypass probe to separate proxy failure from SaaS/DIA failure"),
         "Suspected proxy/SWG egress issue — SaaS traffic through the proxy fails while direct-path evidence differs.",
         "Internet/SaaS access may be impaired by the security egress layer rather than the SaaS provider itself.",
         ("SaaS outage", "DNS resolver issue", "client VPN issue")),
    ]
]
BUILTIN_TEMPLATES.extend(P1_BACKLOG_TEMPLATES)


def builtin_catalog() -> Catalog:
    """The validated built-in set. Import-time safe: validation errors here
    are a build break, not a runtime surprise (guarded by test)."""
    return load_catalog(BUILTIN_TEMPLATES)
