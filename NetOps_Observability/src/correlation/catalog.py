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
]


def builtin_catalog() -> Catalog:
    """The validated built-in set. Import-time safe: validation errors here
    are a build break, not a runtime surprise (guarded by test)."""
    return load_catalog(BUILTIN_TEMPLATES)
