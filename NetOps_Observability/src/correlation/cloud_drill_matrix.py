# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""T5 counter-verification matrix (tracker #120, #105 prep).

The `docs/design/cloud-provider-parity.md` acceptance suite says a provider is
"at level" only when each of its 7 drills has run live and been WATCHED. This
module is the machine-readable half of that watching: for every drill it
declares WHICH counters must move — the signal kinds that have to land in
`netops.corr_signals` during the drill window — so the moment credentials
exist (owner items O1/O2) the drills are runnable as a checklist instead of a
memory exercise. `cloud_drill_verify.py` executes it against the live stack.

Honesty rules (same as the parity doc):
  * `required` kinds MUST move or the drill's counter check FAILS.
  * `corroborating` kinds usually move; reported, never gating.
  * `signatures` are the catalog verdicts the drill may promote; reported so
    the operator sees which fired, never gating (correlation into one incident
    is scenario-dependent — same caveat as drill.py's scope note).
  * Every kind is validated against cloud_producers.CLOUD_KINDS and every
    signature against the built-in catalog (test_cloud_drill_matrix.py), so
    this matrix cannot drift from what the lanes can actually emit.
  * `provider_blind` kinds (gateway/ipsec observers) carry no attrs.provider
    stamp — the verifier must not provider-filter them.

A drill entry with `manual` set has no machine-checkable counter (drill 7 is a
console click-through); it is listed so the matrix stays complete.
"""
from __future__ import annotations

from dataclasses import dataclass

PROVIDERS = ("aws", "azure", "gcp")

# Kinds whose signals never carry attrs.provider (independent gateway/ipsec
# observers — their independence from the cloud API is the design point).
PROVIDER_BLIND_KINDS = frozenset({"ipsec_tunnel_status", "ipsec_underlay_status"})


@dataclass(frozen=True)
class DrillExpectation:
    """One acceptance drill's counter contract (identical across providers
    unless `providers` narrows it — the lanes are provider-blind by design)."""

    drill: int
    name: str
    # Each required entry is an any-of group: the drill passes the group when
    # AT LEAST ONE kind in it moved (providers surface the same fault through
    # different lanes, e.g. a tunnel fault as VPN-state or gateway-drop).
    required: tuple[tuple[str, ...], ...] = ()
    corroborating: tuple[str, ...] = ()
    signatures: tuple[str, ...] = ()
    # Kinds expected to go QUIET during the drill (counted before/inside the
    # window; e.g. a stopped host stops emitting metrics). Reported, not gating:
    # quiet is indistinguishable from a broken lane without a baseline window.
    quiet: tuple[str, ...] = ()
    manual: str = ""
    providers: tuple[str, ...] = PROVIDERS
    notes: str = ""


MATRIX: tuple[DrillExpectation, ...] = (
    DrillExpectation(
        drill=1,
        name="host stop/start",
        required=(("cloud_audit", "cloud_change"),),
        corroborating=("cloud_resource_health", "cloud_state_unknown"),
        quiet=("cloud_metric",),
        notes="power_state truth (stopped ≠ broken) is asserted in the Go "
              "inventory plane (/api/cloud) by the operator — an honest stop "
              "is NOT an incident, so no signature is expected.",
    ),
    DrillExpectation(
        drill=2,
        name="underlay blackhole / tunnel fault",
        required=(
            ("cloud_vpn_tunnel_down", "ipsec_tunnel_status",
             "cloud_gateway_blackhole_drop", "cloud_gateway_no_route_drop"),
        ),
        corroborating=("ipsec_underlay_status", "cloud_bgp_session_down",
                       "cloud_route_count_drop", "cloud_vpn_packet_drop"),
        signatures=("sig.ent.cloud.ipsec-tunnel-down",
                    "sig.ent.middle-mile.ipsec-underlay-down",
                    "sig.ent.cloud.private-connectivity-down",
                    "sig.ent.cloud.route-table-blackhole"),
    ),
    DrillExpectation(
        drill=3,
        name="security-rule block",
        required=(
            ("cloud_flow_log",),               # REJECT evidence
            ("security_policy_change", "cloud_audit", "cloud_change"),
        ),
        signatures=("sig.ent.cloud.sg-nacl-block",),
        notes="the REJECT spike and the rule-change event must BOTH land — "
              "their join is the drill (AWS drill-002 shape).",
    ),
    DrillExpectation(
        drill=4,
        name="LB target kill",
        required=(("cloud_lb_log",),),
        corroborating=("cloud_metric",),
        signatures=("sig.ent.cloud.app-dependency-down",),
        notes="cloud_lb_log rows must carry the LB-vs-target blame attr "
              "(elb_status_code vs target_status_code / statusDetails).",
    ),
    DrillExpectation(
        drill=5,
        name="WAF rule misfire",
        required=(
            ("cloud_waf_log",),
            ("cloud_audit", "cloud_change"),   # the rule change that caused it
        ),
        notes="RCA must NAME the terminating rule — the cloud_waf_log rollup "
              "keys on (web ACL, rule) so the evidence carries it.",
    ),
    DrillExpectation(
        drill=6,
        name="DNS breakage",
        required=(("cloud_dns_log",),),
        corroborating=("cloud_lb_log",),
        notes="NXDOMAIN spike per (name, rcode); joining the app symptom is "
              "the correlation half, watched not gated.",
    ),
    DrillExpectation(
        drill=7,
        name="provider console pivot",
        manual="click every rendered deep-link; each must open the provider "
               "console on the RIGHT resource page (cloud_console.go paths).",
    ),
)


def expectations_for(provider: str) -> list[DrillExpectation]:
    if provider not in PROVIDERS:
        raise ValueError(f"unknown provider {provider!r} (expected one of {PROVIDERS})")
    return [e for e in MATRIX if provider in e.providers]


def all_kinds(exp: DrillExpectation) -> set[str]:
    out: set[str] = set()
    for group in exp.required:
        out.update(group)
    out.update(exp.corroborating)
    out.update(exp.quiet)
    return out
