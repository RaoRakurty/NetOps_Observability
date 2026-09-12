# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Capability-based cloud permission model + a read-only permission-test harness.

The north star is LEAST-PRIVILEGE and READ-ONLY-FIRST: Correlix must never require
Contributor/Owner/Tag-Contributor, and it must degrade GRACEFULLY when a read
capability is missing — a missing capability is a COVERAGE GAP, not a total
failure, and Correlix NEVER auto-broadens its own grant.

So permissions are modeled as discrete CAPABILITIES, each mapped to the exact API
action, the built-in role that grants it, the scope it needs, and whether it is
optional. The harness invokes the ACTUAL API path for each capability and reports
a per-capability STATUS (never a single pass/fail):

    available          the API answered — the capability works
    missing_permission the caller is authenticated but not authorized (403)
    scope_not_granted  authorized for the action but not at this scope
    not_configured     the resource type/feature isn't set up (nothing to read)
    api_disabled       the resource provider isn't registered on the subscription
    not_applicable     the capability doesn't apply here (no such resources)
    error              an unexpected response — reported, never swallowed

Provider-neutral by design: the Capability catalog is shared; each cloud supplies
an ADAPTER of probes (Azure first). AWS/GCP adapters map the same capabilities to
their own API actions/roles without changing this model or the harness.

stdlib-only. Pure classification (classify_probe) is unit-tested against canned
provider responses — no live cloud, no creds.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── statuses ─────────────────────────────────────────────────────────────────
AVAILABLE = "available"
MISSING_PERMISSION = "missing_permission"
SCOPE_NOT_GRANTED = "scope_not_granted"
NOT_CONFIGURED = "not_configured"
API_DISABLED = "api_disabled"
NOT_APPLICABLE = "not_applicable"
ERROR = "error"


@dataclass(frozen=True)
class Capability:
    """One discrete read capability and the exact grant it needs."""
    cap_id: str
    title: str
    # The provider action/permission string (e.g. an Azure RBAC action).
    action: str
    # The built-in role that grants it (least-privilege — never Contributor).
    role: str
    # Whether the platform still functions without it (optional = a coverage gap,
    # not a release blocker). Core lanes are required; enrichment lanes optional.
    optional: bool = True
    description: str = ""


@dataclass
class CapabilityStatus:
    cap_id: str
    status: str
    optional: bool
    detail: str = ""


@dataclass
class ProbeResult:
    """The raw outcome of invoking one capability's API path. status_code is the
    HTTP code; error_code is the provider's machine error code (Azure `code`,
    AWS error Code, GCP status) when present."""
    status_code: int
    error_code: str = ""
    message: str = ""


# ── Azure capability catalog (the first provider adapter) ────────────────────
# Every action is a READ (…/read); NONE requires write. The two lanes Correlix
# depends on (inventory_read, metric_read) are required; the rest are optional
# enrichment whose absence narrows coverage but never stops monitoring.
AZURE_CAPABILITIES: tuple[Capability, ...] = (
    Capability("inventory_read", "Resource inventory",
               "Microsoft.Resources/subscriptions/resources/read", "Reader",
               optional=False, description="Discover VMs, NICs, subnets, LBs."),
    Capability("metric_read", "Platform metrics",
               "Microsoft.Insights/metrics/read", "Monitoring Reader",
               optional=False, description="Azure Monitor time series (CPU/net/availability)."),
    Capability("resource_health_read", "Resource health",
               "Microsoft.ResourceHealth/availabilityStatuses/read", "Reader",
               description="Provider-declared availability state."),
    Capability("activity_event_read", "Activity log",
               "Microsoft.Insights/eventtypes/values/read", "Monitoring Reader",
               description="Control-plane change events (the CloudTrail equivalent)."),
    Capability("topology_read", "Network topology",
               "Microsoft.Network/virtualNetworks/read", "Reader",
               description="VNet/subnet/route-table relationships (consumed, not owned, here)."),
    Capability("network_watch_read", "Network Watcher",
               "Microsoft.Network/networkWatchers/read", "Reader",
               description="Connection/flow diagnostics (optional enrichment)."),
    Capability("diagnostic_settings_read", "Diagnostic settings",
               "Microsoft.Insights/diagnosticSettings/read", "Reader",
               description="Where logs/metrics are exported (optional)."),
    Capability("resource_graph_query", "Resource Graph",
               "Microsoft.ResourceGraph/resources/read", "Reader",
               description="Bulk relationship queries (optional acceleration)."),
    Capability("cost_read", "Cost management",
               "Microsoft.CostManagement/query/read", "Cost Management Reader",
               description="Spend enrichment (optional; a separate built-in role)."),
)

# Capabilities Correlix must NEVER hold — asserted absent by the write-denied test.
FORBIDDEN_WRITE_ACTIONS: tuple[str, ...] = (
    "Microsoft.Resources/tags/write",
    "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Authorization/roleAssignments/write",
)


def classify_probe(pr: ProbeResult) -> str:
    """Map a raw API probe outcome to a capability status. Pure — the whole point
    is that it's testable against canned provider responses.

    Azure error-code contract (the codes its ARM layer actually returns):
      AuthorizationFailed          → not authorized (permission or scope)
      SubscriptionNotRegistered /
        MissingSubscriptionRegistration → the RP is off (api_disabled)
      ResourceNotFound / NotFound  → nothing configured to read
    """
    code = pr.status_code
    ecode = (pr.error_code or "").lower()
    if 200 <= code < 300:
        return AVAILABLE
    if code == 403 or ecode == "authorizationfailed":
        # A scope complaint ("over scope '…'") means the action is allowed but not
        # HERE — a narrower grant, distinct from missing the permission entirely.
        if "over scope" in (pr.message or "").lower() or "scope" in ecode:
            return SCOPE_NOT_GRANTED
        return MISSING_PERMISSION
    if code == 401:
        return MISSING_PERMISSION
    if ecode in ("subscriptionnotregistered", "missingsubscriptionregistration",
                 "disabledsubscription") or code == 409:
        return API_DISABLED
    if code == 404 or ecode in ("resourcenotfound", "notfound"):
        return NOT_CONFIGURED
    return ERROR


def probe_capabilities(caps: tuple[Capability, ...],
                       probe_fn) -> list[CapabilityStatus]:
    """Run each capability's API probe via ``probe_fn(cap) -> ProbeResult`` and
    classify it. ``probe_fn`` is injected (the Azure adapter wires it to a real
    read; tests wire a mock), so this harness never touches the network itself and
    NEVER broadens a grant. Partial results are the norm — one missing capability
    is a coverage gap, not a failure of the others.
    """
    out: list[CapabilityStatus] = []
    for cap in caps:
        try:
            pr = probe_fn(cap)
        except Exception as exc:  # noqa: BLE001 - one probe never kills the sweep
            out.append(CapabilityStatus(cap.cap_id, ERROR, cap.optional, str(exc)[:200]))
            continue
        out.append(CapabilityStatus(cap.cap_id, classify_probe(pr), cap.optional,
                                    pr.message[:200]))
    return out


@dataclass
class CoverageReport:
    """The rollup the UI/docs render: what works, what's a gap, and whether the
    REQUIRED capabilities are all present (the only hard gate)."""
    statuses: list[CapabilityStatus] = field(default_factory=list)

    @property
    def required_ok(self) -> bool:
        return all(s.status == AVAILABLE for s in self.statuses if not s.optional)

    @property
    def gaps(self) -> list[CapabilityStatus]:
        return [s for s in self.statuses if s.status != AVAILABLE]

    def summary(self) -> dict:
        return {
            "required_ok": self.required_ok,
            "available": sum(1 for s in self.statuses if s.status == AVAILABLE),
            "gaps": [{"capability": s.cap_id, "status": s.status, "optional": s.optional}
                     for s in self.gaps],
            "total": len(self.statuses),
        }


def coverage_report(caps: tuple[Capability, ...], probe_fn) -> CoverageReport:
    return CoverageReport(statuses=probe_capabilities(caps, probe_fn))
