"""Azure adapter for the capability permission-test harness (capabilities.py).

Maps each shared Capability to the ACTUAL Azure ARM read it needs and invokes it,
turning the HTTP outcome into a ProbeResult the pure classifier grades. This is
what makes the harness real: it does not INFER permissions from the role name (the
mission forbids "Reader gives everything") — it asks the API and reports what came
back, per capability, read-only. It NEVER attempts a write and NEVER retries with a
broader scope.

The HTTP call is injected (``get_fn``) so this is unit-testable without creds: the
Azure poller wires it to a real GET; tests wire a mock. stdlib-only.
"""
from __future__ import annotations

import urllib.error

import capabilities
from capabilities import AZURE_CAPABILITIES, Capability, CoverageReport, ProbeResult

ARM = "https://management.azure.com"


def _paths(subscription: str, region: str) -> dict[str, str]:
    """Per-capability probe URL (a cheap, top=1 read where the API supports it)."""
    sub = f"{ARM}/subscriptions/{subscription}"
    return {
        "inventory_read": f"{sub}/resources?api-version=2021-04-01&$top=1",
        "metric_read": f"{sub}/providers/Microsoft.Insights/metricDefinitions?api-version=2018-01-01",
        "resource_health_read": f"{sub}/providers/Microsoft.ResourceHealth/availabilityStatuses?api-version=2023-07-01-preview",
        "activity_event_read": f"{sub}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$top=1",
        "topology_read": f"{sub}/providers/Microsoft.Network/virtualNetworks?api-version=2023-09-01",
        "network_watch_read": f"{sub}/providers/Microsoft.Network/networkWatchers?api-version=2023-09-01",
        "diagnostic_settings_read": f"{sub}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview",
        "resource_graph_query": f"{ARM}/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01",
        "cost_read": f"{sub}/providers/Microsoft.CostManagement/dimensions?api-version=2023-03-01",
    }


def _error_code(body: bytes) -> tuple[str, str]:
    """Extract Azure's machine `code` + `message` from an ARM error body."""
    import json
    try:
        err = (json.loads(body or b"{}") or {}).get("error", {}) or {}
        return str(err.get("code", "")), str(err.get("message", ""))
    except (ValueError, AttributeError):
        return "", ""


def make_probe_fn(get_fn, subscription: str, region: str = ""):
    """Return a probe_fn(capability) -> ProbeResult for the harness.

    ``get_fn(url) -> (status_code, body_bytes)`` performs one authenticated GET.
    A capability with no mapped path is reported not_applicable (status 0 → the
    classifier's ERROR bucket is avoided by short-circuiting here)."""
    paths = _paths(subscription, region)

    def probe(cap: Capability) -> ProbeResult:
        url = paths.get(cap.cap_id)
        if not url:
            return ProbeResult(0, "NotApplicable", "no probe path for this capability")
        try:
            status, body = get_fn(url)
        except urllib.error.HTTPError as exc:  # the real transport raises this
            code, msg = _error_code(exc.read() if hasattr(exc, "read") else b"")
            return ProbeResult(exc.code, code, msg)
        except urllib.error.URLError as exc:
            return ProbeResult(0, "Unreachable", str(exc.reason)[:200])
        code, msg = ("", "")
        if status >= 400:
            code, msg = _error_code(body)
        return ProbeResult(status, code, msg)

    return probe


def report(get_fn, subscription: str, region: str = "") -> CoverageReport:
    """Full per-capability coverage report for an Azure principal."""
    probe = make_probe_fn(get_fn, subscription, region)
    # not_applicable short-circuit: map status_code 0 with NotApplicable to the
    # capability status, keeping the harness's classifier pure.
    statuses = []
    for cap in AZURE_CAPABILITIES:
        pr = probe(cap)
        if pr.status_code == 0 and pr.error_code == "NotApplicable":
            statuses.append(capabilities.CapabilityStatus(
                cap.cap_id, capabilities.NOT_APPLICABLE, cap.optional, pr.message))
            continue
        statuses.append(capabilities.CapabilityStatus(
            cap.cap_id, capabilities.classify_probe(pr), cap.optional, pr.message[:200]))
    return CoverageReport(statuses=statuses)
