# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Azure workload-breadth inventory (cloud platform backlog Wave 5 #15).

The Azure twin of aws_workloads.py — K8s + serverless/PaaS classes, ARM
describe/list reads only (free):

  containerservice:managedCluster  Microsoft.ContainerService/managedClusters
                                   (provisioningState + powerState.code)
  containerservice:agentPool       agentPoolProfiles embedded on the cluster
                                   (own provisioningState + count)
  web:serverFarm                   Microsoft.Web/serverfarms (App Service
                                   plans; status Ready/… + site count)
  web:site                         Microsoft.Web/sites (web apps AND Function
                                   apps — kind distinguishes; state Running/
                                   Stopped is a lifecycle truth, not health)
  sql:server                       Microsoft.Sql/servers (state)
  sql:database                     per-server databases (status Online/…),
                                   bounded per-server GETs

Pure parse functions over a collect() orchestrator with per-family isolation
(the azure_components.py architecture, 1:1). STATUS HONESTY: provider signal
or not_measured — never green by default. Permission/misconfiguration
failures become a structured source-status record (source_type "workloads").
"""
from __future__ import annotations

import urllib.parse  # noqa: F401 - parity with azure_components imports

import source_status
from components_common import (DEGRADED, DOWN, HEALTHY, NOT_MEASURED, PAGE_CAP,
                               component_row, retrying, truncate)

ARM = "https://management.azure.com"
API_AKS = "2024-02-01"
API_WEB = "2023-12-01"
API_SQL = "2023-05-01-preview"

# Bounded per-server database GETs (inventory, never an unbounded fan-out).
SQL_SERVER_GET_CAP = 25

SOURCE_TYPE = "workloads"


def _location(res: dict, default_region: str) -> str:
    return str(res.get("location", "") or default_region)


def _rg(res_id: str) -> str:
    """resourceGroups/<rg>/ segment of an ARM id, lowercased ('' if absent)."""
    parts = str(res_id).split("/")
    for i, p in enumerate(parts):
        if p.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1].lower()
    return ""


# ── AKS managed clusters + agent pools ───────────────────────────────────────

def parse_aks_clusters(clusters: list, region: str) -> list:
    """One row per AKS cluster + one per agent pool (embedded profiles — no
    extra API call). powerState is the lifecycle truth: a STOPPED cluster is
    turned off, not broken (P1-2)."""
    rows = []
    for c in clusters:
        props = c.get("properties") or {}
        prov = str(props.get("provisioningState", "")).lower()
        power = str(((props.get("powerState") or {}).get("code")) or "").lower()
        if power == "stopped":
            status, reason = NOT_MEASURED, "powerState=Stopped (cluster is stopped, not failed)"
        elif prov == "succeeded":
            status, reason = HEALTHY, f"provisioningState={prov}"
        elif prov in ("failed", "canceled"):
            status, reason = DOWN, f"provisioningState={prov}"
        elif prov in ("creating", "updating", "upgrading", "scaling",
                      "starting", "stopping", "deleting", "migrating"):
            status, reason = DEGRADED, f"provisioningState={prov}"
        elif prov:
            status, reason = NOT_MEASURED, f"provisioningState={prov}"
        else:
            status, reason = NOT_MEASURED, "no provisioning state returned"
        pools = props.get("agentPoolProfiles") or []
        total_nodes = sum(int(p.get("count", 0) or 0) for p in pools)
        rows.append(component_row(
            region=_location(c, region),
            resource_id=c.get("id", ""), arn_or_uri=c.get("id", ""),
            resource_type="containerservice:managedCluster",
            resource_name=c.get("name", ""),
            status=status, status_reason=reason,
            key_metric=("nodes", total_nodes, "nodes"),
            tags=c.get("tags") or {},
            attrs={"k8s_version": props.get("kubernetesVersion", ""),
                   "power_state": power,
                   "resource_group": _rg(c.get("id", "")),
                   "fqdn": props.get("fqdn", "")}))
        for p in pools:
            pprov = str(p.get("provisioningState", "")).lower()
            ppower = str(((p.get("powerState") or {}).get("code")) or "").lower()
            if ppower == "stopped":
                pstatus, preason = NOT_MEASURED, "powerState=Stopped (pool stopped, not failed)"
            elif pprov == "succeeded":
                pstatus, preason = HEALTHY, f"provisioningState={pprov}"
            elif pprov in ("failed", "canceled"):
                pstatus, preason = DOWN, f"provisioningState={pprov}"
            elif pprov:
                pstatus, preason = DEGRADED, f"provisioningState={pprov}"
            else:
                pstatus, preason = NOT_MEASURED, "no provisioning state returned"
            metric = None
            if isinstance(p.get("count"), int):
                metric = ("nodes", p["count"], "nodes")
            rows.append(component_row(
                region=_location(c, region),
                resource_id=f"{c.get('id', '')}/agentPools/{p.get('name', '')}",
                resource_type="containerservice:agentPool",
                resource_name=p.get("name", ""),
                status=pstatus, status_reason=preason, key_metric=metric,
                attrs={"cluster": c.get("name", ""),
                       "vm_size": p.get("vmSize", ""),
                       "mode": p.get("mode", "")}))
    return truncate(rows, "containerservice:managedCluster")


# ── App Service plans + sites (web apps / Function apps) ─────────────────────

def parse_server_farms(farms: list, region: str) -> list:
    rows = []
    for f in farms:
        props = f.get("properties") or {}
        state = str(props.get("status", "")).lower()
        status = {"ready": HEALTHY, "pending": DEGRADED, "creating": DEGRADED}.get(
            state, NOT_MEASURED)
        metric = None
        if isinstance(props.get("numberOfSites"), int):
            metric = ("sites", props["numberOfSites"], "sites")
        rows.append(component_row(
            region=_location(f, region),
            resource_id=f.get("id", ""), arn_or_uri=f.get("id", ""),
            resource_type="web:serverFarm", resource_name=f.get("name", ""),
            status=status,
            status_reason=f"status={state}" if state else "no status returned",
            key_metric=metric, tags=f.get("tags") or {},
            attrs={"sku": str((f.get("sku") or {}).get("name", "")),
                   "resource_group": _rg(f.get("id", ""))}))
    return truncate(rows, "web:serverFarm")


def parse_sites(sites: list, region: str) -> list:
    """Web apps + Function apps (kind contains functionapp). state Running/
    Stopped is the provider's own signal; Stopped is lifecycle, not a fault."""
    rows = []
    for s in sites:
        props = s.get("properties") or {}
        state = str(props.get("state", "")).lower()
        if state == "running":
            status, reason = HEALTHY, "state=Running"
        elif state == "stopped":
            status, reason = NOT_MEASURED, "state=Stopped (site is stopped, not failed)"
        elif state:
            status, reason = DEGRADED, f"state={state}"
        else:
            status, reason = NOT_MEASURED, "no state returned"
        kind = str(s.get("kind", "")).lower()
        rows.append(component_row(
            region=_location(s, region),
            resource_id=s.get("id", ""), arn_or_uri=s.get("id", ""),
            resource_type="web:site", resource_name=s.get("name", ""),
            status=status, status_reason=reason,
            tags=s.get("tags") or {},
            attrs={"app_kind": "function_app" if "functionapp" in kind else "web_app",
                   "default_host": props.get("defaultHostName", ""),
                   "server_farm_id": str(props.get("serverFarmId", "")).lower(),
                   "resource_group": _rg(s.get("id", ""))}))
    return truncate(rows, "web:site")


# ── SQL servers + databases ──────────────────────────────────────────────────

def parse_sql_servers(servers: list, region: str) -> list:
    rows = []
    for s in servers:
        props = s.get("properties") or {}
        state = str(props.get("state", "")).lower()
        status = {"ready": HEALTHY, "disabled": DOWN}.get(state, NOT_MEASURED)
        rows.append(component_row(
            region=_location(s, region),
            resource_id=s.get("id", ""), arn_or_uri=s.get("id", ""),
            resource_type="sql:server", resource_name=s.get("name", ""),
            status=status,
            status_reason=f"state={state}" if state else "no state returned",
            tags=s.get("tags") or {},
            attrs={"fqdn": props.get("fullyQualifiedDomainName", ""),
                   "version": props.get("version", ""),
                   "resource_group": _rg(s.get("id", ""))}))
    return truncate(rows, "sql:server")


_SQLDB_STATUS = {
    "online": HEALTHY, "creating": DEGRADED, "copying": DEGRADED,
    "restoring": DEGRADED, "resuming": DEGRADED, "scaling": DEGRADED,
    "pausing": DEGRADED, "recovering": DEGRADED,
    "offline": DOWN, "suspect": DOWN, "emergencymode": DOWN,
    "offlinesecondary": DOWN, "disabled": DOWN, "inaccessible": DOWN,
    "paused": NOT_MEASURED, "autoclosed": NOT_MEASURED, "shutdown": NOT_MEASURED,
}


def parse_sql_databases(dbs: list, server_name: str, region: str) -> list:
    rows = []
    for d in dbs:
        if str(d.get("name", "")).lower() == "master":
            continue  # the system database is plumbing, not a workload
        props = d.get("properties") or {}
        state = str(props.get("status", "")).lower()
        status = _SQLDB_STATUS.get(state, NOT_MEASURED)
        reason = f"status={state}" if state else "no status returned"
        if state in ("paused", "autoclosed", "shutdown"):
            reason += " (database is paused/closed, not failed)"
        metric = None
        if isinstance(props.get("maxSizeBytes"), int):
            metric = ("max_size_gb", round(props["maxSizeBytes"] / 2**30, 1), "GB")
        rows.append(component_row(
            region=_location(d, region),
            resource_id=d.get("id", ""), arn_or_uri=d.get("id", ""),
            resource_type="sql:database", resource_name=d.get("name", ""),
            status=status, status_reason=reason, key_metric=metric,
            tags=d.get("tags") or {},
            attrs={"server": server_name,
                   "sku": str((d.get("sku") or {}).get("name", ""))}))
    return truncate(rows, "sql:database")


# ── orchestrator ─────────────────────────────────────────────────────────────

def collect(get_json, subscription: str, region: str, *,
            tenant: str = "") -> tuple[list, dict]:
    """All Azure workload rows for one subscription. get_json(url) is injected
    (already authenticated); wrapped with bounded retry+backoff. Per-family
    isolation; a permission/misconfiguration failure becomes a structured
    source-status record. Returns (rows, errors)."""
    g = retrying(get_json)
    rows: list = []
    errors: dict = {}
    noted = False

    def paged(url: str) -> list:
        out: list = []
        for _ in range(PAGE_CAP):
            res = g(url)
            out.extend(res.get("value", []))
            url = res.get("nextLink") or ""
            if not url:
                break
        return out

    def sub_list(rtype: str, api: str) -> list:
        return paged(f"{ARM}/subscriptions/{subscription}/providers/{rtype}?api-version={api}")

    def family(name: str, fn) -> None:
        nonlocal noted
        try:
            rows.extend(fn())
        except Exception as exc:  # noqa: BLE001 - family isolation
            errors[name] = str(exc)[:160]
            if not noted and source_status.note(
                    "azure", SOURCE_TYPE, exc, tenant=tenant,
                    account=subscription, region=region):
                noted = True

    family("aks_clusters", lambda: parse_aks_clusters(
        sub_list("Microsoft.ContainerService/managedClusters", API_AKS), region))
    family("app_service_plans", lambda: parse_server_farms(
        sub_list("Microsoft.Web/serverfarms", API_WEB), region))
    family("sites", lambda: parse_sites(
        sub_list("Microsoft.Web/sites", API_WEB), region))

    def _sql() -> list:
        servers = sub_list("Microsoft.Sql/servers", API_SQL)
        out = parse_sql_servers(servers, region)
        for s in servers[:SQL_SERVER_GET_CAP]:
            sid = s.get("id", "")
            if not sid:
                continue
            try:
                dbs = paged(f"{ARM}{sid}/databases?api-version={API_SQL}")
            except Exception:  # noqa: BLE001 - one server's dbs unmeasured, never fabricated
                continue
            out.extend(parse_sql_databases(dbs, s.get("name", ""), region))
        return out
    family("sql", _sql)

    if not errors:
        source_status.clear("azure", SOURCE_TYPE, tenant=tenant,
                            account=subscription, region=region)
    return rows, errors
