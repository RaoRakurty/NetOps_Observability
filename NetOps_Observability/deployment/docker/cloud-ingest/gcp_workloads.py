"""GCP workload-breadth inventory (cloud platform backlog Wave 5 #15).

The GCP third of the workload triad (aws_workloads / azure_workloads). Pure
mapping functions over an injected, already-authenticated get_json — the
gcp_components.py posture. DESCRIBE/list-level, free-tier APIs only:

  container:cluster    GKE container.v1 projects/*/locations/-/clusters
                       (status RUNNING/DEGRADED/ERROR… + statusMessage;
                       one wildcard-location list, no per-cluster calls)
  container:nodePool   nodePools embedded on the cluster response
  run:service          Cloud Run Admin v1 (Knative serving) — the
                       namespaces/<project>/services list returns ALL
                       regions in one call; status = the Ready condition
  sqladmin:instance    Cloud SQL Admin v1 instances list (state RUNNABLE/
                       SUSPENDED/FAILED… + activationPolicy for the
                       stopped-not-broken lifecycle truth)

STATUS HONESTY: provider signal or not_measured — never green by default.
Permission/misconfiguration failures become a structured source-status
record (source_type "workloads"); all-family success clears it.
"""
from __future__ import annotations

import source_status
from components_common import (DEGRADED, DOWN, HEALTHY, NOT_MEASURED, PAGE_CAP,
                               component_row, retrying, truncate)
from gcp_components import rel_path

GKE_API = "https://container.googleapis.com/v1"
RUN_API = "https://run.googleapis.com/apis/serving.knative.dev/v1"
SQLADMIN_API = "https://sqladmin.googleapis.com/v1"

SOURCE_TYPE = "workloads"


def _cluster_region(c: dict) -> tuple[str, str]:
    """(region, zone) from a GKE cluster's location. A zonal location
    (us-west1-b) yields its region; a regional one is itself the region."""
    loc = str(c.get("location", "") or c.get("zone", ""))
    if loc.count("-") >= 2:
        return loc.rsplit("-", 1)[0], loc
    return loc, ""


# ── GKE clusters + node pools ────────────────────────────────────────────────

_GKE_STATUS = {"running": HEALTHY, "reconciling": DEGRADED,
               "provisioning": DEGRADED, "stopping": DEGRADED,
               "degraded": DEGRADED, "error": DOWN}
_NODEPOOL_STATUS = {"running": HEALTHY, "provisioning": DEGRADED,
                    "reconciling": DEGRADED, "stopping": DEGRADED,
                    "running_with_error": DEGRADED, "error": DOWN}


def parse_gke_clusters(clusters: list, project: str) -> list:
    """One row per GKE cluster + one per node pool (embedded — no extra
    call). statusMessage rides the reason when the provider set one."""
    rows = []
    for c in clusters:
        region, zone = _cluster_region(c)
        state = str(c.get("status", "")).lower()
        status = _GKE_STATUS.get(state, NOT_MEASURED)
        reason = f"status={state}" if state else "no status returned"
        if c.get("statusMessage"):
            reason += f"; {str(c['statusMessage'])[:80]}"
        rid = f"projects/{project}/locations/{c.get('location', zone or region)}/clusters/{c.get('name', '')}"
        metric = None
        if isinstance(c.get("currentNodeCount"), int):
            metric = ("nodes", c["currentNodeCount"], "nodes")
        labels = c.get("resourceLabels") or {}
        rows.append(component_row(
            region=region, zone=zone,
            resource_id=rid, arn_or_uri=c.get("selfLink", "") or rid,
            resource_type="container:cluster", resource_name=c.get("name", ""),
            vpc_id=rel_path(c.get("network", "")) if c.get("network") else "",
            subnet_ids=[rel_path(c["subnetwork"])] if c.get("subnetwork") else [],
            status=status, status_reason=reason, key_metric=metric,
            tags=labels,
            attrs={"k8s_version": c.get("currentMasterVersion", ""),
                   "autopilot": str(bool((c.get("autopilot") or {}).get("enabled"))).lower()}))
        for p in c.get("nodePools") or []:
            pstate = str(p.get("status", "")).lower()
            pstatus = _NODEPOOL_STATUS.get(pstate, NOT_MEASURED)
            preason = f"status={pstate}" if pstate else "no status returned"
            if p.get("statusMessage"):
                preason += f"; {str(p['statusMessage'])[:80]}"
            pmetric = None
            if isinstance(p.get("initialNodeCount"), int):
                pmetric = ("nodes", p["initialNodeCount"], "nodes")
            rows.append(component_row(
                region=region, zone=zone,
                resource_id=f"{rid}/nodePools/{p.get('name', '')}",
                resource_type="container:nodePool", resource_name=p.get("name", ""),
                status=pstatus, status_reason=preason, key_metric=pmetric,
                attrs={"cluster": c.get("name", ""),
                       "machine_type": str((p.get("config") or {}).get("machineType", "")),
                       "autoscaling": str(bool((p.get("autoscaling") or {}).get("enabled"))).lower()}))
    return truncate(rows, "container:cluster")


# ── Cloud Run services ───────────────────────────────────────────────────────

def parse_run_services(services: list, project: str) -> list:
    """Knative-shape Cloud Run services. Status = the Ready condition — the
    provider's own answer; absent conditions are honestly not_measured."""
    rows = []
    for s in services:
        meta = s.get("metadata") or {}
        st = s.get("status") or {}
        conds = {str(c.get("type", "")): c for c in (st.get("conditions") or [])}
        ready = conds.get("Ready") or {}
        rstate = str(ready.get("status", "")).lower()
        if rstate == "true":
            status, reason = HEALTHY, "Ready=True"
        elif rstate == "false":
            status = DOWN
            reason = f"Ready=False; {str(ready.get('message', ''))[:80]}" \
                if ready.get("message") else "Ready=False"
        elif rstate == "unknown":
            status = DEGRADED
            reason = f"Ready=Unknown; {str(ready.get('message', ''))[:80]}" \
                if ready.get("message") else "Ready=Unknown (revision in progress)"
        else:
            status, reason = NOT_MEASURED, "no Ready condition returned"
        labels = meta.get("labels") or {}
        region = str(labels.get("cloud.googleapis.com/location", ""))
        name = meta.get("name", "")
        rows.append(component_row(
            region=region or "unknown",
            resource_id=f"projects/{project}/locations/{region or '-'}/services/{name}",
            arn_or_uri=st.get("url", ""),
            resource_type="run:service", resource_name=name,
            status=status, status_reason=reason,
            tags={k: v for k, v in labels.items() if not k.startswith("cloud.googleapis.com/")},
            attrs={"url": st.get("url", ""),
                   "latest_ready_revision": st.get("latestReadyRevisionName", "")}))
    return truncate(rows, "run:service")


# ── Cloud SQL instances ──────────────────────────────────────────────────────

_CSQL_STATE = {"runnable": HEALTHY, "pending_create": DEGRADED,
               "maintenance": DEGRADED, "suspended": DOWN, "failed": DOWN}


def parse_cloudsql_instances(instances: list, project: str) -> list:
    rows = []
    for i in instances:
        state = str(i.get("state", "")).lower()
        policy = str((i.get("settings") or {}).get("activationPolicy", "")).lower()
        if state == "runnable" and policy == "never":
            # Lifecycle truth (P1-2): activationPolicy=NEVER is "turned off".
            status, reason = NOT_MEASURED, "state=RUNNABLE, activationPolicy=NEVER (instance is stopped, not failed)"
        else:
            status = _CSQL_STATE.get(state, NOT_MEASURED)
            reason = f"state={state}" if state else "no state returned"
        metric = None
        size_gb = (i.get("settings") or {}).get("dataDiskSizeGb")
        try:
            if size_gb is not None:
                metric = ("disk_size_gb", float(size_gb), "GB")
        except (TypeError, ValueError):
            metric = None
        ips = [a.get("ipAddress", "") for a in (i.get("ipAddresses") or [])]
        rows.append(component_row(
            region=str(i.get("region", "")),
            resource_id=f"projects/{project}/instances/{i.get('name', '')}",
            arn_or_uri=i.get("selfLink", ""),
            resource_type="sqladmin:instance", resource_name=i.get("name", ""),
            status=status, status_reason=reason, key_metric=metric,
            public_ips=ips,
            tags=(i.get("settings") or {}).get("userLabels") or {},
            attrs={"engine": i.get("databaseVersion", ""),
                   "tier": str((i.get("settings") or {}).get("tier", "")),
                   "availability": str((i.get("settings") or {}).get("availabilityType", ""))}))
    return truncate(rows, "sqladmin:instance")


# ── orchestrator ─────────────────────────────────────────────────────────────

def collect(get_json, project: str, *, tenant: str = "") -> tuple[list, dict]:
    """All GCP workload rows for one project. get_json(url) is injected
    (already authenticated), wrapped with bounded retry+backoff. Per-family
    isolation; permission/misconfiguration failures become a structured
    source-status record. Returns (rows, errors)."""
    g = retrying(get_json)
    rows: list = []
    errors: dict = {}
    noted = False

    def listed(url: str, key: str) -> list:
        out: list = []
        for _ in range(PAGE_CAP):
            res = g(url)
            out.extend(res.get(key) or [])
            nxt = res.get("nextPageToken")
            if not nxt:
                break
            url = url.split("&pageToken=")[0].split("?pageToken=")[0]
            url += ("&" if "?" in url else "?") + "pageToken=" + nxt
        return out

    def family(name: str, fn) -> None:
        nonlocal noted
        try:
            rows.extend(fn())
        except Exception as exc:  # noqa: BLE001 - family isolation
            errors[name] = str(exc)[:160]
            if not noted and source_status.note(
                    "gcp", SOURCE_TYPE, exc, tenant=tenant, account=project):
                noted = True

    # GKE: the wildcard location returns every cluster in one response (the
    # v1 clusters.list is not paginated — one bounded read).
    family("gke", lambda: parse_gke_clusters(
        (g(f"{GKE_API}/projects/{project}/locations/-/clusters") or {}).get("clusters") or [],
        project))
    # Cloud Run (Knative v1): the namespaces list spans all regions.
    family("cloud_run", lambda: parse_run_services(
        listed(f"{RUN_API}/namespaces/{project}/services", "items"), project))
    family("cloud_sql", lambda: parse_cloudsql_instances(
        listed(f"{SQLADMIN_API}/projects/{project}/instances", "items"), project))

    if not errors:
        source_status.clear("gcp", SOURCE_TYPE, tenant=tenant, account=project)
    return rows, errors
