"""AWS workload-breadth inventory (cloud platform backlog Wave 5 #15).

Extends discovery beyond network components to the WORKLOAD classes the
product review called out as missing (inventory was VM-only): the K8s layer
and the serverless/PaaS layer. DESCRIBE-level, free-tier APIs only:

  eks:cluster       eks list_clusters + describe_cluster (status + health
                    issues — a real provider signal, rolled up honestly)
  eks:nodegroup     eks list_nodegroups + describe_nodegroup per cluster
                    (status + health issues + desired size)
  lambda:function   lambda list_functions (FunctionConfiguration.State when
                    the provider returns it; absent state = not_measured)
  rds:instance      rds describe_db_instances (DBInstanceStatus)

Same shape discipline as aws_components.py: pure parse functions
(fixture-testable, no live calls) over a collect() orchestrator with
per-family isolation. STATUS HONESTY: a status derives only from a signal
the provider actually returned; no signal → not_measured, never green.

Wave 2 #4 discipline: a permission/misconfiguration failure in a family is
noted as a structured source-status record (source_type "workloads") so the
Ingestion page can say "IAM denied EKS reads since <t>" — never a silent
absence. All-family success clears the record.
"""
from __future__ import annotations

from botocore.config import Config

import source_status
from components_common import (DEGRADED, DOWN, HEALTHY, NOT_MEASURED, PAGE_CAP,
                               component_row, truncate)

BOTO_CFG = Config(connect_timeout=10, read_timeout=25,
                  retries={"max_attempts": 3, "mode": "standard"})

# Bounded per-cluster describes: list_clusters is one call, but cluster and
# nodegroup detail is one describe each — cap them (inventory, not a dump).
CLUSTER_GET_CAP = 25
NODEGROUP_GET_CAP = 100

SOURCE_TYPE = "workloads"


def _pages(client, op: str, key: str, **kw) -> list:
    out: list = []
    for i, page in enumerate(client.get_paginator(op).paginate(**kw)):
        if i >= PAGE_CAP:
            break
        out.extend(page.get(key, []))
    return out


# ── EKS clusters + node groups ───────────────────────────────────────────────

_EKS_CLUSTER_STATUS = {"active": HEALTHY, "updating": DEGRADED,
                       "creating": DEGRADED, "deleting": DEGRADED,
                       "failed": DOWN}
_EKS_NODEGROUP_STATUS = {"active": HEALTHY, "updating": DEGRADED,
                         "creating": DEGRADED, "deleting": DEGRADED,
                         "degraded": DEGRADED,
                         "create_failed": DOWN, "delete_failed": DOWN}


def parse_eks_cluster(cluster: dict, region: str) -> dict:
    """One row per EKS cluster. Status = provider status, demoted to degraded
    when the cluster reports health issues (a real API signal, not a guess)."""
    state = str(cluster.get("status", "")).lower()
    status = _EKS_CLUSTER_STATUS.get(state, NOT_MEASURED)
    reason = f"status={state}" if state else "no status returned"
    issues = ((cluster.get("health") or {}).get("issues")) or []
    if issues and status == HEALTHY:
        status = DEGRADED
    if issues:
        first = issues[0] or {}
        reason += (f"; {len(issues)} health issue(s): "
                   f"{str(first.get('code', ''))[:40]}")
    vpc = (cluster.get("resourcesVpcConfig") or {})
    return component_row(
        region=region,
        resource_id=cluster.get("arn", "") or cluster.get("name", ""),
        arn_or_uri=cluster.get("arn", ""),
        resource_type="eks:cluster",
        resource_name=cluster.get("name", ""),
        vpc_id=vpc.get("vpcId", ""),
        subnet_ids=vpc.get("subnetIds") or [],
        status=status, status_reason=reason,
        tags=cluster.get("tags") or {},
        attrs={"k8s_version": cluster.get("version", ""),
               "platform_version": cluster.get("platformVersion", "")})


def parse_eks_nodegroup(ng: dict, cluster_name: str, region: str) -> dict:
    state = str(ng.get("status", "")).lower()
    status = _EKS_NODEGROUP_STATUS.get(state, NOT_MEASURED)
    reason = f"status={state}" if state else "no status returned"
    issues = ((ng.get("health") or {}).get("issues")) or []
    if issues and status == HEALTHY:
        status = DEGRADED
    if issues:
        first = issues[0] or {}
        reason += (f"; {len(issues)} health issue(s): "
                   f"{str(first.get('code', ''))[:40]}")
    scaling = ng.get("scalingConfig") or {}
    metric = None
    if isinstance(scaling.get("desiredSize"), int):
        metric = ("desired_nodes", scaling["desiredSize"], "nodes")
    return component_row(
        region=region,
        resource_id=ng.get("nodegroupArn", "") or ng.get("nodegroupName", ""),
        arn_or_uri=ng.get("nodegroupArn", ""),
        resource_type="eks:nodegroup",
        resource_name=ng.get("nodegroupName", ""),
        subnet_ids=ng.get("subnets") or [],
        status=status, status_reason=reason, key_metric=metric,
        tags=ng.get("tags") or {},
        attrs={"cluster": cluster_name,
               "capacity_type": ng.get("capacityType", ""),
               "instance_types": ",".join(ng.get("instanceTypes") or [])})


def collect_eks(eks, region: str) -> list:
    """EKS clusters + node groups. Bounded describes; a nodegroup describe
    failing drops only that nodegroup (never fabricates its state)."""
    rows: list = []
    names = _pages(eks, "list_clusters", "clusters")
    ng_budget = NODEGROUP_GET_CAP
    for name in names[:CLUSTER_GET_CAP]:
        cluster = eks.describe_cluster(name=name).get("cluster") or {}
        row = parse_eks_cluster(cluster, region)
        ng_names = _pages(eks, "list_nodegroups", "nodegroups", clusterName=name)
        row["key_metric_name"] = "node_groups"
        row["key_metric_value"] = float(len(ng_names))
        row["key_metric_unit"] = "groups"
        rows.append(row)
        for ng_name in ng_names[:ng_budget]:
            try:
                ng = eks.describe_nodegroup(
                    clusterName=name, nodegroupName=ng_name).get("nodegroup") or {}
            except Exception:  # noqa: BLE001 - one nodegroup unmeasured, never fabricated
                continue
            rows.append(parse_eks_nodegroup(ng, name, region))
        ng_budget = max(0, ng_budget - len(ng_names))
    if len(names) > CLUSTER_GET_CAP:
        for r in rows:
            r.setdefault("attrs", {})["inventory_truncated"] = \
                f"eks:cluster: {len(names) - CLUSTER_GET_CAP} over describe cap"
    return truncate(rows, "eks:cluster")


# ── Lambda functions ─────────────────────────────────────────────────────────

_LAMBDA_STATE = {"active": HEALTHY, "pending": DEGRADED,
                 "inactive": DEGRADED, "failed": DOWN}


def parse_lambda_functions(fns: list, region: str) -> list:
    """list_functions returns FunctionConfiguration objects. State is only
    present for some functions (VPC-attached and container images always carry
    it) — an absent state is honestly not_measured, never green."""
    rows = []
    for fn in fns:
        state = str(fn.get("State", "")).lower()
        if state:
            status = _LAMBDA_STATE.get(state, NOT_MEASURED)
            reason = f"state={state}"
            if fn.get("StateReason"):
                reason += f"; {str(fn['StateReason'])[:80]}"
        else:
            status, reason = NOT_MEASURED, "provider returned no function state"
        vpc = fn.get("VpcConfig") or {}
        metric = None
        if isinstance(fn.get("MemorySize"), int):
            metric = ("memory_mb", fn["MemorySize"], "MB")
        rows.append(component_row(
            region=region,
            resource_id=fn.get("FunctionArn", "") or fn.get("FunctionName", ""),
            arn_or_uri=fn.get("FunctionArn", ""),
            resource_type="lambda:function",
            resource_name=fn.get("FunctionName", ""),
            vpc_id=vpc.get("VpcId", ""),
            subnet_ids=vpc.get("SubnetIds") or [],
            status=status, status_reason=reason, key_metric=metric,
            attrs={"runtime": fn.get("Runtime", ""),
                   "timeout_s": fn.get("Timeout", ""),
                   "last_modified": fn.get("LastModified", "")}))
    return truncate(rows, "lambda:function")


# ── RDS instances ────────────────────────────────────────────────────────────

_RDS_STATUS = {
    "available": HEALTHY, "backing-up": HEALTHY, "maintenance": DEGRADED,
    "modifying": DEGRADED, "upgrading": DEGRADED, "rebooting": DEGRADED,
    "starting": DEGRADED, "storage-optimization": HEALTHY,
    "storage-full": DOWN, "failed": DOWN, "inaccessible-encryption-credentials": DOWN,
    "restore-error": DOWN, "stopped": NOT_MEASURED, "stopping": NOT_MEASURED,
}


def parse_rds_instances(dbs: list, region: str) -> list:
    rows = []
    for db in dbs:
        state = str(db.get("DBInstanceStatus", "")).lower()
        status = _RDS_STATUS.get(state, NOT_MEASURED)
        reason = f"status={state}" if state else "no status returned"
        if state in ("stopped", "stopping"):
            # Lifecycle truth (P1-2): a stopped database is turned off, not broken.
            reason += " (instance is stopped, not failed)"
        sub = db.get("DBSubnetGroup") or {}
        metric = None
        if isinstance(db.get("AllocatedStorage"), int):
            metric = ("allocated_storage_gb", db["AllocatedStorage"], "GB")
        tags = {t.get("Key", ""): t.get("Value", "") for t in (db.get("TagList") or [])}
        rows.append(component_row(
            region=region,
            resource_id=db.get("DBInstanceArn", "") or db.get("DBInstanceIdentifier", ""),
            arn_or_uri=db.get("DBInstanceArn", ""),
            resource_type="rds:instance",
            resource_name=db.get("DBInstanceIdentifier", ""),
            vpc_id=sub.get("VpcId", ""),
            subnet_ids=[s.get("SubnetIdentifier", "")
                        for s in (sub.get("Subnets") or [])],
            status=status, status_reason=reason, key_metric=metric,
            tags=tags,
            attrs={"engine": db.get("Engine", ""),
                   "engine_version": db.get("EngineVersion", ""),
                   "instance_class": db.get("DBInstanceClass", ""),
                   "multi_az": str(bool(db.get("MultiAZ", False))).lower()}))
    return truncate(rows, "rds:instance")


# ── orchestrator ─────────────────────────────────────────────────────────────

def collect(session, region: str, *, tenant: str = "", account: str = "") -> tuple[list, dict]:
    """All AWS workload rows for one region. Per-family isolation; a
    permission/misconfiguration failure becomes a structured source-status
    record ("workloads"), all-success clears it. Returns (rows, errors)."""
    rows: list = []
    errors: dict = {}
    noted = False

    def family(name: str, fn) -> None:
        nonlocal noted
        try:
            rows.extend(fn())
        except Exception as exc:  # noqa: BLE001 - family isolation
            errors[name] = str(exc)[:160]
            if not noted and source_status.note(
                    "aws", SOURCE_TYPE, exc, tenant=tenant,
                    account=account, region=region):
                noted = True

    family("eks", lambda: collect_eks(
        session.client("eks", region_name=region, config=BOTO_CFG), region))
    family("lambda", lambda: parse_lambda_functions(
        _pages(session.client("lambda", region_name=region, config=BOTO_CFG),
               "list_functions", "Functions"), region))
    family("rds", lambda: parse_rds_instances(
        _pages(session.client("rds", region_name=region, config=BOTO_CFG),
               "describe_db_instances", "DBInstances"), region))

    if not errors:
        source_status.clear("aws", SOURCE_TYPE, tenant=tenant,
                            account=account, region=region)
    return rows, errors
