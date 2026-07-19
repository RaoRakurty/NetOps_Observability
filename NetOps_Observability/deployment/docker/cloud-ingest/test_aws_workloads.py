"""AWS workload-inventory tests (Wave 5 #15) — fixture-driven, no live calls.

Pins the parse contract for the K8s + serverless/PaaS classes: STATUS HONESTY
(missing provider signal = not_measured, never green), lifecycle truth
(stopped ≠ broken), health-issue demotion, and the source-status note on a
permission-denied family."""
from __future__ import annotations

import aws_workloads as aw
import source_status

R = "us-west-2"


# ── EKS ──────────────────────────────────────────────────────────────────────

CLUSTER = {
    "name": "prod-eks",
    "arn": "arn:aws:eks:us-west-2:1:cluster/prod-eks",
    "status": "ACTIVE",
    "version": "1.29",
    "platformVersion": "eks.7",
    "resourcesVpcConfig": {"vpcId": "vpc-1", "subnetIds": ["subnet-a", "subnet-b"]},
    "health": {"issues": []},
    "tags": {"app": "shop"},
}


def test_eks_cluster_active_is_healthy_with_context():
    r = aw.parse_eks_cluster(CLUSTER, R)
    assert r["resource_type"] == "eks:cluster"
    assert r["status"] == "healthy"
    assert r["vpc_id"] == "vpc-1"
    assert r["subnet_ids"] == ["subnet-a", "subnet-b"]
    assert r["attrs"]["k8s_version"] == "1.29"
    assert r["confidence"] == "confirmed"  # app tag honoured like instances


def test_eks_cluster_health_issues_demote_to_degraded():
    c = dict(CLUSTER, health={"issues": [{"code": "NodeCreationFailure", "message": "x"}]})
    r = aw.parse_eks_cluster(c, R)
    assert r["status"] == "degraded"
    assert "NodeCreationFailure" in r["status_reason"]


def test_eks_cluster_failed_is_down_and_unknown_state_not_measured():
    assert aw.parse_eks_cluster(dict(CLUSTER, status="FAILED"), R)["status"] == "down"
    assert aw.parse_eks_cluster(dict(CLUSTER, status="SOME_NEW"), R)["status"] == "not_measured"


def test_eks_nodegroup_desired_size_metric():
    ng = {"nodegroupArn": "arn:ng-1", "nodegroupName": "workers",
          "status": "ACTIVE", "scalingConfig": {"desiredSize": 4},
          "subnets": ["subnet-a"], "capacityType": "ON_DEMAND",
          "instanceTypes": ["m5.large"], "health": {"issues": []}}
    r = aw.parse_eks_nodegroup(ng, "prod-eks", R)
    assert r["resource_type"] == "eks:nodegroup"
    assert r["status"] == "healthy"
    assert (r["key_metric_name"], r["key_metric_value"]) == ("desired_nodes", 4.0)
    assert r["attrs"]["cluster"] == "prod-eks"


def test_eks_nodegroup_degraded_status_and_no_scaling_omits_metric():
    ng = {"nodegroupName": "w", "status": "DEGRADED",
          "health": {"issues": [{"code": "AsgInstanceLaunchFailures"}]}}
    r = aw.parse_eks_nodegroup(ng, "c", R)
    assert r["status"] == "degraded"
    assert "key_metric_name" not in r  # absence stays absence


# ── Lambda ───────────────────────────────────────────────────────────────────

FN = {"FunctionName": "checkout", "FunctionArn": "arn:aws:lambda:us-west-2:1:function:checkout",
      "Runtime": "python3.12", "MemorySize": 256, "Timeout": 30,
      "State": "Active", "VpcConfig": {"VpcId": "vpc-1", "SubnetIds": ["subnet-a"]}}


def test_lambda_active_state_and_memory_metric():
    r = aw.parse_lambda_functions([FN], R)[0]
    assert r["resource_type"] == "lambda:function"
    assert r["status"] == "healthy"
    assert (r["key_metric_name"], r["key_metric_value"]) == ("memory_mb", 256.0)
    assert r["vpc_id"] == "vpc-1"


def test_lambda_absent_state_is_not_measured_never_green():
    fn = {k: v for k, v in FN.items() if k != "State"}
    r = aw.parse_lambda_functions([fn], R)[0]
    assert r["status"] == "not_measured"
    assert "no function state" in r["status_reason"]


def test_lambda_failed_state_carries_reason():
    fn = dict(FN, State="Failed", StateReason="Image access denied")
    r = aw.parse_lambda_functions([fn], R)[0]
    assert r["status"] == "down"
    assert "Image access denied" in r["status_reason"]


# ── RDS ──────────────────────────────────────────────────────────────────────

DB = {"DBInstanceIdentifier": "orders-db",
      "DBInstanceArn": "arn:aws:rds:us-west-2:1:db:orders-db",
      "DBInstanceStatus": "available", "Engine": "postgres",
      "EngineVersion": "16.2", "DBInstanceClass": "db.t3.medium",
      "AllocatedStorage": 100, "MultiAZ": True,
      "DBSubnetGroup": {"VpcId": "vpc-1",
                        "Subnets": [{"SubnetIdentifier": "subnet-a"}]},
      "TagList": [{"Key": "service", "Value": "orders"}]}


def test_rds_available_is_healthy_with_storage_metric():
    r = aw.parse_rds_instances([DB], R)[0]
    assert r["resource_type"] == "rds:instance"
    assert r["status"] == "healthy"
    assert (r["key_metric_name"], r["key_metric_value"]) == ("allocated_storage_gb", 100.0)
    assert r["vpc_id"] == "vpc-1"
    assert r["attrs"]["engine"] == "postgres"
    assert r["confidence"] == "confirmed"


def test_rds_stopped_is_lifecycle_not_fault():
    r = aw.parse_rds_instances([dict(DB, DBInstanceStatus="stopped")], R)[0]
    assert r["status"] == "not_measured"  # turned off ≠ broken, and ≠ green
    assert "stopped, not failed" in r["status_reason"]


def test_rds_storage_full_is_down():
    assert aw.parse_rds_instances(
        [dict(DB, DBInstanceStatus="storage-full")], R)[0]["status"] == "down"


# ── orchestrator: isolation + source-status honesty ──────────────────────────

class _DeniedPaginator:
    def paginate(self, **kw):
        raise _client_error("AccessDeniedException", 403)


def _client_error(code: str, status: int) -> Exception:
    exc = Exception(f"An error occurred ({code})")
    exc.response = {"Error": {"Code": code},
                    "ResponseMetadata": {"HTTPStatusCode": status}}
    return exc


class _FakeClient:
    """eks/lambda/rds fake: eks denied, lambda+rds succeed with fixtures."""

    def __init__(self, service):
        self.service = service

    def get_paginator(self, op):
        if self.service == "eks":
            return _DeniedPaginator()
        pages = {"list_functions": [{"Functions": [FN]}],
                 "describe_db_instances": [{"DBInstances": [DB]}]}

        class _P:
            def paginate(self, **kw):
                return iter(pages[op])
        return _P()


class _FakeSession:
    def client(self, service, **kw):
        return _FakeClient(service)


def test_collect_isolates_denied_family_and_notes_source_status():
    source_status.reset()
    rows, errors = aw.collect(_FakeSession(), R, tenant="t1", account="123")
    types = {r["resource_type"] for r in rows}
    assert types == {"lambda:function", "rds:instance"}  # eks degraded only
    assert "eks" in errors
    key = ("t1", "aws", "123", R, "workloads")
    assert source_status._active[key]["status"] == "permission_denied"
    source_status.reset()


def test_collect_all_success_clears_source_status():
    source_status.reset()

    class _OkSession:
        def client(self, service, **kw):
            c = _FakeClient(service)
            if service == "eks":
                class _EksOk:
                    def get_paginator(self, op):
                        class _P:
                            def paginate(self, **kw):
                                return iter([{"clusters": []}])
                        return _P()
                return _EksOk()
            return c
    source_status.note_status("aws", "workloads", "permission_denied", "old",
                             tenant="t1", account="123", region=R)
    rows, errors = aw.collect(_OkSession(), R, tenant="t1", account="123")
    assert errors == {}
    assert ("t1", "aws", "123", R, "workloads") not in source_status._active
    source_status.reset()
