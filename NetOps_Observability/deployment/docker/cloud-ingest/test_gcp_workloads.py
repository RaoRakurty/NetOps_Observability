"""GCP workload-inventory tests (Wave 5 #15) — fixture-driven, no live calls."""
from __future__ import annotations

import urllib.error

import gcp_workloads as gw
import source_status

P = "proj-1"

GKE = {
    "name": "prod-gke", "location": "us-west1",
    "status": "RUNNING", "currentMasterVersion": "1.29.4-gke.1043002",
    "currentNodeCount": 6,
    "network": "https://www.googleapis.com/compute/v1/projects/proj-1/global/networks/vpc-a",
    "subnetwork": "https://www.googleapis.com/compute/v1/projects/proj-1/regions/us-west1/subnetworks/sn-a",
    "resourceLabels": {"app": "shop"},
    "autopilot": {"enabled": False},
    "nodePools": [
        {"name": "default-pool", "status": "RUNNING", "initialNodeCount": 3,
         "config": {"machineType": "e2-standard-4"},
         "autoscaling": {"enabled": True}},
        {"name": "gpu-pool", "status": "ERROR",
         "statusMessage": "quota exceeded"},
    ],
}


def test_gke_cluster_and_node_pools():
    rows = gw.parse_gke_clusters([GKE], P)
    c = rows[0]
    assert c["resource_type"] == "container:cluster"
    assert c["status"] == "healthy"
    assert c["region"] == "us-west1"
    assert (c["key_metric_name"], c["key_metric_value"]) == ("nodes", 6.0)
    assert c["vpc_id"] == "projects/proj-1/global/networks/vpc-a"
    assert c["confidence"] == "confirmed"
    pools = {r["resource_name"]: r for r in rows if r["resource_type"] == "container:nodePool"}
    assert pools["default-pool"]["status"] == "healthy"
    assert pools["default-pool"]["key_metric_value"] == 3.0
    assert pools["gpu-pool"]["status"] == "down"
    assert "quota exceeded" in pools["gpu-pool"]["status_reason"]
    assert pools["gpu-pool"]["attrs"]["cluster"] == "prod-gke"


def test_gke_zonal_location_maps_to_region_and_zone():
    zonal = dict(GKE, location="us-west1-b", nodePools=[])
    r = gw.parse_gke_clusters([zonal], P)[0]
    assert r["region"] == "us-west1"
    assert r["zone"] == "us-west1-b"


def test_gke_degraded_and_unknown_states():
    assert gw.parse_gke_clusters([dict(GKE, status="DEGRADED", nodePools=[])], P)[0]["status"] == "degraded"
    assert gw.parse_gke_clusters([dict(GKE, status="BRAND_NEW", nodePools=[])], P)[0]["status"] == "not_measured"


RUN_SVC = {
    "metadata": {"name": "checkout",
                 "labels": {"cloud.googleapis.com/location": "us-west1",
                            "app": "shop"}},
    "status": {"url": "https://checkout-abc.a.run.app",
               "latestReadyRevisionName": "checkout-00042",
               "conditions": [{"type": "Ready", "status": "True"}]},
}


def test_cloud_run_ready_true_is_healthy():
    r = gw.parse_run_services([RUN_SVC], P)[0]
    assert r["resource_type"] == "run:service"
    assert r["status"] == "healthy"
    assert r["region"] == "us-west1"
    assert r["resource_id"] == "projects/proj-1/locations/us-west1/services/checkout"
    assert r["tags"] == {"app": "shop"}  # provider-internal labels stripped


def test_cloud_run_ready_false_down_with_message_and_absent_not_measured():
    bad = {"metadata": {"name": "x", "labels": {}},
           "status": {"conditions": [{"type": "Ready", "status": "False",
                                      "message": "image pull failed"}]}}
    none = {"metadata": {"name": "y", "labels": {}}, "status": {}}
    rows = gw.parse_run_services([bad, none], P)
    assert rows[0]["status"] == "down"
    assert "image pull failed" in rows[0]["status_reason"]
    assert rows[1]["status"] == "not_measured"


CSQL = {
    "name": "orders-sql", "region": "us-west1", "state": "RUNNABLE",
    "databaseVersion": "POSTGRES_16",
    "selfLink": "https://sqladmin.googleapis.com/v1/projects/proj-1/instances/orders-sql",
    "ipAddresses": [{"ipAddress": "34.1.2.3"}],
    "settings": {"tier": "db-custom-2-8192", "dataDiskSizeGb": "50",
                 "availabilityType": "ZONAL", "activationPolicy": "ALWAYS",
                 "userLabels": {"service": "orders"}},
}


def test_cloudsql_runnable_is_healthy_with_disk_metric():
    r = gw.parse_cloudsql_instances([CSQL], P)[0]
    assert r["resource_type"] == "sqladmin:instance"
    assert r["status"] == "healthy"
    assert (r["key_metric_name"], r["key_metric_value"]) == ("disk_size_gb", 50.0)
    assert r["attrs"]["engine"] == "POSTGRES_16"
    assert r["confidence"] == "confirmed"


def test_cloudsql_stopped_via_activation_policy_is_lifecycle():
    stopped = dict(CSQL, settings=dict(CSQL["settings"], activationPolicy="NEVER"))
    r = gw.parse_cloudsql_instances([stopped], P)[0]
    assert r["status"] == "not_measured"
    assert "stopped, not failed" in r["status_reason"]


def test_cloudsql_failed_and_suspended_are_down():
    assert gw.parse_cloudsql_instances([dict(CSQL, state="FAILED")], P)[0]["status"] == "down"
    assert gw.parse_cloudsql_instances([dict(CSQL, state="SUSPENDED")], P)[0]["status"] == "down"


# ── orchestrator: family isolation + source-status honesty ───────────────────

def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://container.googleapis.com/x", code,
                                  "denied", None, None)


def test_collect_isolates_denied_family_and_notes_source_status():
    source_status.reset()

    def get_json(url):
        if "container.googleapis.com" in url:
            raise _http_error(403)
        return {"items": []}

    rows, errors = gw.collect(get_json, P, tenant="t1")
    assert rows == []
    assert list(errors) == ["gke"]
    key = ("t1", "gcp", P, "", "workloads")
    assert source_status._active[key]["status"] == "permission_denied"
    source_status.reset()


def test_collect_all_success_clears_source_status():
    source_status.reset()
    source_status.note_status("gcp", "workloads", "permission_denied", "old",
                             tenant="t1", account=P)

    def get_json(url):
        if "container.googleapis.com" in url:
            return {"clusters": []}
        return {"items": []}

    rows, errors = gw.collect(get_json, P, tenant="t1")
    assert errors == {}
    assert ("t1", "gcp", P, "", "workloads") not in source_status._active
    source_status.reset()
