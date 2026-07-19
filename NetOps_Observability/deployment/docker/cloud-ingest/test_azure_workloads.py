"""Azure workload-inventory tests (Wave 5 #15) — fixture-driven, no live calls."""
from __future__ import annotations

import urllib.error

import azure_workloads as az
import source_status

R = "westeurope"
SUB = "sub-1"

AKS = {
    "id": "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.ContainerService/managedClusters/prod-aks",
    "name": "prod-aks", "location": "westeurope",
    "tags": {"app": "shop"},
    "properties": {
        "provisioningState": "Succeeded",
        "powerState": {"code": "Running"},
        "kubernetesVersion": "1.29.2",
        "fqdn": "prod-aks.hcp.westeurope.azmk8s.io",
        "agentPoolProfiles": [
            {"name": "system", "count": 3, "vmSize": "Standard_D4s_v5",
             "mode": "System", "provisioningState": "Succeeded",
             "powerState": {"code": "Running"}},
            {"name": "burst", "count": 2, "vmSize": "Standard_D8s_v5",
             "mode": "User", "provisioningState": "Failed",
             "powerState": {"code": "Running"}},
        ],
    },
}


def test_aks_cluster_and_pools_rows():
    rows = az.parse_aks_clusters([AKS], R)
    by_type = {}
    for r in rows:
        by_type.setdefault(r["resource_type"], []).append(r)
    c = by_type["containerservice:managedCluster"][0]
    assert c["status"] == "healthy"
    assert (c["key_metric_name"], c["key_metric_value"]) == ("nodes", 5.0)
    assert c["attrs"]["k8s_version"] == "1.29.2"
    assert c["attrs"]["resource_group"] == "rg1"
    assert c["confidence"] == "confirmed"
    pools = {p["resource_name"]: p for p in by_type["containerservice:agentPool"]}
    assert pools["system"]["status"] == "healthy"
    assert pools["system"]["key_metric_value"] == 3.0
    assert pools["burst"]["status"] == "down"  # provisioningState=Failed
    assert pools["system"]["attrs"]["cluster"] == "prod-aks"


def test_aks_stopped_cluster_is_lifecycle_not_fault():
    stopped = dict(AKS, properties=dict(AKS["properties"],
                                        powerState={"code": "Stopped"}))
    r = az.parse_aks_clusters([stopped], R)[0]
    assert r["status"] == "not_measured"
    assert "stopped, not failed" in r["status_reason"]


def test_aks_unknown_provisioning_state_not_measured():
    odd = dict(AKS, properties=dict(AKS["properties"],
                                    provisioningState="SomethingNew",
                                    agentPoolProfiles=[]))
    assert az.parse_aks_clusters([odd], R)[0]["status"] == "not_measured"


def test_server_farm_ready_and_site_count():
    farm = {"id": "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Web/serverfarms/plan1",
            "name": "plan1", "location": R, "sku": {"name": "P1v3"},
            "properties": {"status": "Ready", "numberOfSites": 4}}
    r = az.parse_server_farms([farm], R)[0]
    assert r["resource_type"] == "web:serverFarm"
    assert r["status"] == "healthy"
    assert (r["key_metric_name"], r["key_metric_value"]) == ("sites", 4.0)
    assert r["attrs"]["sku"] == "P1v3"


def test_sites_function_app_kind_and_stopped_lifecycle():
    fn = {"id": "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Web/sites/fn1",
          "name": "fn1", "location": R, "kind": "functionapp,linux",
          "properties": {"state": "Running", "defaultHostName": "fn1.azurewebsites.net",
                         "serverFarmId": "/subscriptions/sub-1/rg1/plan1"}}
    web = {"id": "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Web/sites/web1",
           "name": "web1", "location": R, "kind": "app",
           "properties": {"state": "Stopped"}}
    rows = az.parse_sites([fn, web], R)
    assert rows[0]["resource_type"] == "web:site"
    assert rows[0]["status"] == "healthy"
    assert rows[0]["attrs"]["app_kind"] == "function_app"
    assert rows[1]["attrs"]["app_kind"] == "web_app"
    assert rows[1]["status"] == "not_measured"  # stopped ≠ broken, ≠ green
    assert "stopped, not failed" in rows[1]["status_reason"]


def test_sql_server_and_databases():
    srv = {"id": "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Sql/servers/s1",
           "name": "s1", "location": R,
           "properties": {"state": "Ready", "fullyQualifiedDomainName": "s1.database.windows.net",
                          "version": "12.0"}}
    dbs = [
        {"id": srv["id"] + "/databases/master", "name": "master",
         "properties": {"status": "Online"}},
        {"id": srv["id"] + "/databases/orders", "name": "orders", "location": R,
         "sku": {"name": "S1"},
         "properties": {"status": "Online", "maxSizeBytes": 2 * 2**30}},
        {"id": srv["id"] + "/databases/legacy", "name": "legacy", "location": R,
         "properties": {"status": "Suspect"}},
        {"id": srv["id"] + "/databases/dev", "name": "dev", "location": R,
         "properties": {"status": "Paused"}},
    ]
    s = az.parse_sql_servers([srv], R)[0]
    assert s["resource_type"] == "sql:server"
    assert s["status"] == "healthy"
    rows = az.parse_sql_databases(dbs, "s1", R)
    names = [r["resource_name"] for r in rows]
    assert "master" not in names  # system db excluded
    by = {r["resource_name"]: r for r in rows}
    assert by["orders"]["status"] == "healthy"
    assert (by["orders"]["key_metric_name"], by["orders"]["key_metric_value"]) == \
        ("max_size_gb", 2.0)
    assert by["legacy"]["status"] == "down"
    assert by["dev"]["status"] == "not_measured"  # paused is lifecycle
    assert by["orders"]["attrs"]["server"] == "s1"


# ── orchestrator: family isolation + source-status honesty ───────────────────

def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://management.azure.com/x", code, "denied", None, None)


def test_collect_isolates_denied_family_and_notes_source_status():
    source_status.reset()

    def get_json(url):
        if "ContainerService" in url:
            raise _http_error(403)
        if "Microsoft.Web/serverfarms" in url:
            return {"value": []}
        if "Microsoft.Web/sites" in url:
            return {"value": []}
        if "Microsoft.Sql/servers" in url:
            return {"value": []}
        return {"value": []}

    rows, errors = az.collect(get_json, SUB, R, tenant="t1")
    assert rows == []
    assert list(errors) == ["aks_clusters"]
    key = ("t1", "azure", SUB, R, "workloads")
    assert source_status._active[key]["status"] == "permission_denied"
    source_status.reset()


def test_collect_all_success_clears_source_status():
    source_status.reset()
    source_status.note_status("azure", "workloads", "permission_denied", "old",
                             tenant="t1", account=SUB, region=R)
    rows, errors = az.collect(lambda url: {"value": []}, SUB, R, tenant="t1")
    assert errors == {}
    assert ("t1", "azure", SUB, R, "workloads") not in source_status._active
    source_status.reset()
