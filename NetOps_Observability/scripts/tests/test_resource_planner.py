#!/usr/bin/env python3
"""Tests for scripts/resource_planner.py — the 26 design-spec scenarios (#102).

Run: python3 -m unittest scripts.tests.test_resource_planner  (from repo root)
 or: cd scripts && python3 -m unittest tests.test_resource_planner
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import resource_planner as rp  # noqa: E402

GIB = rp.GIB
MIB = rp.MIB


def host(mem_gib, cpus=8, disk_gib=500):
    return {"memory_bytes": mem_gib * GIB, "cpus": float(cpus),
            "disk_free_bytes": disk_gib * GIB}


def env_bytes(plan, name):
    return plan["limits_bytes"][name]


class Invariants:
    """Shared assertions applied to every successful plan."""

    def check(self, plan):
        budget = plan["totals"]["budget_bytes"]
        self.assertLessEqual(plan["totals"]["limits_bytes"], budget)
        # internal < container for every derived pair
        lim = plan["limits_bytes"]
        inner = plan["internal"]
        if "OPENSEARCH_HEAP" in inner:
            self.assertLess(rp.parse_size(inner["OPENSEARCH_HEAP"]), lim["opensearch"])
        if "KAFKA_HEAP" in inner and "kafka" in lim:
            self.assertLess(rp.parse_size(inner["KAFKA_HEAP"]), lim["kafka"])
        if "REDIS_MAXMEMORY" in inner:
            self.assertLess(rp.parse_size(inner["REDIS_MAXMEMORY"]), lim["redis"])
        for svc, var in (("api", "API_GOMEMLIMIT"), ("prober", "PROBER_GOMEMLIMIT"),
                         ("goflow2", "GOFLOW2_GOMEMLIMIT")):
            if var in inner and svc in lim:
                self.assertLess(rp.parse_size(inner[var]), lim[svc])
        if "CH_BG_MEM" in inner:
            self.assertLess(int(inner["CH_BG_MEM"]), lim["clickhouse"])
            self.assertLess(int(inner["CH_HOT_UI_MEM"]), lim["clickhouse"])
        if "PG_SHARED_BUFFERS" in inner:
            self.assertLess(rp.parse_size(inner["PG_SHARED_BUFFERS"]), lim["postgres"])
        # floors respected
        floors = {s[0]: s[3] for s in rp.SERVICES}
        for name, v in lim.items():
            self.assertGreaterEqual(v, floors[name], name)


class TestScenarios(unittest.TestCase, Invariants):

    # 1 — demo host, demo workload
    def test_01_demo(self):
        plan = rp.compute_plan(host(16, 4, 100), "demo")
        self.check(plan)
        self.assertEqual(plan["profile"], "demo")

    # 2 — small production
    def test_02_small(self):
        plan = rp.compute_plan(host(32, 8, 1500), "small")
        self.check(plan)
        self.assertGreater(env_bytes(plan, "clickhouse"), 4 * GIB)

    # 3 — flow-heavy
    def test_03_flow_heavy(self):
        plan = rp.compute_plan(host(64, 16, 6000), "custom",
                               {"flows_per_second": 30000, "devices": 500,
                                "interfaces": 20000, "retention_flows_days": 30})
        self.check(plan)
        self.assertGreater(env_bytes(plan, "clickhouse"), 8 * GIB)
        self.assertGreater(env_bytes(plan, "goflow2"), 512 * MIB)

    # 4 — log-heavy (heap = 50% of generated container limit)
    def test_04_log_heavy(self):
        plan = rp.compute_plan(host(64, 16, 2000), "custom",
                               {"syslog_events_per_second": 10000,
                                "retention_logs_days": 14})
        self.check(plan)
        osm = env_bytes(plan, "opensearch")
        self.assertGreater(osm, 3 * GIB)
        heap = rp.parse_size(plan["internal"]["OPENSEARCH_HEAP"])
        self.assertAlmostEqual(heap / osm, 0.5, delta=0.05)

    # 5 — metrics-heavy
    def test_05_metrics_heavy(self):
        plan = rp.compute_plan(host(64, 16, 2000), "custom",
                               {"active_series": 2_000_000})
        self.check(plan)
        self.assertGreater(env_bytes(plan, "victoria"), 4 * GIB)

    # 6 — query-heavy
    def test_06_query_heavy(self):
        base = rp.compute_plan(host(64, 16, 2000), "custom",
                               {"concurrent_analytical_queries": 1})
        heavy = rp.compute_plan(host(64, 16, 2000), "custom",
                                {"concurrent_analytical_queries": 16})
        self.check(heavy)
        self.assertGreater(env_bytes(heavy, "clickhouse"), env_bytes(base, "clickhouse"))
        self.assertGreater(int(heavy["internal"]["CH_MAX_CONCURRENT_QUERIES"]),
                           int(base["internal"]["CH_MAX_CONCURRENT_QUERIES"]))

    # 7 — multi-tenant
    def test_07_multi_tenant(self):
        plan = rp.compute_plan(host(64, 16, 2000), "custom",
                               {"tenants": 50, "concurrent_users": 40})
        self.check(plan)
        self.assertGreater(env_bytes(plan, "postgres"), 1 * GIB)

    # 8 — HA requested on single-node product
    def test_08_ha_refused(self):
        with self.assertRaises(rp.SizingError):
            rp.compute_plan(host(64), "custom", {"high_availability": True})

    # 9 — host too small for the profile
    def test_09_host_too_small(self):
        with self.assertRaises(rp.SizingError) as cm:
            rp.compute_plan(host(8, 4, 100), "medium")
        msg = str(cm.exception)
        self.assertIn("cannot safely fit", msg)
        self.assertIn("Primary contributors", msg)
        self.assertIn("Recommended corrective action", msg)

    # 10 — insufficient storage
    def test_10_insufficient_storage(self):
        with self.assertRaises(rp.SizingError) as cm:
            rp.compute_plan(host(128, 32, 50), "custom",
                            {"flows_per_second": 50000, "retention_flows_days": 30})
        self.assertIn("storage", str(cm.exception).lower())

    # 11 — unknown storage capability advisory at high ingest
    def test_11_unknown_iops_advisory(self):
        plan = rp.compute_plan(host(64, 16, 2000), "custom",
                               {"flows_per_second": 15000})
        self.assertTrue(any("storage capability undeclared" in w
                            for w in plan["warnings"]))

    # 12 — legacy CLICKHOUSE_MEM_LIMIT pin
    def test_12_legacy_clickhouse(self):
        plan = rp.compute_plan(host(64, 16, 2000), "small",
                               legacy={"CLICKHOUSE_MEM_LIMIT": "5g"})
        self.assertEqual(env_bytes(plan, "clickhouse"), 5 * GIB)
        self.assertEqual(plan["pinned"]["clickhouse"], "legacy-env-override")
        self.assertTrue(any("CLICKHOUSE_MEM_LIMIT=5g" in w for w in plan["warnings"]))
        block = rp.env_block(plan)
        self.assertNotIn("CLICKHOUSE_MEM_LIMIT=", block.replace(
            "# clickhouse pinned", ""))

    # 13 — customer override (valid + below-floor rejected)
    def test_13_customer_override(self):
        plan = rp.compute_plan(host(64, 16, 2000), "small",
                               overrides={"clickhouse_mem": "12g"})
        self.assertEqual(env_bytes(plan, "clickhouse"), 12 * GIB)
        with self.assertRaises(rp.SizingError):
            rp.compute_plan(host(64, 16, 2000), "small",
                            overrides={"clickhouse_mem": "1g"})

    # 14 — emergency internal-var override preserved
    def test_14_emergency_internal_override(self):
        plan = rp.compute_plan(host(64, 16, 2000), "small",
                               legacy={"OPENSEARCH_HEAP": "2g"})
        self.assertEqual(plan["internal"]["OPENSEARCH_HEAP"], "2g")
        self.assertTrue(any("OPENSEARCH_HEAP=2g" in w for w in plan["warnings"]))

    # 15/16 — aggregate invariants across profiles/hosts
    def test_15_16_aggregates(self):
        for prof, mem, disk in (("demo", 16, 200), ("small", 32, 1500), ("medium", 64, 4000), ("large", 128, 12000)):
            plan = rp.compute_plan(host(mem, 32, disk), prof)
            self.check(plan)
            alloc = plan["reserves"]["allocatable_bytes"]
            over = plan["reserves"]["overcommit_factor"]
            self.assertLessEqual(plan["totals"]["limits_bytes"],
                                 int(alloc * over) + 1)

    # 17 — internal < container (covered by check(); explicit spot-check)
    def test_17_internal_below_container(self):
        plan = rp.compute_plan(host(64, 16, 4000), "medium")
        self.check(plan)
        gml = rp.parse_size(plan["internal"]["API_GOMEMLIMIT"])
        self.assertAlmostEqual(gml / env_bytes(plan, "api"), 0.9, delta=0.02)

    # 18 — one canonical model: env block values == plan values
    def test_18_emitter_consistency(self):
        plan = rp.compute_plan(host(64, 16, 4000), "medium")
        block = rp.env_block(plan)
        self.assertIn("CLICKHOUSE_MEM_LIMIT=%s" % rp.fmt_bytes(
            env_bytes(plan, "clickhouse")), block)
        self.assertIn("OPENSEARCH_HEAP=%s" % plan["internal"]["OPENSEARCH_HEAP"], block)

    # 19 — determinism
    def test_19_deterministic(self):
        a = rp.compute_plan(host(64, 16, 4000), "medium")
        b = rp.compute_plan(host(64, 16, 4000), "medium")
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    # 20 — invalid / negative / overflow / malformed
    def test_20_invalid_inputs(self):
        with self.assertRaises(ValueError):
            rp.parse_size("-5g")
        with self.assertRaises(ValueError):
            rp.parse_size("banana")
        with self.assertRaises(ValueError):
            rp.normalize_workload({"workload": {"devices": -1}})
        with self.assertRaises(ValueError):
            rp.normalize_workload({"workload": {"devices": 10 ** 13}})
        with self.assertRaises(ValueError):
            rp.compute_plan(host(64), "no-such-profile")

    # 21 — missing workload inputs → floors-only plan
    def test_21_missing_inputs(self):
        plan = rp.compute_plan(host(32, 8, 500), "custom", {})
        self.check(plan)
        self.assertEqual(env_bytes(plan, "clickhouse"),
                         max(4 * GIB, env_bytes(plan, "clickhouse")))

    # 22 — cgroup-limited / small host: demo (relaxed) oversubscribes with a
    # warning instead of refusing — matches shipped 8 GB evaluation behavior
    def test_22_cgroup_limited(self):
        plan = rp.compute_plan(host(8, 4, 200), "demo")
        self.assertTrue(any("oversubscribe" in w for w in plan["warnings"]))
        floors = {s[0]: s[3] for s in rp.SERVICES}
        for name, v in plan["limits_bytes"].items():
            self.assertGreaterEqual(v, floors[name])

    # 23 — cgroup v1/v2 file parsing in detect_host
    def test_23_cgroup_detection(self):
        with tempfile.TemporaryDirectory() as d:
            v2 = os.path.join(d, "memory.max")
            with open(v2, "w") as f:
                f.write("4294967296\n")
            got = rp.detect_host(mem_override=None, cpu_override=2,
                                 disk_override="100g", cgroup_paths=(v2,))
            self.assertEqual(got["memory_bytes"], 4 * GIB)
            with open(v2, "w") as f:
                f.write("max\n")
            got = rp.detect_host(mem_override=None, cpu_override=2,
                                 disk_override="100g", cgroup_paths=(v2,))
            self.assertGreater(got["memory_bytes"], 0)

    # 24 — outage/buffer-growth allowance scales pipeline services
    def test_24_outage_buffer_growth(self):
        quiet = rp.compute_plan(host(64, 16, 2000), "custom",
                                {"syslog_events_per_second": 100})
        busy = rp.compute_plan(host(64, 16, 6000), "custom",
                               {"syslog_events_per_second": 20000,
                                "flows_per_second": 20000})
        self.assertGreater(env_bytes(busy, "vector"), env_bytes(quiet, "vector"))
        self.assertGreater(env_bytes(busy, "kafka"), env_bytes(quiet, "kafka"))

    # 25 — managed-block splice + rollback round-trip
    def test_25_splice_rollback(self):
        plan = rp.compute_plan(host(32, 8, 1500), "small")
        original = "FOO=bar\nCLICKHOUSE_MEM_LIMIT=5g\n"
        spliced = rp.splice_env(original, rp.env_block(plan))
        self.assertIn("FOO=bar", spliced)
        self.assertIn(rp.BLOCK_BEGIN, spliced)
        # re-splice is idempotent (one block only)
        again = rp.splice_env(spliced, rp.env_block(plan))
        self.assertEqual(again.count(rp.BLOCK_BEGIN), 1)
        # rollback = original minus block == original
        removed = rp.splice_env(spliced, "").replace("\n\n", "\n").strip()
        self.assertIn("FOO=bar", removed)
        # legacy detection sees the outside var, never the block's own vars
        legacy = rp.read_env_overrides(spliced)
        self.assertEqual(legacy.get("CLICKHOUSE_MEM_LIMIT"), "5g")
        self.assertNotIn("OPENSEARCH_HEAP", {k for k in legacy
                                             if k != "CLICKHOUSE_MEM_LIMIT"} - {"CLICKHOUSE_MEM_LIMIT"})

    # 26 — unit normalization
    def test_26_units(self):
        self.assertEqual(rp.parse_size("5g"), 5 * GIB)
        self.assertEqual(rp.parse_size("512MiB"), 512 * MIB)
        self.assertEqual(rp.parse_size("2GB"), 2 * 10 ** 9)
        self.assertEqual(rp.parse_size(1024), 1024)
        self.assertEqual(rp.fmt_bytes(5 * GIB), "5g")
        self.assertEqual(rp.fmt_bytes(1536 * MIB), "1536m")
        self.assertEqual(rp.parse_size(rp.fmt_bytes(768 * MIB)), 768 * MIB)

    # sizing-file parser (YAML subset + JSON)
    def test_sizing_file_parser(self):
        yml = """
profile: custom
host:
  memory: auto
workload:
  devices: 500
  flows:
    records_per_second: 15000
    retention_days: 30
  users:
    concurrent_users: 20
"""
        doc = rp.parse_sizing_file(yml)
        w = rp.normalize_workload(doc)
        self.assertEqual(w["devices"], 500)
        self.assertEqual(w["flows_per_second"], 15000)
        self.assertEqual(w["concurrent_users"], 20)
        jdoc = rp.parse_sizing_file(json.dumps(doc))
        self.assertEqual(rp.normalize_workload(jdoc), w)
        with self.assertRaises(ValueError):
            rp.parse_sizing_file("workload:\n  - a list\n")


class TestGolden(unittest.TestCase):
    """Golden plans: regenerate and compare (design §11)."""
    GOLDEN = os.path.join(os.path.dirname(__file__), "golden")
    FIXTURES = {
        "demo-16g": (host(16, 4, 100), "demo", None),
        "medium-64g": (host(64, 16, 4000), "medium", None),
        "flow-heavy-64g": (host(64, 16, 2000), "custom",
                           {"flows_per_second": 15000, "devices": 500,
                            "interfaces": 20000, "syslog_events_per_second": 3000,
                            "concurrent_users": 20,
                            "concurrent_analytical_queries": 8, "tenants": 10}),
    }

    def test_golden_plans(self):
        for name, (h, prof, w) in sorted(self.FIXTURES.items()):
            plan = rp.compute_plan(h, prof, w)
            got = json.dumps(plan, indent=2, sort_keys=True) + "\n"
            path = os.path.join(self.GOLDEN, name + ".plan.json")
            if os.environ.get("UPDATE_GOLDEN"):
                os.makedirs(self.GOLDEN, exist_ok=True)
                with open(path, "w") as f:
                    f.write(got)
                continue
            with open(path) as f:
                self.assertEqual(f.read(), got, "golden drift: %s "
                                 "(UPDATE_GOLDEN=1 to regenerate)" % name)


if __name__ == "__main__":
    unittest.main()
