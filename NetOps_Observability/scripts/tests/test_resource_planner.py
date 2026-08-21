#!/usr/bin/env python3
"""Tests for scripts/resource_planner.py — the 26 design-spec scenarios (#102).

Run: python3 -m unittest scripts.tests.test_resource_planner  (from repo root)
 or: cd scripts && python3 -m unittest tests.test_resource_planner
"""
import json
import os
import re
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

    # signoff: canonical backup map — both replan and rollback must use it
    def test_signoff_backup_paths(self):
        m = rp.plan_backup_paths("/x/deployment/docker/.env")
        self.assertEqual(m["/x/deployment/docker/.env"],
                         "/x/deployment/docker/.env.plan.bak")
        self.assertIn("/x/deployment/docker/resource-plan.json", m)
        self.assertTrue(all(v.endswith(".plan.bak") for v in m.values()))

    # signoff: cgroup v1 numeric sentinel + malformed file are neutralized
    def test_signoff_cgroup_sentinel_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            v1 = os.path.join(d, "memory.limit_in_bytes")
            with open(v1, "w") as f:
                f.write("9223372036854771712\n")   # v1 "unlimited" sentinel
            got = rp.detect_host(cpu_override=2, disk_override="100g",
                                 cgroup_paths=(v1,))
            with open("/proc/meminfo") as f:
                host_kb = int([l for l in f if l.startswith("MemTotal")][0].split()[1])
            self.assertEqual(got["memory_bytes"], host_kb * 1024)  # sentinel > host -> host wins
            with open(v1, "w") as f:
                f.write("garbage\n")
            got = rp.detect_host(cpu_override=2, disk_override="100g",
                                 cgroup_paths=(v1,))
            self.assertGreater(got["memory_bytes"], 0)  # malformed ignored
            tiny = os.path.join(d, "memory.max")
            with open(tiny, "w") as f:
                f.write(str(2 * GIB) + "\n")
            got = rp.detect_host(cpu_override=2, disk_override="100g",
                                 cgroup_paths=(tiny,))
            self.assertEqual(got["memory_bytes"], 2 * GIB)  # tiny limit honored

    # signoff: pinned PG values that oversubscribe the container warn loudly
    def test_signoff_pg_budget_warning(self):
        plan = rp.compute_plan(host(64, 16, 4000), "small",
                               legacy={"PG_WORK_MEM": "256MB"})
        self.assertTrue(any("oversubscribe" in w and "postgres" in w
                            for w in plan["warnings"]))
        clean = rp.compute_plan(host(64, 16, 4000), "small")
        self.assertFalse(any("postgres internal settings" in w
                             for w in clean["warnings"]))

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


REPO = os.path.join(os.path.dirname(__file__), "..", "..")


class TestBusPartitions(unittest.TestCase):
    """BUS_PARTITIONS as first-class config (GA scale programme, Phase 2).

    Automatic EPS-based sizing is deliberately absent — these tests exist to
    prove the setting is VISIBLE and PROTECTED, and that generating a plan
    never resizes anyone's broker.
    """

    H = {"memory_bytes": 64 * GIB, "cpus": 16.0, "disk_free_bytes": 4000 * GIB}

    def bus(self, **kw):
        return rp.compute_plan(self.H, "medium", **kw)["bus"]

    # --- the approval gate: the default must not move -----------------------

    def test_default_is_unchanged_on_every_profile(self):
        """The installer approval gate has not been passed, so a fresh plan
        must still produce today's compose default of 1 — on every profile."""
        for prof, h in (("demo", host(16, 4, 500)), ("small", host(32, 8, 1000)),
                        ("medium", self.H), ("large", host(128, 32, 8000))):
            with self.subTest(profile=prof):
                plan = rp.compute_plan(h, prof)
                self.assertEqual(plan["bus"]["value"], 1)
                self.assertEqual(plan["bus"]["source"], "default")
                self.assertEqual(plan["internal"]["BUS_PARTITIONS"], "1")
                self.assertFalse(plan["bus"]["auto_sizing"])

    # --- existing-install detection -----------------------------------------

    def test_existing_env_value_is_detected(self):
        b = self.bus(legacy={"BUS_PARTITIONS": "4"})
        self.assertEqual((b["value"], b["source"], b["existing"]),
                         (4, "existing-install", 4))

    def test_malformed_existing_value_warns_and_falls_back(self):
        plan = rp.compute_plan(self.H, "medium", legacy={"BUS_PARTITIONS": "abc"})
        self.assertEqual(plan["bus"]["value"], 1)
        self.assertIsNone(plan["bus"]["existing"])
        self.assertTrue(any("not a positive integer" in w
                            for w in plan["warnings"]))

    # --- the raise-only invariant -------------------------------------------

    def test_override_below_existing_is_refused_and_explained(self):
        """Kafka cannot shrink partitions; a plan claiming fewer than the
        broker has is the silent divergence this guard exists to prevent."""
        plan = rp.compute_plan(self.H, "medium",
                               legacy={"BUS_PARTITIONS": "6"},
                               overrides={"bus_partitions": 2})
        self.assertEqual(plan["bus"]["value"], 6)
        self.assertEqual(plan["bus"]["source"], "existing-install")
        self.assertEqual(plan["internal"]["BUS_PARTITIONS"], "6")
        self.assertTrue(any("BELOW the existing" in w for w in plan["warnings"]))

    def test_override_above_existing_applies_and_flags_the_stale_pin(self):
        plan = rp.compute_plan(self.H, "medium",
                               legacy={"BUS_PARTITIONS": "4"},
                               overrides={"bus_partitions": 8})
        self.assertEqual((plan["bus"]["value"], plan["bus"]["source"]),
                         (8, "override"))
        self.assertTrue(any("OUTSIDE the managed block" in w
                            for w in plan["warnings"]))

    def test_override_on_fresh_install_applies(self):
        b = self.bus(overrides={"bus_partitions": 8})
        self.assertEqual((b["value"], b["source"]), (8, "override"))

    def test_invalid_overrides_are_refused(self):
        for bad in (0, -3, "four", []):
            with self.subTest(value=bad):
                with self.assertRaises(rp.SizingError):
                    rp.compute_plan(self.H, "medium",
                                    overrides={"bus_partitions": bad})

    # --- replica / partition mismatch ---------------------------------------

    def test_more_replicas_than_partitions_warns_with_the_idle_count(self):
        plan = rp.compute_plan(self.H, "medium",
                               legacy={"BUS_PARTITIONS": "2"},
                               workload={"correlation_replicas": 5})
        self.assertEqual(plan["bus"]["idle_replicas"], 3)
        self.assertEqual(plan["bus"]["max_useful_replicas"], 2)
        self.assertTrue(any("process no events" in w for w in plan["warnings"]))

    def test_replicas_within_partitions_is_silent(self):
        plan = rp.compute_plan(self.H, "medium",
                               legacy={"BUS_PARTITIONS": "4"},
                               workload={"correlation_replicas": 4})
        self.assertEqual(plan["bus"]["idle_replicas"], 0)
        self.assertFalse(any("process no events" in w for w in plan["warnings"]))

    # --- emitters ------------------------------------------------------------

    def test_env_block_does_not_duplicate_an_out_of_block_pin(self):
        """Two definitions of one key in .env resolve by file order — a coin
        toss the operator cannot see. Defer to the pin instead."""
        plan = rp.compute_plan(self.H, "medium", legacy={"BUS_PARTITIONS": "4"})
        emitted = [ln for ln in rp.env_block(plan).splitlines()
                   if ln.startswith("BUS_PARTITIONS=")]
        self.assertEqual(emitted, [])
        self.assertIn("# BUS_PARTITIONS=4 pinned outside this block",
                      rp.env_block(plan))

    def test_env_block_emits_the_key_when_not_pinned(self):
        plan = rp.compute_plan(self.H, "medium", overrides={"bus_partitions": 4})
        self.assertIn("BUS_PARTITIONS=4", rp.env_block(plan).splitlines())

    def test_plan_txt_surfaces_every_operator_fact(self):
        """These facts must be in the generated plan, not buried in docs."""
        plan = rp.compute_plan(self.H, "medium",
                               legacy={"BUS_PARTITIONS": "4"},
                               workload={"correlation_replicas": 6})
        txt = rp.plan_txt(plan)
        for needle in ("BUS_PARTITIONS", "topics created by kafka-init",
                       "topics correlation consumes", "total broker partitions",
                       "correlation replicas", "max useful replicas",
                       "EXPECTED IDLE REPLICAS", "never reduced",
                       "not redistributed", "controlled migration",
                       "kafka-topics.sh --describe"):
            with self.subTest(fact=needle):
                self.assertIn(needle, txt)

    # --- the constants must stay true of the repo ---------------------------

    def test_bus_topic_counts_match_sources(self):
        """BUS_TOPICS_CREATED/CONSUMED are facts about other files. If those
        files change, fail here rather than let the plan lie to an operator."""
        compose = os.path.join(REPO, "deployment", "docker", "docker-compose.yml")
        with open(compose) as f:
            body = f.read()
        init = body.split("for t in netops.", 1)
        self.assertEqual(len(init), 2, "kafka-init topic loop not found")
        loop = "netops." + init[1].split("; do", 1)[0]
        created = set(re.findall(r"netops\.[A-Za-z0-9_.]+", loop))
        self.assertEqual(
            len(created), rp.BUS_TOPICS_CREATED,
            "kafka-init now creates %d topics, BUS_TOPICS_CREATED says %d — "
            "update the constant AND re-check the broker partition maths"
            % (len(created), rp.BUS_TOPICS_CREATED))

        main = os.path.join(REPO, "src", "correlation", "main.py")
        with open(main) as f:
            src = f.read()
        decl = src.split("TOPICS = [", 1)[1].split("]", 1)[0]
        consumed = set(re.findall(r"netops\.[A-Za-z0-9_.]+", decl))
        self.assertEqual(
            len(consumed), rp.BUS_TOPICS_CONSUMED,
            "correlation now subscribes to %d topics, BUS_TOPICS_CONSUMED says "
            "%d — max_useful_replicas depends on this"
            % (len(consumed), rp.BUS_TOPICS_CONSUMED))
        self.assertTrue(
            consumed <= created,
            "correlation subscribes to topics kafka-init never creates: %s"
            % sorted(consumed - created))


class TestCorrelationQualifiedMemory(unittest.TestCase, Invariants):
    """Tracker 165 qualified correlation at 1.25 GiB on 2026-08-21.

    The planner's job here is not to allocate a nice number — it is to refuse
    to pretend. The old 768 MiB floor is DISPROVEN for the corrected ~516.5 s
    retention horizon (measured peak 668-775 MiB, settled 624-733 MiB), so a
    host that can only supply 768 MiB cannot run the qualified profile, and the
    planner must say so rather than emitting a smaller limit under the same
    support claim.
    """

    QUALIFIED = 1280 * MIB          # 1.25 GiB, exactly 1,342,177,280 bytes

    def test_1_sufficient_host_gets_the_qualified_allocation(self):
        for profile in ("small", "medium", "large"):
            with self.subTest(profile=profile):
                plan = rp.compute_plan(host(128, cpus=32, disk_gib=8000), profile)
                self.assertGreaterEqual(
                    plan["limits_bytes"]["correlation"], self.QUALIFIED,
                    f"{profile}: correlation below the qualified 1.25 GiB")
                self.assertGreaterEqual(
                    plan["reservations_bytes"]["correlation"], self.QUALIFIED,
                    f"{profile}: the RESERVATION is what is guaranteed, and it "
                    "must not sit below the qualified requirement")

    def test_2_a_host_that_cannot_supply_it_is_refused_not_shrunk(self):
        """The whole point: no silent downgrade. Either the qualified figure is
        met, or the planner refuses — never a quiet 768 MiB under the same
        support claim."""
        refused = met = 0
        for gib in (4, 6, 8, 12, 16, 24, 32, 48, 64):
            try:
                plan = rp.compute_plan(host(gib, disk_gib=8000), "medium")
            except rp.SizingError:
                refused += 1
                continue
            met += 1
            self.assertGreaterEqual(
                plan["limits_bytes"]["correlation"], self.QUALIFIED,
                f"{gib}GiB host produced a plan with correlation BELOW the "
                "qualified requirement instead of refusing")
        self.assertTrue(refused, "no host was small enough to exercise refusal")
        self.assertTrue(met, "no host was large enough to exercise success")

    def test_3_a_large_host_does_not_over_allocate_beyond_the_workload(self):
        """The floor is a minimum, not a target. Growing the host must not keep
        inflating correlation — above the workload term it should plateau."""
        big = rp.compute_plan(host(128, cpus=32, disk_gib=8000), "small")
        huge = rp.compute_plan(host(512, cpus=64, disk_gib=8000), "small")
        self.assertEqual(big["limits_bytes"]["correlation"],
                         huge["limits_bytes"]["correlation"],
                         "correlation kept growing with the host rather than "
                         "with the workload")

    def test_4_total_allocation_never_exceeds_the_planner_budget(self):
        """Raising one floor must not push the sum past the budget on any host
        the planner still accepts."""
        for gib in (16, 32, 64, 128):
            for profile in ("demo", "small", "medium"):
                with self.subTest(host=gib, profile=profile):
                    try:
                        plan = rp.compute_plan(host(gib, cpus=16, disk_gib=8000), profile)
                    except rp.SizingError:
                        continue
                    self.check(plan)

    def test_5_the_disproven_768_MiB_floor_cannot_silently_return(self):
        """A regression guard on the constant itself. 768 MiB was not merely
        conservative — it cannot hold the evidence the engine is contractually
        required to retain, so its return is a correctness regression, not a
        tuning choice."""
        floor = next(s[3] for s in rp.SERVICES if s[0] == "correlation")
        self.assertEqual(floor, self.QUALIFIED,
                         "correlation's floor changed; it must track the last "
                         "QUALIFIED measurement, not drift back to 768 MiB")
        self.assertGreater(floor, 768 * MIB)

    def test_6_the_generated_env_block_matches_the_planned_limit(self):
        """A plan nobody emits is not an allocation. The rendered
        CORRELATION_MEM_LIMIT must equal what the planner decided."""
        plan = rp.compute_plan(host(64, cpus=16, disk_gib=8000), "medium")
        block = rp.env_block(plan)
        planned = plan["limits_bytes"]["correlation"]
        # Match the EXACT assignment: "CORRELATION_MEM_LIMIT" is a prefix of
        # "CORRELATION_MEM_LIMIT_X", so a substring check happily accepted a
        # renamed variable that compose would never read.
        lines = [ln for ln in block.splitlines()
                 if ln.split("=", 1)[0].strip() == "CORRELATION_MEM_LIMIT"]
        self.assertEqual(len(lines), 1,
                         "exactly one CORRELATION_MEM_LIMIT assignment expected; "
                         f"found {len(lines)} in the emitted block")
        rendered = lines[0].split("=", 1)[1].strip()
        self.assertEqual(rp.parse_size(rendered), planned,
                         f"emitted {rendered} but planned {planned} bytes")
        self.assertGreaterEqual(rp.parse_size(rendered), self.QUALIFIED)

    def test_an_oversubscribed_host_refuses_rather_than_emitting_a_plan(self):
        """Directly exercises the refusal branch. Deleting the raise let the
        planner sail past an oversubscribed host and emit limits whose SUM
        exceeded the budget — a plan that cannot be honoured, issued under the
        same support claim. Being refused is the feature."""
        tiny = host(8, cpus=4, disk_gib=8000)
        with self.assertRaises(rp.SizingError):
            rp.compute_plan(tiny, "medium")
        with self.assertRaises(rp.SizingError):
            rp.compute_plan(host(16, cpus=8, disk_gib=8000), "large")

    def test_floors_alone_over_budget_refuse_via_the_floors_path(self):
        """Distinguishes the FIRST refusal (floors alone exceed the budget)
        from the second one (elastic trimmed too hard).

        `custom` with an empty workload has no workload terms, so desires ==
        floors and there is no elastic portion to trim. On a host too small for
        the floors, the elastic-trim honesty check therefore cannot fire and
        the floors check is the only thing standing between the operator and a
        plan that cannot be honoured. Removing it survived every other test
        here precisely because the second path masked it on realistic hosts.
        """
        with self.assertRaises(rp.SizingError) as ctx:
            rp.compute_plan(host(8, cpus=4, disk_gib=8000), "custom", workload={})
        msg = str(ctx.exception)
        self.assertIn("minimum memory", msg,
                      "the refusal must state the required minimum, not just decline")
        # and the required minimum must account for the QUALIFIED correlation
        # floor rather than the retired 768 MiB
        floors = sum(s[3] * rp.DOUBLE_COUNTED.get(s[0], 1) for s in rp.SERVICES
                     if s[5] is None)
        self.assertGreaterEqual(floors, self.QUALIFIED)

    def test_every_accepted_STRICT_plan_fits_its_own_budget(self):
        """Whatever a strict profile accepts must sum to within the budget it
        computed, on every host.

        `demo` is deliberately excluded: it is the relaxed evaluation profile
        and oversubscribes on purpose (mem_limit is a cap, not a reservation —
        the 8 GB eval floor only works that way). It did so before this change
        too, so asserting the invariant there would be testing a decision the
        planner makes knowingly, not a regression."""
        self.assertTrue(rp.PROFILES["demo"].get("relaxed"),
                        "demo stopped being the relaxed profile; revisit this test")
        checked = 0
        for gib in (8, 16, 24, 32, 48, 64, 128):
            for profile in ("small", "medium", "large"):
                self.assertFalse(rp.PROFILES[profile].get("relaxed"), profile)
                try:
                    plan = rp.compute_plan(host(gib, cpus=16, disk_gib=8000), profile)
                except rp.SizingError:
                    continue
                self.assertLessEqual(plan["totals"]["limits_bytes"],
                                     plan["totals"]["budget_bytes"],
                                     f"{profile}@{gib}GiB emitted a plan over budget")
                checked += 1
        self.assertGreater(checked, 5, "too few accepted plans to be meaningful")

    def test_the_relaxed_profile_oversubscribes_LOUDLY(self):
        """It is allowed to oversubscribe; it is not allowed to do so quietly."""
        plan = rp.compute_plan(host(8, cpus=4, disk_gib=8000), "demo")
        self.assertTrue(plan["warnings"], "relaxed oversubscription emitted no warning")
        self.assertTrue(
            any("oversubscribe" in w or "NOT production sizing" in w
                for w in plan["warnings"]),
            f"the warning must name the condition: {plan['warnings']}")

    def test_the_correlation_mirrors_agree(self):
        """The qualified figure lives in three places that cannot import each
        other: the planner floor (source of truth), the compose fallback, and
        correlation's series-budget fallback. 768 MiB survived in exactly those
        three spots by drifting independently, so they are pinned together
        here — the one place that can see all three."""
        import pathlib
        import re
        root = pathlib.Path(__file__).resolve().parents[2]
        floor = next(s[3] for s in rp.SERVICES if s[0] == "correlation")

        compose = (root / "deployment/docker/docker-compose.yml").read_text(encoding="utf-8")
        m = re.search(r"mem_limit:\s*\$\{CORRELATION_MEM_LIMIT:-(\d+)m\}", compose)
        self.assertIsNotNone(m, "compose default for CORRELATION_MEM_LIMIT not found")
        self.assertEqual(int(m.group(1)) * MIB, floor,
                         "compose fallback drifted from the planner floor")

        budget = (root / "src/correlation/series_budget.py").read_text(encoding="utf-8")
        m2 = re.search(r"DEFAULT_MEM_BUDGET_BYTES\s*=\s*(\d+)\s*\*\s*MIB", budget)
        self.assertIsNotNone(m2, "series-budget fallback not found")
        self.assertEqual(int(m2.group(1)) * MIB, floor,
                         "series-budget fallback drifted from the planner floor")

    def test_no_second_independent_correlation_memory_constant(self):
        """The qualified figure must have exactly one home. A duplicate that
        drifts is how 768 MiB survived in three places to begin with."""
        floors = [s[3] for s in rp.SERVICES if s[0] == "correlation"]
        self.assertEqual(len(floors), 1, "correlation appears twice in SERVICES")


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
