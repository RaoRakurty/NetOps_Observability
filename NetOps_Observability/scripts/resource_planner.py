#!/usr/bin/env python3
"""Correlix resource planner — the canonical sizing calculator (#102).

Design: docs/design/resource-sizing-design.md (approved v2, 2026-07-11).
Stdlib-only by repository convention. Both installers call this module; no
other code may contain sizing math.

Model:  host capacity → OS/platform reserve → Correlix allocatable budget
        → named profile + workload inputs → per-component container limits
        → application-internal limits derived from EACH COMPONENT'S limit
        (never from host RAM).

Invariants (tested):
  * sum(reservations) <= allocatable; sum(limits) <= allocatable * overcommit
  * every internal limit sits below its component's container limit
  * component floors are never silently reduced — the planner REFUSES instead
  * identical inputs produce byte-identical output (no clocks, sorted keys)

Every scaling coefficient lives in COEFFICIENTS with an evidence class from
the spec taxonomy. `conservative-provisional` values are estimates awaiting
benchmark calibration (design §10) — generated plans say so explicitly.
"""

import argparse
import json
import math
import os
import re
import sys

MIB = 1 << 20
GIB = 1 << 30

BLOCK_BEGIN = "# >>> correlix-resource-plan >>>"
BLOCK_END = "# <<< correlix-resource-plan <<<"

# --------------------------------------------------------------------------
# Units.  Internal math is bytes; accepted forms: 512m/5g/1024k (docker),
# 4GiB/512MiB/2GB, plain bytes.  Decimal GB/MB are parsed as decimal and
# normalized to binary in reports (spec §8 unit discipline).
# --------------------------------------------------------------------------

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]i?b?|b)?\s*$", re.IGNORECASE)
_MULT = {
    "b": 1,
    "k": 1 << 10, "kb": 10 ** 3, "kib": 1 << 10,
    "m": 1 << 20, "mb": 10 ** 6, "mib": 1 << 20,
    "g": 1 << 30, "gb": 10 ** 9, "gib": 1 << 30,
    "t": 1 << 40, "tb": 10 ** 12, "tib": 1 << 40,
}


def parse_size(value):
    """'5g' | '512MiB' | '2GB' | 1024 -> bytes (int). Raises ValueError."""
    if isinstance(value, (int, float)):
        if value < 0 or math.isnan(value) or value in (float("inf"),):
            raise ValueError(f"negative or non-finite size: {value!r}")
        return int(value)
    m = _SIZE_RE.match(str(value))
    if not m:
        raise ValueError(f"malformed size: {value!r}")
    num = float(m.group(1))
    unit = (m.group(2) or "b").lower()
    if unit not in _MULT:
        raise ValueError(f"unknown unit in size: {value!r}")
    out = int(num * _MULT[unit])
    if out < 0 or out > (1 << 62):
        raise ValueError(f"size out of range: {value!r}")
    return out


def fmt_bytes(n):
    """Bytes -> compose-compatible string, binary units, deterministic."""
    if n % GIB == 0:
        return f"{n // GIB}g"
    return f"{max(1, round(n / MIB))}m"


def fmt_human(n):
    if n >= GIB:
        return f"{n / GIB:.1f} GiB"
    return f"{round(n / MIB)} MiB"


# --------------------------------------------------------------------------
# Coefficients — the ONE tunable table.  Evidence classes per design §4.2:
# vendor-required | vendor-recommended | repository-existing |
# benchmark-derived | telemetry-derived | conservative-provisional |
# unknown-measurement-required
# --------------------------------------------------------------------------

COEFFICIENTS = {
    # reserves / policy
    "os_reserve_percent":        {"v": 15,   "cls": "conservative-provisional", "src": "design §2; GitLab omnibus reserves analogue"},
    "os_reserve_floor_bytes":    {"v": 2 * GIB, "cls": "conservative-provisional", "src": "design §2"},
    "safety_reserve_percent":    {"v": 5,    "cls": "conservative-provisional", "src": "design §2"},
    "mem_overcommit_factor":     {"v": 1.15, "cls": "conservative-provisional", "src": "design §4.3 explicit policy knob"},
    "cpu_overcommit_factor":     {"v": 1.5,  "cls": "conservative-provisional", "src": "design §4.3; CPU is compressible"},
    "elastic_trim_floor":        {"v": 0.70, "cls": "conservative-provisional", "src": "design §4 refusal threshold"},
    "disk_reserve_percent":      {"v": 20,   "cls": "conservative-provisional", "src": "design §4.4"},
    # internal-limit ratios (of the COMPONENT limit)
    "opensearch_heap_ratio":     {"v": 0.50, "cls": "vendor-recommended", "src": "OpenSearch 2.x docs: heap 50%, <=31g"},
    "opensearch_heap_cap":       {"v": 31 * GIB, "cls": "vendor-recommended", "src": "compressed-oops ceiling"},
    "kafka_heap_ratio":          {"v": 0.50, "cls": "vendor-recommended", "src": "Kafka ops guidance: small heap, page cache rules"},
    "kafka_heap_cap":            {"v": 6 * GIB, "cls": "vendor-recommended", "src": "Confluent deployment docs"},
    "valkey_maxmemory_ratio":    {"v": 0.75, "cls": "vendor-recommended", "src": "Redis Enterprise 75/25 provisioning rule"},
    "gomemlimit_ratio":          {"v": 0.90, "cls": "vendor-recommended", "src": "Go runtime guidance / automemlimit convention"},
    "victoria_allowed_percent":  {"v": 60,   "cls": "vendor-recommended", "src": "VictoriaMetrics default -memory.allowedPercent"},
    "ch_server_ram_ratio":       {"v": 0.9,  "cls": "vendor-recommended", "src": "ClickHouse max_server_memory_usage_to_ram_ratio default, asserted per design §5"},
    "ch_hot_ui_ratio":           {"v": 0.06, "cls": "repository-existing", "src": "workload-profiles.xml 1g at 16g lab ≈ 6% of CH budget region; floor = today's 1g"},
    "ch_background_ratio":       {"v": 0.25, "cls": "repository-existing", "src": "query-spill.xml 2g cap ≈ half of 4g lab limit scaled conservatively; floor = today's 2g"},
    "ch_spill_ratio":            {"v": 0.20, "cls": "repository-existing", "src": "query-spill.xml 1.5g external group_by/sort; floor = today's 1.5g"},
    "pg_shared_buffers_ratio":   {"v": 0.25, "cls": "vendor-recommended", "src": "PostgreSQL wiki / pgtune"},
    "pg_effective_cache_ratio":  {"v": 0.75, "cls": "vendor-recommended", "src": "PostgreSQL wiki / pgtune"},
    "pg_maintenance_ratio":      {"v": 1 / 16, "cls": "vendor-recommended", "src": "pgtune"},
    # workload terms (bytes per unit) — ALL provisional until §10 calibration
    "vm_bytes_per_series":       {"v": 2 << 10, "cls": "conservative-provisional", "src": "VM docs ~1KiB/series + query overhead margin"},
    "series_per_device":         {"v": 60,  "cls": "conservative-provisional", "src": "audited device_* metric families"},
    "series_per_interface":      {"v": 25,  "cls": "conservative-provisional", "src": "audited if_* metric families"},
    "ch_mem_per_kflow":          {"v": 512 * MIB, "cls": "conservative-provisional", "src": "ingest+merge allowance per 1k flows/s"},
    "ch_mem_per_keps":           {"v": 256 * MIB, "cls": "conservative-provisional", "src": "per 1k syslog EPS"},
    "ch_mem_per_analytical_query": {"v": 512 * MIB, "cls": "conservative-provisional", "src": "query concurrency allowance"},
    "os_mem_per_keps":           {"v": 1 * GIB, "cls": "conservative-provisional", "src": "indexing pressure per 1k EPS"},
    "os_mem_per_user":           {"v": 128 * MIB, "cls": "conservative-provisional", "src": "search concurrency allowance"},
    "kafka_mem_per_5kflow":      {"v": 512 * MIB, "cls": "conservative-provisional", "src": "broker buffering / page-cache room"},
    "api_mem_per_100_devices":   {"v": 64 * MIB, "cls": "conservative-provisional", "src": "collector/session state"},
    "api_mem_per_10_users":      {"v": 64 * MIB, "cls": "conservative-provisional", "src": "concurrent UI/API sessions"},
    "corr_mem_per_keps":         {"v": 128 * MIB, "cls": "conservative-provisional", "src": "window growth per 1k EPS"},
    "corr_window_per_keps":      {"v": 25000, "cls": "conservative-provisional", "src": "signals per 1k EPS in 15m window"},
    "vector_mem_per_10keps":     {"v": 128 * MIB, "cls": "conservative-provisional", "src": "steady-state + outage allowance (B10 pending)"},
    "goflow2_mem_per_10kflow":   {"v": 256 * MIB, "cls": "conservative-provisional", "src": "decoder buffers"},
    "pg_mem_per_10_users":       {"v": 128 * MIB, "cls": "conservative-provisional", "src": "session/report state"},
    "prober_mem_per_kppm":       {"v": 32 * MIB, "cls": "conservative-provisional", "src": "per 1k probe tests/min"},
    # storage terms — provisional until lab-measured (§10)
    "flow_record_bytes":         {"v": 120, "cls": "conservative-provisional", "src": "typical enriched flow row pre-compression"},
    "log_event_bytes":           {"v": 250, "cls": "conservative-provisional", "src": "typical syslog event + index overhead"},
    "ch_compression_ratio":      {"v": 0.20, "cls": "unknown-measurement-required", "src": "measure real CH bytes/row (§10)"},
    "os_index_overhead":         {"v": 1.2, "cls": "conservative-provisional", "src": "index+doc-values expansion pre-compression"},
    "os_compression_ratio":      {"v": 0.30, "cls": "unknown-measurement-required", "src": "measure real OS index bytes (§10)"},
    "vm_disk_bytes_per_sample":  {"v": 1.0, "cls": "vendor-recommended", "src": "VM docs <1 byte/sample typical; rounded up"},
}


def C(name):
    return COEFFICIENTS[name]["v"]


# --------------------------------------------------------------------------
# Service model.  floor = today's audited lab defaults (operational minimums
# per design §1; class repository-existing).  env names match compose.
# --------------------------------------------------------------------------

SERVICES = [
    # name, mem env, cpu env, floor mem, floor cpu, profile gate, scalable
    ("postgres",     "POSTGRES_MEM_LIMIT",    "POSTGRES_CPU_LIMIT",    1 * GIB,   2.0, None,              True),
    ("redis",        "REDIS_MEM_LIMIT",       None,                    128 * MIB, 0.5, None,              False),
    ("kafka",        "KAFKA_MEM_LIMIT",       "KAFKA_CPU_LIMIT",       1 * GIB,   2.0, "embedded-bus",    True),
    ("syslog-ng",    "SYSLOGNG_MEM_LIMIT",    "SYSLOGNG_CPU_LIMIT",    256 * MIB, 1.0, None,              True),
    ("gnmic",        "GNMIC_MEM_LIMIT",       "GNMIC_CPU_LIMIT",       512 * MIB, 1.0, None,              True),
    ("goflow2",      "GOFLOW2_MEM_LIMIT",     "GOFLOW2_CPU_LIMIT",     512 * MIB, 1.0, None,              True),
    ("vector",       "VECTOR_MEM_LIMIT",      "VECTOR_CPU_LIMIT",      512 * MIB, 2.0, None,              True),  # applies to both vector services
    ("opensearch",   "OS_MEM_LIMIT",          "OS_CPU_LIMIT",          3 * GIB,   3.0, None,              True),
    ("osd",          "OSD_MEM_LIMIT",         "OSD_CPU_LIMIT",         768 * MIB, 2.0, "osd",             False),
    ("victoria",     "VICTORIA_MEM_LIMIT",    "VICTORIA_CPU_LIMIT",    1536 * MIB, 2.0, None,             True),
    ("cadvisor",     "CADVISOR_MEM_LIMIT",    "CADVISOR_CPU_LIMIT",    256 * MIB, 1.0, "self-monitoring", False),
    ("node-exporter", "NODE_EXPORTER_MEM_LIMIT", "NODE_EXPORTER_CPU_LIMIT", 128 * MIB, 0.5, "self-monitoring", False),
    ("grafana",      "GRAFANA_MEM_LIMIT",     "GRAFANA_CPU_LIMIT",     512 * MIB, 1.5, "self-monitoring", False),
    ("clickhouse",   "CLICKHOUSE_MEM_LIMIT",  "CLICKHOUSE_CPU_LIMIT",  4 * GIB,   3.0, None,              True),
    ("correlation",  "CORRELATION_MEM_LIMIT", "CORRELATION_CPU_LIMIT", 768 * MIB, 2.0, None,              True),
    ("api",          "API_MEM_LIMIT",         "API_CPU_LIMIT",         512 * MIB, 2.0, None,              True),
    ("prober",       "PROBER_MEM_LIMIT",      None,                    128 * MIB, 0.5, "prober",          True),
    ("frontend",     "FRONTEND_MEM_LIMIT",    None,                    128 * MIB, 0.5, None,              False),
    ("nginx",        "NGINX_MEM_LIMIT",       None,                    128 * MIB, 0.5, None,              False),
]

# vector runs twice (aggregator + router) but shares one env var pair — its
# budget line is counted twice in aggregates.
DOUBLE_COUNTED = {"vector": 2}

# Per-component share caps of the allocatable budget (anti-starvation).
COMPONENT_MAX_SHARE = {
    "clickhouse": 0.40, "opensearch": 0.30, "victoria": 0.20,
    "kafka": 0.15, "postgres": 0.10, "api": 0.10, "correlation": 0.10,
}

# Legacy / emergency-override variable names recognized in .env outside the
# managed block (design §7).
LEGACY_VARS = sorted(
    {s[1] for s in SERVICES if s[1]} | {s[2] for s in SERVICES if s[2]} |
    {"OPENSEARCH_HEAP", "KAFKA_HEAP", "REDIS_MAXMEMORY",
     "VICTORIA_MEM_ALLOWED_PERCENT", "PG_SHARED_BUFFERS", "PG_WORK_MEM",
     "PG_EFFECTIVE_CACHE_SIZE", "PG_MAINTENANCE_WORK_MEM", "PG_MAX_CONNECTIONS",
     "API_GOMEMLIMIT", "PROBER_GOMEMLIMIT", "GOFLOW2_GOMEMLIMIT",
     "CH_MEM_RATIO", "CH_HOT_UI_MEM", "CH_BG_MEM", "CH_SPILL_BYTES",
     "CH_MAX_CONCURRENT_QUERIES", "CORR_WINDOW_BUFFER", "REPORT_WORKERS",
     "BUS_PARTITIONS"}
)


# --------------------------------------------------------------------------
# Bus partitions (GA scale programme, tracker 152/153).
#
# BUS_PARTITIONS is applied by kafka-init to EVERY bus topic it creates, so it
# is a MULTIPLIER on broker cost, not a single count — and correlation
# subscribes to fewer topics than kafka-init creates, so the two numbers are
# not interchangeable.  Both are facts about other files; they are cross-checked
# by scripts/tests/test_resource_planner.py::test_bus_topic_counts_match_sources
# so a change to kafka-init or to the correlation subscription list fails a test
# rather than making this plan quietly lie to an operator.
BUS_TOPICS_CREATED = 17     # deployment/docker/docker-compose.yml, kafka-init
BUS_TOPICS_CONSUMED = 12    # src/correlation/main.py TOPICS
# Today's compose default (${BUS_PARTITIONS:-1}).  DELIBERATELY UNCHANGED: the
# installer approval gate has not been passed, so this generation makes the
# setting visible and protected, it does not resize anyone's broker.
BUS_PARTITIONS_DEFAULT = 1


# --------------------------------------------------------------------------
# Profiles — defaults, not the only mechanism (spec 7.1).  Workload keys
# mirror the sizing-file schema; None = not specified.
# --------------------------------------------------------------------------

PROFILES = {
    "demo": {
        # mirrors today's shipped evaluation behavior: caps may oversubscribe
        # the host (mem_limit is a cap, not a reservation) — the 8 GB eval
        # floor in make-installer README only works this way. Explicitly
        # relaxed; every other profile enforces the budget strictly.
        "relaxed": True,
        "os_reserve_percent": 10, "safety_reserve_percent": 0,
        "mem_overcommit_factor": 1.35,
        "workload": {"devices": 50, "interfaces": 1500, "flows_per_second": 1000,
                     "syslog_events_per_second": 200, "probe_tests_per_minute": 500,
                     "concurrent_users": 5, "concurrent_analytical_queries": 2,
                     "tenants": 3, "retention_flows_days": 14,
                     "retention_logs_days": 14, "retention_metrics_days": 30},
    },
    "small": {
        "workload": {"devices": 200, "interfaces": 8000, "flows_per_second": 5000,
                     "syslog_events_per_second": 2000, "probe_tests_per_minute": 2000,
                     "concurrent_users": 10, "concurrent_analytical_queries": 4,
                     "tenants": 5, "retention_flows_days": 30,
                     "retention_logs_days": 14, "retention_metrics_days": 30},
    },
    "medium": {
        "workload": {"devices": 1000, "interfaces": 40000, "flows_per_second": 20000,
                     "syslog_events_per_second": 5000, "probe_tests_per_minute": 10000,
                     "concurrent_users": 25, "concurrent_analytical_queries": 8,
                     "tenants": 10, "retention_flows_days": 30,
                     "retention_logs_days": 14, "retention_metrics_days": 30},
    },
    "large": {
        "workload": {"devices": 5000, "interfaces": 200000, "flows_per_second": 60000,
                     "syslog_events_per_second": 15000, "probe_tests_per_minute": 30000,
                     "concurrent_users": 50, "concurrent_analytical_queries": 16,
                     "tenants": 25, "retention_flows_days": 30,
                     "retention_logs_days": 14, "retention_metrics_days": 30},
    },
    "custom": {"workload": {}},
}


# --------------------------------------------------------------------------
# Host detection (validation-time overridable for tests / remote planning)
# --------------------------------------------------------------------------

CGROUP_MEM_PATHS = ("/sys/fs/cgroup/memory.max",                    # cgroup v2
                    "/sys/fs/cgroup/memory/memory.limit_in_bytes")  # cgroup v1


# Auto-profile thresholds (GiB of host RAM → named profile). SINGLE source of
# truth shared by install.py's --plan-resources auto selection and the GUI
# facts endpoint (`--detect-json`); duplicate these nowhere.
AUTO_PROFILE_GIB = ((24, "demo"), (48, "small"), (96, "medium"))


def suggest_profile(mem_bytes):
    """The profile an auto-sizing install picks for a host with this much RAM:
    <24 GiB demo, <48 small, <96 medium, else large."""
    gib = mem_bytes / GIB
    for cap, name in AUTO_PROFILE_GIB:
        if gib < cap:
            return name
    return "large"


def detect_host(mem_override=None, cpu_override=None, disk_override=None,
                data_path=".", cgroup_paths=CGROUP_MEM_PATHS):
    mem = parse_size(mem_override) if mem_override else None
    if mem is None:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem = int(line.split()[1]) * 1024
                    break
    # cgroup-limited environments (spec test 22): honor a finite cgroup cap
    # below MemTotal (cgroup v2 then v1).
    for p in cgroup_paths:
        try:
            with open(p) as fh:
                raw = fh.read().strip()
            if raw not in ("max", "") and int(raw) > 0:
                mem = min(mem, int(raw)) if not mem_override else mem
        except (OSError, ValueError):
            pass
    cpus = float(cpu_override) if cpu_override else float(os.cpu_count() or 1)
    if disk_override:
        disk_free = parse_size(disk_override)
    else:
        import shutil
        disk_free = shutil.disk_usage(data_path).free
    if mem is None or mem <= 0 or cpus <= 0:
        raise ValueError("could not determine host capacity")
    return {"memory_bytes": int(mem), "cpus": cpus, "disk_free_bytes": int(disk_free)}


# --------------------------------------------------------------------------
# Minimal strict YAML-subset / JSON sizing-file parser (stdlib-only).
# Supports: nested mappings by 2-space indentation, "key: value" scalars,
# comments, null/true/false/numbers/strings, sizes handled downstream.
# --------------------------------------------------------------------------

def _scalar(tok):
    t = tok.strip().strip('"').strip("'")
    low = t.lower()
    if low in ("null", "~", "none", ""):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "auto":
        return "auto"
    try:
        return int(t)
    except ValueError:
        try:
            return float(t)
        except ValueError:
            return t


def parse_sizing_file(text):
    text = text.strip()
    if text.startswith("{"):
        return json.loads(text)
    root, stack = {}, [(-1, {})]
    stack[0] = (-1, root)
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if raw.lstrip().startswith("- "):
            raise ValueError(f"lists are not supported in the sizing file: {raw!r}")
        if ":" not in raw:
            raise ValueError(f"malformed line in sizing file: {raw!r}")
        key, _, rest = raw.strip().partition(":")
        key = key.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if rest.strip() == "":
            child = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _scalar(rest)
    return root


def normalize_workload(doc):
    """Flatten the nested sizing-file schema into planner keys; validate."""
    w = {}
    src = doc.get("workload", doc) or {}
    flat_map = {
        "devices": ("devices",), "interfaces": ("interfaces",),
        "tenants": ("tenants",),
        "flows_per_second": ("flows", "records_per_second"),
        "avg_flow_bytes": ("flows", "average_record_bytes"),
        "retention_flows_days": ("flows", "retention_days"),
        "syslog_events_per_second": ("logs", "events_per_second"),
        "avg_event_bytes": ("logs", "average_event_bytes"),
        "retention_logs_days": ("logs", "retention_days"),
        "metrics_samples_per_second": ("metrics", "samples_per_second"),
        "active_series": ("metrics", "active_series"),
        "retention_metrics_days": ("metrics", "retention_days"),
        "probe_tests_per_minute": ("probes", "executions_per_minute"),
        "concurrent_users": ("users", "concurrent_users"),
        "concurrent_analytical_queries": ("users", "concurrent_analytical_queries"),
        "report_concurrency": ("report_concurrency",),
        "scheduled_job_concurrency": ("scheduled_job_concurrency",),
    }
    for out_key, path in flat_map.items():
        cur = src
        ok = True
        for p in path:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                ok = False
                break
        if ok and cur is not None:
            if not isinstance(cur, (int, float)) or isinstance(cur, bool):
                raise ValueError(f"workload value {out_key} must be numeric, got {cur!r}")
            if cur < 0:
                raise ValueError(f"workload value {out_key} is negative: {cur!r}")
            if cur > 10 ** 12:
                raise ValueError(f"workload value {out_key} is implausibly large: {cur!r}")
            w[out_key] = cur
    # top-level convenience keys (flat files/tests)
    for k in list(flat_map):
        if k in src and src[k] is not None and k not in w:
            v = src[k]
            if not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0 or v > 10 ** 12:
                raise ValueError(f"workload value {k} invalid: {v!r}")
            w[k] = v
    dep = doc.get("deployment", {}) or {}
    w["high_availability"] = bool(dep.get("high_availability", False))
    w["replication_factor"] = int(dep.get("replication_factor", 1) or 1)
    return w


# --------------------------------------------------------------------------
# Workload terms per scalable component (design §4.2 driver map)
# --------------------------------------------------------------------------

def _series_estimate(w):
    if w.get("active_series"):
        return w["active_series"]
    return (w.get("devices", 0) * C("series_per_device")
            + w.get("interfaces", 0) * C("series_per_interface"))


def workload_terms(w):
    kflows = w.get("flows_per_second", 0) / 1000.0
    keps = w.get("syslog_events_per_second", 0) / 1000.0
    users = w.get("concurrent_users", 0)
    aq = w.get("concurrent_analytical_queries", 0)
    series = _series_estimate(w)
    return {
        "clickhouse": int(kflows * C("ch_mem_per_kflow") + keps * C("ch_mem_per_keps")
                          + aq * C("ch_mem_per_analytical_query")),
        "opensearch": int(keps * C("os_mem_per_keps") + users * C("os_mem_per_user")),
        "victoria": int(series * C("vm_bytes_per_series")),
        "kafka": int((kflows / 5.0) * C("kafka_mem_per_5kflow")),
        "postgres": int((users / 10.0) * C("pg_mem_per_10_users")
                        + w.get("tenants", 0) * 8 * MIB),
        "api": int((w.get("devices", 0) / 100.0) * C("api_mem_per_100_devices")
                   + (users / 10.0) * C("api_mem_per_10_users")),
        "correlation": int(keps * C("corr_mem_per_keps")),
        "vector": int((keps + kflows) / 10.0 * C("vector_mem_per_10keps")),
        "goflow2": int((kflows / 10.0) * C("goflow2_mem_per_10kflow")),
        "syslog-ng": int(keps * 32 * MIB),
        "gnmic": int((w.get("devices", 0) / 100.0) * 32 * MIB),
        "prober": int((w.get("probe_tests_per_minute", 0) / 1000.0) * C("prober_mem_per_kppm")),
    }


def storage_estimate(w):
    """Persistent-store bytes by retention (design §4.4). Returns dict."""
    flows = w.get("flows_per_second", 0)
    eps = w.get("syslog_events_per_second", 0)
    series = _series_estimate(w)
    samples_ps = w.get("metrics_samples_per_second") or series / 30.0  # 30s cadence
    fb = w.get("avg_flow_bytes") or C("flow_record_bytes")
    eb = w.get("avg_event_bytes") or C("log_event_bytes")
    day = 86400
    ch = int(flows * fb * day * w.get("retention_flows_days", 30) * C("ch_compression_ratio")
             + eps * eb * day * min(7, w.get("retention_logs_days", 14)) * C("ch_compression_ratio"))
    osb = int(eps * eb * C("os_index_overhead") * day * w.get("retention_logs_days", 14)
              * C("os_compression_ratio") * max(1, w.get("replication_factor", 1)))
    vm = int(samples_ps * day * w.get("retention_metrics_days", 30) * C("vm_disk_bytes_per_sample"))
    return {"clickhouse": ch, "opensearch": osb, "victoria": vm,
            "total": ch + osb + vm}


# --------------------------------------------------------------------------
# Internal-limit derivations — every value from the COMPONENT limit
# --------------------------------------------------------------------------

def derive_internal(limits, w):
    env = {}
    ch = limits.get("clickhouse")
    if ch:
        env["CH_MEM_RATIO"] = "{:.2f}".format(C("ch_server_ram_ratio"))
        env["CH_HOT_UI_MEM"] = str(max(1 * GIB, int(ch * C("ch_hot_ui_ratio"))))
        env["CH_BG_MEM"] = str(max(2 * GIB if ch >= 4 * GIB else int(ch * 0.5),
                                   int(ch * C("ch_background_ratio"))))
        env["CH_SPILL_BYTES"] = str(max(int(1.5 * GIB) if ch >= 4 * GIB else int(ch * 0.375),
                                        int(ch * C("ch_spill_ratio"))))
        env["CH_MAX_CONCURRENT_QUERIES"] = str(int(max(
            50, 30 + 10 * w.get("concurrent_analytical_queries", 0))))
    osm = limits.get("opensearch")
    if osm:
        heap = min(int(osm * C("opensearch_heap_ratio")), C("opensearch_heap_cap"))
        env["OPENSEARCH_HEAP"] = fmt_bytes(heap)
    k = limits.get("kafka")
    if k:
        env["KAFKA_HEAP"] = fmt_bytes(min(int(k * C("kafka_heap_ratio")), C("kafka_heap_cap")))
    r = limits.get("redis")
    if r:
        # Valkey/Redis units: "mb" is binary (1024^2), bare "m" is DECIMAL —
        # docker-style fmt_bytes would silently shrink the value ~4.8%.
        env["REDIS_MAXMEMORY"] = f"{int(r * C('valkey_maxmemory_ratio')) // MIB}mb"
    v = limits.get("victoria")
    if v:
        env["VICTORIA_MEM_ALLOWED_PERCENT"] = str(int(C("victoria_allowed_percent")))
    pg = limits.get("postgres")
    if pg:
        sb = int(pg * C("pg_shared_buffers_ratio"))
        conns = 50  # api pool 25 [repository-existing] + correlation + reserve
        wm = max(4 * MIB, min(64 * MIB, (pg - sb) // (3 * conns)))
        env["PG_SHARED_BUFFERS"] = f"{sb // MIB}MB"
        env["PG_EFFECTIVE_CACHE_SIZE"] = f"{int(pg * C('pg_effective_cache_ratio')) // MIB}MB"
        env["PG_WORK_MEM"] = f"{max(4, wm // MIB)}MB"
        env["PG_MAINTENANCE_WORK_MEM"] = f"{max(64, int(pg * C('pg_maintenance_ratio')) // MIB)}MB"
        env["PG_MAX_CONNECTIONS"] = str(conns * 2)  # server headroom over pools
    for svc, var in (("api", "API_GOMEMLIMIT"), ("prober", "PROBER_GOMEMLIMIT"),
                     ("goflow2", "GOFLOW2_GOMEMLIMIT")):
        if limits.get(svc):
            env[var] = f"{int(limits[svc] * C('gomemlimit_ratio')) // MIB}MiB"
    corr = limits.get("correlation")
    if corr:
        keps = w.get("syslog_events_per_second", 0) / 1000.0
        env["CORR_WINDOW_BUFFER"] = str(int(max(50000, keps * C("corr_window_per_keps"))))
    if w.get("report_concurrency"):
        env["REPORT_WORKERS"] = str(int(max(2, min(16, w["report_concurrency"]))))
    return env


def derive_bus_partitions(w, legacy, overrides, warnings):
    """Resolve BUS_PARTITIONS and the facts an operator needs to reason about it.

    Automatic EPS-based sizing is deliberately NOT implemented here.  The only
    correlation throughput figure we have (~850-1,050 evt/s) was measured while
    the P1 correlation-thrash defect was still active, which makes it a lower
    bound on a degraded system, not a production sizing constant.  Until the
    scale checkpoints qualify a real number, this function only makes the
    EXISTING setting first-class — visible in the plan, overridable through the
    normal convention, and protected against a silent decrease.  The default is
    unchanged, so generating a plan never resizes a running broker.

    Returns (value, facts).  Appends operator-facing text to `warnings`.
    """
    facts = {
        "topics_created": BUS_TOPICS_CREATED,
        "topics_consumed": BUS_TOPICS_CONSUMED,
        "source": "default",
        "auto_sizing": False,
    }

    # --- existing install: what the .env already claims ---------------------
    existing = None
    raw = legacy.get("BUS_PARTITIONS")
    if raw is not None:
        try:
            existing = int(str(raw).strip())
        except ValueError:
            existing = None
        if existing is None or existing < 1:
            warnings.append(
                f"BUS_PARTITIONS={raw!r} in .env is not a positive integer; "
                "ignored and treated as unset. Check the live topics with "
                "'kafka-topics.sh --describe' before replanning.")
            existing = None

    value = BUS_PARTITIONS_DEFAULT
    if existing is not None:
        value = existing
        facts["source"] = "existing-install"

    # --- explicit override, subject to the raise-only invariant -------------
    ov = overrides.get("bus_partitions")
    if ov is not None:
        try:
            requested = int(ov)
        except (TypeError, ValueError):
            raise SizingError(
                f"override bus_partitions={ov!r} must be a positive integer")
        if requested < 1:
            raise SizingError(
                f"override bus_partitions={requested} must be >= 1")
        if existing is not None and requested < existing:
            # Raise-only: kafka-init only ALTERs topics upward, so writing a
            # lower number would make the generated plan disagree with the live
            # broker — the exact silent divergence this guard exists to prevent.
            warnings.append(
                f"bus_partitions override {requested} is BELOW the existing "
                f"{existing} and was NOT applied. Kafka partitions cannot be "
                "reduced: kafka-init only alters topics upward, so a lower "
                "value would make this plan disagree with the live broker. "
                f"BUS_PARTITIONS stays {existing}. To genuinely shrink the bus "
                "you must rebuild the topics, which is a destructive migration "
                "and is not supported by the installer.")
        else:
            value = requested
            facts["source"] = "override"
            if existing is not None and requested != existing:
                # The out-of-block pin would otherwise sit alongside the managed
                # value as a duplicate .env key, and duplicate keys resolve by
                # file order — a coin toss the operator cannot see.
                warnings.append(
                    f"bus_partitions override {requested} supersedes the "
                    f"BUS_PARTITIONS={existing} pinned in .env OUTSIDE the "
                    "managed block. Remove that line so the file defines the "
                    "setting once, then re-run kafka-init to alter the topics "
                    "up. Until it is removed the pin may win over the plan.")

    facts["value"] = value
    facts["existing"] = existing
    facts["broker_partitions"] = value * BUS_TOPICS_CREATED
    # A consumer group cannot have more ACTIVE members than partitions, and
    # correlation co-partitions across every topic it subscribes to, so the
    # ceiling is the partition count itself.
    facts["max_useful_replicas"] = value

    # --- replica / partition mismatch --------------------------------------
    replicas = w.get("correlation_replicas")
    facts["replicas"] = replicas
    if replicas:
        try:
            replicas = int(replicas)
        except (TypeError, ValueError):
            warnings.append(
                f"correlation_replicas={replicas!r} is not an integer; ignored")
            replicas = None
    if replicas and replicas > value:
        facts["idle_replicas"] = replicas - value
        warnings.append(
            f"correlation_replicas={replicas} exceeds BUS_PARTITIONS={value}: "
            f"{replicas - value} replica(s) will join the consumer group, be "
            f"assigned no partitions and process no events. Either scale "
            f"correlation down to {value}, or raise BUS_PARTITIONS (raise-only, "
            f"and an increase needs a controlled drain — see "
            f"docs/scale-correlation.md).")
    else:
        facts["idle_replicas"] = 0

    return value, facts


# --------------------------------------------------------------------------
# The plan
# --------------------------------------------------------------------------

class SizingError(Exception):
    pass


def compute_plan(host, profile_name, workload=None, overrides=None,
                 legacy=None, enabled_profiles=None):
    if profile_name not in PROFILES:
        raise ValueError("unknown profile {!r} (choose from {})".format(profile_name, "/".join(sorted(PROFILES))))
    prof = PROFILES[profile_name]
    w = dict(prof.get("workload", {}))
    w.update({k: v for k, v in (workload or {}).items() if v is not None})
    overrides = overrides or {}
    legacy = legacy or {}
    enabled = enabled_profiles if enabled_profiles is not None else \
        {"embedded-bus", "prober", "osd", "self-monitoring"}

    if w.get("high_availability"):
        raise SizingError(
            "high_availability: true is not supported by this single-node "
            "deployment generation. Deploy per-site instances or wait for the "
            "HA topology (tracked separately).")

    os_res_pct = prof.get("os_reserve_percent", C("os_reserve_percent"))
    safety_pct = prof.get("safety_reserve_percent", C("safety_reserve_percent"))
    overcommit = prof.get("mem_overcommit_factor", C("mem_overcommit_factor"))

    host_mem = host["memory_bytes"]
    os_reserve = max(int(host_mem * os_res_pct / 100.0), C("os_reserve_floor_bytes"))
    safety = int(host_mem * safety_pct / 100.0)
    allocatable = host_mem - os_reserve - safety
    if allocatable <= 0:
        raise SizingError(f"host memory {fmt_human(host_mem)} is below the minimum supported size")

    active = [s for s in SERVICES if s[5] is None or s[5] in enabled]
    terms = workload_terms(w)

    floors, desires = {}, {}
    for name, _mv, _cv, floor, _cf, _gate, scalable in active:
        mult = DOUBLE_COUNTED.get(name, 1)
        floors[name] = floor
        want = floor + (terms.get(name, 0) if scalable else 0)
        cap_share = COMPONENT_MAX_SHARE.get(name)
        if cap_share:
            want = min(want, int(allocatable * cap_share))
        desires[name] = max(floor, want)
        _ = mult

    def total(d):
        return sum(v * DOUBLE_COUNTED.get(k, 1) for k, v in d.items())

    budget = int(allocatable * overcommit)
    relaxed = bool(prof.get("relaxed"))
    warnings = []
    if total(floors) > budget:
        if not relaxed:
            raise SizingError(_refusal_message(host, allocatable, total(floors),
                                               floors, w, storage_estimate(w),
                                               host["disk_free_bytes"]))
        warnings.append(
            f"evaluation profile: service caps ({fmt_human(total(floors))}) oversubscribe the host "
            f"budget ({fmt_human(budget)}) — mem_limit is a cap, not a reservation; this "
            "matches shipped evaluation behavior and is NOT production sizing")

    limits = dict(desires)
    if relaxed and total(floors) > budget:
        # caps already oversubscribe: keep floors, don't stack workload terms
        limits = dict(floors)
    elif total(limits) > budget:
        # trim only the elastic portion, proportionally
        elastic = {k: limits[k] - floors[k] for k in limits if limits[k] > floors[k]}
        need = total(limits) - budget
        etotal = sum(v * DOUBLE_COUNTED.get(k, 1) for k, v in elastic.items())
        for k, ev in elastic.items():
            cut = int(need * (ev * DOUBLE_COUNTED.get(k, 1) / etotal)) // DOUBLE_COUNTED.get(k, 1)
            limits[k] -= min(cut, ev)
        if total(limits) > budget:  # rounding remainder
            for k in sorted(elastic, key=lambda x: limits[x] - floors[x], reverse=True):
                if total(limits) <= budget:
                    break
                limits[k] = max(floors[k], limits[k] - (total(limits) - budget))
        # honesty threshold: refuse if any scalable engine lost too much.
        # Relaxed (evaluation) profiles keep the best-effort trim instead —
        # a proportional partial allocation beats zeroing the workload terms.
        if not relaxed:
            for k in elastic:
                wanted = desires[k] - floors[k]
                got = limits[k] - floors[k]
                if wanted > 0 and got / wanted < C("elastic_trim_floor"):
                    raise SizingError(_refusal_message(
                        host, allocatable, total(desires), desires, w,
                        storage_estimate(w), host["disk_free_bytes"]))
        warnings.append(f"workload-derived allocations were trimmed {fmt_human(total(desires) - total(limits))} to fit the "
                        "budget; consider a larger host for full headroom")

    # apply explicit customer overrides (validated), then legacy pins
    pinned = {}
    for name in list(limits):
        ov = overrides.get(name + "_mem")
        if ov:
            val = parse_size(ov)
            if val < floors[name]:
                raise SizingError(f"override {name}_mem={ov} is below the component "
                                  f"minimum {fmt_human(floors[name])}")
            limits[name] = val
            pinned[name] = "customer-override"
    env_names = {s[0]: s[1] for s in SERVICES}
    for name, envn in env_names.items():
        if envn and envn in legacy and name in limits:
            try:
                limits[name] = parse_size(legacy[envn])
                pinned[name] = "legacy-env-override"
                warnings.append(
                    f"legacy override {envn}={legacy[envn]} pins {name} (generated recommendation "
                    f"was {fmt_human(desires[name])}); remove it from .env to adopt generated sizing")
            except ValueError:
                warnings.append(f"legacy value {envn}={legacy[envn]!r} is malformed; ignored")
    if total(limits) > budget:
        warnings.append(f"overrides push total limits {fmt_human(total(limits))} above the overcommit "
                        f"budget {fmt_human(budget)} — reduced safety headroom")

    # reservations: guaranteed floor per service; must fit allocatable exactly
    reservations = dict(floors)
    if total(reservations) > allocatable:
        warnings.append("sum of reservations exceeds allocatable (profile "
                        f"'{profile_name}' relaxed mode)")

    # CPU
    cpu = {}
    for name, _mv, cv, _f, cfloor, _g, _s in active:
        cpu[name] = cfloor
    cpu_budget = host["cpus"] * C("cpu_overcommit_factor")
    cpu_total = sum(v * DOUBLE_COUNTED.get(k, 1) for k, v in cpu.items())
    if cpu_total > cpu_budget:
        warnings.append("CPU allocations ({:.1f}) exceed cores x {:.1f} ({:.1f}) — "
                        "CPU is compressible but expect contention under load".format(cpu_total, C("cpu_overcommit_factor"), cpu_budget))

    # storage validation (design §4.4)
    store = storage_estimate(w)
    if (w.get("flows_per_second", 0) >= 10000
            or w.get("syslog_events_per_second", 0) >= 5000):
        warnings.append(
            "storage capability undeclared — this ingest rate needs sustained "
            "write throughput; validate SSD/NVMe-class IOPS before production "
            "(class: unknown-measurement-required)")
    disk_avail = int(host["disk_free_bytes"] * (1 - C("disk_reserve_percent") / 100.0))
    if store["total"] > disk_avail:
        if not relaxed:
            raise SizingError(_refusal_message(host, allocatable, total(limits),
                                               limits, w, store,
                                               host["disk_free_bytes"], disk=True))
        # evaluation mode, and on a replan of a RUNNING system the retained
        # data already on disk double-counts against free space — warn only.
        warnings.append(
            "retention estimate {} exceeds free disk {} — evaluation profile "
            "continues; reduce retention or grow the disk before real load".format(fmt_human(store["total"]), fmt_human(host["disk_free_bytes"])))

    internal = derive_internal(limits, w)
    # legacy pins for internal vars too
    for var in list(internal):
        if var in legacy:
            internal[var] = legacy[var]
            warnings.append(f"legacy override {var}={legacy[var]} preserved (generated "
                            "recommendation differed)")

    # BUS_PARTITIONS is resolved AFTER the generic legacy loop on purpose: the
    # raise-only invariant must be authoritative over a blind legacy copy.
    bus_value, bus = derive_bus_partitions(w, legacy, overrides, warnings)
    internal["BUS_PARTITIONS"] = str(bus_value)

    # #102-signoff: pinned/override PG values can silently oversubscribe the
    # postgres container. Generation identity is SB + 3*conns*wm == limit;
    # maintenance is occasional, so 10% slack before flagging.
    pgl = limits.get("postgres")
    if pgl and "PG_SHARED_BUFFERS" in internal:
        try:
            _sb = parse_size(internal["PG_SHARED_BUFFERS"])
            _wm = parse_size(internal["PG_WORK_MEM"])
            _conns = max(1, int(internal.get("PG_MAX_CONNECTIONS", "100")) // 2)
            _maint = parse_size(internal.get("PG_MAINTENANCE_WORK_MEM", "64MB"))
            if _sb + 3 * _conns * _wm + _maint > pgl * 1.10:
                warnings.append(
                    f"postgres internal settings (shared_buffers {fmt_human(_sb)} "
                    f"+ {_conns} ops x work_mem {fmt_human(_wm)} x3 + maintenance "
                    f"{fmt_human(_maint)}) oversubscribe its {fmt_human(pgl)} "
                    "container limit — lower the pinned values or raise "
                    "postgres memory")
        except (ValueError, KeyError):
            pass

    provisional = sorted({k for k, c in COEFFICIENTS.items()
                          if c["cls"] in ("conservative-provisional",
                                          "unknown-measurement-required")})
    plan = {
        "schema": 1,
        "profile": profile_name,
        "host": {"memory": fmt_human(host_mem), "memory_bytes": host_mem,
                 "cpus": host["cpus"], "disk_free": fmt_human(host["disk_free_bytes"])},
        "reserves": {"os": fmt_human(os_reserve), "safety": fmt_human(safety),
                     "allocatable": fmt_human(allocatable),
                     "allocatable_bytes": allocatable,
                     "overcommit_factor": overcommit},
        "workload": {k: w[k] for k in sorted(w)},
        "limits_bytes": {k: limits[k] for k in sorted(limits)},
        "reservations_bytes": {k: reservations[k] for k in sorted(reservations)},
        "cpus": {k: cpu[k] for k in sorted(cpu)},
        "internal": {k: internal[k] for k in sorted(internal)},
        "bus": bus,
        "pinned": {k: pinned[k] for k in sorted(pinned)},
        "storage_estimate": {k: fmt_human(v) for k, v in sorted(store.items())},
        "totals": {"limits": fmt_human(total(limits)),
                   "limits_bytes": total(limits),
                   "reservations": fmt_human(total(reservations)),
                   "budget": fmt_human(budget), "budget_bytes": budget},
        "warnings": warnings,
        "notice": ("Plan contains conservative-provisional coefficients "
                   "pending benchmark calibration (design §10): "
                   + ", ".join(provisional) + ". This output is NOT "
                   "production-certified sizing."),
    }
    return plan


def _refusal_message(host, allocatable, required, contrib, w, store, disk_free,
                     disk=False):
    top = sorted(contrib.items(), key=lambda kv: kv[1], reverse=True)[:3]
    lines = ["The requested workload cannot safely fit on this deployment."]
    lines.append(f"  Available Correlix memory : {fmt_human(allocatable)}")
    lines.append(f"  Estimated minimum memory  : {fmt_human(required)}")
    lines.append(f"  Available storage (free)  : {fmt_human(disk_free)}")
    lines.append("  Estimated required storage: {}".format(fmt_human(store["total"])))
    lines.append("  Primary contributors:")
    for name, v in top:
        lines.append(f"    - {name:<12} {fmt_human(v)}")
    if disk:
        lines.append("    - retained data exceeds disk: clickhouse {} / opensearch {} / victoria {}".format(fmt_human(store["clickhouse"]), fmt_human(store["opensearch"]),
                        fmt_human(store["victoria"])))
    lines.append("  Recommended corrective action:")
    lines.append("    - Increase host memory%s" % (" / disk" if disk else ""))
    lines.append("    - Reduce retention (flows/logs/metrics days)")
    lines.append("    - Reduce query/user concurrency inputs")
    lines.append("    - Or split stateful stores onto a dedicated host (future topology)")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Emitters
# --------------------------------------------------------------------------

def env_block(plan):
    env_mem = {s[0]: s[1] for s in SERVICES}
    env_cpu = {s[0]: s[2] for s in SERVICES}
    lines = [BLOCK_BEGIN,
             "# Generated by scripts/resource_planner.py — DO NOT EDIT inside this block.",
             "# Re-run 'python3 scripts/install.py --replan' after host/workload changes.",
             "# profile={} host={}".format(plan["profile"], plan["host"]["memory"])]
    for name in sorted(plan["limits_bytes"]):
        if name in plan.get("pinned", {}) and plan["pinned"][name] == "legacy-env-override":
            lines.append(f"# {name} pinned by legacy override outside this block")
            continue
        if env_mem.get(name):
            lines.append("{}={}".format(env_mem[name], fmt_bytes(plan["limits_bytes"][name])))
        if env_cpu.get(name):
            lines.append("{}={}".format(env_cpu[name], ("{:g}".format(plan["cpus"][name]))))
    for var in sorted(plan["internal"]):
        if var == "BUS_PARTITIONS" and plan["bus"]["source"] == "existing-install":
            # Already pinned outside this block by the operator; emitting it
            # here too would define the same key twice in .env.
            lines.append("# BUS_PARTITIONS={} pinned outside this block".format(
                plan["internal"][var]))
            continue
        lines.append("{}={}".format(var, plan["internal"][var]))
    lines.append(BLOCK_END)
    return "\n".join(lines) + "\n"


def plan_txt(plan):
    out = ["Correlix resource plan (profile: {})".format(plan["profile"]),
           "host: {} RAM, {:g} cpus, {} free disk".format(
               plan["host"]["memory"], plan["host"]["cpus"], plan["host"]["disk_free"]),
           "reserves: os {} | safety {} | allocatable {} | overcommit x{:.2f}".format(
               plan["reserves"]["os"], plan["reserves"]["safety"],
               plan["reserves"]["allocatable"], plan["reserves"]["overcommit_factor"]),
           "", f"{'component':<14} {'limit':>10} {'reserve':>10} {'cpus':>6}"]
    for name in sorted(plan["limits_bytes"]):
        pin = f"  [pinned:{plan['pinned'][name]}]" if name in plan["pinned"] else ""
        out.append(f"{name:<14} {fmt_human(plan['limits_bytes'][name]):>10} "
                   f"{fmt_human(plan['reservations_bytes'][name]):>10} "
                   f"{plan['cpus'][name]:>6g}{pin}")
    out.append(f"{'TOTAL':<14} {plan['totals']['limits']:>10}   "
               f"(budget {plan['totals']['budget']})")
    out.append("")
    out.append("internal limits (derived from each component's limit):")
    for var in sorted(plan["internal"]):
        out.append("  {}={}".format(var, plan["internal"][var]))
    out.append("")
    b = plan["bus"]
    replicas = b["replicas"] if b["replicas"] else "not specified"
    out.append("correlation bus partitions (raise-only — read before changing):")
    out.append(f"  BUS_PARTITIONS                {b['value']}  (source: {b['source']})")
    out.append(f"  topics created by kafka-init  {b['topics_created']}")
    out.append(f"  topics correlation consumes   {b['topics_consumed']}"
               f"   ({b['topics_created'] - b['topics_consumed']} carry partitions no "
               "correlation replica reads)")
    out.append(f"  total broker partitions       ~{b['broker_partitions']} "
               f"({b['value']} x {b['topics_created']} topics, single-node broker)")
    out.append(f"  correlation replicas          {replicas}")
    out.append(f"  max useful replicas           {b['max_useful_replicas']} "
               "(a consumer group cannot have more active members than partitions)")
    if b["idle_replicas"]:
        out.append(f"  EXPECTED IDLE REPLICAS        {b['idle_replicas']} "
                   "— alive, joined, consuming nothing")
    if not b["auto_sizing"]:
        out.append("  automatic EPS-based sizing    DISABLED (pending scale "
                   "qualification; the default is unchanged)")
    out.append("  raising it later              partitions can be increased but never "
               "reduced; kafka-init only alters upward")
    out.append("  keyed-data implication        events are tenant-keyed, so an increase "
               "changes which partition a tenant maps to;")
    out.append("                                records produced BEFORE the raise stay "
               "where they are and are not redistributed")
    out.append("  therefore                     an increase is a controlled migration: "
               "drain to a safe lag, then raise")
    out.append("                                (procedure: docs/scale-correlation.md)")
    out.append("  NOTE                          this reflects .env, not the live broker. "
               "Confirm with 'kafka-topics.sh --describe'")
    out.append("                                if BUS_PARTITIONS was ever set outside "
               "the installer.")
    out.append("")
    out.append("storage estimate: {}".format(", ".join(
        f"{k} {v}" for k, v in sorted(plan["storage_estimate"].items()))))
    for wmsg in plan["warnings"]:
        out.append(f"WARNING: {wmsg}")
    out.append(plan["notice"])
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# .env managed-block IO + legacy detection
# --------------------------------------------------------------------------

def plan_backup_paths(env_path):
    """Canonical artifact->backup map for replan/rollback. BOTH sides of the
    backup/restore MUST use this (a Path.with_suffix misfire on the hidden
    '.env' filename once split the write path from the read path)."""
    env_path = os.path.abspath(str(env_path))
    d = os.path.dirname(env_path)
    m = {env_path: env_path + ".plan.bak"}
    for n in ("resource-plan.json", "resource-plan.txt"):
        p = os.path.join(d, n)
        m[p] = p + ".plan.bak"
    return m


def read_env_overrides(env_text):
    """Vars matching LEGACY_VARS set OUTSIDE the managed block."""
    legacy, inside = {}, False
    for line in env_text.splitlines():
        s = line.strip()
        if s == BLOCK_BEGIN:
            inside = True
            continue
        if s == BLOCK_END:
            inside = False
            continue
        if inside or not s or s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        if k.strip() in LEGACY_VARS:
            legacy[k.strip()] = v.strip()
    return legacy


def splice_env(env_text, block):
    lines, out, inside, replaced = env_text.splitlines(), [], False, False
    for line in lines:
        if line.strip() == BLOCK_BEGIN:
            inside, replaced = True, True
            out.append(block.rstrip("\n"))
            continue
        if line.strip() == BLOCK_END:
            inside = False
            continue
        if not inside:
            out.append(line)
    if not replaced:
        out.extend(["", block.rstrip("\n")])
    return "\n".join(out).rstrip("\n") + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Correlix resource planner (#102)")
    ap.add_argument("--profile", default=None, help="demo|small|medium|large|custom")
    ap.add_argument("--sizing-file", help="correlix-sizing.yaml (YAML-subset or JSON)")
    ap.add_argument("--memory", help="override detected host memory (e.g. 64g)")
    ap.add_argument("--cpus", type=float, help="override detected cpu count")
    ap.add_argument("--disk-free", help="override detected free disk (e.g. 500g)")
    ap.add_argument("--env-file", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "deployment", "docker", ".env"))
    ap.add_argument("--write", action="store_true", help="splice the block into --env-file")
    ap.add_argument("--output-dir", help="write resource-plan.json/.txt here")
    ap.add_argument("--detect-json", action="store_true",
                    help="print detected host capacity + suggested auto profile "
                         "as one JSON object and exit (no side effects; GUI "
                         "installer facts endpoint)")
    args = ap.parse_args(argv)

    if args.detect_json:
        # Read-only: detect_host() + the shared auto-profile thresholds.
        # Never writes a file, never touches .env.
        host = detect_host(args.memory, args.cpus, args.disk_free)
        sys.stdout.write(json.dumps({
            "mem_bytes": host["memory_bytes"],
            "mem_gib": round(host["memory_bytes"] / GIB, 1),
            "cpus": host["cpus"],
            "disk_free_bytes": host["disk_free_bytes"],
            "suggested_profile": suggest_profile(host["memory_bytes"]),
        }, sort_keys=True) + "\n")
        return 0

    doc = {}
    if args.sizing_file:
        with open(args.sizing_file) as f:
            doc = parse_sizing_file(f.read())
    profile = args.profile or doc.get("profile") or "demo"
    host_doc = doc.get("host", {}) or {}
    mem = args.memory or (None if host_doc.get("memory") in (None, "auto") else host_doc.get("memory"))
    cpus = args.cpus or (None if host_doc.get("cpu") in (None, "auto") else host_doc.get("cpu"))

    host = detect_host(mem, cpus, args.disk_free)
    workload = normalize_workload(doc) if doc else {}
    overrides = doc.get("overrides", {}) or {}

    legacy = {}
    env_text = ""
    if os.path.exists(args.env_file):
        with open(args.env_file) as f:
            env_text = f.read()
        legacy = read_env_overrides(env_text)

    try:
        plan = compute_plan(host, profile, workload, overrides, legacy)
    except SizingError as e:
        sys.stderr.write(f"ERROR: {e}\n")
        return 2

    sys.stdout.write(plan_txt(plan))
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        with open(os.path.join(args.output_dir, "resource-plan.json"), "w") as f:
            json.dump(plan, f, indent=2, sort_keys=True)
            f.write("\n")
        with open(os.path.join(args.output_dir, "resource-plan.txt"), "w") as f:
            f.write(plan_txt(plan))
    if args.write:
        backup = args.env_file + ".plan.bak"
        if env_text:
            with open(backup, "w") as f:
                f.write(env_text)
        with open(args.env_file, "w") as f:
            f.write(splice_env(env_text, env_block(plan)))
        os.chmod(args.env_file, 0o600)
        sys.stdout.write(f"wrote managed block to {args.env_file} (backup: {backup})\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
