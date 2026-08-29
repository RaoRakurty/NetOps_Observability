"""ClickHouse merge/memory budget stays pinned to the MEASURED numbers.

Source of truth: docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29.md (run
p2-s04b-08290858, 2.5K leg, 75 minutes):

    cgroup limit ................................ 5,584,715,776 B = 5,326 MiB
    max_server_memory_usage (0.9 x cgroup) ...... 5,026,244,198 B = 4,794 MiB
    peak MemoryTracking ......................... 4,566 MiB = 95.2 % of that
    peak MergesMutationsMemoryTracking .......... 3,978 MiB  (merges ALONE)
    inserted 1.40 GiB -> merged 337.6 GiB over 69,201 merges = ~241x amplification
    mark_cache_size ............................. 5,368,709,120 B = 5,120 MiB,
                                                  LARGER than the whole container
    uncompressed_cache_size ..................... 8,589,934,592 B, cache disabled
    background_pool_size 16 x ratio 2 ........... 32 concurrent merges on 3 CPUs
    system.part_log ............................. DISABLED, so all of the above
                                                  had to be RECONSTRUCTED

Every assertion below is one of those numbers or an arithmetic consequence of
one. Changing any single value in memory.xml / system-logs.xml / init.sql /
corr_merge_budget.go turns this file red — that is the point: these are
measurements, not preferences, and a silent edit re-opens a 241x merge storm.

Run:  PATH=/home/rao/.local/bin:$PATH python3 -m pytest tests/test_clickhouse_merge_budget.py -q
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CH = ROOT / "deployment" / "docker" / "clickhouse"
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"

MIB = 1024 * 1024
GIB = 1024 * MIB

# ── the measured deployment sizing (docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29) ──
# CLICKHOUSE_MEM_LIMIT=5326m on the box the run was measured on; ClickHouse
# agreed (asynchronous_metrics CGroupMemoryTotal = 5584715776).
MEASURED_CGROUP_BYTES = 5326 * MIB          # 5,584,715,776
PEAK_MEMORY_TRACKING_MIB = 4566
PEAK_MERGES_MEMORY_MIB = 3978


# ── parsing helpers ──────────────────────────────────────────────────────────

def _compose_yaml(text: str) -> dict:
    """Compose files may carry compose's merge tags (!override, !reset), which
    yaml.safe_load rejects. Same loader as tests/test_assurance_contracts.py."""
    import yaml

    class _ComposeLoader(yaml.SafeLoader):
        pass

    def _passthrough(loader, node):
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        return loader.construct_scalar(node)

    _ComposeLoader.add_constructor("!override", _passthrough)
    _ComposeLoader.add_constructor("!reset", _passthrough)
    return yaml.load(text, Loader=_ComposeLoader)


def _xml(name: str) -> ET.Element:
    return ET.fromstring((CH / name).read_text())


def _setting(root: ET.Element, name: str) -> str:
    el = root.find(name)
    assert el is not None, f"clickhouse config has no <{name}>"
    if "from_env" in el.attrib:
        return "$" + el.attrib["from_env"]
    assert el.text is not None, f"<{name}> has neither a value nor from_env"
    return el.text.strip()


def _clickhouse_service() -> dict:
    svc = _compose_yaml(COMPOSE.read_text())["services"]["clickhouse"]
    assert svc, "docker-compose.yml has no clickhouse service"
    return svc


def _compose_default(var: str) -> str:
    """Resolve ${VAR:-default} from the clickhouse service environment.

    The compose DEFAULT is what CI and any un-planned install actually get, so
    it — not a gitignored .env — is what the contract is written against.
    """
    env = _clickhouse_service()["environment"]
    raw = str(env[var])
    m = re.fullmatch(r"\$\{" + re.escape(var) + r":-([^}]*)\}", raw)
    assert m, f"{var} is not a ${{VAR:-default}} expression: {raw!r}"
    return m.group(1)


def _bytes_of(spec: str) -> int:
    """Parse a compose memory spec ('5326m', '4g') or a plain byte count."""
    m = re.fullmatch(r"(\d+)([kmg]?)b?", spec.strip().lower())
    assert m, f"unparseable memory spec {spec!r}"
    return int(m.group(1)) * {"": 1, "k": 1024, "m": MIB, "g": GIB}[m.group(2)]


def _init_sql_no_comments() -> str:
    """init.sql with `--` line comments stripped: several column comments carry
    a semicolon, so a naive statement split truncates before SETTINGS."""
    out = []
    for line in (CH / "init.sql").read_text().split("\n"):
        i = line.find("--")
        out.append(line if i < 0 else line[:i])
    return "\n".join(out)


def _create_stmt(table: str) -> str:
    sql = _init_sql_no_comments()
    start = sql.find(f"CREATE TABLE IF NOT EXISTS netops.{table}\n")
    assert start >= 0, f"init.sql has no CREATE for netops.{table}"
    end = sql.find(";", start)
    assert end > start, f"init.sql: unterminated CREATE for netops.{table}"
    return sql[start:end]


# ── the per-table merge budget (§(b), init.sql + corr_merge_budget.go) ───────

MERGE_CAPS = {
    # corr_objects carries 86 % of the family's uncompressed bytes (26,878 B/row,
    # `hypotheses` = 45.01 of 48.01 GiB) and grew a 1.86 GiB part at level 1,568.
    "corr_objects": 2 * GIB,
    # Same level pathology one size down: corr_current level 33,082,
    # corr_edges 11,848, corr_evidence 10,825, corr_signals_archive 7,524.
    "corr_signals": 1 * GIB,
    "corr_signals_archive": 1 * GIB,
    "corr_current": 1 * GIB,
    "corr_edges": 1 * GIB,
    "corr_evidence": 1 * GIB,
    "corr_tenant_write_amp": 1 * GIB,
    "corr_path_edges": 1 * GIB,
}
FORCE_MERGE_AGE_S = 600


@pytest.mark.parametrize("table,cap", sorted(MERGE_CAPS.items()))
def test_init_sql_pins_the_measured_merge_cap(table, cap):
    """The stock max_bytes_to_merge_at_max_space_in_pool is 150 GB, i.e. no part
    these tables will ever hold is too big to re-merge — which is how 1.40 GiB of
    inserts produced 337.6 GiB of merges. The cap retires the accumulated part
    from merge selection once it crosses it."""
    stmt = _create_stmt(table)
    assert f"max_bytes_to_merge_at_max_space_in_pool = {cap}" in stmt, (
        f"netops.{table}: merge cap is not the measured "
        f"{cap // GIB} GiB ({cap} B) — see P2_CLICKHOUSE_MEMFLAT_2026-08-29 §(b)")


@pytest.mark.parametrize("table", sorted(MERGE_CAPS))
def test_init_sql_pins_the_idle_consolidation_pass(table):
    """min_age_to_force_merge_seconds = 600 with _on_partition_only = 1: ONE
    bounded consolidation over a partition whose parts have all been idle 10
    minutes, instead of the continuous re-merge trickle. Without
    _on_partition_only this fires on subsets and adds merges rather than
    replacing them."""
    stmt = _create_stmt(table)
    assert f"min_age_to_force_merge_seconds = {FORCE_MERGE_AGE_S}" in stmt, (
        f"netops.{table}: idle force-merge age is not the ratified 600 s")
    assert "min_age_to_force_merge_on_partition_only = 1" in stmt, (
        f"netops.{table}: force-merge is not partition-scoped — it would add "
        f"merges on subsets instead of replacing the trickle")


def test_every_corr_table_in_init_sql_has_a_merge_budget():
    """Coverage, not a fixed list: a corr_* table added without a cap can grow
    the same level-33,082 accumulated part the run measured."""
    sql = _init_sql_no_comments()
    tables = set(re.findall(r"CREATE TABLE IF NOT EXISTS netops\.(corr_\w+)", sql))
    assert tables, "no corr_* CREATE statements found in init.sql — parser drift"
    assert tables == set(MERGE_CAPS), (
        f"corr_* tables in init.sql differ from the budgeted set: "
        f"missing a budget {sorted(tables - set(MERGE_CAPS))}, "
        f"budgeted but absent {sorted(set(MERGE_CAPS) - tables)}")


def test_go_boot_converge_carries_the_identical_budget():
    """init.sql is the FRESH-install authority; corr_merge_budget.go converges
    LIVE deployments on API boot (the corr_retention.go MODIFY SETTING pattern).
    A fresh install and an upgraded one must merge identically."""
    go = (ROOT / "src" / "backend" / "internal" / "chschema"
          / "corr_merge_budget.go").read_text()
    assert "func CorrMergeBudgetDDL()" in go, "converge entrypoint renamed"
    assert 'MODIFY SETTING "+' in go, (
        "the migration is no longer an ALTER ... MODIFY SETTING — live "
        "deployments would never pick the budget up")
    # The two caps and the force-merge age, as literals the Go file computes from.
    assert "corrMergeCapObjects = 2 * 1024 * 1024 * 1024" in go
    assert "corrMergeCapDefault = 1 * 1024 * 1024 * 1024" in go
    assert f"corrMergeForceAgeSeconds = {FORCE_MERGE_AGE_S}" in go
    # Every budgeted table is named in the Go table map.
    for table in MERGE_CAPS:
        assert f'"{table}":' in go, (
            f"netops.{table} has a budget in init.sql but none in "
            f"corr_merge_budget.go — fresh installs and upgrades would diverge")
    # And it is wired into the boot converge list.
    policies = (ROOT / "src" / "backend" / "internal" / "chschema"
                / "policies.go").read_text()
    assert "CorrMergeBudgetDDL()" in policies, (
        "CorrMergeBudgetDDL is not appended to ConvergeStmts — the migration "
        "exists but never runs")


def test_insert_backpressure_is_left_at_the_defaults():
    """Measured: peak PartsActive 927 against parts_to_delay_insert = 1000 and
    parts_to_throw_insert = 3000, and system.errors showed NO insert-side
    TOO_MANY_PARTS. The insert-side backpressure is not what needed changing, so
    nothing may quietly override it — raising it would hide the next parts
    explosion instead of bounding it."""
    for name in ("parts_to_delay_insert", "parts_to_throw_insert"):
        assert name not in _init_sql_no_comments(), (
            f"{name} is overridden in init.sql; the P2 brief keeps it at the "
            f"ClickHouse default (1000 / 3000)")
        for xml_name in ("memory.xml", "custom-settings.xml", "workload-profiles.xml",
                         "query-spill.xml", "system-logs.xml"):
            assert name not in (CH / xml_name).read_text(), (
                f"{name} is overridden in {xml_name}; it must stay at the default")


# ── the server-side budget (memory.xml) ──────────────────────────────────────

def test_background_pool_is_sized_for_a_four_core_box():
    """Measured: background_pool_size 16 x concurrency ratio 2 = 32 concurrent
    merges on a container limited to 3 CPUs is what let merges hold 3,978 MiB.
    6 x 2 = 12 — still 4x the CPU allowance, ~2.7x less concurrent merge memory.
    Both halves are pinned: the concurrency is the PRODUCT, so pinning only the
    pool size would let the ratio silently restore 32."""
    m = _xml("memory.xml")
    assert _setting(m, "background_pool_size") == "6"
    assert _setting(m, "background_merges_mutations_concurrency_ratio") == "2"


def test_mark_cache_no_longer_exceeds_the_container():
    """Measured: the stock ceiling is 5,368,709,120 B = 5,120 MiB — larger than
    the entire 5,326 MiB container and 107 % of the old server cap — against an
    actual MarkCacheBytes of 2.01 MiB. A ceiling that can never be honoured is a
    latent OOM, not a cache policy."""
    assert _setting(_xml("memory.xml"), "mark_cache_size") == str(512 * MIB)
    assert 512 * MIB == 536870912


def test_uncompressed_cache_reservation_is_zero():
    """Measured: UncompressedCacheBytes 0 B — the cache is off
    (use_uncompressed_cache = 0) yet the image reserves 8,589,934,592 B for it."""
    assert _setting(_xml("memory.xml"), "uncompressed_cache_size") == "0"


def test_memory_knobs_are_env_driven_with_compose_defaults():
    """#102 keeps sizing in the resource plan and out of the XML. The two byte
    caps stay from_env so a re-plan can move them; compose carries the measured
    default so an unplanned install still gets it."""
    m = _xml("memory.xml")
    assert _setting(m, "max_server_memory_usage") == "$CH_MAX_SERVER_MEMORY"
    assert _setting(m, "merges_mutations_memory_usage_soft_limit") == "$CH_MERGES_MEM"
    assert _setting(m, "max_server_memory_usage_to_ram_ratio") == "$CH_MEM_RATIO"


def test_max_server_memory_is_the_measured_cgroup_arithmetic():
    """ARITHMETIC (docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29.md):

        cgroup limit ............................ 5,326 MiB
        - page-cache / slab / untracked headroom  1,230 MiB (23.1 %)
        = max_server_memory_usage ............... 4,096 MiB = 4,294,967,296 B

    The 0.9 ratio left only 532 MiB of headroom for a store that moves ~50 GiB
    per run; measured at the peak the cgroup held active_file 1,516 MiB +
    slab_reclaimable 621 MiB = 2,137 MiB of reclaimable kernel memory."""
    cap = int(_compose_default("CH_MAX_SERVER_MEMORY"))
    assert cap == 4 * GIB == 4294967296
    headroom = MEASURED_CGROUP_BYTES - cap
    assert headroom == 1230 * MIB
    assert headroom >= 1 * GIB, "less than 1 GiB left for page cache + slab"


def test_merge_budget_is_under_the_memflat_fifty_percent_clause():
    """1.5 GiB = 37.5 % of the 4,096 MiB server cap, under the proposed memflat
    assertion `MergesMutationsMemoryTracking < 50 % of max_server_memory_usage`
    (§(c) 2). Measured, the run held 3,978 MiB = 83 % of the old cap."""
    merges = int(_compose_default("CH_MERGES_MEM"))
    cap = int(_compose_default("CH_MAX_SERVER_MEMORY"))
    assert merges == 1536 * MIB == 1610612736
    assert merges / cap == 0.375
    assert merges < cap // 2
    # The regression it exists to stop, stated as measurement.
    assert PEAK_MERGES_MEMORY_MIB * MIB > merges, (
        "the measured merge peak is no longer above the new soft limit — "
        "re-derive the budget from a fresh run before relaxing it")


def test_soft_limit_binds_inside_the_cgroup():
    """Left at 0 the soft limit derives as merges_mutations_memory_usage_to_ram_
    ratio (0.5) x cgroup = 2,663 MiB — which the run exceeded by 49 %, because
    the limit is checked when a merge is SCHEDULED, not while it runs. An
    explicit value must therefore be strictly below the derived one, or setting
    it changes nothing at all."""
    merges = int(_compose_default("CH_MERGES_MEM"))
    derived = MEASURED_CGROUP_BYTES // 2
    assert merges < derived, (
        f"explicit merge soft limit {merges} >= the ratio-derived {derived}; "
        "ClickHouse takes min(explicit, ratio x cgroup), so it would be inert")


# ── consistency with the compose memory limit ────────────────────────────────

def _effective_cap(mem_limit: int) -> int:
    """ClickHouse 24.8 takes min(explicit, ratio x cgroup) for both
    max_server_memory_usage and the merges soft limit (0 = 'use the ratio')."""
    ratio = float(_compose_default("CH_MEM_RATIO"))
    explicit = int(_compose_default("CH_MAX_SERVER_MEMORY"))
    derived = int(mem_limit * ratio)
    return derived if explicit == 0 else min(explicit, derived)


@pytest.mark.parametrize("mem_limit_spec,label", [
    (None, "compose default"),
    ("5326m", "the P2-measured deployment sizing"),
])
def test_server_budget_fits_the_compose_memory_limit(mem_limit_spec, label):
    """The whole failure mode is a server whose own ceilings exceed the cgroup
    it runs in. Assert that for the compose default AND for the sizing the run
    was measured on:

      * the effective server cap never reaches the container limit
      * the merge budget stays under half of the effective cap
      * every cache RESERVATION fits, which is what mark_cache_size 5.37 GiB
        against a 5.20 GiB container violated
    """
    svc = _clickhouse_service()
    raw = str(svc["mem_limit"])
    m = re.fullmatch(r"\$\{CLICKHOUSE_MEM_LIMIT:-([^}]*)\}", raw)
    assert m, f"clickhouse mem_limit is not a ${{VAR:-default}} expression: {raw!r}"
    mem_limit = _bytes_of(mem_limit_spec or m.group(1))

    cap = _effective_cap(mem_limit)
    assert cap < mem_limit, (
        f"{label}: effective max_server_memory_usage {cap} >= mem_limit {mem_limit}")
    assert mem_limit - cap >= mem_limit // 10, (
        f"{label}: only {(mem_limit - cap) // MIB} MiB of headroom under a "
        f"{mem_limit // MIB} MiB limit — the kernel needs page cache for a "
        f"store that moves ~50 GiB per run")

    merges = int(_compose_default("CH_MERGES_MEM"))
    merges_eff = min(merges, mem_limit // 2) if merges else mem_limit // 2
    assert merges_eff <= cap // 2, (
        f"{label}: merge budget {merges_eff} exceeds half the server cap {cap}")

    mem = _xml("memory.xml")
    caches = (int(_setting(mem, "mark_cache_size"))
              + int(_setting(mem, "uncompressed_cache_size")))
    assert caches < mem_limit, (
        f"{label}: cache reservations {caches} exceed the container limit "
        f"{mem_limit} — this is the stock 5.37 GiB mark cache regression")
    assert caches <= cap // 4, (
        f"{label}: cache reservations {caches} are more than a quarter of the "
        f"server cap {cap}")


def test_per_query_caps_stay_below_the_server_cap():
    """A single query may never be allowed to spend the whole server budget —
    the 2026-07-09 shape, where one 2.6 GiB read pushed the server to its cgroup
    limit and the OvercommitTracker killed OTHER queries."""
    cap = _effective_cap(_bytes_of("5326m"))
    for var in ("CH_HOT_UI_MEM", "CH_BG_MEM", "CH_SPILL_BYTES"):
        val = int(_compose_default(var))
        assert val <= cap // 2, (
            f"{var}={val} is more than half the {cap}-byte server cap")


def test_no_overlay_resizes_clickhouse_without_resizing_its_budget():
    """The byte caps are absolute, so an overlay that changes the clickhouse
    mem_limit and not CH_MAX_SERVER_MEMORY / CH_MERGES_MEM silently breaks the
    arithmetic above."""
    for overlay in sorted((ROOT / "deployment" / "docker").glob("compose*.yml")) + \
            sorted((ROOT / "deployment" / "docker").glob("docker-compose.*.yml")):
        doc = _compose_yaml(overlay.read_text()) or {}
        svc = (doc.get("services") or {}).get("clickhouse") or {}
        if "mem_limit" not in svc:
            continue
        env = svc.get("environment") or {}
        assert "CH_MAX_SERVER_MEMORY" in env and "CH_MERGES_MEM" in env, (
            f"{overlay.name} overrides the clickhouse mem_limit but not "
            f"CH_MAX_SERVER_MEMORY / CH_MERGES_MEM")


# ── system.part_log and the self-logging TTLs ────────────────────────────────

KEPT_LOG_TTL_DAYS = {"query_log": 7, "metric_log": 3, "part_log": 3}


def test_part_log_is_enabled_again():
    """§1 of the brief: with part_log disabled, 69,201 merges and 337.6 GiB of
    merged bytes had to be RECONSTRUCTED from metric_log + query_log, and the
    ~241x amplification could only be inferred. The merge budget shipped here is
    only verifiable against part_log."""
    root = _xml("system-logs.xml")
    el = root.find("part_log")
    assert el is not None, "system-logs.xml no longer configures part_log"
    assert el.get("remove") is None, (
        "system.part_log is disabled again — the merge budget becomes "
        "unmeasurable (P2_CLICKHOUSE_MEMFLAT_2026-08-29 §1)")


@pytest.mark.parametrize("table,days", sorted(KEPT_LOG_TTL_DAYS.items()))
def test_every_kept_system_log_has_a_bounded_ttl(table, days):
    """#96a: unbounded system.* logging measured 5.84 GiB against 453 MiB of
    real data. Enabling part_log is only safe because it is bounded."""
    el = _xml("system-logs.xml").find(table)
    assert el is not None and el.get("remove") is None, f"{table} is not enabled"
    ttl = el.find("ttl")
    assert ttl is not None and ttl.text, f"system.{table} has no <ttl>"
    assert ttl.text.strip() == f"event_date + INTERVAL {days} DAY DELETE", (
        f"system.{table} TTL is {ttl.text.strip()!r}, want {days} days")


def test_no_system_log_is_enabled_without_a_ttl():
    """Coverage rule, so a future re-enable cannot skip the TTL: every child of
    system-logs.xml is either removed or carries a <ttl>."""
    for el in _xml("system-logs.xml"):
        if el.get("remove") == "1":
            continue
        assert el.find("ttl") is not None, (
            f"system.{el.tag} is enabled with NO ttl — the #96a regression")
        assert el.tag in KEPT_LOG_TTL_DAYS, (
            f"system.{el.tag} was enabled without a pinned TTL in this test")
