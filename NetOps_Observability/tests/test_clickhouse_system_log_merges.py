"""system.* log tables must merge cheaply BY CONSTRUCTION.

Source of truth: docs/scale/P2_CLICKHOUSE_PEAK_S06_2026-08-29.md (run
p2-s06, 14:35-14:50 on 2026-08-29):

    system.metric_log ........................... 997 columns, ~1,015 B/row
    RSS transients .............................. 13, up to 4,406 MiB
    max_server_memory_usage ..................... 4,096 MiB  (peak = 107 % of it)
    MEMORY_LIMIT_EXCEEDED refusals .............. 17, of UNRELATED inserts
    cadence that matches every refusal .......... ProfileEvent_MergedColumns = 997
    the live part, measured in system.parts ..... Wide, 13,693 rows, 13.31 MiB

The cause was not the workload. It was that a metric_log merge whose output
lands between the wide-part threshold (~10,330 rows) and the vertical-merge
activation threshold (131,072 rows) is Wide AND Horizontal: 997 column write
streams open at once, ~1 GiB of writer buffers plus ~1 GiB per source part.
s05 was clean only because its metric_log merges happened to fall below or
above that band.

MECHANISM, verified against the ClickHouse v24.8.14.39-lts source rather than
assumed (the deployed version):

  * MergeTreeData::choosePartFormat (MergeTreeData.cpp:3639)
        Compact iff bytes_uncompressed < min_bytes_for_wide_part
                 OR rows_count        < min_rows_for_wide_part
    Note the OR: EITHER threshold alone forces Compact.
  * MergeTask::chooseMergeAlgorithm (MergeTask.cpp:1304)
        Horizontal unless output part is Wide AND
            rows      >= vertical_merge_algorithm_min_rows_to_activate
            bytes     >= vertical_merge_algorithm_min_bytes_to_activate
            non-PK cols >= vertical_merge_algorithm_min_columns_to_activate
        and, before all of those, Horizontal unconditionally when
            need_remove_expired_values  (a TTL merge)   MergeTask.cpp:1314
            source parts are Compact and
              allow_vertical_merges_from_compact_to_wide_parts = 0   (:1323)
  * MergeTreeDataPartWriterOnDisk::Stream — a Wide column stream holds
        2 x max_compress_block_size + ~68 KiB of mark buffers.
  * MergeTreeDataPartWriterCompact — a Compact part holds ONE CompressedStream
        per distinct codec (`streams_by_codec`), i.e. ~1 for these tables.
  * FutureMergedMutatedPart::assign — the merged part type is
        min(all source part types, choosePartFormat(...)) and Wide < Compact in
        MergeTreeDataPartType, so WIDE IS STICKY: an existing Wide part keeps
        producing Wide merges regardless of the thresholds. That is why the
        operator must let the table be recreated (see the migration note in
        deployment/docker/clickhouse/system-logs.xml).
  * Context::getPartLog — returns {} when the source database is `system`,
        hard-coded. No setting makes system-table merges visible in part_log.

Every assertion below is one of those source facts or the row-size arithmetic
from the brief. Run:

  PATH=/home/rao/.local/bin:$PATH python3 -m pytest \
      tests/test_clickhouse_system_log_merges.py -q
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CH = ROOT / "deployment" / "docker" / "clickhouse"
SYSTEM_LOGS = CH / "system-logs.xml"
MEMORY_XML = CH / "memory.xml"

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB

# ── measured, docs/scale/P2_CLICKHOUSE_PEAK_S06_2026-08-29.md ────────────────
METRIC_LOG_COLUMNS = 997
METRIC_LOG_BYTES_PER_ROW = 1015
METRIC_LOG_TTL_DAYS = 3
SECONDS_PER_DAY = 86400
MEASURED_WIDE_PART_ROWS = 13693          # the part found inside the band

# ── ClickHouse 24.8 stock values, from MergeTreeSettings.h ───────────────────
CH_24_8_STOCK = {
    "min_bytes_for_wide_part": 10485760,
    "min_rows_for_wide_part": 0,
    "enable_vertical_merge_algorithm": 1,
    "vertical_merge_algorithm_min_rows_to_activate": 16 * 8192,   # 131,072
    "vertical_merge_algorithm_min_bytes_to_activate": 0,
    "vertical_merge_algorithm_min_columns_to_activate": 11,
    "allow_vertical_merges_from_compact_to_wide_parts": 1,
    "max_compress_block_size": 1048576,      # global default when 0 here
    "min_compress_block_size": 65536,
    "max_bytes_to_merge_at_max_space_in_pool": 150 * 1000 * 1000 * 1000,
}

# The settings every kept system log must carry, with the ratified value.
REQUIRED_MERGE_SETTINGS = {
    "enable_vertical_merge_algorithm": 1,
    "vertical_merge_algorithm_min_rows_to_activate": 1,
    "vertical_merge_algorithm_min_bytes_to_activate": 0,
    "vertical_merge_algorithm_min_columns_to_activate": 1,
    "allow_vertical_merges_from_compact_to_wide_parts": 1,
    "max_compress_block_size": 65536,
    "min_compress_block_size": 32768,
    "max_bytes_to_merge_at_max_space_in_pool": 128 * MIB,
}

# metric_log alone also pins the wide-part thresholds: 997 columns is the
# outlier, and forcing Compact removes the 997-stream writer entirely.
METRIC_LOG_EXTRA_SETTINGS = {
    "min_rows_for_wide_part": 100_000_000,
    "min_bytes_for_wide_part": 1 * GIB,
}

EXPECTED_TTL_DAYS = {
    "query_log": 7,
    "error_log": 7,
    "metric_log": 3,
    "part_log": 3,
    "asynchronous_metric_log": 3,
    "trace_log": 1,
}

# Guarded by MergeTreeSettings::sanityCheck against
# background_pool_size x background_merges_mutations_concurrency_ratio at table
# ATTACH time: a per-table override here crash-loops the server (exit 36, the
# 2026-08-29 incident) and bypasses memory.xml's <merge_tree> block.
POOL_THRESHOLD_SETTINGS = (
    "number_of_free_entries_in_pool_to_lower_max_size_of_merge",
    "number_of_free_entries_in_pool_to_execute_mutation",
    "number_of_free_entries_in_pool_to_execute_optimize_entire_partition",
)

# Every name that may appear in a <settings> block. A name that is not a real
# MergeTree setting makes the CREATE TABLE fail at startup and the log table is
# then silently never created — the failure mode this allowlist exists to stop.
KNOWN_MERGE_TREE_SETTINGS = set(CH_24_8_STOCK) | {
    "ttl_only_drop_parts",
    "min_age_to_force_merge_seconds",
    "min_age_to_force_merge_on_partition_only",
    "marks_compress_block_size",
    "index_granularity",
    "index_granularity_bytes",
    "merge_max_block_size",
    "merge_max_block_size_bytes",
    "max_bytes_to_merge_at_min_space_in_pool",
}


# ── parsing ─────────────────────────────────────────────────────────────────

def _root() -> ET.Element:
    return ET.fromstring(SYSTEM_LOGS.read_text())


def _enabled_logs() -> dict[str, ET.Element]:
    return {el.tag: el for el in _root() if el.get("remove") != "1"}


def _parse_settings(text: str) -> dict[str, int]:
    """`a = 1, b = 2` -> {'a': 1, 'b': 2}. The string is appended verbatim after
    SETTINGS in the generated CREATE TABLE (SystemLog.cpp getLogSettings), so it
    must parse as a plain `name = value` list."""
    out: dict[str, int] = {}
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.fullmatch(r"([a-z_0-9]+)\s*=\s*(\d+)", chunk)
        assert m, f"unparseable MergeTree setting {chunk!r} in system-logs.xml"
        assert m.group(1) not in out, f"{m.group(1)} set twice"
        out[m.group(1)] = int(m.group(2))
    return out


def _settings_of(table: str) -> dict[str, int]:
    el = _enabled_logs().get(table)
    assert el is not None, f"system.{table} is not enabled in system-logs.xml"
    node = el.find("settings")
    assert node is not None and node.text, (
        f"system.{table} has no <settings> block — it would inherit the stock "
        f"wide/horizontal merge behaviour that produced the s06 peak")
    return _parse_settings(node.text)


def _child_int(table: str, child: str) -> int:
    el = _enabled_logs()[table].find(child)
    assert el is not None and el.text, f"system.{table} has no <{child}>"
    return int(el.text.strip())


# ── the model: when is a merge Wide AND Horizontal? ─────────────────────────

def _is_wide(rows: int, bytes_uncompressed: int, s: dict[str, int]) -> bool:
    """MergeTreeData::choosePartFormat, 24.8. Compact iff EITHER threshold is
    unmet; Wide needs both."""
    min_bytes = s.get("min_bytes_for_wide_part",
                      CH_24_8_STOCK["min_bytes_for_wide_part"])
    min_rows = s.get("min_rows_for_wide_part",
                     CH_24_8_STOCK["min_rows_for_wide_part"])
    return not (bytes_uncompressed < min_bytes or rows < min_rows)


def _is_vertical(rows: int, bytes_uncompressed: int, columns: int,
                 s: dict[str, int]) -> bool:
    """MergeTask::chooseMergeAlgorithm, 24.8, for the non-TTL, Full-storage,
    Ordinary-merging-params case that every system log merge is."""
    if not _is_wide(rows, bytes_uncompressed, s):
        return False
    if not s.get("enable_vertical_merge_algorithm",
                 CH_24_8_STOCK["enable_vertical_merge_algorithm"]):
        return False
    return (
        rows >= s.get("vertical_merge_algorithm_min_rows_to_activate",
                      CH_24_8_STOCK["vertical_merge_algorithm_min_rows_to_activate"])
        and bytes_uncompressed >= s.get(
            "vertical_merge_algorithm_min_bytes_to_activate",
            CH_24_8_STOCK["vertical_merge_algorithm_min_bytes_to_activate"])
        and columns >= s.get(
            "vertical_merge_algorithm_min_columns_to_activate",
            CH_24_8_STOCK["vertical_merge_algorithm_min_columns_to_activate"])
    )


def _in_danger_band(rows: int, columns: int, bytes_per_row: int,
                    s: dict[str, int]) -> bool:
    """The s06 failure mode: the merge output is Wide (one stream per column)
    and the algorithm is Horizontal (all streams open at once)."""
    size = rows * bytes_per_row
    return _is_wide(rows, size, s) and not _is_vertical(rows, size, columns, s)


def _row_counts_to_probe() -> list[int]:
    """Row counts spanning every regime: the stock band edges, the part actually
    measured inside the band, the 3-day TTL horizon, and decades far beyond any
    horizon this table can reach."""
    edges = [1, 2, 8192, 10329, 10330, 10331, MEASURED_WIDE_PART_ROWS,
             131071, 131072, 131073,
             METRIC_LOG_TTL_DAYS * SECONDS_PER_DAY,
             10 ** 6, 10 ** 7, 10 ** 8 - 1, 10 ** 8, 10 ** 8 + 1, 10 ** 9]
    decades = [10 ** e for e in range(0, 11)]
    return sorted(set(edges + decades))


# ── contract: every enabled log is bounded and merge-safe ───────────────────

def test_every_enabled_system_log_has_a_ttl_and_merge_settings():
    """#96a bounded the DISK (5.84 GiB of self-logging vs 453 MiB of data);
    P2/s06 bounds the MEMORY of merging what is kept. A log enabled with only
    one of the two is half-bounded."""
    enabled = _enabled_logs()
    assert set(enabled) == set(EXPECTED_TTL_DAYS), (
        f"enabled system logs {sorted(enabled)} differ from the pinned set "
        f"{sorted(EXPECTED_TTL_DAYS)} — a new one must arrive WITH a TTL and a "
        f"merge-safe <settings> block, and be pinned here")
    for table, el in enabled.items():
        ttl = el.find("ttl")
        assert ttl is not None and ttl.text, f"system.{table} has no <ttl>"
        assert ttl.text.strip() == (
            f"event_date + INTERVAL {EXPECTED_TTL_DAYS[table]} DAY DELETE"), (
            f"system.{table} TTL is {ttl.text.strip()!r}")
        assert el.find("settings") is not None, (
            f"system.{table} has no <settings> — stock merge behaviour")


@pytest.mark.parametrize("table", sorted(EXPECTED_TTL_DAYS))
@pytest.mark.parametrize("name,value", sorted(REQUIRED_MERGE_SETTINGS.items()))
def test_every_enabled_log_carries_the_ratified_merge_settings(table, name, value):
    """The shared block, on every kept log. The vertical settings make
    `Wide implies Vertical`; the compress-block pair bounds the one merge the
    vertical settings cannot cover (a TTL merge is forced Horizontal,
    MergeTask.cpp:1314); the cap retires an accumulated part from re-merging."""
    got = _settings_of(table)
    assert got.get(name) == value, (
        f"system.{table}: {name} = {got.get(name)}, want {value} "
        f"(ClickHouse 24.8 stock is {CH_24_8_STOCK.get(name)})")


@pytest.mark.parametrize("name,value", sorted(METRIC_LOG_EXTRA_SETTINGS.items()))
def test_metric_log_pins_the_wide_part_thresholds(name, value):
    """997 columns is the outlier that made this a 4.4 GiB event rather than a
    curiosity, so metric_log is additionally held Compact."""
    got = _settings_of("metric_log")
    assert got.get(name) == value, (
        f"metric_log: {name} = {got.get(name)}, want {value}")


def test_no_settings_block_names_an_unknown_mergetree_setting():
    """A typo'd setting name does not warn — the CREATE TABLE fails and the log
    table is never created, i.e. the instrument silently disappears."""
    for table in _enabled_logs():
        for name in _settings_of(table):
            assert name in KNOWN_MERGE_TREE_SETTINGS, (
                f"system.{table}: {name!r} is not a known ClickHouse 24.8 "
                f"MergeTree setting; verify it against MergeTreeSettings.h and "
                f"add it to KNOWN_MERGE_TREE_SETTINGS")


def test_no_settings_block_overrides_a_pool_threshold():
    """MergeTreeSettings::sanityCheck runs on the EFFECTIVE per-table settings
    as each table is attached at startup, so one of these here crash-loops the
    server exactly as the 2026-08-29 exit-36 incident did — and bypasses
    memory.xml's <merge_tree> block, where they are checked against the pool."""
    text = SYSTEM_LOGS.read_text()
    for name in POOL_THRESHOLD_SETTINGS:
        assert name not in text, (
            f"{name} is set in system-logs.xml; pool thresholds belong in "
            f"memory.xml's <merge_tree> block")


def test_no_log_uses_an_engine_clause():
    """SystemLog.cpp getLogSettings THROWS BAD_ARGUMENTS at startup if <engine>
    is combined with <ttl>, <partition_by>, <order_by>, <storage_policy> or
    <settings>. The <settings> form is used precisely so the TTL contract
    (#96a) and the merge contract can coexist."""
    for table, el in _enabled_logs().items():
        assert el.find("engine") is None, (
            f"system.{table} uses <engine> together with <ttl>/<settings> — "
            f"ClickHouse refuses to start")


def test_part_log_is_not_relocated_to_another_database():
    """Context::getPartLog returns {} when the SOURCE table's database is
    `system` (hard-coded to DatabaseCatalog::SYSTEM_DATABASE). Moving part_log
    elsewhere therefore does NOT make system-table merges visible; it only
    breaks every reader of `system.part_log`, including
    scripts/scale-miniladder.py and tests/test_clickhouse_merge_budget.py."""
    assert _enabled_logs()["part_log"].find("database") is None, (
        "part_log has been moved out of the system database — this does not "
        "make system.* merges loggable and breaks every system.part_log reader")


# ── the proof: metric_log can never take the Wide+Horizontal path ───────────

def test_metric_log_danger_band_is_empty():
    """THE CENTRAL ASSERTION.

    Band = {merge : output Wide AND algorithm Horizontal}. With the shipped
    settings it is empty for EVERY row count, not merely for the ones the
    3-day TTL allows:

        Wide      requires rows >= min_rows_for_wide_part            = 1e8
        Horizontal requires rows <  vertical_..._min_rows_to_activate = 1
                            or  cols < vertical_..._min_columns_to_activate = 1

    and 997 columns >= 1 while no integer satisfies rows >= 1e8 and rows < 1.
    """
    s = _settings_of("metric_log")
    for rows in _row_counts_to_probe():
        assert not _in_danger_band(rows, METRIC_LOG_COLUMNS,
                                   METRIC_LOG_BYTES_PER_ROW, s), (
            f"a {rows}-row metric_log merge is Wide AND Horizontal: "
            f"{METRIC_LOG_COLUMNS} column write streams at once — the exact "
            f"s06 failure mode")
    # And the analytic statement the sweep samples.
    assert (s["vertical_merge_algorithm_min_rows_to_activate"]
            <= s["min_rows_for_wide_part"])
    assert (s["vertical_merge_algorithm_min_columns_to_activate"]
            <= METRIC_LOG_COLUMNS)
    assert (s["vertical_merge_algorithm_min_bytes_to_activate"]
            <= s["min_bytes_for_wide_part"])


def test_the_band_model_still_reproduces_the_measured_failure():
    """MUTANT / self-check: the same model, fed the ClickHouse 24.8 STOCK
    settings, must report the measured part (Wide, 13,693 rows) as inside the
    band — otherwise the test above passes because the model is blind, not
    because the configuration is safe."""
    stock = dict(CH_24_8_STOCK)
    assert _in_danger_band(MEASURED_WIDE_PART_ROWS, METRIC_LOG_COLUMNS,
                           METRIC_LOG_BYTES_PER_ROW, stock), (
        "the model no longer reproduces the s06 defect on stock settings")
    # The band's stock edges, from the brief: ~10,330 rows to 131,072 rows.
    low = CH_24_8_STOCK["min_bytes_for_wide_part"] // METRIC_LOG_BYTES_PER_ROW
    assert low == 10330
    assert not _in_danger_band(low - 1, METRIC_LOG_COLUMNS,
                               METRIC_LOG_BYTES_PER_ROW, stock)
    assert _in_danger_band(low + 1, METRIC_LOG_COLUMNS,
                           METRIC_LOG_BYTES_PER_ROW, stock)
    assert not _in_danger_band(
        CH_24_8_STOCK["vertical_merge_algorithm_min_rows_to_activate"],
        METRIC_LOG_COLUMNS, METRIC_LOG_BYTES_PER_ROW, stock)


# The band is non-empty iff the smallest Wide part is smaller than the smallest
# Vertical merge, i.e.
#     W := max(min_rows_for_wide_part, ceil(min_bytes_for_wide_part / bytes_per_row))
#     band non-empty  <=>  W < vertical_merge_algorithm_min_rows_to_activate
#                          (given columns >= ..._min_columns_to_activate and
#                           vertical ..._min_bytes_to_activate <= min_bytes_for_wide_part)
# Stock, for ANY table whose rows exceed 10,485,760 / 131,072 = 80 B:
#     W = 10,485,760 / bytes_per_row  <  131,072   ->  band non-empty.
# That is the general statement behind the s06 incident; metric_log's 1,015 B
# rows put W at 10,330.

def _band_open(settings: dict[str, int], columns: int, bytes_per_row: int) -> bool:
    return any(_in_danger_band(rows, columns, bytes_per_row, settings)
               for rows in _row_counts_to_probe())


def test_stock_settings_leave_the_band_open_for_any_normal_row_size():
    """The general form of the defect, so the mutants below are measured against
    a model that is known to detect it: at stock, every table with rows larger
    than 80 B has a non-empty Wide+Horizontal band."""
    assert (CH_24_8_STOCK["min_bytes_for_wide_part"]
            // CH_24_8_STOCK["vertical_merge_algorithm_min_rows_to_activate"]) == 80
    for bytes_per_row in (81, 200, METRIC_LOG_BYTES_PER_ROW, 4096):
        assert _band_open(dict(CH_24_8_STOCK), METRIC_LOG_COLUMNS, bytes_per_row), (
            f"the model no longer detects the stock band at {bytes_per_row} B/row")


@pytest.mark.parametrize("table", sorted(set(EXPECTED_TTL_DAYS) - {"metric_log"}))
def test_the_shared_vertical_guard_is_the_only_guard_those_logs_have(table):
    """MUTANT. query_log / part_log / asynchronous_metric_log / trace_log keep
    the STOCK wide-part thresholds — they are not held Compact, because none of
    them is a 997-column table. Their whole defence is
    `vertical_merge_algorithm_min_rows_to_activate = 1`. Revert it and the band
    reopens, i.e. the setting is load-bearing rather than decorative."""
    s = _settings_of(table)
    assert not _band_open(s, METRIC_LOG_COLUMNS, METRIC_LOG_BYTES_PER_ROW)
    mutant = dict(s)
    mutant["vertical_merge_algorithm_min_rows_to_activate"] = (
        CH_24_8_STOCK["vertical_merge_algorithm_min_rows_to_activate"])
    assert _band_open(mutant, METRIC_LOG_COLUMNS, METRIC_LOG_BYTES_PER_ROW), (
        f"system.{table}: reverting the vertical row threshold does NOT reopen "
        f"the band — the model is blind and this file proves nothing")


def test_metric_log_survives_losing_either_guard_alone():
    """Defence in depth, stated as a test. metric_log carries TWO independent
    guards; each alone closes the band:

      * Compact by construction (min_rows_for_wide_part / min_bytes_for_wide_part)
      * Wide implies Vertical (vertical_..._min_rows/columns_to_activate)
    """
    s = _settings_of("metric_log")

    lost_vertical = dict(s)
    for name in ("vertical_merge_algorithm_min_rows_to_activate",
                 "vertical_merge_algorithm_min_columns_to_activate",
                 "vertical_merge_algorithm_min_bytes_to_activate"):
        lost_vertical[name] = CH_24_8_STOCK[name]
    assert not _band_open(lost_vertical, METRIC_LOG_COLUMNS,
                          METRIC_LOG_BYTES_PER_ROW), (
        "with the vertical settings at stock, the Compact guard no longer "
        "holds metric_log out of the band")

    lost_compact = dict(s)
    for name in ("min_rows_for_wide_part", "min_bytes_for_wide_part"):
        lost_compact[name] = CH_24_8_STOCK[name]
    assert not _band_open(lost_compact, METRIC_LOG_COLUMNS,
                          METRIC_LOG_BYTES_PER_ROW), (
        "with the wide-part thresholds at stock, the vertical settings no "
        "longer hold metric_log out of the band")


def test_metric_log_band_reopens_when_both_guards_are_reverted():
    """MUTANT, the strong form: revert BOTH guards and the band must reopen
    exactly where s06 measured it — the Wide, 13,693-row part."""
    mutant = dict(_settings_of("metric_log"))
    for name in ("min_rows_for_wide_part", "min_bytes_for_wide_part",
                 "vertical_merge_algorithm_min_rows_to_activate",
                 "vertical_merge_algorithm_min_columns_to_activate"):
        mutant[name] = CH_24_8_STOCK[name]
    assert _in_danger_band(MEASURED_WIDE_PART_ROWS, METRIC_LOG_COLUMNS,
                           METRIC_LOG_BYTES_PER_ROW, mutant), (
        "reverting every guard no longer reproduces the measured s06 part; "
        "the proof in this file is not testing what it claims")


def test_vertical_column_threshold_covers_the_narrow_logs_too():
    """asynchronous_metric_log has FOUR columns (event_date, event_time, metric,
    value), below the stock vertical_..._min_columns_to_activate = 11, so at
    stock it could never use the vertical algorithm at any size. Four streams is
    cheap, so this is not the s06 failure — but it is why the shared block pins
    the column threshold at 1 instead of relying on the stock value."""
    assert CH_24_8_STOCK["vertical_merge_algorithm_min_columns_to_activate"] > 4
    s = _settings_of("asynchronous_metric_log")
    assert s["vertical_merge_algorithm_min_columns_to_activate"] <= 4
    assert not _band_open(s, 4, 20)
    mutant = dict(s)
    mutant["vertical_merge_algorithm_min_columns_to_activate"] = (
        CH_24_8_STOCK["vertical_merge_algorithm_min_columns_to_activate"])
    mutant["vertical_merge_algorithm_min_rows_to_activate"] = (
        CH_24_8_STOCK["vertical_merge_algorithm_min_rows_to_activate"])
    assert _band_open(mutant, 4, 200), (
        "a 4-column table at stock thresholds should sit in the band")


def test_metric_log_stays_compact_across_the_whole_ttl_horizon():
    """ARITHMETIC (brief section 3 + the 3-day TTL in system-logs.xml):

        collect_interval_milliseconds = 1000  ->  86,400 rows/day
        3-day TTL                          ->  259,200 rows
        1,015 B/row                        ->  263,088,000 B = 250.9 MiB

    Wide needs BOTH 1e8 rows and 1 GiB. Margins: 385.8x on rows, 4.1x on bytes.
    """
    s = _settings_of("metric_log")
    rows_per_day = SECONDS_PER_DAY * 1000 // _child_int(
        "metric_log", "collect_interval_milliseconds")
    assert rows_per_day == 86400
    horizon_rows = rows_per_day * METRIC_LOG_TTL_DAYS
    horizon_bytes = horizon_rows * METRIC_LOG_BYTES_PER_ROW
    assert horizon_rows == 259200
    assert horizon_bytes == 263088000

    assert not _is_wide(horizon_rows, horizon_bytes, s), (
        "a full 3-day metric_log corpus would already be a Wide part")
    assert s["min_rows_for_wide_part"] / horizon_rows > 100, (
        "less than 100x of row headroom before metric_log parts turn Wide")
    assert s["min_bytes_for_wide_part"] / horizon_bytes > 4, (
        "less than 4x of byte headroom before metric_log parts turn Wide")


def test_worst_case_horizontal_writer_fits_the_merge_budget():
    """The residual risk the compress-block pair bounds: a TTL merge is forced
    Horizontal (MergeTask.cpp:1314) BEFORE the part-type test, so a legacy Wide
    part expiring under the TTL is Wide+Horizontal whatever else is set.

        997 x (2 x max_compress_block_size + 68 KiB of mark buffers)

    at 64 KiB   ->  ~191 MiB      (shipped)
    at 1 MiB    ->  ~2,061 MiB    (stock — 50 % of the whole server cap)
    """
    s = _settings_of("metric_log")
    per_stream = 2 * s["max_compress_block_size"] + 68 * KIB
    worst = METRIC_LOG_COLUMNS * per_stream
    assert worst < 256 * MIB, (
        f"worst-case Horizontal writer for a Wide metric_log part is "
        f"{worst / MIB:.0f} MiB")
    stock_worst = METRIC_LOG_COLUMNS * (
        2 * CH_24_8_STOCK["max_compress_block_size"] + 68 * KIB)
    assert stock_worst > 2 * GIB, "stock arithmetic drifted; re-derive"
    assert worst * 10 < stock_worst, (
        "the compress-block cap no longer buys an order of magnitude")
    assert s["min_compress_block_size"] <= s["max_compress_block_size"], (
        "min_compress_block_size above max_compress_block_size is incoherent")


# ── cadence: the harness's only ClickHouse memory instrument ────────────────

def test_metric_log_keeps_one_second_resolution():
    """scripts/scale-miniladder.py reads max()/countIf() of
    CurrentMetric_MemoryTracking and CurrentMetric_MergesMutationsMemoryTracking
    from system.metric_log over the run window — that is the ENTIRE ClickHouse
    memory gate. The s06 finding is that a clean run and a failing run have
    identical medians (1.25-1.40 GiB) and differ only by 13 ONE-SECOND
    transients. At a 60 s cadence the chance of catching a given 1 s transient
    is 1/60, i.e. an expected 0.2 of s06's 13. Coarsening the cadence would
    blind the gate to the exact failure it exists to detect; the merge cost
    that made 1 s expensive is removed by the settings above instead."""
    assert _child_int("metric_log", "collect_interval_milliseconds") == 1000
    reader = (ROOT / "scripts" / "scale-miniladder.py").read_text()
    assert "system.metric_log" in reader, (
        "the harness no longer reads system.metric_log — re-derive the cadence "
        "argument against whatever replaced it before changing this")
    assert "CurrentMetric_MemoryTracking" in reader


@pytest.mark.parametrize("table", sorted(EXPECTED_TTL_DAYS))
def test_flush_interval_is_bounded_by_how_the_harness_reads_the_logs(table):
    """Raising flush_interval_milliseconds cuts initial part creation (fewer,
    bigger inserts -> fewer merges), so it is a real lever. What bounds it is
    the READER: scripts/scale-miniladder.py queries system.metric_log for the
    run window as soon as the window closes, and a log flushes at most once per
    interval, so anything not yet flushed when the harness reads is simply
    missing — including a 1-second transient in the run's last seconds, which
    is exactly the signal the gate exists to catch.

    Stated as a conditional invariant rather than a fixed number, so this does
    not go falsely red when the harness gains an explicit flush:

      * harness does NOT issue SYSTEM FLUSH LOGS  ->  interval <= 7500 ms
      * harness DOES                              ->  the tail is forced out
                                                      and up to 60 s is fine
    """
    interval = _child_int(table, "flush_interval_milliseconds")
    harness = (ROOT / "scripts" / "scale-miniladder.py").read_text().upper()
    flushes = "FLUSH LOGS" in harness
    ceiling = 60_000 if flushes else 7500
    assert interval <= ceiling, (
        f"system.{table}: flush_interval_milliseconds = {interval} ms exceeds "
        f"{ceiling} ms; the harness "
        + ("flushes explicitly but this is still unreasonably coarse"
           if flushes else
           "does NOT issue SYSTEM FLUSH LOGS, so up to that much of the run's "
           "tail is never written before it reads the window"))
    assert interval >= 1000, (
        f"system.{table}: flushing every {interval} ms creates a part per "
        f"flush — that is the merge churn this whole file is about")


# ── the profiler contract: a sink AND a step ────────────────────────────────

def test_trace_log_exists_as_the_memory_profilers_sink():
    """P2/s06 section 0: total_memory_profiler_step was set and produced
    nothing, because system.trace_log did not exist. Both halves are now
    pinned, in the two files, and neither is useful alone."""
    assert "trace_log" in _enabled_logs(), (
        "system.trace_log is disabled again — memory_profiler_step /"
        " total_memory_profiler_step have no sink and merge memory can only be "
        "attributed by arithmetic")
    mem = ET.fromstring(MEMORY_XML.read_text())
    step = mem.find("total_memory_profiler_step")
    assert step is not None and step.text and int(step.text) == 4 * MIB, (
        "total_memory_profiler_step is not pinned at 4 MiB in memory.xml — "
        "with trace_log enabled this is what emits trace_type='Memory' stacks "
        "for the GLOBAL tracker, background merge threads included")


def test_allocation_sampling_stays_off_by_default():
    """total_memory_tracker_sample_probability is a probability PER ALLOCATION
    (trace_type='MemorySample'), so its cost scales with allocation churn, not
    with memory growth — unbounded in principle. The 4 MiB step profiler is
    bounded by construction (~950 rows for s06's 3.8 GiB ramp) and already
    answers the question. Turn this on for ONE diagnostic run, not for the
    steady state."""
    mem = ET.fromstring(MEMORY_XML.read_text())
    prob = mem.find("total_memory_tracker_sample_probability")
    assert prob is not None and prob.text is not None, (
        "total_memory_tracker_sample_probability is not pinned in memory.xml")
    assert float(prob.text) == 0.0, (
        f"allocation sampling is ON at p={prob.text.strip()} — bound the cost "
        f"and document the run it is for, or put it back to 0")


def test_asynchronous_metric_log_is_enabled_for_rss_and_jemalloc_history():
    """The other missing instrument: without it there is no history of
    MemoryResident, jemalloc.retained (21.65 GiB live at the time) or
    MarkCacheBytes, so candidate 2 of the s06 ranking (allocator dirty-page
    retention) cannot be quantified at all."""
    assert "asynchronous_metric_log" in _enabled_logs()
    assert EXPECTED_TTL_DAYS["asynchronous_metric_log"] == 3


def test_asynchronous_metrics_period_is_left_alone():
    """AsynchronousMetrics is the tick that hard-sets CurrentMetric_MemoryTracking
    to process RSS (MemoryTracker::setRSS, brief section 1). Slowing it to cut
    asynchronous_metric_log volume would coarsen the harness's peak signal by
    the same factor — the 1 s cadence argument again, one layer down.

    Checked as an ELEMENT, not a substring: both names appear in the prose of
    system-logs.xml, which is where the reasoning belongs."""
    for xml_name in ("memory.xml", "system-logs.xml", "custom-settings.xml"):
        root = ET.fromstring((CH / xml_name).read_text())
        for name in ("asynchronous_metrics_update_period_s",
                     "asynchronous_heavy_metrics_update_period_s"):
            assert root.find(name) is None, (
                f"<{name}> is set in {xml_name}; it must stay at the 1 s "
                f"default or the RSS series the gate reads gets coarser")
