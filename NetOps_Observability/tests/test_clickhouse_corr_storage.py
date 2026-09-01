"""The correlation family's STORAGE SHAPE stays pinned to the measured fix.

Source of truth: docs/scale/P2_STEP5_2P5K_VERDICT_2026-08-29.md §3 and
docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29.md ("structural fix").

MEASURED on the live lab server, 2026-08-29:

    netops.corr_objects .............. 1,958,952 rows, 11 active parts, ALL in
                                       ONE partition ('global', 202608)
                                       3.51 GiB on disk / 48.9 GiB uncompressed
    `hypotheses` ..................... 46.01 GiB of that (94 %), LZ4 ratio 13.77
    worst accumulated part ........... 1.86 GiB at merge LEVEL 1,568
    merge write amplification ........ ~241x (1.40 GiB in -> 337.6 GiB merged)

MEASURED offline, 3,000 live `hypotheses` blobs (74.2 MB raw, 24.7 KB/row)
replayed through clickhouse-local 24.8 into four MergeTree tables differing only
in the column codec:

    LZ4 (stock default) .............. 13.94x   (agrees with the live 13.77x)
    ZSTD(1) .......................... 64.59x
    ZSTD(3) .......................... 89.70x   <- chosen, 6.4x better than LZ4
    ZSTD(6) ......................... 104.41x

The merge budget (tests/test_clickhouse_merge_budget.py) BOUNDS the symptom.
This file pins the two changes that remove its cause:

  (a) the blob is ZSTD(3), not LZ4;
  (b) every corr_* history table is partitioned DAILY on the very column its
      TTL is keyed on, so a finished partition stops being a merge candidate
      and ttl_only_drop_parts = 1 drops parts on the horizon instead of up to a
      month late.

Every assertion below is one of those measurements or a direct consequence.

Run:  PATH=/home/rao/.local/bin:$PATH python3 -m pytest tests/test_clickhouse_corr_storage.py -q
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INIT_SQL = ROOT / "deployment" / "docker" / "clickhouse" / "init.sql"
CHSCHEMA = ROOT / "src" / "backend" / "internal" / "chschema"
CORR_SCHEMA_GO = CHSCHEMA / "corr_schema.go"
CORR_REPART_GO = CHSCHEMA / "corr_repartition.go"
CORR_RETENTION_GO = CHSCHEMA / "corr_retention.go"
POLICIES_GO = CHSCHEMA / "policies.go"
GIB = 1024 ** 3

# ── the measured numbers this file exists to defend ─────────────────────────
LAB_CORR_OBJECTS_UNCOMPRESSED_BYTES = int(48.9 * GIB)   # 3.51 GiB on disk
MEASURED_LZ4_RATIO = 13.94
MEASURED_ZSTD3_RATIO = 89.70

# table -> the column its partition key AND its TTL must both be keyed on.
# corr_current is the ONE exception and is asserted separately.
CORR_DAILY_TABLES = {
    "corr_signals": "ts",
    "corr_signals_archive": "ts",
    "corr_objects": "created_at",
    "corr_edges": "created_at",
    "corr_evidence": "created_at",
    "corr_path_edges": "created_at",
    "corr_tenant_write_amp": "window_start",
}


# ── parsing helpers (same approach as test_clickhouse_merge_budget.py) ──────

def _init_sql_no_comments() -> str:
    """init.sql with `--` line comments stripped: several column comments carry
    a semicolon, so a naive statement split truncates before SETTINGS."""
    out = []
    for line in INIT_SQL.read_text().split("\n"):
        i = line.find("--")
        out.append(line if i < 0 else line[:i])
    return "\n".join(out)


def _init_create(table: str) -> str:
    sql = _init_sql_no_comments()
    start = sql.find(f"CREATE TABLE IF NOT EXISTS netops.{table}\n")
    assert start >= 0, f"init.sql has no CREATE for netops.{table}"
    end = sql.find(";", start)
    assert end > start, f"init.sql: unterminated CREATE for netops.{table}"
    return sql[start:end]


def _go_create(table: str) -> str:
    """The CREATE TABLE corr_schema.go emits, sliced up to the NEXT CREATE.

    Not to the closing backtick: corr_signals and corr_signals_archive are built
    by concatenating a shared `signalColumns` block, so their statements span
    several Go string literals."""
    go = CORR_SCHEMA_GO.read_text()
    start = go.find(f"`CREATE TABLE IF NOT EXISTS netops.{table}\n")
    assert start >= 0, f"corr_schema.go has no CREATE for netops.{table}"
    nxt = go.find("`CREATE TABLE IF NOT EXISTS netops.", start + 1)
    return go[start + 1:nxt if nxt > start else len(go)]


def _columns(stmt: str) -> str:
    """Just the column list of a CREATE — the slice helpers above may carry
    trailing prose, and a comment mentioning a column is not a column."""
    end = stmt.find("\nENGINE =")
    return stmt[:end] if end > 0 else stmt


def _clause(stmt: str, name: str) -> str:
    m = re.search(rf"^{name} (.+)$", stmt, re.M)
    return m.group(1).strip() if m else ""


def _init_corr_tables() -> set[str]:
    return set(re.findall(r"CREATE TABLE IF NOT EXISTS netops\.(corr_\w+)",
                          _init_sql_no_comments()))


# ── (a) the codec ───────────────────────────────────────────────────────────

def test_init_sql_pins_the_measured_codec_on_the_blob():
    """`hypotheses` is 46.01 of corr_objects' 48.9 GiB uncompressed (94 %), so it
    is what every re-merge rewrites. ZSTD(3) measured 89.70x against LZ4's
    13.94x on 3,000 live blobs — 6.4x less to read and write per merge."""
    stmt = _init_create("corr_objects")
    assert re.search(r"hypotheses\s+String CODEC\(ZSTD\(3\)\)", stmt), (
        "netops.corr_objects.hypotheses is not CODEC(ZSTD(3)); the stock LZ4 "
        "compresses this column 6.4x worse (13.94x vs 89.70x, MEASURED)")


def test_go_boot_converge_carries_the_identical_codec():
    """init.sql is the FRESH-install authority; corr_schema.go converges LIVE
    deployments. A fresh install and an upgraded one must store identically."""
    assert re.search(r"hypotheses\s+String CODEC\(ZSTD\(3\)\)", _go_create("corr_objects")), (
        "corr_schema.go's corr_objects CREATE does not carry the codec")
    go = CORR_SCHEMA_GO.read_text()
    assert ("ALTER TABLE netops.corr_objects MODIFY COLUMN hypotheses String CODEC(ZSTD(3))"
            in go), (
        "the boot converge has no MODIFY COLUMN for the codec — an EXISTING "
        "deployment would keep LZ4 forever")


def test_the_codec_change_is_metadata_only():
    """Verified on ClickHouse 24.8: a MODIFY COLUMN carrying only a codec change
    produced ZERO rows in system.mutations and left existing parts byte-identical
    (272.01 KiB before and after); the new codec took effect on the next merge
    (272.01 -> 20.17 KiB). That is why it can live in the boot converge list at
    all — if it mutated, it would rewrite a 48.9 GiB table on API start."""
    go = CORR_SCHEMA_GO.read_text()
    alter = "ALTER TABLE netops.corr_objects MODIFY COLUMN hypotheses"
    i = go.find(alter)
    assert i >= 0
    stmt = go[i:go.find("`", i)]
    assert "MATERIALIZE" not in stmt.upper(), (
        "the codec ALTER was turned into a materializing mutation — it would "
        "rewrite the whole table at boot")


def test_corr_current_carries_no_second_copy_of_the_blob():
    """The #100 narrow projection deliberately has NO wide blob columns, which is
    why the codec decision is made exactly once."""
    assert "hypotheses" not in _columns(_init_create("corr_current"))
    assert "hypotheses" not in _columns(_go_create("corr_current"))


def test_the_measured_ratios_are_recorded_where_the_decision_was_made():
    """A codec choice with no measurement beside it is a preference. The number
    that justified ZSTD(3) over LZ4 must stay next to the DDL."""
    for path in (INIT_SQL, CORR_SCHEMA_GO):
        text = path.read_text()
        assert "89.70" in text and "13.94" in text, (
            f"{path.name} states a codec but not the measurement that chose it")


# ── (b) daily partitions ────────────────────────────────────────────────────

@pytest.mark.parametrize("table,col", sorted(CORR_DAILY_TABLES.items()))
def test_init_sql_partitions_every_corr_history_table_daily(table, col):
    """A MONTH-long partition is never 'finished': its parts stay merge
    candidates for a month, so min_age_to_force_merge_on_partition_only can
    never fire and one part grows to 1.86 GiB at level 1,568 (MEASURED)."""
    want = f"(tenant_id, toYYYYMMDD({col}))"
    got = _clause(_init_create(table), "PARTITION BY")
    assert got == want, f"netops.{table} PARTITION BY {got}, want {want}"


@pytest.mark.parametrize("table,col", sorted(CORR_DAILY_TABLES.items()))
def test_go_boot_converge_partitions_identically(table, col):
    want = f"(tenant_id, toYYYYMMDD({col}))"
    got = _clause(_go_create(table), "PARTITION BY")
    assert got == want, f"corr_schema.go: netops.{table} PARTITION BY {got}, want {want}"


@pytest.mark.parametrize("table,col", sorted(CORR_DAILY_TABLES.items()))
def test_the_partition_column_is_the_ttl_column(table, col):
    """THE load-bearing invariant. With ttl_only_drop_parts = 1 a part drops only
    when EVERY row in it has expired, so a partition keyed on a different column
    than the TTL drops LATE. corr_objects was partitioned on window_start while
    its TTL was keyed on created_at: effective retention was the configured
    horizon plus up to a whole month."""
    fixed_ttl = _clause(_init_create(table), "TTL")
    if fixed_ttl:
        assert fixed_ttl.startswith(f"toDateTime({col})"), (
            f"netops.{table}: CREATE TTL {fixed_ttl!r} is not keyed on the "
            f"partition column {col!r}")
        return
    # Otherwise the TTL comes from the retention profile at boot.
    ret = CORR_RETENTION_GO.read_text()
    m = re.search(rf'ttl\("{table}", "toDateTime\((\w+)\)"', ret)
    if m is None:
        pytest.skip(f"{table} has no profile-driven TTL")
    assert m.group(1) == col, (
        f"netops.{table}: corr_retention.go keys the TTL on {m.group(1)!r} but "
        f"the partition is keyed on {col!r} — parts would drop late")


def test_corr_current_is_the_only_table_not_partitioned_by_date():
    """corr_current is a ReplacingMergeTree whose dedup key
    (tenant_id, correlation_id) may NOT span partitions or FINAL cannot collapse
    a re-persist. Its retention is a row-level DELETE WHERE TTL, not a part drop,
    so it gains nothing from finer partitions either."""
    assert _clause(_init_create("corr_current"), "PARTITION BY") == "(tenant_id)"
    assert _clause(_go_create("corr_current"), "PARTITION BY") == "(tenant_id)"
    assert _init_corr_tables() == set(CORR_DAILY_TABLES) | {"corr_current"}, (
        "a corr_* table was added or removed — give it a daily partition key on "
        "its TTL column and list it here, or document why it is an exception")


def test_no_corr_table_is_partitioned_monthly_anywhere():
    """Coverage, not a fixed list: the substring must not survive in ANY corr_*
    CREATE, in either schema authority."""
    for table in _init_corr_tables():
        for label, stmt in (("init.sql", _init_create(table)),
                            ("corr_schema.go", _go_create(table))):
            assert "toYYYYMM(" not in stmt, (
                f"{label}: netops.{table} still carries a MONTHLY date expression")


# ── (c) nothing in the codebase depends on monthly partitions ───────────────

def _sources() -> list[Path]:
    out: list[Path] = []
    for sub, globs in (("src", ("**/*.go", "**/*.py")),
                       ("scripts", ("**/*.sh", "**/*.py")),
                       ("deployment", ("**/*.sql", "**/*.sh"))):
        for g in globs:
            out += [p for p in (ROOT / sub).glob(g)
                    if "node_modules" not in p.parts and "__pycache__" not in p.parts]
    assert out, "source sweep found no files — path drift"
    return out


def test_no_code_path_assumes_a_monthly_corr_partition():
    """The one that would have shipped a silent bug: scripts/ch-cold-export.sh
    parsed the partition tuple with a 6-DIGIT month regex. Against a daily key
    ('acme', 20260803) that reads 202608 and compares it to the current month, so
    every day of the current month looks 'closed' and gets exported while still
    being written to.

    Every `toYYYYMM(` in the tree is examined in context: if a corr_* table name
    appears within the same statement-sized window, the file must justify itself
    in the allowlist below. The allowlist is the review, not the grep."""
    allowed = {
        # Keeps a --month filter so archives exported BEFORE the migration still
        # restore; gained a --day filter for the current daily partitions.
        "ch-cold-restore.sh",
        # Models a PRE-migration (monthly) table on purpose, to migrate it.
        "corr_repartition_test.go",
        # Prose only: the design note explaining what was replaced and why.
        "init.sql",
        "corr_merge_budget.go",
        "corr_repartition.go",
        "corr_schema.go",
    }
    corr = re.compile(r"\bcorr_(objects|edges|evidence|signals|path_edges|"
                      r"signals_archive|tenant_write_amp)\b")
    offenders = []
    for p in _sources():
        if p.name in allowed:
            continue
        text = p.read_text(errors="ignore")
        for m in re.finditer(r"toYYYYMM\(", text):
            window = text[max(0, m.start() - 250):m.end() + 250]
            if corr.search(window):
                offenders.append(f"{p.relative_to(ROOT)}:{text[:m.start()].count(chr(10)) + 1}")
    assert not offenders, (
        "these sites apply a MONTHLY date expression next to a corr_* table: "
        f"{sorted(offenders)}")


def test_the_allowlisted_schema_files_are_monthly_only_in_prose():
    """The four schema/design files above are allowlisted because they DISCUSS
    the old monthly key. Verify that: no CREATE they emit may still carry it
    (test_no_corr_table_is_partitioned_monthly_anywhere covers the DDL), and the
    only remaining occurrences must sit on comment lines."""
    for path in (INIT_SQL, CORR_SCHEMA_GO, CORR_REPART_GO,
                 CHSCHEMA / "corr_merge_budget.go"):
        prefix = "--" if path.suffix == ".sql" else "//"
        for i, line in enumerate(path.read_text().split("\n"), 1):
            if "toYYYYMM(" not in line:
                continue
            stripped = line.strip()
            if stripped.startswith(prefix):
                continue
            # init.sql/corr_schema.go: any live toYYYYMM( must be a non-corr table.
            assert not re.search(r"corr_", line), (
                f"{path.name}:{i} applies a monthly expression to a corr table: {stripped}")


def test_cold_export_handles_both_partition_vintages():
    """A fleet mid-upgrade has both daily and monthly corr partitions; the export
    must classify 'still open' correctly for each, and must not mistake digits in
    a TENANT ID for the date bucket (verified live: the naive regex read
    'tenant123456' as bucket 123456)."""
    sh = (ROOT / "scripts" / "ch-cold-export.sh").read_text()
    assert "d{6,8}" in sh, "cold export still parses a 6-digit month only"
    assert "current_day=" in sh and "current_month=" in sh, (
        "cold export compares one bucket size against the other")
    assert re.search(r"extract\(partition, ',\\+s\*\(\\+d\{6,8\}\)", sh), (
        "the partition-date capture is not anchored after the tuple's comma — a "
        "tenant id containing 6+ digits would be read as the date")


def test_cold_export_cron_guidance_is_daily():
    """Month-partitions justified a monthly cron. Day-partitions do not: a
    monthly export would leave up to a month of days untiered ahead of the TTL,
    which is exactly the data loss the cold tier exists to prevent."""
    sh = (ROOT / "scripts" / "ch-cold-export.sh").read_text()
    assert re.search(r"^#\s+17 2 \* \* \* ", sh, re.M), (
        "the cron example in ch-cold-export.sh is not daily")


def test_cold_restore_filters_on_each_table_partition_column():
    """The filter column must match how the requested ARCHIVE UNIT was grouped
    (ultra #26, 2026-09-01): --day = the current DAILY partition column
    (created_at for corr_objects since the re-partition), but --month = the
    PRE-MIGRATION monthly unit, and corr_objects' monthly archives were
    grouped by toYYYYMM(window_start) — filtering them by created_at put
    month-boundary rows into the adjacent month's restore set.
    Set-level behavior is pinned in test_ch_cold_restore_vintage.py."""
    sh = (ROOT / "scripts" / "ch-cold-restore.sh").read_text()
    assert 'corr_objects)             DAY_COL="created_at"; MONTH_COL="window_start"' in sh, (
        "corr_objects must restore --day by created_at (daily partition/TTL "
        "column) and --month by window_start (the old monthly grouping)")
    assert 'corr_edges|corr_evidence) DAY_COL="created_at"; MONTH_COL="created_at"' in sh, (
        "edges/evidence never changed column — day and month must agree on created_at")
    assert "--day)" in sh and "toYYYYMMDD(${DAY_COL})" in sh, (
        "ch-cold-restore.sh has no day-granularity filter for daily partitions")
    assert "toYYYYMM(${MONTH_COL})" in sh, (
        "the month filter must use the archive-grouping column, not a shared TS_COL")
    assert "TS_COL" not in sh, "a single shared TS_COL cannot serve both vintages"


# ── (d) the live-deployment migration and its gate ──────────────────────────

def test_the_repartition_gate_skips_the_measured_lab_table():
    """A partition-key change is a full table REWRITE. It must never happen by
    surprise at API boot on the lab's 48.9 GiB corr_objects."""
    go = CORR_REPART_GO.read_text()
    m = re.search(r"corrRepartitionDefaultMaxGiB\s+=\s+(\d+)", go)
    assert m, "the size gate default is gone"
    gate = int(m.group(1)) * GIB
    assert gate < LAB_CORR_OBJECTS_UNCOMPRESSED_BYTES, (
        f"the default gate ({m.group(1)} GiB) no longer skips the MEASURED "
        f"48.9 GiB corr_objects — a boot would rewrite it")
    assert "CORR_REPARTITION_MAX_GIB" in go, "the gate is not operator-configurable"


def test_the_gate_measures_uncompressed_bytes():
    """Not bytes on disk: the rewrite has to decompress, re-serialize and
    recompress. corr_objects is 3.51 GiB on disk but 48.9 GiB uncompressed — a
    disk-byte gate of 4 GiB would have let it through."""
    go = CORR_REPART_GO.read_text()
    assert "data_uncompressed_bytes" in go
    assert "MaxUncompressedBytes" in go


def test_the_migration_is_off_by_default_for_big_tables_and_explicit_to_force():
    go = CORR_REPART_GO.read_text()
    for knob in ("CORR_REPARTITION", "CORR_REPARTITION_MAX_GIB",
                 "CORR_REPARTITION_BATCH_ROWS", "CORR_REPARTITION_CATCHUP_PASSES",
                 "CORR_REPARTITION_DROP_OLD"):
        assert knob in go, f"{knob} is not read by the migration"
    assert 'CorrRepartitionForce = "force"' in go
    assert 'CorrRepartitionOff   = "off"' in go


def test_the_migration_never_destroys_the_pre_migration_data_implicitly():
    """The retained netops.<table>__premigration IS the rollback. Dropping it is
    an explicit operator decision."""
    go = CORR_REPART_GO.read_text()
    assert "corrRepartitionBackupSuffix     = \"__premigration\"" in go
    assert "DropOld" in go
    # The swap statement list must not contain a DROP.
    i = go.find("func CorrSwapStmts(")
    assert i >= 0
    body = go[i:go.find("\n}", i)]
    assert "DROP TABLE" not in body, (
        "the swap destroys the pre-migration table — there is no rollback")


def test_every_migration_read_carries_the_cross_tenant_scope():
    """CLAUDE.md §3a rule 4. The STRICT corr row policies filter SELECT on
    `tenant_scope`; a copy that ran under a scoped (or unset) value would copy
    ZERO rows and then 'verify' zero against zero."""
    go = CORR_REPART_GO.read_text()
    assert "const corrScope = \" SETTINGS tenant_scope = '__all__'\"" in go
    for builder in ("CorrPartitionKeysSQL", "CorrPartitionCountSQL",
                    "CorrTotalCountSQL", "CorrCopyPartitionStmts"):
        i = go.find(f"func {builder}(")
        assert i >= 0, f"{builder} is gone"
        body = go[i:go.find("\n}", i)]
        assert "corrScope" in body, (
            f"{builder} reads a corr table without the cross-tenant scope")


def test_the_shadow_table_is_policy_protected_before_it_holds_data():
    """§3a has no grace period: the STRICT policy is created with the table, not
    after the copy."""
    go = CORR_REPART_GO.read_text()
    i = go.find("func CorrShadowCreateStmts(")
    body = go[i:go.find("\n}", i)]
    assert "StrictRowPolicyDDL(shadow)" in body
    assert body.find("CREATE TABLE IF NOT EXISTS") < body.find("StrictRowPolicyDDL(shadow)")


def test_the_migration_is_wired_into_boot_but_not_into_the_ddl_list():
    """It has to read sizes, batch per partition, resume and verify — none of
    which a fire-and-forget DDL list can do — so it runs AFTER the converge list
    succeeds, not inside it."""
    policies = POLICIES_GO.read_text()
    assert "RunCorrRepartition" not in policies, (
        "the migration was put in the statement list; it cannot batch or verify there")
    boot = (ROOT / "src" / "backend" / "clickhouse_policies.go").read_text()
    assert "runCorrRepartition(base)" in boot, (
        "the migration exists but never runs")
    adapter = (ROOT / "src" / "backend" / "clickhouse_repartition.go").read_text()
    assert "chschema.RunCorrRepartition" in adapter


def test_the_migration_copies_in_bounded_per_partition_batches():
    go = CORR_REPART_GO.read_text()
    i = go.find("func CorrCopyPartitionStmts(")
    body = go[i:go.find("\n}", i)]
    assert "max_insert_block_size" in body, "the copy has no memory bound"
    assert "toHour(" in body, "an oversized day-partition is not sub-batched"
    assert "batchRows" in body


def test_the_swap_is_atomic_and_keeps_the_view_and_policies_valid():
    """EXCHANGE TABLES is atomic on the Atomic database engine netops uses, and
    row policies plus netops.corr_objects_latest bind to the table NAME — so both
    keep guarding/reading the right data across the swap with no window."""
    go = CORR_REPART_GO.read_text()
    i = go.find("func CorrSwapStmts(")
    body = go[i:go.find("\n}", i)]
    assert "EXCHANGE TABLES" in body
    assert "StrictRowPolicyDDL(t.Name)" in body, (
        "the STRICT policy is not re-emitted on the live name after the swap")


# ── (c) the findings dedup window (storm-s03, 2026-08-29) ───────────────────
#
# netops.findings is not a corr_* table, but it now depends on the SAME storage
# guarantee the correlation family does, and the guarantee is stated in three
# places that can drift apart independently: the fresh-install CREATE, the boot
# ALTER that converges existing installs, and the retry set in the Python
# service that is only safe because the other two hold.

def test_findings_carries_the_dedup_window_in_init_sql():
    """A findings insert that ends in an UNKNOWN outcome (transport read error
    mid-flight — one row lost that way on storm-s03 replica-3) is re-sent under
    a deterministic insert_deduplication_token. Without the window the server
    has nothing to match the token against and the retry APPENDS a second row,
    which is why the table was excluded from the retry set before this."""
    stmt = _init_create("findings")
    assert "non_replicated_deduplication_window = 1000" in stmt, (
        "netops.findings has no dedup window on a fresh install — the retry "
        "path would duplicate a finding instead of deduping it")


def test_findings_dedup_window_is_converged_on_existing_installs():
    """init.sql only ever runs on a virgin volume; every live install gets it
    from the idempotent, metadata-only boot ALTER."""
    policies = POLICIES_GO.read_text()
    assert ("ALTER TABLE netops.findings MODIFY SETTING "
            "non_replicated_deduplication_window = 1000") in policies, (
        "nothing converges the findings dedup window — an upgraded install "
        "would retry findings inserts with no server-side dedup behind them")


def test_the_python_retry_set_matches_the_ddl_it_claims():
    """CH_DEDUP_SAFE_TABLES is a claim ABOUT THIS DDL. If the table is in the
    set without the window, an ambiguous outcome duplicates; if it has the
    window but is not in the set, the row is thrown away for nothing."""
    main_py = (ROOT / "src" / "correlation" / "main.py").read_text()
    m = re.search(r"CH_DEDUP_SAFE_TABLES = frozenset\(\{(.*?)\}\)", main_py, re.S)
    assert m, "CH_DEDUP_SAFE_TABLES is no longer a literal frozenset"
    assert '"netops.findings"' in m.group(1), (
        "netops.findings carries the dedup window but is not in the retry set")
