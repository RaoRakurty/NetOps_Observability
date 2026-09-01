"""ch-cold-restore.sh archive-grouping date filters (ultra #26, 2026-09-01).

The defect this pins: an old-vintage `--month` restore of corr_objects
filtered rows by created_at, but the pre-migration monthly archives were
grouped by toYYYYMM(window_start) (init.sql "STORAGE SHAPE" — the daily
re-partition moved corr_objects to created_at). Set mismatch: a June window
persisted on Jul 1 sits in the June archive but was dropped by the filter,
while a May 31 window persisted Jun 1 was pulled in — each reachable only
under the adjacent month.

The fix: `--month` (the pre-migration archive unit) filters corr_objects by
window_start — the column its monthly archives were grouped by, and the
event-time month replay/audit consumers ask for; `--day` (the current daily
unit) keeps the daily partition/TTL column (created_at). The other tables
never changed column, so day and month agree for them.

Watchdog-suite style: the FULL script runs against a fake `docker` that logs
every SQL statement and SIMULATES the INSERT's WHERE filter over a fixture
row set spanning the month boundary, so the test asserts the actual restored
row SET, not just the SQL text.
"""

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ch-cold-restore.sh"

FAKE_DOCKER = r'''#!/bin/sh
# Emulates the docker calls ch-cold-restore.sh makes. For the INSERT, the
# date condition is parsed out of the SQL and applied to $FAKE_ROWS
# (id<SP>window_start_yyyymmdd<SP>created_at_yyyymmdd); matching ids append
# to $RESTORED — the simulated side table.
printf 'DOCKER %s\n' "$*" >> "$DOCKER_LOG"
case "$1" in cp) exit 0 ;; esac
for last; do :; done
case "$*" in
  *" ps -q clickhouse"*) echo cid-ch; exit 0 ;;
  *clickhouse-client*)
    printf '%s\n----\n' "$last" >> "$QUERY_LOG"
    case "$last" in
      *"INSERT INTO"*)
        cond=$(printf '%s' "$last" | grep -oE 'toYYYYMM(DD)?\((window_start|created_at|ts)\) = [0-9]+' | head -1)
        if [ -z "$cond" ]; then
            awk '{print $1}' "$FAKE_ROWS" >> "$RESTORED"
        else
            col=$(printf '%s' "$cond" | sed -E 's/^toYYYYMM(DD)?\(([a-z_]+)\).*$/\2/')
            val=${cond##* }
            gran=month; case "$cond" in toYYYYMMDD*) gran=day ;; esac
            awk -v col="$col" -v val="$val" -v gran="$gran" \
                '{ d = (col == "window_start") ? $2 : $3;
                   if (gran == "month") d = substr(d, 1, 6);
                   if (d == val) print $1 }' "$FAKE_ROWS" >> "$RESTORED"
        fi ;;
      *"SELECT count()"*) wc -l < "$RESTORED" ;;
    esac
    exit 0 ;;
esac
exit 0
'''

# The month-boundary fixture (the rows the #26 finding is about):
#   A — June window persisted Jul 1: IN the June monthly archive, was DROPPED
#   B — plain June row (both columns in June)
#   C — May 31 window persisted Jun 1: in the MAY archive, was PULLED IN
FIXTURE_ROWS = (
    "A 20260630 20260701\n"
    "B 20260601 20260601\n"
    "C 20260531 20260601\n"
)


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _layout(tmp_path: Path, table: str):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _write_exec(bindir / "docker", FAKE_DOCKER)
    cold = tmp_path / "cold"
    (cold / table).mkdir(parents=True, exist_ok=True)
    (cold / table / "deadbeef.parquet").write_text("PARQUET-FAKE\n")
    rows = tmp_path / "rows.txt"
    rows.write_text(FIXTURE_ROWS)
    restored = tmp_path / f"restored.{table}.txt"
    restored.write_text("")
    qlog = tmp_path / f"queries.{table}.log"
    qlog.write_text("")
    return bindir, cold, rows, restored, qlog


def _run(tmp_path: Path, table: str, *args):
    bindir, cold, rows, restored, qlog = _layout(tmp_path, table)
    env = os.environ.copy()
    env.update({
        "PATH": f"{bindir}:{env['PATH']}",
        "COMPOSE_DIR": str(tmp_path),
        "COLD_DIR": str(cold),
        "DOCKER_LOG": str(tmp_path / "docker.log"),
        "QUERY_LOG": str(qlog),
        "FAKE_ROWS": str(rows),
        "RESTORED": str(restored),
    })
    r = subprocess.run(["bash", str(SCRIPT), "--table", table, *args], env=env,
                       stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=60)
    ids = set(restored.read_text().split())
    return r, ids, qlog.read_text()


def test_month_restore_uses_window_start_and_lands_boundary_rows(tmp_path):
    """THE #26 regression: --month = the pre-migration archive unit, grouped
    by window_start for corr_objects — June's archive contents, exactly."""
    r, ids, sql = _run(tmp_path, "corr_objects", "--month", "202606")
    assert r.returncode == 0, r.stderr
    assert "toYYYYMM(window_start) = 202606" in sql, sql
    assert "toYYYYMM(created_at)" not in sql, (
        f"the old created_at month filter is the #26 defect:\n{sql}")
    assert ids == {"A", "B"}, (
        f"June's archive unit holds A (June window, persisted Jul 1) and B; "
        f"C belongs to May's. Got {ids}")
    assert "2 rows" in r.stdout, r.stdout


def test_day_restore_keeps_daily_partition_column(tmp_path):
    """--day selects a CURRENT daily partition, which is keyed on created_at
    for corr_objects — unchanged behavior."""
    r, ids, sql = _run(tmp_path, "corr_objects", "--day", "20260601")
    assert r.returncode == 0, r.stderr
    assert "toYYYYMMDD(created_at) = 20260601" in sql, sql
    assert ids == {"B", "C"}, f"the 20260601 daily partition holds B and C: {ids}"


def test_tables_that_never_changed_column_are_untouched(tmp_path):
    """corr_edges/evidence stayed on created_at and the archive on ts across
    the re-partition (granularity-only change): month == day column."""
    r, _, sql = _run(tmp_path, "corr_evidence", "--month", "202606")
    assert r.returncode == 0, r.stderr
    assert "toYYYYMM(created_at) = 202606" in sql, sql

    r, _, sql = _run(tmp_path, "corr_signals_archive", "--month", "202606")
    assert r.returncode == 0, r.stderr
    assert "toYYYYMM(ts) = 202606" in sql, sql
