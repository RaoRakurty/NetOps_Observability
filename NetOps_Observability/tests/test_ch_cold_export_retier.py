"""ch-cold-export.sh late-arrival re-tiering (ultra #22, 2026-09-01).

The defect this pins: the export skipped any partition whose Parquet file
already existed (`[ -s "$out" ] && continue`). "Exported once" is not
"current" — rows landing in a CLOSED day after the nightly 02:17 run (late
ingest, engine catch-up) were never re-exported and were TTL-dropped
untiered, breaking the header's "deletes nothing not already tiered"
guarantee. With daily partitions the safe window shrank from ~a month to
hours.

The fix: the partition-listing query also returns sum(rows) from
system.parts (metadata, no scan); a per-table manifest
(<COLD_DIR>/<table>/.manifest.tsv, pid<TAB>rows) records the hot count at
export time. hot > tiered re-exports in place; hot == tiered skips; a file
with no manifest row (pre-manifest vintage) re-exports once to establish it;
hot < tiered keeps the larger cold file and warns.

Watchdog-suite style: the FULL script runs with a fake `docker` on PATH that
answers the two clickhouse-client calls (partition listing from $FAKE_PARTS,
Parquet export as fake bytes) and appends every SQL statement to $QUERY_LOG.
"""

import datetime as dt
import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ch-cold-export.sh"

FAKE_DOCKER = r'''#!/bin/sh
# Emulates `docker compose --project-directory X exec -T clickhouse
# clickhouse-client -q SQL`. The SQL is always the LAST argument.
for last; do :; done
printf '%s\n----\n' "$last" >> "$QUERY_LOG"
case "$last" in
  *system.parts*) cat "$FAKE_PARTS" ;;
  *"FORMAT Parquet"*) printf 'PARQUET-FAKE\n' ;;
esac
exit 0
'''

YDAY = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).strftime("%Y%m%d")
TOMORROW = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).strftime("%Y%m%d")


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _layout(tmp_path: Path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "docker", FAKE_DOCKER)
    cold = tmp_path / "cold"
    parts = tmp_path / "parts.tsv"
    qlog = tmp_path / "queries.log"
    qlog.write_text("")
    return bindir, cold, parts, qlog


def _run(tmp_path: Path, bindir: Path, cold: Path, parts: Path, qlog: Path, *args):
    env = os.environ.copy()
    env.update({
        "PATH": f"{bindir}:{env['PATH']}",
        "COMPOSE_DIR": str(tmp_path),
        "COLD_DIR": str(cold),
        "TABLES": "corr_objects",
        "FAKE_PARTS": str(parts),
        "QUERY_LOG": str(qlog),
    })
    return subprocess.run(["bash", str(SCRIPT), *args], env=env,
                          stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=60)


def _set_parts(parts: Path, rows) -> None:
    parts.write_text("".join(f"{pid}\t{bucket}\t{n}\n" for pid, bucket, n in rows))


def _export_count(qlog: Path) -> int:
    return qlog.read_text().count("FORMAT Parquet")


def _manifest(cold: Path) -> dict:
    path = cold / "corr_objects" / ".manifest.tsv"
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text().splitlines():
        pid, n = line.split("\t")
        out[pid] = n
    return out


def test_export_skip_and_late_arrival_reexport(tmp_path):
    """THE #22 regression: match -> skip, hot growth -> re-export."""
    bindir, cold, parts, qlog = _layout(tmp_path)
    _set_parts(parts, [("p1", YDAY, 100)])

    # First run: exports and records the count.
    r1 = _run(tmp_path, bindir, cold, parts, qlog)
    assert r1.returncode == 0, r1.stderr
    out_file = cold / "corr_objects" / "p1.parquet"
    assert out_file.read_text() == "PARQUET-FAKE\n"
    assert _manifest(cold) == {"p1": "100"}, _manifest(cold)
    assert _export_count(qlog) == 1
    assert "rows=100" in r1.stdout

    # Second run, unchanged hot count: the check runs, no export happens.
    r2 = _run(tmp_path, bindir, cold, parts, qlog)
    assert r2.returncode == 0, r2.stderr
    assert _export_count(qlog) == 1, "an unchanged partition must not re-export"
    assert "current: corr_objects p1 (hot=100 == tiered=100)" in r2.stdout

    # Late rows land in the CLOSED day: hot 100 -> 150. The old code skipped
    # forever on file existence and those 50 rows died untiered at the TTL.
    _set_parts(parts, [("p1", YDAY, 150)])
    r3 = _run(tmp_path, bindir, cold, parts, qlog)
    assert r3.returncode == 0, r3.stderr
    assert _export_count(qlog) == 2, (
        f"hot(150) > tiered(100) MUST re-export — the #22 defect.\n"
        f"stdout:\n{r3.stdout}\nstderr:\n{r3.stderr}")
    assert "late-arriving rows" in r3.stdout
    assert _manifest(cold) == {"p1": "150"}

    # And the new count settles: next run skips again.
    r4 = _run(tmp_path, bindir, cold, parts, qlog)
    assert _export_count(qlog) == 2, r4.stdout


def test_pre_manifest_file_reexports_once_to_establish_count(tmp_path):
    """A Parquet file from before the manifest existed has an unknown tiered
    count — it re-exports ONCE (bounded one-time cost), then skips."""
    bindir, cold, parts, qlog = _layout(tmp_path)
    _set_parts(parts, [("p1", YDAY, 100)])
    legacy = cold / "corr_objects"
    legacy.mkdir(parents=True)
    (legacy / "p1.parquet").write_text("LEGACY-EXPORT\n")

    r1 = _run(tmp_path, bindir, cold, parts, qlog)
    assert r1.returncode == 0, r1.stderr
    assert _export_count(qlog) == 1, "no manifest row -> establish by re-export"
    assert "no manifest row" in r1.stdout
    assert (legacy / "p1.parquet").read_text() == "PARQUET-FAKE\n"
    assert _manifest(cold) == {"p1": "100"}

    r2 = _run(tmp_path, bindir, cold, parts, qlog)
    assert _export_count(qlog) == 1, f"established file must now skip: {r2.stdout}"


def test_hot_shrink_keeps_larger_cold_file_and_warns(tmp_path):
    """hot < tiered means rows vanished from a closed HOT partition — never
    overwrite the (larger) cold file with the smaller set; warn loudly."""
    bindir, cold, parts, qlog = _layout(tmp_path)
    _set_parts(parts, [("p1", YDAY, 150)])
    r1 = _run(tmp_path, bindir, cold, parts, qlog)
    assert r1.returncode == 0, r1.stderr

    _set_parts(parts, [("p1", YDAY, 90)])
    r2 = _run(tmp_path, bindir, cold, parts, qlog)
    assert r2.returncode == 0, r2.stderr
    assert _export_count(qlog) == 1, "a shrunken hot partition must NOT re-export"
    assert "rows vanished from a closed hot partition" in r2.stderr
    assert _manifest(cold) == {"p1": "150"}, "the recorded tiered count must stand"


def test_open_partition_still_skipped_and_force_still_works(tmp_path):
    bindir, cold, parts, qlog = _layout(tmp_path)
    _set_parts(parts, [("p1", YDAY, 100), ("p2", TOMORROW, 10)])

    r1 = _run(tmp_path, bindir, cold, parts, qlog)
    assert r1.returncode == 0, r1.stderr
    assert _export_count(qlog) == 1
    assert "_partition_id = 'p2'" not in qlog.read_text(), (
        "a still-open day must never be exported")
    assert not (cold / "corr_objects" / "p2.parquet").exists()

    # --force bypasses the count check and re-exports (and re-records).
    r2 = _run(tmp_path, bindir, cold, parts, qlog, "--force")
    assert r2.returncode == 0, r2.stderr
    assert _export_count(qlog) == 2
    assert _manifest(cold) == {"p1": "100"}
