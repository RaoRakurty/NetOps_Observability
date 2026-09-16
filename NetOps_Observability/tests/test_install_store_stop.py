# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""A clean postgres stop is proven by its log, not its exit code (FMEA T1 (d)).

stop_stores_cleanly() stops the stores before TLS phase B recreates them. An
exit code of 0 was taken as "clean". It is not proof: a wrapper can exit 0
around a postmaster that never finished, and the next start then runs crash
recovery (the .123 failure). postgres counts as stopped cleanly only when it
logged `database system is shut down` after the stop began.

No docker: every docker call goes through an injected runner.
Run:  python3 -m pytest tests/test_install_store_stop.py -v
"""

from __future__ import annotations

import sys
import types
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import install

# Recorded from netops-postgres-1 (2026-09-06): a clean fast shutdown.
PG_CLEAN_TAIL = ("2026-09-06 00:39:31.738 UTC [48] LOG:  shutting down\n"
                 "2026-09-06 00:39:36.055 UTC [1] LOG:  database system is shut down\n")
PG_UNFINISHED_TAIL = "2026-09-06 00:39:31.738 UTC [48] LOG:  shutting down\n"
FIXED_NOW = datetime(2026, 9, 15, 3, 11, 0, tzinfo=timezone.utc)


def fake_run(responses: dict, calls: list):
    """responses: "<argv[2]> <argv[3]>" -> (rc, stdout)."""
    def run(argv, **kw):
        calls.append(list(argv))
        rc, out = responses.get(" ".join(argv[2:4]), (0, ""))
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr="")
    return run


def stop(tmp_path, responses):
    calls: list[list[str]] = []
    install.stop_stores_cleanly(tmp_path, run=fake_run(responses, calls),
                                now=lambda: FIXED_NOW)
    return calls


def test_postgres_that_logged_its_shutdown_is_clean(tmp_path, capsys):
    stop(tmp_path, {"ps --status": (0, "postgres\nkafka\n"), "ps -a": (0, "0\n"),
                    "logs --since": (0, PG_CLEAN_TAIL)})
    out, err = capsys.readouterr()
    assert "postgres, kafka stopped cleanly" in out
    assert "crash recovery" not in err


def test_exit_zero_without_the_shutdown_line_is_not_called_clean(tmp_path, capsys):
    stop(tmp_path, {"ps --status": (0, "postgres\nkafka\n"), "ps -a": (0, "0\n"),
                    "logs --since": (0, PG_UNFINISHED_TAIL)})
    out, err = capsys.readouterr()
    assert "did not log 'database system is shut down'" in err
    assert "crash recovery" in err
    assert "kafka stopped cleanly" in out and "postgres, kafka stopped cleanly" not in out


def test_an_unreadable_log_is_reported_not_assumed_clean(tmp_path, capsys):
    stop(tmp_path, {"ps --status": (0, "postgres\n"), "ps -a": (0, "0\n"),
                    "logs --since": (1, "")})
    out, err = capsys.readouterr()
    assert "could not be read to confirm a clean shutdown" in err
    assert "stopped cleanly" not in out


def test_the_log_is_read_from_when_the_stop_began(tmp_path):
    calls = stop(tmp_path, {"ps --status": (0, "postgres\n"), "ps -a": (0, "0\n"),
                            "logs --since": (0, PG_CLEAN_TAIL)})
    verbs = [c[2] for c in calls]
    assert verbs.index("stop") < verbs.index("logs")
    logs = calls[verbs.index("logs")]
    assert logs[3:5] == ["--since", "2026-09-15T03:11:00Z"] and logs[-1] == "postgres"


def test_a_killed_postgres_is_reported_once_without_a_log_probe(tmp_path, capsys):
    calls = stop(tmp_path, {"ps --status": (0, "postgres\n"), "ps -a": (0, "137\n")})
    err = capsys.readouterr().err
    assert "was killed" in err
    assert not [c for c in calls if c[2] == "logs"]


def test_stores_other_than_postgres_need_no_log_probe(tmp_path, capsys):
    calls = stop(tmp_path, {"ps --status": (0, "kafka\nclickhouse\n"), "ps -a": (0, "0\n")})
    assert not [c for c in calls if c[2] == "logs"]
    assert "clickhouse, kafka stopped cleanly" in capsys.readouterr().out
