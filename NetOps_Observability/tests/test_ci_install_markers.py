# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""install.py `@CX@` marker checks for the CI re-run leg (scripts/ci/install_markers.py).

Installer self-healing FMEA 2026-09-15 §5 (CI real boot, item 3): a second
install over the first must exit 0 and must not regress. Until the install
journal (§4.1) lands, "not regress" means the same stage sequence; once it
lands, the bundle stage must be skipped and kafka-acls must still run.

Run:  python3 -m pytest tests/test_ci_install_markers.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import install_markers as im


def stage(sid: str, status: str) -> str:
    return "@CX@ " + json.dumps({"kind": "stage", "id": sid, "title": sid,
                                 "status": status}, separators=(",", ":"))


def run_log(ids: list[str], result: str = "ok", *, skipped: tuple[str, ...] = (),
            fail_at: str | None = None) -> list[str]:
    lines = ["=== checking prerequisites ===", "[ ok  ] docker present"]
    for sid in ids:
        if sid in skipped:
            lines.append(stage(sid, "skipped"))
            continue
        lines.append(stage(sid, "start"))
        lines.append(f"=== {sid} ===")
        if sid == fail_at:
            lines.append(stage(sid, "fail"))
            break
        lines.append(stage(sid, "ok"))
    if result:
        lines.append("@CX@ " + json.dumps({"kind": "result", "status": result}))
    return lines


TLS_RUN = ["prereq", "scaffold", "env", "tls-env", "data-dirs", "bootstrap-appstate",
           "bootstrap-kc", "up-a", "mint", "up-b", "kafka-acls", "status",
           "bootstrap-os", "bootstrap-kc", "bootstrap-grafana"]


def summary(lines: list[str]) -> im.RunSummary:
    return im.summarize(im.parse_markers(lines))


def test_the_stage_ids_are_the_installers_own_contract() -> None:
    # Guard against this file drifting from install.py: every id used here is
    # in PROGRESS_STAGES (read as text, so install.py is not imported/run).
    src = (ROOT / "scripts" / "install.py").read_text(encoding="utf-8")
    block = src[src.index("PROGRESS_STAGES = ("):]
    block = block[:block.index("\n)")]  # the tuple's own closing line
    for sid in set(TLS_RUN) | {"bundle"}:
        assert f'"{sid}"' in block, f"{sid} is not an install.py progress stage"


def test_marker_lines_parse_and_other_lines_are_ignored() -> None:
    assert im.parse_marker_line('@CX@ {"kind":"result","status":"ok"}') == \
        {"kind": "result", "status": "ok"}
    assert im.parse_marker_line('2026-09-15T04:00Z @CX@ {"kind":"x"}') == {"kind": "x"}
    assert im.parse_marker_line("[ ok  ] services started") is None
    assert im.parse_marker_line("@CX@ {not json") is None
    assert im.parse_marker_line("@CX@ [1,2]") is None


def test_a_clean_run_passes() -> None:
    assert im.check_single(summary(run_log(TLS_RUN))) == []


def test_a_log_without_markers_is_not_a_pass() -> None:
    problems = im.check_single(summary(["=== status ===", "[ ok  ] fine"]))
    assert problems and "--progress-json" in problems[0]


def test_a_failed_stage_and_a_failed_result_are_reported() -> None:
    problems = im.check_single(summary(run_log(TLS_RUN, "fail", fail_at="up-b")))
    assert "run: stage up-b failed" in problems
    assert any("terminal result is 'fail'" in p for p in problems)


def test_a_stage_that_never_closed_is_reported() -> None:
    lines = run_log(TLS_RUN[:3], result="") + [stage("up-a", "start")]
    problems = im.check_single(summary(lines))
    assert "run: stage up-a started and never closed" in problems


def test_a_repeated_stage_id_is_two_occurrences() -> None:
    s = summary(run_log(TLS_RUN))
    assert s.ids.count("bootstrap-kc") == 2


def test_without_a_journal_the_rerun_must_repeat_the_sequence() -> None:
    first = summary(run_log(TLS_RUN))
    problems, notes = im.check_rerun(first, summary(run_log(TLS_RUN)), None)
    assert problems == [] and "no install journal" in notes[0]


def test_without_a_journal_a_missing_stage_is_a_regression() -> None:
    first = summary(run_log(TLS_RUN))
    second = summary(run_log([s for s in TLS_RUN if s != "kafka-acls"]))
    problems, _ = im.check_rerun(first, second, None)
    assert any("stage sequence differs" in p for p in problems)


def test_a_failed_rerun_fails() -> None:
    first = summary(run_log(TLS_RUN))
    problems, _ = im.check_rerun(first, summary(run_log(TLS_RUN, "fail",
                                                         fail_at="up-a")), None)
    assert "re-run: stage up-a failed" in problems


def test_when_the_first_run_failed_the_rerun_is_judged_on_its_own() -> None:
    first = summary(run_log(TLS_RUN, "fail", fail_at="up-b"))
    problems, notes = im.check_rerun(first, summary(run_log(TLS_RUN)), None)
    assert problems == [] and "judged on its own" in notes[0]


BUNDLE_RUN = ["prereq", "env", "bundle", "addon-pack", "up-a", "mint", "up-b",
              "kafka-acls", "status"]


def test_with_a_journal_the_bundle_stage_must_be_skipped() -> None:
    first = summary(run_log(BUNDLE_RUN))
    ran_again, _ = im.check_rerun(first, summary(run_log(BUNDLE_RUN)), {"stages": []})
    assert any("bundle stage ran again" in p for p in ran_again)
    skipped, _ = im.check_rerun(first, summary(run_log(BUNDLE_RUN,
                                                       skipped=("bundle",))), {})
    assert skipped == []
    absent, _ = im.check_rerun(first, summary(run_log([s for s in BUNDLE_RUN
                                                      if s != "bundle"])), {})
    assert absent == []


def test_with_a_journal_kafka_acls_is_never_skipped() -> None:
    first = summary(run_log(BUNDLE_RUN))
    second = summary(run_log(BUNDLE_RUN, skipped=("bundle", "kafka-acls")))
    problems, _ = im.check_rerun(first, second, {})
    assert any("kafka-acls must run" in p for p in problems)


def test_with_a_journal_an_unknown_stage_is_reported() -> None:
    first = summary(run_log(BUNDLE_RUN))
    second = summary(run_log(BUNDLE_RUN + ["surprise"], skipped=("bundle",)))
    problems, _ = im.check_rerun(first, second, {})
    assert "re-run: stage surprise did not exist in the first run" in problems


def test_the_online_ci_path_has_no_bundle_stage_so_the_journal_rule_is_quiet() -> None:
    # Honest about scope: CI builds images, so `bundle` never runs there and
    # the skip assertion cannot fire until CI installs from a bundle.
    first = summary(run_log(TLS_RUN))
    problems, _ = im.check_rerun(first, summary(run_log(TLS_RUN)), {})
    assert problems == []


def write(tmp_path: Path, name: str, lines: list[str]) -> str:
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def test_cli_check_and_check_rerun(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    one = write(tmp_path, "1.log", run_log(TLS_RUN))
    two = write(tmp_path, "2.log", run_log(TLS_RUN))
    assert im.main(["check", "--log", one]) == 0
    missing_journal = str(tmp_path / "does-not-exist.json")
    assert im.main(["check-rerun", "--first", one, "--second", two,
                    "--journal", missing_journal]) == 0
    assert "PASS" in capsys.readouterr().out


def test_cli_rerun_regression_exits_1(tmp_path: Path) -> None:
    one = write(tmp_path, "1.log", run_log(TLS_RUN))
    two = write(tmp_path, "2.log", run_log(TLS_RUN[:5], "fail", fail_at="data-dirs"))
    assert im.main(["check-rerun", "--first", one, "--second", two]) == 1


def test_cli_unreadable_input_is_could_not_assess(tmp_path: Path) -> None:
    one = write(tmp_path, "1.log", run_log(TLS_RUN))
    bad_journal = tmp_path / "journal.json"
    bad_journal.write_text("{truncated", encoding="utf-8")
    assert im.main(["check-rerun", "--first", one, "--second", one,
                    "--journal", str(bad_journal)]) == 2
    assert im.main(["check", "--log", str(tmp_path / "nope.log")]) == 2
