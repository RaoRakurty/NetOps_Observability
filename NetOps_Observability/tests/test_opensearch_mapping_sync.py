# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""bootstrap-opensearch.sh adds a template's NEW fields to each lane's current index.

Found live 2026-11-10 (tracker 387): after a deploy, syslog `title` and
`correlation_key` were on every new record but unsearchable, because the lanes are
`dynamic: false` and today's index predates the template change. The fix is
additive only: absent fields are added, a live field is never re-typed.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bootstrap-opensearch.sh"
HELPER = ROOT / "scripts" / "opensearch_mapping_sync.py"

sys.path.insert(0, str(ROOT / "scripts"))
import opensearch_mapping_sync as oms


def _settings(**created: int) -> dict:
    return {idx: {"settings": {"index": {"creation_date": str(ms)}}} for idx, ms in created.items()}


# ---- the pure helper -------------------------------------------------------

def test_targets_are_the_newest_index_of_each_series():
    s = _settings(**{
        "netops-syslog-untagged-2026.11.09": 100,
        "netops-syslog-untagged-2026.11.10": 200,
        "netops-syslog-retail-2026.11.10": 150,
        "netops-syslog-retail-2026.11.08": 50,
        "netops-quarantine": 10,
        ".opendistro-ism-config": 999,
    })
    assert oms.targets(s) == ["netops-quarantine", "netops-syslog-retail-2026.11.10",
                              "netops-syslog-untagged-2026.11.10"]


def test_creation_date_wins_over_the_name():
    # A re-created index of an older day is newer than its name suggests.
    s = _settings(**{"netops-flows-x-2026.11.10": 100, "netops-flows-x-2026.11.09": 300})
    assert oms.targets(s) == ["netops-flows-x-2026.11.09"]


def test_missing_adds_only_absent_fields_and_recurses_into_objects():
    want = {
        "title": {"type": "text"},
        "severity": {"type": "keyword"},
        "bgp": {"properties": {"state": {"type": "keyword"}, "peer_address": {"type": "ip"}}},
        "guidance": {"properties": {"impact": {"type": "text"}}},
    }
    have = {"severity": {"type": "keyword"}, "bgp": {"properties": {"state": {"type": "keyword"}}}}
    add, conflicts = oms.missing(want, have)
    assert add == {"title": {"type": "text"},
                   "bgp": {"properties": {"peer_address": {"type": "ip"}}},
                   "guidance": {"properties": {"impact": {"type": "text"}}}}
    assert conflicts == []


def test_a_retyped_field_is_reported_never_sent():
    add, conflicts = oms.missing({"asn": {"type": "long"}, "n": {"properties": {"x": {"type": "ip"}}}},
                                 {"asn": {"type": "keyword"}, "n": {"properties": {"x": {"type": "keyword"}}}})
    assert add == {}
    assert conflicts == ["asn: template long, live keyword", "n.x: template ip, live keyword"]


def test_object_versus_leaf_is_a_conflict_not_an_addition():
    add, conflicts = oms.missing({"peer": {"properties": {"ip": {"type": "ip"}}}}, {"peer": {"type": "keyword"}})
    assert add == {} and conflicts == ["peer: template object, live keyword"]


def _helper(args: list[str], stdin: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(HELPER)] + args, input=stdin,
                          capture_output=True, text=True, timeout=30, check=False)


@pytest.mark.parametrize("raw", ["", "<html>502</html>", "[]",
                                 '{"error":{"type":"security_exception"},"status":403}'])
def test_an_unreadable_answer_is_an_error_not_nothing_to_do(raw):
    r = _helper(["targets"], raw)
    assert r.returncode == 2 and r.stdout == ""


def test_missing_subcommand_end_to_end(tmp_path):
    tpl = tmp_path / "t.json"
    tpl.write_text(json.dumps({"templates": {"netops-syslog": {"template": {"mappings": {
        "dynamic": False, "properties": {"title": {"type": "text"}, "ts": {"type": "date"}, "n": {"type": "long"}}}}}}}))
    live = json.dumps({"netops-syslog-a-2026.11.10": {"mappings": {"properties": {
        "ts": {"type": "date"}, "n": {"type": "keyword"}}}}})
    r = _helper(["missing", str(tpl), "netops-syslog"], live)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"properties": {"title": {"type": "text"}}}
    assert "n: template long, live keyword" in r.stderr
    # Already complete: no body at all, so the script sends nothing.
    done = json.dumps({"i": {"mappings": {"properties": {"title": {"type": "text"}, "ts": {"type": "date"},
                                                        "n": {"type": "long"}}}}})
    r = _helper(["missing", str(tpl), "netops-syslog"], done)
    assert r.returncode == 0 and r.stdout == ""


# ---- the script, against a fake docker --------------------------------------

_FAKE_DOCKER = """#!/usr/bin/env bash
{ printf '%s\\n' "----"; for a in "$@"; do printf '%s\\n' "$a"; done; } >> "$ARGV_LOG"
body=$(cat)
put=0
for a in "$@"; do [ "$a" = "PUT" ] && put=1; done
for a in "$@"; do
  case "$a" in
    */_cluster/health) exit 0 ;;
    */_index_template/*) printf '{"acknowledged":true}\\n'; exit 0 ;;
    */_settings/index.creation_date*) cat "$FAKE_SETTINGS"; exit 0 ;;
    */_mapping)
      if [ "$put" = 1 ]; then printf '%s\\n' "$body" >> "${ARGV_LOG}.puts"; cat "$FAKE_PUT_REPLY"; exit 0; fi
      cat "$FAKE_MAPPING"; exit 0 ;;
  esac
done
exit 0
"""

TEMPLATE = {"templates": {"netops-syslog": {
    "index_patterns": ["netops-syslog-*"],
    "template": {"mappings": {"dynamic": False, "properties": {
        "ts": {"type": "date"}, "title": {"type": "text"}, "correlation_key": {"type": "keyword"}}}},
}}}


def _run(tmp_path: Path, settings: str, mapping: str, put_reply: str = '{"acknowledged":true}'):
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, repo / "scripts" / SCRIPT.name)
    shutil.copy(HELPER, repo / "scripts" / HELPER.name)
    osdir = repo / "deployment" / "docker" / "opensearch"
    osdir.mkdir(parents=True)
    (repo / "deployment" / "docker" / "docker-compose.yml").write_text("services: {}\n")
    (repo / "deployment" / "docker" / ".env").write_text("COMPOSE_FILE=docker-compose.yml\n")
    (osdir / "index-templates.json").write_text(json.dumps(TEMPLATE))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "docker"
    fake.write_text(_FAKE_DOCKER)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    for name, text in (("settings.json", settings), ("mapping.json", mapping), ("put.json", put_reply)):
        (tmp_path / name).write_text(text)
    log = tmp_path / "argv.log"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "ARGV_LOG": str(log),
           "FAKE_SETTINGS": str(tmp_path / "settings.json"), "FAKE_MAPPING": str(tmp_path / "mapping.json"),
           "FAKE_PUT_REPLY": str(tmp_path / "put.json"), "OS_READY_ATTEMPTS": "2", "OS_READY_SLEEP": "0"}
    env.pop("OPENSEARCH_URL", None)
    r = subprocess.run(["bash", str(repo / "scripts" / SCRIPT.name)], capture_output=True, text=True,
                       env=env, timeout=120, check=False)
    puts = (tmp_path / "argv.log.puts").read_text() if (tmp_path / "argv.log.puts").exists() else ""
    return r, (log.read_text() if log.exists() else ""), puts


SETTINGS = json.dumps(_settings(**{"netops-syslog-untagged-2026.11.09": 1, "netops-syslog-untagged-2026.11.10": 2}))
OLD_MAPPING = json.dumps({"netops-syslog-untagged-2026.11.10": {"mappings": {"properties": {"ts": {"type": "date"}}}}})


def test_new_fields_reach_todays_index_and_only_todays(tmp_path):
    r, argv, puts = _run(tmp_path, SETTINGS, OLD_MAPPING)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "/netops-syslog-untagged-2026.11.10/_mapping" in argv
    assert "/netops-syslog-untagged-2026.11.09/_mapping" not in argv, "only the current index is touched"
    assert json.loads(puts) == {"properties": {"correlation_key": {"type": "keyword"}, "title": {"type": "text"}}}
    assert "→ netops-syslog-untagged-2026.11.10: added correlation_key, title" in r.stdout
    assert "SYNCED   (1): netops-syslog-untagged-2026.11.10" in r.stdout


def test_an_index_that_already_has_every_field_gets_no_put(tmp_path):
    full = json.dumps({"netops-syslog-untagged-2026.11.10": {"mappings": {"properties": {
        "ts": {"type": "date"}, "title": {"type": "text"}, "correlation_key": {"type": "keyword"}}}}})
    r, _, puts = _run(tmp_path, SETTINGS, full)
    assert r.returncode == 0, r.stdout + r.stderr
    assert puts == ""
    assert "SYNCED   (0)" in r.stdout and "SYNC FAILED (0)" in r.stdout


def test_no_index_yet_is_not_a_failure(tmp_path):
    r, _, puts = _run(tmp_path, "{}", "{}")
    assert r.returncode == 0, r.stdout + r.stderr
    assert puts == ""


@pytest.mark.parametrize("settings,mapping,reply", [
    ('{"error":{"type":"security_exception"},"status":403}', OLD_MAPPING, '{"acknowledged":true}'),
    (SETTINGS, "", '{"acknowledged":true}'),
    (SETTINGS, OLD_MAPPING, '{"error":{"type":"illegal_argument_exception"},"status":400}'),
])
def test_a_sync_that_cannot_finish_fails_loudly(tmp_path, settings, mapping, reply):
    r, _, _ = _run(tmp_path, settings, mapping, reply)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "!! mapping sync:" in r.stderr
    assert "until the next daily index" in r.stderr
    assert "APPLIED  (1): netops-syslog" in r.stdout, "the template itself still applied"
