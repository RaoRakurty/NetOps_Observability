# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Log-signature classifier (FMEA 2026-09-15 §4.4, rows 1, 5, 10, 15).

scripts/install_signatures.py is ONE table that every installer caller
(compose_up, wait_healthy, doctor, the wizard's failure panel,
deploy-qualify.sh) classifies container logs with. It only CLASSIFIES: an
action is a whitelisted word (wait / bootstrap:<name> / recreate:<service> /
fail) that a caller may carry out; the module never runs anything.

Pinned here:
  * every signature in the table has at least one realistic recorded log-line
    fixture, and each fixture classifies to exactly that signature — including
    the real lines from the .123 incident (§1.1) and the FMEA §4.4 list;
  * anything the table does not know is `unknown`, never a guess;
  * precedence: a severe class outranks a waiting one; among equals the most
    recent line wins;
  * the evidence line is redacted with install.py's _SECRETISH regex, and a
    captured key NAME is the only request-derived text a remedy may carry;
  * the action vocabulary is validated when the module loads;
  * the CLI reads bounded stdin and prints text or JSON.

Run:  python3 -m pytest tests/test_install_signatures.py -v
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import install_signatures as sigs

# ── recorded fixtures: signature id -> (service, real log line) ─────────────
# Lines are verbatim shapes of what these services print (timestamps and ids
# vary). The .123 postgres lines are from the 2026-09-15 incident log (§1.1).
FIXTURES: dict[str, list[tuple[str, str]]] = {
    "pg-crash-recovery": [
        ("postgres", ("2026-09-15 03:11:07.123 UTC [1] LOG:  database system was interrupted; "
                     "last known up at 2026-09-15 03:03:57 UTC")),
        ("postgres", ("2026-09-15 03:11:17.456 UTC [29] LOG:  syncing data directory (fsync), "
                     "elapsed time: 10.01 s, current path: ./base/16384/2619")),
        ("postgres", ("2026-09-15 03:12:54.001 UTC [29] LOG:  database system was not properly "
                     "shut down; automatic recovery in progress")),
        ("postgres", "2026-09-15 03:12:54.090 UTC [29] LOG:  redo starts at 0/1A2B3C8"),
        ("netops-postgres-1", ("2026-09-15 03:12:58.200 UTC [27] LOG:  checkpoint starting: "
                              "end-of-recovery immediate wait")),
    ],
    "pg-starting": [
        ("postgres", "2026-09-15 03:13:28.771 UTC [88] FATAL:  the database system is starting up"),
        ("postgres", ("2026-09-15 03:13:02.004 UTC [91] FATAL:  the database system is not yet "
                     "accepting connections")),
    ],
    "keycloak-db-missing": [
        ("keycloak", ("2026-09-15 03:40:12,345 ERROR [org.hibernate.engine.jdbc.spi.SqlExceptionHelper] "
                     "(JPA Startup Thread) FATAL: database \"keycloak\" does not exist")),
    ],
    "osd-empty-setting": [
        ("opensearch-dashboards", "FATAL  Error: --opensearch.password must have a value"),
    ],
    "compose-required-variable": [
        ("compose", ("error while interpolating services.api.environment.[]: required variable "
                    "JWT_SECRET is missing a value: JWT_SECRET required (install.py generates it)")),
    ],
    "kafka-authorization": [
        ("correlation", ("kafka.errors.TopicAuthorizationFailedError: [Error 29] "
                        "TopicAuthorizationFailedError: netops.events.raw")),
        ("vector-router", ("org.apache.kafka.common.errors.TopicAuthorizationException: "
                          "Not authorized to access topics: [netops.flows]")),
        ("api", "GroupAuthorizationException: Not authorized to access group: netops-router-a"),
    ],
    "kafka-authentication": [
        ("correlation", ("SaslAuthenticationException: Authentication failed during authentication "
                        "due to invalid credentials with SASL mechanism SCRAM-SHA-512")),
    ],
    "opensearch-flood-stage": [
        ("opensearch", ("[2026-09-05T10:11:12,345][WARN ][o.o.c.r.a.DiskThresholdMonitor] [opensearch] "
                       "flood stage disk watermark [95%] exceeded on [Xq1][opensearch]"
                       "[/usr/share/opensearch/data/nodes/0] free: 2.1gb[4.2%], all indices on this "
                       "node will be marked read-only")),
        ("vector-aggregator", ("ClusterBlockException[index [netops-applogs-2026.09.05] blocked by: "
                              "[TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark, index "
                              "has read-only-allow-delete block];]")),
        ("api", ("cluster_block_exception: index [netops-flows] blocked by: "
                "[FORBIDDEN/12/index read-only / allow delete (api)]; read_only_allow_delete")),
    ],
    "port-allocated": [
        ("syslog-ng", ("Error response from daemon: driver failed programming external connectivity on "
                      "endpoint netops-syslog-ng-1 (5b1c): Bind for 0.0.0.0:514 failed: port is "
                      "already allocated")),
        ("nginx", ("2026/09/15 03:20:01 [emerg] 1#1: bind() to 0.0.0.0:8443 failed "
                  "(98: Address already in use)")),
    ],
    "no-space": [
        ("postgres", ("2026-09-15 04:01:00.000 UTC [44] PANIC:  could not write to file "
                     "\"pg_wal/xlogtemp.44\": No space left on device")),
        ("compose", ("failed to register layer: write /var/lib/docker/overlay2/abc/diff/usr/lib/libx.so: "
                    "no space left on device")),
    ],
    "image-missing": [
        ("compose", "Error response from daemon: No such image: correlix/api:2026.09.15-ge8ebc980"),
        ("compose", ("Error response from daemon: pull access denied for correlix/frontend, repository "
                    "does not exist or may require 'docker login'")),
        ("compose", "Unable to find image 'correlix/prober:2026.09.15' locally"),
    ],
    "jvm-oom": [
        ("opensearch", "java.lang.OutOfMemoryError: Java heap space"),
        ("keycloak", "Terminating due to java.lang.OutOfMemoryError: Metaspace"),
    ],
    "runtime-oom": [
        ("api", "fatal error: runtime: out of memory"),
        ("compose", "Out of memory: Killed process 4242 (clickhouse-serv) total-vm:9123456kB"),
    ],
    "lsm-denial": [
        ("syslog-ng", ("audit: type=1400 audit(1757900000.123:88): apparmor=\"DENIED\" "
                      "operation=\"open\" profile=\"docker-default\" name=\"/var/lib/syslog-ng/\"")),
        ("postgres", ("type=AVC msg=audit(1757900000.5:12): avc:  denied  { write } for pid=77 "
                     "comm=\"postgres\" name=\"pgdata\" scontext=system_u:system_r:container_t:s0")),
    ],
    "daemon-down": [
        ("compose", ("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
                    "Is the docker daemon running?")),
    ],
    "osd-waiting-for-opensearch": [
        ("opensearch-dashboards", ("{\"type\":\"log\",\"@timestamp\":\"2026-09-15T03:30:00Z\","
                                  "\"tags\":[\"error\",\"opensearch\",\"data\"],\"pid\":1,"
                                  "\"message\":\"Unable to retrieve version information from "
                                  "OpenSearch nodes. connect ECONNREFUSED 172.20.0.9:9200\"}")),
    ],
}


def _table_ids() -> set[str]:
    return {s.sig_id for s in sigs.SIGNATURES}


# ── table completeness ──────────────────────────────────────────────────────

def test_every_signature_has_a_recorded_fixture_and_no_fixture_is_orphaned():
    assert set(FIXTURES) == _table_ids(), (
        "each table row needs a real log-line fixture here (FMEA §4.4); "
        f"missing={_table_ids() - set(FIXTURES)} orphaned={set(FIXTURES) - _table_ids()}")


def test_every_fmea_class_is_represented_in_the_table():
    assert {s.klass for s in sigs.SIGNATURES} == set(sigs.CLASSES) - {"unknown"}


@pytest.mark.parametrize(
    "sig_id,service,line",
    [(sid, svc, ln) for sid, rows in FIXTURES.items() for svc, ln in rows],
    ids=lambda v: v if isinstance(v, str) and len(v) < 40 else None,
)
def test_fixture_classifies_to_its_own_signature(sig_id: str, service: str, line: str):
    v = sigs.classify(service, line)
    assert v.sig_id == sig_id, f"{service}: {line!r} -> {v.sig_id} ({v.klass})"
    expected = next(s for s in sigs.SIGNATURES if s.sig_id == sig_id)
    assert v.klass == expected.klass
    assert v.remedy, "every verdict names a plain-language remedy"


# ── the incident lines named in the brief, by class ────────────────────────

@pytest.mark.parametrize("service,line,klass,action", [
    ("postgres", "LOG:  syncing data directory (fsync), elapsed time: 100.03 s", "recovering", "wait"),
    ("postgres", "LOG:  database system was not properly shut down; automatic recovery in progress",
     "recovering", "wait"),
    ("keycloak", 'FATAL: database "keycloak" does not exist', "db-missing", "bootstrap:keycloak-db"),
    ("opensearch-dashboards", "--opensearch.password must have a value", "fatal-config", "fail"),
    ("correlation", "TopicAuthorizationFailedError", "auth-denied", "bootstrap:kafka-acls"),
    ("opensearch", "ClusterBlockException[blocked by: [FORBIDDEN/12/index read-only-allow-delete]]",
     "flood-stage", "fail"),
    ("opensearch", "high disk watermark exceeded; flood-stage watermark reached", "flood-stage", "fail"),
    ("compose", "Bind for 0.0.0.0:162 failed: port is already allocated", "port-conflict", "fail"),
    ("clickhouse", "Cannot write to file: no space left on device", "disk-full", "fail"),
    ("api", "fatal error: runtime: out of memory", "oom-killed", "fail"),
    ("compose", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.", "daemon-down", "wait"),
])
def test_brief_named_lines(service, line, klass, action):
    v = sigs.classify(service, line)
    assert (v.klass, v.action) == (klass, action)


# ── unknown is never a guess ────────────────────────────────────────────────

@pytest.mark.parametrize("service,text", [
    ("postgres", ""),
    ("postgres", "2026-09-15 03:13:40 UTC [1] LOG:  database system is ready to accept connections"),
    ("api", "level=info msg=\"listening\" addr=:8080"),
    ("api", "open /data/x: permission denied"),          # ambiguous: not claimed as an LSM denial
    ("postgres", 'FATAL:  database "keycloak" does not exist'),  # server side: not keycloak's verdict
    ("grafana", "TopicAuthorizationFailed maybe"),        # not the exception name
])
def test_unrecognised_logs_are_unknown(service, text):
    v = sigs.classify(service, text)
    assert v.klass == "unknown"
    assert v.action == "none"
    assert v.sig_id == ""


def test_unknown_action_is_none_not_a_remediation():
    v = sigs.classify("api", "hello")
    assert v.action == "none"
    assert "not recognised" in v.remedy


# ── precedence ──────────────────────────────────────────────────────────────

def test_severe_class_outranks_waiting_class_regardless_of_order():
    text = (
        "PANIC:  could not write to file \"pg_wal/x\": No space left on device\n"
        "LOG:  database system was interrupted; last known up at 03:03:57\n"
        "LOG:  syncing data directory (fsync), elapsed time: 10.01 s\n"
    )
    assert sigs.classify("postgres", text).klass == "disk-full"


def test_most_recent_line_wins_among_equal_rank():
    text = (
        "LOG:  database system was interrupted; last known up at 03:03:57\n"
        "FATAL:  the database system is starting up\n"
        "LOG:  syncing data directory (fsync), elapsed time: 90.00 s\n"
    )
    v = sigs.classify("postgres", text)
    assert v.sig_id == "pg-crash-recovery"
    assert "syncing data directory" in v.evidence


def test_only_the_last_n_lines_are_considered():
    old = "Bind for 0.0.0.0:514 failed: port is already allocated"
    text = old + "\n" + "\n".join(f"info {i}" for i in range(300))
    assert sigs.classify("syslog-ng", text, max_lines=200).klass == "unknown"
    assert sigs.classify("syslog-ng", text, max_lines=400).klass == "port-conflict"


def test_service_scoping_uses_compose_service_name_from_container_names():
    line = 'FATAL: database "keycloak" does not exist'
    assert sigs.classify("netops-keycloak-1", line).klass == "db-missing"
    assert sigs.normalize_service("netops-opensearch-dashboards-1") == "opensearch-dashboards"
    assert sigs.normalize_service("/netops-api-2") == "api"
    assert sigs.normalize_service("postgres") == "postgres"


# ── redaction ───────────────────────────────────────────────────────────────

def test_secretish_regex_is_install_py_verbatim():
    src = (SCRIPTS / "install.py").read_text(encoding="utf-8")
    m = re.search(r'_SECRETISH = re\.compile\(r"([^"]+)"', src)
    assert m, "install.py _SECRETISH moved — re-pin the shared redaction"
    assert sigs.SECRETISH.pattern == m.group(1)
    assert sigs.SECRETISH.flags & re.IGNORECASE


@pytest.mark.parametrize("line", [
    "DB_PASSWORD=hunter2 rejected",
    "Authorization: Bearer abc.def.ghi",
    "using api_key sk-live-123",
    "client_secret=xyz",
    "token=deadbeef",
    "SaslAuthenticationException: invalid credentials",
])
def test_redact_line_withholds_credential_looking_lines(line):
    assert sigs.redact_line(line) == sigs.WITHHELD


def test_evidence_is_redacted_but_classification_still_works():
    v = sigs.classify("correlation",
                      "SaslAuthenticationException: Authentication failed: invalid credentials password=Sentinel-9")
    assert v.klass == "auth-denied"
    assert "Sentinel-9" not in v.evidence
    assert "Sentinel-9" not in json.dumps(v.to_dict())


def test_redacted_tail_bounds_and_redacts():
    text = "a\n\nsecret=1\nb\nc"
    assert sigs.redacted_tail(text, 3) == [sigs.WITHHELD, "b", "c"]


def test_remedy_carries_only_a_validated_key_name():
    v = sigs.classify("compose", "required variable DB_PASSWORD is missing a value: DB_PASSWORD required")
    assert v.klass == "fatal-config"
    assert "DB_PASSWORD" in v.remedy
    evil = "required variable $(rm -rf /) is missing a value"
    assert sigs.classify("compose", evil).klass == "unknown"


def test_long_lines_are_truncated_before_matching_and_in_evidence():
    line = "x" * 50_000 + " port is already allocated"
    v = sigs.classify("nginx", line)
    assert v.klass == "unknown"  # the tail beyond the cap is never scanned
    short = "port is already allocated " + "y" * 50_000
    v2 = sigs.classify("nginx", short)
    assert v2.klass == "port-conflict"
    assert len(v2.evidence) <= sigs.MAX_LINE_CHARS


# ── the action vocabulary ───────────────────────────────────────────────────

@pytest.mark.parametrize("action,ok", [
    ("wait", True), ("fail", True),
    ("bootstrap:keycloak-db", True), ("bootstrap:kafka-acls", True),
    ("bootstrap:opensearch-templates", True),
    ("recreate:keycloak", True), ("recreate:opensearch-dashboards", True),
    ("bootstrap:rm -rf", False), ("bootstrap:unknown-thing", False),
    ("recreate:", False), ("recreate:../../x", False), ("recreate:API", False),
    ("exec:sh", False), ("prune", False), ("", False), ("wait ", False),
])
def test_action_whitelist(action, ok):
    assert sigs.is_valid_action(action) is ok


def test_table_actions_are_all_whitelisted():
    for s in sigs.SIGNATURES:
        assert sigs.is_valid_action(s.action), s.sig_id


def test_invalid_table_is_refused_at_validation():
    bad = sigs.Signature("x", re.compile(".*"), re.compile("boom"), "fatal-config",
                         "remedy", "exec:rm")
    with pytest.raises(ValueError, match="action"):
        sigs.validate_table((bad,))
    bad_class = sigs.Signature("y", re.compile(".*"), re.compile("boom"), "guess",
                               "remedy", "fail")
    with pytest.raises(ValueError, match="class"):
        sigs.validate_table((bad_class,))
    dup = sigs.SIGNATURES[0]
    with pytest.raises(ValueError, match="duplicate"):
        sigs.validate_table((dup, dup))


def test_module_never_executes_anything():
    src = (SCRIPTS / "install_signatures.py").read_text(encoding="utf-8")
    for banned in ("import subprocess", "os.system", "os.exec", "Popen", "import shutil"):
        assert banned not in src, f"the classifier must only classify ({banned})"


# ── CLI ─────────────────────────────────────────────────────────────────────

def _cli(args: list[str], stdin: str | bytes) -> subprocess.CompletedProcess:
    data = stdin.encode() if isinstance(stdin, str) else stdin
    return subprocess.run([sys.executable, str(SCRIPTS / "install_signatures.py"), *args],
                          input=data, capture_output=True, timeout=30, check=False)


def test_cli_json():
    r = _cli(["classify", "keycloak", "--json"], 'FATAL: database "keycloak" does not exist\n')
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["class"] == "db-missing"
    assert doc["action"] == "bootstrap:keycloak-db"
    assert doc["service"] == "keycloak"
    assert set(doc) >= {"class", "action", "remedy", "signature", "evidence", "service"}


def test_cli_text_and_unknown():
    r = _cli(["classify", "api"], "all good\n")
    assert r.returncode == 0
    assert r.stdout.decode().splitlines()[0] == "class: unknown"


def test_cli_module_invocation_from_scripts_dir():
    r = subprocess.run([sys.executable, "-m", "install_signatures", "classify", "postgres"],
                       input=b"automatic recovery in progress\n", capture_output=True,
                       timeout=30, cwd=str(SCRIPTS), check=False)
    assert r.returncode == 0, r.stderr
    assert b"class: recovering" in r.stdout


def test_cli_usage_errors_exit_2():
    assert _cli([], "").returncode == 2
    assert _cli(["classify"], "").returncode == 2
    assert _cli(["classify", "bad service!"], "").returncode == 2
    assert _cli(["classify", "api", "--lines", "0"], "").returncode == 2


def test_cli_bounds_stdin_and_survives_binary():
    blob = b"\xff\xfe" * 10 + b"\nport is already allocated\n" + b"z" * (sigs.MAX_STDIN_BYTES + 10)
    r = _cli(["classify", "nginx", "--json"], blob)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["class"] in {"unknown", "port-conflict"}
    tail_hit = b"a\n" * 10 + b"z" * (sigs.MAX_STDIN_BYTES + 10) + b"\nport is already allocated\n"
    r2 = _cli(["classify", "nginx", "--json"], tail_hit)
    assert json.loads(r2.stdout)["class"] == "port-conflict", "the TAIL of the input is what is kept"
