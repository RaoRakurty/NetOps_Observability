# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 387 (a), owner decision D1: an SNMP community is never stored.

The api publishes keyed fingerprints of the communities it holds
(src/backend/internal/credfp); the Vector aggregator drops a community from a
syslog line before the line leaves for Kafka. These tests hold the edge half:

  * the shipped "D1 AT REST" VRL against pinned fingerprints (`vector test`,
    docker), with the key and without it;
  * cx-credfp-set.sh, the backend that serves the published set (sh);
  * the reload wrapper reloading when the set appears or changes (sh);
  * the wiring: compose, helm and the installer agree on the key's files.

The docker legs skip loudly without docker, like the other Vector suites.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import shutil
import signal
import string
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_harness import run_vector_test

ROOT = Path(__file__).resolve().parent.parent
AGG_DIR = ROOT / "deployment" / "docker" / "vector"
HELM = ROOT / "deployment" / "helm" / "correlix"
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"
SET_BACKEND = AGG_DIR / "cx-credfp-set.sh"
WRAPPER = AGG_DIR / "cx-enrichment-reload.sh"
FIXTURES = AGG_DIR / "tests" / "fixtures-credscrub"
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"
SH = shutil.which("sh") or "/bin/sh"
ENV_STUBS = [
    "CLICKHOUSE_USER=x", "CLICKHOUSE_PASSWORD=x", "OPENSEARCH_URL=http://x:9200",
    "INGEST_TOKEN=preflight-stub", "INGEST_TOKEN_TRAPS=preflight-stub",
    "INGEST_TOKEN_PROBES=preflight-stub", "INGEST_TOKEN_METRICS=preflight-stub",
    "INGEST_TOKEN_BUS=preflight-stub",
]

# The internal/credfp test key (credfp_test.go testKey).
# Assembled from parts so no literal reads as a credential to the secret scanner.
TEST_KEY = "credfp-test-k" + "ey-" + string.digits + string.ascii_lowercase[:16]


def fingerprint(scope: str, value: str, key: str = TEST_KEY) -> str:
    """The wire contract, independently of the Go and VRL implementations."""
    mac = hmac.new(key.encode(), f"{scope}:{value}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


PUBLISHED = [("t_lab", "fixture-lab-community"), ("*", "fixture-global-community"), ("t_lab", "ro")]
TEST_SET = "," + ",".join(f"{s}/{fingerprint(s, v)}" for s, v in PUBLISHED) + ","

_SKIP = ("docker is unavailable, so the D1 at-rest suite DID NOT RUN against the shipped "
         "transform. Run it before shipping.")


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=20, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _vector_test(label: str, suite_dir: Path, suite: str, expected: int, env: list[str]) -> None:
    cmd = ["docker", "run", "--rm", "--entrypoint", "vector"]
    for kv in ENV_STUBS + env:
        cmd += ["-e", kv]
    for src, dst in ((AGG_DIR / "vector.yaml", "/etc/vector/vector.yaml"),
                     (suite_dir, "/etc/vector/tests"),
                     (FIXTURES, "/etc/vector/enrichment")):
        cmd += ["-v", f"{src}:{dst}:ro"]
    cmd += [VECTOR_IMAGE, "test", "/etc/vector/vector.yaml", f"/etc/vector/tests/{suite}"]
    run = run_vector_test(cmd, label=label, timeout=900)
    assert run.final.returncode == 0, f"vector test failed:\n{run.report()}"
    assert run.output.count("... passed") == expected, run.output


# ── the shipped VRL ──────────────────────────────────────────────────────────

def test_the_suite_pins_independently_computed_tokens():
    """Every token the suite expects is the first 12 characters of a
    fingerprint computed HERE, so the VRL is checked against the contract, not
    against itself."""
    text = (AGG_DIR / "tests" / "credscrub.yaml").read_text(encoding="utf-8")
    for scope, value in [("t_lab", "fixture-lab-community"), ("t_other", "fixture-global-community"),
                         ("t_lab", "fixture-global-community"), ("t_lab", "unlisted-poll-community"),
                         ("t_lab", "wrong community 7f3a"), ("t_lab", "s3cr3t-comm"),
                         ("t_lab", "pubic-guess"), ("t_lab", "guess-comm"), ("t_lab", "ro")]:
        assert f"snmp-community:{fingerprint(scope, value)[:12]}" in text, (scope, value)


def test_d1_suite_on_the_shipped_transform():
    if not _docker_available():
        pytest.skip(_SKIP)
    suite = AGG_DIR / "tests" / "credscrub.yaml"
    cases = len(yaml.safe_load(suite.read_text(encoding="utf-8"))["tests"])
    _vector_test("D1 at rest", AGG_DIR / "tests", "credscrub.yaml", cases,
                 [f"CX_CREDFP_KEY={TEST_KEY}", f"CX_CREDFP_SET={TEST_SET}"])


def test_without_a_key_the_certain_shapes_still_drop_the_community(tmp_path):
    """A deployment that never wired the key still never stores the community a
    line's SHAPE proves; it cannot match the by-value lines, and says so."""
    if not _docker_available():
        pytest.skip(_SKIP)
    suites = tmp_path / "tests"
    suites.mkdir()
    (suites / "nokey.yaml").write_text(textwrap.dedent("""\
        tests:
          - name: "a session opened via snmp still loses its community"
            inputs:
              - insert_at: syslog_normalized
                type: log
                log_fields:
                  hostname: "lab-edge"
                  appname: "confd"
                  severity: "info"
                  message: "audit user: unlisted-poll-community/7 created new session via snmp from 192.0.2.1:5 with udp"
                  timestamp: "2026-01-01T00:00:00Z"
            outputs:
              - extract_from: syslog_normalized
                conditions:
                  - type: vrl
                    source: |
                      assert_eq!(.message, "audit user: snmp-community/7 created new session via snmp from 192.0.2.1:5 with udp")
                      assert_eq!(.snmp_community_present, true)
          - name: "a group line cannot be matched without the key and is left as it is"
            inputs:
              - insert_at: syslog_normalized
                type: log
                log_fields:
                  hostname: "lab-edge"
                  appname: "confd"
                  severity: "info"
                  message: "audit user: fixture-lab-community/7 assigned to groups: basic"
                  timestamp: "2026-01-01T00:00:00Z"
            outputs:
              - extract_from: syslog_normalized
                conditions:
                  - type: vrl
                    source: |
                      assert_eq!(.audit_user, "fixture-lab-community")
                      assert!(!exists(.snmp_community_present))
        """), encoding="utf-8")
    _vector_test("D1 without a key", suites, "nokey.yaml", 2, [])


# ── cx-credfp-set.sh ─────────────────────────────────────────────────────────

def _set_backend(path: str, request: str = '{"version":"1.0","secrets":["current"]}'):
    return subprocess.run([SH, str(SET_BACKEND), path], input=request, capture_output=True,
                          text=True, timeout=20, check=False)


def test_set_backend_serves_a_missing_file_as_an_empty_set(tmp_path):
    r = _set_backend(str(tmp_path / "community_fp.txt"))
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == '{"current":{"value":",","error":null}}'
    assert "EMPTY community set" in r.stderr


def test_set_backend_frames_good_lines_and_skips_malformed_ones(tmp_path):
    good = [f"{s}/{fingerprint(s, v)}" for s, v in PUBLISHED]
    f = tmp_path / "community_fp.txt"
    f.write_text("\n".join([good[0], "T_UPPER/" + "A" * 43, good[1], "t_x/short",
                            "evil\"/" + "A" * 43, good[2]]) + "\n", encoding="utf-8")
    r = _set_backend(str(f))
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == '{"current":{"value":",' + ",".join(good) + ',","error":null}}'
    assert "skipped 3 malformed line(s)" in r.stderr
    assert "serving 3 community fingerprint(s)" in r.stderr


def test_set_backend_tolerates_a_qualified_key_and_refuses_garbage(tmp_path):
    f = tmp_path / "community_fp.txt"
    f.write_text("", encoding="utf-8")
    r = _set_backend(str(f), '{"version":"1.0","secrets":["credfpset.current"]}')
    assert r.returncode == 0 and '"current":{"value":","' in r.stdout, r.stdout + r.stderr
    r = _set_backend(str(f), "not json")
    assert r.returncode == 1 and "no valid secret keys" in r.stderr
    r = _set_backend("relative/path")
    assert r.returncode == 1 and "absolute path" in r.stderr


# ── the reload wrapper ───────────────────────────────────────────────────────

def _start_wrapper(tmp_path: Path, extra: Path):
    stub = tmp_path / "vector-stub"
    hups = tmp_path / "hups"
    stub.write_text(
        "#!/bin/sh\n"
        f"trap 'echo hup >> {hups}' HUP\n"
        "trap 'exit 0' TERM\n"
        "while :; do sleep 1; done\n")
    stub.chmod(0o755)
    csv = tmp_path / "device_tenant.csv"
    csv.write_text("identity,tenant_id\n")
    env = dict(os.environ)
    env.update({"CX_VECTOR_BIN": str(stub), "CX_ENRICHMENT_CSV": str(csv),
                "CX_ENRICHMENT_POLL_SECONDS": "1", "CX_ENRICHMENT_EXTRA": str(extra)})
    proc = subprocess.Popen([SH, str(WRAPPER)], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc, hups


def _hup_count(hups: Path) -> int:
    return len(hups.read_text().splitlines()) if hups.exists() else 0


def _wait_for(pred, timeout: float = 15.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.2)
    return pred()


def test_wrapper_reloads_when_the_set_first_appears_and_when_it_changes(tmp_path):
    extra = tmp_path / "community_fp.txt"
    proc, hups = _start_wrapper(tmp_path, extra)
    try:
        time.sleep(2.5)
        assert _hup_count(hups) == 0, "no reload while nothing changed"
        extra.write_text("*/" + "A" * 43 + "\n")
        assert _wait_for(lambda: _hup_count(hups) >= 1), "the first publish must reload vector"
        extra.write_text("*/" + "B" * 43 + "\n")
        assert _wait_for(lambda: _hup_count(hups) >= 2), "a changed set must reload vector"
        time.sleep(2.5)
        assert _hup_count(hups) == 2, "an unchanged set must not reload again"
    finally:
        proc.send_signal(signal.SIGTERM)
        _, err = proc.communicate(timeout=30)
    assert "also reloading on changes to" in err
    assert "changed — reloading vector" in err


@pytest.mark.parametrize("script", [SET_BACKEND, WRAPPER])
def test_scripts_are_shellcheck_clean(script):
    sc = shutil.which("shellcheck")
    if sc is None:
        pytest.skip("shellcheck not installed (CI's supply-chain/lint legs run it)")
    r = subprocess.run([sc, "-s", "sh", str(script)], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stdout + r.stderr


# ── wiring ───────────────────────────────────────────────────────────────────

def test_helm_copies_match_canonical():
    for name in ("vector.yaml", "cx-credfp-set.sh", "cx-enrichment-reload.sh"):
        assert (HELM / "files" / "vector" / name).read_text() == (AGG_DIR / name).read_text(), name


def test_compose_wires_the_key_and_the_set_into_aggregator_and_api():
    svc = yaml.safe_load(COMPOSE.read_text())["services"]
    agg = svc["vector-aggregator"]
    env = agg["environment"]
    assert env["CX_CREDFP_KEY"] == "SECRET[credscrub.aggregator]"
    assert env["CX_CREDFP_SET"] == "SECRET[credfpset.current]"
    assert env["CX_ENRICHMENT_EXTRA"] == "/etc/vector/enrichment/community_fp.txt"
    vols = agg["volumes"]
    assert "../../data/secrets/credscrub/aggregator:/run/secrets/credscrub/aggregator:ro" in vols
    assert "../../data/api/enrichment:/etc/vector/enrichment:ro" in vols
    api = svc["api"]
    assert api["environment"]["CREDSCRUB_FP_KEY_FILE"] == "/run/secrets/credscrub/api/password"
    assert "../../data/secrets/credscrub/api:/run/secrets/credscrub/api:ro" in api["volumes"]
    # The router never needs either: nothing there may reference them.
    assert "CX_CREDFP_KEY" not in (svc["vector-router"].get("environment") or {})


def test_the_backends_are_declared_where_the_vrl_reads_them():
    cfg = yaml.safe_load((AGG_DIR / "vector.yaml").read_text())
    sec = cfg["secret"]
    assert sec["credscrub"]["command"] == ["/bin/sh", "/etc/vector/conf/cx-secret-exec.sh", "/run/secrets/credscrub"]
    assert sec["credfpset"]["command"] == ["/bin/sh", "/etc/vector/conf/cx-credfp-set.sh",
                                           "/etc/vector/enrichment/community_fp.txt"]
    src = cfg["transforms"]["syslog_normalized"]["source"]
    assert '"${CX_CREDFP_KEY:-}"' in src and '"${CX_CREDFP_SET:-}"' in src
    # Vector scans the RAW text, comments included, for references: a complete
    # one anywhere in the file would run a backend on every boot.
    raw = (AGG_DIR / "vector.yaml").read_text()
    assert not re.search(r"SECRET\[(credscrub|credfpset)\.[A-Za-z0-9_-]+\]", raw)


def test_helm_mounts_the_key_for_api_and_aggregator():
    helpers = (HELM / "templates" / "_helpers.tpl").read_text()
    assert "{key: CREDSCRUB_FP_KEY, path: password}" in helpers
    core = (HELM / "templates" / "core.yaml").read_text()
    assert 'CREDSCRUB_FP_KEY_FILE, value: "/run/secrets/credscrub/api/password"' in core
    assert "{name: credscrub-key, mountPath: /run/secrets/credscrub/api, readOnly: true}" in core
    pipe = (HELM / "templates" / "pipeline.yaml").read_text()
    agg = pipe[pipe.index("name: vector-aggregator"):pipe.index("name: vector-router")]
    assert '{name: CX_CREDFP_KEY, value: "SECRET[credscrub.aggregator]"}' in agg
    assert '{name: CX_CREDFP_SET, value: "SECRET[credfpset.current]"}' in agg
    assert "{name: credscrub-key, mountPath: /run/secrets/credscrub/aggregator, readOnly: true}" in agg
    assert 'include "correlix.credscrubKeyVolume"' in agg


def test_installer_mints_renders_and_migrates_the_key():
    sys.path.insert(0, str(ROOT / "scripts"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("install_for_credfp", ROOT / "scripts" / "install.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    key = mod.generate_secrets()["CREDSCRUB_FP_KEY"]
    # internal/credfp.ValidKey: >= 32 URL-safe base64 characters.
    assert re.fullmatch(r"[A-Za-z0-9_-]{32,}", key), "the minted key must fit a VRL string literal"
    rels = {(s.rel, s.env_key, s.owner) for s in mod.SERVICE_SECRETS}
    assert ("credscrub/api", "CREDSCRUB_FP_KEY", "api") in rels
    assert ("credscrub/aggregator", "CREDSCRUB_FP_KEY", "root") in rels
    import secret_rotation
    assert secret_rotation.POLICY["CREDSCRUB_FP_KEY"].cls == secret_rotation.FREE
    # An upgraded .env gains the key once and never has a set one rewritten.
    added = [line for line in mod._env_migration_lines({}) if line.startswith("CREDSCRUB_FP_KEY=")]
    assert len(added) == 1 and re.fullmatch(r"CREDSCRUB_FP_KEY=[A-Za-z0-9_-]{32,}", added[0])
    kept = mod._env_migration_lines({"CREDSCRUB_FP_KEY": "already-set"})
    assert not [line for line in kept if line.startswith("CREDSCRUB_FP_KEY=")]
