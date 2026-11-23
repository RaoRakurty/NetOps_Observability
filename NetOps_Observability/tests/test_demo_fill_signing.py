# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""scripts/demo_fill.py (tracker 475): the api refuses an unsigned prober path
set, so the demo signs its traceroute set with the prober-control key exactly
as the prober does, or skips it and says why. The signature construction is
pinned by the golden vector internal/probercontrol's
TestSignatureGoldenVectorMatchesTheDemoSigner holds: a change on either side
breaks both."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

GOLDEN_KEY = b"golden-key-0123456789abcdefghijklmnopqrstu"
GOLDEN_PAYLOAD = ('{"schema":1,"vantage":"demo-fill","issued_at":"2026-11-22T00:00:00.000000Z",'
                  '"body":[{"dst":"10.0.0.1"}]}')
GOLDEN_SIG = "f70e6bee0e8064f509568abde6e86e36139c38ef9c79bd9d237eb0d9cb7674aa"


@pytest.fixture(scope="module")
def demo_fill():
    sys.path.insert(0, str(SCRIPTS))  # demo_fill imports seed_demo_data beside it
    try:
        spec = importlib.util.spec_from_file_location("demo_fill", SCRIPTS / "demo_fill.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        yield m
    finally:
        sys.path.remove(str(SCRIPTS))


def test_golden_vector_matches_the_go_signer():
    m = hmac.new(GOLDEN_KEY, b"correlix-prober-control/probe-paths\n", hashlib.sha256)
    m.update(GOLDEN_PAYLOAD.encode())
    assert m.hexdigest() == GOLDEN_SIG


def test_seal_path_set_builds_a_verifiable_envelope(demo_fill):
    paths = [{"dst": "10.0.0.1", "method": "icmp", "hops": [], "tenant_id": "t&<x>"}]
    env = json.loads(demo_fill.seal_path_set(GOLDEN_KEY, paths))
    assert env["v"] == 1
    rec = json.loads(env["payload"])
    assert rec["schema"] == 1 and rec["vantage"] == "demo-fill" and rec["body"] == paths
    assert rec["issued_at"].endswith("Z")
    m = hmac.new(GOLDEN_KEY, b"correlix-prober-control/probe-paths\n", hashlib.sha256)
    m.update(env["payload"].encode())
    assert hmac.compare_digest(env["sig"], m.hexdigest())


def test_unreadable_key_skips_with_a_reason_and_never_writes(demo_fill, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PROBER_CONTROL_KEY_FILE", str(tmp_path / "absent"))
    monkeypatch.setattr(demo_fill, "UNSIGNED_PATHS", False)
    monkeypatch.setattr(demo_fill, "_PATH_SKIP_SAID", False)
    writes = []
    monkeypatch.setattr(demo_fill, "redis_set", lambda *a, **k: writes.append(a) or True)
    assert demo_fill.publish_path_set([{"dst": "10.0.0.1"}]) == 0
    assert writes == []
    err = capsys.readouterr().err
    assert "traceroute skipped" in err and "--unsigned-paths" in err


def test_short_key_is_refused_and_never_printed(demo_fill, tmp_path, monkeypatch, capsys):
    key = tmp_path / "password"
    key.write_bytes(b"too-short-secret")
    monkeypatch.setenv("PROBER_CONTROL_KEY_FILE", str(key))
    monkeypatch.setattr(demo_fill, "UNSIGNED_PATHS", False)
    monkeypatch.setattr(demo_fill, "_PATH_SKIP_SAID", False)
    monkeypatch.setattr(demo_fill, "redis_set", lambda *a, **k: pytest.fail("wrote with a refused key"))
    assert demo_fill.publish_path_set([{"dst": "10.0.0.1"}]) == 0
    assert "too-short-secret" not in capsys.readouterr().err


def test_readable_key_writes_a_signed_set_with_the_api_ttl(demo_fill, tmp_path, monkeypatch):
    key = tmp_path / "password"
    key.write_bytes(GOLDEN_KEY + b"\n")
    monkeypatch.setenv("PROBER_CONTROL_KEY_FILE", str(key))
    monkeypatch.setattr(demo_fill, "UNSIGNED_PATHS", False)
    writes = []
    monkeypatch.setattr(demo_fill, "redis_set", lambda *a: writes.append(a) or True)
    assert demo_fill.publish_path_set([{"dst": "10.0.0.1"}]) == 1
    (k, val, ttl), = writes
    assert k == "netops:probe:paths" and ttl == 300
    assert json.loads(val)["v"] == 1
    assert GOLDEN_KEY.decode() not in val


def test_unsigned_flag_writes_the_plain_set(demo_fill, monkeypatch):
    monkeypatch.setattr(demo_fill, "UNSIGNED_PATHS", True)
    writes = []
    monkeypatch.setattr(demo_fill, "redis_set", lambda *a: writes.append(a) or True)
    assert demo_fill.publish_path_set([{"dst": "10.0.0.1"}]) == 1
    assert json.loads(writes[0][1]) == [{"dst": "10.0.0.1"}]
