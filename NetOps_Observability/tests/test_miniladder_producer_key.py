"""Tenant-keyed injection in the G2 mini-ladder (2026-08-22).

THE DEFECT THIS PINS. The production pipeline keys every Kafka topic by TENANT
(Vector: `__key = tenant_id`), so one tenant's records land on one partition
and ONE correlation replica owns the tenant whole. The harness injected with
NULL keys — the console producer round-robins those — so one tenant's stream
split 50/50 across both replicas (measured in run `082201589waa`: final
pending 64,740 / 64,480). Consequences the architecture review documented:
per-replica capacity figures were per-HALF-tenant (~2x flattering), and each
replica minted its own objects for the same devices. A topology production
cannot produce must not be the topology qualification measures.

These tests pin the fix: `Stack.produce(key=...)` sends real Kafka message
keys; `tenant` is the DEFAULT mode; the key resolves from the same registry
the engine trusts; and the legacy null-key payload stays byte-identical
behind an explicit `--producer-key none`.

Run:  python3 -m pytest tests/test_miniladder_producer_key.py -v
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_harness():
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_key", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_key"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before
    return mod


ml = _load_harness()


def _stack():
    """A Stack whose kafka_tool is captured, never executed."""
    st = ml.Stack.__new__(ml.Stack)
    st.calls = []

    def fake_kafka_tool(tool, args, input_text=None, timeout=0,
                        config_flag="--command-config"):
        st.calls.append({"tool": tool, "args": list(args),
                         "input": input_text, "config_flag": config_flag})
        return 0, "", ""

    st.kafka_tool = fake_kafka_tool
    return st


LINES = ['{"hostname": "mlx-x-1", "message": "a"}',
         '{"hostname": "mlx-x-2", "message": "b"}']


# ── keyed mode ───────────────────────────────────────────────────────────────

def test_keyed_produce_sends_parse_key_properties():
    st = _stack()
    ok, err = st.produce("netops.syslog", LINES, key="acme")
    assert ok, err
    args = st.calls[0]["args"]
    assert "--property" in args
    assert "parse.key=true" in args, "message keys are not being parsed"
    assert "key.separator=\t" in args


def test_keyed_produce_prefixes_every_line_with_the_key():
    st = _stack()
    st.produce("netops.syslog", LINES, key="acme")
    payload = st.calls[0]["input"]
    for line in payload.rstrip("\n").split("\n"):
        assert line.startswith("acme\t"), f"unkeyed record in payload: {line[:60]}"
    # the payload after the key is the original JSON, untouched
    assert payload.rstrip("\n").split("\n")[0].split("\t", 1)[1] == LINES[0]


def test_key_may_not_contain_the_separator():
    """A tab inside the key would silently corrupt every record's key AND
    payload split — refuse loudly instead."""
    st = _stack()
    ok, err = st.produce("netops.syslog", LINES, key="bad\tkey")
    assert not ok and "tab" in err
    assert not st.calls, "a rejected key must not produce anything"


# ── legacy mode is byte-identical ────────────────────────────────────────────

def test_null_key_payload_and_args_are_the_legacy_shape():
    """`--producer-key none` must reproduce the pre-fix producer's KEYING
    exactly — it exists precisely so comparison runs against the historical
    evidence trail remain possible.

    2026-08-29: this used to pin the WHOLE argv (`== ["--topic", …]`), which
    is a wider claim than the invariant it guards. Delivery settings are
    orthogonal to keying, and the run that forced this change proved they are
    not optional in either mode: kafka-console-producer's 1.5 s ack deadline
    dropped 901 records under load and exited 0. A legacy-key run that
    silently loses records is not a comparable experiment, it is a broken one
    — so the hardening applies to both modes and is asserted here too."""
    st = _stack()
    st.produce("netops.syslog", LINES)              # key omitted = legacy
    call = st.calls[0]
    assert call["input"] == "\n".join(LINES) + "\n"
    # The legacy shape, stated as what it IS: the topic, and NO key plumbing.
    assert call["args"][:2] == ["--topic", "netops.syslog"]
    assert "parse.key=true" not in call["args"]
    assert "key.separator" not in " ".join(call["args"])
    assert "--property" not in call["args"]
    # …and the injection-integrity settings ride in this mode too.
    assert int(call["args"][call["args"].index("--request-timeout-ms") + 1]) >= 30000
    assert "enable.idempotence=true" in call["args"]
    assert call["config_flag"] == "--producer.config"


# ── registry tenant resolution ───────────────────────────────────────────────

def test_registry_tenant_resolves_the_identity(monkeypatch):
    st = ml.Stack.__new__(ml.Stack)
    st.cid = lambda name: "c1"
    monkeypatch.setattr(ml, "run", lambda cmd, timeout, input_text=None:
                        (0, "identity,tenant_id\nmlx-run-00001,acme\nother,globex\n", ""))
    assert st.registry_tenant("mlx-run-00001") == "acme"
    assert st.registry_tenant("other") == "globex"


@pytest.mark.parametrize("csv_text,why", [
    ("", "empty registry"),
    ("identity,tenant_id\n", "header only"),
    ("identity,tenant_id\nmlx-run-00001,\n", "blank tenant cell"),
    ("identity,tenant_id\nsomeone-else,acme\n", "identity absent"),
])
def test_registry_tenant_falls_back_to_global(monkeypatch, csv_text, why):
    """The fallback must be canon_tenant's default ('global'), never a guess —
    keying with a wrong tenant would re-split the stream, which is the defect
    this feature removes."""
    st = ml.Stack.__new__(ml.Stack)
    st.cid = lambda name: "c1"
    monkeypatch.setattr(ml, "run", lambda cmd, timeout, input_text=None: (0, csv_text, ""))
    assert st.registry_tenant("mlx-run-00001") == "global", why


def test_registry_tenant_without_a_container_is_global():
    st = ml.Stack.__new__(ml.Stack)
    st.cid = lambda name: ""
    assert st.registry_tenant("anything") == "global"


# ── defaults: production topology is the default, legacy is opt-in ───────────

def test_tenant_keying_is_the_default():
    assert ml.parse_args([]).producer_key == "tenant"


def test_none_is_accepted_and_choices_are_closed():
    assert ml.parse_args(["--producer-key", "none"]).producer_key == "none"
    with pytest.raises(SystemExit):
        ml.parse_args(["--producer-key", "hostname"])
