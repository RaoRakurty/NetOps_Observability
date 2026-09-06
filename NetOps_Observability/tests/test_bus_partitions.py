# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Scale P0 — the bus side of tenant-keyed co-partitioning.

The correlation tier scales horizontally by giving instance k partition k of
EVERY consumed topic (range assignor + tenant-keyed producers). That only
holds if the bus keeps three promises, each pinned here against the REAL
committed configs:

  1. kafka-init creates every topic at ONE shared partition count
     (BUS_PARTITIONS, default 1) and ALTERs an existing topic UP to it —
     increase-only, idempotent, loud on failure. Exercised by actually
     RUNNING the committed entrypoint against a fake kafka-topics.sh.
  2. Every keyed Vector kafka sink uses the Java-compatible murmur2
     partitioner and strips the routing key from the payload — a sink added
     with librdkafka's default (consistent_random = CRC32) would hash the
     same tenant to a DIFFERENT partition number than kafka-python/Java.
  3. The flows path is re-keyed: goflow2 (whose sarama partitioner cannot
     match murmur2) produces netops.flows.raw, and the router's re-key hop
     republishes onto netops.flows keyed by tenant.

Run:  python3 -m pytest tests/test_bus_partitions.py -v
"""
import os
import re
import subprocess
import tempfile

import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts)) as fh:
        return fh.read()


def _compose() -> dict:
    return yaml.safe_load(read("deployment", "docker", "docker-compose.yml"))


def _vector(tier: str) -> dict:
    path = {"aggregator": ("deployment", "docker", "vector", "vector.yaml"),
            "router": ("deployment", "docker", "vector-router", "vector.yaml")}[tier]
    return yaml.safe_load(read(*path))


# ── 1. kafka-init: BUS_PARTITIONS create + increase-only alter ──────────────

_FAKE_KAFKA_TOPICS = """#!/usr/bin/env bash
# fake kafka-topics.sh: records argv; --describe prints PartitionCount from env
echo "$@" >> "$CALLS"
for a in "$@"; do
  if [ "$a" = "--describe" ]; then
    echo "Topic: x  TopicId: y  PartitionCount: ${EXISTING:-1}  ReplicationFactor: 1"
  fi
done
exit 0
"""


def _run_kafka_init(bus_partitions, existing: int):
    entry = _compose()["services"]["kafka-init"]["entrypoint"]
    assert entry[0] == "bash" and entry[1] == "-c"
    script = entry[2].replace("$$", "$")  # compose interpolation escape
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "opt/kafka/bin"))
        fake = os.path.join(d, "opt/kafka/bin/kafka-topics.sh")
        with open(fake, "w") as fh:
            fh.write(_FAKE_KAFKA_TOPICS)
        os.chmod(fake, 0o755)
        calls = os.path.join(d, "calls.txt")
        script = script.replace("/opt/kafka/bin/kafka-topics.sh", fake)
        env = dict(os.environ, CALLS=calls, EXISTING=str(existing))
        env.pop("BUS_PARTITIONS", None)
        if bus_partitions is not None:
            env["BUS_PARTITIONS"] = str(bus_partitions)
        proc = subprocess.run(["bash", "-c", script], env=env,
                              capture_output=True, text=True, timeout=60,
                              check=False)
        lines = []
        if os.path.exists(calls):
            with open(calls) as fh:
                lines = fh.read().splitlines()
        return proc, lines


def _topic_count() -> int:
    entry = _compose()["services"]["kafka-init"]["entrypoint"]
    m = re.search(r"for t in (.*?)\s*;\s*do", entry[2], re.DOTALL)
    assert m
    return len([t for t in m.group(1).split() if t.startswith("netops.")])


def test_kafka_init_default_is_one_partition_and_never_alters():
    """BUS_PARTITIONS unset ⇒ byte-identical default behavior: every topic
    created at 1 partition, no alter issued."""
    proc, lines = _run_kafka_init(None, existing=1)
    assert proc.returncode == 0, proc.stderr
    creates = [ln for ln in lines if "--create" in ln]
    assert len(creates) == _topic_count()
    assert all("--partitions 1" in ln for ln in creates)
    assert not [ln for ln in lines if "--alter" in ln]


def test_kafka_init_scales_existing_topics_up():
    proc, lines = _run_kafka_init(4, existing=1)
    assert proc.returncode == 0, proc.stderr
    creates = [ln for ln in lines if "--create" in ln]
    alters = [ln for ln in lines if "--alter" in ln]
    assert all("--partitions 4" in ln for ln in creates)
    assert len(alters) == _topic_count(), "every existing topic must be raised"
    assert all("--partitions 4" in ln for ln in alters)


def test_kafka_init_is_idempotent_and_never_shrinks():
    proc, lines = _run_kafka_init(4, existing=4)
    assert proc.returncode == 0, proc.stderr
    assert not [ln for ln in lines if "--alter" in ln], "already at N: no alter"
    proc, lines = _run_kafka_init(2, existing=4)
    assert proc.returncode == 0, proc.stderr
    assert not [ln for ln in lines if "--alter" in ln], (
        "Kafka cannot shrink partition counts — the init must never try")


def test_kafka_num_partitions_follows_bus_partitions():
    """Broker-side default aligned with kafka-init so a topic minted outside
    the loop (admin tooling; auto-create is off) matches the shared count."""
    env = _compose()["services"]["kafka"]["environment"]
    assert env["KAFKA_NUM_PARTITIONS"] == "${BUS_PARTITIONS:-1}"


def test_tls_variant_kafka_init_mirrors_the_base():
    """compose.tls.yml restates the entrypoint wholesale (compose replaces
    lists) — its topic set and partition logic must not drift from the base."""
    tls = read("deployment", "docker", "compose.tls.yml")
    m = re.search(r"for t in (.*?)\s*;\s*do", tls, re.DOTALL)
    assert m, "tls kafka-init lost its for-loop"
    tls_topics = {t for t in m.group(1).split() if t.startswith("netops.")}
    base = _compose()["services"]["kafka-init"]["entrypoint"][2]
    mb = re.search(r"for t in (.*?)\s*;\s*do", base, re.DOTALL)
    base_topics = {t for t in mb.group(1).split() if t.startswith("netops.")}
    assert tls_topics == base_topics
    assert 'BUS_PARTITIONS' in tls, "tls kafka-init must honor BUS_PARTITIONS"
    assert "--alter" in tls, "tls kafka-init must scale existing topics up"


# ── 2. keyed sinks: murmur2 everywhere, key stripped from payload ───────────

def _kafka_sinks(tier: str) -> dict:
    cfg = _vector(tier)
    return {name: s for name, s in (cfg.get("sinks") or {}).items()
            if s.get("type") == "kafka"}


def test_every_keyed_kafka_sink_uses_java_murmur2_and_strips_the_key():
    """The class guard: ANY kafka sink that sets key_field must use the
    Java-compatible partitioner and strip the key from the encoded payload.
    librdkafka's default (consistent_random, CRC32) hashes the same tenant to
    a different partition number than kafka-python/Java — the co-partitioning
    contract breaks silently, per-tenant, with no error anywhere."""
    seen_keyed = 0
    for tier in ("aggregator", "router"):
        for name, sink in _kafka_sinks(tier).items():
            key_field = sink.get("key_field")
            if not key_field:
                continue
            seen_keyed += 1
            opts = sink.get("librdkafka_options") or {}
            assert opts.get("partitioner") == "murmur2_random", (
                f"{tier}:{name} keys by {key_field!r} without the Java-"
                "compatible murmur2 partitioner")
            except_fields = (sink.get("encoding") or {}).get("except_fields") or []
            assert key_field in except_fields, (
                f"{tier}:{name} leaks its routing key {key_field!r} into the payload")
    assert seen_keyed >= 7, f"expected the keyed sinks (got {seen_keyed})"


def test_correlation_topics_all_have_a_keyed_producer_path():
    """Every topic the correlation engine consumes is fed by at least one
    tenant-keyed sink: the five per-lane aggregator sinks, the templated
    bus-bridge sink (covers identities/controller/app.edge/verification/
    wireless), and the router's flows re-key sink."""
    keyed_topics = set()
    for tier in ("aggregator", "router"):
        for sink in _kafka_sinks(tier).values():
            if sink.get("key_field"):
                keyed_topics.add(sink.get("topic"))
    for t in ("netops.syslog", "netops.snmptrap", "netops.probes",
              "netops.metrics", "netops.cloud", "netops.flows"):
        assert t in keyed_topics, f"{t} has no tenant-keyed producer"
    assert "{{ __topic }}" in keyed_topics, "bus-bridge sink lost its keying"


# ── 3. the flows re-key hop ─────────────────────────────────────────────────

def test_goflow2_produces_the_raw_topic():
    cmd = _compose()["services"]["goflow2"]["command"]
    idx = cmd.index("-transport.kafka.topic")
    assert cmd[idx + 1] == "netops.flows.raw", (
        "goflow2 must produce netops.flows.raw — it cannot tenant-key "
        "netops.flows itself (no registry; sarama FNV-1a != murmur2)")
    tls = read("deployment", "docker", "compose.tls.yml")
    assert "netops.flows.raw" in tls, "tls goflow2 override must follow"


def test_router_rekeys_raw_flows_onto_netops_flows():
    cfg = _vector("router")
    src = cfg["sources"]["kafka_flows_raw"]
    assert src["topics"] == ["netops.flows.raw"]
    assert src["group_id"].startswith("netops-router-"), "ACL group prefix"
    sink = cfg["sinks"]["kafka_flows_keyed"]
    assert sink["topic"] == "netops.flows"
    assert sink["key_field"] == "__key"
    rekey = cfg["transforms"]["flows_rekey"]
    assert rekey["inputs"] == ["kafka_flows_raw"]
    # pass-through fidelity: the kafka-source metadata must be stripped so the
    # bus copy stays byte-equivalent to what goflow2 produced
    for f in ("timestamp", "source_type", "topic", "partition", "offset",
              "message_key", "headers"):
        assert f"del(.{f})" in rekey["source"], f"flows_rekey must strip .{f}"
    # tenancy from the same registry every tier uses
    assert "device_tenant" in rekey["source"]
    assert "sampler_address" in rekey["source"]
    # the STORAGE pipeline stays on the keyed topic (quarantine-restore loop)
    assert cfg["sources"]["kafka_flows"]["topics"] == ["netops.flows"]


def test_acls_cover_the_rekey_hop():
    acls = read("deployment", "docker", "kafka", "apply-acls.sh")
    assert "netops.flows.raw" in acls
    assert re.search(r'ANONYMOUS.*\n\s*--operation Write --operation Describe'
                     r' --topic netops\.flows\.raw', acls), (
        "goflow2's ANONYMOUS grant must move to the raw topic")
    assert re.search(r'"\$ROUTER" --producer \\\n\s*--topic netops\.flows\b', acls), (
        "the router needs produce on netops.flows (the re-key hop)")
