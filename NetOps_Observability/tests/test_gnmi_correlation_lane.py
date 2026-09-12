# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""gNMI → correlation lane contract (ENABLE_GNMI_CORRELATION).

The Go SNMP collector and gnmic are now two producers of the SAME canonical
MetricEvent onto the SAME topic (`netops.metrics`). Everything that keeps those
two honest is checked here, and every check is a property over the whole
surface rather than over the one sample that happened to be wrong:

  * the overlay config is the base config plus EXACTLY the correlation output
    and its shaper — nothing else may drift between the two files;
  * the shaper's RCA table equals `rcaMetricFamilies` in
    src/backend/collectors/metric_events.go, name for name and unit for unit,
    so the gNMI lane can never admit a family the SNMP lane does not;
  * the reshape really produces the handle_metric wire contract — evaluated
    with the REAL engines: gnmic's own event-jq processor (docker) for the
    shaper, and Go's text/template with gnmic's `fromJSON` func and the
    `missingkey=zero` option for the output template (outputs.ExecTemplate);
  * the lane is default-OFF, is pinned off under the mTLS profile, and carries
    no secret in the rendered config.

Run:  python3 -m pytest tests/test_gnmi_correlation_lane.py -v

The two engine-backed tests SKIP (they never silently pass) when docker or the
Go toolchain is unavailable; every static check always runs.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile

import pytest
import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
GNMIC_DIR = os.path.join(ROOT, "deployment", "docker", "gnmic")
BASE_CFG = os.path.join(GNMIC_DIR, "gnmic.yaml")
CORR_CFG = os.path.join(GNMIC_DIR, "gnmic-correlation.yaml")

OVERLAY_OUTPUT = "correlation"
OVERLAY_PROCESSOR = "corr-rca-shape"

# The canonical chain the VictoriaMetrics lane runs, in order. The correlation
# output runs the SAME chain (incl. the ownership gate) before its shaper, so a
# (device, family) pair stays served by exactly one transport on the bus.
# The gate itself is empty since tracker 230 — every canonical family gnmic maps
# is gNMI-owned — and tests/test_gnmi_ownership_contract.py is what proves the
# SNMP side agrees. It stays in the chain because it is the only place a family
# can be handed back to SNMP.
CANONICAL_CHAIN = [
    "canon-override-ts", "canon-names", "canon-status-enums", "canon-bgp-enums",
    "canon-isis-enums", "canon-isis-area-info", "canon-convert", "vendor-nokia",
    "vendor-arista", "transport-tag", "canon-tags", "canon-isis-level-tag",
    "ownership-gate", "drop-unmapped", "drop-internal-tags",
]

# handle_metric's wire contract, in the field order the Go MetricEvent struct
# marshals (src/backend/collectors/metric_events.go). if_alias/index have no
# gNMI source and are omitted, exactly as `omitempty` omits them in Go.
CONTRACT_ORDER = [
    "observer_type", "modality_class", "collection_path", "device", "vendor",
    "if_name", "peer", "neighbor", "signal_family", "metric", "value", "unit",
    "ts",
]


def read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts)) as fh:
        return fh.read()


def load(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that tolerates compose's merge tags — the TLS variant uses
    !override / !reset, which yaml.safe_load rejects outright."""


def _passthrough(loader, node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_constructor("!override", _passthrough)
_ComposeLoader.add_constructor("!reset", _passthrough)


def compose(name: str) -> dict:
    """The compose file as PARSED yaml, not `docker compose config`: these
    assertions are about what is committed, and must run without docker."""
    with open(os.path.join(ROOT, "deployment", "docker", name)) as fh:
        return yaml.load(fh, Loader=_ComposeLoader)


def gnmic_service(name: str = "docker-compose.yml") -> dict:
    return compose(name)["services"]["gnmic"]


# ── the Go allowlist, read from source ────────────────────────────────────────

def go_rca_families() -> dict:
    """{metric: (family, unit)} parsed out of rcaMetricFamilies. Reading the Go
    source (not a copy of it) is the point: the mirror cannot go stale."""
    src = read("src", "backend", "collectors", "metric_events.go")
    block = re.search(
        r"var rcaMetricFamilies = map\[string\]metricMeta\{(.*?)\n\}", src, re.DOTALL)
    assert block, "rcaMetricFamilies not found in metric_events.go"
    rows = re.findall(
        r'"([a-z0-9_]+)":\s*\{"([a-z_]+)",\s*"([a-z_]+)"\}', block.group(1))
    assert rows, "rcaMetricFamilies parsed empty — the literal's shape changed"
    return {m: (f, u) for m, f, u in rows}


def jq_rca_table() -> dict:
    """{metric: (family, unit)} parsed out of the shaper's jq expression. The
    table is the leading JSON object literal of that expression."""
    expr = load(CORR_CFG)["processors"][OVERLAY_PROCESSOR]["event-jq"]["expression"]
    obj = re.match(r"\s*(\{.*?\})\s*as \$rca", expr, re.DOTALL)
    assert obj, "the shaper's RCA table is not the leading `{...} as $rca` literal"
    return {m: (v["f"], v["u"]) for m, v in json.loads(obj.group(1)).items()}


def corr_output() -> dict:
    return load(CORR_CFG)["outputs"][OVERLAY_OUTPUT]


# ── 1. the overlay is a mechanical superset of the base ───────────────────────

def test_overlay_is_the_base_config_plus_exactly_the_correlation_lane():
    base, corr = load(BASE_CFG), load(CORR_CFG)
    assert set(corr["outputs"]) - set(base["outputs"]) == {OVERLAY_OUTPUT}
    assert set(corr["processors"]) - set(base["processors"]) == {OVERLAY_PROCESSOR}
    stripped = dict(corr)
    stripped["outputs"] = {k: v for k, v in corr["outputs"].items()
                           if k != OVERLAY_OUTPUT}
    stripped["processors"] = {k: v for k, v in corr["processors"].items()
                              if k != OVERLAY_PROCESSOR}
    assert stripped == base, (
        "gnmic-correlation.yaml drifted from gnmic.yaml. It is a FULL copy "
        "(gnmic takes one --config and YAML has no include); the ONLY permitted "
        "delta is the correlation output plus its shaper. Edit both together.")


def test_the_base_config_is_not_a_bus_producer():
    """Default deployment unchanged: no kafka/bus output without the flag."""
    for name, out in load(BASE_CFG)["outputs"].items():
        assert out["type"] == "prometheus_write", (
            f"{name} is a {out['type']} output — the default gnmic config must "
            "write to VictoriaMetrics only")


# ── 2. allowlist equality with the Go producer ────────────────────────────────

def test_shaper_allowlist_equals_rca_metric_families():
    go, jq = go_rca_families(), jq_rca_table()
    differing = {k: (go[k], jq[k]) for k in set(go) & set(jq) if go[k] != jq[k]}
    assert jq == go, (
        "the gNMI shaper's RCA table and rcaMetricFamilies disagree.\n"
        f"  only in metric_events.go: {sorted(set(go) - set(jq))}\n"
        f"  only in the gnmic shaper: {sorted(set(jq) - set(go))}\n"
        f"  differing meta: {differing}")
    assert len(go) == 17, "the allowlist changed size — update BOTH producers"


def test_canonically_mapped_non_rca_families_are_not_admitted():
    """gnmic maps more canonical names than correlation admits (per-AFI BGP
    prefixes). Those are VictoriaMetrics-only; the shaper is the gate that keeps
    them off the evidence bus.

    device_isis_adj_state used to be in this tuple. Tracker 222 admitted it (and
    its OSPF twin) as the `igp` family, in BOTH producers together; the guard
    below now proves the remaining hold-back is still held back."""
    admitted = set(jq_rca_table())
    base_src = read("deployment", "docker", "gnmic", "gnmic.yaml")
    for name in ("device_bgp_pfx_in",):
        assert name in base_src, \
            f"{name} is no longer a canonical gnmic name — refresh this guard"
        assert name not in admitted, \
            f"{name} reached the correlation allowlist without a Go counterpart"


# ── 3. the output block: contract, ordering, boundedness ──────────────────────

def test_correlation_output_targets_the_metric_topic_over_the_bus():
    out = corr_output()
    assert out["type"] == "kafka", (
        "gnmic 0.46.0 registers no `http` output (pkg/outputs OutputTypes), and "
        "its only HTTP egress — the event-trigger http ACTION — drops events "
        "past max-occurrences. Kafka is the lane.")
    assert out["format"] == "event"
    assert out["split-events"] is True, \
        "one MetricEvent per Kafka message requires split-events"
    assert out["address"] == "${GNMI_CORRELATION_BROKERS}"
    assert out["topic"] == "${GNMI_CORRELATION_TOPIC}"


def test_correlation_output_runs_the_canonical_chain_then_the_shaper():
    corr = load(CORR_CFG)
    evps = corr["outputs"][OVERLAY_OUTPUT]["event-processors"]
    assert evps == CANONICAL_CHAIN + [OVERLAY_PROCESSOR], (
        "the correlation lane must run the SAME canonical chain as "
        "victoria-canonical — including the ownership gate — and the shaper last")
    assert evps == (corr["outputs"]["victoria-canonical"]["event-processors"]
                    + [OVERLAY_PROCESSOR]), \
        "the two canonical lanes diverged; collision safety depends on them matching"


def test_correlation_output_queue_is_bounded_and_retries_are_capped():
    """§9: bounded queues, bounded retry, no hot reconnect loop."""
    out = corr_output()
    assert isinstance(out["buffer-size"], int) and 0 < out["buffer-size"] <= 10000
    assert isinstance(out["max-retry"], int) and 0 < out["max-retry"] <= 10
    assert out["num-workers"] == 1
    assert out["required-acks"] in ("wait-for-local", "wait-for-all")
    for key in ("timeout", "recovery-wait-time"):
        assert re.fullmatch(r"\d+[ms]s?", out[key]), \
            f"{key} must be an explicit duration (all IO has a timeout)"
    assert out["compression-codec"] == "snappy", \
        "every producer on this bus uses snappy"


# ── 4. the feature flag: default off, pinned off under mTLS, no secrets ───────

def test_default_deployment_loads_the_base_config():
    svc = gnmic_service()
    assert svc["command"] == [
        "subscribe", "--config", "/app/conf/${GNMIC_CONFIG_FILE:-gnmic.yaml}"], \
        "the config file must be env-selected with the BASE file as the default"
    assert svc["environment"]["ENABLE_GNMI_CORRELATION"] == \
        "${ENABLE_GNMI_CORRELATION:-false}", "the feature flag must default false"


def test_correlation_env_is_declared_for_both_config_files():
    """Every ${...} the overlay expands must be supplied by compose, or a
    flipped GNMIC_CONFIG_FILE boots against an unexpanded placeholder."""
    env = gnmic_service()["environment"]
    expanded = set(re.findall(r"\$\{([A-Z0-9_]+)\}", read(
        "deployment", "docker", "gnmic", "gnmic-correlation.yaml")))
    missing = sorted(expanded - set(env))
    assert not missing, f"gnmic-correlation.yaml expands undeclared env: {missing}"


def test_tls_profile_pins_the_flag_off():
    """No SVID and no ACL grant exist for gnmic under compose.tls.yml (SEC-006.3
    removed PLAINTEXT:9092, SEC-007.2 enforces ACLs on netops.metrics), so the
    lane is pinned off there and its broker env names the mTLS listener."""
    env = compose("compose.tls.yml")["services"]["gnmic"]["environment"]
    assert env["ENABLE_GNMI_CORRELATION"] == "false"
    assert env["GNMI_CORRELATION_BROKERS"] == "kafka:9094"


def test_the_lane_carries_no_secret():
    """The correlation output authenticates with nothing: its only env are a
    broker list and a topic. Any credential-shaped key here would be a literal
    in a tracked file (SEC-013)."""
    src = read("deployment", "docker", "gnmic", "gnmic-correlation.yaml")
    out = corr_output()
    for banned in ("password", "token", "sasl", "username", "auth"):
        assert banned not in out, \
            f"the correlation output grew a `{banned}` key — route it through env"
    for line in src.splitlines():
        if re.search(r"(?i)(password|token|secret)\s*:", line):
            assert "${" in line, f"credential-shaped literal in the config: {line!r}"


# ── 5. the shaper, run through gnmic's OWN engine ─────────────────────────────

def gnmic_image() -> str:
    return gnmic_service()["image"]


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    probe = subprocess.run(["docker", "image", "inspect", gnmic_image()],
                           capture_output=True, check=False)
    return probe.returncode == 0


needs_gnmic = pytest.mark.skipif(
    not docker_available(),
    reason="docker or the pinned gnmic image is unavailable")


def run_processors(events: list, names: list) -> list:
    """Apply the REAL gnmic processors to `events` and return the result.

    canon-override-ts is deliberately NOT in the caller's lists: it replaces the
    sample timestamp with collection time (correct at runtime, unpinnable in a
    fixture), and every other stage is deterministic.
    """
    with tempfile.TemporaryDirectory() as tmp:
        inp = os.path.join(tmp, "in.json")
        with open(inp, "w") as fh:
            fh.write(json.dumps(events) + "\n")
        cmd = ["docker", "run", "--rm", "--network", "none",
               "-v", f"{GNMIC_DIR}:/app/conf:ro", "-v", f"{inp}:/in.json:ro",
               "-e", "SRL_GNMI_PASS=unused", "-e", "EOS_GNMI_PASS=unused",
               "-e", "VICTORIA_WRITE_URL=http://unused/api/v1/write",
               "-e", "GNMI_CORRELATION_BROKERS=unused:9092",
               "-e", "GNMI_CORRELATION_TOPIC=netops.metrics",
               "--entrypoint", "/app/gnmic", gnmic_image(),
               "--config", "/app/conf/gnmic-correlation.yaml", "processor"]
        for n in names:
            cmd += ["--name", n]
        cmd += ["--input", "/in.json"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                             check=False)
        assert res.returncode == 0, f"gnmic processor failed: {res.stderr}"
        body = res.stdout[res.stdout.index("["):]
        return json.loads(body)


TS_NS = 1757000000000000000          # whole second: float64-exact round-trip
TS_ISO = "2025-09-04T15:33:20.000000000Z"

RAW_FIXTURES = [
    # Arista cEOS / OpenConfig — interface counters + oper-status, one event
    # carrying TWO values (the shaper must explode it).
    {"name": "oc-interfaces", "timestamp": TS_NS,
     "tags": {"source": "leaf1", "interface_name": "Ethernet1",
              "subscription-name": "oc-interfaces"},
     "values": {"interfaces/interface/state/counters/in-octets": 12345,
                "interfaces/interface/state/oper-status": "UP"}},
    # Arista cEOS / OpenConfig — BGP session state (gNMI-owned control plane).
    {"name": "oc-bgp", "timestamp": TS_NS,
     "tags": {"source": "leaf1", "subscription-name": "oc-bgp",
              "network-instance_name": "default",
              "neighbor_neighbor-address": "10.0.0.1",
              "protocol_identifier": "BGP", "protocol_name": "BGP"},
     "values": {"network-instances/network-instance/protocols/protocol/bgp/"
                "neighbors/neighbor/state/session-state": "ESTABLISHED"}},
    # Arista cEOS / OpenConfig — per-AFI prefixes received: canonical for
    # VictoriaMetrics, NOT an RCA family.
    {"name": "oc-bgp", "timestamp": TS_NS,
     "tags": {"source": "leaf1", "subscription-name": "oc-bgp",
              "network-instance_name": "default",
              "neighbor_neighbor-address": "10.0.0.1",
              "afi-safi_afi-safi-name": "IPV4_UNICAST"},
     "values": {"network-instances/network-instance/protocols/protocol/bgp/"
                "neighbors/neighbor/afi-safis/afi-safi/state/prefixes/received": 17}},
    # Nokia SR Linux native — IS-IS adjacency: canonical AND an RCA family since
    # tracker 222 (the `igp` family; identity = (device, neighbour)).
    {"name": "srl-isis", "timestamp": TS_NS,
     "tags": {"source": "spine1", "subscription-name": "srl-isis",
              "adjacency_neighbor-system-id": "0000.0000.0001",
              "instance_name": "default"},
     "values": {"network-instance/protocols/isis/instance/interface/"
                "adjacency/state": "up"}},
    # Nokia SR Linux native — memory: gNMI-OWNED (no SNMP source at all).
    {"name": "srl-cpu", "timestamp": TS_NS,
     "tags": {"source": "spine1", "subscription-name": "srl-cpu",
              "control_slot": "A"},
     "values": {"platform/control/memory/utilization": 73}},
    # ---- IS-IS DEPTH (frontend-wave #11). Every tag/value shape below is
    # transcribed VERBATIM from a live gNMI capture of lab spine1 (SRL 24.10,
    # 2026-09-02), including the leaf-list `.0` suffix gnmic appends to
    # oper-area-id and the bare "2" the level list-key carries. These are
    # canonical for VictoriaMetrics and must NOT reach the correlation bus.
    {"name": "srl-isis-db", "timestamp": TS_NS,
     "tags": {"source": "spine1", "subscription-name": "srl-isis-db",
              "network-instance_name": "default", "instance_name": "fabric",
              "level_level-number": "2"},
     "values": {"/srl_nokia-network-instance:network-instance/protocols/"
                "srl_nokia-isis:isis/instance/level/statistics/total-lsps": 6}},
    {"name": "srl-isis-db", "timestamp": TS_NS,
     "tags": {"source": "spine1", "subscription-name": "srl-isis-db",
              "network-instance_name": "default", "instance_name": "fabric",
              "level_level-number": "2"},
     "values": {"/srl_nokia-network-instance:network-instance/protocols/"
                "srl_nokia-isis:isis/instance/level/statistics/spf-runs": 10}},
    {"name": "srl-isis-db", "timestamp": TS_NS,
     "tags": {"source": "spine1", "subscription-name": "srl-isis-db",
              "network-instance_name": "default", "instance_name": "fabric"},
     "values": {"/srl_nokia-network-instance:network-instance/protocols/"
                "srl_nokia-isis:isis/instance/oper-area-id.0": "49.0001"}},
    {"name": "srl-isis-timers", "timestamp": TS_NS,
     "tags": {"source": "spine1", "subscription-name": "srl-isis-timers",
              "network-instance_name": "default", "instance_name": "fabric",
              "interface_interface-name": "ethernet-1/1.0",
              "adjacency_neighbor-system-id": "0100.0000.0011",
              "adjacency_adjacency-level": "L2"},
     "values": {"/srl_nokia-network-instance:network-instance/protocols/"
                "srl_nokia-isis:isis/instance/interface/adjacency/"
                "remaining-holdtime": 27}},
]

DETERMINISTIC_CHAIN = [p for p in CANONICAL_CHAIN if p != "canon-override-ts"]


@needs_gnmic
def test_full_chain_admits_only_gnmi_owned_rca_families():
    out = run_processors(RAW_FIXTURES, DETERMINISTIC_CHAIN + [OVERLAY_PROCESSOR])
    got = {(e["tags"]["device"], e["tags"]["metric"]) for e in out}
    assert got == {("leaf1", "device_bgp_peer_state"),
                   ("leaf1", "device_if_in_octets"),
                   ("leaf1", "device_if_oper_status"),
                   ("spine1", "device_isis_adj_state"),
                   ("spine1", "device_mem_percent")}, (
        "the correlation lane must carry exactly the gNMI-OWNED RCA families. "
        "Interfaces joined that set with tracker 230 (the ownership gate no "
        "longer withholds them and the SNMP profiles mark them Owner \"gnmi\"), "
        "so they must reach the bus for a gNMI-only device. IS-IS adjacency "
        "joined it with tracker 222 (the `igp` family). Per-AFI prefixes and "
        "the IS-IS depth series are still held back by the RCA allowlist, not "
        f"by ownership. got: {sorted(got)}")
    isis = next(e for e in out if e["tags"]["metric"] == "device_isis_adj_state")
    assert isis["tags"]["signal_family"] == "igp"
    assert isis["tags"]["unit"] == "state"
    assert isis["tags"]["neighbor"] == "0000.0000.0001", (
        "the shaper must normalise the protocol-dependent neighbour tag "
        "(isis_neighbor here) onto the single `neighbor` wire field")
    assert isis["tags"]["mvalue"] == "3", "SRL `up` → isisISAdjState up(3)"
    bgp = next(e for e in out if e["tags"]["metric"] == "device_bgp_peer_state")
    assert bgp["tags"]["signal_family"] == "bgp"
    assert bgp["tags"]["unit"] == "state"
    assert bgp["tags"]["peer"] == "10.0.0.1"
    assert bgp["tags"]["vendor"] == "arista"
    assert bgp["tags"]["mvalue"] == "6", "BGP enum → BGP4-MIB established(6)"
    assert bgp["tags"]["ts"] == TS_ISO, "ts must be RFC3339Nano, like the Go lane"


# The four IS-IS-depth families and the exact canonical labels each must carry.
# The label SET is the contract igpmon queries on (device/vrf/isis_level/
# isis_neighbor/ifName/area) — a missing or renamed label is an empty panel.
ISIS_DEPTH_EXPECTED = {
    "device_isis_lsp_count": (
        6, {"device": "spine1", "vrf": "default", "isis_level": "L2",
            "vendor": "nokia", "transport": "gnmi"}),
    "device_isis_spf_runs_total": (
        10, {"device": "spine1", "vrf": "default", "isis_level": "L2",
             "vendor": "nokia", "transport": "gnmi"}),
    "device_isis_area": (
        1, {"device": "spine1", "vrf": "default", "area": "49.0001",
            "vendor": "nokia", "transport": "gnmi"}),
    "device_isis_adj_hold_seconds": (
        27, {"device": "spine1", "vrf": "default", "isis_level": "L2",
             "ifName": "ethernet-1/1.0", "isis_neighbor": "0100.0000.0011",
             "vendor": "nokia", "transport": "gnmi"}),
}


@needs_gnmic
def test_isis_depth_families_are_canonicalized_with_their_join_labels():
    """frontend-wave #11: the LSDB/area/SPF/hold series igpmon probes for.

    Run WITHOUT the shaper — this is the VictoriaMetrics lane, which is the only
    lane these belong on. Asserted through gnmic's own engine, so the starlark
    info-series step and the level-number -> L1/L2 vocabulary are proven by the
    runtime that actually applies them, not by re-reading the YAML."""
    out = run_processors(RAW_FIXTURES, DETERMINISTIC_CHAIN)
    got = {}
    for e in out:
        # The ownership gate deletes SNMP-owned values, which can leave an event
        # with no `values` key at all — that is a dropped family, not a failure.
        for name, val in (e.get("values") or {}).items():
            if name.startswith("device_isis_") and name != "device_isis_adj_state":
                got[name] = (val, e["tags"])
    assert set(got) == set(ISIS_DEPTH_EXPECTED), (
        "the IS-IS depth families did not all survive the canonical chain: "
        f"got {sorted(got)}")
    for name, (want_val, want_tags) in ISIS_DEPTH_EXPECTED.items():
        val, tags = got[name]
        assert val == want_val, f"{name}: value {val!r} != {want_val!r}"
        assert tags == want_tags, f"{name}: labels {tags} != {want_tags}"


@needs_gnmic
def test_isis_level_vocabulary_is_single_valued_across_families():
    """One label name, one vocabulary. The adjacency series speaks L1/L2 and the
    level-scoped series carry a bare list-key digit; if the two ever diverge the
    LSDB count silently stops joining the adjacency it describes."""
    out = run_processors(RAW_FIXTURES, DETERMINISTIC_CHAIN)
    levels = {t["isis_level"] for t in ((e.get("tags") or {}) for e in out)
              if "isis_level" in t}
    assert levels and levels <= {"L1", "L2"}, (
        f"isis_level carries a non-canonical vocabulary: {sorted(levels)}")


def test_isis_depth_families_are_not_on_the_correlation_allowlist():
    """These are MONITORING series, not RCA evidence: they have no Go
    counterpart in rcaMetricFamilies and must never widen the bus allowlist."""
    admitted = set(jq_rca_table())
    base_src = read("deployment", "docker", "gnmic", "gnmic.yaml")
    for name in ("device_isis_lsp_count", "device_isis_spf_runs_total",
                 "device_isis_area", "device_isis_adj_hold_seconds"):
        assert name in base_src, \
            f"{name} is no longer a canonical gnmic name — refresh this guard"
        assert name not in admitted, \
            f"{name} reached the correlation allowlist without a Go counterpart"


@needs_gnmic
def test_shaper_explodes_multi_value_events_one_metric_each():
    """The reshape is family-agnostic. The gate is empty since tracker 230, so
    dropping it changes nothing here — it is dropped anyway so this stays a test
    of the RESHAPE and keeps working whichever way a future ownership flip goes."""
    chain = [p for p in DETERMINISTIC_CHAIN if p != "ownership-gate"]
    out = run_processors(RAW_FIXTURES[:1], chain + [OVERLAY_PROCESSOR])
    assert len(out) == 2, "one 2-value event must become two single-value events"
    by_metric = {e["tags"]["metric"]: e for e in out}
    assert set(by_metric) == {"device_if_in_octets", "device_if_oper_status"}
    for ev in out:
        assert len(ev["values"]) == 1
        assert ev["tags"]["signal_family"] == "interface"
        assert ev["tags"]["ifName"] == "Ethernet1"
    assert by_metric["device_if_oper_status"]["tags"]["mvalue"] == "1", \
        "OpenConfig UP → IF-MIB up(1)"
    assert by_metric["device_if_in_octets"]["tags"]["unit"] == "bytes"


@needs_gnmic
def test_shaper_refuses_samples_that_cannot_ground_a_signal():
    """Zero trust at the boundary (§3): evidence handle_metric could not ground
    is refused HERE, not counted as a drop on the bus."""
    hostile = [
        # no device tag
        {"name": "x", "timestamp": TS_NS, "tags": {"ifName": "eth0"},
         "values": {"device_if_in_octets": 1}},
        # interface family without ifName
        {"name": "x", "timestamp": TS_NS, "tags": {"device": "d1"},
         "values": {"device_if_in_octets": 1}},
        # bgp family without peer
        {"name": "x", "timestamp": TS_NS, "tags": {"device": "d1"},
         "values": {"device_bgp_peer_state": 6}},
        # igp family without any neighbour tag (tracker 222)
        {"name": "x", "timestamp": TS_NS, "tags": {"device": "d1"},
         "values": {"device_isis_adj_state": 3}},
        {"name": "x", "timestamp": TS_NS,
         "tags": {"device": "d1", "isis_neighbor": ""},
         "values": {"device_isis_adj_state": 3}},
        {"name": "x", "timestamp": TS_NS, "tags": {"device": "d1"},
         "values": {"device_ospf_nbr_state": 8}},
        # non-numeric value (an unmapped enum that slipped the converter)
        {"name": "x", "timestamp": TS_NS, "tags": {"device": "d1"},
         "values": {"device_mem_percent": "NOT_A_NUMBER"}},
        # not in the allowlist
        {"name": "x", "timestamp": TS_NS, "tags": {"device": "d1"},
         "values": {"device_if_totally_unknown": 1}},
    ]
    assert run_processors(hostile, [OVERLAY_PROCESSOR]) == []


# ── 6. the msg-template, run through Go's OWN text/template ───────────────────

RENDER_MAIN = '''package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/template"
)

// gnmic's template func (pkg/gtemplate/template_funcs.go): fromJSON marshals.
func fromJSON(v any) string { a, _ := json.Marshal(v); return string(a) }

// Mirrors outputs.ExecTemplate + gtemplate.CreateTemplate (pkg/outputs/output.go):
// the marshalled event is json.Unmarshal-ed into `any` and handed to the
// template, which is parsed with Option("missingkey=zero").
func main() {
	tplRaw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	evRaw, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	tpl, err := template.New("msg-template").Option("missingkey=zero").
		Funcs(template.FuncMap{"fromJSON": fromJSON}).Parse(string(tplRaw))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var input any
	if err := json.Unmarshal(evRaw, &input); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := tpl.Execute(os.Stdout, input); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
'''

needs_go = pytest.mark.skipif(shutil.which("go") is None,
                              reason="the Go toolchain is unavailable")


def render(event: dict) -> str:
    """Render one shaped event through the output's msg-template, using the
    same engine gnmic uses. Returns the raw Kafka message body."""
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "main.go"), "w") as fh:
            fh.write(RENDER_MAIN)
        with open(os.path.join(tmp, "go.mod"), "w") as fh:
            fh.write("module render\n\ngo 1.22\n")
        with open(os.path.join(tmp, "tpl.txt"), "w") as fh:
            fh.write(corr_output()["msg-template"])
        with open(os.path.join(tmp, "ev.json"), "w") as fh:
            json.dump(event, fh)
        env = dict(os.environ, GOFLAGS="-mod=mod", GOPROXY="off")
        res = subprocess.run(["go", "run", ".", "tpl.txt", "ev.json"],
                             cwd=tmp, capture_output=True, text=True,
                             timeout=300, env=env, check=False)
        assert res.returncode == 0, f"template render failed: {res.stderr}"
        return res.stdout


def shaped(metric, family, unit, value, device="leaf1", **tags) -> dict:
    base = {"device": device, "metric": metric, "signal_family": family,
            "unit": unit, "mvalue": str(value), "ts": TS_ISO}
    base.update(tags)
    return {"name": "sub", "timestamp": TS_NS, "tags": base,
            "values": {metric: value}}


@needs_go
def test_msg_template_renders_the_metric_event_contract():
    cases = [
        (shaped("device_if_in_octets", "interface", "bytes", 12345,
                ifName="Ethernet1", vendor="arista"),
         {"observer_type": "device", "modality_class": "device_telemetry",
          "collection_path": "gnmi_subscribe", "device": "leaf1",
          "vendor": "arista", "if_name": "Ethernet1",
          "signal_family": "interface", "metric": "device_if_in_octets",
          "value": 12345, "unit": "bytes", "ts": TS_ISO}),
        (shaped("device_if_oper_status", "interface", "state", 1,
                ifName="Ethernet1", vendor="arista"),
         {"observer_type": "device", "modality_class": "device_telemetry",
          "collection_path": "gnmi_subscribe", "device": "leaf1",
          "vendor": "arista", "if_name": "Ethernet1",
          "signal_family": "interface", "metric": "device_if_oper_status",
          "value": 1, "unit": "state", "ts": TS_ISO}),
        (shaped("device_bgp_peer_state", "bgp", "state", 6,
                peer="10.0.0.1", vrf="default", vendor="arista"),
         {"observer_type": "device", "modality_class": "device_telemetry",
          "collection_path": "gnmi_subscribe", "device": "leaf1",
          "vendor": "arista", "peer": "10.0.0.1", "signal_family": "bgp",
          "metric": "device_bgp_peer_state", "value": 6, "unit": "state",
          "ts": TS_ISO}),
        (shaped("device_isis_adj_state", "igp", "state", 3,
                device="spine1", neighbor="0000.0000.0001", vendor="nokia"),
         {"observer_type": "device", "modality_class": "device_telemetry",
          "collection_path": "gnmi_subscribe", "device": "spine1",
          "vendor": "nokia", "neighbor": "0000.0000.0001",
          "signal_family": "igp", "metric": "device_isis_adj_state",
          "value": 3, "unit": "state", "ts": TS_ISO}),
        (shaped("device_mem_percent", "device_resource", "percent", 73,
                device="spine1", vendor="nokia"),
         {"observer_type": "device", "modality_class": "device_telemetry",
          "collection_path": "gnmi_subscribe", "device": "spine1",
          "vendor": "nokia", "signal_family": "device_resource",
          "metric": "device_mem_percent", "value": 73, "unit": "percent",
          "ts": TS_ISO}),
    ]
    for event, expected in cases:
        body = render(event)
        got = json.loads(body)
        assert got == expected, f"{event['tags']['metric']}: {body}"
        # Field ORDER too: both producers put the same bytes on the topic.
        order = [k for k in CONTRACT_ORDER if k in got]
        assert list(got) == order, f"field order drifted: {list(got)}"


@needs_go
def test_msg_template_neutralizes_hostile_device_supplied_identity():
    """Device-supplied tags (ifName, peer, the target name) are untrusted. They
    are rendered through fromJSON = json.Marshal, so a quote cannot break out
    of the JSON and inject a field."""
    evil = 'Eth1","observer_type":"forged'
    body = render(shaped("device_if_in_octets", "interface", "bytes", 1,
                         device='le"af1', ifName=evil, vendor="arista"))
    got = json.loads(body)
    assert got["if_name"] == evil and got["device"] == 'le"af1'
    assert got["observer_type"] == "device", "field injection was not neutralized"


@needs_go
def test_msg_template_emits_the_value_unquoted_as_a_json_number():
    body = render(shaped("device_cpu_percent", "device_resource", "percent", 42))
    assert '"value":42' in body, body
    assert isinstance(json.loads(body)["value"], (int, float))
