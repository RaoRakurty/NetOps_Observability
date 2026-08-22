"""F-18 — idempotent OpenSearch indexing via Kafka-coordinate document ids.

THE DEFECT (run 08221846o1fo, 2026-08-22): a slow OpenSearch made a bulk
request time out client-side AFTER the server had applied it; the sink
retried, and 24,063 docs — one ~60 s window — were indexed twice (same Kafka
partition+offset, two auto _ids, verified live). The accounting gate caught
it as docs > injected.

THE FIX: the shared &log_lane anchor stamps `cx_event_id` from the record's
Kafka coordinate (topic:partition:offset), and every OS log sink already
routes `id_key: cx_event_id` (the F-11 upsert mechanism) — so a retried bulk
upserts instead of duplicating.

SECURITY (the reason the stamp is safe): the anchor STRIPS producer-supplied
cx_event_id first (non-restore-shaped), and `offset`/`partition` are
consumer-side source metadata that overwrite payload-forged values — probed
live: a payload carrying offset=424242/partition=99 was stored with its real
coordinate 3381593/1. An event missing coordinates keeps an AUTO id rather
than collapsing into a shared fallback id: duplication is recoverable,
collapse is not.

Behavioral cases run through the REAL Vector image (scripts/vrl-harness.py)
and SKIP when it is unavailable; the static wiring assertions always run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


def read(*rel: str) -> str:
    return (ROOT.joinpath(*rel)).read_text(encoding="utf-8")


def _vector_cfg(tier: str) -> dict:
    return yaml.safe_load(read("deployment", "docker", f"vector-{tier}"
                               if tier != "router" else "vector-router", "vector.yaml"))


def _harness():
    spec = importlib.util.spec_from_file_location(
        "vrl_harness", ROOT / "scripts" / "vrl-harness.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vrl_harness"] = mod
    spec.loader.exec_module(mod)
    return mod


CFG = _vector_cfg("router")
ANCHOR = CFG["transforms"]["applogs_tagged"]["source"]


# ── static wiring: the stamp exists and every log sink routes it ─────────────

def test_the_anchor_stamps_the_kafka_coordinate():
    assert "cxk" in ANCHOR and ".cx_event_id = join!" in ANCHOR, \
        "the F-18 coordinate stamp is gone from the log_lane anchor"
    assert 'exists(.offset) && exists(.partition)' in ANCHOR.replace(
        "exists(.cx_event_id) && ", ""), \
        "the stamp no longer requires REAL coordinates — a missing-coordinate " \
        "event would collapse into a shared fallback id"


def test_every_log_lane_shares_the_stamping_anchor():
    for lane in ("syslog_tagged", "snmptrap_tagged", "cloudlogs_tagged"):
        assert CFG["transforms"][lane]["source"] == ANCHOR, \
            f"{lane} drifted from the anchor — its lane can duplicate again"


def test_every_log_elasticsearch_sink_routes_the_id():
    routed = []
    for name, sink in CFG["sinks"].items():
        if sink.get("type") != "elasticsearch":
            continue
        inputs = " ".join(sink.get("inputs", []))
        if any(l in inputs for l in ("syslog", "snmptrap", "applogs",
                                     "cloudlogs", "deadletter", "quarantine")):
            routed.append((name, sink.get("id_key")))
    assert routed, "no log-lane elasticsearch sinks found — wiring moved"
    missing = [n for n, k in routed if k != "cx_event_id"]
    assert not missing, f"log sinks without id_key=cx_event_id: {missing}"


# ── behavioral, through the real Vector image ────────────────────────────────

def _run(events):
    h = _harness()
    if not h.available():
        pytest.skip("docker or the pinned Vector image unavailable")
    return h.run_vrl(ANCHOR, events)


def _base(**over):
    ev = {"hostname": "dev-1", "message": "m", "timestamp": "2026-08-22T10:00:00Z",
          "tenant_id": "acme", "topic": "netops.syslog", "partition": 3,
          "offset": 5107939}
    ev.update(over)
    return ev


def test_normal_event_gets_the_coordinate_id():
    out = _run([_base()])
    assert out[0]["cx_event_id"] == "cxk:netops.syslog:3:5107939"


def test_the_id_is_deterministic_across_a_replay():
    a, b = _run([_base()]), _run([_base()])
    assert a[0]["cx_event_id"] == b[0]["cx_event_id"], \
        "replaying the same record minted a different id — retries would duplicate"


def test_restored_quarantine_uuid_survives():
    ev = _base(cx_event_id="0f8fad5b-d9cb-469f-a165-70867728950e",
               cx_restored_from="quarantine")
    out = _run([ev])
    assert out[0]["cx_event_id"] == "0f8fad5b-d9cb-469f-a165-70867728950e", \
        "the restore upsert id was overwritten — INV-F11-08 regressed"


def test_forged_id_is_stripped_then_restamped_from_the_coordinate():
    ev = _base(cx_event_id="attacker-chosen-id")
    out = _run([ev])
    assert out[0]["cx_event_id"] == "cxk:netops.syslog:3:5107939", \
        "a producer-forged non-restore id survived the strip"


def test_missing_coordinates_never_collapse_into_a_fallback_id():
    ev = _base()
    del ev["offset"]
    out = _run([ev])
    assert "cx_event_id" not in out[0], \
        "an event without coordinates was stamped — a shared fallback id " \
        "would COLLAPSE distinct events into one document"
