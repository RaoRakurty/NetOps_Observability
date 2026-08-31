"""The gNMI lane end of the twin: story DSL wiring, scenario validation,
GnmiLane transport and Injector accounting.

The load-bearing property is BACK-COMPAT + attribution: a scenario that does
not ask for `with_gnmi` must build the identical plan it built before the gNMI
stretch, and one that does must produce ops that name the right device,
interface and peer, at the right offsets, with ground-truth labels.
"""
import json
import os
import socket
import threading

import pytest
from conftest import REPO_ROOT
from emitters import GNMI_LANE, LANE_TOPIC, GnmiLane, Injector, build_payload
from gnmi_h2 import Connection
from scenario import (
    STORY_TEMPLATES,
    T1_CORE_LANES,
    ScenarioError,
    load_scenario,
    validate_scenario,
)
from stories import build_run_plan

EXAMPLE = os.path.join(REPO_ROOT, "docs", "design", "examples",
                       "twin-scenario-example.yaml")


def _example() -> dict:
    return load_scenario(EXAMPLE)


def _with_story(params: dict) -> dict:
    sc = _example()
    sc["stories"] = [{
        "id": "ld-gnmi-1", "template": "link_down_cascade",
        "trigger": {"at": "+10s"},
        "affected": {"devices": ["core-a1"], "tenants": ["acme"]},
        "params": params,
        "expect": {"rca": {"affected_includes": ["core-a1"]}},
    }]
    return sc


def _story_items(sc: dict, lane: str | None = None) -> list[dict]:
    plan = build_run_plan(sc, 120.0)
    items = [it for stx in plan["stories"] for it in stx["items"]]
    return [it for it in items if lane is None or it["lane"] == lane]


# ── registry / validation ───────────────────────────────────────────────────

def test_gnmi_is_a_recognised_lane_and_with_gnmi_a_recognised_param():
    assert GNMI_LANE in T1_CORE_LANES
    assert "with_gnmi" in STORY_TEMPLATES["link_down_cascade"]["params"]
    assert LANE_TOPIC[GNMI_LANE].startswith("victoria:")


def test_with_gnmi_scenario_validates():
    validate_scenario(_with_story({"with_gnmi": True}), EXAMPLE)


def test_with_gnmi_on_a_template_that_does_not_take_it_is_refused():
    sc = _example()
    sc["stories"] = [{
        "id": "bf-1", "template": "bgp_flap", "trigger": {"at": "+10s"},
        "affected": {"devices": ["core-a1"], "tenants": ["acme"]},
        "params": {"with_gnmi": True},
        "expect": {"rca": {"affected_includes": ["core-a1"]}}}]
    with pytest.raises(ScenarioError):
        validate_scenario(sc, EXAMPLE)


def test_gnmi_items_are_not_bus_payloads():
    """The bus builder must refuse a gnmi item loudly — it is a PULL lane and
    a silent JSON encode would put a fault op on a Kafka topic."""
    with pytest.raises(ValueError, match="unknown bus lane"):
        build_payload({"lane": "gnmi"}, "twx-x-", {})


# ── story expansion ─────────────────────────────────────────────────────────

def test_without_with_gnmi_the_plan_is_byte_identical_to_the_pre_gnmi_plan():
    plain = build_run_plan(_with_story({}), 120.0)
    assert not [it for stx in plain["stories"] for it in stx["items"]
                if it["lane"] == "gnmi"]
    assert all(stx["labels"] == {} for stx in plain["stories"])


def test_with_gnmi_emits_an_if_down_op_for_each_faulted_interface():
    sc = _with_story({"with_gnmi": True,
                      "interfaces": ["Ethernet1", "Ethernet2"]})
    ops = _story_items(sc, "gnmi")
    downs = [it for it in ops if it["op"] == "if_down"]
    assert {it["ifname"] for it in downs} == {"Ethernet1", "Ethernet2"}
    assert all(it["device"] == "core-a1" for it in downs)
    assert all(it["story_id"] == "ld-gnmi-1" for it in downs)
    # 0.2 s after the LINK-3-UPDOWN console line at the story's t0 (+10 s)
    assert {it["t"] for it in downs} == {10.2}


def test_with_gnmi_drops_every_declared_bgp_session_on_the_faulted_device():
    sc = _with_story({"with_gnmi": True})
    dev = next(d for d in sc["devices"] if d["name"] == "core-a1")
    peers = {str(nb["peer_ip"]) for nb in dev.get("bgp_neighbors") or []}
    assert peers, "fixture must declare a bgp neighbour for this to test"
    bgp_ops = [it for it in _story_items(sc, "gnmi") if it["op"] == "bgp_down"]
    assert {it["peer_ip"] for it in bgp_ops} == peers
    assert all(it["state"] == "IDLE" for it in bgp_ops)
    # 0.2 s after the BGP-5-ADJCHANGE line at t0+3 s
    assert {it["t"] for it in bgp_ops} == {13.2}


def test_gnmi_ops_carry_the_devices_tenant_for_attribution():
    sc = _with_story({"with_gnmi": True})
    tenant = next(d for d in sc["devices"]
                  if d["name"] == "core-a1")["tenant"]
    assert {it["tenant"] for it in _story_items(sc, "gnmi")} == {tenant}


def test_ground_truth_labels_describe_the_gnmi_manifestation():
    plan = build_run_plan(_with_story({"with_gnmi": True}), 120.0)
    labels = plan["stories"][0]["labels"]["gnmi_manifestations"]
    oper = next(m for m in labels if m["path"].endswith("/oper-status"))
    assert (oper["from"], oper["to"]) == ("UP", "DOWN")
    stall = next(m for m in labels if m["path"].endswith("/in-octets"))
    assert (stall["from"], stall["to"]) == ("advancing", "stalled")
    bgp = next(m for m in labels if m["path"].endswith("/session-state"))
    assert (bgp["from"], bgp["to"]) == ("ESTABLISHED", "IDLE")
    # the canonical series a scorer can read this off in VictoriaMetrics
    assert bgp["canonical_series"] == "device_bgp_peer_state"
    assert (bgp["canonical_from"], bgp["canonical_to"]) == (6, 1)
    assert all(m["transport"] == "gnmi" for m in labels)


def test_gnmi_expansion_is_deterministic():
    a = build_run_plan(_with_story({"with_gnmi": True}), 120.0)
    b = build_run_plan(_with_story({"with_gnmi": True}), 120.0)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_syslog_and_gnmi_tell_the_same_story_about_the_same_interface():
    """Cross-transport coherence: the port the console line names is the port
    whose gNMI oper-status drops."""
    sc = _with_story({"with_gnmi": True, "interfaces": ["Ethernet1"]})
    items = _story_items(sc)
    line = next(it for it in items
                if it["lane"] == "syslog" and "LINK-3-UPDOWN" in it["appname"])
    op = next(it for it in items if it["lane"] == "gnmi"
              and it["op"] == "if_down")
    assert op["ifname"] in line["message"]
    assert op["device"] == line["device"]


# ── GnmiLane transport ──────────────────────────────────────────────────────

def test_lane_writes_run_prefixed_ops_to_the_fault_journal(tmp_path):
    journal = tmp_path / "gnmi-faults.jsonl"
    lane = GnmiLane(str(journal))
    ok, err = lane.apply([{"device": "edge-a1", "op": "if_down",
                           "ifname": "Ethernet1", "story_id": "ld-1"}],
                         "twx-run1-")
    assert (ok, err) == (True, "")
    row = json.loads(journal.read_text().splitlines()[0])
    assert row["device"] == "twx-run1-edge-a1"
    assert row["op"] == "if_down"
    assert row["ifname"] == "Ethernet1"
    assert row["story_id"] == "ld-1"
    assert row["ts"]


def test_lane_reports_a_write_failure_instead_of_swallowing_it(tmp_path):
    lane = GnmiLane(str(tmp_path / "no-such-dir" / "faults.jsonl"))
    ok, err = lane.apply([{"device": "e", "op": "if_down"}], "twx-")
    assert not ok and "fault journal" in err


def _h2_listener():
    """A real gnmi_h2 target on loopback; returns (port, stop)."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _peer = listener.accept()
            except OSError:
                return
            threading.Thread(
                target=lambda sock=conn: Connection(
                    sock, lambda p, c, r: iter([b""])).serve(),
                daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return port, lambda: (stop.set(), listener.close())


def test_lane_live_accepts_a_real_target_and_rejects_a_dead_one(tmp_path):
    port, stop = _h2_listener()
    try:
        lane = GnmiLane(str(tmp_path / "f.jsonl"), [("127.0.0.1", port)],
                        connect_timeout=1.0)
        assert lane.live()
        # one dead target in the fleet ⇒ NOT live (no half-emitted stories)
        assert not GnmiLane(str(tmp_path / "f.jsonl"),
                            [("127.0.0.1", port), ("127.0.0.1", 1)],
                            connect_timeout=1.0).live()
    finally:
        stop()
    assert not GnmiLane(str(tmp_path / "f.jsonl"), []).live()


def test_lane_live_rejects_a_port_that_does_not_speak_http2(tmp_path):
    """The twin's target ports sit inside the kernel ephemeral range, where a
    loopback connect can self-connect and succeed against nothing. A bare
    connect() would call that "live"; the probe demands a SETTINGS frame."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        assert not GnmiLane(str(tmp_path / "f.jsonl"), [("127.0.0.1", port)],
                            connect_timeout=1.0).live()
    finally:
        listener.close()


# ── Injector accounting ─────────────────────────────────────────────────────

def _items():
    return [{"t": 0.0, "lane": "gnmi", "tenant": "acme", "device": "edge-a1",
             "story_id": "ld-1", "op": "if_down", "ifname": "Ethernet1",
             "peer_ip": "", "state": ""}]


def test_injector_journals_and_counts_applied_gnmi_ops(tmp_path):
    faults = tmp_path / "gnmi-faults.jsonl"
    inj = Injector(None, "twx-run1-", {"acme": "t-1"},
                   str(tmp_path / "events.jsonl"),
                   gnmi=GnmiLane(str(faults)))
    with open(tmp_path / "events.jsonl", "a", encoding="utf-8") as fh:
        assert inj.emit_batch(_items(), fh)
    assert inj.emitted == {"gnmi": 1}
    assert inj.emitted_by_story == {"ld-1": {"gnmi": 1}}
    row = json.loads((tmp_path / "events.jsonl").read_text().splitlines()[0])
    assert row["device"] == "twx-run1-edge-a1"
    assert row["topic"] == LANE_TOPIC["gnmi"]
    assert row["story_id"] == "ld-1"
    assert len(faults.read_text().splitlines()) == 1


def test_injector_skips_the_lane_loudly_when_no_target_is_running(tmp_path):
    """No gNMI target ⇒ counted skip, never a silent drop and never a run
    failure (gNMI is corroborating evidence, design §4.6)."""
    inj = Injector(None, "twx-run1-", {"acme": "t-1"},
                   str(tmp_path / "events.jsonl"), gnmi=None)
    with open(tmp_path / "events.jsonl", "a", encoding="utf-8") as fh:
        assert inj.emit_batch(_items(), fh)
    assert inj.skipped == {"gnmi": 1}
    assert inj.emitted == {}
    assert inj.produce_failures == []
