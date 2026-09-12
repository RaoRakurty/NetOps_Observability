# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""`twin.py`'s gNMI wiring, exercised for real: rendering the run's target
manifest + gnmic targets file, launching the target server as a child process,
proving the lane is live, applying a fault op through it, and stopping it at
teardown.

The Run phases are driven as unbound methods against a light stub so the test
never needs a live stack — but the SUBPROCESS is real, so this covers the
launch argv, the readiness handshake and the teardown signal path that unit
tests of `gnmi_server` cannot.
"""
import json
import os
import socket

import gnmi_proto as gp
import pytest
import twin
from emitters import GnmiLane
from gnmi_server import DeviceTarget

SCENARIO = {"devices": [
    {"name": "edge-a1", "tenant": "acme",
     "interfaces": [{"name": "Ethernet1"}, {"name": "Ethernet2"}],
     "bgp_neighbors": [{"peer_ip": "203.0.113.9"}]},
    {"name": "core-1", "tenant": "acme",
     "interfaces": [{"name": "Ethernet1"}], "bgp_neighbors": []}]}


class _Stack:
    project = "netops"


class _Run:
    """The attributes twin.Run's gNMI phases actually touch."""

    def __init__(self, run_dir: str) -> None:
        self.run_dir = run_dir
        self.sc = SCENARIO
        self.prefix = "twx-test0-"
        self.runid = "test0"
        self.state: dict = {}
        self.stack = _Stack()

    def hb(self, _phase: str) -> None:
        pass

    def save_state(self) -> None:
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setattr(twin, "GNMI_BASE_PORT", _free_port())
    r = _Run(str(tmp_path))
    twin.Run.setup_gnmi_targets(r)
    yield r
    twin.stop_gnmi_targets(r.state)


def test_setup_renders_manifest_and_targets_into_the_run_dir(run):
    with open(run.state["gnmi_manifest"], encoding="utf-8") as fh:
        manifest = json.load(fh)
    assert [d["name"] for d in manifest["devices"]] == ["twx-test0-edge-a1",
                                                        "twx-test0-core-1"]
    assert manifest["listen_host"] == "0.0.0.0"
    with open(os.path.join(run.run_dir, "gnmi", "gnmic-targets.yaml"),
              encoding="utf-8") as fh:
        targets = fh.read()
    assert "name: twx-test0-edge-a1" in targets
    # the advertised host must be reachable FROM a container on the stack net
    assert f"{manifest['advertise_host']}:{manifest['devices'][0]['port']}:" \
        in targets
    assert run.state["gnmi_advertise_host"] == manifest["advertise_host"]


def test_setup_is_unconditional_so_the_targets_file_always_exists(run):
    """The rendered targets file is the artefact an operator merges into
    gnmic.yaml — it must not depend on a story having asked for the lane."""
    assert os.path.exists(os.path.join(run.run_dir, "gnmi",
                                       "gnmic-targets.yaml"))
    assert "gnmi_target_pid" not in run.state


def test_a_plan_with_no_gnmi_items_starts_no_listener(run):
    plan = {"baseline": [{"lane": "syslog"}], "stories": []}
    assert twin.Run._gnmi_lane(run, plan) is None
    assert "gnmi_target_pid" not in run.state


def test_lane_start_serves_the_targets_and_applies_a_fault_end_to_end(run):
    plan = {"baseline": [],
            "stories": [{"items": [{"lane": "gnmi", "device": "edge-a1"}]}]}
    lane = twin.Run._gnmi_lane(run, plan)
    assert isinstance(lane, GnmiLane)
    assert lane.live()
    assert run.state["gnmi_target_pid"]

    # a real gNMI Get over the real socket: the port is serving OpenConfig
    port = run.state["gnmi_targets"][0]["port"]
    with socket.create_connection(("127.0.0.1", port), 5.0):
        pass

    ok, err = lane.apply([{"device": "edge-a1", "op": "if_down",
                           "ifname": "Ethernet1", "story_id": "ld-1"}],
                         run.prefix)
    assert (ok, err) == (True, "")
    journal = os.path.join(run.run_dir, "gnmi-faults.jsonl")
    with open(journal, encoding="utf-8") as fh:
        row = json.loads(fh.read().splitlines()[0])
    assert row["device"] == "twx-test0-edge-a1"

    # the op the lane wrote is one the served device model accepts
    with open(run.state["gnmi_manifest"], encoding="utf-8") as fh:
        manifest = json.load(fh)
    device = DeviceTarget(manifest["devices"][0])
    device.apply(row)
    oper = {gp.path_str(p): v for p, v in device.leaves()}
    assert oper["/interfaces/interface[name=Ethernet1]/state/oper-status"] \
        == "DOWN"


def test_stop_gnmi_targets_reaps_the_child_and_is_idempotent(run):
    plan = {"baseline": [],
            "stories": [{"items": [{"lane": "gnmi", "device": "edge-a1"}]}]}
    lane = twin.Run._gnmi_lane(run, plan)
    assert lane is not None and lane.live()
    assert twin.stop_gnmi_targets(run.state) == []
    assert not lane.live()
    # a second teardown (or a teardown of a run that never started one) is a
    # no-op, not a problem report
    assert twin.stop_gnmi_targets(run.state) == []
    assert twin.stop_gnmi_targets({}) == []
