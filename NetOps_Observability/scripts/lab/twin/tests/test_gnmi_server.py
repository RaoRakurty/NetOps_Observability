# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Twin gNMI target (gnmi_server): served state, subscribe semantics, fault
hooks, and the manifest/targets artefacts.

Deterministic by construction: every test drives an injected clock, so counter
accumulation and stall are exact arithmetic rather than a sleep race. The path
shapes are asserted against the real subscription paths in
`deployment/docker/gnmic/gnmic.yaml` — if that file's subscriptions move, these
tests are the thing that notices.
"""
import json

import gnmi_proto as gp
import pytest
from gnmi_h2 import GRPC_UNIMPLEMENTED, GrpcStatus, StreamContext
from gnmi_proto import (
    LIST_MODE_ONCE,
    LIST_MODE_POLL,
    SUB_MODE_ON_CHANGE,
    SUB_MODE_SAMPLE,
    enc_msg,
    enc_path,
    enc_uint,
    parse,
    parse_path,
    path_matches,
    path_str,
)
from gnmi_server import (
    DeviceTarget,
    FaultJournalWatcher,
    TargetService,
    generate_manifest,
    render_gnmic_targets,
)

OC_INTERFACES = ["/interfaces/interface/state/counters",
                 "/interfaces/interface/state/oper-status",
                 "/interfaces/interface/state/admin-status"]
OC_BGP_SESSION = ("/network-instances/network-instance[name=*]/protocols"
                  "/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor"
                  "/state/session-state")

SPEC = {
    "name": "twx-t-edge-a1", "tenant": "acme", "port": 57400,
    "interfaces": [{"name": "Ethernet1", "ifindex": 1,
                    "rate_bytes_s": 1000.0},
                   {"name": "Ethernet2", "ifindex": 2,
                    "rate_bytes_s": 2000.0}],
    "bgp_neighbors": [{"peer_ip": "203.0.113.9"}],
}


class Clock:
    """Injected monotonic clock — the whole state model is a function of it."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _target(clock=None):
    return DeviceTarget(SPEC, clock=clock or Clock())


def _leaf(pairs, path_text):
    for path, value in pairs:
        if path_str(path) == path_text:
            return value
    raise AssertionError(f"{path_text} not served; got "
                         f"{[path_str(p) for p, _v in pairs][:8]}")


# ── served surface ──────────────────────────────────────────────────────────

def test_serves_exactly_the_leaves_gnmic_subscribes_to():
    pairs = _target().leaves()
    served = [path_str(p) for p, _v in pairs]
    for sub in OC_INTERFACES:
        assert any(path_matches(parse_path(sub), p) for p, _v in pairs), sub
    assert any(path_matches(parse_path(OC_BGP_SESSION), p) for p, _v in pairs)
    # counters, oper/admin status for both ports; 3 BGP leaves for one peer
    assert len(served) == 2 * (8 + 2) + 3


def test_status_and_session_enums_use_the_spellings_canon_processors_expect():
    """gnmic.yaml's canon-status-enums maps UP/DOWN and canon-bgp-enums maps
    ESTABLISHED/IDLE — anchored regexes, so the spelling is load-bearing."""
    pairs = _target().leaves()
    assert _leaf(pairs, "/interfaces/interface[name=Ethernet1]/state"
                        "/oper-status") == "UP"
    assert _leaf(pairs, "/interfaces/interface[name=Ethernet1]/state"
                        "/admin-status") == "UP"
    assert _leaf(pairs, "/network-instances/network-instance[name=default]"
                        "/protocols/protocol[identifier=BGP][name=BGP]/bgp"
                        "/neighbors/neighbor[neighbor-address=203.0.113.9]"
                        "/state/session-state") == "ESTABLISHED"


def test_counters_advance_deterministically_with_the_clock():
    clock = Clock()
    dev = _target(clock)
    clock.advance(10.0)
    assert _leaf(dev.leaves(), "/interfaces/interface[name=Ethernet1]/state"
                               "/counters/in-octets") == 10_000
    clock.advance(5.0)
    assert _leaf(dev.leaves(), "/interfaces/interface[name=Ethernet1]/state"
                               "/counters/in-octets") == 15_000


def test_select_filters_to_the_requested_subscription_paths():
    dev = _target()
    only_oper = dev.select([parse_path(OC_INTERFACES[1])])
    assert {path_str(p) for p, _v in only_oper} == {
        "/interfaces/interface[name=Ethernet1]/state/oper-status",
        "/interfaces/interface[name=Ethernet2]/state/oper-status"}


# ── fault hooks ─────────────────────────────────────────────────────────────

def test_if_down_flips_oper_status_and_stalls_that_ports_counters_only():
    clock = Clock()
    dev = _target(clock)
    clock.advance(10.0)
    dev.apply({"op": "if_down", "ifname": "Ethernet1"})
    clock.advance(60.0)
    pairs = dev.leaves()
    assert _leaf(pairs, "/interfaces/interface[name=Ethernet1]/state"
                        "/oper-status") == "DOWN"
    # stalled at the value it held when the port went down
    assert _leaf(pairs, "/interfaces/interface[name=Ethernet1]/state"
                        "/counters/in-octets") == 10_000
    # the sibling port is untouched: 70 s x 2000 B/s
    assert _leaf(pairs, "/interfaces/interface[name=Ethernet2]/state"
                        "/counters/in-octets") == 140_000
    # admin-status stays UP — a link failure is not a shutdown
    assert _leaf(pairs, "/interfaces/interface[name=Ethernet1]/state"
                        "/admin-status") == "UP"


def test_if_up_resumes_accumulation_without_rewriting_history():
    clock = Clock()
    dev = _target(clock)
    clock.advance(10.0)
    dev.apply({"op": "if_down", "ifname": "Ethernet1"})
    clock.advance(100.0)
    dev.apply({"op": "if_up", "ifname": "Ethernet1"})
    clock.advance(5.0)
    assert _leaf(dev.leaves(), "/interfaces/interface[name=Ethernet1]/state"
                               "/counters/in-octets") == 15_000


def test_counter_stall_without_a_link_down_keeps_oper_status_up():
    """A silent blackhole: traffic stops, the port still reports UP. The twin
    must be able to express it, because that is the fault operators miss."""
    clock = Clock()
    dev = _target(clock)
    clock.advance(10.0)
    dev.apply({"op": "counter_stall", "ifname": "Ethernet1"})
    clock.advance(50.0)
    pairs = dev.leaves()
    assert _leaf(pairs, "/interfaces/interface[name=Ethernet1]/state"
                        "/oper-status") == "UP"
    assert _leaf(pairs, "/interfaces/interface[name=Ethernet1]/state"
                        "/counters/in-octets") == 10_000


def test_bgp_down_moves_session_state_and_zeroes_received_prefixes():
    dev = _target()
    dev.apply({"op": "bgp_down", "peer_ip": "203.0.113.9", "state": "IDLE"})
    pairs = dev.leaves()
    nb = ("/network-instances/network-instance[name=default]/protocols"
          "/protocol[identifier=BGP][name=BGP]/bgp/neighbors"
          "/neighbor[neighbor-address=203.0.113.9]")
    assert _leaf(pairs, nb + "/state/session-state") == "IDLE"
    assert _leaf(pairs, nb + "/afi-safis/afi-safi[afi-safi-name=IPV4_UNICAST]"
                             "/state/prefixes/received") == 0


def test_bgp_up_increments_established_transitions():
    dev = _target()
    nb = ("/network-instances/network-instance[name=default]/protocols"
          "/protocol[identifier=BGP][name=BGP]/bgp/neighbors"
          "/neighbor[neighbor-address=203.0.113.9]/state"
          "/established-transitions")
    assert _leaf(dev.leaves(), nb) == 1
    dev.apply({"op": "bgp_down", "peer_ip": "203.0.113.9"})
    dev.apply({"op": "bgp_up", "peer_ip": "203.0.113.9"})
    assert _leaf(dev.leaves(), nb) == 2


def test_fault_op_naming_something_the_device_lacks_is_refused_loudly():
    dev = _target()
    with pytest.raises(KeyError):
        dev.apply({"op": "if_down", "ifname": "Ethernet99"})
    with pytest.raises(KeyError):
        dev.apply({"op": "bgp_down", "peer_ip": "192.0.2.1"})
    with pytest.raises(ValueError):
        dev.apply({"op": "reboot"})


# ── fault journal ───────────────────────────────────────────────────────────

def test_journal_watcher_applies_appended_ops_incrementally(tmp_path):
    dev = _target()
    path = tmp_path / "gnmi-faults.jsonl"
    path.write_text("")
    watcher = FaultJournalWatcher(str(path), {dev.name: dev})
    assert watcher.poll_once() == 0
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"device": dev.name, "op": "if_down",
                             "ifname": "Ethernet1"}) + "\n")
    assert watcher.poll_once() == 1
    assert _leaf(dev.leaves(), "/interfaces/interface[name=Ethernet1]/state"
                               "/oper-status") == "DOWN"
    assert watcher.poll_once() == 0          # nothing re-applied


def test_journal_watcher_leaves_a_partial_trailing_line_for_the_next_poll(
        tmp_path):
    dev = _target()
    path = tmp_path / "gnmi-faults.jsonl"
    line = json.dumps({"device": dev.name, "op": "if_down",
                       "ifname": "Ethernet1"})
    path.write_text(line[:12])               # torn write
    watcher = FaultJournalWatcher(str(path), {dev.name: dev})
    assert watcher.poll_once() == 0
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line[12:] + "\n")
    assert watcher.poll_once() == 1


def test_journal_watcher_counts_rejects_instead_of_dropping_them_silently(
        tmp_path):
    """A dropped op means a story is LABELLED but its gNMI half never
    happened — that must be visible, not silent."""
    dev = _target()
    path = tmp_path / "gnmi-faults.jsonl"
    path.write_text("\n".join([
        "{not json",
        json.dumps({"device": "twx-t-nope", "op": "if_down",
                    "ifname": "Ethernet1"}),
        json.dumps({"device": dev.name, "op": "if_down",
                    "ifname": "Ethernet1"}),
    ]) + "\n")
    watcher = FaultJournalWatcher(str(path), {dev.name: dev})
    assert watcher.poll_once() == 1
    assert watcher.rejected == 2


def test_journal_watcher_on_a_missing_file_is_a_no_op(tmp_path):
    watcher = FaultJournalWatcher(str(tmp_path / "absent.jsonl"), {})
    assert watcher.poll_once() == 0


# ── RPC semantics ───────────────────────────────────────────────────────────

def _sub_list(paths, mode=SUB_MODE_SAMPLE, list_mode=None, sample_ns=0,
              heartbeat_ns=0):
    body = b""
    for p in paths:
        sub = enc_msg(1, enc_path(parse_path(p))) + enc_uint(2, mode)
        if sample_ns:
            sub += enc_uint(3, sample_ns)
        if heartbeat_ns:
            sub += enc_uint(5, heartbeat_ns)
        body += enc_msg(2, sub)
    if list_mode is not None:
        body += enc_uint(5, list_mode)
    body += enc_uint(8, 4)                    # JSON_IETF
    return enc_msg(1, body)


def _ctx():
    return StreamContext(1, {":path": "/gnmi.gNMI/Subscribe"})


def _updates(response_bytes):
    """SubscribeResponse.update -> [(path text, json value)]."""
    notification = parse(response_bytes)[1][0]
    out = []
    for raw in parse(notification).get(4, []):
        fields = parse(raw)
        path = gp.dec_path(fields[1][0])["elem"]
        typed = parse(fields[3][0])
        out.append((path_str(path), json.loads(typed[11][0].decode())))
    return out


def test_once_subscription_returns_one_update_then_sync_and_ends():
    service = TargetService(_target())
    out = list(service.handle("/gnmi.gNMI/Subscribe", _ctx(),
                              _sub_list([OC_INTERFACES[1]],
                                        list_mode=LIST_MODE_ONCE)))
    assert len(out) == 2
    assert dict(_updates(out[0])) == {
        "/interfaces/interface[name=Ethernet1]/state/oper-status": "UP",
        "/interfaces/interface[name=Ethernet2]/state/oper-status": "UP"}
    assert parse(out[1])[3] == [1]            # sync_response = true


def test_stream_subscription_dumps_current_state_then_syncs():
    service = TargetService(_target())
    ctx = _ctx()
    gen = service.handle("/gnmi.gNMI/Subscribe", ctx,
                         _sub_list(OC_INTERFACES, sample_ns=30_000_000_000))
    first = next(gen)
    assert len(_updates(first)) == 2 * (8 + 2)
    assert parse(next(gen))[3] == [1]         # sync_response
    ctx.cancelled.set()                       # a cancelled stream stops at once
    assert list(gen) == []


def test_on_change_stream_emits_only_after_the_state_actually_changes():
    dev = _target()
    service = TargetService(dev, min_sample_s=0.01)
    ctx = _ctx()
    gen = service.handle("/gnmi.gNMI/Subscribe", ctx,
                         _sub_list([OC_BGP_SESSION], mode=SUB_MODE_ON_CHANGE))
    next(gen)                                  # initial dump
    next(gen)                                  # sync_response
    dev.apply({"op": "bgp_down", "peer_ip": "203.0.113.9", "state": "IDLE"})
    changed = _updates(next(gen))
    session_state = ("/network-instances/network-instance[name=default]"
                     "/protocols/protocol[identifier=BGP][name=BGP]/bgp"
                     "/neighbors/neighbor[neighbor-address=203.0.113.9]"
                     "/state/session-state")
    assert changed == [(session_state, "IDLE")]
    ctx.cancelled.set()


def test_poll_subscriptions_are_refused_with_an_actionable_status():
    service = TargetService(_target())
    with pytest.raises(GrpcStatus) as exc:
        list(service.handle("/gnmi.gNMI/Subscribe", _ctx(),
                            _sub_list([OC_INTERFACES[0]],
                                      list_mode=LIST_MODE_POLL)))
    assert exc.value.code == GRPC_UNIMPLEMENTED


def test_unknown_rpc_is_unimplemented_not_a_crash():
    service = TargetService(_target())
    with pytest.raises(GrpcStatus) as exc:
        list(service.handle("/gnmi.gNMI/Set", _ctx(), b""))
    assert exc.value.code == GRPC_UNIMPLEMENTED


def test_capabilities_advertises_json_ietf_and_the_openconfig_models():
    service = TargetService(_target())
    body = parse(next(iter(service.handle("/gnmi.gNMI/Capabilities", _ctx(),
                                          b""))))
    assert body[2] == [0, 4]                   # JSON, JSON_IETF
    assert body[3][0] == b"0.8.0"
    models = [parse(m)[1][0].decode() for m in body[1]]
    assert "openconfig-interfaces" in models


# ── manifest + gnmic targets ────────────────────────────────────────────────

SCENARIO = {"devices": [
    {"name": "edge-a1", "tenant": "acme",
     "interfaces": [{"name": "Ethernet1"}, {"name": "Ethernet2"}],
     "bgp_neighbors": [{"peer_ip": "203.0.113.9"}]},
    {"name": "core-1", "tenant": "globex",
     "interfaces": [{"name": "Ethernet1"}], "bgp_neighbors": []}]}


def test_manifest_carries_run_prefixed_names_and_per_device_ports():
    m = generate_manifest(SCENARIO, "twx-abc-",
                          {"edge-a1": 57400, "core-1": 57401},
                          listen_host="0.0.0.0", advertise_host="172.18.0.1",
                          generation="abc")
    assert [d["name"] for d in m["devices"]] == ["twx-abc-edge-a1",
                                                 "twx-abc-core-1"]
    assert [d["port"] for d in m["devices"]] == [57400, 57401]
    assert m["devices"][0]["tenant"] == "acme"
    assert m["devices"][0]["interfaces"][1] == {"name": "Ethernet2",
                                               "ifindex": 2}
    # a manifest device is directly servable
    assert DeviceTarget(m["devices"][0]).name == "twx-abc-edge-a1"


def test_rendered_gnmic_targets_advertise_the_reachable_host_and_names():
    """The rendered file is what an operator merges into gnmic.yaml: it must
    name the twin device (that becomes the `source`/`device` label) and point
    at an address a container on the stack network can reach."""
    m = generate_manifest(SCENARIO, "twx-abc-",
                          {"edge-a1": 57400, "core-1": 57401},
                          listen_host="0.0.0.0", advertise_host="172.18.0.1",
                          generation="abc")
    text = render_gnmic_targets(m)
    assert "targets:" in text
    assert "  172.18.0.1:57400:" in text
    assert "    name: twx-abc-edge-a1" in text
    assert "    insecure: true" in text
    assert "subscriptions: [oc-interfaces, oc-bgp]" in text
    assert "127.0.0.1" not in text
