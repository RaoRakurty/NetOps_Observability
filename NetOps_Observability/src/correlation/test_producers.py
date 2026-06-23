"""Producers (#67 build ⑦): probe events and syslog control-plane events →
canonical Signals. Pins the wire contract with the Go collectors and the
provenance rules the verdict gate depends on (active_probe/vantage_agent vs
control_plane/device — independence is computed from these fields)."""

from datetime import datetime, timedelta, timezone

from episodes import EpisodeDetector
from producers import (
    PROBE_LOSS_PCT,
    episode_signal,
    flow_sample,
    parse_event_ts,
    probe_host,
    probe_signals,
    syslog_control_signal,
)
from signals import EntityType, ModalityClass, Observer, ObserverType, Severity, Source

T0 = datetime(2026, 6, 12, 10, 0, 0, tzinfo=timezone.utc)


def probe_event(**over) -> dict:
    ev = {
        "kind": "stamp", "prober": "prober", "target": "10.70.245.120:8620",
        "ok": True, "rtt_ms": 4.0, "jitter_ms": 0.2, "loss_pct": 0.0,
        "ts": "2026-06-12T10:00:00.123456789Z",
    }
    ev.update(over)
    return ev


# ── probe lane ────────────────────────────────────────────────────────────────


def test_probe_host_forms():
    assert probe_host("10.0.0.1:8620") == "10.0.0.1"
    assert probe_host("10.0.0.1") == "10.0.0.1"
    assert probe_host("http://nginx:8080/x") == "nginx"
    assert probe_host("https://example.com/") == "example.com"


def test_parse_event_ts_nano_and_fallback():
    ts = parse_event_ts("2026-06-12T10:00:00.123456789Z")
    assert ts is not None and ts.tzinfo is not None
    assert ts.microsecond == 123456  # nano truncated to micro
    assert parse_event_ts("") is None
    assert parse_event_ts("not-a-time") is None


def test_healthy_probe_no_signals():
    sigs = probe_signals(probe_event(), EpisodeDetector(), "", T0)
    assert sigs == []  # below loss floor, no RTT baseline yet → nothing


def test_loss_event_is_discrete_signal_with_probe_provenance():
    sigs = probe_signals(
        probe_event(ok=False, rtt_ms=0.0, loss_pct=100.0), EpisodeDetector(), "t1", T0,
    )
    assert len(sigs) == 1
    s = sigs[0]
    assert s.kind == "probe_loss"
    assert s.source is Source.PROBE
    assert s.modality_class is ModalityClass.ACTIVE_PROBE
    assert s.observer.observer_type is ObserverType.VANTAGE_AGENT
    assert s.observer.observer_id == "prober"
    assert s.entity_type is EntityType.PATH
    assert s.entity_id == "prober->10.70.245.120"
    assert "10.70.245.120" in s.entity_tokens  # the seam-grounding token
    assert s.severity is Severity.CRIT
    assert s.tenant_id == "t1"
    # Event time came from the record, not ingest time.
    assert s.ts.isoformat().startswith("2026-06-12T10:00:00.123456")


def test_failed_check_without_loss_pct_becomes_full_loss():
    sigs = probe_signals(
        probe_event(kind="tcp", ok=False, rtt_ms=0.0, loss_pct=0.0),
        EpisodeDetector(), "", T0,
    )
    assert len(sigs) == 1 and sigs[0].value == 100.0


def test_partial_loss_severity_tiers():
    det = EpisodeDetector()
    warn = probe_signals(probe_event(loss_pct=PROBE_LOSS_PCT), det, "", T0)[0]
    high = probe_signals(probe_event(loss_pct=30.0), det, "", T0)[0]
    assert warn.severity is Severity.WARN
    assert high.severity is Severity.HIGH


def test_rtt_step_opens_probe_episode():
    det = EpisodeDetector()
    sigs: list = []
    ts = T0
    # Baseline: ~4ms with tiny alternation so σ>0, then a 40ms step.
    for i in range(60):
        ts += timedelta(seconds=30)
        sigs += probe_signals(
            probe_event(rtt_ms=4.0 + (0.1 if i % 2 else -0.1),
                        ts=ts.isoformat()), det, "", ts,
        )
    assert sigs == []
    for _ in range(6):
        ts += timedelta(seconds=30)
        sigs += probe_signals(probe_event(rtt_ms=40.0, ts=ts.isoformat()), det, "", ts)
    onsets = [s for s in sigs if s.kind == "probe_rtt_anomaly"]
    assert len(onsets) == 1
    s = onsets[0]
    assert s.modality_class is ModalityClass.ACTIVE_PROBE
    assert s.entity_type is EntityType.PATH
    assert s.path_id == "prober->10.70.245.120"
    assert "10.70.245.120" in s.entity_tokens


def test_malformed_probe_event_ignored():
    assert probe_signals({"kind": "stamp"}, EpisodeDetector(), "", T0) == []


# ── syslog control-plane lane ─────────────────────────────────────────────────


def syslog_event(appname: str, message: str, host: str = "leaf1") -> dict:
    return {
        "hostname": host, "appname": appname, "message": message,
        "severity": "notice", "timestamp": "2026-06-12T10:00:01Z", "tenant_id": "",
    }


def test_eos_bgp_adjchange_down():
    s = syslog_control_signal(syslog_event(
        "%BGP-5-ADJCHANGE",
        "peer 10.0.0.9 (AS 65002) old state Established event RecvNotify new state Idle",
    ), "", T0)
    assert s is not None
    assert s.kind == "bgp_adjacency_change"
    assert s.source is Source.SYSLOG
    assert s.modality_class is ModalityClass.CONTROL_PLANE
    assert s.observer.observer_type is ObserverType.DEVICE
    assert s.observer.observer_id == "leaf1"
    assert s.entity_id == "leaf1"
    assert "10.0.0.9" in s.entity_tokens  # both ends share this token → grounding
    assert s.attrs["state"] == "down"
    assert s.severity is Severity.HIGH
    assert s.ts.isoformat().startswith("2026-06-12T10:00:01")


def test_ios_bgp_adjchange_up_is_warn():
    s = syslog_control_signal(syslog_event(
        "%BGP-5-ADJCHANGE", "neighbor 10.0.0.9 Up",
    ), "", T0)
    assert s is not None
    assert s.attrs["state"] == "up"
    assert s.severity is Severity.WARN


def test_ospf_adjchg_classified():
    s = syslog_control_signal(syslog_event(
        "%OSPF-5-ADJCHG", "Process 1, Nbr 10.0.0.2 on Ethernet1 from FULL to DOWN",
    ), "", T0)
    assert s is not None
    assert s.kind == "ospf_adjacency_change"
    assert s.attrs["peer"] == "10.0.0.2"
    assert s.attrs["state"] == "down"


def test_lineproto_updown_interface_entity():
    s = syslog_control_signal(syslog_event(
        "%LINEPROTO-5-UPDOWN",
        "Line protocol on Interface Ethernet1, changed state to down",
    ), "", T0)
    assert s is not None
    assert s.kind == "link_state_change"
    assert s.entity_type is EntityType.INTERFACE
    assert s.entity_id == "leaf1:Ethernet1"
    assert s.attrs["state"] == "down"
    assert s.severity is Severity.HIGH


def test_isis_adjacency_change_srl_down():
    s = syslog_control_signal(syslog_event(
        "-",
        "isis|8808|8853|00045|EV|isisAdjacencyChange|W: In network-instance default, "
        "the level-2 IS-IS adjacency with system 0100.0000.0011, using interface "
        "ethernet-1/1.0, moved to state DOWN.",
        host="spine1",
    ), "", T0)
    assert s is not None
    assert s.kind == "isis_adjacency_change"
    assert s.entity_type is EntityType.DEVICE
    assert s.entity_id == "spine1"
    assert s.attrs["peer"] == "0100.0000.0011"
    assert "0100.0000.0011" in s.entity_tokens
    assert s.attrs["state"] == "down"
    assert s.severity is Severity.HIGH


def test_isis_adjacency_change_up_is_warn():
    s = syslog_control_signal(syslog_event(
        "-", "isis|EV|isisAdjacencyChange|W: ... system 0100.0000.0011 ... moved to state UP.",
        host="spine1",
    ), "", T0)
    assert s is not None and s.kind == "isis_adjacency_change"
    assert s.attrs["state"] == "up" and s.severity is Severity.WARN


def test_lldp_neighbor_new_ceos_interface_entity():
    s = syslog_control_signal(syslog_event(
        "%LLDP-5-NEIGHBOR_NEW",
        "LLDP neighbor with chassisId 0c00.842b.3c00 and portId aac1.ab21.c775 "
        "added on interface Ethernet2",
        host="wan-r2",
    ), "", T0)
    assert s is not None
    assert s.kind == "lldp_neighbor_change"
    assert s.entity_type is EntityType.INTERFACE
    assert s.entity_id == "wan-r2:Ethernet2"
    assert s.attrs["state"] == "up"
    assert s.severity is Severity.WARN


def test_lldp_neighbor_removed_srl_down():
    s = syslog_control_signal(syslog_event(
        "-",
        "lldp|6876|6876|00043|EV|remotePeerRemoved|I: LLDP remote peer removed on "
        "interface ethernet-1/1: System leaf1 with chassis ID 00:1C:73:AD:88:2A",
        host="spine1",
    ), "", T0)
    assert s is not None
    assert s.kind == "lldp_neighbor_change"
    assert s.entity_id == "spine1:ethernet-1/1"
    assert s.attrs["state"] == "down"
    assert s.severity is Severity.HIGH


def test_stp_interface_del_down():
    s = syslog_control_signal(syslog_event(
        "%SPANTREE-6-INTERFACE_DEL", "Interface Ethernet3 has been removed from instance MST0",
    ), "", T0)
    assert s is not None
    assert s.kind == "stp_topology_change"
    assert s.entity_id == "leaf1:Ethernet3"
    assert s.attrs["state"] == "down"
    assert s.severity is Severity.HIGH


def test_stp_state_to_learning_up():
    s = syslog_control_signal(syslog_event(
        "%SPANTREE-6-INTERFACE_STATE",
        "Interface Ethernet3 instance MST0 moving from discarding to learning",
    ), "", T0)
    assert s is not None and s.kind == "stp_topology_change"
    assert s.attrs["state"] == "up" and s.severity is Severity.WARN


def test_unrelated_syslog_yields_none():
    assert syslog_control_signal(syslog_event(
        "%SYS-6-EVENT_TRIGGERED", "Event handler LINK-FLAP was activated",
    ), "", T0) is None
    assert syslog_control_signal(syslog_event(
        "pam_unix(cron", "session): session opened for user root",
    ), "", T0) is None
    assert syslog_control_signal({"hostname": "unknown"}, "", T0) is None


def test_same_peer_token_on_both_ends_supports_grounding():
    a = syslog_control_signal(syslog_event(
        "%BGP-5-ADJCHANGE", "peer 10.0.0.9 ... new state Idle", host="leaf1",
    ), "", T0)
    b = syslog_control_signal(syslog_event(
        "%BGP-5-ADJCHANGE", "peer 10.0.0.9 ... new state Idle", host="spine1",
    ), "", T0)
    assert a is not None and b is not None
    shared = set(a.entity_tokens) & set(b.entity_tokens)
    assert "10.0.0.9" in shared


def test_syslog_classifies_via_parsed_facility_event_type():
    # #31/#32: a vendor log whose appname isn't telling, but the VRL parsed
    # facility + event_type — still classifies off the structured envelope fields,
    # not the raw text. Proves the tag→ctoken broadening (additive, no regression).
    bgp = syslog_control_signal({
        "hostname": "leaf1", "appname": "rsyslogd", "facility": "BGP", "event_type": "adjchange",
        "message": "peer 10.0.0.5 new state Idle", "timestamp": T0.isoformat(),
    }, "", T0)
    assert bgp is not None and bgp.kind == "bgp_adjacency_change" and bgp.attrs["state"] == "down"

    link = syslog_control_signal({
        "hostname": "leaf1", "appname": "x", "facility": "LINK", "event_type": "updown",
        "message": "Interface Ethernet3, changed state to down", "timestamp": T0.isoformat(),
    }, "", T0)
    assert link is not None and link.kind == "link_state_change"


# ── flow lane (C6 passive_flow) ───────────────────────────────────────────────
def test_flow_sample_snake_camel_and_sampling_scale():
    snake = flow_sample({"sampler_address": "10.0.0.9", "in_if": 7, "bytes": 100, "sampling_rate": 50})
    assert snake == ("10.0.0.9", "10.0.0.9:if7", 5000.0)   # 100 bytes × 1-in-50 sampling
    camel = flow_sample({"SamplerAddress": "10.0.0.9", "InIf": 7, "Bytes": 100, "SamplingRate": 0})
    assert camel == ("10.0.0.9", "10.0.0.9:if7", 100.0)    # rate 0/absent ⇒ unsampled ⇒ ×1


def test_flow_sample_rejects_unusable():
    assert flow_sample({"bytes": 100}) is None                            # no sampler → unattributable
    assert flow_sample({"sampler_address": "10.0.0.9", "bytes": 0}) is None     # no volume
    assert flow_sample({"sampler_address": "10.0.0.9", "bytes": "x"}) is None   # malformed


def test_flow_volume_episode_carries_passive_flow_provenance():
    """A flow-byte CUSUM episode → a passive_flow Signal on the exporting interface —
    the 4th independent modality the verdict gate needs, grounding on the exporter."""
    det = EpisodeDetector()
    obs = Observer(observer_id="10.0.0.9", observer_type=ObserverType.FLOW_EXPORTER,
                   collection_path="flow_export")
    ts, sig = T0, None
    for i in range(60):  # baseline ~1 kB/s with σ>0
        ts += timedelta(seconds=30)
        assert det.observe("", "10.0.0.9:if7", "flow_bytes_rate", ts,
                           1000.0 + (10 if i % 2 else -10), clock_quality="unknown") is None
    for _ in range(6):   # a 50× volume surge
        ts += timedelta(seconds=30)
        ev = det.observe("", "10.0.0.9:if7", "flow_bytes_rate", ts, 50000.0, clock_quality="unknown")
        if ev is not None and ev.phase == "onset":
            sig = episode_signal(ev, obs, source=Source.FLOW, modality=ModalityClass.PASSIVE_FLOW,
                                 entity_type=EntityType.INTERFACE, kind_prefix="flow_volume_anomaly",
                                 entity_tokens=("10.0.0.9",))
            break
    assert sig is not None, "a sustained volume surge must open a flow_volume_anomaly episode"
    assert sig.modality_class is ModalityClass.PASSIVE_FLOW
    assert sig.source is Source.FLOW
    assert sig.kind == "flow_volume_anomaly"
    assert sig.entity_id == "10.0.0.9:if7" and "10.0.0.9" in sig.entity_tokens
