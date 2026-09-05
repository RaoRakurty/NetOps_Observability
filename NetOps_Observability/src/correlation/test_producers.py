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
        "kind": "stamp", "prober": "prober", "target": "192.0.2.120:8620",
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


def test_parse_event_ts_infers_year_from_ingest_not_wallclock():
    # RFC 3164 syslog carries no year. Delayed reprocessing (quarantine/flows
    # restore, consumer backlog) across a year boundary must anchor the year on
    # the event's INGEST time, never wall-clock now(): a December event replayed
    # in January must stay in the PRIOR December, or onset order and CUSUM
    # intervals corrupt.
    ingest = datetime(2027, 1, 3, 0, 5, 0, tzinfo=timezone.utc)
    got = parse_event_ts("Dec 11 09:42:00", reference=ingest)
    assert got is not None and got.year == 2026, f"year inferred as {got}"


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
    assert s.entity_id == "prober->192.0.2.120"
    assert "192.0.2.120" in s.entity_tokens  # the seam-grounding token
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
    assert s.path_id == "prober->192.0.2.120"
    assert "192.0.2.120" in s.entity_tokens


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


def test_hsrp_statechange_to_active_is_failover():
    s = syslog_control_signal(syslog_event(
        "%HSRP-5-STATECHANGE", "Vlan10 Grp 1 state Standby -> Active", host="dist-sw1",
    ), "", T0)
    assert s is not None
    assert s.kind == "fhrp_state_change"
    assert s.source is Source.SYSLOG
    assert s.modality_class is ModalityClass.CONTROL_PLANE
    assert s.entity_type is EntityType.DEVICE
    assert s.entity_id == "dist-sw1"
    assert s.attrs["proto"] == "hsrp"
    assert s.attrs["group"] == "1"
    assert s.attrs["interface"] == "Vlan10"
    assert s.attrs["state"] == "active"
    assert s.severity is Severity.HIGH        # takeover
    # tracker 168 (INTENTIONAL DELTA): the interface and the FHRP group number
    # are both DEVICE-LOCAL — "grp1" and "Vlan10" exist on nearly every router,
    # so bare they welded the whole estate. Qualified, they still bind this
    # event to THIS device's own interface; two routers in one real FHRP group
    # must relate through topology, not through a shared group number.
    assert "dist-sw1:Vlan10" in s.entity_tokens and "dist-sw1:grp1" in s.entity_tokens
    assert "Vlan10" not in s.entity_tokens and "grp1" not in s.entity_tokens


def test_vrrp_statechange_to_backup_is_warn():
    s = syslog_control_signal(syslog_event(
        "%VRRP-6-STATECHANGE", "GigabitEthernet0/1 Grp 2 state Master -> Backup", host="dist-sw2",
    ), "", T0)
    assert s is not None and s.kind == "fhrp_state_change"
    assert s.attrs["proto"] == "vrrp"
    assert s.attrs["interface"] == "GigabitEthernet0/1"
    assert s.attrs["state"] == "backup"
    assert s.severity is Severity.WARN        # demotion, not a takeover


def test_macflap_notif_ios():
    s = syslog_control_signal(syslog_event(
        "%SW_MATM-4-MACFLAP_NOTIF",
        "Host 0011.2233.4455 in vlan 10 is flapping between port Gi1/0/1 and port Gi1/0/2",
        host="acc-sw2",
    ), "", T0)
    assert s is not None
    assert s.kind == "mac_flap"
    assert s.entity_type is EntityType.DEVICE
    assert s.entity_id == "acc-sw2"
    assert s.attrs["mac"] == "0011.2233.4455"
    assert s.attrs["vlan"] == "10"
    assert s.attrs["port_a"] == "Gi1/0/1" and s.attrs["port_b"] == "Gi1/0/2"
    assert s.severity is Severity.HIGH
    # tracker 168 (INTENTIONAL DELTA): the MAC stays BARE — it is genuinely
    # global, and two switches seeing the same MAC flap really are related,
    # which is what this signal is about. The VLAN id and the port names are
    # device-local and are qualified.
    assert "0011.2233.4455" in s.entity_tokens
    assert "acc-sw2:vlan10" in s.entity_tokens
    assert "vlan10" not in s.entity_tokens
    assert "acc-sw2:Gi1/0/1" in s.entity_tokens and "Gi1/0/1" not in s.entity_tokens


def test_nxos_l2fm_mac_move():
    s = syslog_control_signal(syslog_event(
        "%L2FM-4-L2FM_MAC_MOVE",
        "Mac 00ab.cd00.1122 in vlan 20 has moved between Eth1/1 to Eth1/2", host="leaf2",
    ), "", T0)
    assert s is not None and s.kind == "mac_flap"
    assert s.attrs["mac"] == "00ab.cd00.1122" and s.attrs["vlan"] == "20"
    assert s.attrs["port_a"] == "Eth1/1" and s.attrs["port_b"] == "Eth1/2"


def test_link_flap_phrase_not_misread_as_mac_flap():
    # "LINK-FLAP" is not a MAC flap — the MAC branch must not greedily claim it.
    assert syslog_control_signal(syslog_event(
        "%SYS-6-EVENT_TRIGGERED", "Event handler LINK-FLAP was activated",
    ), "", T0) is None


# ── DC overlay (VXLAN/EVPN) — P2 ──────────────────────────────────────────────


def test_nve_bfd_vtep_state_down():
    s = syslog_control_signal(syslog_event(
        "%NVE-5-BFD_CC_STATE_CHANGE", "BFD CC down for bfd-neighbor 10.0.0.5", host="leaf3",
    ), "", T0)
    assert s is not None
    assert s.kind == "vtep_state_change"
    assert s.entity_type is EntityType.DEVICE
    assert s.entity_id == "leaf3"
    assert s.attrs["vtep"] == "10.0.0.5"
    assert s.attrs["state"] == "down"
    assert s.severity is Severity.HIGH
    assert "10.0.0.5" in s.entity_tokens   # remote VTEP = underlay grounding token


def test_arista_evpn_blacklisted_duplicate_mac():
    s = syslog_control_signal(syslog_event(
        "%EVPN-3-BLACKLISTED_DUPLICATE_MAC",
        "MAC address 00:1c:73:ef:55:6b on VLAN 110 has been blacklisted for moving "
        "5 or more times within the past 180 seconds", host="leaf1",
    ), "", T0)
    assert s is not None
    assert s.kind == "evpn_mac_move"
    assert s.entity_type is EntityType.DEVICE
    assert s.attrs["mac"] == "00:1c:73:ef:55:6b"
    assert s.attrs["vlan"] == "110"
    assert s.attrs["blacklisted"] is True
    assert s.severity is Severity.HIGH


def test_nxos_hmm_duplicate_host_carries_vni_and_vtep():
    s = syslog_control_signal(syslog_event(
        "%HMM-2-DUP_HOSTS",
        "Detected duplicate host 0000.0033.3333, topology 200, during Local update, "
        "with host located at remote VTEP 192.0.2.4, VNI 2", host="leaf2",
    ), "", T0)
    assert s is not None and s.kind == "evpn_mac_move"
    assert s.attrs["mac"] == "0000.0033.3333"
    assert s.attrs["vni"] == "2"
    assert s.attrs["vtep"] == "192.0.2.4"
    assert "vni2" in s.entity_tokens and "192.0.2.4" in s.entity_tokens


def test_nxos_l2fm_vxlan_loop_is_evpn_not_local_macflap():
    # The VXLAN MAC-move loop is OVERLAY (evpn_mac_move), NOT a local mac_flap —
    # the EVPN branch must claim "VXLAN_MAC_MOVE" before the mac_flap branch.
    s = syslog_control_signal(syslog_event(
        "%L2FM-2-L2FM_VXLAN_MAC_MOVE_PORT_DOWN",
        "Loops detected in the network for mac 0011.2233.4455 between NVE and Eth1/1 "
        "on vlan 10 - Port Eth1/1 Disabled on loop detection", host="leaf4",
    ), "", T0)
    assert s is not None and s.kind == "evpn_mac_move"
    assert s.attrs["mac"] == "0011.2233.4455"
    assert s.attrs["vlan"] == "10"
    assert s.attrs["blacklisted"] is True


def test_plain_l2fm_mac_move_stays_local_macflap():
    # A non-VXLAN L2FM mac move is a LOCAL mac_flap, not an overlay event.
    s = syslog_control_signal(syslog_event(
        "%L2FM-4-L2FM_MAC_MOVE",
        "Mac 00ab.cd00.1122 in vlan 20 has moved between Eth1/1 to Eth1/2", host="leaf2",
    ), "", T0)
    assert s is not None and s.kind == "mac_flap"   # NOT evpn_mac_move


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


# ── generic-alarm fallback (#80 §4 keystone) ──────────────────────────────────


def test_generic_alarm_unrecognized_severe_event_device_scoped():
    # An unrecognized device alarm at err/crit → ONE generic device_alarm signal
    # (no per-mnemonic branch), device-scoped when no interface is named.
    s = syslog_control_signal({**syslog_event(
        "%ENVMON-2-FAN_FAILED", "Fan 2 in chassis has failed", host="core1"),
        "severity": "critical"}, "", T0)
    assert s is not None
    assert s.kind == "device_alarm"
    assert s.source is Source.SYSLOG
    assert s.modality_class is ModalityClass.CONTROL_PLANE
    assert s.entity_type is EntityType.DEVICE
    assert s.entity_id == "core1"
    assert s.severity is Severity.CRIT
    assert s.attrs["facility"] == "ENVMON"
    assert s.attrs["mnemonic"] == "FAN_FAILED"
    assert "core1" in s.entity_tokens


def test_generic_alarm_interface_scoped_when_named():
    s = syslog_control_signal({**syslog_event(
        "%PORT-3-IF_DOWN_ERROR", "Interface Ethernet5 disabled due to error", host="leaf1"),
        "severity": "err"}, "", T0)
    assert s is not None and s.kind == "device_alarm"
    assert s.entity_type is EntityType.INTERFACE
    assert s.entity_id == "leaf1:Ethernet5"
    assert s.severity is Severity.HIGH
    # tracker 168 (INTENTIONAL DELTA): interface-scoped alarm — entity_id is
    # already "leaf1:Ethernet5", so the bare local name is redundant AND unsafe.
    assert s.entity_id == "leaf1:Ethernet5"
    assert "Ethernet5" not in s.entity_tokens
    assert "leaf1" in s.entity_tokens


def test_generic_alarm_below_floor_is_no_signal():
    # notice/info unrecognized events stay searchable logs, never an RCA signal.
    assert syslog_control_signal({**syslog_event(
        "%SYS-5-CONFIG_I", "Configured from console by admin", host="leaf1"),
        "severity": "notice"}, "", T0) is None


def test_specific_classifier_wins_over_generic_alarm():
    # A recognized control-plane event classifies specifically even at high severity —
    # the generic fallback only catches the long tail nothing else matched.
    s = syslog_control_signal({**syslog_event(
        "%BGP-5-ADJCHANGE", "peer 10.0.0.9 new state Idle", host="leaf1"),
        "severity": "critical"}, "", T0)
    assert s is not None and s.kind == "bgp_adjacency_change"  # NOT device_alarm


def test_generic_alarm_severity_from_mnemonic_digit_only():
    # No RFC5424 severity field, but the Cisco %FAC-N-MNEMONIC digit (err=3) drives it.
    s = syslog_control_signal({"hostname": "sw1", "appname": "%PLATFORM-3-ELEMENT_FAULT",
                               "message": "PSU 1 voltage out of range", "timestamp": T0.isoformat()},
                              "", T0)
    assert s is not None and s.kind == "device_alarm" and s.severity is Severity.HIGH


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


# ── Digital Experience grounding (S17, 2026-09-05) ───────────────────────────
#
# Before this, a probe signal was an anonymous "prober->host" PATH: the
# saas-experience RCA template promised to name "the reporting site(s)" and had
# nothing to name them with. These tests pin the grounding that fixes it, and
# pin that it stays ADDITIVE — an event without the DEM fields must produce
# exactly what it produced before.

_DEM_NOW = datetime(2026, 9, 5, 10, 0, 0, tzinfo=timezone.utc)


def _dem_event(**over):
    ev = {
        "kind": "http", "prober": "prober", "target": "https://portal.example/health",
        "ok": False, "loss_pct": 100.0, "rtt_ms": 0.0,
        "ts": "2026-09-05T10:00:00Z",
        "tenant": "acme", "target_id": "dem-abc", "site_id": "dc1",
        "app_id": "portal", "source": "synthetic",
    }
    ev.update(over)
    return ev


def test_probe_signal_grounds_target_site_and_app():
    from producers import probe_signals

    sigs = probe_signals(_dem_event(), EpisodeDetector(), "acme", _DEM_NOW)
    assert sigs, "a fully-lost probe must produce a loss signal"
    sig = sigs[0]
    assert "target:dem-abc" in sig.entity_tokens
    assert "site:dc1" in sig.entity_tokens
    assert "app:portal" in sig.entity_tokens
    # Signal.site is what engine.Node.tokens() promotes for a PATH entity.
    assert sig.site == "dc1"
    assert sig.observer.location == "dc1"
    assert sig.attrs["target_id"] == "dem-abc"
    assert sig.attrs["site_id"] == "dc1"


def test_probe_signal_never_emits_a_tenant_token():
    """signals.py forbids a `tenant:` token prefix precisely to stop two
    tenants' subjects merging on a shared token. The tenant belongs in
    tenant_id, which verified_tenant() has already adjudicated."""
    from producers import probe_signals

    sig = probe_signals(_dem_event(), EpisodeDetector(), "acme", _DEM_NOW)[0]
    for tok in sig.entity_tokens:
        assert not tok.startswith("tenant:"), tok
    assert sig.tenant_id == "acme"


def test_probe_grounding_is_additive():
    """A probe event with none of the DEM fields grounds exactly as it did
    before: the vantage and the host, and nothing else."""
    from producers import probe_signals

    ev = {
        "kind": "icmp", "prober": "prober", "target": "192.0.2.120",
        "ok": False, "loss_pct": 100.0, "ts": "2026-09-05T10:00:00Z",
    }
    sig = probe_signals(ev, EpisodeDetector(), "acme", _DEM_NOW)[0]
    assert sig.entity_tokens == ("prober", "192.0.2.120")
    assert sig.site == ""
    assert sig.attrs == {"probe_kind": "icmp", "target": "192.0.2.120"}
