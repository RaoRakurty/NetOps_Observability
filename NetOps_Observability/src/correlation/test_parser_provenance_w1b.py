"""W1b — parser PROVENANCE and coverage observability.

Until now a Signal recorded WHAT was classified and never WHICH RULE did it, or
which revision of that rule. A parser edit that silently re-routed a vendor line
produced the same `kind` from a different branch and no stored field disagreed,
so the change was invisible in the data. This file pins the fix:

  1. PROVENANCE — every Signal from `syslog_control_signal`,
     `trap_control_signal`, `port_event_signal` and both generic `device_alarm`
     nets carries `rule_id`, `parser_rev`, `rules_hash` and `fidelity` in
     `attrs` (the `corr_signals.attrs` JSON String column — no DDL change).
  2. IDENTITY IS UNTOUCHED — none of the four enters `native_id`, therefore none
     enters `signal_id`. The tracker-198 pinned ids still hold BYTE-FOR-BYTE.
  3. THE TABLE IS THE SOURCE — the ingest screen's marker/pattern tables and the
     port-event rule list are DERIVED from `producers.RULES`, and `rules_hash`
     moves when any rule does.
  4. BYTE-IDENTICAL OUTPUT — the whole fixture corpus (telemetry-catalog's raw
     syslog fixtures, the in-tree test corpora, the trap matrix) replays through
     the new path and reproduces the OLD path's (kind, entity, state, tokens,
     native_id, signal_id) exactly. Provenance is excluded from that comparison
     because it is the only thing that is allowed to be new.
  5. COVERAGE METRICS — rule hits, generic fallbacks and the semantic-promotion
     rate are exported and arithmetically correct.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import datetime, timezone

import pytest

import main
import producers as P
from producers import EMITTED_KINDS, RULES
from signals import DeadLetter

T0 = datetime(2026, 9, 2, 10, 0, 0, tzinfo=timezone.utc)
TS = "2026-09-02T10:00:00.000Z"

# The four keys this change adds. They are the ONLY difference the corpus
# equivalence test below tolerates.
PROVENANCE_KEYS = frozenset({"rule_id", "parser_rev", "rules_hash", "fidelity"})

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "telemetry-catalog"))
GOLDEN = os.path.join(HERE, "fixtures", "parser_golden_corpus.jsonl")


@pytest.fixture(autouse=True)
def _clean_counters():
    """Every test starts from a zeroed parser window — the counters are module
    globals and the whole suite shares this process."""
    P.reset_parser_counters()
    yield
    P.reset_parser_counters()


def syslog_ev(tag: str, msg: str, severity: str = "notice", host: str = "leaf1") -> dict:
    return {"hostname": host, "appname": tag, "message": msg,
            "severity": severity, "timestamp": TS}


def trap_ev(**over) -> dict:
    ev = {"device": "leaf9", "trap_oid": "", "trap_name": "", "event_type": "",
          "severity": "err", "authenticated": True, "varbinds": [],
          "timestamp": TS}
    ev.update(over)
    return ev


# ══ one triggering fixture per RULE ══════════════════════════════════════════
#
# Keyed by rule_id so a new rule with no fixture is RED (see
# `test_every_rule_in_the_table_has_a_triggering_fixture`). Each entry is
# (producer, event) and the branch it fires must stamp exactly that rule_id.

IFN = "1.3.6.1.2.1.31.1.1.1.1"          # ifName column
BGP_PEER = "1.3.6.1.2.1.15.3.1.7"       # bgpPeerRemoteAddr column

RULE_FIXTURES: dict[str, tuple[str, dict]] = {
    # -- syslog control plane -------------------------------------------------
    "syslog.isis.adjacency_change": ("control", syslog_ev(
        "%CLNS-5-ADJCHANGE", "IS-IS adjacency 1921.6800.1001 to state Down")),
    "syslog.bgp.adjacency_change": ("control", syslog_ev(
        "%BGP-5-ADJCHANGE", "neighbor 10.0.0.1 Down Interface flap")),
    "syslog.ospf.adjacency_change": ("control", syslog_ev(
        "%OSPF-5-ADJCHG", "Process 1, Nbr 10.0.0.2 on Ethernet1 from FULL to DOWN")),
    "syslog.routing.adjacency_change": ("control", syslog_ev(
        "%RIB-5-ADJCHANGE", "adjacency to 10.9.9.9 changed state to down")),
    "syslog.bgp.notification": ("control", syslog_ev(
        "%BGP-3-NOTIFICATION",
        "received from neighbor 10.0.0.200 6/4 (Administrative Reset) 0 bytes")),
    "syslog.bgp.route_churn": ("control", syslog_ev(
        "%BGP-5-NBR_RESET", "Neighbor 10.0.0.200 reset (BGP Notification received)")),
    "syslog.link.state_change": ("control", syslog_ev(
        "%LINK-3-UPDOWN", "Interface GigabitEthernet0/1, changed state to down")),
    "syslog.lldp.neighbor_change": ("control", syslog_ev(
        "%LLDP-5-NEIGHBOR_REMOVED", "neighbor removed on interface Ethernet1")),
    "syslog.stp.topology_change": ("control", syslog_ev(
        "%SPANTREE-6-INTERFACE", "Interface Gi0/1 moved to discarding")),
    "syslog.stp.topology_notification": ("control", syslog_ev(
        "%SPANTREE-5-TOPOTRAP", "Topology Change Trap for instance MST0")),
    "syslog.vtep.state_change": ("control", syslog_ev(
        "%NVE-5-BFD_CC_STATE_CHANGE", "BFD CC down for bfd-neighbor 10.1.1.1")),
    "syslog.evpn.mac_move": ("control", syslog_ev(
        "%EVPN-3-BLACKLISTED_DUPLICATE_MAC",
        "host 0011.2233.4455 blacklisted in vlan 10 vni 100 VTEP 10.1.1.1")),
    "syslog.fhrp.state_change": ("control", syslog_ev(
        "%HSRP-5-STATECHANGE", "Vlan10 Grp 1 state Standby -> Active")),
    "syslog.mac.flap": ("control", syslog_ev(
        "%SW_MATM-4-MACFLAP_NOTIF",
        "Host 0011.2233.4455 in vlan 5 is flapping between port Gi0/1 and port Gi0/2")),
    "syslog.generic.device_alarm": ("control", syslog_ev(
        "%ENVMON-2-FAN_FAILED", "Fan 2 in chassis 1 has failed", "critical")),
    # -- syslog port intelligence ---------------------------------------------
    "syslog.port.transceiver_unsupported": ("port", syslog_ev(
        "%PLATFORM-4-XCVR", "Unsupported transceiver found in Gi0/1")),
    "syslog.port.dom_rx_power_low": ("port", syslog_ev(
        "%OPTICS-4-DOM", "Transceiver rx power low alarm on Et1/2 below threshold")),
    "syslog.port.dom_temperature_high": ("port", syslog_ev(
        "%OPTICS-4-DOM", "Transceiver temperature high alarm on Et1/3 above threshold")),
    "syslog.port.dom_lane_bias_anomaly": ("port", syslog_ev(
        "%OPTICS-4-DOM", "Tx bias current high alarm threshold exceeded Et1/5")),
    "syslog.port.prefec_ber_rising": ("port", syslog_ev(
        "%FEC-3-ERR", "Uncorrectable FEC codeword errors on Ethernet1/7")),
    "syslog.port.fec_corrected_rate_high": ("port", syslog_ev(
        "%FEC-4-BER", "pre-FEC BER exceeded on Et1/8")),
    "syslog.port.pcs_local_fault": ("port", syslog_ev(
        "%ETH-3-LOCAL_FAULT", "local fault detected on Ethernet1/10")),
    "syslog.port.pcs_remote_fault": ("port", syslog_ev(
        "%ETH-3-REMOTE_FAULT", "remote fault REMOTE_FAULT on Et1/11")),
    "syslog.port.pcs_deskew_fault": ("port", syslog_ev(
        "%PCS-3-DESKEW", "deskew failure on lane 2 Ethernet1/12")),
    "syslog.port.hi_ber_indication": ("port", syslog_ev(
        "%PCS-3-HIBER", "hi-ber detected Ethernet1/14")),
    "syslog.port.link_down_no_light": ("port", syslog_ev(
        "%OPTICS-3-LOS", "no light detected on Ethernet1/16")),
    "syslog.port.link_flap_on_insert": ("port", syslog_ev(
        "%XCVR-4-FLAP", "transceiver removed then insert on Et1/18 flap")),
    # -- SNMP traps -----------------------------------------------------------
    "trap.link.state_change": ("trap", trap_ev(
        trap_oid="1.3.6.1.6.3.1.1.5.3", trap_name="linkDown",
        varbinds=[{"oid": IFN + ".7", "name": "ifName", "value": "Ethernet7"}])),
    "trap.device.restart": ("trap", trap_ev(
        trap_oid="1.3.6.1.6.3.1.1.5.1", trap_name="coldStart")),
    "trap.bgp.adjacency_change": ("trap", trap_ev(
        trap_oid="1.3.6.1.2.1.15.7.2", trap_name="bgpBackwardTransition",
        varbinds=[{"oid": BGP_PEER + ".10.0.0.5", "name": "bgpPeerRemoteAddr",
                   "value": "10.0.0.5"}])),
    "trap.bgp.adjacency_change.event_type": ("trap", trap_ev(
        trap_oid="1.3.6.1.4.1.30065.3.1", trap_name="vendorTrap",
        event_type="arista_bgp4_v2_backward_transition",
        varbinds=[{"oid": "1.3.6.1.4.1.30065.9.1", "name": "srlPeerAddr",
                   "value": "10.0.0.9"}])),
    "trap.link.state_change.event_type": ("trap", trap_ev(
        trap_oid="1.3.6.1.4.1.9.9.41.2.0.1", trap_name="vendorTrap",
        event_type="if_link_down",
        varbinds=[{"oid": IFN + ".3", "name": "ifName", "value": "Ethernet3"}])),
    "trap.device.restart.event_type": ("trap", trap_ev(
        trap_oid="1.3.6.1.4.1.9.9.41.2.0.2", trap_name="vendorTrap",
        event_type="cold_start")),
    # -- A9: the trap twins of the syslog control-plane symptoms --------------
    "trap.ospf.adjacency_change": ("trap", trap_ev(
        trap_oid="1.3.6.1.2.1.14.16.2.2", trap_name="ospfNbrStateChange",
        event_type="ospf_nbr_state_change",
        varbinds=[{"oid": "1.3.6.1.2.1.14.10.1.1.10.0.0.2.0",
                   "name": "ospfNbrIpAddr", "value": "10.0.0.2"},
                  {"oid": "1.3.6.1.2.1.14.10.1.6.10.0.0.2.0",
                   "name": "ospfNbrState", "value": "down(1)"}])),
    "trap.isis.adjacency_change": ("trap", trap_ev(
        trap_oid="1.3.6.1.2.1.138.0.17", trap_name="isisAdjacencyChange",
        event_type="isis_adjacency_change",
        varbinds=[{"oid": "1.3.6.1.2.1.138.1.6.1.1.6.1.1",
                   "name": "isisISAdjNeighSysID", "value": "1921.6800.1001"},
                  {"oid": "1.3.6.1.2.1.138.1.10.1.12.0",
                   "name": "isisAdjState", "value": "down(1)"}])),
    "trap.stp.topology_change": ("trap", trap_ev(
        trap_oid="1.3.6.1.2.1.17.0.2", trap_name="topologyChange",
        event_type="topology_change")),
    "trap.fhrp.state_change": ("trap", trap_ev(
        trap_oid="1.3.6.1.4.1.9.9.106.2.0.1", trap_name="cHsrpStateChange",
        event_type="c_hsrp_state_change",
        varbinds=[{"oid": IFN + ".5", "name": "ifName", "value": "Vlan100"},
                  {"oid": "1.3.6.1.4.1.9.9.106.1.2.1.1.11.5.1",
                   "name": "cHsrpGrpStandbyState", "value": "active(6)"}])),
    "trap.generic.device_alarm": ("trap", trap_ev(
        trap_oid="1.3.6.1.4.1.9.9.999.0.1", trap_name="vendorAlarm",
        varbinds=[{"oid": "1.3.6.1.4.1.9.9.999.1.1", "name": "alarmText",
                   "value": "PSU 1 failed"}])),
    # -- A9b: device configuration change, on both observers ------------------
    # The syslog row is SHADOW (see events.yaml): its guard matches this line
    # and it emits nothing, so the tests below read `SHADOW_HITS` for it rather
    # than a Signal. The fixture is still required — an unexercised shadow row
    # is a grammar nobody is measuring, which is the opposite of the point.
    "syslog.config.change": ("control", syslog_ev(
        "%SYS-5-CONFIG_I", "Configured from console by admin on vty0")),
    "trap.config.change": ("trap", trap_ev(
        trap_oid="1.3.6.1.4.1.9.9.43.2.0.1", trap_name="ciscoConfigManEvent",
        event_type="cisco_config_man_event",
        varbinds=[{"oid": "1.3.6.1.4.1.9.9.43.1.1.6.1.8.7",
                   "name": "ccmHistoryEventTerminalUser", "value": "admin"}])),
}

PRODUCERS = {
    "control": P.syslog_control_signal,
    "port": P.port_event_signal,
    "trap": P.trap_control_signal,
}


def fire(rule_id: str):
    lane, ev = RULE_FIXTURES[rule_id]
    return PRODUCERS[lane](dict(ev), "t1", T0)


# ══ 1. the table itself ══════════════════════════════════════════════════════

def test_every_rule_in_the_table_has_a_triggering_fixture():
    """The canary. Without it every parametrized test below can go vacuous by
    simply not covering a new rule."""
    missing = sorted({r.rule_id for r in RULES} - set(RULE_FIXTURES))
    assert not missing, (
        f"rules with no triggering fixture: {missing} — add one to "
        "RULE_FIXTURES, or the provenance tests do not cover that branch")
    extra = sorted(set(RULE_FIXTURES) - {r.rule_id for r in RULES})
    assert not extra, f"fixtures for rules that no longer exist: {extra}"


def test_rule_ids_are_unique_and_bounded():
    """`rule_id` is a Prometheus LABEL. Its value set must be fixed at import
    and small — no device string may ever widen it."""
    ids = [r.rule_id for r in RULES]
    assert len(ids) == len(set(ids))
    assert len(ids) < 200, "the rule label set has grown past 'bounded cardinality'"
    assert set(P.RULES_BY_ID) == set(ids)


def test_every_control_and_trap_rule_kind_is_a_declared_emitted_kind():
    """`EMITTED_KINDS` is the coverage check's dead-template guard (#80 §5)."""
    assert {r.kind for r in RULES if r.lane != "port"} <= set(EMITTED_KINDS)


def test_the_port_lane_kinds_stay_outside_emitted_kinds():
    """PINNED, not aspirational: the port-intelligence kinds are the
    `sig.ent.spdc` evidence vocabulary and were never registered in
    EMITTED_KINDS. Moving one INTO that set is a coverage-check decision (#80
    §5), never a side effect of this refactor — so it is red here first."""
    assert {r.kind for r in RULES if r.lane == "port"}.isdisjoint(EMITTED_KINDS)


# The kinds in EMITTED_KINDS that come from OTHER lanes (probes, metric
# episodes, cloud, controller, wireless, synthetics, the clock-skew meta
# finding). Written out rather than computed, so a NEW kind added to
# EMITTED_KINDS is red here until someone decides which lane owns it.
OTHER_LANE_KINDS = frozenset({
    "active_verification_healthy", "active_verification_result",
    "app_error_rate_high", "app_latency_high", "bgp_state_anomaly",
    "clock_skew", "cloud_audit", "cloud_change", "cloud_dns_log",
    "cloud_flow_log", "cloud_health", "cloud_lb_log", "cloud_resource_anomaly",
    "cloud_waf_log", "controller_bfd_down",
    "controller_control_connection_loss", "controller_device_unreachable",
    "controller_policy_change", "controller_tunnel_state",
    "device_resource_anomaly", "flow_volume_anomaly", "if_metric_anomaly",
    # tracker 222: the METRIC lane's IGP adjacency episode
    # (device_ospf_nbr_state / device_isis_adj_state → the `igp` signal family
    # → main.metric_identity). Its SIGNAL-lane twins, ospf_adjacency_change and
    # isis_adjacency_change, are rule-owned and stay that way.
    "igp_state_anomaly",
    "ipsec_tunnel_status", "ipsec_underlay_status", "lb_4xx_high", "lb_5xx",
    "lb_target_unhealthy", "probe_loss", "probe_rtt_anomaly",
    "synthetic_cert_expired", "synthetic_cert_expiring", "synthetic_dns_fail",
    "synthetic_http_4xx", "synthetic_http_5xx", "synthetic_http_fail",
    "synthetic_http_latency_high", "synthetic_icmp_loss",
    "synthetic_tcp_connect_fail", "synthetic_tcp_probe_fail",
    "synthetic_timeout", "synthetic_tls_fail", "wireless_ap_down",
    "wireless_ap_join_flap", "wireless_ap_up", "wireless_radio_down",
    "wireless_radio_up",
})


@pytest.mark.parametrize("kind", sorted(EMITTED_KINDS))
def test_every_emitted_kind_is_owned_by_a_rule_or_another_lane(kind):
    """Parametrized over EMITTED_KINDS. A kind the syslog/trap/port parsers can
    emit MUST have a rule (and therefore a rule_id); anything else must be
    explicitly declared as another lane's."""
    owned = {r.kind for r in RULES}
    assert kind in owned or kind in OTHER_LANE_KINDS, (
        f"kind {kind!r} belongs to no parser rule and is not declared in "
        "OTHER_LANE_KINDS — give it a Rule (so its signals carry provenance) "
        "or declare which lane emits it")


# ══ 2. provenance on every emitted signal ════════════════════════════════════

@pytest.mark.parametrize("rule_id", sorted(RULE_FIXTURES))
def test_every_rule_stamps_its_own_provenance(rule_id):
    rule = P.RULES_BY_ID[rule_id]
    if rule.shadow:
        # A8: a shadow row is EVALUATED and COUNTED and emits nothing, so there
        # is no signal to carry provenance. What must hold is that its fixture
        # reaches it (otherwise the row is unmeasured) and that it changed
        # nothing — asserted here rather than skipped, so a shadow row cannot
        # quietly opt out of this file's coverage.
        before = P.SHADOW_HITS[rule_id]
        assert fire(rule_id) is None, (
            f"{rule_id} is a shadow row and must emit nothing")
        assert P.SHADOW_HITS[rule_id] == before + 1, (
            f"the fixture for {rule_id!r} never reaches its guard")
        return
    sig = fire(rule_id)
    assert sig is not None, f"fixture for {rule_id!r} classified as nothing"
    assert sig.attrs["rule_id"] == rule_id, (
        f"branch stamped {sig.attrs['rule_id']!r} but the fixture targets "
        f"{rule_id!r} — the fixture fires the wrong branch, or the branch reads "
        "the wrong Rule")
    assert sig.kind == rule.kind, "the table's kind and the branch's kind disagree"
    assert sig.attrs["parser_rev"] == P.PARSER_REV
    assert sig.attrs["rules_hash"] == P.RULES_HASH_TAG
    assert sig.attrs["fidelity"] == rule.fidelity


@pytest.mark.parametrize("kind", sorted({r.kind for r in RULES}))
def test_every_emitted_kind_carries_a_rule_id(kind):
    """The product claim, stated per KIND rather than per rule: no signal this
    parser emits is ever anonymous."""
    fired = [fire(rid) for rid, r in
             ((rid, P.RULES_BY_ID[rid]) for rid in sorted(RULE_FIXTURES))
             if r.kind == kind and not r.shadow]
    assert fired, (
        f"no fixture emits {kind!r} — every rule that CAN emit it is a shadow "
        "row, so the kind is unreachable in production")
    for sig in fired:
        assert sig is not None
        assert sig.attrs.get("rule_id") in P.RULES_BY_ID
        assert PROVENANCE_KEYS <= set(sig.attrs)


def test_provenance_survives_the_clickhouse_row_serialization():
    """attrs is a JSON String column (`corr_signals.attrs`), so provenance
    lands with NO DDL change. Prove it round-trips through `to_ch_row`."""
    sig = fire("syslog.bgp.adjacency_change")
    row = sig.to_ch_row()
    attrs = json.loads(row["attrs"])
    assert attrs["rule_id"] == "syslog.bgp.adjacency_change"
    assert attrs["parser_rev"] == P.PARSER_REV
    assert attrs["rules_hash"] == P.RULES_HASH_TAG
    assert attrs["fidelity"] == "code"
    # The identity that reaches ClickHouse is `signal_id`, derived from
    # `native_id` — and neither carries a provenance key.
    assert "rule_id" not in sig.native_id
    assert row["signal_id"] == sig.signal_id_str


# ══ 3. IDENTITY IS UNTOUCHED (tracker 198) ═══════════════════════════════════

def test_the_tracker_198_pinned_identities_still_hold():
    """The exact byte strings pinned by test_alarm_identity_198.py. Provenance
    must never reach native_id — and therefore never reach signal_id."""
    ev = {"hostname": "core1", "appname": "%ENVMON-2-FAN_FAILED",
          "message": "Fan 2 in chassis 1 has failed", "severity": "critical",
          "timestamp": "2026-06-12T10:00:01Z", "tenant_id": ""}
    s = P.syslog_control_signal(ev, "", datetime(2026, 6, 12, 10, 0, tzinfo=timezone.utc))
    assert s is not None
    assert s.native_id == "core1|alarm|ENVMON|FAN_FAILED|-|1781258401000|ee1fc7b0"
    assert str(s.signal_id) == "f97967e3-3ddd-5153-bbb8-d62871448093"
    assert s.attrs["rule_id"] == "syslog.generic.device_alarm"

    link = P.syslog_control_signal(
        {"hostname": "leaf1", "appname": "%LINK-3-UPDOWN",
         "message": "Interface Ethernet3, changed state to down",
         "severity": "err", "timestamp": "2026-06-12T10:00:01Z"},
        "", datetime(2026, 6, 12, 10, 0, tzinfo=timezone.utc))
    assert link is not None
    assert link.native_id == "leaf1|link|Ethernet3|down|1781258401000"

    port = P.port_event_signal(
        {"hostname": "leaf1", "appname": "%OPTICS-3-LOS",
         "message": "no light detected on Ethernet4", "interface": "Ethernet4",
         "severity": "err", "timestamp": "2026-06-12T10:00:01Z"},
        "", datetime(2026, 6, 12, 10, 0, tzinfo=timezone.utc))
    assert port is not None
    assert port.native_id == "leaf1|portevt|link_down_no_light|Ethernet4|1781258401000"


@pytest.mark.parametrize("rule_id", sorted(RULE_FIXTURES))
def test_bumping_parser_rev_never_re_identifies_a_signal(monkeypatch, rule_id):
    """The whole point of keeping provenance out of the identity key: a rule
    revision must not orphan the signals already stored."""
    if P.RULES_BY_ID[rule_id].shadow:
        pytest.skip("shadow row: it emits no signal, so none can be re-identified")
    before = fire(rule_id)
    assert before is not None
    monkeypatch.setattr(P, "PARSER_REV", "9999-12-31-mutant")
    monkeypatch.setattr(P, "RULES_HASH_TAG", "0" * 16)
    after = fire(rule_id)
    assert after is not None
    assert after.native_id == before.native_id
    assert after.signal_id == before.signal_id
    assert after.attrs["parser_rev"] == "9999-12-31-mutant", "the mutant did not take"


# ══ 4. rules_hash — the machine's "the rules changed" ════════════════════════

#: PINNED. A3 re-serialized the rule table (the rows now carry the grammar, so
#: `digest_fields` includes guard/extract/emit), which MOVED this value from
#: 44f1e46426eb39e2… — the last W1b hash — to 1b69ab8f5c4cd610….
#:
#: A9 (the trap-coverage audit) then ADDED four rows — the OSPF/IS-IS adjacency,
#: STP topology-change and FHRP state-change trap twins of symptoms the syslog
#: lane already typed — which moves it again, to the value below. No EXISTING
#: rule's grammar changed: every pre-A9 corpus entry still replays
#: byte-identically (the corpus below is the proof), and the four new rows are
#: only reachable by traps that previously fell to the generic alarm.
#: Re-pinning it is a deliberate act, and `parser_rev` moves with it.
RULES_HASH_A9 = "5ebe16c3b9b6f06fe5db50954b4d2fd7071d7f89d0660b36e7e9b1e1d659021f"
#:
#: A9b (the config-change follow-up) adds TWO more rows — `syslog.config.change`
#: and `trap.config.change`, one symptom (`device_config_change`) on two
#: observers — so the table moved again and so does this pin. Again no EXISTING
#: rule's grammar changed: the whole pre-A9b corpus replays byte-for-byte except
#: the single `entConfigChange` trap fixture A9 recorded as a generic alarm,
#: which is now typed (that entry declares the baseline skip and carries its new
#: recorded output). The syslog half ships `shadow: true` — it is counted and
#: emits nothing — so the SYSLOG lane's emission is byte-identical to A9's.
RULES_HASH_A9B = "a0be9de50a0657bc8a8a029305b23909cf5a09d72179f294b96cec889426eade"
#:
#: 218 (the linkDown/linkUp status enrichment A9 deferred) is the FIRST re-pin
#: that changes an EXISTING rule's grammar rather than adding rows: both link
#: rules now extract `ifAdminStatus`/`ifOperStatus` and emit them as
#: `omit_empty` attrs. It is still additive on the wire — no corpus event
#: carries either varbind, so every recorded output below replays byte-for-byte,
#: and `state`/`entity`/`severity`/`native_id` (therefore `signal_id`) are
#: untouched by construction. `test_link_status_enrichment_218.py` is the proof
#: of both halves.
RULES_HASH_218 = "34cce98ee1a4ee8fb1d6d990930400506f993e61be19b4e30a23c886419a2039"
RULES_HASH_A3 = RULES_HASH_218


def _guard_patterns(node) -> list[str]:
    """Every regex SOURCE string reachable in a guard tree (test-local walker:
    the point is to re-derive, not to reuse the bake's own helper)."""
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "re" and isinstance(v, list) and len(v) >= 2:
                out.append(str(v[1]))
            else:
                out.extend(_guard_patterns(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_guard_patterns(v))
    return out


def test_rules_hash_is_stable_and_matches_the_exported_tag():
    assert P.RULES_HASH == RULES_HASH_A3, (
        "rules_hash moved — a rule changed. If that was intended, re-pin "
        "RULES_HASH_A3 and bump parser_rev in telemetry-catalog/events.yaml.")
    assert P.rules_hash(RULES) == P.RULES_HASH
    assert P.RULES_HASH_TAG == P.RULES_HASH[:16]
    assert len(P.RULES_HASH) == 64      # sha256 hex


@pytest.mark.parametrize("field,value", [
    ("kind", "something_else"),
    ("entity_type", "device_or_interface"),
    ("state", "down"),
    ("state_re", r"\bmutant\b"),
    ("markers", ("MUTANT",)),
    ("pattern_src", r"\bmutant\b"),
    ("fidelity_key", "mutant_family"),
    ("vendors", ("mutant",)),
])
def test_mutating_any_rule_field_moves_the_hash(field, value):
    """MUTANT. A silent edit to a rule must be detectable from the stored data
    alone, even when the author forgot to bump PARSER_REV."""
    mutant = (replace(RULES[0], **{field: value}),) + RULES[1:]
    assert P.rules_hash(mutant) != P.RULES_HASH, (
        f"changing {field!r} left rules_hash unchanged — the field is not in "
        "Rule.digest_fields() and a silent edit to it is invisible")


def test_reordering_the_table_moves_the_hash():
    """Order is behaviour: these branches run in sequence and the port rules are
    first-match-wins, so a swap must not hash the same."""
    swapped = (RULES[1], RULES[0]) + RULES[2:]
    assert P.rules_hash(swapped) != P.RULES_HASH


def test_a_catalog_promotion_is_not_a_parser_edit():
    """`fidelity` is the catalog's claim about a grammar, not the grammar.
    Promoting a family must not read as an edit to the rules."""
    assert "fidelity" not in RULES[0].digest_fields()
    promoted = dict(P.CATALOG_EVENT_FIDELITY, bgp_route_churn="live_validated")
    original = P.CATALOG_EVENT_FIDELITY.copy()
    try:
        P.CATALOG_EVENT_FIDELITY.clear()
        P.CATALOG_EVENT_FIDELITY.update(promoted)
        assert P.rules_hash(RULES) == P.RULES_HASH
    finally:
        P.CATALOG_EVENT_FIDELITY.clear()
        P.CATALOG_EVENT_FIDELITY.update(original)


# ══ 5. fidelity comes from the telemetry catalog ════════════════════════════

def test_the_baked_fidelity_map_matches_the_telemetry_catalog():
    """`CATALOG_EVENT_FIDELITY` is a BUILD-TIME snapshot of events.yaml (the
    catalog is not shipped inside the correlation image). This is the drift
    guard that keeps the snapshot honest."""
    yaml = pytest.importorskip("yaml")
    path = os.path.join(CATALOG_DIR, "events.yaml")
    if not os.path.exists(path):        # pragma: no cover - repo layout only
        pytest.skip("telemetry-catalog not present in this tree")
    with open(path, encoding="utf-8") as fh:
        fams = yaml.safe_load(fh)["families"]
    declared = {name: fam["fidelity_status"] for name, fam in fams.items()
                if fam.get("fidelity_status") is not None}
    assert P.CATALOG_EVENT_FIDELITY == declared, (
        "producers.CATALOG_EVENT_FIDELITY has drifted from "
        "telemetry-catalog/events.yaml — update the snapshot and bump PARSER_REV")


def test_every_rule_fidelity_key_names_a_real_catalog_family():
    yaml = pytest.importorskip("yaml")
    path = os.path.join(CATALOG_DIR, "events.yaml")
    if not os.path.exists(path):        # pragma: no cover - repo layout only
        pytest.skip("telemetry-catalog not present in this tree")
    with open(path, encoding="utf-8") as fh:
        fams = set(yaml.safe_load(fh)["families"])
    for r in RULES:
        if r.fidelity_key is not None:
            assert r.fidelity_key in fams, (
                f"rule {r.rule_id!r} points at catalog family "
                f"{r.fidelity_key!r}, which events.yaml does not define")


@pytest.mark.parametrize("rule_id,expected", [
    # the three families the catalog declares (all doc_claimed today)
    ("syslog.bgp.route_churn", "doc_claimed"),
    ("syslog.mac.flap", "doc_claimed"),
    ("syslog.stp.topology_notification", "doc_claimed"),
    # a family the catalog knows but makes NO fidelity claim about
    ("syslog.bgp.adjacency_change", "code"),
    ("syslog.stp.topology_change", "code"),
    # a branch with no catalog family at all
    ("syslog.fhrp.state_change", "code"),
    # the generic safety nets are never "validated"
    ("syslog.generic.device_alarm", "code"),
    ("trap.generic.device_alarm", "code"),
])
def test_fidelity_is_stamped_from_the_catalog_row(rule_id, expected):
    sig = fire(rule_id)
    assert sig is not None
    assert sig.attrs["fidelity"] == expected


def test_an_undeclared_family_never_reads_as_validated():
    """The honest default. "code" means the grammar lives only in producers.py
    and the catalog vouches for nothing."""
    assert P._fidelity_of(None) == "code"
    assert P._fidelity_of("a_family_nobody_catalogued") == "code"
    assert set(P.CATALOG_EVENT_FIDELITY.values()) <= {
        "doc_claimed", "lab_validated", "live_validated"}


# ══ 6. the screen is DERIVED from the table ═════════════════════════════════

def test_the_guard_markers_are_derived_from_the_rule_table():
    """…from the EMITTING syslog rules. A9b: a `shadow` row emits nothing, so
    widening the ingest screen for it would admit more raw lines into both
    producers and buy no evidence at all — it is observed only on lines the
    screen already admits for some other rule. Re-derived here independently of
    `producers._SCREEN_RULES`, so the exclusion cannot be assumed."""
    expected = []
    for r in RULES:
        if r.lane != "syslog" or r.shadow:
            continue
        for m in r.markers:
            if m not in expected:
                expected.append(m)
    assert list(P._CP_GUARD_MARKERS) == expected
    leaked = {m for r in RULES if r.shadow for m in r.markers} - set(expected)
    assert leaked or not any(r.shadow for r in RULES), (
        "a shadow row's markers are all also declared by an emitting rule — "
        "this test would pass vacuously; pick a different assertion")


def test_the_guard_patterns_are_derived_from_the_rule_table():
    expected = []
    for r in RULES:
        if r.lane == "syslog" and r.pattern_src and r.pattern_src not in expected:
            expected.append(r.pattern_src)
    assert list(P._CP_GUARD_PATTERNS) == expected


def test_every_registered_guard_pattern_is_in_its_own_guard_tree():
    """The table→guard direction of the screen contract.

    `test_ingest_prefilter_p3` walks the guard trees and fails on a regex
    missing from `_CP_GUARD_PATTERNS`; this is the other way round — an entry in
    the table that no longer appears in the rule's OWN guard would silently
    widen the screen (harmless) while advertising coverage for a gate that is
    gone (not harmless: it hides that a rule was deleted).

    Before A3 this read the branch function's source text. The branches are data
    now, so it reads the data — a strictly stronger check: a pattern that merely
    APPEARED in the file used to satisfy it, where a pattern must now be a live
    `re` node of that exact rule's guard."""
    for r in RULES:
        if r.pattern_src:
            assert r.pattern_src in _guard_patterns(r.guard_src), (
                f"rule {r.rule_id!r} registers guard pattern {r.pattern_src!r}, "
                "which is not a `re` node of its own guard tree")


def test_the_port_event_rule_list_is_derived_from_the_rule_table():
    port_rules = [r for r in RULES if r.lane == "port"]
    assert len(P._PORT_EVENT_RULES) == len(port_rules)
    for (pat, kind, iface, sev), rule in zip(P._PORT_EVENT_RULES, port_rules):
        assert kind == rule.kind
        assert pat is rule.pattern, "the screen and the branch must share ONE pattern"
        assert iface == (rule.entity_type == "interface")
        assert sev == rule.severity


def test_a_new_marker_reaches_the_screen_through_the_table_alone():
    """The derivation is the point: registering a branch's screen coverage is
    now the same act as registering the branch."""
    extra = P.Rule(rule_id="syslog.test.mutant", lane="syslog", source="syslog",
                   kind="device_alarm", entity_type="device",
                   markers=("ZZZ_MUTANT_MARKER",))
    markers = []
    for r in (*RULES, extra):
        if r.lane == "syslog":
            markers.extend(r.markers)
    assert "ZZZ_MUTANT_MARKER" in markers
    assert "ZZZ_MUTANT_MARKER" not in P._CP_GUARD_MARKERS


def test_the_screen_still_admits_every_rule_fixture():
    """SOUNDNESS after the refactor: the screen must not reject a line one of
    these rules classifies. Held at INFO severity so the generic device-alarm
    net cannot mask a hole in the derived markers."""
    for rule_id, (lane, ev) in sorted(RULE_FIXTURES.items()):
        rule = P.RULES_BY_ID[rule_id]
        if lane == "trap" or rule.generic:
            continue
        probe = dict(ev, severity="info")
        if rule.shadow:
            # A9b: a shadow row emits nothing, so the screen is NOT widened for
            # it and rejecting its line loses no signal. Asserted in the
            # REJECTING direction so the exclusion is a stated contract rather
            # than a hole in this test's coverage.
            assert not P.syslog_promotable(probe), (
                f"{rule_id!r} is a shadow row — the screen must not be widened "
                "for a rule that cannot emit")
            continue
        assert P.syslog_promotable(probe), (
            f"the derived screen rejects {rule_id!r}: {ev['message']!r}")


# ══ 7. coverage metrics ═════════════════════════════════════════════════════

def test_rule_hits_are_counted_per_rule_and_pre_seeded():
    assert set(P.RULE_HITS) == {r.rule_id for r in RULES}
    assert set(P.RULE_HITS.values()) == {0}, "counters must start at zero"
    fire("syslog.bgp.adjacency_change")
    fire("syslog.bgp.adjacency_change")
    fire("syslog.link.state_change")
    assert P.RULE_HITS["syslog.bgp.adjacency_change"] == 2
    assert P.RULE_HITS["syslog.link.state_change"] == 1
    assert P.RULE_HITS["syslog.mac.flap"] == 0


def test_generic_fallbacks_are_counted_by_lane():
    fire("syslog.generic.device_alarm")
    fire("syslog.generic.device_alarm")
    fire("trap.generic.device_alarm")
    assert P.GENERIC_FALLBACKS == {"syslog": 2, "trap": 1}


def test_an_empty_window_makes_no_promotion_claim():
    """1.0, never 0.0 — an empty window must not page as 'the parser stopped
    classifying'."""
    assert P.semantic_promotion_rate() == 1.0


def test_the_promotion_rate_is_typed_over_admitted():
    for _ in range(7):
        fire("syslog.link.state_change")          # typed
    for _ in range(3):
        fire("syslog.generic.device_alarm")       # generic
    assert P.semantic_promotion_rate() == pytest.approx(0.7)
    stats = P.parser_stats()
    assert stats["promotion_window_used"] == 10
    assert stats["promotion_window"] == P.PROMOTION_WINDOW == 10_000


def test_lines_that_classify_as_nothing_are_not_in_the_denominator():
    """The rate measures PARSER COVERAGE, not the noise mix. A line nothing
    claims is the pre-filter's business."""
    fire("syslog.link.state_change")
    for _ in range(50):
        assert P.syslog_control_signal(
            syslog_ev("%SYS-6-LOGGINGHOST", "Logging to host 10.0.0.2 started",
                      "info"), "t1", T0) is None
    assert P.parser_stats()["promotion_window_used"] == 1
    assert P.semantic_promotion_rate() == 1.0


def test_the_window_rolls_and_forgets(monkeypatch):
    """A ROLLING window: an old generic must age out, not weigh forever. Run at
    a small window so the test stays fast, then prove the arithmetic."""
    monkeypatch.setattr(P, "PROMOTION_WINDOW", 4)
    P.reset_parser_counters()
    fire("syslog.generic.device_alarm")
    for _ in range(3):
        fire("syslog.link.state_change")
    assert P.semantic_promotion_rate() == pytest.approx(0.75)
    for _ in range(4):
        fire("syslog.link.state_change")
    assert P.semantic_promotion_rate() == 1.0
    assert P.parser_stats()["promotion_window_used"] == 4


def test_the_ring_never_grows_past_the_window(monkeypatch):
    monkeypatch.setattr(P, "PROMOTION_WINDOW", 8)
    P.reset_parser_counters()
    for i in range(200):
        fire("syslog.link.state_change" if i % 2 else "syslog.generic.device_alarm")
    assert len(P._PROMO_RING) == 8
    assert P.semantic_promotion_rate() == pytest.approx(0.5)


# ══ 8. exposition ═══════════════════════════════════════════════════════════

def test_the_parser_metrics_are_exported():
    fire("syslog.bgp.adjacency_change")
    fire("syslog.generic.device_alarm")
    fire("trap.generic.device_alarm")
    body = main._metrics_text()
    assert "# TYPE corr_parser_rule_hits_total counter" in body
    assert 'corr_parser_rule_hits_total{rule_id="syslog.bgp.adjacency_change"} 1' in body
    assert 'corr_parser_generic_fallback_total{source="syslog"} 1' in body
    assert 'corr_parser_generic_fallback_total{source="trap"} 1' in body
    assert "# TYPE corr_semantic_promotion_rate gauge" in body
    assert "corr_semantic_promotion_rate 0.333333" in body
    assert f'parser_rev="{P.PARSER_REV}"' in body
    assert f'rules_hash="{P.RULES_HASH_TAG}"' in body
    # the pre-existing pre-filter series must survive untouched
    assert "# TYPE corr_ingest_prefilter_total counter" in body


def test_every_rule_id_gets_a_series_even_at_zero():
    """A rule that stops firing must read as a FLAT series, not a missing one —
    that is what makes a silently dead branch visible."""
    body = main._metrics_text()
    for r in RULES:
        assert f'corr_parser_rule_hits_total{{rule_id="{r.rule_id}"}} ' in body


def test_the_health_payload_carries_the_parser_block():
    fire("syslog.mac.flap")
    parser = main._health_payload()["parser"]
    assert parser["parser_rev"] == P.PARSER_REV
    assert parser["rules_hash"] == P.RULES_HASH_TAG
    assert parser["rules"] == len(RULES)
    assert parser["rule_hits"]["syslog.mac.flap"] == 1
    assert parser["semantic_promotion_rate"] == 1.0


def test_the_rule_label_set_is_the_only_label_the_parser_metrics_carry():
    """LLM-free zero trust on cardinality: no device/tenant string may reach a
    label on these series."""
    fire("syslog.generic.device_alarm")
    for line in main._metrics_text().splitlines():
        if not line.startswith("corr_parser_rule_hits_total{"):
            continue
        label = line.split('rule_id="', 1)[1].split('"', 1)[0]
        assert label in P.RULES_BY_ID


# ══ 9. BYTE-IDENTICAL OUTPUT over the whole fixture corpus ══════════════════
#
# `fixtures/parser_golden_corpus.jsonl` is the OLD path, frozen: every raw
# syslog line in telemetry-catalog/fixtures/syslog_events.jsonl, every syslog-
# shaped string literal harvested from the in-tree `test_*.py` corpora (crossed
# with the RFC5424 severities, and used as both the tag and the message so the
# classification-token gates are exercised), a curated line per vendor grammar,
# and a trap matrix over every classified OID / trap name / event_type /
# varbind shape. Each entry records what the PRE-provenance parser produced.
#
# Regenerating it is a deliberate act, never a way to make this test pass: the
# file IS the old behaviour, and if the new parser disagrees with it the parser
# changed.


def _shot(sig) -> dict | None:
    """The comparison surface: identity + classification + attrs, MINUS the four
    provenance keys, which are the only thing allowed to be new."""
    if sig is None:
        return None
    attrs = sig.attrs if isinstance(sig.attrs, dict) else {}
    return {
        "kind": sig.kind,
        "entity_type": sig.entity_type.value,
        "entity_id": sig.entity_id,
        "state": str(attrs.get("state", "")),
        "tokens": list(sig.entity_tokens),
        "native_id": sig.native_id,
        "signal_id": str(sig.signal_id),
        "severity": sig.severity.value,
        "metric_name": sig.metric_name,
        "modality_class": sig.modality_class.value,
        "attrs": {k: v for k, v in sorted(attrs.items())
                  if k not in PROVENANCE_KEYS},
    }


def _strip(expected: dict | None) -> dict | None:
    if expected is None or "attrs" not in expected:
        return expected
    out = dict(expected)
    out["attrs"] = {k: v for k, v in expected["attrs"].items()
                    if k not in PROVENANCE_KEYS}
    return out


@pytest.fixture(scope="module")
def golden() -> list[dict]:
    with open(GOLDEN, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_the_golden_corpus_is_big_enough_to_prove_something(golden):
    """A canary on the corpus itself: an empty or shrunken file would make the
    equivalence test below vacuously green."""
    assert len(golden) >= 1000, f"corpus shrank to {len(golden)} entries"
    kinds = {out["kind"] for e in golden for out in e["out"].values()
             if out and "kind" in out}
    missing = sorted({r.kind for r in RULES} - kinds)
    assert not missing, f"the corpus no longer exercises: {missing}"


def test_the_whole_fixture_corpus_replays_byte_identically(golden):
    """THE REGRESSION. Old path vs new path over every fixture: same kind, same
    entity, same state, same tokens, same native_id, same signal_id, same
    attrs — provenance excluded."""
    mismatches = []
    for entry in golden:
        ev = entry["ev"]
        lanes = (("trap_control_signal", P.trap_control_signal),) \
            if entry["lane"] == "trap" else \
            (("syslog_control_signal", P.syslog_control_signal),
             ("port_event_signal", P.port_event_signal))
        for name, fn in lanes:
            # A malformed-provenance line is DeadLetter'd by the producer; the
            # corpus records that outcome too, so it has to survive the replay
            # as an outcome rather than as a test error. (Today's corpus holds
            # none — the assertion below is what would notice a NEW one.)
            try:
                got = _shot(fn(dict(ev), "t1", T0))
            except DeadLetter as exc:
                got = {"error": type(exc).__name__}
            want = _strip(entry["out"][name])
            if got != want:
                mismatches.append((name, ev.get("message") or ev.get("trap_oid"),
                                   want, got))
    assert not mismatches, (
        f"{len(mismatches)} fixture(s) classify differently than before this "
        f"change. First: {mismatches[0]}")


def test_every_classified_corpus_entry_now_carries_provenance(golden):
    """The other half of the same replay: everything that WAS classified is now
    also attributed."""
    seen: set[str] = set()
    for entry in golden:
        ev = entry["ev"]
        lanes = (P.trap_control_signal,) if entry["lane"] == "trap" else \
            (P.syslog_control_signal, P.port_event_signal)
        for fn in lanes:
            try:
                sig = fn(dict(ev), "t1", T0)
            except DeadLetter:
                continue          # no signal, so nothing to attribute
            if sig is None:
                continue
            assert PROVENANCE_KEYS <= set(sig.attrs), (
                f"{sig.kind} from {ev!r} carries no provenance")
            seen.add(sig.attrs["rule_id"])
    assert seen <= set(P.RULES_BY_ID)
    assert len(seen) >= 20, f"the corpus only exercised {len(seen)} rules"
