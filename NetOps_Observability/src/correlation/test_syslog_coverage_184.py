# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 184 — syslog parser coverage of the enterprise-outage symptoms.

WHAT WAS MEASURED (2026-08-29, against `producers.syslog_control_signal`):
on one generated outage site 51 % of the syslog stream was invisible to the
engine. Per symptom:

  * `%BGP-5-NBR_RESET`   NOT promoted at all — notice severity is under the
                         generic device-alarm floor and the mnemonic carries no
                         ADJCHANGE token, so BGP route/update churn produced
                         nothing.
  * `%BGP-4-MAXPFX`      promoted only as a generic `device_alarm`: no peer
    `%BGP-3-NOTIFICATION` token, no state, no `bgp_*` kind.
  * `%SPANTREE-5-TOPOTRAP` promoted onto the SYNTHETIC entity `<host>:unknown`,
                         collapsing every TCN a device ever logs onto one
                         identity.
  * `mac_flap`           promoted with NO `attrs["state"]`, so a MAC move could
                         never contribute a state transition.

WHAT THIS FILE PINS. One block per symptom: every vendor shape the parser now
claims, the near-miss line that must NOT be claimed by the new rule, the
identity contract (distinct content → distinct native_id; byte-identical line →
identical id), and a REGRESSION PIN listing what every pre-existing fixture
classified as before this change — so a future edit that quietly re-routes an
old line is red, not silent.

FIDELITY (telemetry-catalog/README.md ladder): every vendor shape below is
`doc_claimed` — taken from vendor documentation, not from a captured device
stream. `docs/design/telemetry-coverage-reference.md` documents the BGP MIB
plane, not these syslog grammars, and the L2 fabric (STP/MAC) research row is
still PENDING there. The catalog rows say so; these fixtures pin
parser↔catalog agreement, they do not promote a row.
"""

from datetime import datetime, timezone

import pytest

import confirmability
import coverage as cov
import producers as P
from catalog import builtin_catalog
from layers import CausalLayer, layer_of
from producers import EMITTED_KINDS, syslog_control_signal
from signals import EntityType, ModalityClass, Severity, Source

T0 = datetime(2026, 9, 2, 10, 0, 0, tzinfo=timezone.utc)


def ev(tag: str, msg: str, severity: str = "notice", host: str = "cov-dev-1",
       ms: int = 0) -> dict:
    return {
        "hostname": host, "appname": tag, "message": msg, "severity": severity,
        "timestamp": f"2026-09-02T10:00:00.{ms:03d}Z",
    }


def classify(tag: str, msg: str, severity: str = "notice", host: str = "cov-dev-1",
             ms: int = 0):
    return syslog_control_signal(ev(tag, msg, severity, host, ms), "t1", T0)


# ══ SYMPTOM 1+2 — BGP route/update churn (%BGP-5-NBR_RESET) ═════════════════
#
# PROMOTE, new kind `bgp_route_churn`: state-bearing and peer-tokened, but NOT
# an adjacency change — a reset reason may be a soft/administrative clear, and
# calling it "adjacency down" would be a false session-down.

NBR_RESET_SHAPES = [
    # Cisco IOS / IOS-XE / NX-OS share this mnemonic and this text.
    ("%BGP-5-NBR_RESET",
     "%BGP-5-NBR_RESET: Neighbor 10.0.0.200 reset (BGP Notification received)",
     "notice", "BGP Notification received"),
    ("%BGP-5-NBR_RESET",
     "%BGP-5-NBR_RESET: Neighbor 10.0.0.200 reset (User reset request)",
     "notice", "User reset request"),
    ("%BGP-5-NBR_RESET",
     "%BGP-5-NBR_RESET: Neighbor 10.0.0.200 reset (Peer closed the session)",
     "notice", "Peer closed the session"),
]


@pytest.mark.parametrize("tag,msg,sev,reason", NBR_RESET_SHAPES,
                         ids=[r for _t, _m, _s, r in NBR_RESET_SHAPES])
def test_bgp_nbr_reset_promotes_as_peer_tokened_route_churn(tag, msg, sev, reason):
    s = classify(tag, msg, sev)
    assert s is not None, "the symptom tracker 184 measured as INVISIBLE"
    assert s.kind == "bgp_route_churn"
    assert s.entity_type is EntityType.DEVICE and s.entity_id == "cov-dev-1"
    assert s.attrs["state"] == "churn"          # state-bearing (was: nothing)
    assert s.attrs["subtype"] == "nbr_reset"
    assert s.attrs["peer"] == "10.0.0.200"      # peer-tokened (was: nothing)
    assert "10.0.0.200" in s.entity_tokens      # the grounding handle
    assert s.attrs["reason"] == reason
    assert s.severity is Severity.WARN
    assert s.source is Source.SYSLOG
    assert s.modality_class is ModalityClass.CONTROL_PLANE


def test_bgp_route_churn_survives_the_notice_severity_floor():
    """The exact reason it used to vanish: notice (5) is BELOW the generic
    device-alarm floor, so nothing but a classified branch can see it."""
    assert P.syslog_severity_num(ev("%BGP-5-NBR_RESET", "x"), "%BGP-5-NBR_RESET") == 5
    assert 5 > P.ALARM_SEVERITY_FLOOR
    assert classify(*NBR_RESET_SHAPES[0][:3]) is not None


def test_the_update_burst_is_the_same_shape_emitted_densely():
    """`bgp_router_update_burst` has no mnemonic of its own — it is the same
    %BGP-5-NBR_RESET line repeated. Each occurrence must be its OWN signal."""
    a = classify(*NBR_RESET_SHAPES[0][:3], ms=1)
    b = classify(*NBR_RESET_SHAPES[0][:3], ms=2)
    assert a is not None and b is not None
    assert a.signal_id_str != b.signal_id_str


# ══ SYMPTOM 3 — prefix pressure (%BGP-4-MAXPFX / MAXPFXEXCEED) ══════════════

def test_bgp_maxpfx_warning_is_churn_not_a_teardown():
    s = classify(
        "%BGP-4-MAXPFX",
        "%BGP-4-MAXPFX: No. of prefix received from 10.0.0.200 (afi 0) "
        "reaches 12000, max 250000", "warning")
    assert s is not None and s.kind == "bgp_route_churn"   # was: device_alarm
    assert s.attrs["subtype"] == "maxpfx"
    assert s.attrs["peer"] == "10.0.0.200"
    # The session is still ESTABLISHED at the warning threshold — "down" here
    # would be a session teardown the device never reported.
    assert s.attrs["state"] == "churn"
    assert s.attrs["prefix_count"] == "12000" and s.attrs["prefix_max"] == "250000"
    assert s.severity is Severity.WARN


def test_bgp_maxpfx_exceeded_shuts_the_peer_and_reads_down():
    s = classify(
        "%BGP-4-MAXPFXEXCEED",
        "%BGP-4-MAXPFXEXCEED: No. of prefix received from 10.0.0.200 (afi 0): "
        "250001 exceed limit 250000", "warning")
    assert s is not None and s.kind == "bgp_route_churn"
    assert s.attrs["state"] == "down" and s.severity is Severity.HIGH
    assert s.attrs["prefix_count"] == "250001" and s.attrs["prefix_max"] == "250000"


def test_junos_prefix_limit_shape():
    """Junos rpd carries no mnemonic in appname — matched on the message."""
    s = classify(
        "rpd",
        "bgp_rt_maxprefixes_check: 10.0.0.200 (External AS 65001): Configured "
        "maximum prefix-limit threshold(90%) exceeded for inet-unicast nlri: "
        "9000 (instance master)", "warning", host="junos-edge1")
    assert s is not None and s.kind == "bgp_route_churn"
    assert s.attrs["subtype"] == "maxpfx" and s.attrs["peer"] == "10.0.0.200"
    assert s.attrs["prefix_count"] == "9000"


# ══ SYMPTOM 4 — %BGP-3-NOTIFICATION ════════════════════════════════════════
#
# PROMOTE as `bgp_adjacency_change`: RFC 4271 §6 — a speaker that sends or
# receives a NOTIFICATION closes the session. It is a real adjacency transition
# and the kind the engine's BGP signatures already consume, so it needs no new
# template to be useful.

NOTIFICATION_SHAPES = [
    ("cisco-received", "%BGP-3-NOTIFICATION",
     ("%BGP-3-NOTIFICATION: received from neighbor 10.0.0.200 6/4 "
     "(Administrative Reset) 0 bytes"), "err", "6/4", "Administrative Reset"),
    ("cisco-sent", "%BGP-3-NOTIFICATION",
     ("%BGP-3-NOTIFICATION: sent to neighbor 10.0.0.200 4/0 "
     "(hold time expired) 0 bytes"), "err", "4/0", "hold time expired"),
    ("junos-rpd", "rpd",
     ("bgp_pp_recv:3435: NOTIFICATION received from 10.0.0.200 (External AS "
     "65001): code 6 (Cease) subcode 4 (Administrative Reset)"), "err",
     "6/4", "Administrative Reset"),
]


@pytest.mark.parametrize("vid,tag,msg,sev,code,reason", NOTIFICATION_SHAPES,
                         ids=[v for v, *_ in NOTIFICATION_SHAPES])
def test_bgp_notification_is_a_real_adjacency_teardown(vid, tag, msg, sev, code, reason):
    s = classify(tag, msg, sev)
    assert s is not None
    assert s.kind == "bgp_adjacency_change"     # was: device_alarm
    assert s.entity_type is EntityType.DEVICE and s.entity_id == "cov-dev-1"
    assert s.attrs["state"] == "down"           # was: no state
    assert s.attrs["subtype"] == "notification"
    assert s.attrs["peer"] == "10.0.0.200"      # was: no peer token
    assert "10.0.0.200" in s.entity_tokens
    assert s.attrs["code"] == code and s.attrs["reason"] == reason
    assert s.severity is Severity.HIGH


def test_notification_and_adjchange_for_one_teardown_are_two_signals():
    """A device logs BOTH lines for one teardown, often in the same
    millisecond. They are two corroborating reports (like %LINK + %LINEPROTO)
    and must not collapse onto one identity."""
    notif = classify("%BGP-3-NOTIFICATION",
                     "%BGP-3-NOTIFICATION: received from neighbor 10.0.0.200 "
                     "6/4 (Administrative Reset) 0 bytes", "err")
    adj = classify("%BGP-5-ADJCHANGE",
                   "%BGP-5-ADJCHANGE: neighbor 10.0.0.200 Down BGP "
                   "Notification sent", "notice")
    assert notif is not None and adj is not None
    assert notif.kind == adj.kind == "bgp_adjacency_change"
    assert notif.native_id != adj.native_id
    assert notif.signal_id_str != adj.signal_id_str


# ══ NEAR MISSES — the same words, different semantics ═══════════════════════

def test_a_reset_reason_that_mentions_notification_is_still_churn():
    """%BGP-5-NBR_RESET states its reason as "(BGP Notification received)".
    Reading the message before the mnemonic would file a RESET as a TEARDOWN —
    the exact false session-down this branch exists to avoid."""
    s = classify(*NBR_RESET_SHAPES[0][:3])
    assert s is not None
    assert s.kind == "bgp_route_churn" and s.attrs["subtype"] == "nbr_reset"


def test_an_adjchange_that_mentions_notification_stays_an_adjchange():
    """The ADJCHANGE branch owns this line; the churn branch must not steal it,
    and its identity must stay the pre-184 one."""
    s = classify("%BGP-5-ADJCHANGE",
                 "%BGP-5-ADJCHANGE: neighbor 10.0.0.200 Down BGP Notification "
                 "sent", "notice")
    assert s is not None and s.kind == "bgp_adjacency_change"
    assert "subtype" not in s.attrs
    assert s.native_id.startswith("cov-dev-1|bgp_adj|10.0.0.200|down|")


def test_a_non_bgp_notification_line_is_not_a_bgp_event():
    """The gate is (BGP in the classification token) AND the mnemonic — a
    NOTIFICATION from some other subsystem must not become a BGP signal."""
    s = classify("%SNMP-5-NOTIFICATION",
                 "%SNMP-5-NOTIFICATION: notification log is full", "notice")
    assert s is None or not s.kind.startswith("bgp_")


def test_a_maxpfx_line_from_another_subsystem_is_not_bgp_churn():
    s = classify("%PLATFORM-6-MAXPFX_TABLE",
                 "%PLATFORM-6-MAXPFX_TABLE: fib table resized", "notice")
    assert s is None or s.kind != "bgp_route_churn"


# ══ SYMPTOM 5 — %SPANTREE-5-TOPOTRAP attribution ═══════════════════════════

def test_tcn_is_attributed_to_the_device_and_its_stp_instance():
    s = classify("%SPANTREE-5-TOPOTRAP",
                 "%SPANTREE-5-TOPOTRAP: Topology Change Trap for instance MST0",
                 "notice")
    assert s is not None and s.kind == "stp_topology_change"
    # was: EntityType.INTERFACE on the synthetic entity "cov-dev-1:unknown"
    assert s.entity_type is EntityType.DEVICE
    assert s.entity_id == "cov-dev-1"
    assert "cov-dev-1:unknown" != s.entity_id
    assert s.attrs["instance"] == "MST0" and s.attrs["interface"] == ""
    # tracker 168: the instance is DEVICE-LOCAL, so it is qualified, never bare.
    assert "cov-dev-1:mst0" in s.entity_tokens and "mst0" not in s.entity_tokens


def test_a_pvst_tcn_is_attributed_to_its_vlan():
    s = classify("%SPANTREE-5-TOPOTRAP",
                 "%SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan 100",
                 "notice")
    assert s is not None and s.entity_id == "cov-dev-1"
    assert s.attrs["instance"] == "100"
    # `vlan100` cannot collide with an MST instance NAMED "100".
    assert "cov-dev-1:vlan100" in s.entity_tokens


def test_two_tcns_for_different_instances_are_two_signals():
    """The collapse tracker 184 measured: every TCN on one device shared the
    identity `<host>:unknown|unknown`, so same-millisecond TCNs were ONE."""
    a = classify("%SPANTREE-5-TOPOTRAP",
                 "%SPANTREE-5-TOPOTRAP: Topology Change Trap for instance MST0")
    b = classify("%SPANTREE-5-TOPOTRAP",
                 "%SPANTREE-5-TOPOTRAP: Topology Change Trap for instance MST1")
    assert a is not None and b is not None
    assert a.native_id != b.native_id and a.signal_id_str != b.signal_id_str


def test_a_tcn_that_names_a_port_keeps_the_port():
    """%SPANTREE-5-ROOTCHANGE names a port without the word "Interface" — it
    is a real port attribution, not a device-scoped TCN."""
    s = classify("%SPANTREE-5-ROOTCHANGE",
                 "%SPANTREE-5-ROOTCHANGE: Root Changed for vlan 100: New Root "
                 "Port is GigabitEthernet0/1", "notice")
    assert s is not None
    assert s.entity_type is EntityType.INTERFACE
    assert s.entity_id == "cov-dev-1:GigabitEthernet0/1"


def test_the_port_transition_line_is_unchanged_byte_for_byte():
    """NEAR MISS / REGRESSION: %SPANTREE-6-PORT_STATE names an interface, so it
    must keep the interface scope AND the pre-184 native_id (its identity was
    never the problem)."""
    s = classify("%SPANTREE-6-PORT_STATE",
                 "%SPANTREE-6-PORT_STATE: Interface GigabitEthernet0/49 "
                 "instance MST0 moving from forwarding to blocking", "notice")
    assert s is not None and s.kind == "stp_topology_change"
    assert s.entity_type is EntityType.INTERFACE
    assert s.entity_id == "cov-dev-1:GigabitEthernet0/49"
    assert s.attrs["state"] == "down"
    assert s.native_id == (
        f"cov-dev-1|stp|GigabitEthernet0/49|down|{int(T0.timestamp() * 1000)}")


# ══ SYMPTOM 6 — mac_flap carries a state ═══════════════════════════════════

def test_mac_flap_is_state_bearing():
    s = classify("%SW_MATM-4-MACFLAP_NOTIF",
                 "Host 0011.2233.4455 in vlan 10 is flapping between port "
                 "Gi1/0/1 and port Gi1/0/2", "warning")
    assert s is not None and s.kind == "mac_flap"
    assert s.attrs["state"] == "flapping"       # was: no state at all
    assert s.attrs["port_a"] == "Gi1/0/1" and s.attrs["port_b"] == "Gi1/0/2"


def test_a_mac_move_names_its_old_and_new_port():
    s = classify("%L2FM-4-L2FM_MAC_MOVE",
                 "Mac 00ab.cd00.1122 in vlan 20 has moved from Eth1/1 to Eth1/2",
                 "warning", host="leaf2")
    assert s is not None and s.kind == "mac_flap"
    assert s.attrs["state"] == "moved"
    assert s.attrs["from_port"] == "Eth1/1" and s.attrs["to_port"] == "Eth1/2"


def test_the_mac_state_is_never_a_recovery_word():
    """No vendor logs "the MAC stopped moving", so neither value may read as a
    recovery — a MAC move must never close an incident."""
    from aggregation import RECOVERY_STATES, health_of, parsed_state
    for tag, msg in (
        ("%SW_MATM-4-MACFLAP_NOTIF",
         ("Host 0011.2233.4455 in vlan 10 is flapping between port Gi1/0/1 and "
         "port Gi1/0/2")),
        ("%L2FM-4-L2FM_MAC_MOVE",
         "Mac 00ab.cd00.1122 in vlan 20 has moved from Eth1/1 to Eth1/2"),
    ):
        s = classify(tag, msg, "warning")
        assert s is not None
        st = parsed_state(s)
        assert st and st not in RECOVERY_STATES
        assert health_of(st) == "unhealthy"      # a health CLAIM, was none


def test_the_mac_flap_identity_is_unchanged():
    """The MAC identity was never the defect — adding a state must not re-key
    every mac_flap signal ever persisted."""
    s = classify("%SW_MATM-4-MACFLAP_NOTIF",
                 "Host 0011.2233.4455 in vlan 10 is flapping between port "
                 "Gi1/0/1 and port Gi1/0/2", "warning", host="acc-sw2")
    assert s is not None
    assert s.native_id == (
        f"acc-sw2|mac_flap|0011.2233.4455|vlan10|{int(T0.timestamp() * 1000)}")


def test_a_link_flap_phrase_is_still_not_a_mac_flap():
    """NEAR MISS: the flap-state rule must not make the MAC branch greedier."""
    assert classify("%SYS-6-EVENT_TRIGGERED",
                    "Event handler LINK-FLAP was activated", "notice") is None


# ══ IDENTITY — content in, collisions out ══════════════════════════════════

DISTINCT_PAIRS = [
    ("churn-peer", ("%BGP-5-NBR_RESET",
                    "%BGP-5-NBR_RESET: Neighbor 10.0.0.200 reset (User reset request)"),
     ("%BGP-5-NBR_RESET",
      "%BGP-5-NBR_RESET: Neighbor 10.0.0.201 reset (User reset request)")),
    ("churn-subtype", ("%BGP-5-NBR_RESET",
                       "%BGP-5-NBR_RESET: Neighbor 10.0.0.200 reset (User reset request)"),
     ("%BGP-4-MAXPFX",
      "%BGP-4-MAXPFX: No. of prefix received from 10.0.0.200 (afi 0) reaches 12000, max 250000")),
    ("churn-count", ("%BGP-4-MAXPFX",
                     "%BGP-4-MAXPFX: No. of prefix received from 10.0.0.200 (afi 0) reaches 12000, max 250000"),
     ("%BGP-4-MAXPFX",
      "%BGP-4-MAXPFX: No. of prefix received from 10.0.0.200 (afi 0) reaches 13000, max 250000")),
    ("notify-code", ("%BGP-3-NOTIFICATION",
                     "%BGP-3-NOTIFICATION: received from neighbor 10.0.0.200 6/4 (Administrative Reset) 0 bytes"),
     ("%BGP-3-NOTIFICATION",
      "%BGP-3-NOTIFICATION: sent to neighbor 10.0.0.200 4/0 (hold time expired) 0 bytes")),
    ("tcn-instance", ("%SPANTREE-5-TOPOTRAP",
                      "%SPANTREE-5-TOPOTRAP: Topology Change Trap for instance MST0"),
     ("%SPANTREE-5-TOPOTRAP",
      "%SPANTREE-5-TOPOTRAP: Topology Change Trap for instance MST1")),
]


@pytest.mark.parametrize("label,a,b", DISTINCT_PAIRS,
                         ids=[lbl for lbl, _a, _b in DISTINCT_PAIRS])
def test_two_distinct_lines_never_share_one_identity(label, a, b):
    """The tracker-198 rule for the classified branches: the EXTRACTED FIELDS
    are the content, so any two lines that differ in them differ in id — even
    inside one millisecond."""
    sa = classify(a[0], a[1], "err")
    sb = classify(b[0], b[1], "err")
    assert sa is not None and sb is not None
    assert sa.native_id != sb.native_id, f"{label}: identity collapse"
    assert sa.signal_id_str != sb.signal_id_str


@pytest.mark.parametrize("label,a,b", DISTINCT_PAIRS,
                         ids=[lbl for lbl, _a, _b in DISTINCT_PAIRS])
def test_a_byte_identical_redelivery_still_dedups(label, a, b):
    """The other direction: replay must re-derive the SAME id, or every
    redelivery becomes a new signal."""
    first = classify(a[0], a[1], "err")
    again = classify(a[0], a[1], "err")
    assert first is not None and again is not None
    assert first.native_id == again.native_id
    assert first.signal_id_str == again.signal_id_str


# ══ the new kind is REGISTERED everywhere the contract requires ════════════

def test_bgp_route_churn_is_registered_in_every_ledger():
    assert "bgp_route_churn" in EMITTED_KINDS
    assert confirmability.KIND_MODALITY["bgp_route_churn"] is ModalityClass.CONTROL_PLANE
    assert layer_of("bgp_route_churn") is CausalLayer.NETWORK


def test_bgp_route_churn_is_a_declared_blind_spot_not_an_orphan():
    """It is CORROBORATING evidence — no signature REQUIRES it, and until one
    references it the kind is inert for RCA. That is declared, not accidental:
    the orphan-producer gate would otherwise be red."""
    cat = builtin_catalog()
    assert "bgp_route_churn" in cov.INTENTIONAL_BLIND
    entry = cov.INTENTIONAL_BLIND["bgp_route_churn"]
    assert entry["reason"] and entry["owner"] and entry["date_added"]
    assert cov.classify_kind("bgp_route_churn", cat) == "intentional_blind"
    assert not cov.orphan_producer_kinds(cat)


def test_bgp_notification_needs_no_new_template_to_be_useful():
    """The other half of the design: a NOTIFICATION reuses a kind signatures
    ALREADY consume, so that symptom lights up with no catalog change."""
    cat = builtin_catalog()
    assert "bgp_adjacency_change" in cov.consumed_kinds(cat)


# ══ the ingest pre-filter still passes every newly promotable line ══════════

@pytest.mark.parametrize("tag,msg,sev", [
    (t, m, s) for t, m, s, _r in NBR_RESET_SHAPES
] + [
    ("%BGP-4-MAXPFX",
     ("%BGP-4-MAXPFX: No. of prefix received from 10.0.0.200 (afi 0) reaches "
     "12000, max 250000"), "info"),
    ("%BGP-3-NOTIFICATION",
     ("%BGP-3-NOTIFICATION: received from neighbor 10.0.0.200 6/4 "
     "(Administrative Reset) 0 bytes"), "info"),
    ("rpd",
     ("bgp_pp_recv:3435: NOTIFICATION received from 10.0.0.200 (External AS "
     "65001): code 6 (Cease) subcode 4 (Administrative Reset)"), "info"),
    ("rpd",
     ("bgp_rt_maxprefixes_check: 10.0.0.200 (External AS 65001): Configured "
     "maximum prefix-limit threshold(90%) exceeded for inet-unicast nlri: 9000"),
     "info"),
    ("%SPANTREE-5-TOPOTRAP",
     "%SPANTREE-5-TOPOTRAP: Topology Change Trap for instance MST0", "info"),
])
def test_the_screen_never_rejects_a_newly_promotable_line(tag, msg, sev):
    """Held at INFO so the severity net cannot mask a missing marker: the
    pre-filter's soundness contract is that it NEVER rejects a line a
    classifier would have promoted."""
    e = ev(tag, msg, sev)
    assert syslog_control_signal(e, "t1", T0) is not None, "bad fixture"
    assert P.syslog_promotable(e)


# ══ REGRESSION PIN — what every pre-existing line classified as ════════════
#
# Captured from the parser BEFORE this change. Four rows carry the tracker-184
# delta and say so; every other row must be byte-identical forever.
#   (tag, message, severity) -> (kind, entity_id, state)
PRE_184: list[tuple[str, str, str, tuple[str | None, str | None, str | None], str]] = [
    # ---- telemetry-catalog/fixtures/syslog_events.jsonl ----
    ("%BGP-5-ADJCHANGE",
     "peer 10.0.0.1 (AS 65001) old state Established event RecvNotify new state Idle",
     "notice", ("bgp_adjacency_change", "cov-dev-1", "down"), ""),
    ("%BGP-5-ADJCHANGE", "neighbor 192.168.100.5 Down Interface flap", "notice",
     ("bgp_adjacency_change", "cov-dev-1", "down"), ""),
    ("%OSPF-5-ADJCHG", "Process 1, Nbr 10.0.0.2 on Ethernet1 from FULL to DOWN",
     "notice", ("ospf_adjacency_change", "cov-dev-1", "down"), ""),
    ("%LINK-3-UPDOWN", "Interface Ethernet1, changed state to down", "err",
     ("link_state_change", "cov-dev-1:Ethernet1", "down"), ""),
    ("%LINEPROTO-5-UPDOWN",
     "Line protocol on Interface Ethernet1, changed state to up", "notice",
     ("link_state_change", "cov-dev-1:Ethernet1", "up"), ""),
    ("%SYS-5-CONFIG_I", "Configured from console", "notice",
     (None, None, None), ""),
    ("%LLDP-5-NEIGHBOR_NEW",
     ("LLDP neighbor with chassisId 0c00.842b.3c00 and portId aac1.ab21.c775 "
     "added on interface Ethernet2"), "notice",
     ("lldp_neighbor_change", "cov-dev-1:Ethernet2", "up"), ""),
    ("-",
     ("lldp|6876|6876|00043|EV|remotePeerRemoved|I: LLDP remote peer removed on "
     "interface ethernet-1/1: System leaf1 with chassis ID 00:1C:73:AD:88:2A, "
     "port Ethernet1"), "notice",
     ("lldp_neighbor_change", "cov-dev-1:ethernet-1/1", "down"), ""),
    ("%SPANTREE-6-INTERFACE_DEL",
     "Interface Ethernet3 has been removed from instance MST0", "notice",
     ("stp_topology_change", "cov-dev-1:Ethernet3", "down"), ""),
    ("%SPANTREE-6-INTERFACE_STATE",
     "Interface Ethernet3 instance MST0 moving from discarding to learning",
     "notice", ("stp_topology_change", "cov-dev-1:Ethernet3", "up"), ""),
    ("-",
     ("isis|8808|8853|00045|EV|isisAdjacencyChange|W: In network-instance "
     "default, the level-2 IS-IS adjacency with system 0100.0000.0011, using "
     "interface ethernet-1/1.0, moved to state DOWN."), "notice",
     ("isis_adjacency_change", "cov-dev-1", "down"), ""),
    ("-",
     ("isis|8808|8853|00047|EV|isisAdjacencyChange|W: In network-instance "
     "default, the level-2 IS-IS adjacency with system 0100.0000.0011, using "
     "interface ethernet-1/1.0, moved to state UP."), "notice",
     ("isis_adjacency_change", "cov-dev-1", "up"), ""),
    # ---- scripts/enterprise_outage_chain.py exemplars ----
    ("LINK-3-UPDOWN",
     "%LINK-3-UPDOWN: Interface GigabitEthernet0/48, changed state to down",
     "err", ("link_state_change", "cov-dev-1:GigabitEthernet0/48", "down"), ""),
    ("LINEPROTO-5-UPDOWN",
     ("%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/48, "
     "changed state to up"), "notice",
     ("link_state_change", "cov-dev-1:GigabitEthernet0/48", "up"), ""),
    ("OSPF-5-ADJCHG",
     ("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.200 on GigabitEthernet0/48 from "
     "FULL to DOWN, Neighbor Down: Interface down or detached"), "notice",
     ("ospf_adjacency_change", "cov-dev-1", "down"), ""),
    ("BGP-5-ADJCHANGE",
     "%BGP-5-ADJCHANGE: neighbor 10.0.0.200 Down BGP Notification sent",
     "notice", ("bgp_adjacency_change", "cov-dev-1", "down"), ""),
    ("BGP-5-ADJCHANGE", "%BGP-5-ADJCHANGE: neighbor 10.0.0.200 Up", "notice",
     ("bgp_adjacency_change", "cov-dev-1", "up"), ""),
    ("SPANTREE-6-PORT_STATE",
     ("%SPANTREE-6-PORT_STATE: Interface GigabitEthernet0/49 instance MST0 "
     "moving from forwarding to blocking"), "notice",
     ("stp_topology_change", "cov-dev-1:GigabitEthernet0/49", "down"), ""),
    ("SPANTREE-6-PORT_STATE",
     ("%SPANTREE-6-PORT_STATE: Interface GigabitEthernet0/49 instance MST0 "
     "moving from listening to forwarding"), "notice",
     ("stp_topology_change", "cov-dev-1:GigabitEthernet0/49", "up"), ""),
    # ---- the four tracker-184 deltas (pre-184 value in the comment) ----
    ("BGP-5-NBR_RESET",
     "%BGP-5-NBR_RESET: Neighbor 10.0.0.200 reset (BGP Notification received)",
     "notice", ("bgp_route_churn", "cov-dev-1", "churn"),
     "184: was (None, None, None) — invisible"),
    ("BGP-4-MAXPFX",
     ("%BGP-4-MAXPFX: No. of prefix received from 10.0.0.200 (afi 0) reaches "
     "12000, max 250000"), "warning",
     ("bgp_route_churn", "cov-dev-1", "churn"),
     "184: was ('device_alarm', 'cov-dev-1', None) — no peer, no state, no kind"),
    ("BGP-3-NOTIFICATION",
     ("%BGP-3-NOTIFICATION: received from neighbor 10.0.0.200 6/4 "
     "(Administrative Reset) 0 bytes"), "err",
     ("bgp_adjacency_change", "cov-dev-1", "down"),
     "184: was ('device_alarm', 'cov-dev-1', None)"),
    ("SPANTREE-5-TOPOTRAP",
     "%SPANTREE-5-TOPOTRAP: Topology Change Trap for instance MST0", "notice",
     ("stp_topology_change", "cov-dev-1", "unknown"),
     "184: was ('stp_topology_change', 'cov-dev-1:unknown', 'unknown')"),
    ("SW_MATM-4-MACFLAP_NOTIF",
     ("%SW_MATM-4-MACFLAP_NOTIF: Host 0011.2233.4455 in vlan 200 is flapping "
     "between port GigabitEthernet0/48 and port GigabitEthernet0/49"), "warning",
     ("mac_flap", "cov-dev-1", "flapping"), "184: state was None"),
]


@pytest.mark.parametrize("tag,msg,sev,expect,delta", PRE_184,
                         ids=[f"{i}-{r[0]}" for i, r in enumerate(PRE_184)])
def test_every_pre_existing_line_still_yields_its_kind(tag, msg, sev, expect, delta):
    s = classify(tag, msg, sev)
    got = (None, None, None) if s is None else (
        s.kind, s.entity_id, s.attrs.get("state"))
    assert got == expect, (
        f"{tag}: {got} != {expect}"
        + (f"  ({delta})" if delta else "  — an UNDECLARED coverage change"))


def test_the_regression_pin_covers_every_declared_delta():
    """Exactly the five symptoms tracker 184 names carry a delta; a sixth
    appearing here means the change grew beyond its bounded context."""
    deltas = [row[0] for row in PRE_184 if row[4]]
    assert deltas == ["BGP-5-NBR_RESET", "BGP-4-MAXPFX", "BGP-3-NOTIFICATION",
                      "SPANTREE-5-TOPOTRAP", "SW_MATM-4-MACFLAP_NOTIF"]
