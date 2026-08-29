"""The ENTERPRISE OUTAGE causal chain — one definition, two harnesses.

WHY THIS MODULE EXISTS. Two harnesses need the same fault story:

  * `scripts/lab/twin/` (the network digital twin) runs it on a DECLARED
    topology, at small scale, and scores RCA accuracy against the engine's
    `corr_objects` (`twin.py score`);
  * `scripts/scale-miniladder.py` replicates it across a 2,500-device fleet
    inside a ratified throughput plan, and measures TTUR / completion.

They differ in everything EXCEPT the two things that must never diverge: the
WIRE VOCABULARY (which vendor mnemonic carries which symptom) and the PHASE
TIMELINE (what causes what, in which order). Both live here, and both
harnesses import them, so a change to the story is a change in one file and
neither harness can drift into emitting a message the other does not.

WHAT "PROMOTED" MEANS. `src/correlation/producers.py` promotes a raw syslog
line to a correlation Signal only for the shapes it recognizes. A harness that
invents a plausible-looking message for a symptom the parser cannot read
produces GROUND TRUTH THAT LIES: the scorer counts a miss the engine was never
given the evidence for. So every event type in this chain carries its measured
promotion outcome (`PROMOTED` / `NOT_PROMOTED`), pinned against the real
producer by tests in BOTH harnesses, and the harnesses write that table into
their ground truth. A `not_promoted` row is a PRODUCT BACKLOG ITEM — a symptom
real networks emit and this engine cannot see — never a licence to substitute a
message that happens to classify.

THE MESSAGES ARE VENDOR-STANDARD, not invented: Cisco IOS-XE / NX-OS shapes
(`%LINK-3-UPDOWN`, `%LINEPROTO-5-UPDOWN`, `%OSPF-5-ADJCHG`, `%BGP-5-ADJCHANGE`,
`%BGP-4-MAXPFX`, `%BGP-5-NBR_RESET`, `%BGP-3-NOTIFICATION`,
`%SPANTREE-5-TOPOTRAP`, `%SPANTREE-6-PORT_STATE`, `%SW_MATM-4-MACFLAP_NOTIF`).
Stdlib only; no imports from either harness, so neither can create a cycle.
"""
from __future__ import annotations

import typing

# ── the phase timeline ──────────────────────────────────────────────────────
#
# Offsets are SECONDS AFTER THE CAUSE (the core uplink going down), given as a
# band the harness draws from with `JITTER_FRACTION` jitter on top. The order
# below is the CAUSAL order and both harnesses enforce it monotonically: a
# jittered draw may never place a phase before the phase that caused it.
PHASE_BANDS: tuple[tuple[str, tuple[float, float]], ...] = (
    ("uplink_down", (0.0, 0.0)),            # t0: the cause itself
    ("ospf_neighbor_down", (1.0, 3.0)),     # the IGP notices the dead uplink
    ("ospf_interface_flap", (2.0, 10.0)),   # a second core port starts flapping
    ("bgp_session_flap", (5.0, 15.0)),      # the eBGP session to transit flaps
    ("route_churn", (10.0, 60.0)),          # withdraw/announce + update burst
    ("access_layer", (20.0, 90.0)),         # STP reconvergence + MAC re-homing
    ("recovery", (150.0, 300.0)),           # …unless the site is a hard outage
)
PHASE_ORDER: tuple[str, ...] = tuple(name for name, _band in PHASE_BANDS)
PHASE_BAND: dict[str, tuple[float, float]] = dict(PHASE_BANDS)

# Every drawn offset is multiplied by uniform(1-J, 1+J).
JITTER_FRACTION = 0.20

# A symptom is re-reported this many times inside the repeat window (both
# harnesses cap the spread so a repeat still lands inside the window it counts
# in; the miniladder's cap is SCENARIO_REPEAT_MAX_OFFSET_S).
REPEAT_RANGE: tuple[int, int] = (1, 6)

# The OSPF-interface flap cycles this many times (down→up per cycle).
FLAP_CYCLE_RANGE: tuple[int, int] = (2, 4)

# Route churn: events per second, and for how long.
CHURN_EPS_RANGE: tuple[float, float] = (5.0, 20.0)
# The upper end of the owner's 30–60 s band is deliberately NOT used at 2.5K:
# see `CHURN_DURATION_RANGE_SCALE`. The twin (small topology, no throughput
# budget) uses the full band.
CHURN_DURATION_RANGE: tuple[float, float] = (30.0, 60.0)
# THROUGHPUT-BOUNDED variant for the mini-ladder. The storm scenario is a
# STRUCTURAL change to a ratified nominal stream and must stay ≤ ~2 % of the
# raw fleet, or completion/TTUR stop being comparable with `t-nominal-2.5k`.
# Route churn is by far the heaviest phase — rate × duration outweighs every
# other phase of every other template COMBINED — so the 2.5K rung draws its
# duration from the lower half of the band and caps the phase at a fixed
# event budget.
#
# THE ARITHMETIC (measured, seed 20260829, 2,500 devices, 900 s, 900,000
# planned raw events). The four original templates plan 7,147 events (0.79 %).
# Fifteen sites at the FULL band plan 11,026 more, for 2.019 % — over the
# ratified bound. The cap below trims the churn phase alone (the only phase
# whose size is a free parameter rather than a physical count of devices or
# transitions) and lands the scenario at the share reported in ground truth's
# `counts.scenario_event_share_of_plan`. Both the PLANNED rate/duration and
# the EMITTED count go into each incident's timeline, so a truncated churn
# phase is visible, never silent.
CHURN_DURATION_RANGE_SCALE: tuple[float, float] = (30.0, 45.0)
CHURN_MAX_EVENTS_SCALE = 380

# Share of the site's access layer that re-converges STP / re-homes a MAC.
STP_SHARE_RANGE: tuple[float, float] = (0.20, 0.60)
MAC_SHARE_RANGE: tuple[float, float] = (0.10, 0.30)

# Share of sites that never recover inside the window (a hard outage).
NO_RECOVERY_SHARE = 0.25


# ── the wire vocabulary ─────────────────────────────────────────────────────
#
# Each builder returns the (appname, message, severity) triple both harnesses
# put on the wire. `appname` is the Cisco `%FACILITY-N-MNEMONIC` tag without
# its leading `%` (what the syslog envelope carries); the message repeats the
# full tag exactly as a real device does.

Line = tuple[str, str, str]


def link(ifname: str, state: str) -> Line:
    """%LINK-3-UPDOWN — the physical port. `state` is "down" or "up"."""
    return ("LINK-3-UPDOWN",
            f"%LINK-3-UPDOWN: Interface {ifname}, changed state to {state}",
            "err")


def lineproto(ifname: str, state: str) -> Line:
    """%LINEPROTO-5-UPDOWN — the line protocol on the same port. Emitted a
    beat after %LINK on real hardware, which is why the chain emits both."""
    return ("LINEPROTO-5-UPDOWN",
            (f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {ifname}, "
             f"changed state to {state}"),
            "notice")


def ospf_adj(peer: str, ifname: str, state: str) -> Line:
    """%OSPF-5-ADJCHG. `producers._state_of` reads "down beats up", so the DOWN
    arm may name FULL while the UP arm must contain no down-token at all
    (LOADING, never INIT)."""
    tail = ("from FULL to DOWN, Neighbor Down: Interface down or detached"
            if state == "down" else "from LOADING to FULL, Loading Done")
    return ("OSPF-5-ADJCHG",
            f"%OSPF-5-ADJCHG: Process 1, Nbr {peer} on {ifname} {tail}",
            "notice")


def bgp_adj(peer: str, state: str) -> Line:
    """%BGP-5-ADJCHANGE — the session transition."""
    word = "Down BGP Notification sent" if state == "down" else "Up"
    return ("BGP-5-ADJCHANGE",
            f"%BGP-5-ADJCHANGE: neighbor {peer} {word}",
            "notice")


def bgp_nbr_reset(peer: str) -> Line:
    """%BGP-5-NBR_RESET — the withdraw/announce churn a resetting session
    produces. NOT PROMOTED: notice severity is under the generic device-alarm
    floor and the mnemonic carries no ADJCHANGE token, so the classifier
    returns None. This is the honest representation of BGP route churn."""
    return ("BGP-5-NBR_RESET",
            (f"%BGP-5-NBR_RESET: Neighbor {peer} reset "
             f"(BGP Notification received)"),
            "notice")


def bgp_maxpfx(peer: str, prefixes: int) -> Line:
    """%BGP-4-MAXPFX — the prefix count crossing its threshold as the table
    churns. Promotes only through the GENERIC device-alarm net (warning
    severity), so the engine sees "something is wrong on this device", not
    "this BGP session is churning"."""
    return ("BGP-4-MAXPFX",
            (f"%BGP-4-MAXPFX: No. of prefix received from {peer} (afi 0) "
             f"reaches {prefixes}, max 250000"),
            "warning")


def bgp_notification(peer: str) -> Line:
    """%BGP-3-NOTIFICATION — the router-update burst's session teardown.
    Promotes as a generic device_alarm (err severity)."""
    return ("BGP-3-NOTIFICATION",
            (f"%BGP-3-NOTIFICATION: received from neighbor {peer} 6/4 "
             f"(Administrative Reset) 0 bytes"),
            "err")


def stp_tcn() -> Line:
    """%SPANTREE-5-TOPOTRAP — the topology-change notification that floods the
    whole STP domain, so EVERY switch in the site logs it. It names no
    interface, so the classifier's `_IF_RE` finds none and the signal lands on
    the synthetic entity `<host>:unknown` with state "unknown" — promoted, but
    with a DEGRADED identity (see PARSER_COVERAGE_DETAIL)."""
    return ("SPANTREE-5-TOPOTRAP",
            "%SPANTREE-5-TOPOTRAP: Topology Change Trap for instance MST0",
            "notice")


def stp_port(ifname: str, state: str) -> Line:
    """%SPANTREE-6-PORT_STATE — the port that actually transitions. This is the
    shape the classifier's STP branch is built for ("Interface X … to
    blocking/forwarding"), so it carries a real interface entity."""
    frm, to = (("forwarding", "blocking") if state == "down"
               else ("listening", "forwarding"))
    return ("SPANTREE-6-PORT_STATE",
            (f"%SPANTREE-6-PORT_STATE: Interface {ifname} instance MST0 "
             f"moving from {frm} to {to}"),
            "notice")


def mac_flap(mac: str, vlan: int | str, port_a: str, port_b: str) -> Line:
    """%SW_MATM-4-MACFLAP_NOTIF — a host MAC re-homing between two ports as the
    L2 topology reconverges."""
    return ("SW_MATM-4-MACFLAP_NOTIF",
            (f"%SW_MATM-4-MACFLAP_NOTIF: Host {mac} in vlan {vlan} is "
             f"flapping between port {port_a} and port {port_b}"),
            "warning")


def mac_address(n: int) -> str:
    """A locally-administered (02:…) MAC, unique per `n`, in Cisco dotted form.

    Unique matters: `producers.syslog_control_signal` puts the bare MAC in
    `entity_tokens` ON PURPOSE (two devices seeing one MAC flap ARE related),
    so a MAC reused across two sites would WELD those sites into one false
    correlation object. It also must not look like a dotted quad — three
    4-hex-digit groups cannot match `\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b`.
    """
    v = 0x021100000000 + (int(n) & 0xFFFFFFFF)
    return f"{v >> 32:04x}.{(v >> 16) & 0xFFFF:04x}.{v & 0xFFFF:04x}"


# ── parser coverage ─────────────────────────────────────────────────────────

PROMOTED = "promoted"
NOT_PROMOTED = "not_promoted"

# Sample arguments the EXEMPLARS are built from. Tests feed the exemplar to the
# real producer and assert the row below; a harness that emits some other shape
# for the same event type is caught by its own line-classification test.
SAMPLE_IF = "GigabitEthernet0/48"
SAMPLE_IF_B = "GigabitEthernet0/49"
SAMPLE_PEER = "10.0.0.200"
SAMPLE_VLAN = 200
SAMPLE_MAC = mac_address(1)


class ChainSignature(typing.NamedTuple):
    """One requested outage symptom and what the REAL parser does with it.

    `entity_shape` is how the classifier keys the resulting signal:
      device:interface  → `<host>:<ifname>`   (the port is the subject)
      device            → `<host>`            (the device is the subject)
      device:unknown    → `<host>:unknown`    (DEGRADED — no interface token)
      ""                → nothing is produced
    `state` is `attrs["state"]` — "" means the signal carries no state at all,
    so it can never contribute a state TRANSITION to the engine.
    `components` is non-empty for a COMPOSITE symptom: one with no mnemonic of
    its own, expressed through other rows.
    """

    event_type: str
    phase: str
    coverage: str
    kind: str
    entity_shape: str
    state: str
    exemplar: Line | None
    components: tuple[str, ...]
    note: str


def _row(event_type, phase, coverage, kind, entity_shape, state, exemplar,
         note, components=()) -> ChainSignature:
    return ChainSignature(event_type, phase, coverage, kind, entity_shape,
                          state, exemplar, tuple(components), note)


CHAIN_SIGNATURES: tuple[ChainSignature, ...] = (
    _row("link_down", "uplink_down", PROMOTED, "link_state_change",
         "device:interface", "down", link(SAMPLE_IF, "down"),
         "the cause: the core's uplink port"),
    _row("link_up", "recovery", PROMOTED, "link_state_change",
         "device:interface", "up", link(SAMPLE_IF, "up"),
         "the recovery transition on the same identity"),
    _row("lineproto_down", "uplink_down", PROMOTED, "link_state_change",
         "device:interface", "down", lineproto(SAMPLE_IF, "down"),
         "same entity as %LINK — a second, corroborating report of one fault"),
    _row("lineproto_up", "recovery", PROMOTED, "link_state_change",
         "device:interface", "up", lineproto(SAMPLE_IF, "up"), ""),
    _row("ospf_neighbor_down", "ospf_neighbor_down", PROMOTED,
         "ospf_adjacency_change", "device", "down",
         ospf_adj(SAMPLE_PEER, SAMPLE_IF, "down"),
         "peer IP becomes a shared entity_token — the corroboration handle"),
    _row("ospf_neighbor_up", "recovery", PROMOTED, "ospf_adjacency_change",
         "device", "up", ospf_adj(SAMPLE_PEER, SAMPLE_IF, "up"), ""),
    _row("ospf_interface_flap", "ospf_interface_flap", PROMOTED,
         "link_state_change+ospf_adjacency_change", "", "", None,
         "NO OSPF-interface-level mnemonic exists in the parser (or in Cisco "
         "IOS): an OSPF interface flap is observable only as the port's "
         "LINK/LINEPROTO transitions plus the adjacency loss they cause. The "
         "chain emits exactly that — it does not invent an %OSPF-*-IFSTATE.",
         ("link_down", "link_up", "lineproto_down", "lineproto_up",
          "ospf_neighbor_down", "ospf_neighbor_up")),
    _row("bgp_session_down", "bgp_session_flap", PROMOTED,
         "bgp_adjacency_change", "device", "down",
         bgp_adj(SAMPLE_PEER, "down"), ""),
    _row("bgp_session_up", "bgp_session_flap", PROMOTED,
         "bgp_adjacency_change", "device", "up", bgp_adj(SAMPLE_PEER, "up"),
         ""),
    _row("bgp_route_churn", "route_churn", NOT_PROMOTED, "", "", "",
         bgp_nbr_reset(SAMPLE_PEER),
         "BACKLOG. %BGP-5-NBR_RESET is the standard vendor line for a session "
         "resetting under withdraw/announce churn, and the classifier drops "
         "it: notice severity is below the generic device-alarm floor and the "
         "mnemonic carries no ADJCHANGE/ADJCHG token. Per-prefix churn has no "
         "syslog representation at all (it is BMP/BGP-UPDATE data), so route "
         "churn is INVISIBLE to correlation today."),
    _row("bgp_router_update_burst", "route_churn", NOT_PROMOTED, "", "", "",
         bgp_nbr_reset(SAMPLE_PEER),
         "BACKLOG. Same signature, emitted densely — the update burst that "
         "follows a session reset. Also invisible."),
    _row("bgp_maxprefix", "route_churn", PROMOTED, "device_alarm", "device",
         "", bgp_maxpfx(SAMPLE_PEER, 12000),
         "PARTIAL. Promotes only through the GENERIC device-alarm net "
         "(warning severity), so the engine learns 'this device raised an "
         "alarm', not 'this BGP session is churning': no peer token, no "
         "state, no bgp_* kind."),
    _row("bgp_notification", "route_churn", PROMOTED, "device_alarm",
         "device", "", bgp_notification(SAMPLE_PEER),
         "PARTIAL. Same generic net, via err severity."),
    _row("stp_topology_change", "access_layer", PROMOTED,
         "stp_topology_change", "device:unknown", "unknown", stp_tcn(),
         "DEGRADED IDENTITY. %SPANTREE-5-TOPOTRAP names no interface, so the "
         "signal keys on `<host>:unknown` and carries state 'unknown' — every "
         "TCN a device ever logs collapses onto one synthetic identity."),
    _row("stp_port_block", "access_layer", PROMOTED, "stp_topology_change",
         "device:interface", "down", stp_port(SAMPLE_IF_B, "down"),
         "the port that actually transitioned — a real interface identity"),
    _row("stp_port_forward", "recovery", PROMOTED, "stp_topology_change",
         "device:interface", "up", stp_port(SAMPLE_IF_B, "up"), ""),
    _row("mac_move", "access_layer", PROMOTED, "mac_flap", "device", "",
         mac_flap(SAMPLE_MAC, SAMPLE_VLAN, SAMPLE_IF, SAMPLE_IF_B),
         "promoted, but the signal carries no state — a MAC move can never "
         "contribute a state transition or a recovery"),
)

CHAIN_BY_TYPE: dict[str, ChainSignature] = {
    s.event_type: s for s in CHAIN_SIGNATURES}


def parser_coverage() -> dict[str, str]:
    """{event_type: "promoted"|"not_promoted"} — what a run's scorer must read
    before counting a missed symptom against the engine."""
    return {s.event_type: s.coverage for s in CHAIN_SIGNATURES}


def parser_coverage_detail() -> dict[str, dict]:
    """The same table with the evidence: the exemplar line, the kind and the
    entity shape the REAL producer yields, and why."""
    out: dict[str, dict] = {}
    for s in CHAIN_SIGNATURES:
        row: dict = {
            "phase": s.phase,
            "coverage": s.coverage,
            "signal_kind": s.kind,
            "entity_shape": s.entity_shape,
            "state": s.state,
            "note": s.note,
        }
        if s.exemplar is not None:
            row["appname"] = s.exemplar[0]
            row["message"] = s.exemplar[1]
            row["severity"] = s.exemplar[2]
        if s.components:
            row["components"] = list(s.components)
        out[s.event_type] = row
    return out


def not_promoted_types() -> tuple[str, ...]:
    """The symptoms this engine CANNOT see. A product backlog item each."""
    return tuple(s.event_type for s in CHAIN_SIGNATURES
                 if s.coverage == NOT_PROMOTED)


def entity_of(event_type: str, device: str, ifname: str = "") -> str:
    """The entity_id the classifier will derive for this event on `device`.

    Kept here so neither harness re-implements the parser to describe its own
    ground truth (the failure mode: ground truth that names an identity the
    engine never creates).
    """
    shape = CHAIN_BY_TYPE[event_type].entity_shape
    if shape == "device:interface":
        return f"{device}:{ifname}"
    if shape == "device:unknown":
        return f"{device}:unknown"
    if shape == "device":
        return device
    return ""


def signal_kind(event_type: str) -> str:
    """The correlation `kind`, or "" when the line never promotes."""
    s = CHAIN_BY_TYPE[event_type]
    return "" if s.coverage == NOT_PROMOTED else s.kind


def phase_index(phase: str) -> int:
    return PHASE_ORDER.index(phase)
