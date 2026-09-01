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

import hashlib
import json
import math
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


# ── the storm SHAPE ─────────────────────────────────────────────────────────
#
# WHY A SHAPE OBJECT EXISTS (P3, 2026-08-29). `docs/scale/P3_AGGREGATION_
# OPPORTUNITY_2026-08-29.md` measured the ratified 2.5K workload and found it
# has almost no aggregation opportunity: 900,001 raw → 44,280 signals, 0 %
# collapse under a 60 s event-time bucket, 0 state transitions, 0 recoveries.
# `t-storm-2.5k` fixed the DYNAMICS but not the MASS — its scenario is 1.78 %
# of the raw fleet, so the other 98.2 % is still the repeat-free production
# background and an Aggregation Plane can only ever touch ~2 % of what the
# engine sees.
#
# To A/B the Aggregation Plane (owner memo §16–§19) the harness needs a stream
# whose REPETITION AND DYNAMICS ARE A DECLARED PARAMETER, not a by-product of
# how five templates happened to be sized. `StormShape` is that parameter set.
# Every knob is CONTENT-DERIVED — a number in this file, drawn against a
# SHA-256-seeded RNG — and never read from the wall clock, the process, the
# environment or the achieved send rate, so the same (shape, seed, device list)
# plans a byte-identical stream on any box (memo §21).
#
# THE DEFAULT IS TODAY. `DEFAULT_SHAPE` reproduces the ratified `t-storm-2.5k`
# plan exactly — every accessor below returns the module constant it replaces
# when the shape is the default, so the RNG CALL SEQUENCE is unchanged and the
# scenario digest is unchanged. `tests/test_storm_scenario_profile.py` pins
# that digest; a knob whose default drifts turns the pin red rather than
# silently re-basing every recorded 2.5K number.

# The measured share of the ratified 900,000-event fleet plan that today's
# `t-storm-2.5k` scenario carries (16,060 events, seed 20260829, 2,500
# devices, 900 s). `StormShape.for_share` scales against this.
BASE_STORM_SHARE = 0.017844

# The mean of `REPEAT_RANGE` — the scenario-wide repeat mean the default shape
# reports and every per-template repeat band scales proportionally against.
BASE_REPEAT_FACTOR = (REPEAT_RANGE[0] + REPEAT_RANGE[1]) / 2.0   # 3.5

# The centre of `CHURN_EPS_RANGE`, in events/s per site. The band is
# reconstructed as (0.4 d, 1.6 d), which at d = 12.5 is exactly (5.0, 20.0).
BASE_CHURN_DENSITY = (CHURN_EPS_RANGE[0] + CHURN_EPS_RANGE[1]) / 2.0   # 12.5
_CHURN_BAND_LO = CHURN_EPS_RANGE[0] / BASE_CHURN_DENSITY               # 0.4
_CHURN_BAND_HI = CHURN_EPS_RANGE[1] / BASE_CHURN_DENSITY               # 1.6

# `upstream_link_failure` puts 2 contradictory healthy observers on a 24-device
# affected set; that ratio is the default.
BASE_CONTRADICTION_RATIO = 2.0 / 24.0

# The MASS MODEL behind `for_share`, measured on the default plan (16,060
# events, seed 20260829): the share of scenario events each lever owns.
#   structural  onset/expansion/flap/flap_up/recovery/contradiction   29.7 %
#   repeat      the in-window re-reports `repeat_factor` governs      26.5 %
#   reassert    the periodic re-assertion of an unfixed fault          5.8 %
#   churn       the route-churn phase `churn_density` governs         37.9 %
# Structural mass scales with the incident count alone; the other three scale
# with the incident count TIMES their own knob. `for_share` inverts that.
MASS_STRUCTURAL = 0.297
MASS_AMPLIFIABLE = 1.0 - MASS_STRUCTURAL


# A shape may claim at most this many passes over the fleet, and at most this
# share of it. Both exist so a mis-specified target fails loudly at plan time
# instead of leaving the background with no devices to speak from.
INCIDENT_DENSITY_MAX = 6.0
DEVICE_BUDGET_MAX = 0.92

def _clampi(v: float, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(v)))


class StormShape(typing.NamedTuple):
    """The declared repetition/dynamics of a storm workload.

    Fields are the owner's §16–§19 dimensions. Auxiliary fields (the last
    block) are the mechanical knobs the ladder needs to REACH a declared
    `storm_share_of_raw` without making any single incident bursty; they are
    derived by `for_share` and are part of the shape's content digest like
    every other knob.

    NOTHING here may be read from the clock, the environment or the run: a
    shape is a constant of the profile (memo §21 deterministic replay).
    """

    # ── what the memo names ────────────────────────────────────────────────
    name: str = "t-storm"
    # Target fraction of the ratified raw fleet plan carried by scenario
    # events. The plan's ACHIEVED share is measured and written into ground
    # truth beside it; the ladder tests hold achieved to ±10 % of target.
    storm_share_of_raw: float = BASE_STORM_SHARE
    # Mean re-reports of one symptom identity inside `repeat_window_s`.
    repeat_factor: float = BASE_REPEAT_FACTOR
    # How the per-symptom repeat count is drawn: "bounded" = uniform over a
    # band scaled to the mean (today's behaviour); "geometric" = a memoryless
    # draw with the same mean, truncated at `repeat_cap`.
    repeat_distribution: str = "bounded"
    repeat_cap: int = 512
    repeat_window_s: float = 60.0
    # (lo, hi) bound on how many DEVICES independently observe one cause.
    # Today's plan measures min 1 / max 25 — a template asking for more is
    # clamped, one asking for fewer is left alone.
    vantages_per_cause: tuple = (1, 25)
    # Share of incidents that recover inside the window (the complement is a
    # hard outage). Today: 1 - NO_RECOVERY_SHARE.
    recovery_ratio: float = 1.0 - NO_RECOVERY_SHARE
    # (lo, hi) down→up cycles of the flapping core port.
    flap_cycles: tuple = FLAP_CYCLE_RANGE
    # BGP route-churn events per second per site (the band is (0.4 d, 1.6 d)).
    churn_density: float = BASE_CHURN_DENSITY
    # (lo, hi) seconds the churn phase runs for.
    churn_duration_s: tuple = CHURN_DURATION_RANGE_SCALE
    # Hard cap on churn events per site — the throughput budget.
    churn_max_events: int = CHURN_MAX_EVENTS_SCALE
    # Share of an incident's affected devices that emit a contradictory
    # healthy observation while the fault is still open.
    contradiction_ratio: float = BASE_CONTRADICTION_RATIO
    # Shares of the affected set that arrive per blast-radius wave.
    blast_radius_waves: tuple = (0.5, 0.3, 0.2)

    # ── auxiliary: how the ladder REACHES the declared share ───────────────
    # Incident count multiplier. Values > 1 make incidents OVERLAP on the
    # device fleet (round-robin allocation rounds), which is how a large storm
    # share is reached without making any one site bursty.
    incident_density: float = 1.0
    # Multiplier on the re-assertion FREQUENCY of an unfixed fault (the period
    # is divided by it).
    reassert_density: float = 1.0
    # Share of the fleet incidents may claim; the rest is the noise pool.
    device_budget: float = 0.65
    # Multiplier widening every template's onset window toward the full run
    # window, so a bigger storm spreads rather than piles up.
    onset_span: float = 1.0

    # -- derived accessors (each returns the module constant at default) ----
    def repeat_scale(self) -> float:
        return float(self.repeat_factor) / BASE_REPEAT_FACTOR

    def repeats_range(self, base: tuple) -> tuple:
        """`base` scaled to this shape's repeat mean. At the default the scale
        is exactly 1.0, so the band — and the `rng.randint` call made from it —
        is byte-identical to today's."""
        s = self.repeat_scale()
        if s == 1.0:
            return (int(base[0]), int(base[1]))
        lo = max(0, round(float(base[0]) * s))
        hi = max(lo, round(float(base[1]) * s))
        return (lo, min(hi, int(self.repeat_cap)))

    def draw_repeats(self, rng, base: tuple) -> int:
        """How many EXTRA re-reports this symptom gets. One RNG draw either
        way, so a shape change never re-phases the rest of the stream."""
        lo, hi = self.repeats_range(base)
        if self.repeat_distribution == "geometric":
            # Memoryless with the same mean as the bounded band: a few
            # identities chatter far harder than the mean, which is what a
            # real repetition storm looks like. Inverse-CDF so it is ONE draw.
            # Shifted-geometric parameterization: on support {0, 1, ...} a
            # geometric with success probability p has E[N] = (1-p)/p, so
            # p = 1/(mean+1) — i.e. P(N >= k) = (mean/(mean+1))**k — gives
            # E[N] = mean exactly. (The naive p = 1/mean reads mean-1: ~29 %
            # under-injection at the configured 3.5.)
            mean = max(1.0, (lo + hi) / 2.0)
            u = rng.random()
            n = math.floor(math.log(max(u, 1e-12)) /
                           math.log(mean / (mean + 1.0)))
            return _clampi(n, 0, int(self.repeat_cap))
        if self.repeat_distribution != "bounded":   # 16.1: never guess
            raise ValueError(
                f"StormShape {self.name!r}: repeat_distribution "
                f"{self.repeat_distribution!r} is neither 'bounded' nor "
                f"'geometric'")
        return rng.randint(lo, hi)

    def churn_eps_range(self) -> tuple:
        d = float(self.churn_density)
        return (round(_CHURN_BAND_LO * d, 6), round(_CHURN_BAND_HI * d, 6))

    def churn_duration_range(self) -> tuple:
        return (float(self.churn_duration_s[0]), float(self.churn_duration_s[1]))

    def no_recovery_share(self) -> float:
        return max(0.0, min(1.0, 1.0 - float(self.recovery_ratio)))

    def flap_cycle_range(self) -> tuple:
        return (int(self.flap_cycles[0]), int(self.flap_cycles[1]))

    def contradiction_devices(self, n_affected: int) -> int:
        return max(0, round(float(self.contradiction_ratio) *
                            max(0, int(n_affected))))

    def blast_waves(self) -> tuple:
        return tuple(float(x) for x in self.blast_radius_waves)

    def vantage_devices(self, base: int) -> int:
        lo, hi = int(self.vantages_per_cause[0]), int(self.vantages_per_cause[1])
        return max(lo, min(hi, int(base)))

    def reassert_every_s(self, base: float) -> float:
        b = float(base or 0.0)
        if b <= 0.0:
            return 0.0
        return b / max(1e-9, float(self.reassert_density))

    def instances_per_1k(self, base: float) -> float:
        return float(base) * float(self.incident_density)

    def onset_window(self, base: tuple, window_s: float) -> tuple:
        """`base` widened by `onset_span` toward the whole window. At the
        default span the band is returned untouched."""
        lo, hi = float(base[0]), float(base[1])
        if self.onset_span == 1.0:
            return (lo, hi)
        hi = min(float(window_s) - 10.0, lo + (hi - lo) * float(self.onset_span))
        return (lo, max(lo, hi))

    # -- identity ----------------------------------------------------------
    def as_dict(self) -> dict:
        out = self._asdict()
        for k, v in list(out.items()):
            if isinstance(v, tuple):
                out[k] = list(v)
        return out

    def digest(self) -> str:
        """SHA-256 over the canonical knob set. Two shapes with this digest
        plan the same stream from the same seed; a knob nobody meant to change
        moves it."""
        blob = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    # -- the ladder law ----------------------------------------------------
    @classmethod
    def for_share(cls, target: float, name: str = "",
                  repeat_distribution: str = "bounded") -> StormShape:
        """The shape that carries `target` of the raw fleet plan.

        THE LAW (measured, not guessed — see the MASS_* constants). Amplifying
        the storm `A = target / BASE_STORM_SHARE` times is split so that no
        single incident becomes bursty:

          * the INCIDENT COUNT grows first, as `A ** 0.62`, capped at
            `INCIDENT_DENSITY_MAX`. More concurrent sites/faults is the shape
            of a real estate-wide event, and it spreads mass over the whole
            window for free. Past one pass of the fleet the incidents OVERLAP
            on devices (allocation rounds) — a device carrying two faults in
            fifteen minutes is ordinary, and the device budget grows with it so
            the noise pool still exists.
          * whatever amplification the incident count did not absorb goes to
            the three per-incident mass levers together — repeats,
            re-assertion and route churn — solved from the mass model:
                total/base = n * (MASS_STRUCTURAL + MASS_AMPLIFIABLE * m)
          * route churn takes its share as `sqrt(m)` MORE EVENTS PER SECOND and
            `sqrt(m)` LONGER, never as a rate spike: a session that resets for
            three minutes is what a real reconvergence storm looks like, and a
            phase that stays inside its 10 s chunk quota is what the harness
            requires (the per-chunk guard checks it).
          * onsets spread across the whole window in step with `m`.

        Everything here is arithmetic on constants in this file. `for_share` is
        a pure function: the same target always yields the same shape digest.
        """
        base = cls(name=name or "t-storm")
        tgt = float(target)
        if not (0.0 < tgt < 1.0):
            raise ValueError(f"storm_share_of_raw must be in (0, 1), got {tgt!r}")
        a = tgt / BASE_STORM_SHARE
        if a <= 1.0:
            return base._replace(name=name or "t-storm",
                                 storm_share_of_raw=tgt,
                                 repeat_distribution=repeat_distribution)
        n = min(INCIDENT_DENSITY_MAX, a ** 0.62)
        m = max(1.0, (a / n - MASS_STRUCTURAL) / MASS_AMPLIFIABLE)
        rt = math.sqrt(m)
        # The device budget grows with the incident count but always leaves a
        # noise pool: the background fills every chunk's remaining quota from
        # devices no incident touches, and that disjointness is what makes
        # "a background line never carries a cause entity" structural.
        budget = min(DEVICE_BUDGET_MAX, base.device_budget * min(n, 1.45))
        return cls(
            name=name or f"t-storm-{round(tgt * 100)}",
            storm_share_of_raw=tgt,
            repeat_factor=round(BASE_REPEAT_FACTOR * m, 4),
            repeat_distribution=repeat_distribution,
            repeat_cap=base.repeat_cap,
            repeat_window_s=base.repeat_window_s,
            vantages_per_cause=base.vantages_per_cause,
            recovery_ratio=base.recovery_ratio,
            flap_cycles=base.flap_cycles,
            churn_density=round(BASE_CHURN_DENSITY * rt, 4),
            churn_duration_s=(round(CHURN_DURATION_RANGE_SCALE[0] * rt, 2),
                              round(CHURN_DURATION_RANGE_SCALE[1] * rt, 2)),
            churn_max_events=round(CHURN_MAX_EVENTS_SCALE * m),
            contradiction_ratio=base.contradiction_ratio,
            blast_radius_waves=base.blast_radius_waves,
            incident_density=round(n, 4),
            reassert_density=round(m, 4),
            device_budget=round(budget, 4),
            onset_span=round(min(1.75, 1.0 + 0.10 * m), 4),
        )


DEFAULT_SHAPE = StormShape()


# ── the step-0 aggregation measurement, as a pure function ──────────────────
#
# PORTED FROM the P3 step-0 script that produced `docs/scale/P3_AGGREGATION_
# OPPORTUNITY_2026-08-29.md` (offline re-instantiation of the ratified stream,
# parsed by the real `producers.syslog_control_signal`; source A, which agreed
# with the live Kafka window to ±1 event). What is ported is the MEASUREMENT,
# not the generator: the caller supplies observations, so the harness can run
# it at PLAN time — offline, in seconds, with no stack and no parser — because
# every scenario line already carries the kind/entity/state the REAL parser
# derives (`entity_of` / `signal_kind` above).
#
# The metric set is owner memo §5 (event/aggregation metrics) and §6 (causal
# amplification): unique semantic events under the candidate keys K1..K5,
# repeat factor per kind, the causal-significance split (first occurrence /
# state transition / recovery / repeat), the per-second rates, vantages per
# identity, and the projected raw→engine ratio under ideal K3 aggregation.
#
# THE KEYS (memo §16's candidate, decomposed so the measurement can choose):
#   K1 = (tenant, entity_id, kind)
#   K2 = K1 + severity
#   K3 = K2 + 60 s event-time bucket      ← the bucketed key P3 would ship
#   K4 = K2 + 300 s event-time bucket
#   K5 = K2 + parsed state
AGG_BUCKET_S_K3 = 60
AGG_BUCKET_S_K4 = 300

# States that mean "the thing came back". Kept here, beside the vocabulary
# that produces them, so the harness and any scorer classify a recovery the
# same way.
RECOVERY_STATES: frozenset = frozenset(
    {"up", "forwarding", "learning", "full"})


class Observation(typing.NamedTuple):
    """One planned or observed line, in the terms the CLASSIFIER would give it.

    `promoted` False means the real parser returns None for this line: it is
    counted as raw mass and never as an identity, a transition or a recovery
    (the failure mode: ground truth reporting dynamics the engine cannot see).
    """

    t: float          # event time, seconds from the window start
    device: str       # the emitting device — the observer/vantage
    entity_id: str    # the identity the classifier keys on ("" if unpromoted)
    kind: str         # the correlation kind ("" if unpromoted)
    severity: str     # the wire severity
    state: str        # attrs["state"], "" when the signal carries none
    promoted: bool = True


def _quantile(sorted_vals: list, q: float) -> float:
    if not sorted_vals:
        return 0.0
    i = min(len(sorted_vals) - 1, max(0, round(q * (len(sorted_vals) - 1))))
    return float(sorted_vals[i])


def measure_stream(observations, window_s: float, raw_events: int = 0,
                   tenant: str = "") -> dict:
    """Owner memo §5/§6 metrics over a stream of `Observation`s.

    PURE: no clock, no RNG, no IO. The same observations always yield the same
    dict, so the numbers can ride into ground truth and be compared run to run.

    `raw_events` is the TOTAL raw line count the observations were drawn from
    (the ratified fleet plan, not just the promoted subset); it is what makes
    `promotion_pct` and the raw→engine projection meaningful. Zero means "the
    observations ARE the whole stream".
    """
    window = max(float(window_s), 1e-9)
    obs = list(observations)
    n_raw = int(raw_events) if raw_events else len(obs)

    k1: set = set()
    k2: set = set()
    k3: set = set()
    k4: set = set()
    k5: set = set()
    per_kind_raw: dict = {}
    per_kind_k3: dict = {}
    per_kind_class: dict = {}
    per_id_count: dict = {}
    vantages_per_id: dict = {}
    vantages_per_kind_entity: dict = {}
    last_state: dict = {}
    seen: set = set()
    classes = {"first": 0, "transition": 0, "recovery": 0, "repeat": 0}
    n_sig = 0
    unpromoted = 0

    # A TOTAL order, so the measurement is a pure function of the SET of
    # observations and not of the order they were handed over in: two events
    # with the same event time on the same identity would otherwise be
    # classified first/repeat differently depending on the caller's iteration
    # order, and the plan-time number would stop matching a scorer's.
    for o in sorted(obs, key=lambda x: (x.t, x.device, x.kind, x.entity_id,
                                        x.state, x.severity)):
        if not o.promoted or not o.kind:
            unpromoted += 1
            continue
        n_sig += 1
        a = (tenant, o.entity_id, o.kind)
        b = a + (o.severity,)
        bucket3 = b + (int(o.t // AGG_BUCKET_S_K3),)
        k1.add(a)
        k2.add(b)
        k3.add(bucket3)
        k4.add(b + (int(o.t // AGG_BUCKET_S_K4),))
        k5.add(b + (o.state,))
        per_kind_raw[o.kind] = per_kind_raw.get(o.kind, 0) + 1
        per_kind_k3.setdefault(o.kind, set()).add(bucket3)
        per_id_count[a] = per_id_count.get(a, 0) + 1
        vantages_per_id.setdefault(a, set()).add(o.device)
        vantages_per_kind_entity.setdefault(o.entity_id, set()).add(o.device)
        cls = per_kind_class.setdefault(
            o.kind, {"first": 0, "transition": 0, "recovery": 0, "repeat": 0})
        if a not in seen:
            seen.add(a)
            what = "first"
        else:
            prev = last_state.get(a)
            if prev is not None and o.state != prev:
                what = "recovery" if o.state in RECOVERY_STATES else "transition"
            else:
                what = "repeat"
        classes[what] += 1
        cls[what] += 1
        last_state[a] = o.state

    counts = sorted(per_id_count.values())
    vcounts = sorted(len(v) for v in vantages_per_id.values())
    n_k3 = len(k3)
    # IDEAL K3 aggregation: every repeat inside a 60 s bucket on one identity
    # collapses to a single delta signal — an UPPER BOUND on what the
    # Aggregation Plane can remove, never a promise. On top of it the plane
    # MUST still forward every state transition and every recovery
    # synchronously (memo §17: do not defer causally-significant events), so
    # those are added back; the result can never exceed today's signal count.
    sig_to_engine = min(n_sig, n_k3 + classes["transition"]
                        + classes["recovery"])

    return {
        "raw_events": n_raw,
        "signals": n_sig,
        "unpromoted_events": unpromoted,
        "promotion_pct": round(100.0 * n_sig / max(1, n_raw), 4),
        "window_s": round(window, 3),
        "unique": {"K1": len(k1), "K2": len(k2), "K3": n_k3, "K4": len(k4),
                   "K5": len(k5)},
        "reduction_pct": {
            "K1": round(100.0 * (1.0 - len(k1) / max(1, n_sig)), 3),
            "K2": round(100.0 * (1.0 - len(k2) / max(1, n_sig)), 3),
            "K3": round(100.0 * (1.0 - n_k3 / max(1, n_sig)), 3),
            "K4": round(100.0 * (1.0 - len(k4) / max(1, n_sig)), 3),
            "K5": round(100.0 * (1.0 - len(k5) / max(1, n_sig)), 3),
        },
        "classes": dict(classes),
        "class_share_pct": {
            k: round(100.0 * v / max(1, n_sig), 3) for k, v in classes.items()},
        "per_kind": {
            k: {"raw": per_kind_raw[k],
                "k3": len(per_kind_k3[k]),
                "repeat_factor": round(
                    per_kind_raw[k] / max(1, len(per_kind_k3[k])), 3),
                **per_kind_class[k]}
            for k in sorted(per_kind_raw)},
        "repeats_per_identity": {
            "identities": len(counts),
            "mean": round(sum(counts) / max(1, len(counts)), 3),
            "p50": _quantile(counts, 0.50), "p95": _quantile(counts, 0.95),
            "p99": _quantile(counts, 0.99),
            "max": float(counts[-1]) if counts else 0.0,
        },
        "vantages_per_identity": {
            "mean": round(sum(vcounts) / max(1, len(vcounts)), 3),
            "p95": _quantile(vcounts, 0.95),
            "max": float(vcounts[-1]) if vcounts else 0.0,
            "multi_vantage_identities": sum(1 for v in vcounts if v >= 2),
            "max_vantages_on_one_entity": max(
                (len(v) for v in vantages_per_kind_entity.values()), default=0),
        },
        "rates": {
            "raw_eps": round(n_raw / window, 3),
            "signal_eps": round(n_sig / window, 3),
            "unique_semantic_eps_K3": round(n_k3 / window, 3),
            "duplicates_eps": round(classes["repeat"] / window, 3),
            "state_changing_eps": round(
                (classes["first"] + classes["transition"]
                 + classes["recovery"]) / window, 3),
            "transitions_eps": round(classes["transition"] / window, 3),
            "recoveries_eps": round(classes["recovery"] / window, 3),
        },
        "projection": {
            # What the engine sees today, and what it would see if the
            # Aggregation Plane collapsed repeats on the K3 key while still
            # forwarding every transition and recovery synchronously.
            "signals_today": n_sig,
            "signals_with_K3_aggregation": sig_to_engine,
            "signals_removed": n_sig - sig_to_engine,
            "reduction_pct": round(
                100.0 * (n_sig - sig_to_engine) / max(1, n_sig), 3),
            "raw_to_engine_ratio_today": round(n_raw / max(1, n_sig), 3),
            "raw_to_engine_ratio_aggregated": round(
                n_raw / max(1, sig_to_engine), 3),
            "ideal_k3_identities": n_k3,
        },
    }


# The knobs a DECLARED TOPOLOGY can express. The rest of `StormShape` is about
# how a 2,500-device fleet is ALLOCATED to incidents (`storm_share_of_raw`,
# `incident_density`, `device_budget`, `onset_span`, `blast_radius_waves`,
# `vantages_per_cause`); the twin's stories name their own devices and blast
# radius, so those knobs have nothing to act on there and declaring one is a
# hard error rather than a silent no-op.
TOPOLOGY_SHAPE_KNOBS: frozenset = frozenset({
    "name", "repeat_factor", "repeat_distribution", "repeat_cap",
    "repeat_window_s", "recovery_ratio", "flap_cycles", "churn_density",
    "churn_duration_s", "churn_max_events", "contradiction_ratio",
})


def shape_from_params(params: dict, allowed: frozenset | None = None,
                      where: str = "shape") -> StormShape:
    """Build a `StormShape` from a scenario file's declared knobs.

    ZERO TRUST on the declaration (§3): an unknown knob, a wrong type or an
    out-of-range value is a hard error, never a silently ignored key — a story
    that thought it was declaring a repetition storm and got the default back
    would produce ground truth that lies about its own workload.
    """
    if not isinstance(params, dict):
        raise TypeError(f"{where} must be a mapping, got "
                        f"{type(params).__name__}")
    permitted = allowed if allowed is not None else frozenset(
        StormShape._fields)
    unknown = sorted(set(params) - permitted)
    if unknown:
        raise ValueError(f"{where}: unknown knob(s) {unknown} — allowed: "
                         f"{sorted(permitted)}")
    kw: dict = {}
    for key, value in params.items():
        default = getattr(DEFAULT_SHAPE, key)
        if isinstance(default, tuple):
            if not isinstance(value, (list, tuple)) or len(value) != len(default):
                raise TypeError(
                    f"{where}.{key} must be a {len(default)}-item list, got "
                    f"{value!r}")
            kw[key] = tuple(value)
            continue
        if isinstance(default, str):
            if not isinstance(value, str):
                raise TypeError(f"{where}.{key} must be a string, got "
                                f"{value!r}")
            kw[key] = value
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"{where}.{key} must be a number, got {value!r}")
        kw[key] = type(default)(value)
    shape = DEFAULT_SHAPE._replace(**kw)
    if shape.repeat_distribution not in ("bounded", "geometric"):
        raise ValueError(
            f"{where}.repeat_distribution must be 'bounded' or 'geometric', "
            f"got {shape.repeat_distribution!r}")
    for key, lo, hi in (("repeat_factor", 0.0, 4096.0),
                        ("recovery_ratio", 0.0, 1.0),
                        ("contradiction_ratio", 0.0, 1.0),
                        ("churn_density", 0.0, 100000.0),
                        ("repeat_window_s", 0.1, 86400.0),
                        ("storm_share_of_raw", 0.0, 1.0),
                        ("device_budget", 0.0, 1.0),
                        ("incident_density", 0.0, INCIDENT_DENSITY_MAX)):
        v = float(getattr(shape, key))
        if not lo <= v <= hi:
            raise ValueError(f"{where}.{key} must be in [{lo}, {hi}], got {v}")
    if int(shape.flap_cycles[0]) > int(shape.flap_cycles[1]):
        raise ValueError(f"{where}.flap_cycles is inverted: {shape.flap_cycles}")
    if float(shape.churn_duration_s[0]) > float(shape.churn_duration_s[1]):
        raise ValueError(
            f"{where}.churn_duration_s is inverted: {shape.churn_duration_s}")
    return shape
