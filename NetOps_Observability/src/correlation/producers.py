"""Signal producers — bus events → canonical Signals (#67 build ⑦).

Pure event→Signal construction for the two evidence lanes the demo build adds
to the spine:

  * probe events (netops.probes, POSTed by the Go STAMP sender / synthetics
    runner via Vector) → active_probe signals with vantage-agent observer
    provenance: discrete probe_loss observations + CUSUM episodes on RTT.
  * syslog control-plane events (BGP/OSPF adjacency changes, link state
    changes) → control_plane signals with device observer provenance.

Both lanes carry event time from the source record (probe sender clock /
RFC5424 timestamp), not ingest time — clock_quality stays "unknown" until the
rp.* wiring threads calibrated source clocks, so the onset budget is widened
honestly rather than assumed away.

Everything here is deterministic given (event, detector state): no wall-clock
reads, no IO. main.py owns tenancy resolution, persistence and buffering.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from episodes import EpisodeDetector, EpisodeEvent
from regex_screen import pattern_screen
from signals import (
    MAX_ID_CHARS,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
    observer_of,
)
from timenorm import parse_any_timestamp

log = logging.getLogger("correlation")

# Loss at/above this (percent) is a discrete probe_loss signal each cycle.
PROBE_LOSS_PCT = 5.0


def severity_for(peak_z: float) -> Severity:
    if peak_z >= 8:
        return Severity.CRIT
    if peak_z >= 5:
        return Severity.HIGH
    return Severity.WARN


# ── generic-alarm ingestion (#80 §4 — the keystone safety net) ────────────────
#
# Any device-generated alarm at severity ≥ the floor that NO specific classifier
# recognized still becomes a canonical `device_alarm` signal (no per-mnemonic
# branch), so a fault with no signature is grounded evidence, never a blind spot.
# Below the floor stays a searchable log, never an RCA signal (anti-firehose).
# kind `device_alarm` matches no signature → it only enriches clusters / the
# undetermined-with-evidence outcome — exactly the long-tail coverage the fault
# matrix (docs/design/fault-coverage-and-signature-matrix.md) relies on.

# CONTENT DISCRIMINATOR (tracker 198) — why the generic-alarm ids carry one.
#
# `signal_id = uuid5(NS, "{source}|{native_id}|{ts_ms}")`, so the native_id IS the
# identity. Every CLASSIFIED producer below builds one out of the fields its
# classifier extracted (peer, interface, state, mac, vlan, group, role) — the
# semantic content of the event — so two lines that collide there are, in the
# classifier's own vocabulary, the same event at the same millisecond.
#
# The two GENERIC device_alarm nets are the exception: they fire precisely when
# nothing was recognized, so their id held only host + facility + mnemonic (or
# device + trap OID). Two DIFFERENT lines from one device sharing those in the
# same millisecond therefore produced the SAME signal_id, and the batcher/window
# dedup then silently discarded one genuinely distinct piece of evidence
# (docs/scale/TRACKER_198_DUPLICATE_SIGNAL_RCA_2026-09-02.md). Folding a short
# hash of the event's own content into the id fixes that WITHOUT weakening
# idempotency: a true Kafka redelivery carries byte-identical content, so it
# still hashes to the same tag and still dedups.
#
# AUDIT OF EVERY native_id BUILDER IN THIS MODULE (tracker 198). The question
# asked of each: can two DISTINCT events legitimately share this id inside one
# millisecond?
#
#   episode_signal      tenant|entity|metric|phase|onset_ms — NO. An episode is
#                       one open interval per (tenant, entity, metric) in the
#                       detector; onset and clear differ in `phase`. The id is
#                       the episode's natural key, not a summary of text.
#   probe_signals       prober|host|kind|loss|ts_ms — NO. One measurement per
#                       (prober, target, kind) per probe cycle; a second in the
#                       same millisecond is a duplicate of the same measurement,
#                       which is exactly what this id should collapse.
#   syslog_control_*    host|<kind>|<peer|ifname|mac|vlan|group|role>|state|ts_ms
#                       — NO for a classified line: the extracted fields ARE the
#                       event's content, so a collision means the classifier saw
#                       the same event twice. Residual: when extraction yields
#                       '?'/'' (an unparsed peer or interface) two distinct lines
#                       can still collide. That residual is deliberately left
#                       alone — narrowing it means changing the identity of every
#                       classified control-plane signal, far past this fix — and
#                       it is no longer INVISIBLE: `CHBatcher.add` now counts
#                       every in-batch identity collapse as
#                       corr_signal_batch{event="rows_identity_collapsed"}.
#   trap_control_*      device|trap_link|iface|state|ts_ms and the bgp/restart
#                       twins — NO, same reasoning as the classified syslog
#                       branches (the varbind-extracted entity + state is the
#                       content).
#   port_event_signal   host|portevt|kind|port|ts_ms — NO. `kind` is the matched
#                       rule (the classification) and `port` its subject; two
#                       lines matching the same rule on the same port in one
#                       millisecond are the same optics event.
#   clock_skew_signal   host|clock_skew|ts_ms — NO. One per-device meta-finding
#                       per event; a second in the same millisecond is the same
#                       finding about the same clock.
#   device_alarm (x2)   FIXED here — see above.
_CONTENT_TAG_CHARS = 8


def _content_tag(text: str) -> str:
    """Short, stable content discriminator for an identity string.

    Deterministic and process-independent (a plain SHA-256 prefix, never
    `hash()`, which is salted per process) — replay must re-derive the same
    signal_id in a different process, years later. Not a security primitive:
    it separates distinct events, it does not authenticate them. Encoding is
    surrogate-tolerant because the text arrives from `json.loads` of an
    untrusted device string and may carry lone surrogates (§3 zero trust).
    """
    return hashlib.sha256(
        text.encode("utf-8", "surrogatepass"),
    ).hexdigest()[:_CONTENT_TAG_CHARS]


def _tagged_native_id(native: str, text: str) -> str:
    """`native` with `_content_tag(text)` appended, RESERVING room for the tag.

    `Signal._bound_untrusted_strings` caps native_id at MAX_ID_CHARS by cutting
    the TAIL, and the components here are untrusted device strings (a 300-char
    hostname is a valid syslog input). Trimming the descriptive head ourselves
    is what guarantees the discriminator survives the cap — otherwise a long
    hostname would silently restore the collision this exists to prevent. The
    trailing ts_ms that gets trimmed first is redundant anyway: the uuid5 key
    already carries ts_ms as its own field.
    """
    return f"{native[:MAX_ID_CHARS - _CONTENT_TAG_CHARS - 1]}|{_content_tag(text)}"


# Severity keyword/char → numeric (RFC5424; lower = more severe). Covers IOS
# keywords, SR Linux single-char (I/N/W/E/C), and the %FAC-N-MNEMONIC tag digit.
_SEVERITY_NUM: dict[str, int] = {
    "emerg": 0, "emergency": 0, "alert": 1, "crit": 2, "critical": 2, "c": 2,
    "err": 3, "error": 3, "e": 3, "warn": 4, "warning": 4, "w": 4,
    "notice": 5, "note": 5, "n": 5, "info": 6, "informational": 6, "i": 6,
    "debug": 7, "d": 7,
}

# Anti-firehose floor: warning(4) or worse becomes a generic alarm; notice/info/
# debug stay logs only. main.py may override the module global from env.
ALARM_SEVERITY_FLOOR = 4  # warning

_TAG_SEV_RE = re.compile(r"%[A-Z0-9_]+-(\d)-[A-Z0-9_]+")  # Cisco %FAC-N-MNEMONIC


def syslog_severity_num(ev: dict, tag: str) -> int | None:
    """Most-severe numeric severity (0=emerg..7=debug) derivable from the event —
    the RFC5424/SR-Linux `severity` keyword/char AND the Cisco %FAC-N-MNEMONIC tag
    digit. None when neither parses (the generic-alarm fallback then abstains: no
    severity, no guessed alarm)."""
    cands: list[int] = []
    sev = str(ev.get("severity") or "").strip().lower()
    if sev in _SEVERITY_NUM:
        cands.append(_SEVERITY_NUM[sev])
    m = _TAG_SEV_RE.search(tag)
    if m:
        cands.append(int(m.group(1)))
    return min(cands) if cands else None


def _severity_from_num(n: int) -> Severity:
    if n <= 2:   # emerg / alert / crit
        return Severity.CRIT
    if n == 3:   # err
        return Severity.HIGH
    return Severity.WARN  # warning (the floor)


# Canonical set of signal kinds the producer pipeline can emit (the syslog/trap/
# probe producers here + the metric-episode kinds main.py emits via
# metric_identity). The #80 §5 coverage check (coverage.py) asserts no signature
# REQUIRES a kind absent from this set (the dead-template guard). KEEP IN SYNC when
# a producer gains a kind — the coverage test will fail loudly if you forget.
EMITTED_KINDS: frozenset[str] = frozenset({
    # probe lane
    "probe_loss", "probe_rtt_anomaly",
    # syslog control-plane
    "isis_adjacency_change", "bgp_adjacency_change", "ospf_adjacency_change",
    "routing_adjacency_change", "link_state_change", "lldp_neighbor_change",
    "stp_topology_change", "fhrp_state_change", "mac_flap",
    # BGP session churn / prefix pressure (tracker 184): %BGP-5-NBR_RESET and
    # %BGP-4-MAXPFX — a session that is resetting or a prefix table under
    # pressure, which is NOT an adjacency transition. Corroborating evidence for
    # a BGP fault; declared in coverage.INTENTIONAL_BLIND until a signature
    # references it (see that entry for the template clause that would).
    "bgp_route_churn",
    # DC overlay (P2)
    "vtep_state_change", "evpn_mac_move",
    # trap lane
    "device_restart",
    # generic-alarm keystone (#80 §4)
    "device_alarm",
    # metric episodes (main.py metric_identity + C6 flow)
    "if_metric_anomaly", "bgp_state_anomaly", "device_resource_anomaly",
    # cloud provider metrics (CloudWatch / Azure Monitor → canonical metric lane)
    "cloud_resource_anomaly",
    "flow_volume_anomaly",
    # cloud lane (#81 P3G — handle_cloud emits these; consumed by the cloud signatures)
    "cloud_change", "cloud_audit", "cloud_flow_log", "cloud_health",
    # cloud edge-device logs (cloud_log_parsers → netops.cloud → cloud_signal_from_event):
    # the LB 5xx / WAF block / DNS failure lanes consumed BOTH by the P2 path-causality
    # attributor (path_attribution.CLOUD_EDGE_FAULT_KINDS) and by the dependency-graph
    # attribution signatures (sig.ent.app.edge-*). cloud_flow_log (above) is the
    # SG/NACL reject lane.
    "cloud_lb_log", "cloud_waf_log", "cloud_dns_log",
    # IPsec/IKE tunnel state from the enterprise VPN gateway (cloud_signal_from_event
    # kind=ipsec_tunnel_status; observer ipsec:<gw>, independent of the cloud API).
    "ipsec_tunnel_status",
    # The gateway's off-tunnel reachability check to the peer's public address —
    # the underlay-root witness (sig.ent.middle-mile.ipsec-underlay-down).
    "ipsec_underlay_status",
    # synthetic application-experience lane (synthetic_normalize.py, from
    # collectors/synthetics.go via netops.probes) — external Digital-Experience,
    # NOT APM: an HTTP/TCP/ICMP synthetic outcome → a semantic app-experience kind.
    "synthetic_http_fail", "synthetic_http_5xx", "synthetic_http_4xx",
    "synthetic_http_latency_high", "synthetic_tls_fail", "synthetic_dns_fail",
    "synthetic_tcp_connect_fail", "synthetic_timeout", "synthetic_icmp_loss",
    "synthetic_tcp_probe_fail", "synthetic_cert_expired", "synthetic_cert_expiring",
    # app-edge lane (#98 P5 — lb_normalize.py, netops.app.edge): LB/proxy/ingress
    # telemetry in the CANONICAL vocabulary the app signatures already consume.
    # lb_4xx_high is INTENTIONAL_BLIND (auth/config/client indicator, never
    # outage-confirming).
    "lb_5xx", "lb_target_unhealthy", "app_error_rate_high", "app_latency_high",
    "lb_4xx_high",
    # NMS controller-intelligence lane (controller_events.py, netops.controller_events
    # — #95 P4 producer + runtime wiring LIVE; found unregistered by the #99 R3
    # all-lanes golden test): management-plane witnesses from vendor controllers.
    "controller_tunnel_state", "controller_bfd_down",
    "controller_control_connection_loss", "controller_device_unreachable",
    "controller_policy_change",
    # Wireless state-transition lane (#128 Phase 3 — nms/wireless_events.go
    # synthesizes these onto netops.controller_events from ap_join/radio_oper
    # state changes; controller_events.py binds them to wireless entities).
    # Recovery kinds (_up) are INTENTIONAL_BLIND in coverage.py: they support,
    # they are never fault evidence.
    "wireless_ap_down", "wireless_ap_up", "wireless_ap_join_flap",
    "wireless_radio_down", "wireless_radio_up",
    # clock-skew meta-finding (log-time standard S5/R5): origin timestamp vs
    # receive time beyond tolerance — a device with a wrong clock (syslog lane,
    # clock_skew_signal below) or an ingest lane delivering beyond its expected
    # lag (cloud poller). Deliberately a META finding: recorded to corr_signals
    # for operators, NEVER buffered into the engine window (it must not lend an
    # extra modality plane to a real fault) → INTENTIONAL_BLIND in coverage.py.
    "clock_skew",
    # active-verification lane (RCA spec item 8 — verification_producer.py,
    # netops.verification): the verify engine's bounded READ-ONLY check battery
    # against implicated devices. Consumed at RUNTIME by scoring's
    # corroborates_kinds/refutes_kinds matching, not by a catalog clause
    # vocabulary → INTENTIONAL_BLIND in coverage.py.
    "active_verification_result", "active_verification_healthy",
})


# ══ PARSER PROVENANCE + THE RULE TABLE (W1b) ═════════════════════════════════
#
# THE PROBLEM THIS SOLVES. Until now a Signal said WHAT was classified and never
# WHICH RULE classified it, or which revision of that rule. A parser edit that
# silently re-routed a vendor line was invisible in the data: the same kind came
# out, from a different branch, and no stored field disagreed. Three fields on
# every classified signal close that:
#
#   rule_id     a stable identifier for the branch that fired (fixed set, so it
#               is safe as a metric label)
#   parser_rev  a HAND-BUMPED revision of the rule corpus — the human statement
#               "the rules changed here"
#   rules_hash  a COMPUTED sha256 over the ordered rule table — the machine
#               statement, which catches the edit whose author forgot to bump
#               parser_rev
#
# and a fourth, `fidelity`, says how well-evidenced the GRAMMAR is (the
# telemetry-catalog ladder: doc_claimed < lab_validated < live_validated), or
# "code" when the catalog declares no fidelity for that family.
#
# IDENTITY IS UNTOUCHED (tracker 198). None of the four enters `native_id`, so
# none enters `signal_id = uuid5(NS, source|native_id|ts_ms)`. Identity stays
# CONTENT-based: bumping PARSER_REV must never re-identify a stored event, and a
# replay of an archived row must still derive the id it derived years ago.
# They ride in `attrs`, which `Signal.to_ch_row` serializes into the
# `corr_signals.attrs` String column (JSON) — so there is NO DDL change.
#
# WHY A TABLE. The branches below are hand-written Python and stay that way for
# now, but every fact ABOUT a branch — its id, its kind, the markers its guard
# tests, the message regex it compiles, the catalog family it implements — now
# lives in exactly one place, `RULES`. The ingest screen's marker/pattern tables
# are DERIVED from it (see `_CP_GUARD_MARKERS`), the port-event rule list is
# DERIVED from it (`_PORT_EVENT_RULES`), and the hit counters are keyed by it.
# That is the first step toward the catalog executing the rules rather than
# mirroring them.

# HAND-BUMPED on any rule change. Pair it with the computed RULES_HASH below:
# the constant is the intent, the hash is the proof.
PARSER_REV = "2026-09-02-184"

# The telemetry-catalog event-family fidelity ladder, as of PARSER_REV. This is
# a BUILD-TIME SNAPSHOT of `telemetry-catalog/events.yaml` (families that
# declare a `fidelity_status`), not a runtime read: the catalog is a repo
# artifact and is deliberately NOT shipped inside the correlation image (see
# deployment/docker/Dockerfile.correlation — it copies src/correlation/ only),
# so a runtime read would resolve to "unknown" in production and to the real
# value in tests, which is worse than no lookup at all. Drift is caught in CI
# instead: test_parser_provenance_w1b.py loads events.yaml and asserts this map
# is exactly the set of families that declare a fidelity_status.
#
# A family the catalog knows but leaves undeclared, and a branch with no catalog
# family at all, both stamp "code": the grammar exists only in this file and the
# catalog makes no evidence claim about it. That is the honest default — it must
# never read as validated.
CATALOG_EVENT_FIDELITY: dict[str, str] = {
    "bgp_route_churn": "doc_claimed",
    "mac_move": "doc_claimed",
    "stp_topology_notification": "doc_claimed",
}
FIDELITY_UNCATALOGUED = "code"


def _fidelity_of(family: str | None) -> str:
    """Catalog fidelity for an event family; "code" when it declares none."""
    if not family:
        return FIDELITY_UNCATALOGUED
    return CATALOG_EVENT_FIDELITY.get(family, FIDELITY_UNCATALOGUED)


# Bounded keyword gap for the port-event patterns (H11 ReDoS bound). Real
# DOM/FEC/optics lines put their keywords within a few words of each other; a
# bounded gap makes backtracking cost a small constant. Defined here because the
# rule table below is now the single place those patterns are written.
_G = r"[^\n]{0,80}"


@dataclass(frozen=True)
class Rule:
    """One classified branch of the parser, as DATA.

    `pattern` is derived from `pattern_src` at construction, so the string a
    guard compiles and the string the ingest screen reads are the same object —
    they cannot drift apart.
    """

    rule_id: str                       # stable id; the metric label
    lane: str                          # "control" | "port" | "trap" (the producer)
    source: str                        # wire Source value: "syslog" | "trap"
    kind: str                          # the emitted Signal kind (∈ EMITTED_KINDS)
    entity_type: str                   # "device" | "interface" | "device_or_interface"
    state: str | None = None           # the fixed state, when the branch has one
    state_re: str | None = None        # the regex the branch derives state with
    vendors: tuple[str, ...] = ()      # vendor grammars the branch targets
    markers: tuple[str, ...] = ()      # classification-token literals its guard tests
    pattern_src: str | None = None     # message regex its guard tests (source text)
    flags: int = re.IGNORECASE         # flags `pattern_src` is compiled with
    fidelity_key: str | None = None    # telemetry-catalog events.yaml family
    severity: Severity | None = None   # the fixed severity, when the branch has one
    generic: bool = False              # the unclassified safety net (not a typed rule)
    pattern: re.Pattern | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.pattern_src is not None:
            object.__setattr__(self, "pattern",
                               re.compile(self.pattern_src, self.flags))

    @property
    def fidelity(self) -> str:
        return _fidelity_of(self.fidelity_key)

    def digest_fields(self) -> tuple[str, ...]:
        """Everything that MAKES this rule — the input to `rules_hash`.

        `fidelity` is deliberately absent: it is the catalog's claim about the
        grammar, not the grammar. A catalog promotion must not read as a parser
        edit.
        """
        return (
            self.rule_id, self.lane, self.source, self.kind, self.entity_type,
            self.state or "", self.state_re or "", ",".join(self.vendors),
            ",".join(self.markers), self.pattern_src or "", str(self.flags),
            self.fidelity_key or "",
            self.severity.value if self.severity is not None else "",
            "1" if self.generic else "0",
        )


def rules_hash(rules: tuple[Rule, ...]) -> str:
    """sha256 over the ORDERED rule table — the machine's "the rules changed".

    Order is part of the identity on purpose: these branches are `if`/`elif` in
    sequence and `_PORT_EVENT_RULES` is first-match-wins, so swapping two rules
    changes what the parser does even though the set is unchanged.
    """
    h = hashlib.sha256()
    for r in rules:
        h.update("\x1f".join(r.digest_fields()).encode("utf-8"))
        h.update(b"\x1e")
    return h.hexdigest()


# ── the table ────────────────────────────────────────────────────────────────
#
# Declared in CLASSIFICATION ORDER within each lane, because order is behaviour
# (see `rules_hash`). Marker/pattern coverage is the ingest screen's soundness
# contract: one marker per DISJUNCT of a guard, and where a guard is a
# conjunction ("LINK" in ctoken AND "UPDOWN" in ctoken) only the more selective
# conjunct is registered — see `_build_syslog_screen`.

# -- syslog control-plane lane (`syslog_control_signal`) ----------------------
R_ISIS_ADJ = Rule(
    rule_id="syslog.isis.adjacency_change", lane="control", source="syslog",
    kind="isis_adjacency_change", entity_type="device",
    state_re=r"to state\s+(\w+)", vendors=("nokia", "cisco"),
    markers=("ISISADJACENCYCHANGE", "CLNS"),
    fidelity_key="isis_adjacency_change",
)
R_BGP_ADJ = Rule(
    rule_id="syslog.bgp.adjacency_change", lane="control", source="syslog",
    kind="bgp_adjacency_change", entity_type="device",
    vendors=("cisco", "arista", "juniper"), markers=("ADJCHANGE", "ADJCHG"),
    fidelity_key="bgp_adjacency_change",
)
R_OSPF_ADJ = Rule(
    rule_id="syslog.ospf.adjacency_change", lane="control", source="syslog",
    kind="ospf_adjacency_change", entity_type="device",
    vendors=("cisco", "arista"), markers=("ADJCHANGE", "ADJCHG"),
    fidelity_key="ospf_adjacency_change",
)
R_ROUTING_ADJ = Rule(
    rule_id="syslog.routing.adjacency_change", lane="control", source="syslog",
    kind="routing_adjacency_change", entity_type="device",
    vendors=("generic",), markers=("ADJCHANGE", "ADJCHG"),
)
# The two tracker-184 BGP-churn rules share one guard (markers + pattern); the
# branch splits them on the mnemonic. A NOTIFICATION closes the session (RFC 4271
# §6) and is therefore a genuine adjacency change; a reset or a prefix-limit
# warning is not.
_BGP_CHURN_MARKERS = ("NBR_RESET", "MAXPFX", "NOTIFICATION")
_BGP_CHURN_PATTERN = (r"\b(?:NOTIFICATION\s+(?:sent\s+to|received\s+from)|"
                      r"maximum\s+prefix-limit)\b")
R_BGP_NOTIFY = Rule(
    rule_id="syslog.bgp.notification", lane="control", source="syslog",
    kind="bgp_adjacency_change", entity_type="device", state="down",
    vendors=("cisco", "juniper"), markers=_BGP_CHURN_MARKERS,
    pattern_src=_BGP_CHURN_PATTERN, fidelity_key="bgp_adjacency_change",
    severity=Severity.HIGH,
)
R_BGP_CHURN = Rule(
    rule_id="syslog.bgp.route_churn", lane="control", source="syslog",
    kind="bgp_route_churn", entity_type="device",
    state_re=r"\b(?:exceed(?:ed|s)?|shut\s?down|shutdown|disabl\w*)\b",
    vendors=("cisco", "juniper"), markers=_BGP_CHURN_MARKERS,
    pattern_src=_BGP_CHURN_PATTERN, fidelity_key="bgp_route_churn",
)
R_LINK = Rule(
    rule_id="syslog.link.state_change", lane="control", source="syslog",
    kind="link_state_change", entity_type="interface",
    vendors=("cisco", "arista"), markers=("UPDOWN",),
    fidelity_key="link_state_change",
)
R_LLDP = Rule(
    rule_id="syslog.lldp.neighbor_change", lane="control", source="syslog",
    kind="lldp_neighbor_change", entity_type="interface",
    state_re=r"\b(?:removed|deleted|aged)\b", vendors=("arista", "nokia"),
    markers=("LLDP", "REMOTEPEER"), fidelity_key="lldp_neighbor_change",
)
R_STP_IF = Rule(
    rule_id="syslog.stp.topology_change", lane="control", source="syslog",
    kind="stp_topology_change", entity_type="interface",
    state_re=r"\bto\s+(forwarding|learning|discarding|blocking)\b",
    vendors=("cisco", "arista"), markers=("SPANTREE",),
    fidelity_key="stp_topology_change",
)
R_STP_TCN = Rule(
    rule_id="syslog.stp.topology_notification", lane="control", source="syslog",
    kind="stp_topology_change", entity_type="device",
    state_re=r"\bto\s+(forwarding|learning|discarding|blocking)\b",
    vendors=("cisco",), markers=("SPANTREE",),
    fidelity_key="stp_topology_notification",
)
R_VTEP = Rule(
    rule_id="syslog.vtep.state_change", lane="control", source="syslog",
    kind="vtep_state_change", entity_type="device",
    vendors=("cisco",), markers=("NVE", "VTEP"),
)
R_EVPN = Rule(
    rule_id="syslog.evpn.mac_move", lane="control", source="syslog",
    kind="evpn_mac_move", entity_type="device", severity=Severity.HIGH,
    vendors=("arista", "cisco"),
    markers=("EVPN", "HMM", "DUP_HOST", "VXLAN_MAC_MOVE"),
    pattern_src=r"\b(?:blacklisted|duplicate host|between NVE and)\b",
)
R_FHRP = Rule(
    rule_id="syslog.fhrp.state_change", lane="control", source="syslog",
    kind="fhrp_state_change", entity_type="device",
    state_re=r"->\s*(\w+)", vendors=("cisco", "arista"),
    markers=("HSRP", "VRRP", "STANDBY"),
)
R_MAC_FLAP = Rule(
    rule_id="syslog.mac.flap", lane="control", source="syslog",
    kind="mac_flap", entity_type="device", severity=Severity.HIGH,
    state_re=r"\bflap", vendors=("cisco", "arista"),
    markers=("MACFLAP", "MAC_MOVE"),
    pattern_src=(r"\b(?:is flapping between|has moved between|mac[\s_-]?move|"
                 r"mac[\s_-]?flap)\b"),
    fidelity_key="mac_move",
)
R_SYSLOG_ALARM = Rule(
    rule_id="syslog.generic.device_alarm", lane="control", source="syslog",
    kind="device_alarm", entity_type="device_or_interface",
    vendors=("any",), generic=True,
)

# The ADJCHANGE branch's kind is chosen by protocol; the table holds all three
# so the branch never names a kind of its own.
_ADJ_RULES: dict[str, Rule] = {
    "bgp": R_BGP_ADJ, "ospf": R_OSPF_ADJ, "routing": R_ROUTING_ADJ,
}

# -- syslog port-intelligence lane (`port_event_signal`) ----------------------
# ORDERED, first match wins — `_PORT_EVENT_RULES` is derived from these in this
# order, so moving one changes classification (and `rules_hash`).
_PORT_RULES: tuple[Rule, ...] = (
    Rule(rule_id="syslog.port.transceiver_unsupported", lane="port",
         source="syslog", kind="transceiver_unsupported", entity_type="interface",
         severity=Severity.HIGH, vendors=("cisco", "arista", "fortinet"),
         pattern_src=(r"unsupported\s+transceiver|unqualified\s+(sfp|transceiver|optic)"
                      r"|not\s+qualified|UNSUPPORTED_TRANSCEIVER|transceiver"
                      + _G + r"not\s+supported")),
    Rule(rule_id="syslog.port.dom_rx_power_low", lane="port", source="syslog",
         kind="dom_rx_power_low", entity_type="interface", severity=Severity.HIGH,
         vendors=("generic",),
         pattern_src=(r"(rx|receive)" + _G + r"power" + _G + r"(low|below)" + _G
                      + r"(alarm|threshold)|RX_POWER_LOW|low\s+rx\s+power")),
    Rule(rule_id="syslog.port.dom_temperature_high", lane="port", source="syslog",
         kind="dom_temperature_high", entity_type="interface", severity=Severity.HIGH,
         vendors=("generic",),
         pattern_src=(r"(temperature|temp)" + _G + r"(high|above)" + _G
                      + r"(alarm|threshold|warning)|TEMP_HIGH|high\s+temperature")),
    Rule(rule_id="syslog.port.dom_lane_bias_anomaly", lane="port", source="syslog",
         kind="dom_lane_bias_anomaly", entity_type="interface", severity=Severity.WARN,
         vendors=("generic",),
         pattern_src=(r"(tx\s+)?bias" + _G + r"(high|current)" + _G
                      + r"(alarm|threshold)|BIAS_HIGH")),
    Rule(rule_id="syslog.port.prefec_ber_rising", lane="port", source="syslog",
         kind="prefec_ber_rising", entity_type="interface", severity=Severity.HIGH,
         vendors=("generic",),
         pattern_src=(r"uncorrectable" + _G + r"(fec|codeword|block)|FEC" + _G
                      + r"UNCORRECTABLE|post[-_ ]?fec" + _G + r"(error|ber)")),
    Rule(rule_id="syslog.port.fec_corrected_rate_high", lane="port", source="syslog",
         kind="fec_corrected_rate_high", entity_type="interface", severity=Severity.WARN,
         vendors=("generic",),
         pattern_src=(r"pre[-_ ]?fec\s+ber|fec" + _G + r"corrected" + _G
                      + r"(rate|high)|CORRECTED_FEC")),
    Rule(rule_id="syslog.port.pcs_local_fault", lane="port", source="syslog",
         kind="pcs_local_fault", entity_type="interface", severity=Severity.HIGH,
         vendors=("generic",), pattern_src=r"local\s+fault|LOCAL_FAULT"),
    Rule(rule_id="syslog.port.pcs_remote_fault", lane="port", source="syslog",
         kind="pcs_remote_fault", entity_type="interface", severity=Severity.HIGH,
         vendors=("generic",), pattern_src=r"remote\s+fault|REMOTE_FAULT"),
    Rule(rule_id="syslog.port.pcs_deskew_fault", lane="port", source="syslog",
         kind="pcs_deskew_fault", entity_type="interface", severity=Severity.HIGH,
         vendors=("generic",),
         pattern_src=(r"deskew|align" + _G + r"(marker|lane)" + _G
                      + r"(fail|lost)|PCS" + _G + r"DESKEW")),
    Rule(rule_id="syslog.port.hi_ber_indication", lane="port", source="syslog",
         kind="hi_ber_indication", entity_type="interface", severity=Severity.HIGH,
         vendors=("generic",), pattern_src=r"hi[-_ ]?ber|high\s+bit\s+error"),
    Rule(rule_id="syslog.port.link_down_no_light", lane="port", source="syslog",
         kind="link_down_no_light", entity_type="interface", severity=Severity.HIGH,
         vendors=("generic",),
         pattern_src=r"no\s+(light|signal)|loss\s+of\s+(light|signal)|LOS\b|SIGNAL_LOSS"),
    Rule(rule_id="syslog.port.link_flap_on_insert", lane="port", source="syslog",
         kind="link_flap_on_insert", entity_type="interface", severity=Severity.WARN,
         vendors=("generic",),
         pattern_src=(r"transceiver" + _G + r"(insert|remov)" + _G
                      + r"(insert|remov)|SFP" + _G + r"flap|optic" + _G + r"flap")),
)

# -- SNMP trap lane (`trap_control_signal`) -----------------------------------
R_TRAP_LINK = Rule(
    rule_id="trap.link.state_change", lane="trap", source="trap",
    kind="link_state_change", entity_type="interface", vendors=("standard",),
    fidelity_key="link_state_change",
)
R_TRAP_RESTART = Rule(
    rule_id="trap.device.restart", lane="trap", source="trap",
    kind="device_restart", entity_type="device", severity=Severity.HIGH,
    vendors=("standard",),
)
R_TRAP_BGP = Rule(
    rule_id="trap.bgp.adjacency_change", lane="trap", source="trap",
    kind="bgp_adjacency_change", entity_type="device", vendors=("standard",),
    fidelity_key="bgp_adjacency_change",
)
R_TRAP_BGP_ETYPE = Rule(
    rule_id="trap.bgp.adjacency_change.event_type", lane="trap", source="trap",
    kind="bgp_adjacency_change", entity_type="device", vendors=("any",),
    fidelity_key="bgp_adjacency_change",
)
R_TRAP_LINK_ETYPE = Rule(
    rule_id="trap.link.state_change.event_type", lane="trap", source="trap",
    kind="link_state_change", entity_type="interface", vendors=("any",),
    fidelity_key="link_state_change",
)
R_TRAP_RESTART_ETYPE = Rule(
    rule_id="trap.device.restart.event_type", lane="trap", source="trap",
    kind="device_restart", entity_type="device", severity=Severity.HIGH,
    vendors=("any",),
)
R_TRAP_ALARM = Rule(
    rule_id="trap.generic.device_alarm", lane="trap", source="trap",
    kind="device_alarm", entity_type="device_or_interface", vendors=("any",),
    generic=True,
)

RULES: tuple[Rule, ...] = (
    R_ISIS_ADJ, R_BGP_ADJ, R_OSPF_ADJ, R_ROUTING_ADJ,
    R_BGP_NOTIFY, R_BGP_CHURN, R_LINK, R_LLDP, R_STP_IF, R_STP_TCN,
    R_VTEP, R_EVPN, R_FHRP, R_MAC_FLAP, R_SYSLOG_ALARM,
    *_PORT_RULES,
    R_TRAP_LINK, R_TRAP_RESTART, R_TRAP_BGP,
    R_TRAP_BGP_ETYPE, R_TRAP_LINK_ETYPE, R_TRAP_RESTART_ETYPE, R_TRAP_ALARM,
)

RULES_BY_ID: dict[str, Rule] = {r.rule_id: r for r in RULES}
if len(RULES_BY_ID) != len(RULES):                      # pragma: no cover - guard
    raise RuntimeError("duplicate rule_id in producers.RULES")

# The computed half of provenance. The full digest is the comparison value; the
# 16-hex prefix is what rides on every signal (64 hex chars per row, times the
# whole syslog firehose, buys nothing over 64 bits of collision resistance).
RULES_HASH = rules_hash(RULES)
RULES_HASH_TAG = RULES_HASH[:16]


# ── parser observability (bounded-cardinality counters) ──────────────────────
#
# `rule_id` is a FIXED set (the table above), so it is safe as a Prometheus
# label — the series count is len(RULES), known at import, and no device string
# can widen it. Pre-seeded at zero so a rule that stops firing is visible as a
# flat series rather than as an absent one.
RULE_HITS: dict[str, int] = {r.rule_id: 0 for r in RULES}
GENERIC_FALLBACKS: dict[str, int] = {"syslog": 0, "trap": 0}

# The semantic-promotion rate is measured over a ROLLING WINDOW of the last
# PROMOTION_WINDOW ADMITTED lines — "admitted" meaning a line that produced a
# signal at all (typed or generic). Lines that classify as nothing are not in
# the denominator: they are the pre-filter's business, not the parser's, and
# including them would make the rate a function of the noise mix rather than of
# parser coverage. A fixed-size ring keeps the read O(1) and the memory bounded
# (one int per slot, allocated once) — /metrics must never pay an O(window) sum.
PROMOTION_WINDOW = 10_000
_PROMO_RING: list[int] = []
_PROMO_POS = 0
_PROMO_TYPED = 0


def _record_promotion(typed: bool) -> None:
    global _PROMO_POS, _PROMO_TYPED
    v = 1 if typed else 0
    if len(_PROMO_RING) < PROMOTION_WINDOW:
        _PROMO_RING.append(v)
        _PROMO_TYPED += v
        return
    _PROMO_TYPED += v - _PROMO_RING[_PROMO_POS]
    _PROMO_RING[_PROMO_POS] = v
    _PROMO_POS = (_PROMO_POS + 1) % PROMOTION_WINDOW


def semantic_promotion_rate() -> float:
    """typed / (typed + generic) over the last PROMOTION_WINDOW admitted lines.

    1.0 when nothing has been admitted yet: an empty window makes no claim, and
    reporting 0.0 would page as "the parser stopped classifying".
    """
    if not _PROMO_RING:
        return 1.0
    return _PROMO_TYPED / len(_PROMO_RING)


def parser_stats() -> dict:
    """Provenance + coverage counters, for /metrics and the health payload."""
    return {
        "parser_rev": PARSER_REV,
        "rules_hash": RULES_HASH_TAG,
        "rules": len(RULES),
        "rule_hits": dict(RULE_HITS),
        "generic_fallbacks": dict(GENERIC_FALLBACKS),
        "semantic_promotion_rate": round(semantic_promotion_rate(), 6),
        "promotion_window": PROMOTION_WINDOW,
        "promotion_window_used": len(_PROMO_RING),
    }


def reset_parser_counters() -> None:
    """Test hook."""
    global _PROMO_POS, _PROMO_TYPED
    for k in RULE_HITS:
        RULE_HITS[k] = 0
    for k in GENERIC_FALLBACKS:
        GENERIC_FALLBACKS[k] = 0
    _PROMO_RING.clear()
    _PROMO_POS = 0
    _PROMO_TYPED = 0


def _prov(rule: Rule) -> dict:
    """Count the hit and return the provenance `attrs` for this rule.

    Called exactly once per emitted Signal, from the branch's own `attrs`
    literal. The returned keys are provenance ONLY — none of them reaches
    `native_id`, so `signal_id` is unchanged (tracker 198: identity is content).
    """
    RULE_HITS[rule.rule_id] += 1
    if rule.generic:
        GENERIC_FALLBACKS[rule.source] = GENERIC_FALLBACKS.get(rule.source, 0) + 1
    _record_promotion(not rule.generic)
    return {
        "rule_id": rule.rule_id,
        "parser_rev": PARSER_REV,
        "rules_hash": RULES_HASH_TAG,
        "fidelity": rule.fidelity,
    }


def episode_signal(
    ev: EpisodeEvent,
    observer: Observer,
    *,
    source: Source = Source.METRIC,
    modality: ModalityClass = ModalityClass.DEVICE_TELEMETRY,
    entity_type: EntityType = EntityType.DEVICE,
    kind_prefix: str = "metric_anomaly",
    entity_tokens: tuple[str, ...] = (),
    path_id: str | None = None,
    extra_attrs: dict | None = None,
) -> Signal:
    """EpisodeEvent → canonical Signal row (deterministic identity: the episode
    is identified by its onset, so onset+clear rows share native_id lineage).
    Provenance is parameterized so probe-path episodes carry active_probe /
    vantage-agent provenance instead of device telemetry (#67 build ⑦);
    extra_attrs carries lane-specific provenance (e.g. flow app-attribution
    source/confidence, #98 Phase 4) without touching the episode fields."""
    tenant_id, entity_id, metric = ev.key
    onset_ms = int(ev.onset_ts.timestamp() * 1000)
    attrs = {
        **(extra_attrs or {}),
        "phase": ev.phase,
        "onset_uncertainty_s": round(ev.onset_uncertainty_s, 3),
        "peak_deviation": round(ev.peak_deviation, 4),
        "integral": round(ev.integral, 2),
    }
    if ev.clear_ts is not None:
        attrs["clear_ts"] = ev.clear_ts.isoformat()
    return Signal(
        tenant_id=tenant_id,
        ts=ev.onset_ts if ev.phase == "onset" else (ev.clear_ts or ev.onset_ts),
        source=source,
        kind=kind_prefix if ev.phase == "onset" else f"{kind_prefix}_clear",
        observer=observer,
        modality_class=modality,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity_for(ev.peak_deviation),
        native_id=f"{tenant_id}|{entity_id}|{metric}|{ev.phase}|{onset_ms}",
        entity_tokens=entity_tokens,
        path_id=path_id,
        metric_name=metric,
        value=ev.value,
        baseline=ev.baseline,
        deviation=ev.deviation,
        attrs=attrs,
    )

# Timestamps the correlation lanes could not parse. Every call site falls back
# to ingest time, which silently re-stamps the event with RECEIVE time — the
# input to `onset_uncertainty_s`, i.e. to the cause/effect ORDER that RCA is
# built on. A fallback that nothing counts is a lie that looks like data, so
# the substitution is now visible (surfaced as ingest.event_ts_invalid).
TS_INVALID = 0


def ts_invalid_count() -> int:
    """Timestamps present on the wire but unparseable (fell back to ingest time)."""
    return TS_INVALID


def reset_ts_invalid() -> None:
    """Test hook."""
    global TS_INVALID
    TS_INVALID = 0


def parse_event_ts(raw: object, *, reference: datetime | None = None) -> datetime | None:
    """Wire event time → tz-aware UTC; None when absent/malformed (the caller
    substitutes ingest time — honest fallback, never a guess).

    Accepts every shape the ingest lane normalizes (timenorm.parse_any_timestamp,
    the same _EPOCH_MS/_US/_NS thresholds Vector uses downstream): RFC3339/ISO
    with or without an offset, float epoch SECONDS, int epoch ms/µs/ns, numeric
    strings, and RFC3164 syslog header time. This function used to accept ONLY
    RFC3339 and returned None for every numeric epoch — so a numeric-epoch
    producer landed correctly in ClickHouse (normalized by the vector-router,
    which sits downstream of Kafka) while the correlation engine, which reads
    UPSTREAM of it, re-timestamped the same event to receive time. Both stores
    then disagreed about when the event happened, and nothing said so.
    """
    if raw is None or raw == "":
        return None
    # Year inference for a year-less format (RFC 3164 syslog) must anchor on the
    # event's INGEST time, which every caller holds and now passes. Wall-clock
    # now() is a last-resort fallback ONLY — delayed reprocessing (quarantine or
    # flows restore, a consumer backlog) across a year boundary would otherwise
    # stamp a December event into the current year, corrupting onset order and
    # CUSUM intervals. This keeps the module's "no wall-clock reads" promise for
    # every real call path.
    ref = reference or datetime.now(timezone.utc)
    parsed = parse_any_timestamp(raw, reference=ref)
    if parsed is None:
        global TS_INVALID
        TS_INVALID += 1
        return None
    return parsed[0]


# ── flow events (netops.flows) — passive_flow volume aggregation (C6) ─────────


def _flow_field(ev: dict, *names: str) -> str:
    """First present value among alternative field spellings — the bus may carry
    goflow2 CamelCase (SamplerAddress) or the CH-aligned snake_case (sampler_address)."""
    for n in names:
        v = ev.get(n)
        if v not in (None, ""):
            return str(v)
    return ""


def flow_sample(ev: dict) -> tuple[str, str, float] | None:
    """One raw flow record → (sampler, entity_id, bytes_estimate) for per-interface
    volume aggregation, or None when the record can't be attributed/measured.

    entity_id = `<sampler>:if<in_if>` — the exporting interface. An HONEST fallback:
    production resolves the sampler IP → device and the ifIndex → ifName (the same
    canonicalization seam as traps, G2); until then the flow grounds on the sampler
    token. bytes are scaled by the sampling rate to estimate true volume (a 1-in-N
    sampler under-reports by N×); rate 0/absent ⇒ unsampled ⇒ ×1."""
    sampler = _flow_field(ev, "sampler_address", "SamplerAddress", "sampler")
    if not sampler:
        return None
    try:
        nbytes = float(_flow_field(ev, "bytes", "Bytes") or 0)
    except ValueError:
        return None
    if nbytes <= 0:
        return None
    try:
        rate = int(_flow_field(ev, "sampling_rate", "SamplingRate") or 0)
    except ValueError:
        rate = 0
    in_if = _flow_field(ev, "in_if", "InIf", "InIfIndex") or "0"
    return sampler, f"{sampler}:if{in_if}", nbytes * (rate if rate > 0 else 1)


# ── probe events (netops.probes) ──────────────────────────────────────────────


def probe_host(target: str) -> str:
    """Bare host out of a probe target (host[:port] or URL) — the grounding
    token that can intersect a seam endpoint / probe binding."""
    t = target
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    if t.count(":") == 1:  # host:port (IPv6 literals have ≥2 colons)
        t = t.split(":", 1)[0]
    return t


def _loss_severity(loss: float) -> Severity:
    if loss >= 75:
        return Severity.CRIT
    if loss >= 25:
        return Severity.HIGH
    return Severity.WARN


def probe_signals(
    ev: dict, detector: EpisodeDetector, tenant: str, ingest_ts: datetime,
) -> list[Signal]:
    """One probe event → 0..2 signals: a discrete probe_loss observation when
    loss crosses the floor, and an RTT episode onset/clear from the CUSUM
    detector when reachable. May raise DeadLetter (caller counts + parks)."""
    kind = str(ev.get("kind") or "")
    prober = str(ev.get("prober") or "")
    target = str(ev.get("target") or "")
    if not kind or not prober or not target:
        return []
    host = probe_host(target)
    ts = parse_event_ts(ev.get("ts"), reference=ingest_ts) or ingest_ts
    entity = f"{prober}->{host}"
    observer = Observer(
        observer_id=prober,
        observer_type=ObserverType.VANTAGE_AGENT,
        collection_path="direct",
        clock_quality="unknown",
    )
    rtt = float(ev.get("rtt_ms") or 0.0)
    loss = float(ev.get("loss_pct") or 0.0)
    ok = bool(ev.get("ok"))
    if not ok and loss <= 0.0:
        loss = 100.0

    out: list[Signal] = []
    if loss >= PROBE_LOSS_PCT:
        ts_ms = int(ts.timestamp() * 1000)
        out.append(Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.PROBE,
            kind="probe_loss",
            observer=observer,
            modality_class=ModalityClass.ACTIVE_PROBE,
            entity_type=EntityType.PATH,
            entity_id=entity,
            severity=_loss_severity(loss),
            native_id=f"{prober}|{host}|{kind}|loss|{ts_ms}",
            entity_tokens=(prober, host),
            path_id=entity,
            metric_name=f"probe_loss_pct[{kind}]",
            value=loss,
            attrs={"probe_kind": kind, "target": target},
        ))
    if ok and rtt > 0.0:
        ep = detector.observe(
            tenant, entity, f"probe_rtt_ms[{kind}]", ts, rtt, clock_quality="unknown",
        )
        if ep is not None:
            out.append(episode_signal(
                ep, observer,
                source=Source.PROBE,
                modality=ModalityClass.ACTIVE_PROBE,
                entity_type=EntityType.PATH,
                kind_prefix="probe_rtt_anomaly",
                entity_tokens=(prober, host),
                path_id=entity,
            ))
    return out


# ── syslog control-plane events (netops.syslog) ───────────────────────────────
#
# Real-world shapes these patterns are built from (lab cEOS + Cisco-style):
#   "%BGP-5-ADJCHANGE: peer 10.0.0.1 (AS 65001) old state Established event
#    RecvNotify new state Idle"                                   (EOS)
#   "%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down Interface flap"     (IOS)
#   "%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Ethernet1 from FULL to DOWN"
#   "%LINK-3-UPDOWN: Interface Ethernet1, changed state to down"
#   "%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed
#    state to down"
# The RFC5424 tag (%FAC-SEV-MNEMONIC) arrives in .appname via the Vector
# syslog source; the text after the colon arrives in .message.

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# ── tracker 168: device-LOCAL names are not global correlation subjects ──────
#
# THE DEFECT. An interface name is unique only WITHIN its device. Emitting a bare
# `GigabitEthernet0/5` as an entity_token made it a GLOBAL grounding subject, so
# every device in the estate that owns a `GigabitEthernet0/5` became a rank-7
# shared-token candidate of every other. Reproduced end to end: `dc1-switch-a` and
# `branch-77-rtr` each flapping their Gi0/5 within the temporal reach fused into
# ONE RCA object on `grounding=topo:shared:GigabitEthernet0/5 rank=7 weight=0.452`.
# The §3/§4 gate caps such an object at `suspected` so it can never be a false
# CONFIRMED RCA, but the evidence graph is still wrong — unrelated devices, an
# inflated affected() set, and (measured at 1K) 48 index groups of 1,000 nodes
# each, ~25.1M candidate pairs, which was the throughput wall as well.
#
# THE RULE. Identity establishes SAMENESS; topology establishes RELATIONSHIPS
# between different entities. Accidental string equality is not topology.
#
#   * On an INTERFACE-scoped signal the bare name is redundant: `entity_id` is
#     already `device:ifname` and Node.tokens() derives both it and the device
#     part. So the local name is simply dropped from entity_tokens.
#   * On a DEVICE-scoped signal that legitimately points AT an interface/port/
#     group (FHRP, MAC-flap), the local name is QUALIFIED with its device via
#     `_device_local`, which preserves the intended binding to that device's own
#     interface node and removes the cross-device weld.
#
# Genuinely global identifiers — MAC addresses, peer/VTEP IPs — stay bare: two
# devices seeing the same MAC really are related.
#
# `attrs` keeps the raw local name either way, so search and the UI are unchanged.
def _device_local(device: str, *names: str) -> tuple[str, ...]:
    """Qualify device-local names (`Gi0/5`, `grp1`, `vlan10`) as `device:name`."""
    return tuple(f"{device}:{n}" for n in names if n and n != "unknown")


_IF_RE = re.compile(r"[Ii]nterface\s+([A-Za-z][\w/.\-]*)")
_DOWN_RE = re.compile(r"\b(?:down|idle|init|backward|failed)\b", re.IGNORECASE)
_UP_RE = re.compile(r"\b(?:up|established|full)\b", re.IGNORECASE)


def _state_of(msg: str) -> str:
    """down beats up: 'old state Established new state Idle' is a down."""
    if _DOWN_RE.search(msg):
        return "down"
    if _UP_RE.search(msg):
        return "up"
    return "unknown"


# -- P3 change B: the syslog INGEST PRE-FILTER --------------------------------
#
# MEASURED (docs/scale/P3_AGGREGATION_OPPORTUNITY_2026-08-29 SS1/SS6). On the
# ratified `t-nominal-2.5k` workload 900,001 raw syslog lines yield 44,280
# signals: 95.1 % of lines are fully parsed and then dropped, and `handle.syslog`
# costs 789 s of engine time. Those lines are all distinct, from distinct
# devices, so aggregation cannot touch them -- "only an early mnemonic reject
# (not a key) can cut it".
#
# Per-line cost of the drop path, measured on the ratified noise mix:
#     syslog_control_signal   35 us   (ts parse + Observer + ~15 regex/substring)
#     port_event_signal       90 us   (its own union pre-filter, tracker 156)
#     clock_skew_signal      0.3 us   (already short-circuits on a field test)
# The port union is the single most expensive step and costs MORE than running
# its twelve rules one by one -- Python's `re` cannot factor an alternation of
# bounded-gap patterns. A literal-containment screen answers the same question
# in ~2 us.
#
# THE CONTRACT. `syslog_promotable` is a NECESSARY condition for promotion by
# `syslog_control_signal` OR `port_event_signal`. It may return True for a line
# that then classifies as nothing (wasted microseconds, no behaviour change); it
# must NEVER return False for a line either producer would have promoted. The
# screen is therefore built as a UNION of per-gate necessary conditions, and it
# fails OPEN whenever any part of it cannot be derived.
#
# DERIVED, NOT HAND-WRITTEN, on both halves:
#   * the port-event half is extracted from `_PORT_EVENT_RULES` themselves by
#     `regex_screen.pattern_screen` -- adding a rule updates the screen with it;
#   * the control-plane half is the table below, and `test_ingest_prefilter_p3`
#     re-derives it from `syslog_control_signal`'s OWN AST: every top-level `if`
#     that can return a Signal must be covered (an OR needs every branch covered,
#     an AND needs one), and an unrecognized guard shape fails the test. Adding a
#     branch without registering its marker is RED in CI.
#
# ORDERING NOTE. The `device_alarm` safety net at the bottom of the chain fires
# on SEVERITY alone, for any mnemonic. So the screen tests severity FIRST and
# passes every warning-or-worse line unconditionally; only notice/info/debug
# lines reach the literal scan.
#
# One MARKER per promotion gate of `syslog_control_signal`. Where a gate is a
# conjunction ("LINK" in ctoken AND "UPDOWN" in ctoken) only ONE conjunct is
# needed for soundness, and the more selective one is registered.
#
# W1b: DERIVED FROM `RULES`, not hand-written. Each control-plane Rule declares
# the markers and the message pattern ITS OWN guard tests, so registering a new
# branch's screen coverage is now the same act as registering the branch — the
# two cannot drift. The order below is rule-table order, de-duplicated
# first-seen; `_build_syslog_screen` folds them into a set, so order is
# presentation only.
#
#   ISISADJACENCYCHANGE, CLNS   IS-IS adjacency  (CLNS ^ ADJ -> CLNS)
#   ADJCHANGE, ADJCHG           BGP / OSPF / generic adjacency
#   NBR_RESET, MAXPFX, NOTIFICATION   BGP churn (tracker 184; "BGP" ^ one of these)
#   UPDOWN                      (LINK v LINEPROTO) ^ UPDOWN
#   LLDP, REMOTEPEER            (LLDP ^ NEIGHBOR) v REMOTEPEER
#   SPANTREE                    STP topology change / notification
#   NVE, VTEP                   NVE v (VTEP ^ BFD)
#   EVPN, HMM, DUP_HOST, VXLAN_MAC_MOVE   EVPN MAC mobility
#   HSRP, VRRP, STANDBY         FHRP state change
#   MACFLAP, MAC_MOVE           local MAC flap / move


def _dedup(items) -> tuple[str, ...]:
    """First-seen order, no duplicates (several Rules share one guard)."""
    seen: dict[str, None] = {}
    for it in items:
        seen.setdefault(it, None)
    return tuple(seen)


_CP_GUARD_MARKERS: tuple[str, ...] = _dedup(
    m for r in RULES if r.lane == "control" for m in r.markers)
# The regexes those same gates test against the MESSAGE. Taken from the rule
# table as SOURCE TEXT, which is the identical string the gate compiles — the
# `Rule.pattern` the branch matches with is `re.compile` of this very string.
_CP_GUARD_PATTERNS: tuple[str, ...] = _dedup(
    r.pattern_src for r in RULES if r.lane == "control" and r.pattern_src)


def _build_syslog_screen() -> tuple[str, ...] | None:
    """Every literal the screen tests, lower-cased. None = UNSCREENABLE, in
    which case `syslog_promotable` fails open and the pre-filter is inert.

    Failure is loud (SS10: no silent degradation) but never fatal: a rule whose
    pattern this cannot read costs the optimization, not a signal.
    """
    lits: set[str] = {m.lower() for m in _CP_GUARD_MARKERS}
    for source in _CP_GUARD_PATTERNS:
        screen = pattern_screen(source)
        if screen is None:
            log.warning("syslog ingest pre-filter DISABLED: control-plane guard "
                        "pattern %r cannot be screened soundly", source)
            return None
        lits |= screen
    for pat, kind, _iface, _sev in _PORT_EVENT_RULES:
        screen = pattern_screen(pat.pattern)
        if screen is None:
            log.warning("syslog ingest pre-filter DISABLED: port-event rule %r "
                        "cannot be screened soundly", kind)
            return None
        lits |= screen
    # Longest first: the most selective literals answer soonest, and `in` is a
    # C substring search whose cost barely moves with the needle.
    return tuple(sorted(lits, key=lambda x: (-len(x), x)))


# Built at the bottom of this module, once `_PORT_EVENT_RULES` exists -- the
# screen is derived from those rules, so it cannot be built before them.
_SYSLOG_SCREEN_LITERALS: tuple[str, ...] | None = None

PREFILTER_REJECTED = 0   # raw syslog lines the screen proved cannot promote
PREFILTER_PASSED = 0     # raw syslog lines handed to the full classifiers


def prefilter_counts() -> tuple[int, int]:
    """(passed, rejected) -- exposed as corr_ingest_prefilter_total."""
    return PREFILTER_PASSED, PREFILTER_REJECTED


def reset_prefilter_counts() -> None:
    """Test hook."""
    global PREFILTER_PASSED, PREFILTER_REJECTED
    PREFILTER_PASSED = PREFILTER_REJECTED = 0


def syslog_promotable(ev: dict) -> bool:
    """False only when NEITHER `syslog_control_signal` NOR `port_event_signal`
    can possibly promote this raw line. Counted; see the contract above.

    The haystack is a superset of both classifiers' own classification tokens:
    `syslog_control_signal` reads `appname + " " + facility + " " + event_type`
    (upper) and `message` (upper); `port_event_signal` reads the same four
    fields joined by single spaces and capped at 2 KB. Joining with a space
    means no marker can straddle a field boundary in either, so a marker present
    in their token is present here -- and this one is uncapped, so truncation can
    only make this screen MORE permissive.
    """
    global PREFILTER_PASSED, PREFILTER_REJECTED
    lits = _SYSLOG_SCREEN_LITERALS
    if lits is None:                        # fail open (see _build_syslog_screen)
        PREFILTER_PASSED += 1
        return True
    tag = str(ev.get("appname") or "").upper()
    # The generic device-alarm net (bottom of the chain) fires on severity alone.
    sev_num = syslog_severity_num(ev, tag)
    if sev_num is not None and sev_num <= ALARM_SEVERITY_FLOOR:
        PREFILTER_PASSED += 1
        return True
    hay = " ".join((
        str(ev.get("message") or ""),
        tag,
        str(ev.get("facility") or ""),
        str(ev.get("event_type") or ""),
    )).lower()
    for lit in lits:
        if lit in hay:
            PREFILTER_PASSED += 1
            return True
    PREFILTER_REJECTED += 1
    return False


def syslog_control_signal(ev: dict, tenant: str, ingest_ts: datetime) -> Signal | None:
    """Adjacency / link-state syslog → one control_plane Signal; None for
    everything that is not a recognized control-plane event. May raise
    DeadLetter on malformed provenance.

    tracker 198: the generic `device_alarm` net at the bottom now folds a hash
    of the message text into its native_id, so two distinct unrecognized lines
    that share host + facility + mnemonic (+ interface) inside one millisecond
    are two signals instead of one. The V1 qualification leg's `corr_signals`
    ROW COUNT (informational, never gated) may therefore rise slightly: fewer
    distinct alarms collapse into each other. Nothing else moves — persistence,
    versioning, the memflat structures and the replay guard are untouched
    (INVARIANTS §10/§10a), and a byte-identical redelivery still derives the
    same signal_id and still dedups."""
    host = str(ev.get("hostname") or "")
    if not host or host == "unknown":
        return None
    tag = str(ev.get("appname") or "").upper()
    msg = str(ev.get("message") or "")
    # Fold the VRL-parsed facility + mnemonic (#31 envelope) into the classification
    # token so vendor logs whose appname isn't telling still classify off the
    # structured fields. ctoken ⊇ tag, so every previously-matched event still
    # matches identically — this only ADDS coverage, never changes existing output.
    ctoken = (tag + " " + str(ev.get("facility") or "") + " " + str(ev.get("event_type") or "")).upper()
    ts = parse_event_ts(ev.get("timestamp"), reference=ingest_ts) or ingest_ts
    ts_ms = int(ts.timestamp() * 1000)
    # Interned (tracker 156): this is a per-DEVICE fact rebuilt on every syslog
    # line. See signals.observer_of — bounded, value-identical.
    observer = observer_of(
        host,
        ObserverType.DEVICE,
        collection_path="direct",   # the device itself emitted the event
        clock_quality="unknown",
    )

    # IS-IS adjacency — Nokia SR Linux emits "isisAdjacencyChange" in the message
    # with a nil appname; Cisco IOS uses %CLNS-5-ADJCHANGE. Checked before the
    # generic ADJCHANGE branch so CLNS isn't misfiled as "routing". Device-scoped,
    # peer = the IS-IS system-id (the shared adjacency identity, mirrors the catalog).
    if "ISISADJACENCYCHANGE" in msg.upper() or ("CLNS" in ctoken and "ADJ" in ctoken):
        sysid_m = re.search(r"\b([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\b", msg)
        peer = sysid_m.group(1) if sysid_m else ""
        tgt_m = re.search(r"to state\s+(\w+)", msg, re.IGNORECASE)
        state = _state_of(tgt_m.group(1)) if tgt_m else _state_of(msg)
        tokens: tuple[str, ...] = (host, peer) if peer else (host,)
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind=R_ISIS_ADJ.kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE,
            entity_id=host,
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|isis_adj|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens,
            metric_name="isis_adjacency",
            attrs={"peer": peer, "state": state, "tag": tag or "isisAdjacencyChange",
                   **_prov(R_ISIS_ADJ)},
        )

    if "ADJCHANGE" in ctoken or "ADJCHG" in ctoken:
        proto = "bgp" if "BGP" in ctoken else "ospf" if "OSPF" in ctoken else "routing"
        rule = _ADJ_RULES[proto]
        peer_m = _IP_RE.search(msg)
        peer = peer_m.group(1) if peer_m else ""
        state = _state_of(msg)
        tokens = (host, peer) if peer else (host,)
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind=rule.kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE,
            entity_id=host,
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|{proto}_adj|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens,
            metric_name=f"{proto}_adjacency",
            attrs={"peer": peer, "state": state, "tag": tag, **_prov(rule)},
        )

    # ── BGP session churn / prefix pressure (tracker 184) ───────────────────
    #
    # THE GAP THIS CLOSES. A real BGP fault emits MORE than %BGP-5-ADJCHANGE,
    # and the classifier used to drop those extra lines or flatten them into a
    # generic `device_alarm` with NO peer token, NO state and NO bgp_* kind —
    # measured on a generated enterprise outage as the single largest slice of
    # the invisible stream. The mnemonics, per vendor:
    #
    #   %BGP-5-NBR_RESET      the session was reset, WITH the reason         (IOS/IOS-XE/NX-OS)
    #     "Neighbor 10.0.0.200 reset (BGP Notification received)"
    #   %BGP-4-MAXPFX         prefix count crossed its warning threshold     (IOS/IOS-XE/NX-OS)
    #     "No. of prefix received from 10.0.0.200 (afi 0) reaches 12000, max 250000"
    #   %BGP-4-MAXPFXEXCEED   the limit was EXCEEDED — the peer is shut      (IOS/IOS-XE/NX-OS)
    #   %BGP-3-NOTIFICATION   a BGP NOTIFICATION was sent/received           (IOS/IOS-XE/NX-OS)
    #     "received from neighbor 10.0.0.200 6/4 (Administrative Reset) 0 bytes"
    #   Junos (rpd, appname carries no mnemonic — matched on the MESSAGE):
    #     "bgp_pp_recv:3435: NOTIFICATION received from 10.0.0.200 (External AS
    #      65001): code 6 (Cease) subcode 4 (Administrative Reset)"
    #     "bgp_rt_maxprefixes_check: 10.0.0.200 (External AS 65001): Configured
    #      maximum prefix-limit threshold(90%) exceeded for inet-unicast nlri: 9000"
    #
    # TWO KINDS, on purpose:
    #   * A NOTIFICATION always CLOSES the session (RFC 4271 §6 — "sends a
    #     NOTIFICATION message and closes the connection"), so it is a genuine
    #     `bgp_adjacency_change`, state down. It is the SAME fault the ADJCHANGE
    #     line reports from the other side of the FSM — a second, corroborating
    #     report from the same observer, exactly like %LINK + %LINEPROTO — and it
    #     is the ONLY line some platforms log, so filing it as an adjacency
    #     change is what makes those devices visible to the BGP signatures at all.
    #   * A RESET or a prefix-limit warning is NOT an adjacency transition: a
    #     reset reason may be a soft/administrative clear and a MAXPFX warning
    #     leaves the session ESTABLISHED. Calling either "adjacency down" would
    #     be a false session-down, so they get their own `bgp_route_churn` kind
    #     (state-bearing, peer-tokened) and stay honest about what they saw.
    #
    # NOT COVERED, and it is not a parser gap: PER-PREFIX churn (which prefixes
    # were withdrawn/re-announced) has NO syslog representation on any vendor —
    # it is BMP / BGP-UPDATE data. These mnemonics are the session-level shadow
    # of it, which is all syslog can carry.
    if ("BGP" in ctoken and ("NBR_RESET" in ctoken or "MAXPFX" in ctoken
                             or "NOTIFICATION" in ctoken)) \
            or re.search(r"\b(?:NOTIFICATION\s+(?:sent\s+to|received\s+from)|maximum\s+prefix-limit)\b",
                         msg, re.IGNORECASE):
        peer_m = _IP_RE.search(msg)
        peer = peer_m.group(1) if peer_m else ""
        # MNEMONIC FIRST, message second. %BGP-5-NBR_RESET states its reason as
        # "(BGP Notification received)" — reading the message first would file a
        # reset as a teardown. The message shapes are the JUNOS fallback only
        # (rpd puts no mnemonic in appname), and they are anchored on the
        # "sent to"/"received from" that a Cisco reason text never contains.
        if "NBR_RESET" in ctoken:
            subtype = "nbr_reset"
        elif "MAXPFX" in ctoken:
            subtype = "maxpfx"
        elif "NOTIFICATION" in ctoken:
            subtype = "notification"
        elif re.search(r"\bmaximum\s+prefix-limit\b", msg, re.IGNORECASE):
            subtype = "maxpfx"
        else:
            subtype = "notification"
        notify = subtype == "notification"
        maxpfx = subtype == "maxpfx"
        # The peer was actually torn down: an explicit limit-exceeded/shutdown.
        shut = bool(re.search(r"\b(?:exceed(?:ed|s)?|shut\s?down|shutdown|disabl\w*)\b",
                              msg, re.IGNORECASE))
        # The reason a vendor puts in parentheses: "(BGP Notification received)",
        # "(Administrative Reset)", "(Cease)". The LAST one that is not vendor
        # bookkeeping — Cisco trails "(afi 0)" and Junos "(External AS 65001)" /
        # "(instance master)" alongside the real reason. Bounded: untrusted text.
        reason = ""
        for cand in re.findall(r"\(([^)\n]{1,64})\)", msg):
            if re.match(r"(?:afi|external\s+as|internal\s+as|instance|as)\b|^[\d.%\s]+$",
                        cand, re.IGNORECASE):
                continue
            reason = cand
        # NOTIFICATION code/subcode ("6/4" on IOS; "code 6 ... subcode 4" on Junos).
        code_m = (re.search(r"\b(\d{1,2})/(\d{1,2})\b", msg)
                  or re.search(r"\bcode\s+(\d{1,2})\b[^\n]{0,40}?\bsubcode\s+(\d{1,3})\b",
                               msg, re.IGNORECASE))
        code = f"{code_m.group(1)}/{code_m.group(2)}" if code_m else ""
        # Prefix counts: IOS "reaches 12000, max 250000"; Junos "nlri: 9000".
        cnt_m = (re.search(r"\breaches\s+(\d{1,10})\b", msg, re.IGNORECASE)
                 or re.search(r"\bnlri:\s*(\d{1,10})\b", msg, re.IGNORECASE)
                 or re.search(r":\s*(\d{1,10})\s+exceed", msg, re.IGNORECASE))
        pfx_count = cnt_m.group(1) if cnt_m else ""
        max_m = (re.search(r"\bmax(?:imum)?[\s:]+(\d{1,10})\b", msg, re.IGNORECASE)
                 or re.search(r"\blimit\s+(\d{1,10})\b", msg, re.IGNORECASE))
        pfx_max = max_m.group(1) if max_m else ""
        tokens = (host, peer) if peer else (host,)
        if notify:
            # A NOTIFICATION closes the session — a real adjacency transition.
            return Signal(
                tenant_id=tenant, ts=ts, source=Source.SYSLOG,
                kind=R_BGP_NOTIFY.kind, observer=observer,
                modality_class=ModalityClass.CONTROL_PLANE,
                entity_type=EntityType.DEVICE, entity_id=host,
                severity=Severity.HIGH,
                # `notify` keeps this distinct from the ADJCHANGE branch's id, so
                # both reports of one teardown survive in the same millisecond.
                native_id=f"{host}|bgp_adj|notify|{peer or '?'}|{code or '-'}|down|{ts_ms}",
                entity_tokens=tokens, metric_name="bgp_adjacency",
                attrs={"peer": peer, "state": "down", "subtype": "notification",
                       "code": code, "reason": reason, "tag": tag,
                       **_prov(R_BGP_NOTIFY)},
            )
        # A limit that was EXCEEDED shuts the peer; a threshold warning does not.
        state = "down" if (maxpfx and shut) else "churn"
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.SYSLOG,
            kind=R_BGP_CHURN.kind, observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=host,
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=(f"{host}|bgp_churn|{subtype}|{peer or '?'}|"
                       f"{pfx_count or '-'}|{state}|{ts_ms}"),
            entity_tokens=tokens, metric_name="bgp_route_churn",
            attrs={"peer": peer, "state": state, "subtype": subtype,
                   "reason": reason, "prefix_count": pfx_count,
                   "prefix_max": pfx_max, "tag": tag, **_prov(R_BGP_CHURN)},
        )

    if ("LINK" in ctoken or "LINEPROTO" in ctoken) and "UPDOWN" in ctoken:
        if_m = _IF_RE.search(msg)
        ifname = if_m.group(1) if if_m else "unknown"
        state = _state_of(msg)
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind=R_LINK.kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE,
            entity_id=f"{host}:{ifname}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|link|{ifname}|{state}|{ts_ms}",
            entity_tokens=(host,),   # tracker 168: entity_id is already host:ifname
            metric_name="link_state",
            attrs={"interface": ifname, "state": state, "tag": tag,
                   **_prov(R_LINK)},
        )

    # LLDP neighbor change — cEOS %LLDP-5-NEIGHBOR_NEW/REMOVED; SR Linux emits
    # "remotePeerAdded/remotePeerRemoved" in the message with a nil appname.
    # Interface-scoped: a vanished neighbor cross-checks the IS-IS/BGP adjacency.
    if ("LLDP" in ctoken and "NEIGHBOR" in ctoken) or "REMOTEPEER" in msg.upper():
        if_m = re.search(r"on interface\s+([A-Za-z][\w/.\-]*)", msg, re.IGNORECASE) or _IF_RE.search(msg)
        ifname = if_m.group(1) if if_m else "unknown"
        if re.search(r"\b(?:removed|deleted|aged)\b", msg, re.IGNORECASE):
            state = "down"
        elif re.search(r"\b(?:added|new)\b", msg, re.IGNORECASE):
            state = "up"
        else:
            state = "unknown"
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind=R_LLDP.kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE,
            entity_id=f"{host}:{ifname}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|lldp|{ifname}|{state}|{ts_ms}",
            entity_tokens=(host,),   # tracker 168: entity_id is already host:ifname
            metric_name="lldp_neighbor",
            attrs={"interface": ifname, "state": state, "tag": tag or "remotePeer",
                   **_prov(R_LLDP)},
        )

    # STP topology change — cEOS %SPANTREE-6-INTERFACE_DEL/ADD/STATE. Interface-
    # scoped; prefer the transition target ("...to learning/forwarding").
    #
    # TRACKER 184 — TCN ATTRIBUTION. A domain-wide topology-change notification
    # names NO interface: Cisco IOS/IOS-XE "%SPANTREE-5-TOPOTRAP: Topology Change
    # Trap for instance MST0" (PVST: "... for vlan 100"). The old branch fell back
    # to the literal string "unknown", so EVERY TCN a switch ever logged landed on
    # the SYNTHETIC entity `<host>:unknown` — one fake interface node per device
    # that fused unrelated topology changes and collapsed same-millisecond TCNs
    # onto one identity. There is nothing interface-shaped to key on, so a TCN is
    # now keyed on the DEVICE, with the STP INSTANCE/VLAN it names carried as a
    # device-local grounding token (tracker 168: `MST0` and `vlan100` exist on
    # every switch in the estate, so they are qualified, never bare).
    #   1. "Interface X ..."     → that interface   (unchanged; every existing line)
    #   2. a bare port name      → that port        (e.g. "New Root Port is Gi0/1")
    #   3. an instance / VLAN    → the DEVICE, token <host>:mst0 / <host>:vlan100
    #   4. nothing at all        → the DEVICE
    if "SPANTREE" in tag:
        if_m = _IF_RE.search(msg) or re.search(
            r"\b((?:Gi|Te|Fa|Po|Port-channel|Eth\w*|GigabitEthernet|TenGigE)[\d][\w/.\-]*)\b", msg)
        ifname = if_m.group(1) if if_m else ""
        inst_m = re.search(r"\binstance\s+([A-Za-z0-9_\-]{1,32})\b", msg, re.IGNORECASE)
        vlan_m = re.search(r"\bvlan\s*(\d{1,4})\b", msg, re.IGNORECASE)
        # `instance` is the vendor's own token (what telemetry-catalog's
        # stp_topology_notification family labels `stp_instance`); `inst_tok` is
        # the device-local grounding token, which prefixes a PVST VLAN so
        # `vlan100` can never collide with an MST instance NAMED "100".
        if inst_m:
            instance = inst_m.group(1)
            inst_tok = instance.lower()
        elif vlan_m:                       # PVST names a VLAN, not an MST instance
            instance = vlan_m.group(1)
            inst_tok = f"vlan{instance}"
        else:
            mst_m = re.search(r"\b(MST\d{1,4})\b", msg)
            instance = mst_m.group(1) if mst_m else ""
            inst_tok = instance.lower()
        tgt_m = re.search(r"\bto\s+(forwarding|learning|discarding|blocking)\b", msg, re.IGNORECASE)
        if tgt_m:
            state = "up" if tgt_m.group(1).lower() in ("forwarding", "learning") else "down"
        elif re.search(r"\b(?:removed|discarding|blocking)\b", msg, re.IGNORECASE):
            state = "down"
        elif re.search(r"\b(?:added|forwarding|learning)\b", msg, re.IGNORECASE):
            state = "up"
        else:
            state = "unknown"
        rule_stp = R_STP_IF if ifname else R_STP_TCN
        etype_stp = EntityType.INTERFACE if ifname else EntityType.DEVICE
        eid_stp = f"{host}:{ifname}" if ifname else host
        # tracker 168: an interface-scoped signal already carries the port in its
        # entity_id; a device-scoped one qualifies the instance/VLAN with the host.
        toks_stp = ((host,) if ifname
                    else (host,) + _device_local(host, inst_tok))
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind=rule_stp.kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=etype_stp,
            entity_id=eid_stp,
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            # An interface-scoped STP signal keeps its identity BYTE-FOR-BYTE (the
            # port is the content, and those lines never collapsed). Only the
            # port-less TCN gets a new one: the instance is the only content it
            # carries, and without it two TCNs for two different instances in one
            # millisecond were ONE signal.
            native_id=(f"{host}|stp|{ifname}|{state}|{ts_ms}" if ifname else
                       f"{host}|stp_tcn|{instance or '?'}|{state}|{ts_ms}"),
            entity_tokens=toks_stp,
            metric_name="stp_state",
            attrs={"interface": ifname, "instance": instance,
                   "state": state, "tag": tag, **_prov(rule_stp)},
        )

    # VTEP / NVE peer reachability (DC overlay) — NX-OS %NVE-5-BFD_CC_STATE_CHANGE
    # ("BFD CC down for bfd-neighbor <remote-VTEP>"): the underlay→VTEP liveness that
    # gates VXLAN-encapsulated traffic. Device-scoped; the remote VTEP IP is a
    # grounding token so it binds to the underlay reachability/BGP to that loopback.
    if "NVE" in ctoken or ("VTEP" in ctoken and "BFD" in (ctoken + " " + msg.upper())):
        peer_m = _IP_RE.search(msg)
        peer = peer_m.group(1) if peer_m else ""
        state = _state_of(msg)
        tokens = (host, peer) if peer else (host,)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.SYSLOG, kind=R_VTEP.kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=host,
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|vtep|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens, metric_name="vtep_state",
            attrs={"vtep": peer, "state": state, "tag": tag, **_prov(R_VTEP)},
        )

    # EVPN MAC mobility / duplicate-MAC freeze (DC overlay) — the cross-VTEP analog
    # of a local mac_flap: Arista %EVPN-3-BLACKLISTED_DUPLICATE_MAC, NX-OS
    # %HMM-2-DUP_HOSTS, %L2FM-2-L2FM_VXLAN_MAC_MOVE_PORT_DOWN. Checked BEFORE the
    # local mac_flap branch (NX-OS "VXLAN_MAC_MOVE" else hits it). Device-scoped; the
    # MAC, VLAN, VNI and remote VTEP are grounding tokens.
    if ("EVPN" in ctoken or "HMM" in ctoken or "DUP_HOST" in ctoken
            or "VXLAN_MAC_MOVE" in ctoken
            or re.search(r"\b(?:blacklisted|duplicate host|between NVE and)\b", msg, re.IGNORECASE)):
        mac_m = re.search(
            r"\b([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b", msg)
        mac = mac_m.group(1) if mac_m else ""
        vlan_m = re.search(r"\bvlan\s*(\d+)\b", msg, re.IGNORECASE)
        vlan = vlan_m.group(1) if vlan_m else ""
        vni_m = re.search(r"\bvni\s*(\d+)\b", msg, re.IGNORECASE)
        vni = vni_m.group(1) if vni_m else ""
        vtep_m = re.search(r"VTEP\s+(\d{1,3}(?:\.\d{1,3}){3})", msg, re.IGNORECASE)
        vtep = vtep_m.group(1) if vtep_m else ""
        blacklisted = bool(re.search(r"blacklist|frozen|disabl|port[\s-]?down", msg, re.IGNORECASE))
        tokens = tuple(t for t in (host, mac, f"vlan{vlan}" if vlan else "",
                                   f"vni{vni}" if vni else "", vtep) if t)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.SYSLOG, kind=R_EVPN.kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=host,
            severity=Severity.HIGH,
            native_id=f"{host}|evpn_mac|{mac or '?'}|vlan{vlan or '?'}|{ts_ms}",
            entity_tokens=tokens or (host,), metric_name="evpn_mac_move",
            attrs={"mac": mac, "vlan": vlan, "vni": vni, "vtep": vtep,
                   "blacklisted": blacklisted, "tag": tag, **_prov(R_EVPN)},
        )

    # First-hop redundancy (HSRP/VRRP) state change — Cisco %HSRP-5-STATECHANGE /
    # %STANDBY-6-STATECHANGE, %VRRP-6-STATECHANGE; Arista %VRRP-6-... A member's role
    # transition; "-> Active"/"-> Master" is a TAKEOVER (a failover happened). Device-
    # scoped (the FHRP group lives on the device); group + interface/VLAN are grounding
    # tokens so a gateway-reachability probe on the adjacent segment correlates via the
    # existing seam/adjacency rung (the standby going Active never teaches grounding
    # the word "HSRP").
    if "HSRP" in ctoken or "VRRP" in ctoken or "STANDBY" in ctoken:
        proto = "vrrp" if "VRRP" in ctoken else "hsrp"
        grp_m = re.search(r"\b[Gg]r(?:ou)?p\s+(\d+)\b", msg)
        group = grp_m.group(1) if grp_m else ""
        if_m = _IF_RE.search(msg) or re.search(
            r"\b((?:Vl(?:an)?|Gi|Te|Fa|Po|Port-channel|Eth\w*|GigabitEthernet|TenGigE)[\d][\w/.\-]*)\b", msg)
        ifname = if_m.group(1) if if_m else "unknown"
        # The NEW role: the target of an "X -> Y" transition, else the trailing state word.
        tgt_m = re.search(r"->\s*(\w+)", msg) or re.search(r"\bstate\s+(\w+)\s*$", msg, re.IGNORECASE)
        role = (tgt_m.group(1) if tgt_m else "").lower()
        takeover = role in ("active", "master")
        # tracker 168: the interface and the FHRP group number are both
        # DEVICE-LOCAL. Qualified, they still bind this event to THIS device's
        # own interface node (the stated intent); bare, `grp1` and `Gi0/5` welded
        # every HSRP-speaking device in the estate together. Two routers in one
        # FHRP group must relate through topology, not through a group number.
        tokens = (host,) + _device_local(host, ifname,
                                         f"grp{group}" if group else "")
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind=R_FHRP.kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE,
            entity_id=host,
            severity=Severity.HIGH if takeover else Severity.WARN,
            native_id=f"{host}|fhrp|{proto}|{ifname}|grp{group or '?'}|{role or '?'}|{ts_ms}",
            entity_tokens=tokens or (host,),
            metric_name="fhrp_state",
            attrs={"proto": proto, "group": group, "interface": ifname,
                   "state": role, "tag": tag, **_prov(R_FHRP)},
        )

    # MAC flap / move — a host MAC oscillating between two ports: an L2 loop, a
    # dual-homing / NIC-teaming misconfig, or a duplicate MAC. Cisco %SW_MATM-4-
    # MACFLAP_NOTIF, NX-OS %L2FM-4-L2FM_MAC_MOVE, Arista %MACFLAP. Device-scoped; the
    # MAC, VLAN and the two ports are grounding tokens so it binds to the interface
    # metrics on either port.
    if ("MACFLAP" in ctoken or "MAC_MOVE" in ctoken
            or re.search(r"\b(?:is flapping between|has moved between|mac[\s_-]?move|mac[\s_-]?flap)\b",
                         msg, re.IGNORECASE)):
        mac_m = re.search(
            r"\b([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b", msg)
        mac = mac_m.group(1) if mac_m else ""
        vlan_m = re.search(r"\bvlan\s*(\d+)\b", msg, re.IGNORECASE)
        vlan = vlan_m.group(1) if vlan_m else ""
        ports = re.findall(
            r"\b(?:Gi|Te|Fa|Po|Port-channel|Eth\w*|GigabitEthernet|TenGigE)[\d][\w/.\-]*", msg)
        # tracker 168: the MAC is genuinely global — two devices seeing the same
        # MAC flap ARE related, and that is the relation this signal is about.
        # The VLAN id and the port names are device-local (`vlan10` and `Gi0/1`
        # exist on almost every switch), so they are qualified: the binding to
        # THIS device's port metrics is preserved, the estate-wide weld is not.
        # tracker 184 — THE MOVE NEEDS A STATE. The signal carried no
        # `attrs["state"]` at all, so `aggregation.parsed_state` read "" and
        # `health_of` made NO health claim: a MAC move could never contribute a
        # state transition, and a device whose MACs are moving looked exactly
        # like a device whose MACs are not. It is a one-way symptom (no vendor
        # logs "the MAC stopped moving"), so the state is the KIND of movement,
        # never a recovery word: "flapping" (oscillating between two ports) or
        # "moved" (a single relocation). Both are outside
        # `aggregation.RECOVERY_STATES`, so both read as unhealthy — which is
        # the truth about a moving MAC.
        flapping = bool(re.search(r"\bflap", msg, re.IGNORECASE) or "MACFLAP" in ctoken)
        state = "flapping" if flapping else "moved"
        # NX-OS names the DIRECTION ("has moved from Eth1/1 to Eth1/2"); the
        # Cisco flap line only names the pair ("between port A and port B"), so
        # from/to stay empty rather than guessing an order.
        dir_m = re.search(
            r"\bfrom\s+((?:Gi|Te|Fa|Po|Port-channel|Eth\w*|GigabitEthernet|TenGigE)[\d][\w/.\-]*)"
            r"\s+to\s+((?:Gi|Te|Fa|Po|Port-channel|Eth\w*|GigabitEthernet|TenGigE)[\d][\w/.\-]*)",
            msg, re.IGNORECASE)
        from_port = dir_m.group(1) if dir_m else ""
        to_port = dir_m.group(2) if dir_m else ""
        tokens = ((host,) + ((mac,) if mac else ())
                  + _device_local(host, f"vlan{vlan}" if vlan else "", *ports[:2]))
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind=R_MAC_FLAP.kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE,
            entity_id=host,
            severity=Severity.HIGH,
            native_id=f"{host}|mac_flap|{mac or '?'}|vlan{vlan or '?'}|{ts_ms}",
            entity_tokens=tokens or (host,),
            metric_name="mac_flap",
            attrs={"mac": mac, "vlan": vlan, "state": state,
                   "port_a": ports[0] if ports else "",
                   "port_b": ports[1] if len(ports) > 1 else "",
                   "from_port": from_port, "to_port": to_port, "tag": tag,
                   **_prov(R_MAC_FLAP)},
        )

    # Generic device-alarm fallback (#80 §4 keystone) — the SAFETY NET. Nothing
    # above recognized this event, but if the DEVICE itself flagged it at warning
    # or worse it is still real evidence: one canonical `device_alarm` signal so it
    # grounds + correlates + tiers like any other (no per-mnemonic branch). Below
    # the floor (notice/info/debug) stays a searchable log, never an RCA signal.
    sev_num = syslog_severity_num(ev, tag)
    if sev_num is not None and sev_num <= ALARM_SEVERITY_FLOOR:
        if_m = _IF_RE.search(msg)
        ifname = if_m.group(1) if if_m else ""
        facility = (str(ev.get("facility") or "")
                    or (tag.split("-", 1)[0].lstrip("%") if "-" in tag else tag.lstrip("%")))
        mnem = tag.rsplit("-", 1)[-1] if "-" in tag else str(ev.get("event_type") or "")
        toks_: tuple[str, ...]
        if ifname:
            etype_, eid_, toks_ = EntityType.INTERFACE, f"{host}:{ifname}", (host,)   # tracker 168
        else:
            etype_, eid_, toks_ = EntityType.DEVICE, host, (host,)
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind=R_SYSLOG_ALARM.kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=etype_,
            entity_id=eid_,
            severity=_severity_from_num(sev_num),
            # tracker 198: the message text is the discriminator — without it two
            # DISTINCT unrecognized lines sharing facility+mnemonic(+interface) in
            # one millisecond collapsed onto one signal_id and one of them was
            # dropped as a "replay". Byte-identical redelivery still dedups.
            native_id=_tagged_native_id(
                f"{host}|alarm|{facility}|{mnem or '?'}|{ifname or '-'}|{ts_ms}", msg),
            entity_tokens=toks_,
            metric_name="device_alarm",
            attrs={"facility": facility, "mnemonic": mnem, "severity": sev_num,
                   "interface": ifname, "tag": tag, "text": msg[:256],
                   **_prov(R_SYSLOG_ALARM)},
        )

    return None


# ── SNMP traps (netops.snmptrap) ──────────────────────────────────────────────
#
# Traps are discrete control-plane RCA evidence — often the FIRST hard signal of
# a failure. But the trap firehose is noisy and full of vendor-specific
# notifications, so ONLY a small, explicit set of high-value, well-standardized
# families becomes a correlation signal. Everything else stays searchable in
# OpenSearch and creates NO RCA signal (trap_control_signal returns None → the
# caller counts it as dropped). Expand the allowlist deliberately, with fixtures.

# Standard SNMPv2-MIB notification OIDs (RFC 3418) + BGP4-MIB (RFC 4273) and its
# deprecated notification root. Classifying by OID is more robust than by the
# rendered trap_name (which varies by agent MIB load).
_TRAP_COLDSTART = "1.3.6.1.6.3.1.1.5.1"
_TRAP_WARMSTART = "1.3.6.1.6.3.1.1.5.2"
_TRAP_LINKDOWN  = "1.3.6.1.6.3.1.1.5.3"
_TRAP_LINKUP    = "1.3.6.1.6.3.1.1.5.4"
_TRAP_BGP_ESTABLISHED = "1.3.6.1.2.1.15.7.1"
_TRAP_BGP_BACKWARD    = "1.3.6.1.2.1.15.7.2"
_TRAP_BGP_ESTABLISHED_LEGACY = "1.3.6.1.2.1.0.1"  # deprecated BGP4-MIB root
_TRAP_BGP_BACKWARD_LEGACY    = "1.3.6.1.2.1.0.2"

# Varbind OIDs carrying the affected entity identity.
_VB_IFINDEX = "1.3.6.1.2.1.2.2.1.1"
_VB_IFNAME  = "1.3.6.1.2.1.31.1.1.1.1"
_VB_IFDESCR = "1.3.6.1.2.1.2.2.1.2"
_VB_BGP_PEER_ADDR = "1.3.6.1.2.1.15.3.1.7"  # bgpPeerRemoteAddr


def _trap_varbind(ev: dict, *oid_prefixes: str) -> str:
    """First varbind value whose OID equals or is indexed under one of the given
    column OIDs (e.g. ifName.7 matches the ifName column). '' when absent."""
    for vb in ev.get("varbinds") or []:
        oid = str(vb.get("oid") or "")
        for p in oid_prefixes:
            if oid == p or oid.startswith(p + "."):
                return str(vb.get("value") or "")
    return ""


def _trap_varbind_byname(ev: dict, *name_substrs: str) -> str:
    """First varbind whose RESOLVED name contains one of the substrings. The MIB
    index now names varbinds, so a vendor's peer/interface column matches by its
    object name without hardcoding its enterprise OID (e.g. Arista's BGP peer
    column resolves to a name containing 'peer')."""
    for vb in ev.get("varbinds") or []:
        nm = str(vb.get("name") or "").lower()
        if nm and any(s in nm for s in name_substrs):
            return str(vb.get("value") or "")
    return ""


def _trap_interface(ev: dict) -> str:
    """Affected interface identity from the trap varbinds: prefer ifName/ifDescr
    (matches the metric entity model device:ifName); fall back to ifIndex, then to
    any vendor varbind whose resolved name looks interface-ish."""
    return (_trap_varbind(ev, _VB_IFNAME)
            or _trap_varbind(ev, _VB_IFDESCR)
            or _trap_varbind(ev, _VB_IFINDEX)
            or _trap_varbind_byname(ev, "ifname", "ifdescr", "interfacename", "intfname")
            or "unknown")


def _trap_content(ev: dict, name: str, etype: str) -> str:
    """Canonical rendering of what a trap actually SAID — its resolved name, its
    normalized event_type and its varbinds in wire order — for the generic-alarm
    content tag (tracker 198). Deterministic: the varbind list order is the one
    the receiver emitted and JSON round-trips it unchanged, so a redelivery of
    the same trap renders byte-identically and still dedups.
    """
    vbs = ev.get("varbinds") or []
    parts = [name, etype]
    if isinstance(vbs, list):
        for vb in vbs:
            if isinstance(vb, dict):
                parts.append(f"{vb.get('oid')}={vb.get('value')}")
            else:
                parts.append(str(vb))
    return "\x1f".join(str(x) for x in parts)


def trap_control_signal(ev: dict, tenant: str, ingest_ts: datetime) -> Signal | None:
    """Normalized SNMP trap → one control_plane Signal for the high-value
    families only (link state, device restart, BGP transition); None for every
    unclassified trap (kept searchable, never an RCA signal). Mirrors the
    syslog/metric entity model so trap evidence binds to the same interface/peer.

    HA-failover, environmental/hardware-health, and threshold-alarm traps are
    vendor-specific OIDs — deliberately deferred to a per-vendor fixture-driven
    follow-up rather than guessed (the anti-noise guardrail).

    tracker 198: the generic `device_alarm` fallback folds a hash of the trap's
    own content (name + event_type + varbinds) into its native_id, so two
    unclassified traps of one OID that differ only in their varbinds no longer
    share a signal_id inside a millisecond. Same informational row-count note as
    `syslog_control_signal`; redelivery idempotency is preserved."""
    # G2 canonicalization: the device MUST be a real inventory id (attributed by the
    # Go receiver's G2a — source-IP/sysName/agent-addr — and, when that fails, by the
    # caller's C7.1 EntityResolver). We deliberately do NOT fall back to the raw source
    # IP (ev["host"]): a NAT-collapsed source would otherwise form a PHANTOM device
    # (e.g. "192.0.2.120:Ethernet1") that never correlates with the real device's
    # metrics/syslog. An unattributed trap stays searchable in OpenSearch but is not an
    # RCA signal — the same honesty guardrail as an unclassified trap.
    device = str(ev.get("device") or "")
    if not device:
        return None
    oid = str(ev.get("trap_oid") or "")
    name = str(ev.get("trap_name") or "")
    ts = parse_event_ts(ev.get("timestamp"), reference=ingest_ts) or ingest_ts
    ts_ms = int(ts.timestamp() * 1000)
    # v1/v2c traps are spoofable (authenticated=false); recorded as evidence but
    # the flag lets the engine weight it. v3-auth traps are trustworthy.
    authed = bool(ev.get("authenticated"))
    observer = Observer(
        observer_id=device,
        observer_type=ObserverType.DEVICE,
        collection_path="direct",   # the device itself emitted the trap
        clock_quality="unknown",
    )

    # Link state — interface-scoped (binds to interface metrics).
    if oid in (_TRAP_LINKDOWN, _TRAP_LINKUP) or name in ("linkDown", "linkUp"):
        state = "down" if (oid == _TRAP_LINKDOWN or name == "linkDown") else "up"
        iface = _trap_interface(ev)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=R_TRAP_LINK.kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE, entity_id=f"{device}:{iface}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{device}|trap_link|{iface}|{state}|{ts_ms}",
            entity_tokens=(device,), metric_name="link_state",   # tracker 168
            attrs={"interface": iface, "state": state, "trap_oid": oid,
                   "authenticated": authed, **_prov(R_TRAP_LINK)},
        )

    # Device restart — device-scoped lifecycle event.
    if oid in (_TRAP_COLDSTART, _TRAP_WARMSTART) or name in ("coldStart", "warmStart"):
        kind_type = "cold" if (oid == _TRAP_COLDSTART or name == "coldStart") else "warm"
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=R_TRAP_RESTART.kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=device,
            severity=Severity.HIGH,
            native_id=f"{device}|trap_restart|{kind_type}|{ts_ms}",
            entity_tokens=(device,), metric_name="device_restart",
            attrs={"restart": kind_type, "trap_oid": oid, "authenticated": authed,
                   **_prov(R_TRAP_RESTART)},
        )

    # BGP neighbor transition — device:peer scoped (binds to BGP peer metrics).
    if oid in (_TRAP_BGP_BACKWARD, _TRAP_BGP_ESTABLISHED,
               _TRAP_BGP_BACKWARD_LEGACY, _TRAP_BGP_ESTABLISHED_LEGACY):
        established = oid in (_TRAP_BGP_ESTABLISHED, _TRAP_BGP_ESTABLISHED_LEGACY)
        state = "up" if established else "down"
        peer = _trap_varbind(ev, _VB_BGP_PEER_ADDR)
        entity_id = f"{device}:{peer}" if peer else device
        tokens = (device, peer) if peer else (device,)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=R_TRAP_BGP.kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=entity_id,
            severity=Severity.WARN if established else Severity.HIGH,
            native_id=f"{device}|trap_bgp|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens, metric_name="bgp_adjacency",
            attrs={"peer": peer, "state": state, "trap_oid": oid,
                   "authenticated": authed, **_prov(R_TRAP_BGP)},
        )

    # Generic vendor classification via the normalized event_type (envelope, #32).
    # Catches vendor BGP/link/restart traps the standard-OID checks above miss
    # (e.g. Arista arista_bgp4_v2_backward_transition) — vendor-agnostic, keyed off
    # the MIB-decoded event_type, not a per-vendor OID hardcode. Same Signal shapes.
    etype = str(ev.get("event_type") or "").lower()
    if "bgp" in etype and any(k in etype for k in ("backward", "transition", "established", "neighbor", "fsm", "state")):
        established = "establish" in etype
        state = "up" if established else "down"
        peer = (_trap_varbind(ev, _VB_BGP_PEER_ADDR)
                or _trap_varbind_byname(ev, "peerremoteaddr", "peeraddr", "remoteaddr", "peer"))
        entity_id = f"{device}:{peer}" if peer else device
        tokens = (device, peer) if peer else (device,)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=R_TRAP_BGP_ETYPE.kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=entity_id,
            severity=Severity.WARN if established else Severity.HIGH,
            native_id=f"{device}|trap_bgp|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens, metric_name="bgp_adjacency",
            attrs={"peer": peer, "state": state, "trap_oid": oid, "event_type": etype,
                   "authenticated": authed, **_prov(R_TRAP_BGP_ETYPE)},
        )
    if "link" in etype and ("down" in etype or "up" in etype):
        state = "down" if "down" in etype else "up"
        iface = _trap_interface(ev)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=R_TRAP_LINK_ETYPE.kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE, entity_id=f"{device}:{iface}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{device}|trap_link|{iface}|{state}|{ts_ms}",
            entity_tokens=(device,), metric_name="link_state",   # tracker 168
            attrs={"interface": iface, "state": state, "trap_oid": oid, "event_type": etype,
                   "authenticated": authed, **_prov(R_TRAP_LINK_ETYPE)},
        )
    if "start" in etype and ("cold" in etype or "warm" in etype):
        kind_type = "cold" if "cold" in etype else "warm"
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=R_TRAP_RESTART_ETYPE.kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=device, severity=Severity.HIGH,
            native_id=f"{device}|trap_restart|{kind_type}|{ts_ms}",
            entity_tokens=(device,), metric_name="device_restart",
            attrs={"restart": kind_type, "trap_oid": oid, "event_type": etype,
                   "authenticated": authed, **_prov(R_TRAP_RESTART_ETYPE)},
        )

    # Generic device-alarm fallback (#80 §4 keystone) — an unclassified trap is
    # still real evidence IF the device/MIB flagged it at warning or worse (the MIB
    # severity the Go receiver's trapMeta resolved). One canonical `device_alarm`
    # signal so vendor alarm traps with no dedicated branch still ground + correlate.
    # Below the floor stays searchable in OpenSearch, never an RCA signal.
    sev_num = _SEVERITY_NUM.get(str(ev.get("severity") or "").strip().lower())
    if sev_num is not None and sev_num <= ALARM_SEVERITY_FLOOR:
        iface = _trap_interface(ev)
        toks_: tuple[str, ...]
        if iface and iface != "unknown":
            etype_, eid_, toks_ = EntityType.INTERFACE, f"{device}:{iface}", (device,)   # tracker 168
        else:
            etype_, eid_, toks_ = EntityType.DEVICE, device, (device,)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=R_TRAP_ALARM.kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=etype_, entity_id=eid_, severity=_severity_from_num(sev_num),
            # tracker 198 (same defect as the syslog generic alarm above): the OID
            # alone does not identify the EVENT — two unclassified traps of one
            # OID differing only in their varbinds (different entity, different
            # threshold) collided in a millisecond. The varbind rendering is the
            # trap's content; it is stable under redelivery.
            native_id=_tagged_native_id(
                f"{device}|alarm|{oid or '?'}|{ts_ms}", _trap_content(ev, name, etype)),
            entity_tokens=toks_, metric_name="device_alarm",
            attrs={"trap_oid": oid, "trap_name": name, "event_type": etype,
                   "category": str(ev.get("category") or ""), "severity": sev_num,
                   "authenticated": authed,
                   "interface": iface if iface != "unknown" else "",
                   **_prov(R_TRAP_ALARM)},
        )

    return None  # unclassified — searchable in OpenSearch, no RCA signal


# ---------------------------------------------------------------------------
# Port Intelligence physical-layer event producer (#94 P3b). Classifies
# transceiver / optics / DOM / FEC syslog into the sig.ent.spdc.* evidence
# kinds so the physical-layer signatures fire from real device logs. Vendor
# patterns are recognized off the VRL-parsed envelope (facility/mnemonic/
# message), not a per-vendor hardcode; an unrecognized line returns None
# (searchable, never a spurious RCA signal). Pure + table-driven + tested.

# (regex, kind, entity=interface?, severity) — ordered; first match wins. The
# kinds line up with the sig.ent.spdc catalog's required/supporting evidence.
#
# H11 (ReDoS): these rules run on device-supplied syslog text on the single
# event loop. The original patterns chained unbounded `.*` gaps between the
# keywords ("(rx|receive).*(power).*(low|below).*(alarm|threshold)"), whose
# backtracking on a keyword-dense non-matching line was superlinear — a 4KB
# adversarial message cost ~3.9s and froze consume/healthz/engine. Two bounds
# fix the class without changing what a real vendor line classifies as:
#   1. every inter-keyword gap is `[^\n]{0,80}` — real DOM/FEC/optics lines put
#      their keywords within a few words of each other, never 80+ chars apart,
#      and a bounded gap makes backtracking cost a small constant;
#   2. the classification token itself is capped (_PORT_EVENT_TEXT_CAP) before
#      any regex runs, so total work is bounded regardless of message size.
# W1b: DERIVED FROM `RULES` (the `lane == "port"` rules, in table order — this
# list is first-match-wins, so the order IS behaviour and is part of
# `rules_hash`). The tuple shape is kept because `_build_syslog_screen`, the
# union pre-filter and the screen's own tests consume it, and because a test
# monkeypatches an extra rule onto it to prove the screen fails open.
_PORT_EVENT_RULES: list[tuple[re.Pattern, str, bool, Severity]] = [
    (rule.pattern, rule.kind, rule.entity_type == "interface", rule.severity)
    for rule in RULES if rule.lane == "port"
    if rule.pattern is not None and rule.severity is not None
]
_PORT_RULE_BY_KIND: dict[str, Rule] = {r.kind: r for r in _PORT_RULES}

# H11: classification never needs more text than this — a real vendor DOM/FEC
# line is well under 2000 chars, and the cap bounds regex work on a hostile or
# corrupted oversized message BEFORE any pattern runs. The full message still
# rides the signal (attrs.message, its own 240-char cap) and OpenSearch.
_PORT_EVENT_TEXT_CAP = 2000

# TRACKER 156. Every syslog line used to run all of _PORT_EVENT_RULES — measured
# at 12 of the 16.5 regex searches per event, and for ordinary traffic
# (%LINK-3-UPDOWN, BGP adjacency, …) all 12 miss. This is the UNION of exactly
# those patterns, so it is a sound pre-filter: a union matches if and only if at
# least one alternative matches, therefore a message the union rejects cannot
# match any individual rule. It is built FROM the rules rather than hand-written,
# so it cannot drift out of sync when a rule is added.
#
# IGNORECASE is applied to the whole union even though a few rules are
# case-sensitive. That can only make the pre-filter MORE permissive — it may let
# a line through to the real chain that then matches nothing, which costs a few
# microseconds and changes no outcome. The direction that would be a bug
# (rejecting a line a rule would have matched) is impossible by construction.
_PORT_EVENT_PREFILTER = re.compile(
    "|".join(f"(?:{pat.pattern})" for pat, _k, _i, _s in _PORT_EVENT_RULES),
    re.IGNORECASE)

# P3 change B: the ingest screen is derived from BOTH classifiers' gates, so it
# is built here -- the first point at which every input to it exists. See
# `_build_syslog_screen` (above `syslog_control_signal`) for the contract.
_SYSLOG_SCREEN_LITERALS = _build_syslog_screen()


def _port_of(ev: dict) -> str:
    """Best-effort port/interface name from the parsed envelope."""
    for k in ("interface", "if_name", "ifname", "port"):
        v = ev.get(k)
        if v:
            return str(v)
    m = re.search(r"\b((?:Ethernet|Eth|Et|Gi|Te|Fo|Hu|xe-|ge-|et-)[\w./:-]+)", str(ev.get("message") or ""))
    return m.group(1) if m else ""


def port_event_signal(ev: dict, tenant: str, ingest_ts: datetime) -> Signal | None:
    """Transceiver/optics/DOM/FEC syslog → one device_telemetry Signal in the
    sig.ent.spdc evidence vocabulary; None for anything unrecognized. Feeds the
    physical-layer signatures (#94). Also the source of port_event_log rows."""
    host = str(ev.get("hostname") or ev.get("device") or "")
    if not host or host == "unknown":
        return None
    msg = str(ev.get("message") or "")
    # H11: cap BEFORE any regex — see _PORT_EVENT_TEXT_CAP. Each part is capped
    # on its own so an oversized message can never truncate away the structured
    # fields (facility/event_type/appname) a vendor line may classify on.
    ctoken = " ".join((
        msg[:_PORT_EVENT_TEXT_CAP],
        str(ev.get("facility") or "")[:256],
        str(ev.get("event_type") or "")[:256],
        str(ev.get("appname") or "")[:256],
    ))
    # One union search instead of twelve (tracker 156). Placed BEFORE the
    # timestamp parse and the Observer construction, because for a non-port line
    # those were pure waste too — an allocation and a date parse per event that
    # nothing ever read.
    if not _PORT_EVENT_PREFILTER.search(ctoken):
        return None
    ts = parse_event_ts(ev.get("timestamp"), reference=ingest_ts) or ingest_ts
    ts_ms = int(ts.timestamp() * 1000)
    # Interned (tracker 156): identical per-device Observer built on every event.
    observer = observer_of(
        host, ObserverType.DEVICE,
        collection_path="direct", clock_quality="unknown",
    )
    for pat, kind, iface_scoped, sev in _PORT_EVENT_RULES:
        if not pat.search(ctoken):
            continue
        # W1b: the table row this rule came from, for provenance + the hit
        # counter. `_PORT_EVENT_RULES` is derived from `_PORT_RULES`, so the
        # lookup always hits in production; it can miss only for a rule a TEST
        # injected, and such a rule then carries no provenance rather than
        # inventing a rule_id that is in no table.
        rule = _PORT_RULE_BY_KIND.get(kind)
        port = _port_of(ev)
        toks_: tuple[str, ...]
        if iface_scoped and port:
            etype_, eid_, toks_ = EntityType.INTERFACE, f"{host}:{port}", (host,)   # tracker 168
        else:
            etype_, eid_, toks_ = EntityType.DEVICE, host, (host,)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.SYSLOG, kind=kind,
            observer=observer, modality_class=ModalityClass.DEVICE_TELEMETRY,
            entity_type=etype_, entity_id=eid_, severity=sev,
            native_id=f"{host}|portevt|{kind}|{port or '-'}|{ts_ms}",
            entity_tokens=toks_, metric_name="port_event",
            attrs={"interface": port, "port_event": kind, "message": msg[:240],
                   **(_prov(rule) if rule is not None else {})},
        )
    return None


# ── clock-skew meta-finding (log-time standard S5 / rule R5) ──────────────────

# |origin − receive| beyond this many seconds on the syslog lane flags the
# device clock (Vector stamps clock_skew_s past the same tolerance; this guard
# re-checks so a stray/garbage field can never fabricate a finding).
SYSLOG_CLOCK_SKEW_TOLERANCE_S = 300.0


def clock_skew_signal(ev: dict, tenant: str, ingest_ts: datetime) -> Signal | None:
    """A syslog event whose origin timestamp disagrees with the pipeline's
    receive clock beyond tolerance → one per-device `clock_skew` META signal.

    The skew is measured at the ingest edge (Vector's normalize remap compares
    the parsed origin timestamp against now() and stamps `clock_skew_s`, signed
    seconds, positive = device clock ahead). This producer only VALIDATES and
    shapes it — no re-measurement, no guessing. Returns None when the event
    carries no (or an in-tolerance) skew stamp.

    MANAGEMENT_PLANE + platform observer by design: the platform is the witness
    (it compared the clocks), and the kind is INTENTIONAL_BLIND — the caller
    records it for operators but never buffers it into the engine window, so a
    wrong clock can't lend a fake corroborating plane to a real fault."""
    raw = ev.get("clock_skew_s")
    if raw is None or isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    skew = float(raw)
    if abs(skew) <= SYSLOG_CLOCK_SKEW_TOLERANCE_S:
        return None
    host = str(ev.get("hostname") or "")
    if not host or host == "unknown":
        return None
    ts = parse_event_ts(ev.get("timestamp"), reference=ingest_ts) or ingest_ts
    direction = "ahead" if skew > 0 else "behind"
    return Signal(
        tenant_id=tenant,
        ts=ts,
        source=Source.SYSLOG,
        kind="clock_skew",
        observer=Observer(
            observer_id="log-pipeline",
            observer_type=ObserverType.PLATFORM,
            collection_path="syslog",
            clock_quality="ntp",   # the pipeline host is NTP-synced; the device is suspect
        ),
        modality_class=ModalityClass.MANAGEMENT_PLANE,
        entity_type=EntityType.DEVICE,
        entity_id=host,
        severity=Severity.WARN,
        native_id=f"{host}|clock_skew|{int(ts.timestamp() * 1000)}",
        entity_tokens=(host,),
        metric_name="clock_skew_s",
        value=skew,
        attrs={
            "clock_skew_s": skew,
            "tolerance_s": SYSLOG_CLOCK_SKEW_TOLERANCE_S,
            "direction": direction,
            "lane": "syslog",
        },
    )
