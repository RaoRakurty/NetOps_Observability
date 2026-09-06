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

Every Signal the syslog / trap / port classifiers emit carries PROVENANCE in
`attrs` -- `rule_id`, `parser_rev`, `rules_hash`, `fidelity` -- so a stored
signal says which rule of which parser revision produced it. See "PARSER
PROVENANCE + THE RULE TABLE" below; none of it touches signal identity.

A3: those three classifiers are no longer hand-written `if`/`elif` chains. The
rules live in `telemetry-catalog/events.yaml` -- the same rows the catalog's own
conformance reader executes, so there is exactly ONE copy of every vendor
grammar -- are baked into the checked-in `parser_rules.py` (the image does not
ship the catalog), and `classify()` below is a generic interpreter over them.
Adding a symptom is a catalog ROW plus a fixture, not a code branch.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Callable, Iterable
from datetime import datetime, timezone

from episodes import EpisodeDetector, EpisodeEvent
from parser_rules import BAKED_RULES_HASH, RULES
from parser_rules import CATALOG_EVENT_FIDELITY as _CATALOG_EVENT_FIDELITY
from parser_rules import PARSER_REV as _PARSER_REV
from regex_screen import pattern_screen
from rule_model import (
    FIDELITY_UNCATALOGUED,
    MISS,
    Ctx,
    Emit,
    Guard,
    Rule,
    rules_hash,
)
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
    # Device configuration change (A9 follow-up) — %SYS-5-CONFIG_I / UI_COMMIT
    # and the CISCO-CONFIG-MAN-MIB / JUNIPER-CFGMGMT-MIB traps. The "what
    # changed?" evidence: consumed as an OPTIONAL clause by the adjacency
    # families and the security hardening-drift story, never as a verdict of its
    # own (it is emitted at `info`, below `severity_open_floor`, so it cannot
    # open an RCA object by itself).
    "device_config_change",
    # DC overlay (P2)
    "vtep_state_change", "evpn_mac_move",
    # trap lane
    "device_restart",
    # generic-alarm keystone (#80 §4)
    "device_alarm",
    # metric episodes (main.py metric_identity + C6 flow)
    "if_metric_anomaly", "bgp_state_anomaly", "device_resource_anomaly",
    # IGP adjacency state off the POLLED series (tracker 222). The signal-lane
    # twin is ospf_adjacency_change / isis_adjacency_change above; this is the
    # metric lane, which answers "is it still bad?" without a recovery line.
    "igp_state_anomaly",
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


# ══ PARSER PROVENANCE + THE RULE TABLE (W1b → A3) ════════════════════════════
#
# THE PROBLEM THIS SOLVES. A Signal used to say WHAT was classified and never
# WHICH RULE classified it, or which revision of that rule. A parser edit that
# silently re-routed a vendor line was invisible in the data: the same kind came
# out, from a different branch, and no stored field disagreed. Three fields on
# every classified signal close that:
#
#   rule_id     a stable identifier for the rule that fired (fixed set, so it
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
# ── A3: THE CATALOG IS THE EXECUTOR ──────────────────────────────────────────
#
# W1b turned every fact ABOUT a branch into a row of a `RULES` table while the
# branch bodies stayed hand-written Python. A3 finishes the move: the rows now
# carry the GRAMMAR too (guard tree, extractions, emission), they live in
# `telemetry-catalog/events.yaml` — the same file the catalog's own conformance
# reader uses, so there is exactly ONE copy of every regex — and the classifiers
# below are a GENERIC INTERPRETER over them.
#
#     telemetry-catalog/events.yaml            the source of truth (34 runtime
#            |                                 rules + 4 catalog-only)
#            |  telemetry-catalog/bake_rules.py
#            v
#     parser_rules.py (GENERATED, checked in)  because the image does NOT ship
#            |                                 telemetry-catalog/ — a runtime
#            |                                 YAML read would resolve to the
#            |                                 real rules in tests and to
#            |                                 NOTHING in production
#            v
#     RULES  ->  classify() below              order preserved exactly; the
#                                              interpreter walks a lane's rules
#                                              in sequence, first match wins
#
# A new symptom is now a catalog ROW plus a fixture, not a code branch. The
# ingest screen's marker/pattern tables are still DERIVED from the table
# (`_CP_GUARD_MARKERS`), the port-event rule list is still DERIVED from it
# (`_PORT_EVENT_RULES`), and the hit counters are still keyed by it — all of
# that is unchanged, it simply now reads rows that also execute.
#
# WHAT DID NOT CHANGE: every classified signal's kind, entity, state, tokens,
# native_id, signal_id and attrs are byte-identical to the branch code (proved
# over the 1,115-entry golden corpus by test_parser_provenance_w1b). `rules_hash`
# DID change — the table's serialization now includes the grammar — and the new
# value is pinned in that test.

#: HAND-BUMPED in events.yaml on any rule change; re-exported here because it is
#: part of this module's published surface (main.py /metrics, the health block).
PARSER_REV = _PARSER_REV

#: The telemetry-catalog event-family fidelity ladder, as of PARSER_REV — a
#: BUILD-TIME SNAPSHOT baked from `telemetry-catalog/events.yaml`, not a runtime
#: read (the catalog is a repo artifact, deliberately NOT shipped inside the
#: correlation image — deployment/docker/Dockerfile.correlation copies
#: src/correlation/ only). Drift is caught in CI instead: the bake `--check`
#: guard plus test_parser_provenance_w1b, which loads events.yaml and asserts
#: this map is exactly the set of families that declare a fidelity_status.
#:
#: A family the catalog knows but leaves undeclared, and a rule with no catalog
#: family at all, both stamp "code": the grammar makes no evidence claim. That is
#: the honest default — it must never read as validated.
CATALOG_EVENT_FIDELITY = _CATALOG_EVENT_FIDELITY


def _fidelity_of(family: str | None) -> str:
    """Catalog fidelity for an event family; "code" when it declares none."""
    if not family:
        return FIDELITY_UNCATALOGUED
    return CATALOG_EVENT_FIDELITY.get(family, FIDELITY_UNCATALOGUED)


RULES_BY_ID: dict[str, Rule] = {r.rule_id: r for r in RULES}
if len(RULES_BY_ID) != len(RULES):                      # pragma: no cover - guard
    raise RuntimeError("duplicate rule_id in producers.RULES")

# The computed half of provenance. The full digest is the comparison value; the
# 16-hex prefix is what rides on every signal (64 hex chars per row, times the
# whole syslog firehose, buys nothing over 64 bits of collision resistance).
RULES_HASH = rules_hash(RULES)
RULES_HASH_TAG = RULES_HASH[:16]
if RULES_HASH != BAKED_RULES_HASH:                      # pragma: no cover - guard
    raise RuntimeError(
        "parser_rules.py was hand-edited: the recomputed rules_hash "
        f"{RULES_HASH[:16]} does not match the baked {BAKED_RULES_HASH[:16]}. "
        "Edit telemetry-catalog/events.yaml and re-run bake_rules.py.")

# The per-lane tables the interpreter walks, split ONCE at import. Order within
# a lane is the order the rows are declared in events.yaml, and order IS
# behaviour (see `rules_hash`).
_SYSLOG_RULES: tuple[Rule, ...] = tuple(r for r in RULES if r.lane == "syslog")
_PORT_RULES: tuple[Rule, ...] = tuple(r for r in RULES if r.lane == "port")
_TRAP_RULES: tuple[Rule, ...] = tuple(r for r in RULES if r.lane == "trap")



# ── parser observability (bounded-cardinality counters) ──────────────────────
#
# `rule_id` is a FIXED set (the table above), so it is safe as a Prometheus
# label — the series count is len(RULES), known at import, and no device string
# can widen it. Pre-seeded at zero so a rule that stops firing is visible as a
# flat series rather than as an absent one.
RULE_HITS: dict[str, int] = {r.rule_id: 0 for r in RULES}
GENERIC_FALLBACKS: dict[str, int] = {"syslog": 0, "trap": 0}

# A8 — SHADOW RULES. A row that carries `shadow: true` is evaluated by the
# interpreter exactly like any other, its hits are counted HERE, and then it
# emits NOTHING and falls through to the next rule. That is how a candidate
# grammar earns its promotion: you can measure how often it would have fired, on
# real production traffic, before it is allowed to produce evidence — instead of
# guessing from a handful of fixtures. Pre-seeded at zero, same bounded-label
# argument as RULE_HITS.
#
# It already rides in `parser_stats()` (so /healthz carries it); the /metrics
# series `corr_parser_shadow_hits_total{rule_id}` is a one-block addition beside
# `corr_parser_rule_hits_total` in main.py, which this module does not own. No
# shadow row ships today, so the map — and the series — are empty until one does.
SHADOW_HITS: dict[str, int] = {r.rule_id: 0 for r in RULES if r.shadow}

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
        # Per-rule METADATA (not counters): what each rule IS, so the API's
        # parser-coverage page can render the corpus — lane, emitted kind, the
        # catalog's fidelity claim for its grammar, and whether it is a shadow
        # row that deliberately emits nothing. Derived from the same fixed
        # `RULES` table the counters are keyed by (bounded, import-time), in
        # CLASSIFICATION ORDER, so the list is deterministic and no runtime
        # string can widen it. `fidelity` is read through `Rule.fidelity`, so a
        # catalog promotion/demotion shows up here without a parser edit.
        "rules_meta": [
            {"rule_id": r.rule_id, "lane": r.lane, "kind": r.kind,
             "fidelity": r.fidelity, "shadow": bool(r.shadow)}
            for r in RULES
        ],
        "rule_hits": dict(RULE_HITS),
        "shadow_hits": dict(SHADOW_HITS),
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
    for k in SHADOW_HITS:
        SHADOW_HITS[k] = 0
    _PROMO_RING.clear()
    _PROMO_POS = 0
    _PROMO_TYPED = 0


def _count_emission(rule_id: str, generic: bool, source: str) -> None:
    """The per-rule hit accounting one emitted Signal owes.

    Split out of `_prov` (tracker 234) so the interpreter's emitter can write the
    four provenance keys straight into the attrs dict it is already building,
    instead of allocating a second dict and merging it, while the FROZEN branch
    baseline — which calls `_prov` from its own `attrs` literal and must keep
    doing so — still counts exactly the same way. One accounting path, two
    callers.
    """
    RULE_HITS[rule_id] += 1
    if generic:
        GENERIC_FALLBACKS[source] = GENERIC_FALLBACKS.get(source, 0) + 1
    _record_promotion(not generic)


def _prov(rule: Rule) -> dict:
    """Count the hit and return the provenance `attrs` for this rule.

    Called exactly once per emitted Signal, from the branch's own `attrs`
    literal. The returned keys are provenance ONLY — none of them reaches
    `native_id`, so `signal_id` is unchanged (tracker 198: identity is content).

    Kept for `fixtures/parser_branch_baseline.py`, which is FROZEN and calls it;
    the interpreter takes the allocation-free path in `_build_signal`.
    """
    _count_emission(rule.rule_id, rule.generic, rule.source)
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

    # Digital Experience grounding (S17, 2026-09-05) — ADDITIVE.
    #
    # Before this, a probe signal was an anonymous "prober->host" PATH: no site,
    # no target identity, no application. The saas-experience RCA template
    # promised to name "the reporting site(s)" and had nothing to name them
    # with. These three tokens are what let an RCA say "experience degraded for
    # site X / application Y" instead of quoting a bare hostname.
    #
    # `site:` and `target:` are already-sanctioned token prefixes (the semantic
    # lane in synthetic_normalize.py uses both). There is deliberately NO
    # `tenant:` token — signals.py forbids that prefix precisely to stop two
    # tenants' subjects merging on a shared token; the tenant lives in
    # Signal.tenant_id, which verified_tenant() has already adjudicated.
    site = str(ev.get("site_id") or ev.get("site") or "")
    target_id = str(ev.get("target_id") or "")
    app = str(ev.get("app_id") or ev.get("app") or "")
    tokens: list[str] = [prober, host]
    if target_id:
        tokens.append(f"target:{target_id}")
    if site:
        tokens.append(f"site:{site}")
    if app:
        tokens.extend([app, f"app:{app}"])
    entity_tokens = tuple(tokens)
    # The observer's LOCATION is the vantage's site, matching the semantic lane.
    if site:
        observer = Observer(
            observer_id=prober,
            observer_type=ObserverType.VANTAGE_AGENT,
            collection_path="direct",
            clock_quality="unknown",
            location=site,
        )
    probe_attrs = {"probe_kind": kind, "target": target}
    if target_id:
        probe_attrs["target_id"] = target_id
    if site:
        probe_attrs["site_id"] = site
    if app:
        probe_attrs["app"] = app

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
            entity_tokens=entity_tokens,
            path_id=entity,
            site=site,
            metric_name=f"probe_loss_pct[{kind}]",
            value=loss,
            attrs=dict(probe_attrs),
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
                entity_tokens=entity_tokens,
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
#     group (FHRP, MAC-flap), the local name is QUALIFIED with its device — the
#     `local: true` flag on a token spec — which preserves the intended binding
#     to that device's own interface node and removes the cross-device weld.
#
# Genuinely global identifiers — MAC addresses, peer/VTEP IPs — stay bare: two
# devices seeing the same MAC really are related.
#
# `attrs` keeps the raw local name either way, so search and the UI are unchanged.
#
# A3: this is now DECLARED, not coded — `_tokens_of` applies it from the row's
# own `tokens:` spec, so a new rule states its grounding intent instead of
# remembering to call a helper.


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
# DERIVED, NOT HAND-WRITTEN, on both halves -- and since W1b both halves derive
# from the SAME place, `RULES`:
#   * the port-event half is extracted from `_PORT_EVENT_RULES` (itself built
#     from the `lane == "port"` rules) by `regex_screen.pattern_screen` --
#     adding a rule updates the screen with it;
#   * the control-plane half is `_CP_GUARD_MARKERS` / `_CP_GUARD_PATTERNS`,
#     which are now built from the `lane == "syslog"` rules' own `markers` and
#     `pattern_src`, so registering a branch's screen coverage is the same act
#     as registering the branch. `test_ingest_prefilter_p3` then re-derives it
#     INDEPENDENTLY from `syslog_control_signal`'s OWN AST: every top-level `if`
#     that can return a Signal must be covered (an OR needs every branch covered,
#     an AND needs one), and an unrecognized guard shape fails the test. So a
#     branch whose Rule forgot a marker is still RED in CI -- the table is the
#     single source, the AST walk is the independent auditor of it.
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


def _dedup(items: Iterable[str]) -> tuple[str, ...]:
    """First-seen order, no duplicates (several Rules share one guard)."""
    seen: dict[str, None] = {}
    for it in items:
        seen.setdefault(it, None)
    return tuple(seen)


# A SHADOW ROW CONTRIBUTES NOTHING TO THE SCREEN (A9b). A shadow rule emits
# nothing, so widening the screen for it would buy no evidence and would cost
# the whole estate: the screen is what keeps the classifiers off the ~95 % of
# syslog that can never promote, and every literal added to it admits more raw
# lines into the two producers. A shadow row is therefore observed ONLY on lines
# the screen already admits for another rule's sake; measuring the shapes the
# screen REJECTS is the parser-coverage mining path (`parsercov`), which reads
# the firehose off the bus and never touches the ingest hot path.
#
# It also keeps promotion honest as a ONE-LINE act: flipping `shadow: false`
# re-derives the screen, the generated VRL and `rules_hash` together, so the
# admission change lands in the same commit as the emission change instead of
# leaking in ahead of it.
_SCREEN_RULES: tuple[Rule, ...] = tuple(
    r for r in RULES if r.lane == "syslog" and not r.shadow)

_CP_GUARD_MARKERS: tuple[str, ...] = _dedup(
    m for r in _SCREEN_RULES for m in r.markers)
# The regexes those same gates test against the MESSAGE, as SOURCE TEXT.
#
# A3 ended the copy. `pattern_src` used to be a hand-kept duplicate of a string
# the branch body compiled inline; the guard is now DATA, and the bake refuses a
# `pattern_src` that is not a live `re` node of that rule's own `guard` tree. So
# the screen cannot claim coverage for a gate that no longer exists. Both
# directions are still pinned in CI:
# `test_ingest_prefilter_p3` walks the guard trees and fails on a guard regex
# that is NOT in this tuple, and
# `test_parser_provenance_w1b.test_every_registered_guard_pattern_is_in_its_own_guard_tree`
# fails on an entry here that is not a node of its rule's guard.
_CP_GUARD_PATTERNS: tuple[str, ...] = _dedup(
    r.pattern_src for r in _SCREEN_RULES if r.pattern_src)


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



# ══ THE INTERPRETER (A3) ═════════════════════════════════════════════════════
#
# One generic classifier for all three lanes. Per lane it builds the haystacks
# and the lane vars, then walks that lane's rules IN ORDER:
#
#     guard (marker / literal pre-check, then the message regex)
#       → extraction (lazy, memoized: only the fields THIS rule's emission
#         actually reads are ever computed)
#       → Signal, via the same constructors the branch code used, including the
#         tracker-198 content tag on the generic-alarm families.
#
# First match wins and nothing after it runs — identical to the `if`/`elif`
# chain this replaces, which is why the corpus replays byte-for-byte.
#
# COST. The guards are closure trees over compiled patterns and `in` tests
# (built once, at import), and the cheap literal checks come first exactly as
# the hand-written guards ordered them; `msg.upper()` and the trap content
# rendering are derived on first use, so a line that classifies as nothing pays
# only for the substring tests it fails. Benchmarked against the branch code
# over the golden corpus in test_parser_interpreter_a3.py.

_ENTITY_TYPES: dict[str, EntityType] = {
    "device": EntityType.DEVICE, "interface": EntityType.INTERFACE,
}
_MODALITIES: dict[str, ModalityClass] = {
    "control_plane": ModalityClass.CONTROL_PLANE,
    "device_telemetry": ModalityClass.DEVICE_TELEMETRY,
}


# The severity gates, as MODULE-LEVEL functions of the context: `Ctx.sev()`
# memoizes the answer, so nothing is allocated per event to hold it. Each
# returns None both when no severity parses AND when it is below the floor, so
# `{severity_floor: ...}` is a single `is not None`.
#
# `ALARM_SEVERITY_FLOOR` is read at CALL time on purpose: main.py may override
# the module global from the environment at startup, and a gate that had closed
# over the number would ignore it.


def _syslog_sev(ctx: Ctx) -> int | None:
    """RFC5424/SR-Linux keyword AND the Cisco %FAC-N-MNEMONIC tag digit."""
    n = syslog_severity_num(ctx.base["ev"], ctx.base["tag"])
    return n if (n is not None and n <= ALARM_SEVERITY_FLOOR) else None


def _trap_sev(ctx: Ctx) -> int | None:
    """The MIB severity the Go receiver's trapMeta resolved. Unlike the syslog
    lane there is no tag digit to fall back on."""
    n = _SEVERITY_NUM.get(str(ctx.base["ev"].get("severity") or "").strip().lower())
    return n if (n is not None and n <= ALARM_SEVERITY_FLOOR) else None


def _no_severity(ctx: Ctx) -> None:
    """The port lane has no severity-floor rule; every rule there is explicit."""


def _trap_content_of(ctx: Ctx) -> str:
    """The trap's own content rendering, for the generic-alarm content tag.
    A module-level function (not a per-event closure) so the trap lane hands the
    interpreter a CONSTANT callback table."""
    return _trap_content(ctx.base["ev"], ctx.base["name"], ctx.base["etype"])


_TRAP_LANE_FNS: dict[str, Callable[[Ctx], object]] = {
    "trap_content": _trap_content_of,
}


def _tokens_of(emit: _Emission, ctx: Ctx, owner: str) -> tuple[str, ...]:
    """Grounding tokens from the emission spec (tracker 168 semantics).

    A token whose template references an EMPTY var is DROPPED rather than
    rendered into a stub (`vlan` with no number). A `local` token is a
    DEVICE-LOCAL name — an interface, an FHRP group, an STP instance — so it is
    qualified as `<device>:<name>`: bare, it welded every device in the estate
    that owns the same port number into one RCA object.
    """
    cached = ctx.vars
    only = emit.tokens_only
    if only is not None:
        # `tokens: [{t: '{host}'}]` — the commonest shape by far.
        v = cached.get(only, MISS)
        if v is MISS:
            v = ctx.var(only)
        if v:
            return (v if isinstance(v, str) else str(v),)
        return (owner,) if emit.tokens_fallback else ()
    out: list[str] = []
    for t in emit.tokens:
        single = t.single
        if single is not None:
            # `"{peer}"` — read once; empty means the token does not exist.
            v = cached.get(single, MISS)
            if v is MISS:
                v = ctx.var(single)
            if not v:
                continue
            v = v if isinstance(v, str) else str(v)
        else:
            skip = False
            for n in t.names:
                if not ctx.var(n):
                    skip = True
                    break
            if skip:
                continue
            v = t.render(ctx)
        if t.local:
            if not v or v == "unknown":
                continue
            v = f"{owner}:{v}"
        elif not v:
            continue
        out.append(v)
    if not out and emit.tokens_fallback:
        return (owner,)
    return tuple(out)


class _Emission:
    """One rule's emission block with every per-event lookup already done.

    THE LEVER (tracker 234). Phase-split profiling put 54 us of the syslog
    lane's 79 us in EMISSION rather than in the guards, and the emitter was
    paying, on EVERY signal, for work whose answer is fixed at import: eleven
    attribute reads off a non-slotted frozen dataclass, two dict lookups to turn
    the row's `modality:`/`entity.type:` STRINGS into enum members, a property
    call for the rule's fidelity, and a second dict allocated and merged just to
    carry four constant provenance keys.

    None of that is per-event information. It is resolved once, here, at import,
    into a `__slots__` object the emitter reads by slot. What is left per event
    is exactly the work that depends on the event: the guards, the templates,
    the extractions and the Signal.

    Deliberately NOT a dataclass: `__slots__` is the whole point, and a frozen
    dataclass would put an attribute lookup back on the path this exists to take
    it off.
    """

    __slots__ = (
        "attr_plan", "content_tag", "entity_id", "entity_id_else",
        "entity_type", "entity_type_else", "entity_when", "fidelity", "generic",
        "kind", "metric", "modality", "native_id", "rule_id", "severity",
        "source", "tokens", "tokens_fallback", "tokens_only",
    )

    def __init__(self, rule: Rule, emit: Emit) -> None:
        self.entity_when = emit.entity_when
        self.entity_type = _ENTITY_TYPES[emit.entity_type]
        self.entity_id = emit.entity_id
        # `entity_type_else` is "" on a rule with no conditional entity; it is
        # never read in that case, so it resolves to the primary type rather
        # than needing a KeyError-shaped guard on the hot path.
        self.entity_type_else = _ENTITY_TYPES[emit.entity_type_else or emit.entity_type]
        self.entity_id_else = emit.entity_id_else
        self.native_id = emit.native_id
        self.content_tag = emit.content_tag
        self.severity = emit.severity
        self.attr_plan = emit.attr_plan
        self.kind = emit.kind
        self.metric = emit.metric_name
        self.modality = _MODALITIES[emit.modality]
        self.tokens = emit.tokens
        self.tokens_only = emit.tokens_only
        self.tokens_fallback = emit.tokens_fallback
        # Provenance that is constant for the life of the process. PARSER_REV
        # and RULES_HASH_TAG are deliberately NOT cached: they are module
        # globals a test may patch to prove the stamp is real, and reading two
        # globals is cheaper than the dict this used to allocate anyway.
        self.rule_id = rule.rule_id
        self.fidelity = rule.fidelity
        self.generic = rule.generic
        self.source = rule.source


def _build_signal(
    em: _Emission, ctx: Ctx, tenant: str, ts: datetime,
    observer: Observer, owner: str, source: Source,
) -> Signal:
    """A matched rule + its context → the Signal its `emit:` block describes."""
    when = em.entity_when
    if when is not None and not when(ctx):
        etype = em.entity_type_else
        eid = em.entity_id_else(ctx) if em.entity_id_else else owner
    else:
        etype = em.entity_type
        eid = em.entity_id(ctx)
    native = em.native_id(ctx)
    tag = em.content_tag
    if tag is not None:
        # tracker 198: the event's OWN content discriminates the id, so two
        # distinct unrecognized lines from one device in the same millisecond
        # are two signals — while a byte-identical redelivery still dedups.
        native = _tagged_native_id(native, str(ctx.var(tag)))
    cached = ctx.vars
    attrs: dict[str, object] = {}
    for key, name, fn in em.attr_plan:
        if name is None:
            attrs[key] = fn(ctx)
            continue
        v = cached.get(name, MISS)
        attrs[key] = ctx.var(name) if v is MISS else v
    # The four provenance keys, written straight in. They used to be a dict
    # built by `_prov` and merged; the merge and the allocation were pure tax
    # (tracker 234). `_count_emission` keeps the accounting identical.
    attrs["rule_id"] = em.rule_id
    attrs["parser_rev"] = PARSER_REV
    attrs["rules_hash"] = RULES_HASH_TAG
    attrs["fidelity"] = em.fidelity
    _count_emission(em.rule_id, em.generic, em.source)
    return Signal(
        tenant_id=tenant,
        ts=ts,
        source=source,
        kind=em.kind,
        observer=observer,
        modality_class=em.modality,
        entity_type=etype,
        entity_id=eid,
        severity=em.severity(ctx),
        native_id=native,
        entity_tokens=_tokens_of(em, ctx, owner),
        metric_name=em.metric,
        attrs=attrs,
    )


def _plan(rules: tuple[Rule, ...]) -> tuple[tuple[Guard, bool, Rule, _Emission], ...]:
    """A lane's rules flattened for the walk: (guard, reads_vars, rule, emission).

    Two attribute lookups per rule per line is not free when a lane has fifteen
    rules and the workload is 900k lines; the tuple unpack is. It is also where
    "every runtime rule has a guard and an emit" is checked ONCE, at import,
    instead of per event — and where the emission block is resolved to the
    slotted `_Emission` the emitter reads (tracker 234)."""
    out: list[tuple[Guard, bool, Rule, _Emission]] = []
    for r in rules:
        if r.guard is None or r.emit is None:     # pragma: no cover - guard
            raise RuntimeError(f"rule {r.rule_id!r} has no guard/emit")
        out.append((r.guard, r.guard_reads_vars, r, _Emission(r, r.emit)))
    return tuple(out)


#: Built once, at import — the walk order of each lane.
_SYSLOG_PLAN = _plan(_SYSLOG_RULES)
_PORT_PLAN = _plan(_PORT_RULES)
_TRAP_PLAN = _plan(_TRAP_RULES)


def _run(
    rules: tuple[tuple[Guard, bool, Rule, _Emission], ...], ctx: Ctx, tenant: str,
    ts: datetime, observer: Observer, owner: str, source: Source,
) -> Signal | None:
    """Walk a lane's rules in order; first non-shadow match emits.

    The extraction table is bound on the MATCH, not per rule: no guard in the
    table reads an extracted var today (`guard_reads_vars` says so, per rule, at
    import), so binding it fifteen times per line would be pure interpreter tax
    on the ingest hot path. A rule that ever does read one gets the table bound
    before its guard runs, and re-bound on the match — correct either way.
    """
    for guard, reads_vars, rule, em in rules:
        if reads_vars:                            # pragma: no cover - none today
            ctx.enter(rule.extract)
        if not guard(ctx):
            continue
        if rule.shadow:
            # A8: counted, then IGNORED — evaluation continues at the next rule
            # exactly as if this row were absent, so a shadow row can never
            # change what the parser emits.
            SHADOW_HITS[rule.rule_id] = SHADOW_HITS.get(rule.rule_id, 0) + 1
            continue
        ctx.enter(rule.extract)
        return _build_signal(em, ctx, tenant, ts, observer, owner, source)
    return None


def syslog_control_signal(ev: dict, tenant: str, ingest_ts: datetime) -> Signal | None:
    """Adjacency / link-state syslog → one control_plane Signal; None for
    everything that is not a recognized control-plane event. May raise
    DeadLetter on malformed provenance.

    A3: the fifteen hand-written branches are gone — this builds the lane's
    haystacks and hands them to the interpreter, which walks the `lane: syslog`
    rows of telemetry-catalog/events.yaml in declared order.

    tracker 198: the generic `device_alarm` net at the bottom of that order
    folds a hash of the message text into its native_id, so two distinct
    unrecognized lines that share host + facility + mnemonic (+ interface)
    inside one millisecond are two signals instead of one. Nothing else moves —
    persistence, versioning, the memflat structures and the replay guard are
    untouched (INVARIANTS §10/§10a), and a byte-identical redelivery still
    derives the same signal_id and still dedups."""
    host = str(ev.get("hostname") or "")
    if not host or host == "unknown":
        return None
    tag = str(ev.get("appname") or "").upper()
    msg = str(ev.get("message") or "")
    # Fold the VRL-parsed facility + mnemonic (#31 envelope) into the
    # classification token so vendor logs whose appname isn't telling still
    # classify off the structured fields. ctoken ⊇ tag, so every previously
    # matched event still matches identically — this only ADDS coverage.
    ctoken = (tag + " " + str(ev.get("facility") or "") + " "
              + str(ev.get("event_type") or "")).upper()
    ts = parse_event_ts(ev.get("timestamp"), reference=ingest_ts) or ingest_ts
    # Interned (tracker 156): this is a per-DEVICE fact rebuilt on every syslog
    # line. See signals.observer_of — bounded, value-identical.
    observer = observer_of(
        host,
        ObserverType.DEVICE,
        collection_path="direct",   # the device itself emitted the event
        clock_quality="unknown",
    )
    ctx = Ctx(
        {"ev": ev, "msg": msg, "tag": tag, "ctoken": ctoken},
        {"host": host, "ts_ms": int(ts.timestamp() * 1000), "tag": tag, "msg": msg},
        _syslog_sev,
    )
    return _run(_SYSLOG_PLAN, ctx, tenant, ts, observer, host, Source.SYSLOG)

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

    A3: the branches are `lane: trap` rows of telemetry-catalog/events.yaml,
    walked in declared order by the interpreter.

    tracker 198: the generic `device_alarm` fallback folds a hash of the trap's
    own content (name + event_type + varbinds) into its native_id, so two
    unclassified traps of one OID that differ only in their varbinds no longer
    share a signal_id inside a millisecond. Redelivery idempotency is
    preserved: the rendering is byte-stable."""
    # G2 canonicalization: the device MUST be a real inventory id (attributed by
    # the Go receiver's G2a — source-IP/sysName/agent-addr — and, when that
    # fails, by the caller's C7.1 EntityResolver). We deliberately do NOT fall
    # back to the raw source IP (ev["host"]): a NAT-collapsed source would
    # otherwise form a PHANTOM device (e.g. "192.0.2.120:Ethernet1") that never
    # correlates with the real device's metrics/syslog. An unattributed trap
    # stays searchable in OpenSearch but is not an RCA signal — the same honesty
    # guardrail as an unclassified trap.
    device = str(ev.get("device") or "")
    if not device:
        return None
    oid = str(ev.get("trap_oid") or "")
    name = str(ev.get("trap_name") or "")
    # The MIB-decoded envelope (#32): how a VENDOR trap the standard OIDs miss
    # still classifies, without a per-vendor OID hardcode.
    etype = str(ev.get("event_type") or "").lower()
    ts = parse_event_ts(ev.get("timestamp"), reference=ingest_ts) or ingest_ts
    # v1/v2c traps are spoofable (authenticated=false); recorded as evidence but
    # the flag lets the engine weight it. v3-auth traps are trustworthy.
    authed = bool(ev.get("authenticated"))
    observer = Observer(
        observer_id=device,
        observer_type=ObserverType.DEVICE,
        collection_path="direct",   # the device itself emitted the trap
        clock_quality="unknown",
    )
    ctx = Ctx(
        {"ev": ev, "oid": oid, "name": name, "etype": etype},
        {"device": device, "ts_ms": int(ts.timestamp() * 1000), "oid": oid,
         "name": name, "etype": etype, "authed": authed},
        _trap_sev,
        # Only the generic-alarm row reads this, and only after every classified
        # row has declined — so the rendering is never built for a trap that
        # classifies.
        _TRAP_LANE_FNS,
    )
    return _run(_TRAP_PLAN, ctx, tenant, ts, observer, device, Source.TRAP)


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
# W1b/A3: DERIVED FROM `RULES` (the `lane == "port"` rows, in table order —
# first-match-wins, so the order IS behaviour and is part of `rules_hash`). The
# CLASSIFIER walks `_PORT_RULES` (the Rule objects) through the interpreter;
# this flattened projection exists for the SCREEN — `_build_syslog_screen`, the
# union pre-filter and their tests consume it, and a test monkeypatches an extra
# entry onto it to prove the screen fails open.
_PORT_EVENT_RULES: list[tuple[re.Pattern, str, bool, Severity]] = [
    (rule.pattern, rule.kind, rule.entity_type == "interface", rule.severity)
    for rule in _PORT_RULES
    if rule.pattern is not None and rule.severity is not None
]
# kind → Rule for the port lane. The interpreter does not need it (it carries
# the Rule through the walk); it exists for the FROZEN pre-A3 branch code in
# fixtures/parser_branch_baseline.py, which classifies by kind and looks the
# rule up here so the benchmark's two sides stamp identical provenance.
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


def port_event_signal(ev: dict, tenant: str, ingest_ts: datetime) -> Signal | None:
    """Transceiver/optics/DOM/FEC syslog → one device_telemetry Signal in the
    sig.ent.spdc evidence vocabulary; None for anything unrecognized. Feeds the
    physical-layer signatures (#94). Also the source of port_event_log rows.

    A3: the twelve rules are `lane: port` rows of telemetry-catalog/events.yaml
    and differ only in id / pattern / severity / kind — one shared emission
    shape, so a new optics symptom is a five-line row."""
    host = str(ev.get("hostname") or ev.get("device") or "")
    if not host or host == "unknown":
        return None
    msg = str(ev.get("message") or "")
    # H11: cap BEFORE any regex — see _PORT_EVENT_TEXT_CAP. Each part is capped
    # on its own so an oversized message can never truncate away the structured
    # fields (facility/event_type/appname) a vendor line may classify on.
    pctoken = " ".join((
        msg[:_PORT_EVENT_TEXT_CAP],
        str(ev.get("facility") or "")[:256],
        str(ev.get("event_type") or "")[:256],
        str(ev.get("appname") or "")[:256],
    ))
    # One union search instead of twelve (tracker 156). Placed BEFORE the
    # timestamp parse and the Observer construction, because for a non-port line
    # those were pure waste too — an allocation and a date parse per event that
    # nothing ever read.
    if not _PORT_EVENT_PREFILTER.search(pctoken):
        return None
    ts = parse_event_ts(ev.get("timestamp"), reference=ingest_ts) or ingest_ts
    # Interned (tracker 156): identical per-device Observer built on every event.
    observer = observer_of(
        host, ObserverType.DEVICE,
        collection_path="direct", clock_quality="unknown",
    )
    ctx = Ctx(
        {"ev": ev, "pctoken": pctoken, "msg": msg},
        {"host": host, "ts_ms": int(ts.timestamp() * 1000), "msg": msg},
        _no_severity,
    )
    return _run(_PORT_PLAN, ctx, tenant, ts, observer, host, Source.SYSLOG)


# The three lanes, by name — `classify(ev, lane, ...)` is the one entry point the
# rest of the system needs, and the name the rule table's `lane` column refers to.
_LANES: dict[str, Callable[[dict, str, datetime], Signal | None]] = {
    "syslog": syslog_control_signal,
    "port": port_event_signal,
    "trap": trap_control_signal,
}


def classify(ev: dict, lane: str, tenant: str, ingest_ts: datetime) -> Signal | None:
    """Run one raw event through a lane's rules → a Signal, or None.

    The lane-agnostic entry point: `lane` is the `lane:` column of
    telemetry-catalog/events.yaml. An unknown lane raises rather than silently
    classifying nothing — a typo must not read as "this event matched no rule".
    """
    fn = _LANES.get(lane)
    if fn is None:
        raise ValueError(f"unknown parser lane {lane!r}; want one of {sorted(_LANES)}")
    return fn(ev, tenant, ingest_ts)


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
