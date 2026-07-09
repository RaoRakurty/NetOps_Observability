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

import re
from datetime import datetime, timezone

from episodes import EpisodeDetector, EpisodeEvent
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

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
    # DC overlay (P2)
    "vtep_state_change", "evpn_mac_move",
    # trap lane
    "device_restart",
    # generic-alarm keystone (#80 §4)
    "device_alarm",
    # metric episodes (main.py metric_identity + C6 flow)
    "if_metric_anomaly", "bgp_state_anomaly", "device_resource_anomaly",
    "flow_volume_anomaly",
    # cloud lane (#81 P3G — handle_cloud emits these; consumed by the cloud signatures)
    "cloud_change", "cloud_audit", "cloud_flow_log", "cloud_health",
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
})


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

_FRACTION_RE = re.compile(r"(\.\d{6})\d+")  # >µs precision → truncate for fromisoformat


def parse_event_ts(raw: object) -> datetime | None:
    """RFC3339/ISO event time → tz-aware UTC; None when absent/malformed
    (the caller substitutes ingest time — honest fallback, never a guess)."""
    if not raw:
        return None
    s = _FRACTION_RE.sub(r"\1", str(raw).strip().replace("Z", "+00:00"))
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


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
    ts = parse_event_ts(ev.get("ts")) or ingest_ts
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


def syslog_control_signal(ev: dict, tenant: str, ingest_ts: datetime) -> Signal | None:
    """Adjacency / link-state syslog → one control_plane Signal; None for
    everything that is not a recognized control-plane event. May raise
    DeadLetter on malformed provenance."""
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
    ts = parse_event_ts(ev.get("timestamp")) or ingest_ts
    ts_ms = int(ts.timestamp() * 1000)
    observer = Observer(
        observer_id=host,
        observer_type=ObserverType.DEVICE,
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
            kind="isis_adjacency_change",
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE,
            entity_id=host,
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|isis_adj|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens,
            metric_name="isis_adjacency",
            attrs={"peer": peer, "state": state, "tag": tag or "isisAdjacencyChange"},
        )

    if "ADJCHANGE" in ctoken or "ADJCHG" in ctoken:
        proto = "bgp" if "BGP" in ctoken else "ospf" if "OSPF" in ctoken else "routing"
        peer_m = _IP_RE.search(msg)
        peer = peer_m.group(1) if peer_m else ""
        state = _state_of(msg)
        tokens = (host, peer) if peer else (host,)
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind=f"{proto}_adjacency_change",
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE,
            entity_id=host,
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|{proto}_adj|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens,
            metric_name=f"{proto}_adjacency",
            attrs={"peer": peer, "state": state, "tag": tag},
        )

    if ("LINK" in ctoken or "LINEPROTO" in ctoken) and "UPDOWN" in ctoken:
        if_m = _IF_RE.search(msg)
        ifname = if_m.group(1) if if_m else "unknown"
        state = _state_of(msg)
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind="link_state_change",
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE,
            entity_id=f"{host}:{ifname}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|link|{ifname}|{state}|{ts_ms}",
            entity_tokens=(host, ifname),
            metric_name="link_state",
            attrs={"interface": ifname, "state": state, "tag": tag},
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
            kind="lldp_neighbor_change",
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE,
            entity_id=f"{host}:{ifname}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|lldp|{ifname}|{state}|{ts_ms}",
            entity_tokens=(host, ifname),
            metric_name="lldp_neighbor",
            attrs={"interface": ifname, "state": state, "tag": tag or "remotePeer"},
        )

    # STP topology change — cEOS %SPANTREE-6-INTERFACE_DEL/ADD/STATE. Interface-
    # scoped; prefer the transition target ("...to learning/forwarding").
    if "SPANTREE" in tag:
        if_m = _IF_RE.search(msg)
        ifname = if_m.group(1) if if_m else "unknown"
        tgt_m = re.search(r"\bto\s+(forwarding|learning|discarding|blocking)\b", msg, re.IGNORECASE)
        if tgt_m:
            state = "up" if tgt_m.group(1).lower() in ("forwarding", "learning") else "down"
        elif re.search(r"\b(?:removed|discarding|blocking)\b", msg, re.IGNORECASE):
            state = "down"
        elif re.search(r"\b(?:added|forwarding|learning)\b", msg, re.IGNORECASE):
            state = "up"
        else:
            state = "unknown"
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind="stp_topology_change",
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE,
            entity_id=f"{host}:{ifname}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|stp|{ifname}|{state}|{ts_ms}",
            entity_tokens=(host, ifname),
            metric_name="stp_state",
            attrs={"interface": ifname, "state": state, "tag": tag},
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
            tenant_id=tenant, ts=ts, source=Source.SYSLOG, kind="vtep_state_change",
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=host,
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|vtep|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens, metric_name="vtep_state",
            attrs={"vtep": peer, "state": state, "tag": tag},
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
            tenant_id=tenant, ts=ts, source=Source.SYSLOG, kind="evpn_mac_move",
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=host,
            severity=Severity.HIGH,
            native_id=f"{host}|evpn_mac|{mac or '?'}|vlan{vlan or '?'}|{ts_ms}",
            entity_tokens=tokens or (host,), metric_name="evpn_mac_move",
            attrs={"mac": mac, "vlan": vlan, "vni": vni, "vtep": vtep,
                   "blacklisted": blacklisted, "tag": tag},
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
        tokens = tuple(t for t in (host, ifname, f"grp{group}" if group else "")
                       if t and t != "unknown")
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind="fhrp_state_change",
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE,
            entity_id=host,
            severity=Severity.HIGH if takeover else Severity.WARN,
            native_id=f"{host}|fhrp|{proto}|{ifname}|grp{group or '?'}|{role or '?'}|{ts_ms}",
            entity_tokens=tokens or (host,),
            metric_name="fhrp_state",
            attrs={"proto": proto, "group": group, "interface": ifname, "state": role, "tag": tag},
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
        tokens = tuple(t for t in (host, mac, f"vlan{vlan}" if vlan else "", *ports[:2]) if t)
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind="mac_flap",
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE,
            entity_id=host,
            severity=Severity.HIGH,
            native_id=f"{host}|mac_flap|{mac or '?'}|vlan{vlan or '?'}|{ts_ms}",
            entity_tokens=tokens or (host,),
            metric_name="mac_flap",
            attrs={"mac": mac, "vlan": vlan,
                   "port_a": ports[0] if ports else "",
                   "port_b": ports[1] if len(ports) > 1 else "", "tag": tag},
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
            etype_, eid_, toks_ = EntityType.INTERFACE, f"{host}:{ifname}", (host, ifname)
        else:
            etype_, eid_, toks_ = EntityType.DEVICE, host, (host,)
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind="device_alarm",
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=etype_,
            entity_id=eid_,
            severity=_severity_from_num(sev_num),
            native_id=f"{host}|alarm|{facility}|{mnem or '?'}|{ifname or '-'}|{ts_ms}",
            entity_tokens=toks_,
            metric_name="device_alarm",
            attrs={"facility": facility, "mnemonic": mnem, "severity": sev_num,
                   "interface": ifname, "tag": tag, "text": msg[:256]},
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


def trap_control_signal(ev: dict, tenant: str, ingest_ts: datetime) -> Signal | None:
    """Normalized SNMP trap → one control_plane Signal for the high-value
    families only (link state, device restart, BGP transition); None for every
    unclassified trap (kept searchable, never an RCA signal). Mirrors the
    syslog/metric entity model so trap evidence binds to the same interface/peer.

    HA-failover, environmental/hardware-health, and threshold-alarm traps are
    vendor-specific OIDs — deliberately deferred to a per-vendor fixture-driven
    follow-up rather than guessed (the anti-noise guardrail)."""
    # G2 canonicalization: the device MUST be a real inventory id (attributed by the
    # Go receiver's G2a — source-IP/sysName/agent-addr — and, when that fails, by the
    # caller's C7.1 EntityResolver). We deliberately do NOT fall back to the raw source
    # IP (ev["host"]): a NAT-collapsed source would otherwise form a PHANTOM device
    # (e.g. "10.70.245.120:Ethernet1") that never correlates with the real device's
    # metrics/syslog. An unattributed trap stays searchable in OpenSearch but is not an
    # RCA signal — the same honesty guardrail as an unclassified trap.
    device = str(ev.get("device") or "")
    if not device:
        return None
    oid = str(ev.get("trap_oid") or "")
    name = str(ev.get("trap_name") or "")
    ts = parse_event_ts(ev.get("timestamp")) or ingest_ts
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
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind="link_state_change",
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE, entity_id=f"{device}:{iface}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{device}|trap_link|{iface}|{state}|{ts_ms}",
            entity_tokens=(device, iface), metric_name="link_state",
            attrs={"interface": iface, "state": state, "trap_oid": oid,
                   "authenticated": authed},
        )

    # Device restart — device-scoped lifecycle event.
    if oid in (_TRAP_COLDSTART, _TRAP_WARMSTART) or name in ("coldStart", "warmStart"):
        kind_type = "cold" if (oid == _TRAP_COLDSTART or name == "coldStart") else "warm"
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind="device_restart",
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=device,
            severity=Severity.HIGH,
            native_id=f"{device}|trap_restart|{kind_type}|{ts_ms}",
            entity_tokens=(device,), metric_name="device_restart",
            attrs={"restart": kind_type, "trap_oid": oid, "authenticated": authed},
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
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind="bgp_adjacency_change",
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=entity_id,
            severity=Severity.WARN if established else Severity.HIGH,
            native_id=f"{device}|trap_bgp|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens, metric_name="bgp_adjacency",
            attrs={"peer": peer, "state": state, "trap_oid": oid,
                   "authenticated": authed},
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
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind="bgp_adjacency_change",
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=entity_id,
            severity=Severity.WARN if established else Severity.HIGH,
            native_id=f"{device}|trap_bgp|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens, metric_name="bgp_adjacency",
            attrs={"peer": peer, "state": state, "trap_oid": oid, "event_type": etype, "authenticated": authed},
        )
    if "link" in etype and ("down" in etype or "up" in etype):
        state = "down" if "down" in etype else "up"
        iface = _trap_interface(ev)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind="link_state_change",
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE, entity_id=f"{device}:{iface}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{device}|trap_link|{iface}|{state}|{ts_ms}",
            entity_tokens=(device, iface), metric_name="link_state",
            attrs={"interface": iface, "state": state, "trap_oid": oid, "event_type": etype, "authenticated": authed},
        )
    if "start" in etype and ("cold" in etype or "warm" in etype):
        kind_type = "cold" if "cold" in etype else "warm"
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind="device_restart",
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=device, severity=Severity.HIGH,
            native_id=f"{device}|trap_restart|{kind_type}|{ts_ms}",
            entity_tokens=(device,), metric_name="device_restart",
            attrs={"restart": kind_type, "trap_oid": oid, "event_type": etype, "authenticated": authed},
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
            etype_, eid_, toks_ = EntityType.INTERFACE, f"{device}:{iface}", (device, iface)
        else:
            etype_, eid_, toks_ = EntityType.DEVICE, device, (device,)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind="device_alarm",
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=etype_, entity_id=eid_, severity=_severity_from_num(sev_num),
            native_id=f"{device}|alarm|{oid or '?'}|{ts_ms}",
            entity_tokens=toks_, metric_name="device_alarm",
            attrs={"trap_oid": oid, "trap_name": name, "event_type": etype,
                   "category": str(ev.get("category") or ""), "severity": sev_num,
                   "authenticated": authed,
                   "interface": iface if iface != "unknown" else ""},
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
_PORT_EVENT_RULES: list[tuple[re.Pattern, str, bool, Severity]] = [
    # Unsupported / unqualified transceiver (Cisco %PLATFORM UNSUPPORTED_TRANSCEIVER,
    # Arista "unsupported transceiver", FortiGate "unqualified SFP").
    (re.compile(r"unsupported\s+transceiver|unqualified\s+(sfp|transceiver|optic)|not\s+qualified|UNSUPPORTED_TRANSCEIVER|transceiver.*not\s+supported", re.I),
     "transceiver_unsupported", True, Severity.HIGH),
    # DOM/DDM optical threshold alarms (SFF-8472 / %OPTICS / vendor DOM).
    (re.compile(r"(rx|receive).*(power).*(low|below).*(alarm|threshold)|RX_POWER_LOW|low\s+rx\s+power", re.I),
     "dom_rx_power_low", True, Severity.HIGH),
    (re.compile(r"(temperature|temp).*(high|above).*(alarm|threshold|warning)|TEMP_HIGH|high\s+temperature", re.I),
     "dom_temperature_high", True, Severity.HIGH),
    (re.compile(r"(tx\s+)?bias.*(high|current).*(alarm|threshold)|BIAS_HIGH", re.I),
     "dom_lane_bias_anomaly", True, Severity.WARN),
    # FEC / PCS.
    (re.compile(r"uncorrectable.*(fec|codeword|block)|FEC.*UNCORRECTABLE|post[-_ ]?fec.*(error|ber)", re.I),
     "prefec_ber_rising", True, Severity.HIGH),
    (re.compile(r"pre[-_ ]?fec\s+ber|fec.*corrected.*(rate|high)|CORRECTED_FEC", re.I),
     "fec_corrected_rate_high", True, Severity.WARN),
    (re.compile(r"local\s+fault|LOCAL_FAULT", re.I), "pcs_local_fault", True, Severity.HIGH),
    (re.compile(r"remote\s+fault|REMOTE_FAULT", re.I), "pcs_remote_fault", True, Severity.HIGH),
    (re.compile(r"deskew|align.*(marker|lane).*(fail|lost)|PCS.*DESKEW", re.I),
     "pcs_deskew_fault", True, Severity.HIGH),
    (re.compile(r"hi[-_ ]?ber|high\s+bit\s+error", re.I), "hi_ber_indication", True, Severity.HIGH),
    # Optic present but no light / signal (link-down-with-optic-in fingerprint).
    (re.compile(r"no\s+(light|signal)|loss\s+of\s+(light|signal)|LOS\b|SIGNAL_LOSS", re.I),
     "link_down_no_light", True, Severity.HIGH),
    # Transceiver insert/remove flap on insert (interop/incompat fingerprint).
    (re.compile(r"transceiver.*(insert|remov).*(insert|remov)|SFP.*flap|optic.*flap", re.I),
     "link_flap_on_insert", True, Severity.WARN),
]


def _port_of(ev: dict) -> str:
    """Best-effort port/interface name from the parsed envelope."""
    for k in ("interface", "if_name", "ifname", "port"):
        v = ev.get(k)
        if v:
            return str(v)
    m = re.search(r"\b((?:Ethernet|Eth|Et|Gi|Te|Fo|Hu|xe-|ge-|et-)[\w./:-]+)", str(ev.get("message") or ""))
    return m.group(1) if m else ""


def port_event_signal(ev: dict, tenant: str, ingest_ts: datetime) -> "Signal | None":
    """Transceiver/optics/DOM/FEC syslog → one device_telemetry Signal in the
    sig.ent.spdc evidence vocabulary; None for anything unrecognized. Feeds the
    physical-layer signatures (#94). Also the source of port_event_log rows."""
    host = str(ev.get("hostname") or ev.get("device") or "")
    if not host or host == "unknown":
        return None
    msg = str(ev.get("message") or "")
    ctoken = msg + " " + str(ev.get("facility") or "") + " " + str(ev.get("event_type") or "") + " " + str(ev.get("appname") or "")
    ts = parse_event_ts(ev.get("timestamp")) or ingest_ts
    ts_ms = int(ts.timestamp() * 1000)
    observer = Observer(
        observer_id=host, observer_type=ObserverType.DEVICE,
        collection_path="direct", clock_quality="unknown",
    )
    for pat, kind, iface_scoped, sev in _PORT_EVENT_RULES:
        if not pat.search(ctoken):
            continue
        port = _port_of(ev)
        toks_: tuple[str, ...]
        if iface_scoped and port:
            etype_, eid_, toks_ = EntityType.INTERFACE, f"{host}:{port}", (host, port)
        else:
            etype_, eid_, toks_ = EntityType.DEVICE, host, (host,)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.SYSLOG, kind=kind,
            observer=observer, modality_class=ModalityClass.DEVICE_TELEMETRY,
            entity_type=etype_, entity_id=eid_, severity=sev,
            native_id=f"{host}|portevt|{kind}|{port or '-'}|{ts_ms}",
            entity_tokens=toks_, metric_name="port_event",
            attrs={"interface": port, "port_event": kind, "message": msg[:240]},
        )
    return None
