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
) -> Signal:
    """EpisodeEvent → canonical Signal row (deterministic identity: the episode
    is identified by its onset, so onset+clear rows share native_id lineage).
    Provenance is parameterized so probe-path episodes carry active_probe /
    vantage-agent provenance instead of device telemetry (#67 build ⑦)."""
    tenant_id, entity_id, metric = ev.key
    onset_ms = int(ev.onset_ts.timestamp() * 1000)
    attrs = {
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
        tokens = (host, peer) if peer else (host,)
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
    device = str(ev.get("device") or ev.get("host") or "")
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

    return None  # unclassified — searchable in OpenSearch, no RCA signal
