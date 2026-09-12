# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""FROZEN pre-A3 branch code — the BENCHMARK BASELINE. Not production code.

This is `producers.syslog_control_signal` / `trap_control_signal` /
`port_event_signal` exactly as they were before A3 replaced the hand-written
`if`/`elif` chains with the generic interpreter over the telemetry catalog. It
exists for ONE purpose: so `test_parser_interpreter_a3.py` can measure the
interpreter against the real thing it replaced, on the real corpus, instead of
against a remembered number.

RULES OF THIS FILE:
  * Nothing in `src/correlation/` imports it except that benchmark test.
  * It is FROZEN. It is not kept in step with the catalog and must never be
    "fixed" to match a new rule — the moment it disagrees with the interpreter
    on the golden corpus, the interpreter is the truth and this file is
    history. (The parity test uses the golden corpus, not this file.)
  * The rule table, provenance stamping and the shared helpers come from the
    LIVE module, so the two sides pay the same cost for the same work and the
    ratio measures the classification chain and nothing else.

Parsing is on the ingest hot path (measured at 35 us/line for the control lane
on the ratified 2.5k workload), which is why the ratio is a gate and not a note.
"""

from __future__ import annotations

import re
from datetime import datetime

import producers as P
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
    observer_of,
)

_R = P.RULES_BY_ID


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
    ts = P.parse_event_ts(ev.get("timestamp"), reference=ingest_ts) or ingest_ts
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
            kind=_R["syslog.isis.adjacency_change"].kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE,
            entity_id=host,
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|isis_adj|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens,
            metric_name="isis_adjacency",
            attrs={"peer": peer, "state": state, "tag": tag or "isisAdjacencyChange",
                   **P._prov(_R["syslog.isis.adjacency_change"])},
        )

    if "ADJCHANGE" in ctoken or "ADJCHG" in ctoken:
        proto = "bgp" if "BGP" in ctoken else "ospf" if "OSPF" in ctoken else "routing"
        rule = _R[{"bgp": "syslog.bgp.adjacency_change",
                    "ospf": "syslog.ospf.adjacency_change",
                    "routing": "syslog.routing.adjacency_change"}[proto]]
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
            attrs={"peer": peer, "state": state, "tag": tag, **P._prov(rule)},
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
                kind=_R["syslog.bgp.notification"].kind, observer=observer,
                modality_class=ModalityClass.CONTROL_PLANE,
                entity_type=EntityType.DEVICE, entity_id=host,
                severity=Severity.HIGH,
                # `notify` keeps this distinct from the ADJCHANGE branch's id, so
                # both reports of one teardown survive in the same millisecond.
                native_id=f"{host}|bgp_adj|notify|{peer or '?'}|{code or '-'}|down|{ts_ms}",
                entity_tokens=tokens, metric_name="bgp_adjacency",
                attrs={"peer": peer, "state": "down", "subtype": "notification",
                       "code": code, "reason": reason, "tag": tag,
                       **P._prov(_R["syslog.bgp.notification"])},
            )
        # A limit that was EXCEEDED shuts the peer; a threshold warning does not.
        state = "down" if (maxpfx and shut) else "churn"
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.SYSLOG,
            kind=_R["syslog.bgp.route_churn"].kind, observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=host,
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=(f"{host}|bgp_churn|{subtype}|{peer or '?'}|"
                       f"{pfx_count or '-'}|{state}|{ts_ms}"),
            entity_tokens=tokens, metric_name="bgp_route_churn",
            attrs={"peer": peer, "state": state, "subtype": subtype,
                   "reason": reason, "prefix_count": pfx_count,
                   "prefix_max": pfx_max, "tag": tag, **P._prov(_R["syslog.bgp.route_churn"])},
        )

    if ("LINK" in ctoken or "LINEPROTO" in ctoken) and "UPDOWN" in ctoken:
        if_m = _IF_RE.search(msg)
        ifname = if_m.group(1) if if_m else "unknown"
        state = _state_of(msg)
        return Signal(
            tenant_id=tenant,
            ts=ts,
            source=Source.SYSLOG,
            kind=_R["syslog.link.state_change"].kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE,
            entity_id=f"{host}:{ifname}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|link|{ifname}|{state}|{ts_ms}",
            entity_tokens=(host,),   # tracker 168: entity_id is already host:ifname
            metric_name="link_state",
            attrs={"interface": ifname, "state": state, "tag": tag,
                   **P._prov(_R["syslog.link.state_change"])},
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
            kind=_R["syslog.lldp.neighbor_change"].kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE,
            entity_id=f"{host}:{ifname}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|lldp|{ifname}|{state}|{ts_ms}",
            entity_tokens=(host,),   # tracker 168: entity_id is already host:ifname
            metric_name="lldp_neighbor",
            attrs={"interface": ifname, "state": state, "tag": tag or "remotePeer",
                   **P._prov(_R["syslog.lldp.neighbor_change"])},
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
        rule_stp = _R["syslog.stp.topology_change"] if ifname else _R["syslog.stp.topology_notification"]
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
                   "state": state, "tag": tag, **P._prov(rule_stp)},
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
            tenant_id=tenant, ts=ts, source=Source.SYSLOG, kind=_R["syslog.vtep.state_change"].kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=host,
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{host}|vtep|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens, metric_name="vtep_state",
            attrs={"vtep": peer, "state": state, "tag": tag, **P._prov(_R["syslog.vtep.state_change"])},
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
            tenant_id=tenant, ts=ts, source=Source.SYSLOG, kind=_R["syslog.evpn.mac_move"].kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=host,
            severity=Severity.HIGH,
            native_id=f"{host}|evpn_mac|{mac or '?'}|vlan{vlan or '?'}|{ts_ms}",
            entity_tokens=tokens or (host,), metric_name="evpn_mac_move",
            attrs={"mac": mac, "vlan": vlan, "vni": vni, "vtep": vtep,
                   "blacklisted": blacklisted, "tag": tag, **P._prov(_R["syslog.evpn.mac_move"])},
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
            kind=_R["syslog.fhrp.state_change"].kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE,
            entity_id=host,
            severity=Severity.HIGH if takeover else Severity.WARN,
            native_id=f"{host}|fhrp|{proto}|{ifname}|grp{group or '?'}|{role or '?'}|{ts_ms}",
            entity_tokens=tokens or (host,),
            metric_name="fhrp_state",
            attrs={"proto": proto, "group": group, "interface": ifname,
                   "state": role, "tag": tag, **P._prov(_R["syslog.fhrp.state_change"])},
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
            kind=_R["syslog.mac.flap"].kind,
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
                   **P._prov(_R["syslog.mac.flap"])},
        )

    # Generic device-alarm fallback (#80 §4 keystone) — the SAFETY NET. Nothing
    # above recognized this event, but if the DEVICE itself flagged it at warning
    # or worse it is still real evidence: one canonical `device_alarm` signal so it
    # grounds + correlates + tiers like any other (no per-mnemonic branch). Below
    # the floor (notice/info/debug) stays a searchable log, never an RCA signal.
    sev_num = P.syslog_severity_num(ev, tag)
    if sev_num is not None and sev_num <= P.ALARM_SEVERITY_FLOOR:
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
            kind=_R["syslog.generic.device_alarm"].kind,
            observer=observer,
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=etype_,
            entity_id=eid_,
            severity=P._severity_from_num(sev_num),
            # tracker 198: the message text is the discriminator — without it two
            # DISTINCT unrecognized lines sharing facility+mnemonic(+interface) in
            # one millisecond collapsed onto one signal_id and one of them was
            # dropped as a "replay". Byte-identical redelivery still dedups.
            native_id=P._tagged_native_id(
                f"{host}|alarm|{facility}|{mnem or '?'}|{ifname or '-'}|{ts_ms}", msg),
            entity_tokens=toks_,
            metric_name="device_alarm",
            attrs={"facility": facility, "mnemonic": mnem, "severity": sev_num,
                   "interface": ifname, "tag": tag, "text": msg[:256],
                   **P._prov(_R["syslog.generic.device_alarm"])},
        )

    return None


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
    ts = P.parse_event_ts(ev.get("timestamp"), reference=ingest_ts) or ingest_ts
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
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=_R["trap.link.state_change"].kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE, entity_id=f"{device}:{iface}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{device}|trap_link|{iface}|{state}|{ts_ms}",
            entity_tokens=(device,), metric_name="link_state",   # tracker 168
            attrs={"interface": iface, "state": state, "trap_oid": oid,
                   "authenticated": authed, **P._prov(_R["trap.link.state_change"])},
        )

    # Device restart — device-scoped lifecycle event.
    if oid in (_TRAP_COLDSTART, _TRAP_WARMSTART) or name in ("coldStart", "warmStart"):
        kind_type = "cold" if (oid == _TRAP_COLDSTART or name == "coldStart") else "warm"
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=_R["trap.device.restart"].kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=device,
            severity=Severity.HIGH,
            native_id=f"{device}|trap_restart|{kind_type}|{ts_ms}",
            entity_tokens=(device,), metric_name="device_restart",
            attrs={"restart": kind_type, "trap_oid": oid, "authenticated": authed,
                   **P._prov(_R["trap.device.restart"])},
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
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=_R["trap.bgp.adjacency_change"].kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=entity_id,
            severity=Severity.WARN if established else Severity.HIGH,
            native_id=f"{device}|trap_bgp|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens, metric_name="bgp_adjacency",
            attrs={"peer": peer, "state": state, "trap_oid": oid,
                   "authenticated": authed, **P._prov(_R["trap.bgp.adjacency_change"])},
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
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=_R["trap.bgp.adjacency_change.event_type"].kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=entity_id,
            severity=Severity.WARN if established else Severity.HIGH,
            native_id=f"{device}|trap_bgp|{peer or '?'}|{state}|{ts_ms}",
            entity_tokens=tokens, metric_name="bgp_adjacency",
            attrs={"peer": peer, "state": state, "trap_oid": oid, "event_type": etype,
                   "authenticated": authed, **P._prov(_R["trap.bgp.adjacency_change.event_type"])},
        )
    if "link" in etype and ("down" in etype or "up" in etype):
        state = "down" if "down" in etype else "up"
        iface = _trap_interface(ev)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=_R["trap.link.state_change.event_type"].kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.INTERFACE, entity_id=f"{device}:{iface}",
            severity=Severity.HIGH if state == "down" else Severity.WARN,
            native_id=f"{device}|trap_link|{iface}|{state}|{ts_ms}",
            entity_tokens=(device,), metric_name="link_state",   # tracker 168
            attrs={"interface": iface, "state": state, "trap_oid": oid, "event_type": etype,
                   "authenticated": authed, **P._prov(_R["trap.link.state_change.event_type"])},
        )
    if "start" in etype and ("cold" in etype or "warm" in etype):
        kind_type = "cold" if "cold" in etype else "warm"
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=_R["trap.device.restart.event_type"].kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE, entity_id=device, severity=Severity.HIGH,
            native_id=f"{device}|trap_restart|{kind_type}|{ts_ms}",
            entity_tokens=(device,), metric_name="device_restart",
            attrs={"restart": kind_type, "trap_oid": oid, "event_type": etype,
                   "authenticated": authed, **P._prov(_R["trap.device.restart.event_type"])},
        )

    # Generic device-alarm fallback (#80 §4 keystone) — an unclassified trap is
    # still real evidence IF the device/MIB flagged it at warning or worse (the MIB
    # severity the Go receiver's trapMeta resolved). One canonical `device_alarm`
    # signal so vendor alarm traps with no dedicated branch still ground + correlate.
    # Below the floor stays searchable in OpenSearch, never an RCA signal.
    sev_num = P._SEVERITY_NUM.get(str(ev.get("severity") or "").strip().lower())
    if sev_num is not None and sev_num <= P.ALARM_SEVERITY_FLOOR:
        iface = _trap_interface(ev)
        toks_: tuple[str, ...]
        if iface and iface != "unknown":
            etype_, eid_, toks_ = EntityType.INTERFACE, f"{device}:{iface}", (device,)   # tracker 168
        else:
            etype_, eid_, toks_ = EntityType.DEVICE, device, (device,)
        return Signal(
            tenant_id=tenant, ts=ts, source=Source.TRAP, kind=_R["trap.generic.device_alarm"].kind,
            observer=observer, modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=etype_, entity_id=eid_, severity=P._severity_from_num(sev_num),
            # tracker 198 (same defect as the syslog generic alarm above): the OID
            # alone does not identify the EVENT — two unclassified traps of one
            # OID differing only in their varbinds (different entity, different
            # threshold) collided in a millisecond. The varbind rendering is the
            # trap's content; it is stable under redelivery.
            native_id=P._tagged_native_id(
                f"{device}|alarm|{oid or '?'}|{ts_ms}", _trap_content(ev, name, etype)),
            entity_tokens=toks_, metric_name="device_alarm",
            attrs={"trap_oid": oid, "trap_name": name, "event_type": etype,
                   "category": str(ev.get("category") or ""), "severity": sev_num,
                   "authenticated": authed,
                   "interface": iface if iface != "unknown" else "",
                   **P._prov(_R["trap.generic.device_alarm"])},
        )

    return None  # unclassified — searchable in OpenSearch, no RCA signal



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
    # H11: cap BEFORE any regex — see P._PORT_EVENT_TEXT_CAP. Each part is capped
    # on its own so an oversized message can never truncate away the structured
    # fields (facility/event_type/appname) a vendor line may classify on.
    ctoken = " ".join((
        msg[:P._PORT_EVENT_TEXT_CAP],
        str(ev.get("facility") or "")[:256],
        str(ev.get("event_type") or "")[:256],
        str(ev.get("appname") or "")[:256],
    ))
    # One union search instead of twelve (tracker 156). Placed BEFORE the
    # timestamp parse and the Observer construction, because for a non-port line
    # those were pure waste too — an allocation and a date parse per event that
    # nothing ever read.
    if not P._PORT_EVENT_PREFILTER.search(ctoken):
        return None
    ts = P.parse_event_ts(ev.get("timestamp"), reference=ingest_ts) or ingest_ts
    ts_ms = int(ts.timestamp() * 1000)
    # Interned (tracker 156): identical per-device Observer built on every event.
    observer = observer_of(
        host, ObserverType.DEVICE,
        collection_path="direct", clock_quality="unknown",
    )
    for pat, kind, iface_scoped, sev in P._PORT_EVENT_RULES:
        if not pat.search(ctoken):
            continue
        # W1b: the table row this rule came from, for provenance + the hit
        # counter. `P._PORT_EVENT_RULES` is derived from `_PORT_RULES`, so the
        # lookup always hits in production; it can miss only for a rule a TEST
        # injected, and such a rule then carries no provenance rather than
        # inventing a rule_id that is in no table.
        rule = P._PORT_RULE_BY_KIND.get(kind)
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
                   **(P._prov(rule) if rule is not None else {})},
        )
    return None

