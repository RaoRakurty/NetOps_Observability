#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Generate + validate the embedded OID index (oididx.json) — BUILD TIME ONLY.

Design: docs/design/research/telemetry-normalization-architecture.md §6.

Compiles a curated MIB set with pysmi's `mibdump` (offline-capable; resolves
IMPORTS from vendored dirs first, then public mirrors) into JSON, then flattens
every object/column/notification into the runtime index
({name,mib,kind,type,enum,severity_hint}). The Go runtime only embeds the JSON
(stdlib `embed`); pysmi is build-time tooling, never a runtime dep (CLAUDE.md §6).

  python3 gen_index.py                 # default MIB set
  MIBS="IF-MIB ARISTA-SMI-MIB" python3 gen_index.py   # override

Adds vendor coverage = list the vendor's trap MIBs below (or via $MIBS) and ensure
they're reachable from a --mib-source (vendored dir or the LibreNMS mirror).
"""
from __future__ import annotations
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "index", "oididx.json")
VENDOR_LOCAL = [os.path.join(HERE, d) for d in ("ietf", "iana")] + [
    os.path.join(HERE, "vendor", v)
    for v in (sorted(os.listdir(os.path.join(HERE, "vendor"))) if os.path.isdir(os.path.join(HERE, "vendor")) else [])
]

# Curated MIB set: IETF core every fabric emits + the lab's vendors. Expand here
# (or $MIBS). Vendor MIBs resolve from the LibreNMS mirror source below.
DEFAULT_MIBS = [
    "SNMPv2-MIB", "IF-MIB", "BGP4-MIB", "OSPF-MIB", "OSPF-TRAP-MIB", "ISIS-MIB",
    "ENTITY-MIB", "ENTITY-SENSOR-MIB", "IP-MIB", "TCP-MIB", "UDP-MIB",
    "HOST-RESOURCES-MIB", "LLDP-MIB", "BRIDGE-MIB", "Q-BRIDGE-MIB",
    "P-BRIDGE-MIB", "RSTP-MIB", "DISMAN-EVENT-MIB", "CISCO-CONFIG-MAN-MIB",
    # Arista (enterprise 30065) — the lab's spines/leaves. Modules from the
    # LibreNMS mirror (SOURCES below). Cover interface/BGP/entity/sensor/bridging
    # objects + their notification subtrees.
    "ARISTA-SMI-MIB", "ARISTA-GENERAL-MIB", "ARISTA-IF-MIB", "ARISTA-BGP4V2-MIB",
    "ARISTA-BGP4V2-TC-MIB", "ARISTA-ENTITY-SENSOR-MIB", "ARISTA-VRF-MIB",
    "ARISTA-NEXTHOP-GROUP-MIB", "ARISTA-MLAG-MIB", "ARISTA-REDUNDANCY-MIB",
    "ARISTA-BRIDGING-MIB", "ARISTA-MAC-ACCOUNTING-MIB",
    # Cisco (enterprise 9) — IOS/NX-OS. High-value object + notification MIBs.
    "CISCO-SMI", "CISCO-TC", "CISCO-PROCESS-MIB", "CISCO-ENVMON-MIB",
    "CISCO-ENTITY-FRU-CONTROL-MIB", "CISCO-SYSLOG-MIB", "CISCO-BGP4-MIB",
    "CISCO-OSPF-MIB", "OLD-CISCO-INTERFACES-MIB", "CISCO-MEMORY-POOL-MIB",
    # Juniper (enterprise 2636) — Junos.
    # JUNIPER-CHASSIS-DEFINES-MIB is deliberately NOT here (tracker 377): it is
    # 2.8k product/slot IDENTITY OIDs (jnxProductName*, jnxSlot*), no
    # notification and no column, so it can decode no trap — the receiver names
    # varbinds by their OID, never by an OID-valued payload. pysmi also fails on
    # it (duplicate symbol jnxSlotMX2010 in Juniper's own file), and net-snmp
    # would print its identities as OBJECT-TYPE, i.e. 2.8k mislabelled
    # `scalar` nodes. Listing it only ever produced a silent failure.
    "JUNIPER-SMI", "JUNIPER-MIB",
    "JUNIPER-IF-MIB", "BGP4-V2-MIB-JUNIPER", "JUNIPER-CFGMGMT-MIB",
    # Nokia SR OS (enterprise 6527) — TiMetra.
    "TIMETRA-GLOBAL-MIB", "TIMETRA-CHASSIS-MIB", "TIMETRA-BGP-MIB",
    "TIMETRA-LOG-MIB", "TIMETRA-SYSTEM-MIB",
]
# mibdump source order: vendored dirs (offline, authoritative) → public mirror →
# LibreNMS comprehensive vendor mirror, including the per-vendor subdirs (@mib@ is
# the module-name placeholder; mibdump tries each source until a module resolves).
_LNMS = "https://raw.githubusercontent.com/librenms/librenms/master/mibs"
SOURCES = ["file://" + d for d in VENDOR_LOCAL if os.path.isdir(d)] + [
    "https://mibs.pysnmp.com/asn1/@mib@",
    f"{_LNMS}/@mib@",
] + [f"{_LNMS}/{v}/@mib@" for v in ("arista", "cisco", "juniper", "nokia", "dell", "fortinet")]

# MIBs carry no universal severity; seed the well-known notifications here.
#
# WHY A HINT IS NOT COSMETICS — IT IS THE ADMISSION GATE. `trapMeta()`
# (collectors/snmptrap.go) falls back to "notice" for a notification with no
# hint, and notice (5) is BELOW the correlation engine's
# `producers.ALARM_SEVERITY_FLOOR` (4 = warning). A trap that lands below that
# floor is stored and searchable in OpenSearch and NEVER reaches the engine —
# not even as the generic `device_alarm` safety net. So an unhinted (or
# notice-hinted) notification is invisible to RCA by omission, which is exactly
# what the A9 trap audit found for the two families below.
#
# THE RULE THIS TABLE FOLLOWS. A notification that reports a FAULT, a
# DEGRADATION or a CHANGE OF STATE an operator would want correlated is
# `warning`; its recovery/clear twin is `info` — the same split `linkDown` /
# `linkUp` has always had. `info` still reaches OpenSearch; it just never opens
# an RCA object on its own.
SEVERITY_HINT = {
    # ── IETF core ────────────────────────────────────────────────────────────
    "linkDown": "warning", "authenticationFailure": "warning",
    "bgpBackwardTransition": "warning", "ospfNbrStateChange": "warning",
    # CISCO-BGP4-MIB deliberately carries NO hint (2026-11-03): decoded, its
    # notifications are named and searchable, but a `warning` seed would lift
    # each of the up-to-five cbgp traps IOS-XE sends per transition over the
    # alarm floor as a generic device_alarm. They get a typed rule with
    # one-signal-per-transition identity instead (tracker 374).
    "ospfIfStateChange": "warning", "coldStart": "info", "warmStart": "info",
    "linkUp": "info", "bgpEstablished": "info",
    # TIMETRA-BGP-MIB (tracker 377): Nokia sends these for IPv6 peers ONLY (IPv4
    # uses the RFC 4273 pair), so there is no multi-family duplication to guard
    # against — the same fault/recovery split as bgpBackwardTransition/
    # bgpEstablished. They are typed by `trap.bgp.nokia_ng`.
    "tBgpNgBackwardTransition": "warning", "tBgpNgEstablished": "info",
    # RFC 7331 (tracker 387): every vendor's BFD session, the same split again.
    # They are typed by `trap.bfd.session`, so this only makes the stored level true.
    "bfdSessDown": "warning", "bfdSessUp": "info",

    # ── CONFIG CHANGE (A9 follow-up) ─────────────────────────────────────────
    # "What changed?" is the first question of every real RCA, and a config
    # change is the direct input to the security hardening-drift story. These
    # were `notice`/unhinted, i.e. below the floor: the engine could not see a
    # device being reconfigured AT ALL. They are `warning`, not higher: a
    # change is not itself a fault — it is context that must be REACHABLE.
    # The parser types them further as `device_config_change`
    # (telemetry-catalog/events.yaml, rule `trap.config.change`) — all except
    # `entConfigChange`, which is an INVENTORY change (module / PSU / SFP added
    # or removed) and stays a generic `device_alarm` (E5b).
    "entConfigChange": "warning",              # was notice — below the floor
    "ciscoConfigManEvent": "warning",          # was notice — below the floor
    "ccmCLIRunningConfigChanged": "warning",
    "jnxCmCfgChange": "warning", "jnxCmRescueChange": "warning",
    "tmnxConfigModify": "warning", "tmnxConfigCreate": "warning",
    "tmnxConfigDelete": "warning",

    # ── HARDWARE / ENVIRONMENT (A9 follow-up) ────────────────────────────────
    # Fan, PSU, temperature, FRU and entity-sensor health. Every one of these
    # was UNHINTED and therefore defaulted to `notice`: a failed power supply
    # or an over-temperature chassis never became evidence. There is no typed
    # syslog kind for environmental health to pair them with (see the coverage
    # matrix, "Audited and NOT promoted"), so they stay GENERIC `device_alarm`s
    # — but a generic alarm the engine can see is the whole point.
    #
    # BOUNDARY: CPU/memory pressure (cpmCPURisingThreshold,
    # ciscoMemoryPoolLowMemoryNotif) is deliberately NOT here — the metric
    # lane already carries it as `device_resource_anomaly` with a real
    # magnitude, and a generic alarm would be a second kind for one symptom. The
    # typed rows that exist (`trap.resource.*`, `trap.sdwan.*`, tracker 387) land
    # on that episode's own node, from the same observer, below the open floor.
    #   Cisco — ENVMON
    "ciscoEnvMonFanNotification": "warning",
    "ciscoEnvMonTemperatureNotification": "warning",
    "ciscoEnvMonVoltageNotification": "warning",
    "ciscoEnvMonRedundantSupplyNotification": "warning",
    "ciscoEnvMonShutdownNotification": "warning",
    "ciscoEnvMonFanStatusChangeNotif": "warning",
    "ciscoEnvMonSuppStatusChangeNotif": "warning",
    "ciscoEnvMonTempStatusChangeNotif": "warning",
    "ciscoEnvMonVoltStatusChangeNotif": "warning",
    #   Cisco — ENTITY-FRU-CONTROL (an insert is inventory, not a fault)
    "cefcModuleStatusChange": "warning", "cefcPowerStatusChange": "warning",
    "cefcFanTrayStatusChange": "warning",
    "cefcPowerSupplyOutputChange": "warning",
    "cefcUnrecognizedFRU": "warning", "cefcFRURemoved": "warning",
    "cefcFRUInserted": "info",
    #   IETF entity state + Arista sensor alarm
    "entStateOperDisabled": "warning", "entStateOperEnabled": "info",
    "aristaEntSensorAlarm": "warning",
    #   Juniper — the fault/recovery pairs the MIB defines explicitly
    "jnxFanFailure": "warning", "jnxPowerSupplyFailure": "warning",
    "jnxOverTemperature": "warning", "jnxFruFailed": "warning",
    "jnxFruOffline": "warning", "jnxFruPowerOff": "warning",
    "jnxFruRemoval": "warning", "jnxFruCheck": "warning",
    "jnxHardDiskFailed": "warning", "jnxHardDiskMissing": "warning",
    "jnxFanOK": "info", "jnxPowerSupplyOK": "info",
    "jnxTemperatureOK": "info", "jnxFruOK": "info",
    "jnxFruOnline": "info", "jnxFruPowerOn": "info",
    "jnxFruInsertion": "info",
    #   Nokia SR OS — chassis equipment
    "tmnxEqFanFailure": "warning", "tmnxEqPowerSupplyFailure": "warning",
    "tmnxEnvTempTooHigh": "warning", "tmnxEqCardFailure": "warning",
    "tmnxEqMemoryFailure": "warning", "tmnxEqCpuFailure": "warning",
    "tmnxEqPowerSupplyRemoved": "warning",
    "tmnxEqPowerSupplyInserted": "info", "tmnxEqCardInserted": "info",
}
# Standard OIDs whose MIB won't compile from source here (SMIv1 grammar, e.g.
# Q-BRIDGE-MIB→RFC-1212) but which are stable IETF definitions — anchored so the
# common L2/MAC varbinds resolve by name. Compiled MIBs override these if present.
STD_OVERLAY = {
    "1.3.6.1.2.1.17.7.1.2.2.1.2": {"name": "dot1qTpFdbPort", "mib": "Q-BRIDGE-MIB", "kind": "column", "type": "INTEGER"},
    "1.3.6.1.2.1.17.7.1.2.2.1.3": {"name": "dot1qTpFdbStatus", "mib": "Q-BRIDGE-MIB", "kind": "column", "type": "INTEGER",
                                   "enum": {"1": "other", "2": "invalid", "3": "learned", "4": "self", "5": "mgmt"}},
    "1.3.6.1.2.1.17.4.3.1.1": {"name": "dot1dTpFdbAddress", "mib": "BRIDGE-MIB", "kind": "column", "type": "MacAddress"},
    "1.3.6.1.2.1.17.4.3.1.2": {"name": "dot1dTpFdbPort", "mib": "BRIDGE-MIB", "kind": "column", "type": "INTEGER"},
    # ARISTA-BRIDGE-EXT-MIB (30065.3.2) objects + module node now come from the REAL
    # MIB via the net-snmp pass (correct OIDs). Only the 30065.3.2.0.x enterprise
    # traps stay anchored here: the module defines NO NOTIFICATION-TYPE, so these
    # v1-form traps have no name in any MIB. Named from the module's sole documented
    # purpose ("host move information"; aristaDot1qTpFdbNumMoves = "number of times a
    # MAC changed ports"). net-snmp can't supply them — no compiler can.
    "1.3.6.1.4.1.30065.3.2.0.1": {"name": "aristaBridgeExtMacMove", "mib": "ARISTA-BRIDGE-EXT-MIB", "kind": "notification", "severity_hint": "warning"},
    "1.3.6.1.4.1.30065.3.2.0.2": {"name": "aristaBridgeExtMacMove", "mib": "ARISTA-BRIDGE-EXT-MIB", "kind": "notification", "severity_hint": "warning"},
}
ASSERTIONS = {  # regression guard — mirrors collectors/oidindex_test.go
    "1.3.6.1.2.1.2.2.1.8": ("ifOperStatus", "column"),
    "1.3.6.1.6.3.1.1.5.3": ("linkDown", "notification"),
    "1.3.6.1.2.1.1.5.0": ("sysName", "scalar"),
    # CISCO-BGP4-MIB reaches the index (it silently did not until 2026-11-03).
    "1.3.6.1.4.1.9.9.187.0.1": ("cbgpFsmStateChange", "notification"),
    "1.3.6.1.4.1.9.9.187.0.8": ("cbgpPeer2BackwardTransition", "notification"),
    "1.3.6.1.4.1.9.9.187.1.2.5.1.3": ("cbgpPeer2State", "column"),
    # tracker 377: four modules pysmi silently dropped (they import SMIv1
    # RFC-1212 somewhere in their chain) now reach the index via net-snmp.
    "1.0.8802.1.1.2.0.0.1": ("lldpRemTablesChange", "notification"),
    "1.3.6.1.4.1.9.2.2.1.1.20": ("locIfReason", "column"),
    "1.3.6.1.4.1.6527.3.1.3.14.0.8": ("tBgpNgBackwardTransition", "notification"),
    "1.3.6.1.4.1.6527.3.1.2.14.4.7.1.59": ("tBgpPeerNgConnState", "column"),
    # tracker 387: the live vEdge trap and the varbinds recorded on the lab.
    "1.3.6.1.4.1.41916.100.2.114": ("viptelaSystemCpuUsage", "notification"),
    "1.3.6.1.4.1.41916.100.1.1": ("eventTime", "scalar"),
    "1.3.6.1.4.1.41916.100.1.2": ("netconfNotificationSeverity", "scalar"),
    "1.3.6.1.4.1.41916.100.1.54": ("viptelaSystemWarning", "scalar"),
    "1.3.6.1.4.1.41916.100.1.190": ("viptelaSystemCpuUserPercentage", "scalar"),
    "1.3.6.1.4.1.41916.100.1.191": ("viptelaSystemCpuSystemPercentage", "scalar"),
    "1.3.6.1.4.1.41916.100.1.192": ("viptelaSystemCpuIdlePercentage", "scalar"),
    # One symbol, several modules: each module's own OID must survive.
    "1.3.6.1.4.1.9.9.1006.2.2": ("netconfNotificationSeverity", "scalar"),
    "1.3.6.1.4.1.9.9.1006.0.1": ("ciscoSdwanSecurityControlConnectionStateChange", "notification"),
    "1.3.6.1.4.1.9.9.1002.0.1": ("ciscoSdwanBfdStateChange", "notification"),
    # RFC 7331.
    "1.3.6.1.2.1.222.0.1": ("bfdSessUp", "notification"),
    "1.3.6.1.2.1.222.0.2": ("bfdSessDown", "notification"),
}


def mibdump(mibs: list[str], outdir: str) -> None:
    # Compile per-MIB into a shared dir so one MIB's SMIv1 grammar failure (e.g.
    # BGP4-MIB→RFC-1212) doesn't abort the batch; pysmi borrows pre-compiled JSON
    # for ones it can't parse from source.
    exe = shutil.which("mibdump") or os.path.expanduser("~/.local/bin/mibdump")
    for mib in mibs:
        cmd = [exe, "--destination-format", "json", "--destination-directory", outdir]
        for s in SOURCES:
            cmd += ["--mib-source", s]
        cmd.append(mib)
        try:
            r = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            print(f"gen_index: timeout compiling {mib} — skipped", file=sys.stderr)
            continue
        # NEVER silent (scripts/CLAUDE.md §16.1): a module pysmi failed or
        # ignored contributes nothing, and CISCO-BGP4-MIB sat in DEFAULT_MIBS
        # with zero nodes for months because this line said nothing. Name it;
        # the net-snmp pass may still cover it (NETSNMP_ROOTS).
        out = (r.stdout or "") + (r.stderr or "")
        for label in ("Failed MIBs:", "Ignored MIBs:"):
            line = next((ln for ln in out.splitlines() if ln.startswith(label)), "")
            if mib in [m.strip().split(" (")[0] for m in line[len(label):].split(",")]:
                print(f"gen_index: pysmi {label[:-6].lower()} {mib} — no pysmi nodes from it", file=sys.stderr)


def flatten(outdir: str) -> dict[str, dict]:
    nodes: dict[str, dict] = {}
    for fn in sorted(os.listdir(outdir)):
        if not fn.endswith(".json"):
            continue
        mod = fn[:-5]
        try:
            data = json.load(open(os.path.join(outdir, fn)))
        except Exception:
            continue
        for sym, obj in data.items():
            if not isinstance(obj, dict):
                continue
            oid = obj.get("oid")
            cls, nt = obj.get("class"), obj.get("nodetype")
            if not oid or "." not in str(oid):
                continue
            if cls in ("notificationtype", "trapnotification"):
                kind = "notification"
            elif nt == "column":
                kind = "column"
            elif nt == "scalar":
                kind = "scalar"
            else:
                continue  # tables/groups/types aren't varbind/trap targets
            node = {"name": obj.get("name", sym), "mib": mod, "kind": kind}
            syn = obj.get("syntax") or {}
            if isinstance(syn, dict):
                if syn.get("type"):
                    node["type"] = syn["type"]
                enum = (syn.get("constraints") or {}).get("enumeration")
                if isinstance(enum, dict) and enum:
                    node["enum"] = {str(v): k for k, v in enum.items()}  # int→label
            if kind == "notification" and node["name"] in SEVERITY_HINT:
                node["severity_hint"] = SEVERITY_HINT[node["name"]]
            nodes.setdefault(oid, node)  # first module wins (deterministic order)
    return nodes


# ── net-snmp compile path (for MIBs pysmi can't parse) ────────────────────────
# pysmi 2.0 fails on the SMIv1 RFC-1212 OBJECT-TYPE macro, which blocks the entire
# bridge-MIB family (BRIDGE/P-BRIDGE/Q-BRIDGE + vendor extensions). net-snmp's
# snmptranslate parses SMIv1 correctly, so we compile the vendored MIB tree with it
# and extract the high-value subtrees with REAL, authoritative OIDs (no hand-anchors).
VENDORED = os.path.join(HERE, "vendored")
NETSNMP_ROOTS = (
    "1.3.6.1.2.1.17",         # dot1dBridge / dot1q / p-bridge (FDB/MAC tables)
    "1.3.6.1.4.1.30065.3.2",  # ARISTA-BRIDGE-EXT-MIB (MAC-move tracking)
    # CISCO-BGP4-MIB. pysmi drops the whole module: it IMPORTS BGP4-MIB, whose
    # SMIv1 RFC-1212 grammar pysmi cannot parse, so the module was listed in
    # DEFAULT_MIBS yet contributed ZERO nodes — every cbgp* trap (IOS-XE's BGP
    # session transitions, incl. the only carrier of recoveries) arrived as an
    # undecoded enterpriseSpecific (recorded on the lab, 2026-11-01; E7).
    "1.3.6.1.4.1.9.9.187",
    # tracker 377 — the same silent drop, the same cure. Each module (or a module
    # in its import chain) imports SMIv1 RFC-1212, which pysmi cannot parse, so
    # pysmi reported it IGNORED and it contributed nothing:
    "1.0.8802.1.1.2",            # LLDP-MIB (lldpRemTablesChange = neighbour churn)
    "1.3.6.1.2.1.134",           # RSTP-MIB (RFC 4318 objects)
    "1.3.6.1.4.1.9.2.2",         # OLD-CISCO-INTERFACES-MIB (locIfReason in linkDown)
    "1.3.6.1.4.1.6527.3.1.2.14",  # TIMETRA-BGP-MIB objects (tBgpPeerNg* varbinds)
    "1.3.6.1.4.1.6527.3.1.3.14",  # TIMETRA-BGP-MIB notifications (IPv6 sessions)
    # RFC 7331 BFD-STD-MIB: the standard BFD session path, every vendor at once.
    "1.3.6.1.2.1.222",
    # Tracker 387, Cisco SD-WAN. Only the trap subtrees, never the operational
    # tables: the index is what a TRAP needs decoded, and VIPTELA-TRAPS alone
    # carries all of a vEdge's notifications and their varbinds.
    "1.3.6.1.4.1.41916.100",      # VIPTELA-TRAPS (Viptela OS: vEdge + controllers)
    # IOS XE SD-WAN (cEdge) sends from Cisco's own tree (ciscoMgmt), not 41916.
    # `.0` = notifications, `.2` = their varbinds.
    "1.3.6.1.4.1.9.9.1003.0", "1.3.6.1.4.1.9.9.1003.2",  # CISCO-SDWAN-OMP-MIB
    "1.3.6.1.4.1.9.9.1006.0", "1.3.6.1.4.1.9.9.1006.2",  # CISCO-SDWAN-SECURITY-MIB
    # CISCO-SDWAN-BFD-MIB: notifications ONLY, deliberately. The arcs of its
    # varbinds (ciscoSdwanBfdLocalSystemIp, ...RemoteColor, ...) MOVE between
    # releases (17.9 != 17.12 != 26.1, measured at the pinned commit), so naming
    # them from one release would mislabel another release's values. They stay
    # honestly numeric until a capture says which layout a device sends.
    "1.3.6.1.4.1.9.9.1002.0",
)
_TZ_RE = re.compile(r'"([^"]+)"\s+"([\d.]+)"')
#: `snmptranslate -Td` block header: `MODULE-NAME::nodeName` alone on a line.
_TD_HEAD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*::([A-Za-z][A-Za-z0-9-]*)$")
NETSNMP_BATCH = 200  # OIDs per snmptranslate call (one full -M parse each)

# ── FETCHED (not redistributed) vendor MIBs ──────────────────────────────────
# Arista's enterprise MIBs carry "Copyright (c) 2008 Arista Networks, Inc. All
# rights reserved." with NO redistribution grant (licence audit 2026-09-03, D4),
# so they are NOT vendored in this repo and do NOT travel in the source tarball.
# The ~55 other vendor MIBs already resolve at build time from a mirror; these
# two could not, only because the SMIv1 net-snmp pass needs real files on disk.
# They are therefore fetched into a GITIGNORED cache that the -M path includes.
#
# ZERO TRUST (CLAUDE.md §3): the mirror is not trusted. Every byte — freshly
# downloaded OR already cached — is checked against the pinned sha256 before it
# reaches the parser. A pin with no sum, a mirror whose content moved, or a
# cache someone edited is a HARD failure with a named reason, never a skip.
FETCHED = os.path.join(VENDORED, ".fetched")
FETCH_TIMEOUT = 30        # seconds per attempt (CLAUDE.md §9: bounded IO)
FETCH_ATTEMPTS = 3        # per URL, with backoff + jitter
FETCH_MAX_BYTES = 4 << 20  # a MIB module is tens of KB; refuse an unbounded body
#: module -> {sha256, urls}. URLs are tried in order; the sum is what is trusted.
FETCH_PINS: dict[str, dict] = {
    "ARISTA-SMI-MIB": {
        "sha256": "0f909eea68ad7144ebc82c3d140653c0faa31e66f6de439921c3e4a4a11ca4e3",
        "urls": (
            "https://mibs.pysnmp.com/asn1/ARISTA-SMI-MIB",
            "https://raw.githubusercontent.com/librenms/librenms/master/mibs/arista/ARISTA-SMI-MIB",
        ),
    },
    "ARISTA-BRIDGE-EXT-MIB": {
        "sha256": "9cb0cc8b5cd2cb26179d2eb1e0a7eb1d5e74e099b8459668fc039b9fa355c8ff",
        "urls": ("https://mibs.pysnmp.com/asn1/ARISTA-BRIDGE-EXT-MIB",),
    },
    # CISCO-BGP4-MIB for the net-snmp pass (see NETSNMP_ROOTS), with every
    # module it imports that the vendored tree lacks. The two Cisco modules
    # carry "Copyright (c) ... Cisco Systems, Inc." with no redistribution grant,
    # so — exactly like Arista — they are fetched, never vendored. The three
    # IETF modules are pinned the same way rather than vendored, which would
    # need the RFC-text provenance SOURCES.md records for every vendored file.
    "CISCO-BGP4-MIB": {
        "sha256": "522ba3a3fa0b27be2bfe8902c4f8d74c77d610796b1fee1b5b8f40acbe3cb7a1",
        "urls": (
            "https://mibs.pysnmp.com/asn1/CISCO-BGP4-MIB",
            "https://raw.githubusercontent.com/librenms/librenms/master/mibs/cisco/CISCO-BGP4-MIB",
        ),
    },
    "CISCO-SMI": {
        "sha256": "3ea80f8160af50ba77e7309b7f95b4b6edb3ddc57dbe67eb0ee18ae1b56fd332",
        "urls": (
            "https://mibs.pysnmp.com/asn1/CISCO-SMI",
            "https://raw.githubusercontent.com/librenms/librenms/master/mibs/cisco/CISCO-SMI",
        ),
    },
    "BGP4-MIB": {
        "sha256": "4dc18e17081988b15fad393bc68b36533a3edf4c8e66c0060d054f6ff6b3909b",
        "urls": ("https://mibs.pysnmp.com/asn1/BGP4-MIB",),
    },
    "INET-ADDRESS-MIB": {
        "sha256": "59563805ec90609c31a1c512aa627fe58a95dfc6eeed53de12622a1493da27d1",
        "urls": ("https://mibs.pysnmp.com/asn1/INET-ADDRESS-MIB",),
    },
    "SNMP-FRAMEWORK-MIB": {
        "sha256": "bcf1faf35bb6dd9cbc06afb7eaf69e03d7da03893ee14df68ceb9424e23287bc",
        "urls": ("https://mibs.pysnmp.com/asn1/SNMP-FRAMEWORK-MIB",),
    },
    # tracker 377 (owner 2026-11-07: extend the fetch posture to Nokia and
    # Juniper). LLDP-MIB, RSTP-MIB, OLD-CISCO-INTERFACES-MIB and TIMETRA-BGP-MIB
    # plus every module in their import chains the vendored tree lacks. All are
    # pinned to ONE LibreNMS COMMIT (not `master`), so the URL is immutable and
    # TIMETRA-BGP-MIB comes from the same Nokia release as the TIMETRA modules it
    # imports. Nokia (TIMETRA-*) and Cisco text carries no redistribution grant:
    # fetched, never vendored — the Arista posture. IEEE/IETF/IANA modules are
    # pinned the same way rather than vendored (SOURCES.md).
    "ATM-TC-MIB": {
        "sha256": "279a938f6d73bba203fb36e47cd702c02e3e54dc2f55608c960c4476ce6c5f82",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/ATM-TC-MIB",),
    },
    "HCNUM-TC": {
        "sha256": "c8d21522e37294169277cab9a9e6e0dae85ce2a106af3e64429ece8f35b6835c",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/HCNUM-TC",),
    },
    "IANA-ADDRESS-FAMILY-NUMBERS-MIB": {
        "sha256": "2c253fe33eb9266849c36f7aae39b059a910e98832026991f8fdf68260c08568",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/IANA-ADDRESS-FAMILY-NUMBERS-MIB",),
    },
    "IANA-RTPROTO-MIB": {
        "sha256": "8848bde6c0141fa6b63a16bc78b6484a15b66b55c80d1c76f8c3cff453b98b87",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/IANA-RTPROTO-MIB",),
    },
    "IEEE8021-PAE-MIB": {
        "sha256": "cf94698475c0208a95c1697f502c17e0751c04f57f6640d739a8fcea32dd7c3f",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/IEEE8021-PAE-MIB",),
    },
    "IP-FORWARD-MIB": {
        "sha256": "6b55a19e712c0012cd2ac9813c5cddb10c93fdfa01e2e87c2c2fe14c41bd2a04",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/IP-FORWARD-MIB",),
    },
    "IP-MIB": {
        "sha256": "6a6ec284b2de6f21a4d090927dba474a131c777d1c0b5a80a57fe21a7dd4a3d3",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/IP-MIB",),
    },
    "LLDP-MIB": {
        "sha256": "f0dac7bac08b6d632d2f2363aba8acf106ee7cf83c15f14823489390c31d6769",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/LLDP-MIB",),
    },
    "OLD-CISCO-INTERFACES-MIB": {
        "sha256": "67bef549d12ee67d01c648346283badb38f49884ac48f83047f746947a7b4342",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/cisco/OLD-CISCO-INTERFACES-MIB",),
    },
    "RFC-1215": {
        "sha256": "dbd38e3a42cb0b391e9dafa606a5ee11ff2dcdd4c6781cb42ae1cd6185bcc4e2",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/RFC-1215",),
    },
    "RSTP-MIB": {
        "sha256": "235203e6c465bad9bee34b6c5ad34d5e61a83e37ca0162a694417c2c87bb8409",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/RSTP-MIB",),
    },
    "SNMPv2-MIB": {
        "sha256": "b4f8ef130f580b86d2b6bc890564e46100785f589431df76954e878a7b166e11",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/SNMPv2-MIB",),
    },
    "TIMETRA-BGP-MIB": {
        "sha256": "b91f895f0ff3a9a4e597fe912900fc1f69ee72f993d522b39ccb4501ef85a023",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-BGP-MIB",),
    },
    "TIMETRA-CHASSIS-MIB": {
        "sha256": "891e287f4d379d65e498dcc476b8e6afa04c9f82856cb78f1b586a833bbb00b1",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-CHASSIS-MIB",),
    },
    "TIMETRA-FILTER-MIB": {
        "sha256": "44fce8b1f8e80fb03764ec9566af5dc5067edcacbcff9734a672d5feb281c4bc",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-FILTER-MIB",),
    },
    "TIMETRA-GLOBAL-MIB": {
        "sha256": "a3a18503892c9bc6c77a1a4969ac43b9f20f76e6d1dd2d6bcf9d4228a7bd7169",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-GLOBAL-MIB",),
    },
    "TIMETRA-PORT-MIB": {
        "sha256": "0a3368d31d7ee6f95a9c8540be77ff820518c549fb59d9eceb1620a982acc331",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-PORT-MIB",),
    },
    "TIMETRA-QOS-MIB": {
        "sha256": "6091dc29d35807b252cc6ff85d06f5412423ee61eda047d1f3b9e91b1c46ae35",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-QOS-MIB",),
    },
    "TIMETRA-SAP-MIB": {
        "sha256": "9e3c006ae30563a22a2ce4e40ffee811e90bd6fa83022a58d49d9e8cb1eea9ac",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-SAP-MIB",),
    },
    "TIMETRA-SERV-MIB": {
        "sha256": "01fee2cf5adeced4137bd921807b3f7c157c645114fc2abf1b584f61754b2edf",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-SERV-MIB",),
    },
    "TIMETRA-TC-MIB": {
        "sha256": "e970f2099fffec00d08b71eca070f11eba4edd8c84123846eaddb5f99314e45a",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-TC-MIB",),
    },
    "TIMETRA-VRTR-MIB": {
        "sha256": "72729fdd64382e64b255e2c2f64ae9e3167428755c231df1fa01ef763318b424",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-VRTR-MIB",),
    },
    # Tracker 387 (owner D4, 2026-11-09): Cisco SD-WAN, from Cisco's OWN repo only,
    # at ONE commit, never a branch name. The repo carries no licence file and the
    # module text no grant, so: fetched, never vendored.
    #
    # WHICH RELEASE, deterministically: the highest-numbered release whose
    # notification set contains every other release's. vEdge: 20.12 has all 123
    # (20.9 lacks 3; 20.18 and 26.1 dropped viptelaSystemPseudoCommitStatus), and
    # 20.15 ties it, so the lower of the tie, whose table the owner checked.
    # Every notification and varbind keeps its arc from 20.9 to 26.1, so one
    # release decodes them all. cEdge: 17.18, the superset of 17.9..26.1.
    # A release is one file per module name, so two releases can never clash.
    "VIPTELA-GLOBAL": {
        "sha256": "e09867c3595a10ef910dfadc29db15cb2904716de4a7ff125165e0151e87cf1d",
        "urls": ("https://raw.githubusercontent.com/cisco/cisco-mibs/c9ab98c03ee051de74edda72f6d5c43ee65cad91/sdwan/controller/20.12/VIPTELA-GLOBAL.mib",),
    },
    "VIPTELA-TRAPS": {
        "sha256": "63c828762372bae49dd47a99c1a99e8c705ad4b8e9f50f883aa1bc86e0aea865",
        "urls": ("https://raw.githubusercontent.com/cisco/cisco-mibs/c9ab98c03ee051de74edda72f6d5c43ee65cad91/sdwan/controller/20.12/VIPTELA-TRAPS.mib",),
    },
    "CISCO-SDWAN-BFD-MIB": {
        "sha256": "9104b6b5b556a217f7871ea8a2b162d66c9a2bbe1ccf8d19351ba6bf4e7adf8f",
        "urls": ("https://raw.githubusercontent.com/cisco/cisco-mibs/c9ab98c03ee051de74edda72f6d5c43ee65cad91/sdwan/device/17.18/CISCO-SDWAN-BFD-MIB.my",),
    },
    "CISCO-SDWAN-OMP-MIB": {
        "sha256": "8d6558a4caa8fd2f9e085160c0bf3bc7283f1dfb8435f437d3a007a5e3748f4c",
        "urls": ("https://raw.githubusercontent.com/cisco/cisco-mibs/c9ab98c03ee051de74edda72f6d5c43ee65cad91/sdwan/device/17.18/CISCO-SDWAN-OMP-MIB.my",),
    },
    "CISCO-SDWAN-SECURITY-MIB": {
        "sha256": "691d6fe69ba36d5891e7961ee4a297d6f66f221fba3aeef3c3d121f138408f44",
        "urls": ("https://raw.githubusercontent.com/cisco/cisco-mibs/c9ab98c03ee051de74edda72f6d5c43ee65cad91/sdwan/device/17.18/CISCO-SDWAN-SECURITY-MIB.my",),
    },
    # RFC 7331 / 7330 (IETF Simplified BSD), with the IANA TC module and imports,
    # at the LibreNMS commit tracker 377 already pins: Cisco's repo has no copy.
    "BFD-STD-MIB": {
        "sha256": "2347ad90da66c030176469a048130f3bcb7f0baf55e4a6a89ee0d93be1aa75f9",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/BFD-STD-MIB",),
    },
    "BFD-TC-STD-MIB": {
        "sha256": "bd5e1d5b3e1f8eb5e789eecec4fc8181fb7e8e1283f667fc463fba2eb7014c7a",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/BFD-TC-STD-MIB",),
    },
    "DIFFSERV-MIB": {
        "sha256": "f4f7178ef2b45fe60bd7a5c498c89e82be95619ae5ddca3442ca7ac0acb9f7a8",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/DIFFSERV-MIB",),
    },
    "DIFFSERV-DSCP-TC": {
        "sha256": "8b2f0df9f3ac448a7a9f3d20897fde4509a8d78d5dcf4a2c01f419dab66e7e6a",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/DIFFSERV-DSCP-TC",),
    },
    "INTEGRATED-SERVICES-MIB": {
        "sha256": "da8fac25d2aaaf060f1c40e9f1682556203454d12ec9890f55f2323c1f92fc96",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/INTEGRATED-SERVICES-MIB",),
    },
    "IANA-BFD-TC-STD-MIB": {
        "sha256": "5617e0077c1e21cce1e3fc318cd2d2d1ff49c495c7b8f405f226141f3176d02d",
        "urls": ("https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/IANA-BFD-TC-STD-MIB",),
    },
}


class FetchError(RuntimeError):
    """A pinned MIB could not be obtained AND verified. Always fatal."""


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str) -> bytes:
    """GET `url` over https with a bounded body and bounded time. Raises the
    last error if every attempt fails — nothing here is swallowed."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise FetchError(f"pinned URL is not https: {url}")
    last: Exception | None = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "correlix-gen_index"})
            # urlopen is safe here: the scheme is asserted https above.
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                body = resp.read(FETCH_MAX_BYTES + 1)
            if len(body) > FETCH_MAX_BYTES:
                raise FetchError(f"{url}: body exceeds {FETCH_MAX_BYTES} bytes")
            return body
        except FetchError:
            raise
        except Exception as exc:  # noqa: BLE001 - never swallowed: retried, then raised
            last = exc
            if attempt < FETCH_ATTEMPTS:
                # backoff + jitter (CLAUDE.md §9)
                time.sleep(min(4.0, 0.5 * 2 ** (attempt - 1)) + random.uniform(0, 0.3))
    raise FetchError(f"{url}: {type(last).__name__}: {last}")


def fetch_pinned_mibs() -> tuple[list[str], list[str]]:
    """Materialise FETCH_PINS into the gitignored cache.

    Returns (verified, skipped) module names. `skipped` is non-empty ONLY when
    the operator explicitly opted out with MIB_FETCH=0 — a DECLARED degraded
    state the caller reports. Every other failure raises FetchError.
    """
    offline = os.environ.get("MIB_FETCH", "1") == "0"
    os.makedirs(FETCHED, exist_ok=True)
    verified: list[str] = []
    skipped: list[str] = []
    for mod, pin in sorted(FETCH_PINS.items()):
        want = str(pin.get("sha256") or "")
        if len(want) != 64 or not re.fullmatch(r"[0-9a-f]{64}", want):
            raise FetchError(f"{mod}: no usable sha256 pin — refusing to trust the mirror")
        dest = os.path.join(FETCHED, mod)
        if os.path.isfile(dest):
            got = _sha256_file(dest)
            if got != want:
                raise FetchError(
                    f"{mod}: cached {dest} has sha256 {got}, pinned {want} — the "
                    "cache is stale or tampered; delete it and re-run")
            verified.append(mod)
            continue
        if offline:
            skipped.append(mod)
            continue
        errors: list[str] = []
        body: bytes | None = None
        for url in pin["urls"]:
            try:
                body = _download(url)
                break
            except FetchError as exc:
                errors.append(str(exc))
        if body is None:
            raise FetchError(
                f"{mod}: every pinned URL failed:\n    " + "\n    ".join(errors)
                + "\n  Set MIB_FETCH=0 to build WITHOUT it (Arista 30065.3.2 objects "
                  "then come only from the existing index floor + STD_OVERLAY).")
        got = hashlib.sha256(body).hexdigest()
        if got != want:
            raise FetchError(
                f"{mod}: downloaded sha256 {got}, pinned {want} — upstream moved or "
                "the transfer was tampered with; verify the new content by hand and "
                "re-pin FETCH_PINS before trusting it")
        tmp = dest + ".part"
        with open(tmp, "wb") as fh:
            fh.write(body)
        os.replace(tmp, dest)  # atomic: a partial file never becomes the cache
        verified.append(mod)
    return verified, skipped


def netsnmp_mib_dirs() -> list[str]:
    """`-M` search path: the vendored tree first, then the fetched cache."""
    return [d for d in (VENDORED, FETCHED) if os.path.isdir(d)]


def _td_blocks_by_oid(text: str) -> dict[str, str]:
    """Split `snmptranslate -Td` output into blocks keyed by the OID each states.

    A block opens with `MODULE::name` and closes with its `::= { iso(1) ... 7 }`
    line, whose arcs are the OID. A block with no such line has no key: it is
    dropped, and its node keeps whatever the floor index holds.
    """
    out: dict[str, str] = {}
    lines: list[str] = []
    for line in text.splitlines():
        if _TD_HEAD_RE.match(line):
            lines = []
            continue
        lines.append(line)
        m = re.match(r"\s*::=\s*\{(.*)\}", line)
        if m:
            arcs = [a.group(1) or a.group(2)
                    for a in re.finditer(r"\((\d+)\)|(?<![\w(-])(\d+)(?![\w)-])", m.group(1))]
            if arcs:
                out[".".join(arcs)] = "\n".join(lines) + "\n"
            lines = []
    return out


def netsnmp_nodes() -> dict:
    """Compile the vendored MIB tree with net-snmp and extract nodes under the
    target subtrees (real OIDs/types/enums). Returns {} if snmptranslate or the
    tree is absent — so the build still works where net-snmp isn't installed."""
    exe = shutil.which("snmptranslate")
    if not exe or not os.path.isdir(VENDORED):
        print("gen_index: net-snmp/vendored tree absent — skipping SMIv1 pass.", file=sys.stderr)
        return {}
    mpath = ":".join(netsnmp_mib_dirs())  # net-snmp -M is colon-separated
    try:
        tz = subprocess.run([exe, "-M", mpath, "-m", "ALL", "-Tz"],
                            capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return {}
    # (name, oid) PAIRS, never a name->oid dict: one symbol may be defined by
    # several modules at different OIDs (netconfNotificationSeverity is in
    # VIPTELA-TRAPS and in four CISCO-SDWAN-* modules), and a dict would keep
    # whichever the walk printed last and lose the others without a word.
    pairs = [(m.group(1), m.group(2)) for m in _TZ_RE.finditer(tz)]
    name_of = {oid: name for name, oid in pairs}                     # oid→name
    out: dict[str, dict] = {}
    wanted = [(name, oid) for name, oid in pairs
              if any(oid == r or oid.startswith(r + ".") for r in NETSNMP_ROOTS)]
    # BATCHED (tracker 377): every snmptranslate call re-parses the WHOLE -M tree
    # (~12 MB once the TIMETRA chain is fetched), so one call per node took ~2 s
    # x ~1,000 nodes and blew the run's budget. `-Td` takes many OIDs; each
    # block it prints starts with a `MODULE::name` header, which keys the block
    # back to its OID by the block's own `::= { ... }` line (never by position,
    # so a node net-snmp declines cannot shift every later block onto the wrong
    # OID; and never by name, which is not unique across modules).
    td_of: dict[str, str] = {}
    for i in range(0, len(wanted), NETSNMP_BATCH):
        chunk = wanted[i:i + NETSNMP_BATCH]
        try:
            text = subprocess.run([exe, "-M", mpath, "-m", "ALL", "-Td", *[o for _, o in chunk]],
                                  capture_output=True, text=True, timeout=300).stdout
        except Exception as exc:
            print(f"gen_index: net-snmp batch {i // NETSNMP_BATCH} failed ({exc}) — its "
                  f"{len(chunk)} node(s) keep their floor entries", file=sys.stderr)
            continue
        td_of.update(_td_blocks_by_oid(text))
    for name, oid in wanted:
        td = td_of.get(oid)
        if td is None:
            continue
        if "NOTIFICATION-TYPE" in td:
            kind = "notification"
        elif "OBJECT-TYPE" in td and "SYNTAX" in td and "SEQUENCE" not in td:
            # net-snmp prints a bare OBJECT IDENTIFIER, a table and a row as
            # OBJECT-TYPE too. Only something with a value syntax is a varbind.
            kind = "column" if name_of.get(oid.rsplit(".", 1)[0], "").endswith("Entry") else "scalar"
        else:
            continue  # OBJECT IDENTIFIER / module-identity / conformance group
        node = {"name": name, "mib": (re.search(r"--\s*FROM\s+([A-Z0-9-]+)", td) or [None, ""])[1], "kind": kind}
        msyn = re.search(r"SYNTAX\s+(\w+)(.*)", td)
        if msyn:
            node["type"] = msyn.group(1)
            # DateAndTime is the one textual convention the receiver decodes (RFC
            # 2579 octets), so it keeps its name, as pysmi's nodes already do.
            if re.search(r"TEXTUAL CONVENTION\s+DateAndTime\b", td):
                node["type"] = "DateAndTime"
            # A label may contain a hyphen (`init-in-gr(5)`). `\w+` alone took
            # `gr` as the label, a wrong name for a real value.
            enum = dict(re.findall(r"([A-Za-z][\w-]*)\((-?\d+)\)", msyn.group(2)))
            if enum:
                node["enum"] = {v: k for k, v in enum.items()}  # int→label
        if kind == "notification" and name in SEVERITY_HINT:
            node["severity_hint"] = SEVERITY_HINT[name]
        out[oid] = node
    return out


# ── table INDEX clauses (tracker 387, trap semantics) ─────────────────────────
# A trap's varbinds name a ROW by their instance suffix: bgpPeerState.10.0.0.1 is
# the bgpPeerTable row of peer 10.0.0.1. Which arcs mean what is stated by the
# row's INDEX (or AUGMENTS) clause and the SYNTAX of each index object, so that is
# what the index records on every column, and the receiver decodes the suffix
# from it with no table named in code:
#   index          the index objects' names, in order (the clause as written)
#   index_oids     their OIDs (a pack keys a meaning, e.g. peer_address, by OID)
#   index_syntax   how each one is encoded in an instance suffix (RFC 2578 §7.7):
#                    ipv4          IpAddress: 4 arcs
#                    int           any INTEGER-based syntax: 1 arc
#                    inet_type     InetAddressType (RFC 4001): 1 arc
#                    inet_address  InetAddress: a length arc, then that many octets
#                                  (the type before it says which length is legal)
#                    string        a variable OCTET STRING: length arc, then octets
#                    fixed:N       a fixed-size OCTET STRING: N arcs, no length
#                    unknown       anything else: the receiver will not guess
#   index_implied  the last object is IMPLIED (no length arc)
# Two compilers state it: pysmi's JSON (`indices` / `augmention` on a row) for the
# modules it compiles, net-snmp's `-Td` (INDEX / AUGMENTS lines) for the rest.
_INDEX_INT_BASES = {"INTEGER", "Integer32", "Unsigned32", "Gauge32", "Counter32",
                    "TimeTicks", "Integer", "Gauge", "Counter"}
_INDEX_FIXED_TCS = {"InetAddressIPv4": 4, "InetAddressIPv6": 16, "InetAddressIPv4z": 8,
                    "InetAddressIPv6z": 20, "MacAddress": 6}
INDEX_ONLY_ENV = "INDEX_ONLY"


def index_token(base: str, tc: str, fixed: int | None) -> str:
    """The suffix encoding of one index object, from its SYNTAX (see above)."""
    if tc == "InetAddressType":
        return "inet_type"
    if tc == "InetAddress":
        return "inet_address"
    if tc in _INDEX_FIXED_TCS:
        return f"fixed:{_INDEX_FIXED_TCS[tc]}"
    b = (base or "").strip()
    if b == "IpAddress":
        return "ipv4"
    if b in _INDEX_INT_BASES:
        return "int"
    if b in ("OCTET STRING", "OCTET", "OctetString"):
        return f"fixed:{fixed}" if fixed else "string"
    return "unknown"


def _pysmi_fixed(constraints: dict | None) -> int | None:
    c = constraints or {}
    if isinstance(c.get("fixed"), int):
        return int(c["fixed"])
    sizes = c.get("size") or []
    if len(sizes) == 1 and isinstance(sizes[0], dict) and sizes[0].get("min") == sizes[0].get("max") \
            and isinstance(sizes[0].get("min"), int) and sizes[0]["min"] > 0:
        return int(sizes[0]["min"])
    return None


def pysmi_index_clauses(outdir: str) -> dict[str, dict]:
    """{column OID: clause} from the rows pysmi compiled into `outdir`."""
    symtab: dict[tuple[str, str], dict] = {}
    tcs: dict[str, dict] = {}
    for fn in sorted(os.listdir(outdir)) if os.path.isdir(outdir) else []:
        if not fn.endswith(".json"):
            continue
        try:
            data = json.load(open(os.path.join(outdir, fn)))
        except (OSError, ValueError) as exc:
            print(f"gen_index: index clauses: {fn} unreadable ({exc}) — skipped", file=sys.stderr)
            continue
        for sym, obj in data.items():
            if isinstance(obj, dict):
                symtab[(fn[:-5], obj.get("name", sym))] = obj
                if obj.get("class") == "textualconvention":
                    tcs.setdefault(obj.get("name", sym), obj)

    def token(obj: dict) -> str:
        syn = obj.get("syntax") or {}
        t = str(syn.get("type") or "")
        cons = syn.get("constraints")
        tc = ""
        if t in tcs:
            tc = t
            tsyn = tcs[t].get("type") or {}
            t = str(tsyn.get("type") or "")
            cons = cons or tsyn.get("constraints")
        return index_token(t, tc, _pysmi_fixed(cons))

    def indices(row: dict, depth: int = 0) -> list[dict] | None:
        if depth > 4:
            return None
        if row.get("indices"):
            return list(row["indices"])
        aug = row.get("augmention") or row.get("augments")
        if isinstance(aug, dict) and aug.get("object"):
            target = symtab.get((aug.get("module", ""), aug["object"]))
            return indices(target, depth + 1) if target else None
        return None

    rows: dict[str, dict] = {}
    for (mod, _name), obj in symtab.items():
        if obj.get("nodetype") != "row" or not obj.get("oid"):
            continue
        idx = indices(obj)
        if not idx:
            continue
        names, oids, toks = [], [], []
        for i in idx:
            comp = symtab.get((i.get("module", mod), i.get("object", "")))
            if not comp or not comp.get("oid"):
                names = []
                break
            names.append(comp.get("name", i.get("object")))
            oids.append(str(comp["oid"]))
            toks.append(token(comp))
        if names:
            clause = {"index": names, "index_oids": oids, "index_syntax": toks}
            if idx[-1].get("implied"):
                clause["index_implied"] = True
            rows[str(obj["oid"])] = clause
    out: dict[str, dict] = {}
    for obj in symtab.values():
        oid = str(obj.get("oid") or "")
        if obj.get("nodetype") == "column" and "." in oid and oid.rsplit(".", 1)[0] in rows:
            out[oid] = rows[oid.rsplit(".", 1)[0]]
    return out


_TD_NAMED_HEAD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)::([A-Za-z][A-Za-z0-9-]*)$")


def _td_named_blocks(text: str) -> list[tuple[str, str, str]]:
    """`snmptranslate -Td` output as (module, name, block) per printed object."""
    out: list[tuple[str, str, str]] = []
    head: tuple[str, str] | None = None
    lines: list[str] = []
    for line in text.splitlines():
        m = _TD_NAMED_HEAD_RE.match(line)
        if m:
            if head:
                out.append((head[0], head[1], "\n".join(lines)))
            head, lines = (m.group(1), m.group(2)), []
            continue
        lines.append(line)
    if head:
        out.append((head[0], head[1], "\n".join(lines)))
    return out


def _td_oid(block: str) -> str:
    for line in block.splitlines():
        m = re.match(r"\s*::=\s*\{(.*)\}", line)
        if m:
            arcs = [a.group(1) or a.group(2)
                    for a in re.finditer(r"\((\d+)\)|(?<![\w(-])(\d+)(?![\w)-])", m.group(1))]
            return ".".join(arcs)
    return ""


def _td_header(block: str) -> str:
    """The clauses before DESCRIPTION: prose there may say anything."""
    return block.split("DESCRIPTION", 1)[0]


def _td_token(block: str) -> str:
    head = _td_header(block)
    tc = (re.search(r"--\s*TEXTUAL CONVENTION\s+(\S+)", head) or [None, ""])[1]
    msyn = re.search(r"SYNTAX\s+(OCTET STRING|OBJECT IDENTIFIER|\w+)\s*(.*)", head)
    base = msyn.group(1) if msyn else ""
    fixed = None
    if msyn and base == "OCTET STRING":
        rest = msyn.group(2)
        m1 = re.match(r"\(\s*(\d+)\s*\)", rest)
        m2 = re.match(r"\(\s*(\d+)\s*\.\.\s*(\d+)\s*\)", rest)
        if m1 and int(m1.group(1)) > 0:
            fixed = int(m1.group(1))
        elif m2 and m2.group(1) == m2.group(2) and int(m2.group(1)) > 0:
            fixed = int(m2.group(1))
    return index_token(base, tc, fixed)


def _netsnmp_td_run(exe: str, mpath: str, objs: list[str]) -> list[tuple[str, str, str]]:
    try:
        # -IR looks a bare name (an AUGMENTS target) up across modules, but reads
        # a numeric OID as a name too, so a call carries one kind or the other.
        bare = all(o[:1].isalpha() and "::" not in o for o in objs)
        flags = ["-IR"] if bare else []
        text = subprocess.run([exe, "-M", mpath, "-m", "ALL", *flags, "-Td", *objs],
                              capture_output=True, text=True, timeout=300).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"gen_index: index clauses: net-snmp batch failed ({exc}) — "
              f"{len(objs)} object(s) get no clause from it", file=sys.stderr)
        return []
    return _td_named_blocks(text)


def _netsnmp_td(exe: str, mpath: str, objs: list[str]) -> list[tuple[str, str, str]]:
    """-Td blocks for `objs`. snmptranslate stops at the first object it cannot
    resolve, so a short batch is retried one object at a time (each failure then
    costs only itself, and is named)."""
    out: list[tuple[str, str, str]] = []
    bare = [o for o in objs if o[:1].isalpha() and "::" not in o]
    rest = [o for o in objs if o not in set(bare)]
    batches = [rest[i:i + NETSNMP_BATCH] for i in range(0, len(rest), NETSNMP_BATCH)]
    batches += [bare[i:i + NETSNMP_BATCH] for i in range(0, len(bare), NETSNMP_BATCH)]
    for chunk in batches:
        got = _netsnmp_td_run(exe, mpath, chunk)
        if len(got) >= len(chunk):
            out.extend(got)
            continue
        unresolved = 0
        for one in chunk:
            single = _netsnmp_td_run(exe, mpath, [one])
            unresolved += not single
            out.extend(single)
        if unresolved:
            print(f"gen_index: index clauses: net-snmp resolved no definition for {unresolved} "
                  f"of {len(chunk)} object(s) — those columns keep no clause", file=sys.stderr)
    return out


def netsnmp_index_clauses(columns: list[str]) -> dict[str, dict]:
    """{column OID: clause} for `columns`, read through net-snmp from each
    column's row (its OID minus the last arc). {} without net-snmp."""
    exe = shutil.which("snmptranslate")
    if not exe or not columns:
        return {}
    mpath = ":".join(netsnmp_mib_dirs())
    parents = sorted({c.rsplit(".", 1)[0] for c in columns if "." in c})
    rows: dict[str, tuple[str, list[str], bool, str]] = {}  # oid → (module, comps, implied, augments)
    for mod, _name, block in _netsnmp_td(exe, mpath, parents):
        head = _td_header(block)
        oid = _td_oid(block)
        mi = re.search(r"^\s*INDEX\s*\{([^}]*)\}", head, re.M)
        ma = re.search(r"^\s*AUGMENTS\s*\{\s*([A-Za-z][\w-]*)\s*\}", head, re.M)
        if mi:
            raw = [c.strip() for c in mi.group(1).split(",") if c.strip()]
            implied = bool(raw) and raw[-1].startswith("IMPLIED ")
            comps = [c.replace("IMPLIED ", "").strip() for c in raw]
            rows[oid] = (mod, comps, implied, "")
        elif ma:
            rows[oid] = (mod, [], False, ma.group(1))
    # AUGMENTS: the augmented row's own clause (one level; a chain is resolved
    # by the next pass of the same loop, bounded).
    for _ in range(3):
        pending = {o: r[3] for o, r in rows.items() if r[3]}
        if not pending:
            break
        for mod, name, block in _netsnmp_td(exe, mpath, sorted(set(pending.values()))):
            mi = re.search(r"^\s*INDEX\s*\{([^}]*)\}", _td_header(block), re.M)
            ma = re.search(r"^\s*AUGMENTS\s*\{\s*([A-Za-z][\w-]*)\s*\}", _td_header(block), re.M)
            for o, target in pending.items():
                if target != name:
                    continue
                if mi:
                    raw = [c.strip() for c in mi.group(1).split(",") if c.strip()]
                    implied = bool(raw) and raw[-1].startswith("IMPLIED ")
                    rows[o] = (mod, [c.replace("IMPLIED ", "").strip() for c in raw], implied, "")
                elif ma:
                    rows[o] = (rows[o][0], [], False, ma.group(1))
                else:
                    rows[o] = (rows[o][0], [], False, "")
    want = sorted({f"{r[0]}::{c}" for r in rows.values() for c in r[1]})
    comp: dict[str, tuple[str, str]] = {}  # MODULE::name → (oid, token)
    for mod, name, block in _netsnmp_td(exe, mpath, want):
        oid = _td_oid(block)
        if oid:
            comp[f"{mod}::{name}"] = (oid, _td_token(block))
    out: dict[str, dict] = {}
    for c in columns:
        r = rows.get(c.rsplit(".", 1)[0])
        if not r or not r[1]:
            continue
        resolved = [comp.get(f"{r[0]}::{n}") for n in r[1]]
        if any(x is None for x in resolved):
            continue
        clause = {"index": list(r[1]), "index_oids": [x[0] for x in resolved],
                  "index_syntax": [x[1] for x in resolved]}
        if r[2]:
            clause["index_implied"] = True
        out[c] = clause
    return out


INDEX_FIELDS = ("index", "index_oids", "index_syntax", "index_implied")


def apply_index_clauses(nodes: dict, clauses: dict[str, dict]) -> int:
    """Set the clause on every COLUMN node it names; return how many changed.
    A node the clause does not reach keeps nothing stale: its fields are cleared
    only when a compiler stated a different clause."""
    n = 0
    for oid, clause in clauses.items():
        node = nodes.get(oid)
        if not node or node.get("kind") != "column":
            continue
        before = {k: node.get(k) for k in INDEX_FIELDS}
        for k in INDEX_FIELDS:
            node.pop(k, None)
        node.update(clause)
        if {k: node.get(k) for k in INDEX_FIELDS} != before:
            n += 1
    return n


# What a trap needs decoded today, and the forms each MIB states (regression
# guard; mirrors collectors/trap_index_test.go).
INDEX_ASSERTIONS = {
    "1.3.6.1.2.1.15.3.1.2": (["bgpPeerRemoteAddr"], ["ipv4"]),                      # bgpPeerState
    "1.3.6.1.4.1.9.9.187.1.2.1.1.8": (["bgpPeerRemoteAddr"], ["ipv4"]),             # cbgpPeerPrevState (AUGMENTS)
    "1.3.6.1.4.1.9.9.187.1.2.5.1.3": (["cbgpPeer2Type", "cbgpPeer2RemoteAddr"],
                                      ["inet_type", "inet_address"]),               # cbgpPeer2State
    "1.3.6.1.2.1.2.2.1.8": (["ifIndex"], ["int"]),                                  # ifOperStatus
}


def validate_index_clauses(nodes: dict) -> list[str]:
    errs = []
    for oid, (names, toks) in INDEX_ASSERTIONS.items():
        n = nodes.get(oid) or {}
        if n.get("index") != names or n.get("index_syntax") != toks:
            errs.append(f"{oid} ({n.get('name')}): index {n.get('index')} {n.get('index_syntax')}, "
                        f"want {names} {toks}")
    return errs


def validate(nodes: dict) -> list[str]:
    errs = []
    for oid, (name, kind) in ASSERTIONS.items():
        n = nodes.get(oid)
        if not n:
            errs.append(f"missing assertion OID {oid} ({name})")
        elif n.get("name") != name or n.get("kind") != kind:
            errs.append(f"{oid}: got {n.get('name')}/{n.get('kind')}, want {name}/{kind}")
    return errs


def main() -> int:
    mibs = os.environ.get("MIBS", " ".join(DEFAULT_MIBS)).split()
    # Pinned, checksum-verified fetch of the MIBs this repo does not redistribute.
    # Fail closed: the ONLY non-fatal outcome is the operator's explicit opt-out,
    # and even that is announced (scripts/CLAUDE.md §16.1 — no silent skips).
    try:
        fetched, skipped = fetch_pinned_mibs()
    except FetchError as exc:
        print(f"gen_index: FATAL: pinned MIB fetch failed — {exc}", file=sys.stderr)
        return 1
    if fetched:
        print(f"gen_index: fetched+verified {len(fetched)} pinned MIB(s): {', '.join(fetched)}")
    if skipped:
        print("gen_index: WARNING — MIB_FETCH=0, so " + ", ".join(skipped) + " were NOT "
              "fetched. The net-snmp pass cannot see them: Arista devices decode with the "
              "standard MIBs, plus whatever 1.3.6.1.4.1.30065.3.2 nodes the existing index "
              "floor and STD_OVERLAY already carry (the 30065.3.2.0.x v1-form traps). "
              "This is a DECLARED degraded build, not a failure.", file=sys.stderr)
    # Start from the existing index as a floor — compiled MIBs ADD coverage and
    # enrich type/enum, but a network/compile miss must never regress the core.
    base: dict[str, dict] = {}
    if not os.environ.get("CLEAN"):  # CLEAN=1 → rebuild from scratch (purge stale)
        try:
            base = json.load(open(INDEX)).get("nodes", {})
        except Exception:
            pass
    # INDEX_ONLY=1: add the table INDEX clauses to the CHECKED-IN nodes and change
    # nothing else (no node added, renamed or re-typed). The full run computes the
    # same clauses after its merge, so the two cannot disagree.
    index_only = os.environ.get(INDEX_ONLY_ENV) == "1"
    with tempfile.TemporaryDirectory() as tmp:
        mibdump(mibs, tmp)
        gen = {} if index_only else flatten(tmp)
        clauses = pysmi_index_clauses(tmp)
    for oid, n in gen.items():
        if oid in base:
            hint = base[oid].get("severity_hint")  # keep curated severity overlay
            base[oid].update(n)
            if hint:
                base[oid]["severity_hint"] = hint
        else:
            base[oid] = n
    # net-snmp pass: authoritative for the SMIv1 bridge family pysmi can't compile.
    ns = {} if index_only else netsnmp_nodes()
    for oid, n in ns.items():
        base[oid] = n  # override — real compiled MIB beats pysmi/overlay
    for oid, n in STD_OVERLAY.items():
        base.setdefault(oid, n)  # only fills genuinely-undefined OIDs (e.g. v1 traps)
    # THE TABLE IS THE SOURCE OF TRUTH FOR A CURATED HINT — re-applied LAST.
    # The merge above preserves the hint already stored on a node, which is what
    # keeps a curated overlay alive across a compile that cannot supply one; but
    # it also meant a hint CHANGE in SEVERITY_HINT could never propagate to an
    # OID the index already held (the first value ever generated won forever).
    # That is how `entConfigChange` stayed pinned below the alarm floor. A name
    # this table does not mention keeps whatever it has (e.g. the STD_OVERLAY
    # v1-trap hints), so the overlay is still preserved.
    for n in base.values():
        if n.get("kind") == "notification" and n.get("name") in SEVERITY_HINT:
            n["severity_hint"] = SEVERITY_HINT[n["name"]]
    nodes = base
    # INDEX clauses last, over the merged nodes: pysmi's where it compiled the
    # row, net-snmp's for every other column (it reads the vendored tree and the
    # pinned cache, so a module neither can load keeps whatever the floor holds).
    missing = [o for o, n in nodes.items() if n.get("kind") == "column" and o not in clauses]
    clauses.update(netsnmp_index_clauses(missing))
    changed = apply_index_clauses(nodes, clauses)
    print(f"gen_index: pysmi={len(gen)} net-snmp={len(ns)} nodes; index now {len(nodes)}; "
          f"INDEX clauses on {sum(1 for n in nodes.values() if n.get('index_syntax'))} column(s) "
          f"({changed} changed).")
    errs = validate(nodes) + validate_index_clauses(nodes)
    if errs:
        print("gen_index: VALIDATION FAILED:\n  " + "\n  ".join(errs), file=sys.stderr)
        return 1
    body = json.dumps(nodes, sort_keys=True, separators=(",", ":")).encode()
    index = {
        "version": "sha256:" + hashlib.sha256(body).hexdigest()[:16],
        "generated": "build",
        "note": "GENERATED by gen_index.py (pysmi/mibdump for the MIB set + net-snmp/snmptranslate over the vendored tree for SMIv1 modules pysmi can't parse). Do not hand-edit — see mibs/README.md.",
        "mibs": mibs,
        "nodes": nodes,
    }
    json.dump(index, open(INDEX, "w"), indent=1, sort_keys=False)
    open(INDEX, "a").write("\n")
    print(f"gen_index: OK — {len(nodes)} nodes from {len(mibs)} MIB(s), version {index['version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
