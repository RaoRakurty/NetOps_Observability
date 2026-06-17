#!/usr/bin/env python3
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
import shutil
import subprocess
import sys
import tempfile

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
    "JUNIPER-SMI", "JUNIPER-MIB", "JUNIPER-CHASSIS-DEFINES-MIB",
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

# MIBs carry no universal severity; seed the well-known IETF notifications.
SEVERITY_HINT = {
    "linkDown": "warning", "authenticationFailure": "warning",
    "bgpBackwardTransition": "warning", "ospfNbrStateChange": "warning",
    "ospfIfStateChange": "warning", "coldStart": "info", "warmStart": "info",
    "linkUp": "info", "bgpEstablished": "info", "entConfigChange": "notice",
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
}
ASSERTIONS = {  # regression guard — mirrors collectors/oidindex_test.go
    "1.3.6.1.2.1.2.2.1.8": ("ifOperStatus", "column"),
    "1.3.6.1.6.3.1.1.5.3": ("linkDown", "notification"),
    "1.3.6.1.2.1.1.5.0": ("sysName", "scalar"),
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
            subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            print(f"gen_index: timeout compiling {mib} — skipped", file=sys.stderr)


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
    # Start from the existing index as a floor — compiled MIBs ADD coverage and
    # enrich type/enum, but a network/compile miss must never regress the core.
    base: dict[str, dict] = {}
    try:
        base = json.load(open(INDEX)).get("nodes", {})
    except Exception:
        pass
    with tempfile.TemporaryDirectory() as tmp:
        mibdump(mibs, tmp)
        gen = flatten(tmp)
    for oid, n in gen.items():
        if oid in base:
            hint = base[oid].get("severity_hint")  # keep curated severity overlay
            base[oid].update(n)
            if hint:
                base[oid]["severity_hint"] = hint
        else:
            base[oid] = n
    for oid, n in STD_OVERLAY.items():
        base.setdefault(oid, n)  # anchor standard OIDs whose MIB won't compile
    nodes = base
    print(f"gen_index: compiled {len(gen)} nodes; index now {len(nodes)} (seed+overlay-merged).")
    errs = validate(nodes)
    if errs:
        print("gen_index: VALIDATION FAILED:\n  " + "\n  ".join(errs), file=sys.stderr)
        return 1
    body = json.dumps(nodes, sort_keys=True, separators=(",", ":")).encode()
    index = {
        "version": "sha256:" + hashlib.sha256(body).hexdigest()[:16],
        "generated": "build",
        "note": "GENERATED by gen_index.py (pysmi/mibdump over the curated MIB set). Do not hand-edit — see mibs/README.md.",
        "mibs": mibs,
        "nodes": nodes,
    }
    json.dump(index, open(INDEX, "w"), indent=1, sort_keys=False)
    open(INDEX, "a").write("\n")
    print(f"gen_index: OK — {len(nodes)} nodes from {len(mibs)} MIB(s), version {index['version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
