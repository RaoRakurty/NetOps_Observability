# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""snmpsim data-file generation from the scenario topology (tracker 152
fidelity wave, design §4.3).

For every scenario device this renders a `.snmprec` simulation file (system
group + ifTable/ifXTable rows from `interfaces[]`) plus one shared
`manifest.json` that the in-container supervisor (`snmpsim_supervisor.py`)
reconciles against: one `snmpsim-command-responder` process per device, bound
to the device's twinnet address, so agent IDENTITY IS THE ADDRESS — the same
property the product's discovery scanner and pollers key on. (Design §4.3
sizes shards at ~125 agents/process for T1's 500-device ceiling; per-device
processes are the fidelity-wave shape at demo scale and the R-3 escape hatch
note stands — sharding is a supervisor change, not a DSL change.)

Determinism: everything (sysName, engine ids, MACs, counter baselines) is
derived from (prefix, device) — a golden-file unit test pins the output.

The generated sysName equals the run-prefixed device name so a discovered
agent and a twin-registered device carry the SAME identity, and the trap
receiver's sysName rescue matches (`collectors/snmptrap.go` EqualFold against
the stored name).
"""
from __future__ import annotations

import hashlib
import json
import os

DEFAULT_COMMUNITY = "public"
SYSOBJECTID = "1.3.6.1.4.1.8072.3.2.10"   # net-snmp arc (a real, mapped PEN)
STATIC_UPTIME_TICKS = 12345600            # ~34h; static walk data (documented)

# snmprec tags (snmpsim data-file format): 2=Integer 4=OctetString 4x=hex-
# OctetString 6=ObjectIdentifier 64=IpAddress 65=Counter32 66=Gauge32
# 67=TimeTicks 70=Counter64


def _oid_key(oid: str) -> tuple[int, ...]:
    return tuple(int(x) for x in oid.split("."))


def _h(name: str, n: int) -> int:
    """Deterministic n-byte integer from a name (counter baselines, MACs)."""
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:n], "big")


def engine_id_hex(device_name: str) -> str:
    """Deterministic SNMPv3 engine id: enterprise-format prefix (0x80 + PEN
    8072, format 4 'text') + 8 name-derived bytes."""
    return "80001f8804" + hashlib.sha256(device_name.encode()).hexdigest()[:16]


def device_mac(device_name: str, ifindex: int) -> str:
    body = _h(f"{device_name}:{ifindex}", 5)
    octets = [0x02] + [(body >> (8 * i)) & 0xFF for i in range(4, -1, -1)]
    return "".join(f"{o:02x}" for o in octets)


def snmprec_for_device(dev: dict, prefix: str, site_names: dict[str, str],
                       seed: int) -> str:
    """Render one device's .snmprec (sorted by OID, snmpsim requirement)."""
    name = prefix + dev["name"]
    ifaces = dev["interfaces"]
    rows: list[tuple[str, str, str]] = [
        ("1.3.6.1.2.1.1.1.0", "4",
         f"Correlix Twin simulated {dev['role']} device {name}"),
        ("1.3.6.1.2.1.1.2.0", "6", SYSOBJECTID),
        ("1.3.6.1.2.1.1.3.0", "67", str(STATIC_UPTIME_TICKS)),
        ("1.3.6.1.2.1.1.4.0", "4", "twin@correlix"),
        ("1.3.6.1.2.1.1.5.0", "4", name),
        ("1.3.6.1.2.1.1.6.0", "4",
         site_names.get(dev.get("site") or "", dev.get("site") or "lab")),
        ("1.3.6.1.2.1.1.7.0", "2", "78"),
        ("1.3.6.1.2.1.2.1.0", "2", str(len(ifaces))),
    ]
    for i, itf in enumerate(ifaces, start=1):
        ifname = str(itf["name"])
        speed_mbps = int(itf.get("speed_mbps") or 1000)
        speed_bps = min(speed_mbps * 1_000_000, 4_294_967_295)
        base = _h(f"{seed}:{name}:{ifname}", 6)
        rows += [
            (f"1.3.6.1.2.1.2.2.1.1.{i}", "2", str(i)),
            (f"1.3.6.1.2.1.2.2.1.2.{i}", "4", ifname),
            (f"1.3.6.1.2.1.2.2.1.3.{i}", "2", "6"),          # ethernetCsmacd
            (f"1.3.6.1.2.1.2.2.1.5.{i}", "66", str(speed_bps)),
            (f"1.3.6.1.2.1.2.2.1.6.{i}", "4x", device_mac(name, i)),
            (f"1.3.6.1.2.1.2.2.1.7.{i}", "2", "1"),          # admin up
            (f"1.3.6.1.2.1.2.2.1.8.{i}", "2", "1"),          # oper up
            (f"1.3.6.1.2.1.2.2.1.10.{i}", "65", str(base % 3_000_000_000)),
            (f"1.3.6.1.2.1.2.2.1.13.{i}", "65", str(base % 97)),
            (f"1.3.6.1.2.1.2.2.1.14.{i}", "65", str(base % 53)),
            (f"1.3.6.1.2.1.2.2.1.16.{i}", "65",
             str((base // 7) % 3_000_000_000)),
            (f"1.3.6.1.2.1.2.2.1.19.{i}", "65", str(base % 89)),
            (f"1.3.6.1.2.1.2.2.1.20.{i}", "65", str(base % 41)),
            (f"1.3.6.1.2.1.31.1.1.1.1.{i}", "4", ifname),
            (f"1.3.6.1.2.1.31.1.1.1.6.{i}", "70", str(base * 512)),
            (f"1.3.6.1.2.1.31.1.1.1.10.{i}", "70", str((base // 3) * 512)),
            (f"1.3.6.1.2.1.31.1.1.1.15.{i}", "66", str(speed_mbps)),
            (f"1.3.6.1.2.1.31.1.1.1.18.{i}", "4",
             str(itf.get("description") or "")),
        ]
    rows.sort(key=lambda r: _oid_key(r[0]))
    return "".join(f"{oid}|{tag}|{val}\n" for oid, tag, val in rows)


def usm_creds(dev: dict, prefix: str) -> dict | None:
    """Resolved SNMPv3 USM credentials for a v3 device (design §4.3: engine-id
    + USM creds per device). Keys default DETERMINISTIC lab values (this is a
    simulator, not a secret store — the operator copies them into a credential
    profile to poll; documented in the runbook) and can be overridden in the
    scenario's `snmp.usm` block."""
    snmp = dev.get("snmp") or {}
    if str(snmp.get("version") or "v2c") != "v3":
        return None
    usm = snmp.get("usm") or {}
    user = str(usm.get("user") or "twin-sim")
    return {
        "user": user,
        "auth_proto": str(usm.get("auth") or "sha").upper(),
        "auth_key": str(usm.get("auth_key")
                        or f"twin-auth-{prefix}{dev['name']}"),
        "priv_proto": str(usm.get("priv") or "aes128").upper()
                      .replace("AES128", "AES"),
        "priv_key": str(usm.get("priv_key")
                        or f"twin-priv-{prefix}{dev['name']}"),
        "engine_id": engine_id_hex(prefix + dev["name"]),
    }


def generate_agents(sc: dict, prefix: str, addresses: dict[str, str],
                    out_root: str, generation: str) -> dict:
    """Write per-device data dirs + the supervisor manifest under
    `out_root` (the shared /data/twin/agents volume). `addresses` maps
    scenario device name → twinnet IP. Returns the manifest dict."""
    seed = int(sc["meta"]["seed"])
    site_names = {s["id"]: str(s.get("name") or s["id"])
                  for s in sc.get("sites") or []}
    agents = []
    for dev in sc["devices"]:
        name = prefix + dev["name"]
        snmp = dev.get("snmp") or {}
        community = str(snmp.get("community") or DEFAULT_COMMUNITY)
        ddir = os.path.join(out_root, name)
        os.makedirs(ddir, exist_ok=True)
        rec = snmprec_for_device(dev, prefix, site_names, seed)
        with open(os.path.join(ddir, f"{community}.snmprec"), "w",
                  encoding="utf-8") as f:
            f.write(rec)
        agents.append({
            "device": name,
            "ip": addresses[dev["name"]],
            "port": 161,
            "data_dir": name,           # relative to the manifest's dir
            "community": community,
            "v3": usm_creds(dev, prefix),
        })
    manifest = {"generation": generation, "agents": agents}
    tmp = os.path.join(out_root, ".manifest.json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
    os.replace(tmp, os.path.join(out_root, "manifest.json"))
    return manifest
