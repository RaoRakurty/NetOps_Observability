"""Steady-state + fault-story schedule engine (tracker 152, design §5).

`build_run_plan(scenario, duration_s)` expands a validated scenario into a
fully DETERMINISTIC emission plan: `(scenario, seed)` decides every event's
content and relative timing (design §3.3 rule). Wall-clock timestamps are the
ONLY thing added later, at emission time — the determinism unit test pins two
builds of the same scenario byte-identical.

Every event shape here is one the correlation producers PROVABLY recognize
(design §4.0 signature inventory; `correlation_e2e.py` is the live-proven
reference for the wire dicts). Nothing invented: stories may only claim
signatures from that table.

T1-CORE scope note: lanes are syslog (console-producer → netops.syslog),
probes (netops.probes), cloud (netops.cloud) and metrics (netops.metrics) —
all bus-direct. SNMP/snmpsim, traps-over-UDP, IPFIX and gNMI are a LATER wave;
attribution rides the per-NAME registry rows (`hostname` fallback mode,
design §3.4), which is why every hostname/target/device field carries the
run-prefixed device name.
"""
from __future__ import annotations

import random
from typing import Any

from scenario import baseline_flow_fps, parse_offset_s

# Benign baseline chatter: mnemonics that match NO recognized control-plane
# signature (they must never fabricate link/bgp evidence). warning/err lines
# become generic `device_alarm` signals by design (producers.py severity
# floor) — realistic noise the engine must not weld into stories.
_CHATTER = [
    ("SYS-5-CONFIG_I", "Configured from console by admin on vty0", "notice"),
    ("SYS-6-LOGGINGHOST_STARTSTOP", "Logging to host 198.19.255.10 port 514 started", "info"),
    ("SEC_LOGIN-5-LOGIN_SUCCESS", "Login Success [user: netops] at console", "notice"),
    ("SYS-5-RESTART", "RP operational state notification", "notice"),
    ("PLATFORM-4-ELEMENT_WARNING", "Committed memory utilization above minor threshold", "warning"),
    ("SNMP-3-AUTHFAIL", "Authentication failure for SNMP req from host 198.19.255.20", "err"),
]

# severity → chatter lines by class, used with the scenario's severity_mix.
_CHATTER_BY_SEV = {
    "notice": [c for c in _CHATTER if c[2] in ("notice", "info")],
    "warning": [c for c in _CHATTER if c[2] == "warning"],
    "err": [c for c in _CHATTER if c[2] == "err"],
}


def _pick_severity(rng: random.Random, mix: dict[str, float]) -> str:
    """Deterministic severity draw from the scenario's mix (defaults benign)."""
    order = [(k, float(v)) for k, v in sorted(mix.items())] or [("notice", 1.0)]
    total = sum(w for _, w in order) or 1.0
    x = rng.random() * total
    acc = 0.0
    for sev, w in order:
        acc += w
        if x <= acc:
            return sev
    return order[-1][0]


def _syslog(t: float, device: str, tenant: str, appname: str, message: str,
            severity: str, story_id: str | None = None) -> dict:
    return {"t": round(t, 3), "lane": "syslog", "tenant": tenant,
            "device": device, "story_id": story_id,
            "appname": appname, "message": message, "severity": severity}


def _probe(t: float, target: str, tenant: str, prober: str, loss: float,
           intent: str, vantage: str, story_id: str | None = None,
           rtt: float = 12.0) -> dict:
    return {"t": round(t, 3), "lane": "probes", "tenant": tenant,
            "device": target, "story_id": story_id, "prober": prober,
            "loss_pct": round(loss, 1), "rtt_ms": rtt,
            "probe_intent": intent, "vantage_type": vantage}


def _metric(t: float, device: str, tenant: str, value: float,
            ts_off: float, story_id: str | None = None,
            metric: str = "cpu") -> dict:
    # ts_off: event-time offset (seconds, negative = past) applied at emission
    # — the CUSUM baseline+step shape needs backdated sample times
    # (correlation_e2e.cpu_stream, 26 baseline + 10 peak, 2 s spacing).
    return {"t": round(t, 3), "lane": "metrics", "tenant": tenant,
            "device": device, "story_id": story_id, "metric": metric,
            "value": value, "ts_off": round(ts_off, 1),
            "signal_family": "device_resource"}


def _cloud(t: float, kind: str, tenant: str, resource_id: str, account: str,
           region: str, severity: str, story_id: str | None = None,
           value: float = 0.0, metric_name: str = "") -> dict:
    return {"t": round(t, 3), "lane": "cloud", "tenant": tenant,
            "device": resource_id, "story_id": story_id, "kind": kind,
            "resource_id": resource_id, "account": account, "region": region,
            "severity": severity, "value": value, "metric_name": metric_name}


def _trap(t: float, device: str, tenant: str, trap: str,
          story_id: str | None = None, ifindex: int | None = None,
          ifname: str = "", ifdescr: str = "", peer_ip: str = "") -> dict:
    """Fidelity-wave trap lane (design §4.4): `trap` is one of linkDown /
    linkUp / coldStart / warmStart / bgpBackwardTransition / bgpEstablished —
    exactly the §4.0 trap rows `producers.trap_control_signal` classifies.
    The emitter adds the mandatory sysUpTime/snmpTrapOID bindings plus a
    sysName.0 varbind (hostname-mode attribution rescue)."""
    return {"t": round(t, 3), "lane": "trap", "tenant": tenant,
            "device": device, "story_id": story_id, "trap": trap,
            "ifindex": ifindex, "ifname": ifname, "ifdescr": ifdescr,
            "peer_ip": peer_ip}


def _flow(t: float, device: str, tenant: str, count: int, flow_seed: str,
          story_id: str | None = None) -> dict:
    """One second's worth of flow records from `device`'s exporter (design
    §4.5). `count` records are expanded at emission time deterministically
    from `flow_seed` — the plan stays compact, the content stays a pure
    function of (scenario, seed)."""
    return {"t": round(t, 3), "lane": "flows", "tenant": tenant,
            "device": device, "story_id": story_id, "count": int(count),
            "flow_seed": flow_seed}


def _dev(sc: dict, name: str) -> dict:
    for d in sc["devices"]:
        if d["name"] == name:
            return d
    raise KeyError(name)  # unreachable after validation


def _external_bgp_peer(dev: dict) -> str:
    """The device's external BGP peer IP (no peer_device = not an internal
    session) — the peer a seam/WAN story flaps. Validation guarantees stories
    that need one run on devices that have one; refuse loudly otherwise."""
    for nb in dev.get("bgp_neighbors") or []:
        if not nb.get("peer_device"):
            return str(nb["peer_ip"])
    raise ValueError(
        f"device {dev['name']!r} has no external bgp_neighbor (one without "
        f"peer_device) — required by this story template")


def _first_interface(dev: dict) -> str:
    return str(dev["interfaces"][0]["name"])


# ── story template expanders ────────────────────────────────────────────────
# Each returns a list of schedule items with t relative to the story's t0.

def _tpl_dx_circuit_flap_cloud_withdrawal(story: dict, sc: dict,
                                          rng: random.Random) -> list[dict]:
    p = story.get("params") or {}
    flaps = int(p.get("flap_count", 2))
    hold = float(p.get("hold_s", 45))
    final_down = str(p.get("final_state", "down")) == "down"
    cloud = p.get("cloud") or {}
    kinds = list(cloud.get("kinds") or ["cloud_bgp_session_down"])
    account = str(cloud.get("account", "000000000000"))
    region = str(cloud.get("region", "us-east-1"))
    resource = str(cloud.get("resource_id", "seam-resource"))
    loss = float(p.get("probe_loss_pct", 85))
    sid = story["id"]
    aff = story["affected"]
    tenant = (aff.get("tenants") or [None])[0]
    devices = aff.get("devices") or []

    items: list[dict] = []
    t = 0.0
    for cycle in range(flaps):
        for dn in devices:
            dev = _dev(sc, dn)
            peer = _external_bgp_peer(dev)
            items.append(_syslog(
                t, dn, dev["tenant"], "BGP-5-ADJCHANGE",
                f"%BGP-5-ADJCHANGE: neighbor {peer} Down BGP Notification sent",
                "notice", sid))
        # provider side sees the session drop a few seconds later
        if "cloud_bgp_session_down" in kinds:
            items.append(_cloud(t + 4.0, "cloud_bgp_session_down", tenant,
                                resource, account, region, "high", sid))
        if cycle == 0 and "cloud_route_count_drop" in kinds:
            items.append(_cloud(t + 9.0, "cloud_route_count_drop", tenant,
                                resource, account, region, "high", sid,
                                value=0.0, metric_name="advertised_routes"))
        t += hold
        if cycle < flaps - 1 or not final_down:
            for dn in devices:
                dev = _dev(sc, dn)
                peer = _external_bgp_peer(dev)
                items.append(_syslog(
                    t, dn, dev["tenant"], "BGP-5-ADJCHANGE",
                    f"%BGP-5-ADJCHANGE: neighbor {peer} Up", "notice", sid))
            if "cloud_bgp_session_down" in kinds:
                items.append(_cloud(t + 4.0, "cloud_bgp_session_up", tenant,
                                    resource, account, region, "info", sid))
            t += hold
    # customer-path probe loss across the story window + a short tail
    end = t + 60.0
    pt = 2.0
    while pt < end:
        for dn in devices:
            dev = _dev(sc, dn)
            items.append(_probe(pt, dn, dev["tenant"], "vantage-1", loss,
                                "customer_path", "public_cloud_agent", sid))
        pt += 15.0
    return items


def _tpl_bgp_flap(story: dict, sc: dict, rng: random.Random) -> list[dict]:
    p = story.get("params") or {}
    flaps = int(p.get("flap_count", 3))
    hold = float(p.get("hold_s", 30))
    loss = float(p.get("probe_loss_pct", 40))
    with_trap = bool(p.get("with_trap"))
    sid = story["id"]
    items: list[dict] = []
    t = 0.0
    for dn in story["affected"].get("devices") or []:
        dev = _dev(sc, dn)
        peer = _external_bgp_peer(dev)
        for _cyc in range(flaps):
            items.append(_syslog(
                t, dn, dev["tenant"], "BGP-5-ADJCHANGE",
                f"%BGP-5-ADJCHANGE: neighbor {peer} Down Hold timer expired",
                "notice", sid))
            if with_trap:
                items.append(_trap(t + 0.5, dn, dev["tenant"],
                                   "bgpBackwardTransition", sid,
                                   peer_ip=peer))
            t += hold
            items.append(_syslog(
                t, dn, dev["tenant"], "BGP-5-ADJCHANGE",
                f"%BGP-5-ADJCHANGE: neighbor {peer} Up", "notice", sid))
            if with_trap:
                items.append(_trap(t + 0.5, dn, dev["tenant"],
                                   "bgpEstablished", sid, peer_ip=peer))
            t += hold
        items.append(_probe(5.0, dn, dev["tenant"], "vantage-1", loss,
                            "customer_path", "public_cloud_agent", sid))
    return items


def _tpl_device_restart(story: dict, sc: dict,
                        rng: random.Random) -> list[dict]:
    """§5.7: coldStart trap + reboot-window silence + interface-up storm on
    return. Expect: device_restart-rooted single incident; forbid:
    per-interface incident spray."""
    p = story.get("params") or {}
    reboot_s = float(p.get("reboot_s", 60))
    sid = story["id"]
    items: list[dict] = []
    for dn in story["affected"].get("devices") or []:
        dev = _dev(sc, dn)
        items.append(_trap(0.0, dn, dev["tenant"], "coldStart", sid))
        # (baseline chatter keeps flowing — the reboot "silence" is the story
        # window itself; suppressing per-device baseline is not modeled in T1)
        for i, itf in enumerate(dev["interfaces"], start=1):
            up_t = reboot_s + i * 1.0
            items.append(_syslog(
                up_t, dn, dev["tenant"], "LINK-3-UPDOWN",
                f"%LINK-3-UPDOWN: Interface {itf['name']}, changed state "
                f"to up", "notice", sid))
            items.append(_trap(up_t + 0.5, dn, dev["tenant"], "linkUp", sid,
                               ifindex=i, ifname=str(itf["name"]),
                               ifdescr=str(itf["name"])))
    return items


def _tpl_traffic_drop(story: dict, sc: dict,
                      rng: random.Random) -> tuple[list[dict], list[dict]]:
    """Fidelity wave: the affected exporters' flow volume collapses to
    (100-drop_pct)% for `duration_s`. Returns (items, suppressions) — the
    plan builder removes the devices' BASELINE flow items inside the window
    and these residual-rate items stand in. Optional probe loss makes the
    story §4.0-detectable (flows alone are evidence, not a signal)."""
    p = story.get("params") or {}
    drop_pct = float(p.get("drop_pct", 90))
    dur = float(p.get("duration_s", 120))
    loss = p.get("probe_loss_pct")
    sid = story["id"]
    fps_by_dev = baseline_flow_fps(sc)
    items: list[dict] = []
    suppressions: list[dict] = []
    for dn in story["affected"].get("devices") or []:
        dev = _dev(sc, dn)
        base_fps = fps_by_dev.get(dn, 0.0)
        residual = round(base_fps * (1.0 - drop_pct / 100.0))
        suppressions.append({"lane": "flows", "device": dn,
                             "from": 0.0, "to": dur})
        sec = 0
        while sec < dur:
            if residual > 0:
                items.append(_flow(float(sec), dn, dev["tenant"], residual,
                                   f"{sid}:{dn}:{sec}", sid))
            if loss is not None and sec % 20 == 0:
                items.append(_probe(float(sec), dn, dev["tenant"],
                                    "vantage-1", float(loss),
                                    "customer_path", "public_cloud_agent",
                                    sid))
            sec += 1
    return items, suppressions


def _tpl_link_down_cascade(story: dict, sc: dict,
                           rng: random.Random) -> list[dict]:
    p = story.get("params") or {}
    loss = float(p.get("probe_loss_pct", 85))
    with_trap = bool(p.get("with_trap"))
    sid = story["id"]
    items: list[dict] = []
    for dn in story["affected"].get("devices") or []:
        dev = _dev(sc, dn)
        ifname = _first_interface(dev)
        items.append(_syslog(
            0.0, dn, dev["tenant"], "LINK-3-UPDOWN",
            f"%LINK-3-UPDOWN: Interface {ifname}, changed state to down",
            "err", sid))
        if with_trap:
            # the device also pushes the standard linkDown notification with
            # ifIndex/ifName/ifDescr varbinds (§4.0 trap row)
            items.append(_trap(0.5, dn, dev["tenant"], "linkDown", sid,
                               ifindex=1, ifname=ifname, ifdescr=ifname))
        items.append(_syslog(
            1.0, dn, dev["tenant"], "LINEPROTO-5-UPDOWN",
            f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {ifname}, "
            f"changed state to down", "notice", sid))
        # downstream BGP sessions riding the link drop too
        for nb in dev.get("bgp_neighbors") or []:
            items.append(_syslog(
                3.0, dn, dev["tenant"], "BGP-5-ADJCHANGE",
                f"%BGP-5-ADJCHANGE: neighbor {nb['peer_ip']} Down "
                f"Interface flap", "notice", sid))
        items.append(_probe(6.0, dn, dev["tenant"], "vantage-1", loss,
                            "customer_path", "public_cloud_agent", sid))
    return items


def _tpl_isp_brownout_multi_tenant(story: dict, sc: dict,
                                   rng: random.Random) -> list[dict]:
    p = story.get("params") or {}
    loss = float(p.get("probe_loss_pct", 35))
    dur = float(p.get("duration_s", 120))
    sid = story["id"]
    items: list[dict] = []
    t = 0.0
    while t < dur:
        for dn in story["affected"].get("devices") or []:
            dev = _dev(sc, dn)
            items.append(_probe(t, dn, dev["tenant"], "vantage-1",
                                loss + rng.random() * 10.0,
                                "customer_path", "public_cloud_agent", sid))
        t += 20.0
    return items


def _cpu_stream(dn: str, tenant: str, sid: str, peak: float,
                n_base: int = 26, n_peak: int = 10) -> list[dict]:
    """The proven CUSUM shape (correlation_e2e.cpu_stream): ≥20 baseline
    samples then a sustained step, event times backdated 2 s apart."""
    items: list[dict] = []
    for i in range(n_base):
        items.append(_metric(0.0, dn, tenant, 12.0 + (i % 3),
                             ts_off=-(n_base + n_peak - i) * 2.0,
                             story_id=sid))
    for i in range(n_peak):
        items.append(_metric(0.0, dn, tenant, peak,
                             ts_off=-(n_peak - i) * 2.0, story_id=sid))
    return items


def _tpl_cpu_exhaustion(story: dict, sc: dict,
                        rng: random.Random) -> list[dict]:
    p = story.get("params") or {}
    dn = str(p.get("cpu_device") or (story["affected"].get("devices") or [""])[0])
    dev = _dev(sc, dn)
    peak = float(p.get("peak_pct", 98.0))
    items = _cpu_stream(dn, dev["tenant"], story["id"], peak)
    if p.get("with_impact"):
        items.append(_syslog(
            5.0, dn, dev["tenant"], "SYS-2-MALLOCFAIL",
            "%SYS-2-MALLOCFAIL: Memory allocation of 65536 bytes failed from "
            "Process BGP Router", "crit", story["id"]))
    return items


def _tpl_optics_degradation(story: dict, sc: dict,
                            rng: random.Random) -> list[dict]:
    sid = story["id"]
    items: list[dict] = []
    for dn in story["affected"].get("devices") or []:
        dev = _dev(sc, dn)
        ifname = str((story.get("params") or {}).get("interface")
                     or _first_interface(dev))
        ramp = [
            (0.0, "SFF8472-3-THRESHOLD_VIOLATION",
             f"Rx power low warning; Port {ifname}: RX_POWER_LOW", "warning"),
            (20.0, "PHY-4-FEC_UNCORRECTABLE",
             (f"Interface {ifname}: FEC uncorrectable codeword errors "
              f"detected, pre-FEC BER 1.2e-4"), "warning"),
            (40.0, "PCS-3-LOCAL_FAULT",
             f"Interface {ifname}: LOCAL_FAULT detected", "err"),
            (60.0, "LINK-3-UPDOWN",
             f"%LINK-3-UPDOWN: Interface {ifname}, changed state to down",
             "err"),
        ]
        for t, app, msg, sev in ramp:
            items.append(_syslog(t, dn, dev["tenant"], app, msg, sev, sid))
    return items


def _tpl_vpn_tunnel_down(story: dict, sc: dict,
                         rng: random.Random) -> list[dict]:
    p = story.get("params") or {}
    cloud = p.get("cloud") or {}
    account = str(cloud.get("account", "000000000000"))
    region = str(cloud.get("region", "us-east-1"))
    resource = str(cloud.get("resource_id", "vpn-tunnel"))
    loss = float(p.get("probe_loss_pct", 90))
    sid = story["id"]
    aff = story["affected"]
    tenant = (aff.get("tenants") or [None])[0]
    items: list[dict] = [
        _cloud(0.0, "cloud_vpn_tunnel_down", tenant, resource, account,
               region, "high", sid),
        _cloud(6.0, "cloud_vpn_packet_drop", tenant, resource, account,
               region, "warning", sid, value=100.0, metric_name="packet_drop"),
    ]
    for dn in aff.get("devices") or []:
        dev = _dev(sc, dn)
        peer = _external_bgp_peer(dev)
        items.append(_syslog(
            2.0, dn, dev["tenant"], "BGP-5-ADJCHANGE",
            f"%BGP-5-ADJCHANGE: neighbor {peer} Down BGP Notification sent",
            "notice", sid))
        items.append(_probe(8.0, dn, dev["tenant"], "vantage-1", loss,
                            "customer_path", "public_cloud_agent", sid))
    return items


def _tpl_negative_debug_probe(story: dict, sc: dict,
                              rng: random.Random) -> list[dict]:
    p = story.get("params") or {}
    loss = float(p.get("probe_loss_pct", 90))
    count = int(p.get("count", 5))
    sid = story["id"]
    items: list[dict] = []
    for i in range(count):
        for dn in story["affected"].get("devices") or []:
            dev = _dev(sc, dn)
            items.append(_probe(i * 10.0, dn, dev["tenant"], "labgen", loss,
                                "lab_test", "local_container", sid))
    return items


def _tpl_negative_unrelated_concurrency(story: dict, sc: dict,
                                        rng: random.Random) -> list[dict]:
    p = story.get("params") or {}
    sid = story["id"]
    items: list[dict] = []
    cpu_dn = str(p["cpu_device"])
    items += _cpu_stream(cpu_dn, _dev(sc, cpu_dn)["tenant"], sid, 97.0)
    bgp_dn = str(p["bgp_device"])
    bgp_dev = _dev(sc, bgp_dn)
    peer = _external_bgp_peer(bgp_dev)
    items.append(_syslog(
        2.0, bgp_dn, bgp_dev["tenant"], "BGP-5-ADJCHANGE",
        f"%BGP-5-ADJCHANGE: neighbor {peer} Down", "notice", sid))
    probe_dn = str(p["probe_device"])
    items.append(_probe(4.0, probe_dn, _dev(sc, probe_dn)["tenant"],
                        "vantage-1", 70.0, "customer_path",
                        "public_cloud_agent", sid))
    return items


_TEMPLATE_FNS = {
    "link_down_cascade": _tpl_link_down_cascade,
    "bgp_flap": _tpl_bgp_flap,
    "dx_circuit_flap_cloud_withdrawal": _tpl_dx_circuit_flap_cloud_withdrawal,
    "isp_brownout_multi_tenant": _tpl_isp_brownout_multi_tenant,
    "cpu_exhaustion": _tpl_cpu_exhaustion,
    "optics_degradation": _tpl_optics_degradation,
    "vpn_tunnel_down": _tpl_vpn_tunnel_down,
    "negative_debug_probe": _tpl_negative_debug_probe,
    "negative_unrelated_concurrency": _tpl_negative_unrelated_concurrency,
    "device_restart": _tpl_device_restart,       # fidelity wave (trap lane)
    "traffic_drop": _tpl_traffic_drop,           # fidelity wave (flows lane)
}


# ── plan builder ────────────────────────────────────────────────────────────

def build_run_plan(sc: dict, duration_s: float) -> dict[str, Any]:
    """Expand (scenario, seed, duration) → the deterministic emission plan.

    Returns {"baseline": [items sorted by t], "stories": [
        {"id", "template", "t0", "items" (t relative to run start, offset
         applied), "affected", "expect"} ...]}.
    """
    seed = int(sc["meta"]["seed"])
    rng = random.Random(seed)

    baseline: list[dict] = []
    base = sc.get("baseline") or {}
    syslog_cfg = base.get("syslog") or {}
    per_dev = float(syslog_cfg.get("per_device_eps") or 0.0)
    mix = syslog_cfg.get("severity_mix") or {"notice": 1.0}
    if per_dev > 0:
        interval = 1.0 / per_dev
        for d in sc["devices"]:
            # deterministic per-device phase so chatter interleaves
            t = rng.random() * interval
            seq = 0
            while t < duration_s:
                sev = _pick_severity(rng, mix)
                app, msg, line_sev = rng.choice(_CHATTER_BY_SEV.get(
                    sev, _CHATTER_BY_SEV["notice"]))
                baseline.append(_syslog(
                    t, d["name"], d["tenant"], app,
                    f"{msg} [seq {seq}]", line_sev))
                seq += 1
                t += interval
    for pr in base.get("probes") or []:
        iv = float(pr.get("interval_s") or 30.0)
        target = str(pr["target"])
        dev = _dev(sc, target)
        t = rng.random() * iv
        while t < duration_s:
            baseline.append(_probe(
                t, target, dev["tenant"], str(pr.get("prober") or "vantage-1"),
                0.0, str(pr.get("intent") or "customer_path"),
                str(pr.get("vantage") or "public_cloud_agent"), rtt=11.0))
            t += iv
    # Fidelity wave: baseline `flows` now EMITS (design §4.5) — one compact
    # per-device-per-second item carrying the record count + a deterministic
    # flow_seed. (`baseline.metrics: snmp_poll: passive` stays passive on
    # purpose: those metrics come from the REAL Go pollers hitting the twin's
    # snmpsim agents, never from bus injection.)
    for dn, fps in sorted(baseline_flow_fps(sc).items()):
        dev = _dev(sc, dn)
        count = max(1, round(fps))
        sec = 0
        while sec < int(duration_s):
            baseline.append(_flow(float(sec) + 0.5, dn, dev["tenant"], count,
                                  f"base:{seed}:{dn}:{sec}"))
            sec += 1
    baseline.sort(key=lambda e: (e["t"], e["lane"], e["device"]))

    stories_out: list[dict] = []
    suppressions: list[dict] = []
    for st in sc.get("stories") or []:
        t0 = parse_offset_s(st["trigger"]["at"], f"story {st['id']} trigger")
        fn = _TEMPLATE_FNS[st["template"]]
        # str seeds hash via SHA-512 in random.seed(version=2) — deterministic
        # across processes (a tuple/str __hash__ would NOT be, PYTHONHASHSEED).
        expanded = fn(st, sc, random.Random(f"{seed}:{st['id']}"))
        if isinstance(expanded, tuple):
            items, sup = expanded
            for s in sup:
                suppressions.append({**s, "from": round(s["from"] + t0, 3),
                                     "to": round(s["to"] + t0, 3)})
        else:
            items = expanded
        for it in items:
            it["t"] = round(it["t"] + t0, 3)
        items.sort(key=lambda e: (e["t"], e["lane"], e["device"]))
        stories_out.append({
            "id": st["id"],
            "template": st["template"],
            "t0": t0,
            "items": items,
            "affected": st["affected"],
            "expect": st["expect"],
        })
    if suppressions:
        def _suppressed(it: dict) -> bool:
            return any(s["lane"] == it["lane"] and s["device"] == it["device"]
                       and s["from"] <= it["t"] < s["to"]
                       for s in suppressions)
        baseline = [it for it in baseline if not _suppressed(it)]
    return {"baseline": baseline, "stories": stories_out}


def plan_end_s(plan: dict) -> float:
    """Last scheduled emission second in the plan."""
    last = 0.0
    for it in plan["baseline"]:
        last = max(last, it["t"])
    for stx in plan["stories"]:
        for it in stx["items"]:
            last = max(last, it["t"])
    return last
