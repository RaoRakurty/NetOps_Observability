#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Demo-fill generator — make every dashboard panel light up for a walkthrough.

Extends seed_demo_data.py (flows / base metrics / tunnels / findings) with the
telemetry the other panels need, pushed through the REAL pipelines so the demo
shows the actual path working, not just rows in a store:

  * BGP adjacency + link-state syslog  -> host :5514 -> syslog-ng -> Vector
      (fills Logs, and drives the correlation engine's control-plane lane)
  * SNMP traps (decoded JSON, readable trap_name) -> Vector :8688
      (fills Troubleshooting -> SNMP traps)
  * active probe events (STAMP/ICMP) -> Vector :8689 -> netops.probes
      (drives the correlation engine's active-probe lane)
  * interface counters w/ real ifName, error/CRC counters, BGP peer-state
    gauges, STAMP rtt/loss/pdv -> VictoriaMetrics
      (fills Interface Performance, BGP panels, Path SLA / STAMP)
  * traceroute path JSON -> Redis  (fills Network Path -> Flow Trace), signed
    with the prober-control key like a real prober's (tracker 475); skipped,
    with the reason, when that key is not readable (see --unsigned-paths)

Everything is reached the same way seed_demo_data does it: host UDP for the
published syslog port, and `docker compose exec` for the stack-internal
services (VM / Vector / Redis / ClickHouse are NOT host-exposed by design).

Time-boxed: `--duration N` pushes a fresh tick every --step seconds for N
seconds, then stops — the shape the demo knob drives.

Usage:
  python3 scripts/demo_fill.py --once                 # one backfill + one live tick
  python3 scripts/demo_fill.py --duration 300         # push live for 5 minutes
  python3 scripts/demo_fill.py --duration 300 --only syslog,probes,metrics
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import json
import os
import socket
import sys
import time

# Reuse the existing seeder's compose plumbing + base content.
import seed_demo_data as base

# Fabric-shaped device set with realistic interface names (NOT ifIndex — the
# #71 complaint) so Interface Performance reads cleanly.
FABRIC = [
    # device,        mgmt,         ifname,        peer_ip,    seam_role
    ("leaf1", "10.0.0.11", "Ethernet1", "10.0.0.1", "spine1"),
    ("leaf2", "10.0.0.12", "Ethernet1", "10.0.0.1", "spine1"),
    ("leaf3", "10.0.0.13", "Ethernet2", "10.0.0.2", "spine2"),
    ("leaf4", "10.0.0.14", "Ethernet2", "10.0.0.2", "spine2"),
    ("wan-r2", "10.0.0.20", "Ethernet10", "192.168.100.5", "isp-a"),
]
PROBE_TARGETS = ["10.70.245.120", "8.8.8.8", "aws-tgw"]
SYSLOG_HOST, SYSLOG_PORT = "127.0.0.1", 5514


# ── reaching internal services (via the seeder's compose exec) ────────────────


def bus_post(url: str, obj: dict) -> bool:
    """POST one JSON object to an internal Vector HTTP source. Uses the victoria
    container as the in-network curl box (it has wget + is on the netops net)."""
    body = json.dumps(obj)
    script = (
        "wget -qO- --header='Content-Type: application/json' "
        f"--post-data='{body}' '{url}' >/dev/null 2>&1; echo $?"
    )
    r = base.compose("exec", "-T", "victoria", "sh", "-c", script, capture=True)
    return r.returncode == 0


def redis_set(key: str, val: str, ttl_s: int = 0) -> bool:
    args = ["exec", "-T", "redis", "redis-cli", "SET", key, val]
    if ttl_s > 0:
        args += ["EX", str(ttl_s)]
    r = base.compose(*args, capture=True)
    if r.returncode != 0:
        # §16.1: say why, never swallow (stderr carries no secret: the value
        # is the signed envelope or plain demo JSON).
        err = (r.stderr or r.stdout or "").strip().splitlines()
        print(f"  ! redis SET {key} failed (exit {r.returncode}): {err[-1] if err else 'no output'}",
              file=sys.stderr)
    return r.returncode == 0


# ── signed path sets (tracker 475) ────────────────────────────────────────────
#
# The api believes a prober path set only when it is signed with the
# prober-control key (internal/probercontrol: a v1 envelope, kind "probe-paths",
# around a ResultRecord {schema, vantage, issued_at, body}). An unsigned set is
# refused — and counted, and logged — unless the platform administrator has
# turned on the console-only "Accept unsigned path traces" switch. So the demo
# signs its set when the operator running it can read the rendered key, and
# otherwise skips the traceroute pipeline with a message saying exactly why.
# The key is read into memory only: never printed, logged or passed on a
# command line.

PATH_SET_KIND = "probe-paths"
PATH_SET_TTL_S = 300  # the api believes a set for 300 s (ProbePathsMaxAge)
DEMO_VANTAGE = "demo-fill"
MIN_KEY_BYTES = 32  # probercontrol.minKeyBytes


def prober_key_path() -> str:
    """The api's rendered prober-control key (data/secrets/probercontrol/api)."""
    override = os.environ.get("PROBER_CONTROL_KEY_FILE", "").strip()
    if override:
        return override
    return os.path.normpath(os.path.join(base.COMPOSE_DIR, "..", "..", "data", "secrets",
                                         "probercontrol", "api", "password"))


def read_prober_key() -> tuple[bytes | None, str]:
    """(key, why-not). The reason names the path and the error, never the key."""
    path = prober_key_path()
    try:
        with open(path, "rb") as fh:
            key = fh.read().strip()
    except OSError as exc:
        return None, f"the prober-control key at {path} is not readable ({exc.strerror or exc})"
    if len(key) < MIN_KEY_BYTES:
        return None, f"the prober-control key at {path} is shorter than {MIN_KEY_BYTES} bytes"
    return key, ""


def seal_path_set(key: bytes, paths: list[dict], vantage: str = DEMO_VANTAGE) -> str:
    """Sign paths exactly as collectors.NewPathSealer does (SealResult + Seal)."""
    issued = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    payload = json.dumps({"schema": 1, "vantage": vantage, "issued_at": issued, "body": paths},
                         separators=(",", ":"))
    m = hmac.new(key, f"correlix-prober-control/{PATH_SET_KIND}\n".encode(), hashlib.sha256)
    m.update(payload.encode())
    return json.dumps({"v": 1, "payload": payload, "sig": m.hexdigest()}, separators=(",", ":"))


# ── syslog: BGP adjacency + link state (RFC5424 → host :5514) ──────────────────

_SYSLOG_SOCK = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def _syslog_send(host: str, appname: str, msg: str, severity: int = 5) -> None:
    """RFC5424 frame; PRI = facility(local0=16)*8 + severity. The hostname must
    survive as the device key (correlation + tenant attribution rely on it)."""
    pri = 16 * 8 + severity
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # RFC5424: <PRI>VERSION TS HOST APP PROCID MSGID STRUCTURED-DATA MSG
    # (PROCID/MSGID/SD nil). hostname + appname parse cleanly — what the
    # correlation control-plane parser and tenant attribution key off.
    frame = f"<{pri}>1 {ts} {host} {appname} - - - {msg}"
    _SYSLOG_SOCK.sendto(frame.encode(), (SYSLOG_HOST, SYSLOG_PORT))


def emit_syslog(down: bool) -> int:
    """One round of fabric control-plane events. `down` toggles a flap so the
    Logs panel shows both transitions and correlation sees a real change."""
    n = 0
    for dev, _mgmt, ifname, peer, _seam in FABRIC:
        if down:
            _syslog_send(dev, "%BGP-5-ADJCHANGE",
                         f"peer {peer} (AS 65001) old state Established event HoldTimer "
                         f"new state Idle", severity=4)
            _syslog_send(dev, "%LINEPROTO-5-UPDOWN",
                         f"Line protocol on Interface {ifname}, changed state to down", severity=3)
        else:
            _syslog_send(dev, "%BGP-5-ADJCHANGE",
                         f"peer {peer} (AS 65001) old state Idle event Established "
                         f"new state Established", severity=5)
            _syslog_send(dev, "%LINEPROTO-5-UPDOWN",
                         f"Line protocol on Interface {ifname}, changed state to up", severity=5)
        n += 2
    return n


# ── SNMP traps (decoded JSON with readable names → Vector :8688) ───────────────

TRAP_KINDS = [
    ("linkDown", "1.3.6.1.6.3.1.1.5.3", "warning"),
    ("linkUp", "1.3.6.1.6.3.1.1.5.4", "notice"),
    ("bgpBackwardTransition", "1.3.6.1.2.1.15.7.2", "warning"),
    ("coldStart", "1.3.6.1.6.3.1.1.5.1", "notice"),
]


def emit_traps() -> int:
    n = 0
    for i, (dev, mgmt, ifname, _peer, _seam) in enumerate(FABRIC):
        name, oid, sev = TRAP_KINDS[i % len(TRAP_KINDS)]
        trap = {
            "device": dev, "host": mgmt, "severity": sev,
            "trap_name": name, "trap_oid": oid, "snmp_version": "2c",
            "varbinds": [
                {"oid": "ifDescr", "value": ifname},
                {"oid": "ifIndex", "value": str(i + 1)},
            ],
        }
        if bus_post("http://vector-aggregator:8688/", trap):
            n += 1
    return n


# ── active probe events (→ Vector :8689 → netops.probes) ──────────────────────


def emit_probes(degraded: bool) -> int:
    n = 0
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime())
    for obs in ("api", "prober"):
        for tgt in PROBE_TARGETS:
            loss = 18.0 if (degraded and tgt == "10.70.245.120") else 0.0
            rtt = 120.0 if (degraded and tgt == "10.70.245.120") else 6.0
            ev = {"kind": "stamp", "prober": obs, "target": tgt,
                  "ok": loss < 100, "rtt_ms": rtt, "jitter_ms": 1.5,
                  "loss_pct": loss, "ts": ts}
            if bus_post("http://vector-aggregator:8689/", ev):
                n += 1
    return n


# ── VictoriaMetrics: interface / BGP / STAMP panels ───────────────────────────


def metric_block(at_ms: int, elapsed_s: float, degraded: bool) -> list[str]:
    lines = []
    for i, (dev, mgmt, ifname, peer, _seam) in enumerate(FABRIC):
        lab = f'{{device="{dev}",instance="{mgmt}",ifName="{ifname}",ifIndex="{i+1}",site="lab"}}'
        plab = f'{{device="{dev}",instance="{mgmt}",peer="{peer}",site="lab"}}'
        util = 35 + (i * 7)
        in_bps = (util / 100.0) * 1_000_000_000 / 8
        # Interface throughput counters (rate() → bps) keyed by ifName.
        lines.append(f"if_in_octets{lab} {int(in_bps*elapsed_s)} {at_ms}")
        lines.append(f"if_out_octets{lab} {int(in_bps*0.7*elapsed_s)} {at_ms}")
        lines.append(f"if_in_util_percent{lab} {util:.1f} {at_ms}")
        lines.append(f"if_out_util_percent{lab} {util*0.7:.1f} {at_ms}")
        # Error / CRC counters — small but non-zero so the error panels render.
        errs = int(elapsed_s * (5 if i == 0 else 1))
        lines.append(f"if_in_errors{lab} {errs} {at_ms}")
        lines.append(f"if_in_crc_errors{lab} {errs//2} {at_ms}")
        # BGP peer state: 6=Established, 1=Idle (BGP4-MIB bgpPeerState).
        state = 1 if (degraded and i == 0) else 6
        lines.append(f"bgp_peer_state{plab} {state} {at_ms}")
        lines.append(f"bgp_peer_established_transitions{plab} {1 if degraded else 0} {at_ms}")
    # STAMP path SLA per target.
    for tgt in PROBE_TARGETS:
        deg = degraded and tgt == "10.70.245.120"
        tl = f'{{dst="{tgt}",probe="stamp"}}'
        lines.append(f"probe_rtt_ms{tl} {120.0 if deg else 6.0:.3f} {at_ms}")
        lines.append(f"probe_loss_pct{tl} {18.0 if deg else 0.0:.2f} {at_ms}")
        lines.append(f"probe_pdv_ms{tl} {8.0 if deg else 0.4:.3f} {at_ms}")
    return lines


def emit_metrics(degraded: bool, elapsed_s: float) -> int:
    now_ms = int(time.time() * 1000)
    block = metric_block(now_ms, max(1.0, elapsed_s), degraded)
    base.vm_push("\n".join(block) + "\n")
    return len(block)


# ── traceroute (→ Redis netops:probe:paths) ───────────────────────────────────


def emit_traceroute() -> int:
    # Two traceroute modes are demonstrated:
    #  • PRIORITY / "auto" (10.70.245.120): icmp first; where icmp got no reply
    #    (hop 2 = a "*"), tcp fills the gap — one merged path, the filled hop
    #    tagged via=tcp. This is the mtr-style "icmp, fall back to tcp" mode.
    #  • PARALLEL / "both" (others): icmp and tcp traced independently and shown
    #    as a row each; they diverge in the middle (different ECMP / firewall).
    paths = []
    auto_tgt = "10.70.245.120"
    paths.append({
        "dst": auto_tgt, "method": "auto", "reached": True, "signature": f"sig-auto-{auto_tgt}",
        "hops": [
            {"ttl": 1, "ip": "10.0.0.1", "host": "lan-gw1", "rtt_ms": 0.4},
            {"ttl": 2, "ip": "172.40.40.52", "host": "wan-edge2", "rtt_ms": 2.6, "via": "tcp"},  # icmp "*" → filled by tcp
            {"ttl": 3, "ip": auto_tgt, "host": "dc-core1", "rtt_ms": 6.2},
        ],
    })
    for tgt in PROBE_TARGETS:
        if tgt == auto_tgt:
            continue
        icmp_hops = [
            {"ttl": 1, "ip": "10.0.0.1", "rtt_ms": 0.4},
            {"ttl": 2, "ip": "172.40.40.52", "rtt_ms": 2.1},
            {"ttl": 3, "ip": tgt, "rtt_ms": 6.2},
        ]
        tcp_hops = [
            {"ttl": 1, "ip": "10.0.0.1", "rtt_ms": 0.5},
            {"ttl": 2, "ip": "172.40.40.86", "rtt_ms": 2.4},  # different middle hop
            {"ttl": 3, "ip": tgt, "rtt_ms": 6.9},
        ]
        paths.append({"dst": tgt, "method": "icmp", "hops": icmp_hops,
                      "signature": f"sig-icmp-{tgt}", "reached": True})
        paths.append({"dst": tgt, "method": "tcp", "hops": tcp_hops,
                      "signature": f"sig-tcp-{tgt}", "reached": True})
    return publish_path_set(paths)


# Set by main(): write the unsigned form (only for an install where the
# administrator has turned on "Accept unsigned path traces").
UNSIGNED_PATHS = False
_PATH_SKIP_SAID = False


def publish_path_set(paths: list[dict]) -> int:
    """Write the demo path set to the legacy key, signed. 1 written, 0 not."""
    global _PATH_SKIP_SAID
    if UNSIGNED_PATHS:
        # Refused by the api unless the console switch is on; the operator
        # asked for it explicitly.
        return 1 if redis_set("netops:probe:paths", json.dumps(paths), PATH_SET_TTL_S) else 0
    key, why = read_prober_key()
    if key is None:
        if not _PATH_SKIP_SAID:
            print("  ! traceroute skipped: the api refuses unsigned path sets (tracker 475) and "
                  f"{why}. Run as a user who can read it, set PROBER_CONTROL_KEY_FILE, or turn on "
                  "'Accept unsigned path traces' (Platform → Configuration → Features) and pass "
                  "--unsigned-paths.", file=sys.stderr)
            _PATH_SKIP_SAID = True
        return 0
    return 1 if redis_set("netops:probe:paths", seal_path_set(key, paths), PATH_SET_TTL_S) else 0


# ── orchestration ─────────────────────────────────────────────────────────────

ALL = {"syslog", "traps", "probes", "metrics", "traceroute", "base"}


def backfill_metrics(degraded: bool, backfill_s: int = 1800, step_s: int = 30) -> None:
    """Backfill the interface/BGP/STAMP series so panels have depth on load."""
    now_ms = int(time.time() * 1000)
    start = now_ms - backfill_s * 1000
    batch, t = [], start
    while t <= now_ms:
        batch += metric_block(t, (t - start) / 1000.0, degraded)
        t += step_s * 1000
    print(f"• demo metrics backfill: {len(batch):,} samples ({backfill_s//60} min)…")
    base.vm_push("\n".join(batch) + "\n")


def tick(sel: set[str], degraded: bool, elapsed_s: float) -> None:
    parts = []
    if "syslog" in sel:
        parts.append(f"syslog={emit_syslog(degraded)}")
    if "traps" in sel:
        parts.append(f"traps={emit_traps()}")
    if "probes" in sel:
        parts.append(f"probes={emit_probes(degraded)}")
    if "metrics" in sel:
        parts.append(f"metrics={emit_metrics(degraded, elapsed_s)}")
    if "traceroute" in sel:
        parts.append(f"traceroute={emit_traceroute()}")
    print(f"  tick ({'degraded' if degraded else 'healthy'}): " + " ".join(parts), flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Demo-fill generator (panels + correlation).")
    ap.add_argument("--once", action="store_true", help="one backfill + one live tick, then exit")
    ap.add_argument("--duration", type=int, default=0, metavar="SECONDS",
                    help="push a live tick every --step seconds for N seconds, then stop")
    ap.add_argument("--step", type=int, default=30, help="seconds between live ticks (default 30)")
    ap.add_argument("--only", default="", help="comma list subset of: " + ",".join(sorted(ALL)))
    ap.add_argument("--degrade", action="store_true",
                    help="emit a degraded incident (loss/flap) instead of healthy steady-state")
    ap.add_argument("--unsigned-paths", action="store_true",
                    help="write the traceroute set unsigned; the api refuses it unless "
                         "'Accept unsigned path traces' is on (default: sign with the "
                         "prober-control key, or skip if it is not readable)")
    args = ap.parse_args()
    global UNSIGNED_PATHS
    UNSIGNED_PATHS = args.unsigned_paths

    sel = set(args.only.split(",")) & ALL if args.only else set(ALL)
    print(f"demo-fill: pipelines={sorted(sel)} (compose dir: {base.COMPOSE_DIR})")

    if "base" in sel:
        base.seed_metrics()
        base.seed_flows(0.3, 20000)
        base.seed_tunnels()
        base.seed_findings()
    if sel & {"metrics"}:
        backfill_metrics(args.degrade)

    if args.once or not args.duration:
        tick(sel, args.degrade, args.step)
        print("demo-fill: one-shot done.")
        return

    deadline = time.time() + args.duration
    start = time.time()
    print(f"demo-fill: live for {args.duration}s (step {args.step}s)…")
    while time.time() < deadline:
        tick(sel, args.degrade, time.time() - start)
        time.sleep(max(1, args.step))
    print("demo-fill: duration elapsed, stopped.")


if __name__ == "__main__":
    sys.exit(main())
