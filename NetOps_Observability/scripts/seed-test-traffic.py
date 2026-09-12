#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Seed the NetOps stack with synthetic traffic so every module populates.

Drives the *real* ingest paths so you can watch data appear in the UI:

  syslog   → UDP/TCP :5514  (syslog-ng → Vector → OpenSearch netops-syslog-*)
  netflow  → UDP :2055      (goflow2 → Vector → ClickHouse netops.flows)
  metrics  → VictoriaMetrics /api/v1/import/prometheus  (Metrics Explorer)
  findings → ClickHouse netops.findings                 (Alerts → Incidents)

These four cover Search, Flows, Metrics, and Incidents with NO API auth.
Device/alert seeding that needs the API uses a token if you provide one
(NETOPS_TOKEN, or NETOPS_USER + NETOPS_PASSWORD).

Stdlib only — no pip installs. Safe to re-run; it appends fresh data.

Examples:
  ./seed-test-traffic.py                 # everything, default volumes
  ./seed-test-traffic.py syslog flows    # only those two
  ./seed-test-traffic.py --host 10.1.2.3 # target a remote stack
  COUNT=200 ./seed-test-traffic.py metrics
"""
import argparse
import json
import os
import random
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Config — overridable by env / flags so this works against a remote host too.
# ---------------------------------------------------------------------------
HOST = os.environ.get("NETOPS_HOST", "127.0.0.1")
BASE_PORT = int(os.environ.get("BASE_PORT", "8000"))
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "5514"))
NETFLOW_PORT = int(os.environ.get("NETFLOW_PORT", "2055"))
# VictoriaMetrics + ClickHouse are not published on the host by default, so
# we reach them by exec-ing through the compose network when local. When the
# stack is local we shell out to `docker compose exec`; for remote use, set
# VICTORIA_URL / CLICKHOUSE_URL to reachable endpoints.
VICTORIA_URL = os.environ.get("VICTORIA_URL", "")
CLICKHOUSE_URL = os.environ.get("CLICKHOUSE_URL", "")

DEVICES = [
    ("edge-rtr-01", "10.20.0.1"),
    ("edge-rtr-02", "10.20.0.2"),
    ("core-sw-01", "10.20.1.1"),
    ("core-sw-02", "10.20.1.2"),
    ("dist-sw-03", "10.20.2.3"),
    ("fw-edge-01", "10.20.3.1"),
]
SUBNETS = ["10.20.10.", "10.20.20.", "192.168.5.", "172.16.8."]
SEVERITIES = [  # (RFC3164 numeric severity, label) — Vector maps these through
    (3, "error"),
    (4, "warning"),
    (5, "notice"),
    (6, "info"),
    (7, "debug"),
    (2, "critical"),
]
SYSLOG_MSGS = [
    ("sshd", "Accepted password for netops from {ip} port {port}"),
    ("sshd", "Failed password for invalid user admin from {ip} port {port}"),
    ("bgpd", "%BGP-5-ADJCHANGE: neighbor {ip} Up"),
    ("bgpd", "%BGP-3-NOTIFICATION: sent to neighbor {ip} hold time expired"),
    ("ospf", "%OSPF-5-ADJCHG: Process 1, Nbr {ip} on Gi0/1 from LOADING to FULL"),
    ("kernel", "Interface GigabitEthernet0/{port} changed state to down"),
    ("kernel", "Interface GigabitEthernet0/{port} changed state to up"),
    ("snmpd", "Connection from UDP: [{ip}]:{port}"),
    ("sys", "%SYS-5-CONFIG_I: Configured from console by netops"),
    ("dhcpd", "DHCPACK on {ip} to 00:1b:44:11:3a:b7 via eth0"),
]
FINDING_KINDS = ["anomaly", "correlation", "threshold_breach", "flap"]


def rand_ip(subnet=None):
    return (subnet or random.choice(SUBNETS)) + str(random.randint(2, 254))


# ---------------------------------------------------------------------------
# syslog → syslog-ng (RFC3164). Both UDP and a few TCP for variety.
# ---------------------------------------------------------------------------
def seed_syslog(count):
    sent = 0
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(count):
        sev, _label = random.choice(SEVERITIES)
        facility = 16  # local0
        pri = facility * 8 + sev
        host, _addr = random.choice(DEVICES)
        tag, tmpl = random.choice(SYSLOG_MSGS)
        msg = tmpl.format(ip=rand_ip(), port=random.randint(1024, 65000))
        ts = time.strftime("%b %d %H:%M:%S", time.localtime())
        # RFC3164: <PRI>TIMESTAMP HOST TAG: MSG
        line = f"<{pri}>{ts} {host} {tag}[{random.randint(100,9999)}]: {msg}"
        data = line.encode("utf-8", "replace")
        try:
            if i % 5 == 0:  # ~20% over TCP to exercise that path too
                with socket.create_connection((HOST, SYSLOG_PORT), timeout=2) as tcp:
                    tcp.sendall(data + b"\n")
            else:
                udp.sendto(data, (HOST, SYSLOG_PORT))
            sent += 1
        except OSError as e:
            print(f"  ! syslog send failed: {e}", file=sys.stderr)
            break
        if i % 50 == 0:
            time.sleep(0.02)
    udp.close()
    print(f"  syslog: sent {sent} messages to {HOST}:{SYSLOG_PORT} (udp+tcp)")
    return sent


# ---------------------------------------------------------------------------
# NetFlow v5 → goflow2. v5 is a fixed binary layout: 24-byte header + N*48.
# ---------------------------------------------------------------------------
def _nf5_header(count, seq, uptime_ms, unix_secs):
    # version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq,
    # engine_type, engine_id, sampling_interval
    return struct.pack(
        ">HHIIIIBBH", 5, count, uptime_ms, unix_secs, 0, seq, 0, 0, 0
    )


def _nf5_record(uptime_ms):
    """One NetFlow v5 flow record — exactly 48 bytes."""
    src = rand_ip()
    dst = rand_ip()
    pkts = random.randint(1, 5000)
    octets = pkts * random.randint(40, 1400)
    first = uptime_ms - random.randint(1000, 60000)
    last = uptime_ms - random.randint(0, 1000)
    src_port = random.choice([22, 80, 443, 3389, 53, random.randint(1024, 65000)])
    dst_port = random.choice([22, 80, 443, 161, 514, random.randint(1024, 65000)])
    proto = random.choice([6, 6, 6, 17, 1])  # weight TCP
    # Layout: srcaddr dstaddr nexthop input output dPkts dOctets First Last
    #         srcport dstport pad1 tcp_flags prot tos src_as dst_as
    #         src_mask dst_mask pad2
    return struct.pack(
        ">IIIHHIIIIHHBBBBHHBBH",
        struct.unpack(">I", socket.inet_aton(src))[0],
        struct.unpack(">I", socket.inet_aton(dst))[0],
        0,                            # nexthop 0.0.0.0
        random.randint(1, 48),        # input snmp if
        random.randint(1, 48),        # output snmp if
        pkts,
        octets,
        first & 0xFFFFFFFF,
        last & 0xFFFFFFFF,
        src_port,
        dst_port,
        0,                            # pad1
        random.choice([0, 16, 24]),   # tcp_flags
        proto,
        0,                            # tos
        random.randint(0, 65000),     # src_as
        random.randint(0, 65000),     # dst_as
        random.choice([24, 25, 30]),  # src_mask
        random.choice([24, 25, 30]),  # dst_mask
        0,                            # pad2
    )


def seed_netflow(count):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = random.randint(1, 100000)
    sent_flows = 0
    per_packet = 12  # NetFlow v5 caps at 30; keep packets small
    remaining = count
    while remaining > 0:
        n = min(per_packet, remaining)
        uptime = int(time.monotonic() * 1000) & 0xFFFFFFFF
        pkt = _nf5_header(n, seq, uptime, int(time.time()))
        for _ in range(n):
            pkt += _nf5_record(uptime)
        try:
            udp.sendto(pkt, (HOST, NETFLOW_PORT))
        except OSError as e:
            print(f"  ! netflow send failed: {e}", file=sys.stderr)
            break
        seq += n
        sent_flows += n
        remaining -= n
        time.sleep(0.03)
    udp.close()
    print(f"  netflow: sent {sent_flows} v5 flow records to {HOST}:{NETFLOW_PORT}")
    return sent_flows


# ---------------------------------------------------------------------------
# Metrics → VictoriaMetrics (Prometheus text exposition import).
# ---------------------------------------------------------------------------
def _post(url, data, headers, method="POST"):
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, r.read()


def _victoria_import(body_text):
    """POST Prometheus-format samples to VM, locally via docker exec or HTTP."""
    if VICTORIA_URL:
        url = VICTORIA_URL.rstrip("/") + "/api/v1/import/prometheus"
        _post(url, body_text.encode(), {"Content-Type": "text/plain"})
        return "http"
    # Local: POST through the compose network from a container with curl
    # (victoria binds the network iface, not loopback; the api image is
    # distroless — opensearch ships curl and resolves `victoria` by name).
    import subprocess
    p = subprocess.run(
        ["docker", "compose", "exec", "-T", "opensearch",
         "curl", "-s", "-m", "20", "-X", "POST", "--data-binary", "@-",
         "http://victoria:8428/api/v1/import/prometheus"],
        input=body_text.encode(), cwd=_compose_dir(),
        capture_output=True, check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode()[:300] or "victoria import failed")
    return "docker"


def seed_metrics(count):
    # Emit a few realistic SNMP-style gauges per device, ramped so charts move.
    lines = []
    now_ms = int(time.time() * 1000)
    for host, addr in DEVICES:
        cpu = random.randint(15, 99)
        mem = random.randint(20, 95)
        up = random.choice([1, 1, 1, 0])  # occasional down → can trip alerts
        lbl = f'device_id="{host}",instance="{addr}",site="lab"'
        lines.append(f"up{{{lbl}}} {up} {now_ms}")
        lines.append(f"cpu_usage{{{lbl}}} {cpu} {now_ms}")
        lines.append(f"memory_usage{{{lbl}}} {mem} {now_ms}")
        for ifn in range(1, 4):
            il = f'device_id="{host}",ifName="Gi0/{ifn}"'
            lines.append(f"ifInOctets{{{il}}} {random.randint(1_000_000, 9_000_000_000)} {now_ms}")
            lines.append(f"ifOutOctets{{{il}}} {random.randint(1_000_000, 9_000_000_000)} {now_ms}")
            lines.append(f"ifOperStatus{{{il}}} {random.choice([1,1,1,2])} {now_ms}")
    # Replicate the block `count` times with small time offsets so the
    # Metrics Explorer has a short series to draw rather than one point.
    body = []
    for k in range(max(1, count)):
        t = now_ms - (count - k) * 15000  # 15s spacing back in time
        for line in lines:
            base, _, _ts = line.rpartition(" ")
            body.append(f"{base} {t}")
    via = _victoria_import("\n".join(body) + "\n")
    print(f"  metrics: imported {len(body)} samples to VictoriaMetrics (via {via})")
    return len(body)


# ---------------------------------------------------------------------------
# Findings → ClickHouse netops.findings (Alerts → Incidents view).
# ---------------------------------------------------------------------------
def _clickhouse_insert(sql, body_bytes):
    if CLICKHOUSE_URL:
        url = CLICKHOUSE_URL.rstrip("/") + "/?query=" + urllib.parse.quote(sql)
        user = os.environ.get("CLICKHOUSE_USER", "netops")
        pw = os.environ.get("CLICKHOUSE_PASSWORD", "")
        import base64
        auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
        _post(url, body_bytes, {"Authorization": f"Basic {auth}"})
        return "http"
    import subprocess
    p = subprocess.run(
        ["docker", "compose", "exec", "-T", "clickhouse",
         "clickhouse-client", "-q", sql],
        input=body_bytes, cwd=_compose_dir(), capture_output=True, check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode()[:300] or "clickhouse insert failed")
    return "docker"


def seed_alert_breach(count):
    """Push metrics that breach the shipped rules so alerts fire.

    The engine evaluates each rule as an INSTANT query and fires on the first
    matching tick (it does not honor `for:`), so one fresh breaching sample is
    enough — the alert fires within ~30s. We push a few times over ~90s to
    stay inside the 5-min instant-staleness window while the engine ticks.
      HighCPU         cpu_usage > 90
      HighMemory      memory_usage > 85
      DeviceUnreachable  up == 0
    """
    host, addr = DEVICES[0]
    lbl = f'device_id="{host}",instance="{addr}",site="lab"'
    rounds = max(1, min(count, 8))
    for k in range(rounds):
        now_ms = int(time.time() * 1000)
        body = "\n".join([
            f"cpu_usage{{{lbl}}} 99 {now_ms}",
            f"memory_usage{{{lbl}}} 95 {now_ms}",
            f"up{{{lbl}}} 0 {now_ms}",
        ]) + "\n"
        _victoria_import(body)
        if k < rounds - 1:
            time.sleep(15)
    print(f"  alert-demo: pushed breaching metrics for {host} "
          f"(cpu=99, mem=95, up=0) x{rounds} — HighCPU/HighMemory/"
          f"DeviceUnreachable should fire within ~30s")
    return rounds


def seed_findings(count):
    rows = []
    for _ in range(count):
        host, _addr = random.choice(DEVICES)
        sev = random.choice(["info", "warning", "warning", "critical"])
        kind = random.choice(FINDING_KINDS)
        score = round(random.uniform(2.5, 9.8), 2)
        comp = random.choice(["interface", "bgp", "cpu", "memory", "flow"])
        rows.append({
            "id": f"f-{random.randint(10**9, 10**10)}",
            "kind": kind,
            "severity": sev,
            "score": score,
            "device": host,
            "component": comp,
            "summary": f"{kind} on {host}/{comp} (z={score})",
            "description": f"Synthetic {kind} finding generated by seed-test-traffic.py",
            "labels": {"source": "seed", "site": "lab"},
        })
    body = "\n".join(json.dumps(r) for r in rows).encode() + b"\n"
    via = _clickhouse_insert(
        "INSERT INTO netops.findings (id,kind,severity,score,device,component,summary,description,labels) FORMAT JSONEachRow",
        body,
    )
    print(f"  findings: inserted {len(rows)} rows into netops.findings (via {via})")
    return len(rows)


# ---------------------------------------------------------------------------
def _compose_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "deployment", "docker")


SEEDERS = {
    "syslog": seed_syslog,
    "netflow": seed_netflow,
    "flows": seed_netflow,   # alias
    "metrics": seed_metrics,
    "findings": seed_findings,
    "alert-demo": seed_alert_breach,
    "alerts": seed_alert_breach,  # alias
}


def main():
    global HOST
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*",
                    help="subset to run: syslog netflow metrics findings (default: all)")
    ap.add_argument("--host", default=HOST, help="stack host (default %(default)s)")
    ap.add_argument("--count", type=int, default=int(os.environ.get("COUNT", "120")),
                    help="rough volume per target (default %(default)s)")
    args = ap.parse_args()
    HOST = args.host

    chosen = args.targets or ["syslog", "netflow", "metrics", "findings"]
    # de-dup while preserving order; map flows→netflow
    seen, order = set(), []
    for t in chosen:
        key = "netflow" if t == "flows" else t
        if key not in seen:
            seen.add(key)
            order.append(key)

    print(f"Seeding test traffic → {HOST} (count≈{args.count} per target)\n")
    results = {}
    for key in order:
        fn = SEEDERS.get(key)
        if not fn:
            print(f"  ? unknown target '{key}' (skipped)")
            continue
        print(f"[{key}]")
        try:
            results[key] = fn(args.count)
        except Exception as e:  # noqa: BLE001 - report and continue
            print(f"  ! {key} failed: {e}", file=sys.stderr)
            results[key] = None
        print()

    ok = [k for k, v in results.items() if v]
    bad = [k for k, v in results.items() if not v]
    print("Done. Data takes a few seconds to flow through Vector → storage.")
    print(f"  seeded: {', '.join(ok) or 'none'}")
    if bad:
        print(f"  FAILED: {', '.join(bad)}")
    print("\nWhere to look in the UI:")
    print("  Search    → syslog messages (severity-coded)")
    print("  Analytics → Flows (top talkers / by-proto)")
    print("  Analytics → Metrics (cpu_usage, ifInOctets, …; needs METRICS_URL=victoria)")
    print("  Alerts    → Incidents (findings)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
