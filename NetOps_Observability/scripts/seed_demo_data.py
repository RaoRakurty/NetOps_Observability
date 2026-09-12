#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Seed the running stack with demo telemetry so every dashboard/metric is
exercised — useful for a functional walkthrough without live devices.

It populates:
  * ~1 GB of NetFlow records  -> ClickHouse netops.flows
  * per-device resource metrics (cpu/mem/storage/if-util + if octet counters)
    -> VictoriaMetrics, so the Overview gauges ("wheels") fill with color
  * overlay tunnels (IPsec/SD-WAN/GRE)  -> ClickHouse netops.tunnels
  * a handful of fresh anomaly findings -> ClickHouse netops.findings

Everything is pushed through `docker compose exec` against the internal
ClickHouse/VictoriaMetrics services (neither is exposed on the host), so run it
from anywhere — it locates the compose project itself.

Usage:
  python3 scripts/seed_demo_data.py              # one-shot seed
  python3 scripts/seed_demo_data.py --gb 2       # ~2 GB of flows
  python3 scripts/seed_demo_data.py --metrics-only --loop 1500
                                                 # keep gauges live ~25 min
"""
import argparse
import math
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE_DIR = os.path.normpath(os.path.join(HERE, "..", "deployment", "docker"))

# (name, mgmt address, cpu, mem, storage, if-util) baseline load per device.
# Tuned so the four Overview gauges land in *different* color bands — CPU/storage
# healthy (emerald), memory busy (amber), network util hot (rose) — to show the
# severity color-coding rather than one flat hue.
DEVICES = [
    ("edge-rtr-01", "10.20.0.1", 78, 82, 55, 96),
    ("edge-rtr-02", "10.20.0.2", 44, 74, 40, 92),
    ("core-sw-01", "10.20.1.1", 35, 78, 30, 95),
    ("dist-sw-03", "10.20.2.3", 22, 68, 25, 91),
    ("fw-edge-01", "10.20.3.1", 88, 78, 70, 95),
]


def compose(*args, stdin=None, capture=False):
    cmd = ["docker", "compose", *args]
    return subprocess.run(
        cmd, cwd=COMPOSE_DIR, input=stdin, text=True,
        capture_output=capture, check=False,
    )


def ch(sql):
    """Run a ClickHouse query via the clickhouse container."""
    r = compose("exec", "-T", "clickhouse", "clickhouse-client", "-q", sql, capture=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
    return r


def vm_push(exposition):
    """POST Prometheus-exposition text into VictoriaMetrics' import endpoint."""
    script = (
        "cat > /tmp/seed.prom && "
        "wget -qO- --post-file=/tmp/seed.prom "
        "'http://127.0.0.1:8428/api/v1/import/prometheus' && rm -f /tmp/seed.prom"
    )
    r = compose("exec", "-T", "victoria", "sh", "-c", script, stdin=exposition, capture=True)
    if r.returncode != 0:
        sys.stderr.write("VM push failed: " + (r.stderr or "") + "\n")
    return r.returncode == 0


# ---- flows ------------------------------------------------------------------

def seed_flows(total_gb, rows):
    """Insert `rows` flow records over the last hour whose effective bytes
    (bytes * sampling_rate) sum to ~total_gb."""
    target_bytes = int(total_gb * (1024 ** 3))
    avg = max(64, target_bytes // rows)            # per-row mean
    span = 2 * avg                                  # rand()%span => mean ~avg
    # A talker pool: the five devices plus a few "external" peers, so top-talker
    # aggregation produces meaningful hot pairs.
    pool = ("['10.20.0.1','10.20.0.2','10.20.1.1','10.20.2.3','10.20.3.1',"
            "'8.8.8.8','1.1.1.1','203.0.113.10','198.51.100.20','172.16.5.5',"
            "'10.20.5.50','104.16.0.1','9.9.9.9','140.82.121.4']")
    protos = "[6,6,6,6,6,6,6,6,17,17,17,17,1,6,17]"     # TCP-heavy, some UDP/ICMP
    dports = "[443,443,443,80,80,53,53,22,123,3389,8443,5060,161,179,514]"
    sql = f"""
INSERT INTO netops.flows
  (ts, time_received_ns, sampler_address, src_addr, dst_addr, src_port, dst_port,
   proto, bytes, packets, in_if, out_if, src_as, dst_as, sampling_rate, vlan_id)
SELECT
  now64(3) - toIntervalSecond(toUInt32(rand() % 3600))      AS ts,
  toUInt64(0),
  '10.20.0.1',
  arrayElement({pool}, toUInt32(rand() % 14) + 1)            AS src_addr,
  arrayElement({pool}, toUInt32(rand(1) % 14) + 1)           AS dst_addr,
  toUInt16(1024 + rand(2) % 64000)                           AS src_port,
  toUInt16(arrayElement({dports}, toUInt32(rand(3) % 15) + 1)) AS dst_port,
  toUInt8(arrayElement({protos}, toUInt32(rand(4) % 15) + 1)) AS proto,
  toUInt64(64 + rand(5) % {span})                            AS bytes,
  toUInt64(1 + rand(6) % 60)                                 AS packets,
  toUInt32(rand(7) % 8), toUInt32(rand(8) % 8),
  toUInt32(0), toUInt32(0),
  toUInt32(1)                                                AS sampling_rate,
  toUInt16(0)
FROM numbers({rows})
"""
    print(f"• flows: inserting {rows:,} rows (~{total_gb:.2f} GB effective)…")
    r = ch(sql)
    if r.returncode == 0:
        got = ch("SELECT formatReadableSize(sum(bytes*sampling_rate)) FROM netops.flows "
                 "WHERE ts >= now() - INTERVAL 3600 SECOND").stdout.strip()
        print(f"  ✓ flows total (last 1h): {got}")


# ---- metrics ----------------------------------------------------------------

def metric_lines(at_ms, jitter_phase):
    """Build the Prometheus exposition for one timestamp (ms)."""
    lines = []
    for name, addr, cpu, mem, sto, ifu in DEVICES:
        lab = f'{{device="{name}",instance="{addr}",site="lab"}}'
        wob = 6 * math.sin(jitter_phase + hash(name) % 7)  # gentle per-device wobble
        for metric, base in (
            ("device_cpu_percent", cpu),
            ("device_mem_percent", mem),
            ("device_storage_percent", sto),
            ("device_if_util_percent", ifu),
        ):
            val = max(1, min(99, base + wob))
            lines.append(f"{metric}{lab} {val:.1f} {at_ms}")
    return lines


def counter_lines(at_ms, elapsed_s):
    """Monotonic interface octet counters so rate() yields a real throughput."""
    lines = []
    for name, addr, cpu, mem, sto, ifu in DEVICES:
        lab = f'{{device="{name}",instance="{addr}",site="lab"}}'
        # util% → bytes/sec (cap ~1Gbps link), integrated over elapsed seconds.
        in_bps = (ifu / 100.0) * 1_000_000_000 / 8
        out_bps = in_bps * 0.7
        lines.append(f"device_if_in_octets{lab} {int(in_bps*elapsed_s)} {at_ms}")
        lines.append(f"device_if_out_octets{lab} {int(out_bps*elapsed_s)} {at_ms}")
    return lines


def seed_metrics(backfill_s=1800, step_s=30):
    """Backfill resource gauges + interface counters up to 'now'."""
    now_ms = int(time.time() * 1000)
    start = now_ms - backfill_s * 1000
    batch = []
    n = 0
    t = start
    while t <= now_ms:
        elapsed = (t - start) / 1000.0
        phase = elapsed / 120.0
        batch += metric_lines(t, phase)
        batch += counter_lines(t, elapsed)
        n += 1
        t += step_s * 1000
    print(f"• metrics: pushing {len(batch):,} samples across {n} steps "
          f"({backfill_s//60} min backfill)…")
    ok = vm_push("\n".join(batch) + "\n")
    print("  ✓ device gauges + interface counters populated" if ok else "  ✗ metric push failed")


def push_now():
    """Single current-time push (used by --loop to keep gauges live)."""
    now_ms = int(time.time() * 1000)
    phase = (now_ms / 1000.0) / 120.0
    batch = metric_lines(now_ms, phase) + counter_lines(now_ms, now_ms / 1000.0)
    vm_push("\n".join(batch) + "\n")


# ---- tunnels ----------------------------------------------------------------

def seed_tunnels():
    rows = [
        ("ipsec-hub-edge01", "ipsec", "edge-rtr-01", "10.20.0.1", "hub-dc-01", "198.51.100.1", "up", 14.2, 1.1, 0.0, 4.7, 864000),
        ("ipsec-hub-edge02", "ipsec", "edge-rtr-02", "10.20.0.2", "hub-dc-01", "198.51.100.1", "up", 22.8, 2.4, 0.2, 4.4, 432000),
        ("sdwan-br-core01", "sdwan", "core-sw-01", "10.20.1.1", "branch-12", "203.0.113.12", "up", 31.5, 3.8, 0.6, 4.1, 215000),
        ("sdwan-br-core02", "sdwan", "core-sw-01", "10.20.1.1", "branch-27", "203.0.113.27", "degraded", 88.0, 12.5, 3.1, 2.6, 98000),
        ("gre-fw-partner", "gre", "fw-edge-01", "10.20.3.1", "partner-gw", "192.0.2.9", "up", 41.0, 4.2, 0.3, 3.9, 512000),
        ("ipsec-dr-edge01", "ipsec", "edge-rtr-01", "10.20.0.1", "dr-site-01", "198.51.100.50", "down", 0.0, 0.0, 100.0, 0.0, 0),
        ("sdwan-cloud-dist", "sdwan", "dist-sw-03", "10.20.2.3", "aws-tgw", "52.94.1.1", "up", 18.6, 2.0, 0.1, 4.6, 690000),
        ("gre-lab-mesh", "gre", "edge-rtr-02", "10.20.0.2", "lab-spine", "10.20.9.9", "up", 7.4, 0.6, 0.0, 4.9, 1200000),
    ]
    values = ",".join(
        f"(now64(3), '{i}','{ty}','{ld}','{la}','{rd}','{ra}','{st}',{lat},{jit},{loss},{qoe},{up})"
        for (i, ty, ld, la, rd, ra, st, lat, jit, loss, qoe, up) in rows
    )
    sql = ("INSERT INTO netops.tunnels (ts,id,type,local_device,local_addr,remote_device,"
           "remote_addr,status,latency_ms,jitter_ms,loss_pct,qoe,uptime_s) VALUES " + values)
    print(f"• tunnels: inserting {len(rows)} overlay tunnels…")
    if ch(sql).returncode == 0:
        print("  ✓ tunnels populated")


# ---- findings ---------------------------------------------------------------

def seed_findings():
    seed = [
        ("zscore", "critical", 9.2, "fw-edge-01", "cpu", "CPU saturation on fw-edge-01", "Rolling z-score breached: sustained CPU > 90%."),
        ("zscore", "warning", 4.1, "edge-rtr-01", "if-util", "Edge uplink nearing capacity", "edge-rtr-01 ge-0/0/1 utilization > 80% for 10m."),
        ("correlation", "error", 6.7, "core-sw-01", "memory", "Memory pressure correlated with flap", "Mem climb correlated with BGP session reset."),
        ("zscore", "notice", 2.3, "dist-sw-03", "storage", "Log volume growth", "Storage trend anomaly on dist-sw-03."),
        ("correlation", "critical", 8.8, "sdwan-br-core02", "tunnel", "SD-WAN branch-27 degraded", "Loss 3.1% + jitter 12ms; QoE dropped to 2.6."),
        ("zscore", "warning", 3.9, "edge-rtr-02", "if-util", "Asymmetric traffic spike", "Inbound 4x baseline on edge-rtr-02."),
    ]
    values = ",".join(
        f"(now64(3) - toIntervalSecond({i*47}), generateUUIDv4(), '{k}','{sev}',{sc},'{dev}','{comp}','{summ}','{desc}', map())"
        for i, (k, sev, sc, dev, comp, summ, desc) in enumerate(seed)
    )
    sql = ("INSERT INTO netops.findings (ts,id,kind,severity,score,device,component,summary,description,labels) "
           "VALUES " + values)
    print(f"• findings: inserting {len(seed)} fresh anomalies…")
    if ch(sql).returncode == 0:
        print("  ✓ findings populated")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gb", type=float, default=1.0, help="approx GB of flow traffic (default 1)")
    ap.add_argument("--rows", type=int, default=50000, help="flow row count (default 50k)")
    ap.add_argument("--metrics-only", action="store_true", help="only (re)push metrics")
    ap.add_argument("--loop", type=int, default=0, metavar="SECONDS",
                    help="keep pushing current metrics every 30s for N seconds")
    args = ap.parse_args()

    if args.loop:
        print(f"keep-alive: refreshing gauges every 30s for {args.loop}s…")
        deadline = time.time() + args.loop
        while time.time() < deadline:
            push_now()
            time.sleep(30)
        print("keep-alive: done.")
        return

    print(f"Seeding demo telemetry (compose dir: {COMPOSE_DIR})\n")
    seed_metrics()
    if not args.metrics_only:
        seed_flows(args.gb, args.rows)
        seed_tunnels()
        seed_findings()
    print("\nDone. Open http://localhost:8000 — gauges/flows/tunnels/findings are live.")
    print("Tip: gauges go stale after ~5 min; re-run, or use --metrics-only --loop 1500 to keep them live.")


if __name__ == "__main__":
    main()
