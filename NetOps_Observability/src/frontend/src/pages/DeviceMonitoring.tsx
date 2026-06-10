import { useEffect, useMemo, useState } from "react";
import { api, Device, Alert, Tunnel } from "../services/api";
import { useShell } from "../context/shell";
import { StatStrip, Stat } from "../components/ui";
import DataTable, { Column } from "../components/DataTable";
import {
  Group, Panel, MetricLine, MetricTop, BarPanel, EmptyHint, fmtBps, fmtPct, fmtBytes, fmtUptime, latest, seriesLabel, useMetricRange,
} from "../components/board/panels";
import { latSev, lossSev, coerce as coerceTunnel, fmtTunnelUptime } from "../tabs/Tunnels";
import { Stub } from "./Placeholders";

// Device Monitoring — the network-device-fleet cockpit (Datadog "Network Device
// Monitoring" master board). Collapsible, tinted section groups built on the
// shared board framework (components/board/panels). Every panel is wired to data
// we collect (SNMP metrics in VictoriaMetrics, the device inventory, active
// alerts); sections needing data we don't yet collect (NetPath, synthetics,
// IPsec OIDs, geomap) render a "Planned" stub. The inventory row drills into the
// Interface Performance board scoped to that device.

// ── Fleet pulse: reachability tiles + alerts-by-severity ─────────────────────
const SEV_ORDER = ["critical", "error", "warning", "notice", "info"];
function FleetPulse() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [d, a] = await Promise.all([api.devices(), api.alerts()]);
        if (!alive) return;
        setDevices(d ?? []);
        setAlerts(a ?? []);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const { monitored, reachable, unreachable } = useMemo(() => {
    const now = Date.now();
    let r = 0;
    for (const d of devices) {
      const seen = Date.parse(d.last_seen || "");
      if (Number.isFinite(seen) && now - seen < 5 * 60_000) r++;
    }
    return { monitored: devices.length, reachable: r, unreachable: devices.length - r };
  }, [devices]);

  const bySev = useMemo(() => {
    const open = alerts.filter((a) => !a.resolved_at);
    const counts: Record<string, number> = {};
    for (const a of open) {
      const s = (a.severity || "info").toLowerCase();
      counts[s] = (counts[s] || 0) + 1;
    }
    return SEV_ORDER.filter((s) => counts[s]).map((s) => ({ sev: s, n: counts[s] }));
  }, [alerts]);

  const sevTone = (s: string) => (s === "critical" || s === "error" ? "bad" : s === "warning" ? "warn" : "");

  return (
    <>
      <StatStrip>
        <Stat label="Monitored devices" value={monitored} />
        <Stat label="Reachable" value={reachable} tone="good" />
        <Stat label="Unreachable" value={unreachable} tone={unreachable > 0 ? "bad" : ""} />
        <Stat label="Open alerts" value={alerts.filter((a) => !a.resolved_at).length} tone={bySev.some((x) => x.sev === "critical" || x.sev === "error") ? "bad" : bySev.length ? "warn" : "good"} />
      </StatStrip>
      <Panel title="Active alerts by severity">
        {err ? (
          <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
        ) : bySev.length === 0 ? (
          <div className="empty">No active alerts. 🎉</div>
        ) : (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {bySev.map((x) => (
              <span key={x.sev} className={`badge ${sevTone(x.sev)}`}>{x.sev}: {x.n}</span>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}

// ── Device inventory & uptime (with drill-down to Interface Performance) ──────
function DeviceInventory() {
  const { navigate } = useShell();
  const [rows, setRows] = useState<Device[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const d = await api.devices();
        if (alive) { setRows(d ?? []); setErr(null); }
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 60_000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const now = Date.now();
  const cols = useMemo<Column<Device>[]>(() => [
    {
      key: "reach", header: "", width: "28px", render: (d) => {
        const seen = Date.parse(d.last_seen || "");
        const up = Number.isFinite(seen) && now - seen < 5 * 60_000;
        return <span title={up ? "Reachable" : "Unreachable"} style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: up ? "var(--good)" : "var(--bad)" }} />;
      },
    },
    { key: "name", header: "Device", sortable: true, text: (d) => d.name, render: (d) => d.name },
    { key: "address", header: "Address", sortable: true, text: (d) => d.address, render: (d) => <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{d.address}</span> },
    { key: "vendor", header: "Vendor", sortable: true, text: (d) => d.vendor || "—", render: (d) => d.vendor || "—" },
    { key: "model", header: "Model", sortable: true, text: (d) => d.model || "—", render: (d) => d.model || "—" },
    { key: "source", header: "Source", sortable: true, text: (d) => d.source, render: (d) => d.source },
    { key: "last_seen", header: "Last seen", sortable: true, sortValue: (d) => Date.parse(d.last_seen || "") || 0, render: (d) => (d.last_seen ? new Date(d.last_seen).toLocaleString() : "—") },
    {
      key: "act", header: "", width: "150px", render: (d) => (
        <button
          className="btn-ghost"
          style={{ fontSize: 11, padding: "3px 8px" }}
          onClick={() => navigate(`infrastructure/ifperf/${encodeURIComponent(d.name)}`)}
          title="Open Interface Performance scoped to this device"
        >
          Interface Performance →
        </button>
      ),
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
  ], []);

  return (
    <Panel title="Devices — inventory & reachability">
      {err ? (
        <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
      ) : rows.length === 0 ? (
        <div className="empty">No devices discovered yet.</div>
      ) : (
        <DataTable<Device> rows={rows} columns={cols} rowKey={(d) => d.id} height={Math.min(420, 44 + rows.length * 30)} ariaLabel="Device inventory" initialSort={{ key: "name", dir: "asc" }} />
      )}
    </Panel>
  );
}

// ── Uptime top-list, from device_sysuptime ───────────────────────────────────
function UptimeList({ minutes }: { minutes: number }) {
  const { series } = useMetricRange("device_sysuptime", minutes, 30);
  const rows = series.map((s) => ({ label: seriesLabel(s, ["device"]), value: latest(s) / 100 })).sort((a, b) => b.value - a.value).slice(0, 10);
  return (
    <Panel title="Longest device uptime">
      {rows.length === 0 ? (
        <div className="empty">No uptime data.</div>
      ) : (
        <ul className="dm-list">
          {rows.map((r) => (
            <li key={r.label}><span>{r.label}</span><strong>{fmtUptime(r.value)}</strong></li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

// ── Flow insights — fleet traffic from the flow records (NetFlow/IPFIX/sFlow) ──
function FlowInsights({ since }: { since: number }) {
  const [talkers, setTalkers] = useState<{ label: string; value: number }[]>([]);
  const [exporters, setExporters] = useState<{ label: string; value: number }[]>([]);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    const run = async () => {
      try {
        const [t, e] = await Promise.all([api.topTalkers(since, 10), api.flowsTopN("device", since, 10)]);
        if (!alive) return;
        setTalkers(((t?.data as any[]) ?? []).map((r) => ({ label: `${r.src} → ${r.dst}`, value: Number(r.bytes_total) })));
        setExporters(((e?.data as any[]) ?? []).map((r) => ({ label: String(r.k), value: Number(r.bytes_total) })));
        setErr(null);
      } catch (ex) { if (alive) setErr((ex as Error).message); }
    };
    run();
    const id = setInterval(run, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, [since]);
  return (
    <div className="dm-grid">
      <BarPanel title="Busiest talkers (bytes)" rows={talkers} fmtX={fmtBytes} err={err} dataKind="flows" />
      <BarPanel title="Top flow exporters (bytes)" rows={exporters} fmtX={fmtBytes} err={err} dataKind="flows" />
    </div>
  );
}

// ── Tunnel overlay — current state per tunnel from netops.tunnels ────────────
// Discovered by the tunnels collector (IF-MIB + TUNNEL-MIB SNMP walk, vendor-
// neutral); this is the fleet summary — the full searchable view with QoE/jitter
// heat lives at Infrastructure → Tunnels.
function TunnelOverlay() {
  const [rows, setRows] = useState<Tunnel[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const res = await api.tunnels(200);
        if (alive) { setRows((res?.data ?? []).map(coerceTunnel)); setErr(null); }
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const endpoint = (device: string, addr: string) => (
    <span title={`${device || "—"}${addr ? ` · ${addr}` : ""}`}>
      {device || "—"}
      {addr && <span className="mini-meta" style={{ marginLeft: 6, fontFamily: "var(--font-mono, monospace)" }}>{addr}</span>}
    </span>
  );

  const cols = useMemo<Column<Tunnel>[]>(() => [
    { key: "type", header: "Type", width: 84, text: (t) => t.type ?? "", render: (t) => <span className="badge">{t.type || "—"}</span> },
    { key: "local", header: "Local", sortable: true, text: (t) => `${t.local_device} ${t.local_addr}`, sortValue: (t) => t.local_device || "", render: (t) => endpoint(t.local_device, t.local_addr) },
    { key: "remote", header: "Remote", sortable: true, text: (t) => `${t.remote_device} ${t.remote_addr}`, sortValue: (t) => t.remote_device || "", render: (t) => endpoint(t.remote_device, t.remote_addr) },
    { key: "latency", header: "Latency", width: 92, align: "right", sortable: true, sortValue: (t) => t.latency_ms, sev: (t) => latSev(t.latency_ms), render: (t) => (t.latency_ms > 0 ? `${t.latency_ms.toFixed(1)} ms` : "—") },
    { key: "loss", header: "Loss", width: 80, align: "right", sortable: true, sortValue: (t) => t.loss_pct, sev: (t) => lossSev(t.loss_pct), render: (t) => (t.loss_pct > 0 ? `${t.loss_pct.toFixed(2)} %` : "—") },
    { key: "uptime", header: "Uptime", width: 88, align: "right", sortable: true, sortValue: (t) => t.uptime_s, render: (t) => fmtTunnelUptime(t.uptime_s) },
    {
      key: "status", header: "Status", width: 82, sortable: true, text: (t) => t.status ?? "", sortValue: (t) => t.status ?? "",
      render: (t) => <span className={`badge ${t.status === "up" ? "good" : "bad"}`}>{t.status || "?"}</span>,
    },
  ], []);

  const up = rows.filter((t) => t.status === "up").length;
  const down = rows.length - up;
  const ipsec = rows.filter((t) => t.type === "ipsec").length;
  const gre = rows.filter((t) => t.type === "gre").length;

  if (err) return <Panel title="Tunnels — current state"><div className="empty" style={{ color: "var(--bad)" }}>{err}</div></Panel>;
  if (rows.length === 0) return <Panel title="Tunnels — current state"><EmptyHint kind="tunnels" /></Panel>;

  return (
    <>
      <StatStrip>
        <Stat label="Tunnels" value={rows.length} />
        <Stat label="Up" value={up} tone="good" />
        <Stat label="Down" value={down} tone={down > 0 ? "bad" : ""} />
        <Stat label="IPsec / GRE" value={`${ipsec} / ${gre}`} />
      </StatStrip>
      <Panel
        title="Tunnels — current state"
        action={<a href="#/infrastructure/tunnels" style={{ color: "var(--accent)", fontWeight: 600, fontSize: 12 }}>Full tunnels view →</a>}
      >
        <DataTable<Tunnel>
          rows={rows}
          columns={cols}
          rowKey={(t) => t.id}
          height={Math.min(360, 44 + rows.length * 30)}
          ariaLabel="Tunnels current state"
          initialSort={{ key: "status", dir: "asc" }}
        />
      </Panel>
    </>
  );
}

// Fleet packet-mix union (sum across fleet), tagged by kind for the legend.
function fleetPacketMix(dir: "in" | "out"): string {
  return [
    `label_replace(sum(rate(device_if_${dir}_ucast_pkts[5m])),"kind","unicast","","")`,
    `label_replace(sum(rate(device_if_${dir}_mcast_pkts[5m])),"kind","multicast","","")`,
    `label_replace(sum(rate(device_if_${dir}_bcast_pkts[5m])),"kind","broadcast","","")`,
  ].join(" or ");
}

export default function DeviceMonitoring({ rangeMinutes = 60 }: { rangeMinutes?: number } = {}) {
  const m = rangeMinutes;
  return (
    <div className="dm-board">
      <Group title="Fleet pulse & reachability" hue="#22C55E">
        <FleetPulse />
      </Group>

      <Group title="Fleet aggregates" hue="#3B82F6">
        <div className="dm-grid">
          <MetricLine title="Fleet total throughput (bps)" query="sum(rate(device_if_in_octets[5m]) * 8) + sum(rate(device_if_out_octets[5m]) * 8)" minutes={m} fmtY={fmtBps} />
          <MetricLine title="Fleet errors + discards (/s)" query="sum(rate(device_if_in_errors[5m]) + rate(device_if_out_errors[5m]) + rate(device_if_in_discards[5m]) + rate(device_if_out_discards[5m]))" minutes={m} fmtY={(n) => `${n.toFixed(2)}/s`} />
        </div>
      </Group>

      <Group title="Device inventory & uptime" hue="#EAB308">
        <DeviceInventory />
        <div className="dm-grid">
          <UptimeList minutes={m} />
        </div>
      </Group>

      <Group title="Device resources — CPU & memory" hue="#F59E0B">
        <div className="dm-grid">
          <MetricLine title="Average CPU utilization (%)" query="avg(device_cpu_percent)" minutes={m} fmtY={fmtPct} />
          <MetricLine title="Average memory utilization (%)" query="avg(device_mem_percent)" minutes={m} fmtY={fmtPct} />
          <MetricTop title="Devices with highest CPU (%)" query="device_cpu_percent" minutes={m} fmtX={fmtPct} labelKeys={["device"]} />
          <MetricTop title="Devices with highest memory (%)" query="device_mem_percent" minutes={m} fmtX={fmtPct} labelKeys={["device"]} />
        </div>
      </Group>

      <Group title="Interfaces" hue="#0EA5E9">
        <div className="dm-grid">
          <MetricTop title="Busiest interfaces — inbound (bps)" query="topk(10, rate(device_if_in_octets[5m]) * 8)" minutes={m} fmtX={fmtBps} labelKeys={["device", "index"]} />
          <MetricTop title="Busiest interfaces — outbound (bps)" query="topk(10, rate(device_if_out_octets[5m]) * 8)" minutes={m} fmtX={fmtBps} labelKeys={["device", "index"]} />
          <MetricTop title="Interfaces with most errors (/s)" query="topk(10, rate(device_if_in_errors[5m]) + rate(device_if_out_errors[5m]))" minutes={m} fmtX={(n) => `${n.toFixed(2)}/s`} labelKeys={["device", "index"]} />
          <MetricTop title="Interfaces with most discards (/s)" query="topk(10, rate(device_if_in_discards[5m]) + rate(device_if_out_discards[5m]))" minutes={m} fmtX={(n) => `${n.toFixed(2)}/s`} labelKeys={["device", "index"]} />
          <MetricTop title="Interface flaps (24h)" query="topk(10, changes(device_if_oper_status[24h]))" minutes={m} fmtX={(n) => `${n.toFixed(0)}`} labelKeys={["device", "index"]} />
        </div>
      </Group>

      <Group title="Throughput & line speed" hue="#14B8A6">
        <div className="dm-grid">
          <MetricLine title="Device aggregate throughput (bps)" query="sum by (device) (rate(device_if_in_octets[5m]) * 8 + rate(device_if_out_octets[5m]) * 8)" minutes={m} fmtY={fmtBps} labelKeys={["device"]} />
          <MetricTop title="Highest inbound utilization (%)" query="topk(10, rate(device_if_in_octets[5m]) * 8 * 100 / device_if_speed)" minutes={m} fmtX={fmtPct} labelKeys={["device", "index"]} />
          <MetricTop title="Highest outbound utilization (%)" query="topk(10, rate(device_if_out_octets[5m]) * 8 * 100 / device_if_speed)" minutes={m} fmtX={fmtPct} labelKeys={["device", "index"]} />
        </div>
      </Group>

      <Group title="Packet mix (pkt/s)" hue="#D946EF">
        <div className="dm-grid">
          <MetricLine title="Fleet inbound — unicast / multicast / broadcast" query={fleetPacketMix("in")} minutes={m} fmtY={(n) => `${n.toFixed(0)}/s`} labelKeys={["kind"]} />
          <MetricLine title="Fleet outbound — unicast / multicast / broadcast" query={fleetPacketMix("out")} minutes={m} fmtY={(n) => `${n.toFixed(0)}/s`} labelKeys={["kind"]} />
        </div>
      </Group>

      <Group title="Traffic insights (NetFlow)" hue="#8B5CF6">
        <FlowInsights since={m * 60} />
        <p className="mini-meta" style={{ margin: 0 }}>
          Fleet traffic from flow records. Full filtering and per-dimension breakdowns are in the <a href="#/flows" style={{ color: "var(--accent)", fontWeight: 600 }}>Flows</a> dashboard.
        </p>
      </Group>

      <Group title="Network Path & synthetics" hue="#F97316" defaultOpen={false}>
        <Stub
          icon="topology"
          title="Path & synthetic monitoring"
          summary="Hop-by-hop path latency (Flow Trace / Network Path) and active ICMP/HTTP synthetic checks. Requires the active-probe pipeline (see Infrastructure → Flow Trace)."
          planned={["NetPath status, active paths, check interval", "ICMP / HTTP response-time runners", "Synthetic test status"]}
        />
      </Group>

      <Group title="VPN & overlay tunnels" hue="#A855F7">
        <TunnelOverlay />
        <p className="mini-meta" style={{ margin: 0 }}>
          Tunnel interfaces (IPsec / GRE / VTI) discovered via standard IF-MIB &amp; TUNNEL-MIB SNMP walks.
          Latency / loss / QoE populate when an SD-WAN controller or active-probe source reports them.
        </p>
      </Group>

      <Group title="Geographic map" hue="#0EA5E9" defaultOpen={false}>
        <Stub
          icon="explore"
          title="Device geomap"
          summary="Devices plotted by site/region with live health overlays — shared with Infrastructure → Device Geomap."
          planned={["Site/region placement from inventory metadata", "Reachability overlays per location"]}
        />
      </Group>
    </div>
  );
}
