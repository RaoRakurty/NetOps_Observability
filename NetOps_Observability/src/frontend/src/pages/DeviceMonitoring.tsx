import { useEffect, useMemo, useState } from "react";
import { api, Device, Alert } from "../services/api";
import { useShell } from "../context/shell";
import { StatStrip, Stat } from "../components/ui";
import DataTable, { Column } from "../components/DataTable";
import {
  Group, Panel, MetricLine, MetricTop, fmtBps, fmtPct, fmtUptime, latest, seriesLabel, useMetricRange,
} from "../components/board/panels";
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

      <Group title="Traffic insights (NetFlow)" hue="#8B5CF6" defaultOpen={false}>
        <Stub
          icon="flows"
          title="Traffic insights"
          summary="Flow-derived traffic for the fleet lives in the dedicated Flows dashboard, which has the full filter bar and per-dimension breakdowns."
          planned={["Embedded flow summary tiles (busiest talkers, top exporters)", "Deep-link each device into its flows"]}
        />
      </Group>

      <Group title="Network Path & synthetics" hue="#F97316" defaultOpen={false}>
        <Stub
          icon="topology"
          title="Path & synthetic monitoring"
          summary="Hop-by-hop path latency (Flow Trace / Network Path) and active ICMP/HTTP synthetic checks. Requires the active-probe pipeline (see Infrastructure → Flow Trace)."
          planned={["NetPath status, active paths, check interval", "ICMP / HTTP response-time runners", "Synthetic test status"]}
        />
      </Group>

      <Group title="IPsec VPN tunnels" hue="#A855F7" defaultOpen={false}>
        <Stub
          icon="stack"
          title="IPsec VPN tunnels (SNMP)"
          summary="Tunnel auth/crypto failures and per-tunnel throughput from vendor IPsec SNMP OIDs. Overlay/tunnel telemetry currently lives in the Tunnels view."
          planned={["IPsec auth & crypto failure counters (Cisco-style OIDs)", "Per-tunnel throughput", "Fold into the existing Tunnels overlay view"]}
        />
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
