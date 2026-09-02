import { fmtDateTime } from "../lib/time";
import { useState } from "react";
import { Device } from "../services/api";
import { MetricLine, MetricStat, labelSelector, fmtBps, fmtPct } from "../components/board/panels";
import InterfacePerformance from "./InterfacePerformance";
import DeviceNeighbors from "./DeviceNeighbors";
import DeviceConfigPanel from "./config/DeviceConfigPanel";
import DevicePcapPanel from "./capture/DevicePcapPanel";
import VrfInterfaces from "./device/VrfInterfaces";
import { vrfTerm } from "../lib/vendorTerms";

// DeviceDetailPage — the full-page device drill-down (NetBox/Dynatrace-style):
// breadcrumb + identity header + a KPI strip, then tabs (Overview · Interfaces ·
// Routing). Every panel is backed by metrics/topology we already collect — no new
// backend. Opened full-screen from the Devices inventory (the old narrow inspector
// couldn't carry the graph rows the reference design needs).

// Functional type → label + colour (mirrors the list page taxonomy).
const TYPE_META: Record<string, { label: string; color: string }> = {
  router: { label: "Router", color: "#3b82f6" }, switch: { label: "Switch", color: "#22c55e" },
  firewall: { label: "Firewall", color: "#ef4444" }, "load-balancer": { label: "Load balancer", color: "#a855f7" },
  ap: { label: "Access point", color: "#06b6d4" }, wlc: { label: "WLC", color: "#14b8a6" },
  "cloud-gw": { label: "Cloud GW", color: "#f59e0b" }, generic: { label: "Generic", color: "var(--muted)" },
};

const DOWN_AFTER_MS = 5 * 60 * 1000;

type Tab = "overview" | "interfaces" | "vrf" | "routing" | "config" | "capture";

export default function DeviceDetailPage({ device, onClose }: { device: Device; onClose: () => void }) {
  const [tab, setTab] = useState<Tab>("overview");
  const d = device;
  const sel = labelSelector({ device: d.id });
  const seen = new Date(d.last_seen).getTime();
  const down = !!seen && Date.now() - seen > DOWN_AFTER_MS;
  const t = TYPE_META[d.type || "generic"] ?? TYPE_META.generic;

  return (
    <div className="ddp-scrim" onClick={onClose}>
      <div className="ddp" onClick={(e) => e.stopPropagation()}>
        {/* Header — breadcrumb + identity + close */}
        <div className="ddp-head">
          <div className="ddp-crumb">Network devices <span aria-hidden>›</span> {d.name || d.id}</div>
          <button className="ddp-x" onClick={onClose} aria-label="Close">×</button>
          <div className="ddp-title">
            <span className="ddp-typedot" style={{ background: t.color }} />
            <h2 className="device-name">{d.name || d.id}</h2>
            <span className={`badge ${down ? "" : "good"}`} style={down ? { background: "var(--bad)", color: "#fff" } : undefined}>
              {down ? "Down" : "Up"}
            </span>
          </div>
          <div className="ddp-sub">
            <span style={{ color: t.color, fontWeight: 600 }}>{t.label}</span>
            <span>·</span><span style={{ fontFamily: "var(--font-mono)" }}>{d.address}</span>
            {d.vendor && <><span>·</span><span style={{ textTransform: "capitalize" }}>{d.vendor}</span></>}
            <span>·</span><span>last seen {seen ? fmtDateTime(seen) : "—"}</span>
          </div>
        </div>

        {/* Tabs */}
        <div className="ddp-tabs" role="tablist">
          {([["overview", "Overview"], ["interfaces", "Interfaces"], ["vrf", `By ${vrfTerm(d.vendor)}`], ["routing", "Routing & neighbors"], ["config", "Configuration"], ["capture", "Packet capture"]] as [Tab, string][]).map(([id, label]) => (
            <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? "on" : ""} onClick={() => setTab(id)}>{label}</button>
          ))}
        </div>

        <div className="ddp-body">
          {tab === "overview" && (
            <>
              <div className="ddp-kpis">
                <MetricStat label="Reachability" query={`${seen && !down ? "vector(100)" : "vector(0)"}`} minutes={60} fmt={(v) => `${v}%`} tone={() => (down ? "bad" : "good")} />
                <MetricStat label="Interfaces up" query={`count(device_if_oper_status${sel} == 1) or vector(0)`} minutes={60} fmt={(v) => String(Math.round(v))} />
                <MetricStat label="Interfaces down" query={`count(device_if_oper_status${sel} == 2) or vector(0)`} minutes={60} fmt={(v) => String(Math.round(v))} tone={(n) => (n > 0 ? "warn" : "")} />
                <MetricStat label="BGP peers established" query={`count(device_bgp_peer_state${sel} == 6) or vector(0)`} minutes={60} fmt={(v) => String(Math.round(v))} />
                <MetricStat label="Traffic in" query={`sum(rate(device_if_in_octets${sel}[5m]) * 8) or vector(0)`} minutes={60} fmt={fmtBps} />
                <MetricStat label="Traffic out" query={`sum(rate(device_if_out_octets${sel}[5m]) * 8) or vector(0)`} minutes={60} fmt={fmtBps} />
              </div>
              <div className="ddp-grid2">
                <MetricLine title="CPU usage" query={`device_cpu_percent${sel}`} minutes={120} fmtY={fmtPct} height={220} />
                <MetricLine title="Memory usage" query={`device_mem_percent${sel}`} minutes={120} fmtY={fmtPct} height={220} />
                <MetricLine title="Traffic in" query={`sum(rate(device_if_in_octets${sel}[5m]) * 8)`} minutes={120} fmtY={fmtBps} height={220} />
                <MetricLine title="Traffic out" query={`sum(rate(device_if_out_octets${sel}[5m]) * 8)`} minutes={120} fmtY={fmtBps} height={220} />
              </div>
            </>
          )}
          {tab === "interfaces" && <InterfacePerformance initialDevice={d.id} rangeMinutes={60} />}
          {/* Interfaces grouped by routing instance, in the DEVICE's own dialect
              (item 4). The tab label is the vendor's word — a Juniper operator
              reads "By routing-instance". The panel renders its own honest
              coverage strip: on a transport that does not collect the binding it
              says so instead of inventing a default group. */}
          {tab === "vrf" && <VrfInterfaces device={d} />}
          {tab === "routing" && <DeviceNeighbors device={d} />}
          {/* Configuration backup / golden baseline / drift (FEATURE_CONFIG_BACKUP).
              Renders its own "not enabled" card when the flag is off. */}
          {tab === "config" && <DeviceConfigPanel device={d} />}
          {/* On-demand, bounded packet capture (FEATURE_PACKET_CAPTURE).
              Renders its own "not enabled" card when the flag is off. */}
          {tab === "capture" && <DevicePcapPanel device={d} />}
        </div>
      </div>
    </div>
  );
}
