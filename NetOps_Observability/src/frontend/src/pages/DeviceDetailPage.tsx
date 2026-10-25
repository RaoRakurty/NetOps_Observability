// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { deviceHealth, DEVICE_HEALTH_META } from "./device/deviceHealth";
import { fmtDateTime } from "../lib/time";
import { useState } from "react";
import { Device } from "../services/api";
import { MetricLine, MetricStat, labelSelector, fmtBps, fmtPct } from "../components/board/panels";
import InterfacePerformance from "./InterfacePerformance";
import DeviceNeighbors from "./DeviceNeighbors";
import DeviceConfigPanel from "./config/DeviceConfigPanel";
import DevicePcapPanel from "./capture/DevicePcapPanel";
import VrfInterfaces from "./device/VrfInterfaces";
import ControllerOverview, { controllerOf, controllerOnly } from "./device/ControllerOverview";
import { vrfTerm } from "../lib/vendorTerms";
import { deviceSerial } from "./device/serial";

// DeviceDetailPage — the full-page device drill-down (NetBox/Dynatrace-style):
// breadcrumb + identity header + a KPI strip, then tabs (Overview · Interfaces ·
// Neighbours). Every panel is backed by metrics/topology we already collect — no
// new backend. Opened full-screen from the Devices inventory (the old narrow
// inspector couldn't carry the graph rows the reference design needs).
//
// UI-words sweep 4 (tracker 270): tab labels are one word each and the KPI strip
// states the number without a caption. What a neighbour protocol reports is an
// authored file behind the `(i)` on the Neighbours panel, not a line here.

// Functional type → label + colour (mirrors the list page taxonomy).
const TYPE_META: Record<string, { label: string; color: string }> = {
  router: { label: "Router", color: "#3b82f6" }, switch: { label: "Switch", color: "#22c55e" },
  firewall: { label: "Firewall", color: "#ef4444" }, "load-balancer": { label: "Load balancer", color: "#a855f7" },
  ap: { label: "Access point", color: "#06b6d4" }, wlc: { label: "WLC", color: "#14b8a6" },
  "cloud-gw": { label: "Cloud GW", color: "#f59e0b" }, generic: { label: "Generic", color: "var(--muted)" },
};

type Tab = "overview" | "interfaces" | "vrf" | "routing" | "config" | "capture";

export default function DeviceDetailPage({ device, onClose }: { device: Device; onClose: () => void }) {
  const [tab, setTab] = useState<Tab>("overview");
  const d = device;
  const sel = labelSelector({ device: d.id });
  const seen = new Date(d.last_seen).getTime();
  const serial = deviceSerial(d);
  // The SAME status the inventory list shows (owner report 2026-10-10: the
  // popup used its own last_seen threshold and disagreed with the list).
  const h = deviceHealth(d, false);
  const hm = DEVICE_HEALTH_META[h];
  // Liveness = the collectors' own poll results (NETCONF excluded: it is a
  // config transport, not a poller that every device speaks).
  const reachSel = sel.replace(/}$/, ',collector!="netconf"}');
  const t = TYPE_META[d.type || "generic"] ?? TYPE_META.generic;
  // A device a controller reports (vManage today) gets that controller's view;
  // one known ONLY through the controller has no direct-collection figures to
  // show, so it gets the controller's view alone.
  const ctl = controllerOf(d);
  const apiOnly = !!ctl && controllerOnly(d);

  return (
    <div className="ddp-scrim" onClick={onClose}>
      <div className="ddp" onClick={(e) => e.stopPropagation()}>
        {/* Header — breadcrumb + identity + close */}
        <div className="ddp-head">
          <div className="ddp-crumb">Devices <span aria-hidden>›</span> {d.name || d.id}</div>
          <button className="ddp-x" onClick={onClose} aria-label="Close">×</button>
          <div className="ddp-title">
            <span className="ddp-typedot" style={{ background: t.color }} />
            <h2 className="device-name">{d.name || d.id}</h2>
            <span className="badge" style={{ background: hm.color, color: "#fff" }} title="Live status from the collectors' polls">
              {hm.arrow} {hm.label}
            </span>
          </div>
          <div className="ddp-sub">
            <span style={{ color: t.color, fontWeight: 500 }}>{t.label}</span>
            <span>·</span><span style={{ fontFamily: "var(--font-mono)" }}>{d.address}</span>
            {d.vendor && <><span>·</span><span style={{ textTransform: "capitalize" }}>{d.vendor}</span></>}
            {d.software_version && <><span>·</span><span style={{ fontFamily: "var(--font-mono)" }}>{d.software_version}</span></>}
            {serial && <><span>·</span><span title={serial.from}>Serial <span style={{ fontFamily: "var(--font-mono)" }}>{serial.serial}</span></span></>}
            <span>·</span><span title="When discovery last listed this device (not whether it answers)">last discovered {seen ? fmtDateTime(seen) : "—"}</span>
          </div>
        </div>

        {/* Tabs */}
        <div className="ddp-tabs" role="tablist">
          {([["overview", "Overview"], ["interfaces", "Interfaces"], ["vrf", `By ${vrfTerm(d.vendor)}`], ["routing", "Neighbors"], ["config", "Config"], ["capture", "Capture"]] as [Tab, string][]).map(([id, label]) => (
            <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? "on" : ""} onClick={() => setTab(id)}>{label}</button>
          ))}
        </div>

        <div className="ddp-body">
          {tab === "overview" && apiOnly && ctl && <ControllerOverview device={d} info={ctl} />}
          {tab === "overview" && !apiOnly && (
            <>
              <div className="ddp-kpis">
                <MetricStat label="Reachability (1h)" query={`100 * avg_over_time(min(collector_target_up${reachSel})[1h:1m])`} minutes={60} fmt={(v) => `${Math.round(v)}%`} tone={(n) => (n < 99 ? (n < 50 ? "bad" : "warn") : "good")} />
                <MetricStat label="Interfaces up" query={`count(device_if_oper_status${sel} == 1) or vector(0)`} minutes={60} fmt={(v) => String(Math.round(v))} />
                <MetricStat label="Interfaces down" query={`count(device_if_oper_status${sel} == 2) or vector(0)`} minutes={60} fmt={(v) => String(Math.round(v))} tone={(n) => (n > 0 ? "warn" : "")} />
                <MetricStat label="BGP peers" query={`count(device_bgp_peer_state${sel}) or vector(0)`} minutes={60} fmt={(v) => String(Math.round(v))} />
                <MetricStat label="BGP established" query={`count(device_bgp_peer_state${sel} == 6) or vector(0)`} minutes={60} fmt={(v) => String(Math.round(v))} />
                <MetricStat label="OSPF neighbors" query={`count(device_ospf_nbr_state${sel}) or vector(0)`} minutes={60} fmt={(v) => String(Math.round(v))} />
                <MetricStat label="OSPF full" query={`count(device_ospf_nbr_state${sel} == 8) or vector(0)`} minutes={60} fmt={(v) => String(Math.round(v))} />
                <MetricStat label="Traffic in" query={`sum(rate(device_if_in_octets${sel}[5m]) * 8) or vector(0)`} minutes={60} fmt={fmtBps} />
                <MetricStat label="Traffic out" query={`sum(rate(device_if_out_octets${sel}[5m]) * 8) or vector(0)`} minutes={60} fmt={fmtBps} />
              </div>
              <div className="ddp-grid2">
                <MetricLine title="CPU usage" query={`device_cpu_percent${sel}`} minutes={120} fmtY={fmtPct} height={220} />
                {/* Per memory pool. Vendors that report used/free bytes (Cisco
                    CISCO-MEMORY-POOL and others) get the percentage derived by
                    the collector; a platform with no memory source shows no data. */}
                <MetricLine title="Memory usage" query={`max by (index) (device_mem_percent${sel})`} minutes={120} fmtY={fmtPct} height={220} />
                <MetricLine title="Traffic in" query={`sum(rate(device_if_in_octets${sel}[5m]) * 8)`} minutes={120} fmtY={fmtBps} height={220} />
                <MetricLine title="Traffic out" query={`sum(rate(device_if_out_octets${sel}[5m]) * 8)`} minutes={120} fmtY={fmtBps} height={220} />
              </div>
              {ctl && <ControllerOverview device={d} info={ctl} />}
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
