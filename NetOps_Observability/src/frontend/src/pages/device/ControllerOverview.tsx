// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ControllerOverview — what a controller integration reports about one device,
// on the device page (owner 2026-10-19: devices known only through a
// controller's API must show its data). Today: Catalyst SD-WAN Manager
// (vManage); the other controllers plug in as their metrics land.
//
// LOOKBACK. vManage publishes its statistics 30–60 minutes late (the
// connector reads closed 10-minute buckets behind a settle window), so "the
// last 5 minutes" is always empty for it. Every figure here reads the latest
// value within the last 3 hours and the panel says how late the data is.
//
// The series are labelled device=<this device's id> by the controller→
// inventory join at ingest, so the same tenant metric scope that guards every
// other device panel applies unchanged.

import { MetricLine, MetricStat, labelSelector, fmtBps, fmtPct } from "../../components/board/panels";
import type { Device } from "../../services/api";

export type ControllerInfo = { system: string; label: string };

const CONTROLLER_LABEL: Record<string, string> = {
  vmanage: "vManage",
};

/** The controller this device is reported by, or null. A device is
 *  controller-reported when it was discovered through an integration's API
 *  (source "api") or carries a controller's key (an SNMP twin merged with it). */
export function controllerOf(d: Pick<Device, "source" | "labels">): ControllerInfo | null {
  const system = (d.labels?.source_system || "").trim().toLowerCase();
  if (!system) return null;
  return { system, label: CONTROLLER_LABEL[system] ?? system };
}

/** True when ONLY a controller reports this device (no direct collection). */
export function controllerOnly(d: Pick<Device, "source">): boolean {
  return d.source === "api";
}

const LOOKBACK = "3h";
const int = (n: number) => String(Math.round(n));

export default function ControllerOverview({ device, info }: { device: Device; info: ControllerInfo }) {
  const sel = labelSelector({ device: device.id });
  const last = (metric: string) => `last_over_time(${metric}${sel}[${LOOKBACK}])`;
  return (
    <section className="ddp-ctl" aria-label={`From ${info.label}`}>
      <div className="ddp-ctl-head">
        <h3>From {info.label}</h3>
        <span className="adm-line">{info.label} publishes these 30–60 minutes late.</span>
      </div>
      <div className="ddp-kpis">
        <MetricStat label="CPU" query={`max(${last("controller_metric_device_cpu_pct")})`} minutes={60} fmt={fmtPct} tone={(n) => (n >= 90 ? "bad" : n >= 75 ? "warn" : "")} />
        <MetricStat label="Memory" query={`max(${last("controller_metric_device_mem_pct")})`} minutes={60} fmt={fmtPct} tone={(n) => (n >= 90 ? "bad" : n >= 80 ? "warn" : "")} />
        <MetricStat label="Disk" query={`max(${last("controller_metric_device_disk_pct")})`} minutes={60} fmt={fmtPct} tone={(n) => (n >= 90 ? "bad" : "")} />
        <MetricStat label="Control connections" query={`max(${last("controller_metric_device_control_connections")})`} minutes={60} fmt={int} />
        <MetricStat label="BFD sessions up" query={`max(${last("controller_metric_device_bfd_sessions_up")})`} minutes={60} fmt={int} />
        <MetricStat label="BFD sessions down" query={`max(${last("controller_metric_device_bfd_sessions_down")})`} minutes={60} fmt={int} tone={(n) => (n > 0 ? "warn" : "")} />
        <MetricStat label="Tunnels" query={`count(${last("controller_metric_tunnel_loss_pct")}) or vector(0)`} minutes={60} fmt={int} />
        <MetricStat label="Worst tunnel loss" query={`max(${last("controller_metric_tunnel_loss_pct")})`} minutes={60} fmt={fmtPct} tone={(n) => (n >= 5 ? "bad" : n >= 1 ? "warn" : "")} />
      </div>
      <div className="ddp-grid2">
        <MetricLine title="CPU usage" query={`controller_metric_device_cpu_pct${sel}`} minutes={360} fmtY={fmtPct} height={220} />
        <MetricLine title="Tunnel loss" query={`controller_metric_tunnel_loss_pct${sel}`} minutes={360} fmtY={fmtPct} height={220} labelKeys={["tunnel"]} />
        <MetricLine title="Tunnel latency" query={`controller_metric_tunnel_latency_ms${sel}`} minutes={360} fmtY={(n) => `${Math.round(n)} ms`} height={220} labelKeys={["tunnel"]} />
        <MetricLine title="Interface traffic in" query={`sum by (interface) (controller_metric_interface_rx_bps${sel})`} minutes={360} fmtY={fmtBps} height={220} labelKeys={["interface"]} />
      </div>
    </section>
  );
}
