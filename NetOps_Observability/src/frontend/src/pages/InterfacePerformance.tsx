import { useEffect, useMemo, useState } from "react";
import { api, Device } from "../services/api";
import {
  Group, MetricLine, MetricTop, fmtBps, fmtPct, labelSelector, useMetricRange,
} from "../components/board/panels";
import { Stub } from "./Placeholders";

// Interface Performance — per-device / per-interface deep dive (Datadog
// "Interface Performance" equivalent). Scoped by a device + interface picker;
// drillable from the Device Monitoring inventory row via
// #/infrastructure/ifperf/<deviceId>. Every panel is backed by SNMP interface
// metrics we already collect (device_if_* in VictoriaMetrics, labels device/index).

// Parse an optional device id from the hash 3rd path segment (drill-down).
function deviceFromHash(): string {
  const seg = (location.hash || "").replace(/^#\/?/, "").split("/")[2] || "";
  try { return decodeURIComponent(seg); } catch { return seg; }
}

export default function InterfacePerformance({ rangeMinutes = 60 }: { rangeMinutes?: number } = {}) {
  const m = rangeMinutes;
  const [devices, setDevices] = useState<Device[]>([]);
  const [device, setDevice] = useState<string>(() => deviceFromHash());
  const [iface, setIface] = useState<string>("");

  // Device list for the picker (label by name, value = the metric `device` label
  // which the collectors set to the device name).
  useEffect(() => {
    let alive = true;
    api.devices().then((d) => { if (alive) setDevices(d ?? []); }).catch(() => {});
    return () => { alive = false; };
  }, []);

  // React to drill-down hash changes (e.g. arriving from Device Monitoring).
  useEffect(() => {
    const onHash = () => { setDevice(deviceFromHash()); setIface(""); };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Interface options for the chosen device, discovered from the metric labels.
  const ifaceQuery = device ? `device_if_oper_status${labelSelector({ device })}` : "";
  const { series: ifaceSeries } = useMetricRange(ifaceQuery || "vector(0)", m, 30);
  const ifaceOptions = useMemo(() => {
    if (!device) return [];
    const idx = new Set<string>();
    for (const s of ifaceSeries) if (s.metric?.index) idx.add(s.metric.index);
    return Array.from(idx).sort((a, b) => Number(a) - Number(b));
  }, [ifaceSeries, device]);

  // Selectors: device-scoped (for top-N across a device's interfaces) and the
  // fully-pinned scope (device + interface) for the focused timeseries.
  const devSel = labelSelector({ device });
  const sel = labelSelector({ device, index: iface });
  // Fleet-wide selector when no device chosen.
  const scopeNote = device ? (iface ? `${device} · if ${iface}` : device) : "all devices";

  return (
    <div className="dm-board">
      {/* Scope bar */}
      <div className="card dm-scopebar">
        <div className="dm-scope-fields">
          <label>
            <span>Device</span>
            <select value={device} onChange={(e) => { setDevice(e.target.value); setIface(""); }}>
              <option value="">All devices</option>
              {devices.map((d) => (
                <option key={d.id} value={d.name}>{d.name}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Interface</span>
            <select value={iface} onChange={(e) => setIface(e.target.value)} disabled={!device}>
              <option value="">All interfaces</option>
              {ifaceOptions.map((i) => (
                <option key={i} value={i}>ifIndex {i}</option>
              ))}
            </select>
          </label>
          {(device || iface) && (
            <button className="btn-ghost" onClick={() => { setDevice(""); setIface(""); }}>Clear</button>
          )}
          <span className="mini-meta" style={{ marginLeft: "auto" }}>Scope: {scopeNote}</span>
        </div>
      </div>

      <Group title="All interfaces — leaders" hue="#0EA5E9">
        <div className="dm-grid">
          <MetricTop title="Interfaces by inbound throughput" query={`topk(10, rate(device_if_in_octets${devSel}[5m]) * 8)`} minutes={m} fmtX={fmtBps} labelKeys={["device", "index"]} />
          <MetricTop title="Interfaces by outbound throughput" query={`topk(10, rate(device_if_out_octets${devSel}[5m]) * 8)`} minutes={m} fmtX={fmtBps} labelKeys={["device", "index"]} />
        </div>
      </Group>

      <Group title="Top flapping interfaces" hue="#EAB308">
        <MetricTop title="Interface state changes (24h)" query={`topk(15, changes(device_if_oper_status${devSel}[24h]))`} minutes={m} fmtX={(n) => `${n.toFixed(0)}`} labelKeys={["device", "index"]} />
      </Group>

      <Group title="Throughput & utilization" hue="#22C55E">
        <div className="dm-grid">
          <MetricLine title="Throughput — inbound (bits/s)" query={`rate(device_if_in_octets${sel}[5m]) * 8`} minutes={m} fmtY={fmtBps} labelKeys={["device", "index"]} />
          <MetricLine title="Throughput — outbound (bits/s)" query={`rate(device_if_out_octets${sel}[5m]) * 8`} minutes={m} fmtY={fmtBps} labelKeys={["device", "index"]} />
          <MetricLine title="Inbound utilization (%)" query={`rate(device_if_in_octets${sel}[5m]) * 8 * 100 / device_if_speed${sel}`} minutes={m} fmtY={fmtPct} labelKeys={["device", "index"]} />
          <MetricLine title="Outbound utilization (%)" query={`rate(device_if_out_octets${sel}[5m]) * 8 * 100 / device_if_speed${sel}`} minutes={m} fmtY={fmtPct} labelKeys={["device", "index"]} />
        </div>
      </Group>

      <Group title="Errors & discards" hue="#EF4444">
        <div className="dm-grid">
          <MetricTop title="Interfaces with most errors" query={`topk(10, rate(device_if_in_errors${devSel}[5m]) + rate(device_if_out_errors${devSel}[5m]))`} minutes={m} fmtX={(n) => `${n.toFixed(2)}/s`} labelKeys={["device", "index"]} />
          <MetricTop title="Interfaces with most discards" query={`topk(10, rate(device_if_in_discards${devSel}[5m]) + rate(device_if_out_discards${devSel}[5m]))`} minutes={m} fmtX={(n) => `${n.toFixed(2)}/s`} labelKeys={["device", "index"]} />
          <MetricLine title="Errors — inbound vs outbound (/s)" query={`label_replace(sum(rate(device_if_in_errors${sel}[5m])),"dir","inbound","","") or label_replace(sum(rate(device_if_out_errors${sel}[5m])),"dir","outbound","","")`} minutes={m} fmtY={(n) => `${n.toFixed(2)}/s`} labelKeys={["dir"]} />
          <MetricLine title="Discards — inbound vs outbound (/s)" query={`label_replace(sum(rate(device_if_in_discards${sel}[5m])),"dir","inbound","","") or label_replace(sum(rate(device_if_out_discards${sel}[5m])),"dir","outbound","","")`} minutes={m} fmtY={(n) => `${n.toFixed(2)}/s`} labelKeys={["dir"]} />
        </div>
      </Group>

      <Group title="Packet mix (pkt/s)" hue="#8B5CF6">
        <div className="dm-grid">
          <MetricLine title="Inbound — unicast / multicast / broadcast" query={packetMixQuery(sel, "in")} minutes={m} fmtY={(n) => `${n.toFixed(0)}/s`} labelKeys={["kind"]} />
          <MetricLine title="Outbound — unicast / multicast / broadcast" query={packetMixQuery(sel, "out")} minutes={m} fmtY={(n) => `${n.toFixed(0)}/s`} labelKeys={["kind"]} />
        </div>
      </Group>

      <Group title="Oper & admin status" hue="#F59E0B">
        <OperAdminLegend />
        <div className="dm-grid">
          <MetricLine title="ifOperStatus over time" query={`device_if_oper_status${sel}`} minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "index"]} stepped />
          <MetricLine title="ifAdminStatus over time" query={`device_if_admin_status${sel}`} minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "index"]} stepped />
        </div>
      </Group>

      <Group title="NetFlow traffic" hue="#A855F7" defaultOpen={false}>
        <Stub
          icon="flows"
          title="Per-interface flows"
          summary="Flow-level talkers and conversations for this interface live in the dedicated Flows dashboard, which filters by device and ingress/egress interface and has the full breakdown."
          planned={[
            "Inline flow tiles filtered to this device + interface (in_if/out_if)",
            "Deep-link this interface into the Flows board with the filter pre-set",
          ]}
        />
      </Group>
    </div>
  );
}

// packetMixQuery builds a 3-series (unicast/multicast/broadcast) union for a
// direction, tagged via label_replace so the chart legend reads cleanly.
function packetMixQuery(sel: string, dir: "in" | "out"): string {
  const u = `device_if_${dir}_ucast_pkts${sel}`;
  const mc = `device_if_${dir}_mcast_pkts${sel}`;
  const b = `device_if_${dir}_bcast_pkts${sel}`;
  return [
    `label_replace(sum(rate(${u}[5m])),"kind","unicast","","")`,
    `label_replace(sum(rate(${mc}[5m])),"kind","multicast","","")`,
    `label_replace(sum(rate(${b}[5m])),"kind","broadcast","","")`,
  ].join(" or ");
}

// Small legend mapping the numeric ifOper/ifAdminStatus values (IF-MIB).
function OperAdminLegend() {
  return (
    <p className="mini-meta" style={{ margin: 0 }}>
      <strong>ifOperStatus</strong>: 1 up · 2 down · 3 testing · 4 unknown · 5 dormant · 6 notPresent · 7 lowerLayerDown ·{" "}
      <strong>ifAdminStatus</strong>: 1 up · 2 down · 3 testing
    </p>
  );
}
