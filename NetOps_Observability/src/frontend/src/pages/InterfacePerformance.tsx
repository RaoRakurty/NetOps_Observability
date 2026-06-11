import { useEffect, useMemo, useState } from "react";
import { api, Device } from "../services/api";
import {
  Group, MetricLine, MetricTop, BarPanel, fmtBps, fmtPct, fmtBytes, labelSelector, useMetricRange,
} from "../components/board/panels";

// Interface Performance — per-device / per-interface deep dive.
// Scoped by a device + interface picker;
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
  // Flow filters key on the exporter IP (sampler_address) — resolve the device's
  // management address from inventory.
  const deviceAddr = devices.find((d) => d.name === device)?.address || "";

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
          <MetricLine title="Inbound utilization (%)" query={`rate(device_if_in_octets${sel}[5m]) * 8 * 100 / (device_if_speed${sel} * 1000000)`} minutes={m} fmtY={fmtPct} labelKeys={["device", "index"]} />
          <MetricLine title="Outbound utilization (%)" query={`rate(device_if_out_octets${sel}[5m]) * 8 * 100 / (device_if_speed${sel} * 1000000)`} minutes={m} fmtY={fmtPct} labelKeys={["device", "index"]} />
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

      <Group title="NetFlow traffic" hue="#A855F7" defaultOpen>
        <InterfaceFlows addr={deviceAddr} device={device} iface={iface} since={m * 60} />
      </Group>
    </div>
  );
}

// InterfaceFlows — top talkers split by direction: ingress (in_if) top sources,
// egress (out_if) top destinations. Filters key on the exporter IP + ifIndex.
// When NO device is selected (addr=""), it scopes fleet-wide so the section is
// useful by default instead of blank. Pure flow data (IPFIX/NetFlow), no new
// collection. Only devices that actually EXPORT flow records appear — so a
// selected non-exporting device gets an honest note, not the generic
// "turn on NetFlow" onboarding hint (flows ARE arriving, just not from it).
function InterfaceFlows({ addr, device, iface, since }: { addr: string; device: string; iface: string; since: number }) {
  const [ingress, setIngress] = useState<{ label: string; value: number }[]>([]);
  const [egress, setEgress] = useState<{ label: string; value: number }[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    const run = async () => {
      try {
        // Omit the device key entirely when no device is chosen → fleet-wide.
        const dev = addr ? { device: addr } : {};
        const inF = { ...dev, ...(iface ? { in_if: iface } : {}) };
        const outF = { ...dev, ...(iface ? { out_if: iface } : {}) };
        const [a, b] = await Promise.all([
          api.flowsTopN("src_addr", since, 10, "", inF),
          api.flowsTopN("dst_addr", since, 10, "", outF),
        ]);
        if (!alive) return;
        setIngress(((a?.data as any[]) ?? []).map((r) => ({ label: String(r.k), value: Number(r.bytes_total) })));
        setEgress(((b?.data as any[]) ?? []).map((r) => ({ label: String(r.k), value: Number(r.bytes_total) })));
        setErr(null);
      } catch (e) { if (alive) setErr((e as Error).message); }
      finally { if (alive) setLoading(false); }
    };
    setLoading(true);
    run();
    const id = setInterval(run, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, [addr, iface, since]);

  const scope = addr ? "" : " (fleet-wide)";
  // A selected device with no flow records is almost always a non-exporter,
  // not a broken pipeline — say so honestly instead of the onboarding hint.
  const deviceHasNoFlows = !!addr && !loading && !err && ingress.length === 0 && egress.length === 0;
  return (
    <>
      <div className="dm-grid">
        <BarPanel title={`Top sources — ingress${scope}${iface ? ` (ifIndex ${iface})` : ""}`} rows={ingress} fmtX={fmtBytes} loading={loading} err={err} dataKind="flows" />
        <BarPanel title={`Top destinations — egress${scope}${iface ? ` (ifIndex ${iface})` : ""}`} rows={egress} fmtX={fmtBytes} loading={loading} err={err} dataKind="flows" />
      </div>
      {deviceHasNoFlows ? (
        <p className="mini-meta" style={{ margin: 0 }}>
          <b>{device}</b> isn’t exporting flow records (NetFlow/IPFIX/sFlow) in this window — only devices configured to
          export flows appear here. Configure flow export on the device, or clear the device filter to see fleet-wide traffic.
        </p>
      ) : (
        <p className="mini-meta" style={{ margin: 0 }}>
          {addr
            ? `Flows with ${device} as the exporter. Pick an interface above to scope to ingress/egress on that port.`
            : "Fleet-wide top talkers across all exporters. Select a device to scope to the flows it exports."}
        </p>
      )}
    </>
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
