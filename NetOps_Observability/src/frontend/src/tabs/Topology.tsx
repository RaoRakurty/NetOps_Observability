import { useEffect, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api, Device } from "../services/api";

// Topology view — renders the device inventory as a force-directed
// graph. Edges aren't populated yet (the Device model doesn't carry
// neighbor data); when LLDP/CDP discovery lands, fill the `links`
// array below from `device.labels.peers` or similar.

export default function Topology() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.devices().then((d) => setDevices(d ?? [])).catch((e) => setError((e as Error).message));
  }, []);

  const nodes = devices.map((d) => ({
    id: d.id,
    name: d.name || d.id,
    symbolSize: 24,
    itemStyle: { color: colorForSource(d.source) },
    label: { show: true, color: "#e6e8eb" },
    category: d.source,
  }));

  // No edges yet — render a friendly empty graph if we have devices.
  const links: any[] = [];

  const categories = Array.from(new Set(devices.map((d) => d.source))).map((s) => ({ name: s }));

  return (
    <div className="card">
      <h2>Topology</h2>
      <p style={{ color: "var(--muted)", fontSize: 12, marginTop: 0 }}>
        Discovered devices rendered as a force-directed graph. Edges will appear once
        LLDP/CDP or BGP-LS discovery is implemented (see <code>src/backend/discovery.go</code>).
      </p>
      {error && <p style={{ color: "var(--bad)" }}>{error}</p>}
      {nodes.length === 0 ? (
        <div className="empty">No devices to plot yet — add some on the Devices tab.</div>
      ) : (
        <ReactECharts
          style={{ height: 600 }}
          option={{
            backgroundColor: "transparent",
            tooltip: {},
            legend: [{ data: categories.map((c) => c.name), textStyle: { color: "#8a93a0" } }],
            series: [
              {
                type: "graph",
                layout: "force",
                roam: true,
                draggable: true,
                force: { repulsion: 200, edgeLength: 100 },
                categories,
                data: nodes,
                links,
                edgeSymbol: ["none", "arrow"],
                lineStyle: { color: "#4f9eff", opacity: 0.6 },
              },
            ],
          }}
        />
      )}
    </div>
  );
}

function colorForSource(source: string): string {
  switch (source) {
    case "netbox":
      return "#4ad08b";
    case "snmp":
      return "#f5b04a";
    case "static":
      return "#4f9eff";
    case "manual":
      return "#b794f4";
    default:
      return "#8a93a0";
  }
}
