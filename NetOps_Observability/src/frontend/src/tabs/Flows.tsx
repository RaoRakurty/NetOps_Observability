import { useEffect, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api } from "../services/api";
import { chartBase, axisStyle, areaGradient, paletteColor } from "../theme/charts";

type TopTalkerRow = {
  src: string;
  dst: string;
  bytes_total: number;
  packets_total: number;
  flows: number;
};

type ProtoRow = {
  proto: number;
  bytes_total: number;
  packets_total: number;
  flows: number;
};

type TsRow = { bucket: string; bytes_total: number; packets_total: number };

type ByTypeRow = {
  flow_type: string;
  bytes_total: number;
  packets_total: number;
  flows: number;
  exporters: number;
};

// Source families the collector ingests (goflow2 → flow_type column).
const FLOW_TYPES: { value: string; label: string }[] = [
  { value: "", label: "All sources" },
  { value: "netflow", label: "NetFlow" },
  { value: "ipfix", label: "IPFIX" },
  { value: "sflow", label: "sFlow" },
];

const PROTO_NAMES: Record<number, string> = {
  1: "ICMP",
  6: "TCP",
  17: "UDP",
  47: "GRE",
  50: "ESP",
  89: "OSPF",
  132: "SCTP",
};

// sinceSeconds is supplied by the shell's global time range; when omitted
// the component manages its own range selector.
export default function Flows({ sinceSeconds }: { sinceSeconds?: number } = {}) {
  const [since, setSince] = useState(sinceSeconds ?? 3600);
  const [ftype, setFtype] = useState(""); // "" | netflow | ipfix | sflow
  const [top, setTop] = useState<TopTalkerRow[]>([]);
  const [byProto, setByProto] = useState<ProtoRow[]>([]);
  const [byType, setByType] = useState<ByTypeRow[]>([]);
  const [ts, setTs] = useState<TsRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (sinceSeconds !== undefined) setSince(sinceSeconds);
  }, [sinceSeconds]);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [a, b, c, d] = await Promise.all([
          api.topTalkers(since, 25, ftype),
          api.flowsByProto(since, ftype),
          api.flowsTimeseries(since, Math.max(60, Math.floor(since / 60)), ftype),
          api.flowsByType(since),
        ]);
        if (!alive) return;
        setTop((a?.data as TopTalkerRow[]) ?? []);
        setByProto((b?.data as ProtoRow[]) ?? []);
        setTs((c?.data as TsRow[]) ?? []);
        setByType((d?.data as ByTypeRow[]) ?? []);
        setError(null);
      } catch (e) {
        if (alive) setError((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [since, ftype]);

  return (
    <>
      <div className="card">
        <div className="admin-card-head">
          <h2>{(FLOW_TYPES.find((t) => t.value === ftype)?.label ?? "All sources")} · flow analytics</h2>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <select value={ftype} onChange={(e) => setFtype(e.target.value)} title="Flow source" style={{ width: 150 }}>
              {FLOW_TYPES.map((t) => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
            {sinceSeconds === undefined && (
              <select value={since} onChange={(e) => setSince(Number(e.target.value))} style={{ width: 170 }}>
                <option value={900}>Last 15 minutes</option>
                <option value={3600}>Last 1 hour</option>
                <option value={21600}>Last 6 hours</option>
                <option value={86400}>Last 24 hours</option>
              </select>
            )}
          </div>
        </div>
        <p className="mini-meta">
          Counts scaled by each device's sampling rate. Pick a source to view only NetFlow, IPFIX or sFlow — or click a chip below.
        </p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
          {byType.length === 0 ? (
            <span className="mini-meta">No flow data in this window.</span>
          ) : (
            byType.map((t) => (
              <button
                key={t.flow_type}
                type="button"
                onClick={() => setFtype(ftype === t.flow_type ? "" : t.flow_type)}
                className={`badge ${ftype === t.flow_type ? "good" : "accent-badge"}`}
                style={{ cursor: "pointer", border: "none" }}
                title={`${t.exporters} exporter(s) sending ${t.flow_type}`}
              >
                {String(t.flow_type).toUpperCase()}: {Number(t.flows).toLocaleString()} flows · {t.exporters} exporters
              </button>
            ))
          )}
        </div>
        {error && <p style={{ color: "var(--bad)", marginTop: 8 }}>{error}</p>}
      </div>

      <div className="card">
        <h2>Traffic over time</h2>
        {ts.length === 0 ? (
          <div className="empty">No flow data yet.</div>
        ) : (
          <ReactECharts
            style={{ height: 300 }}
            option={{
              ...chartBase,
              tooltip: { ...chartBase.tooltip, trigger: "axis" },
              legend: { ...chartBase.legend, data: ["Bytes", "Packets"], top: 0, right: 0 },
              grid: { left: 64, right: 64, top: 36, bottom: 28 },
              xAxis: { type: "time", ...axisStyle },
              yAxis: [
                { type: "value", name: "bytes", ...axisStyle },
                { type: "value", name: "packets", ...axisStyle, splitLine: { show: false } },
              ],
              series: [
                {
                  name: "Bytes",
                  type: "line",
                  showSymbol: false,
                  smooth: true,
                  lineStyle: { color: paletteColor(0), width: 2 },
                  itemStyle: { color: paletteColor(0) },
                  areaStyle: { color: areaGradient(0) },
                  data: ts.map((r) => [r.bucket, r.bytes_total]),
                },
                {
                  name: "Packets",
                  type: "line",
                  yAxisIndex: 1,
                  showSymbol: false,
                  smooth: true,
                  lineStyle: { color: paletteColor(1), width: 2 },
                  itemStyle: { color: paletteColor(1) },
                  data: ts.map((r) => [r.bucket, r.packets_total]),
                },
              ],
            }}
          />
        )}
      </div>

      <div className="card">
        <h2>Top talkers</h2>
        {top.length === 0 ? (
          <div className="empty">No flow data yet.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Destination</th>
                <th>Bytes</th>
                <th>Packets</th>
                <th>Flows</th>
              </tr>
            </thead>
            <tbody>
              {top.map((r, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: "ui-monospace, monospace" }}>{r.src}</td>
                  <td style={{ fontFamily: "ui-monospace, monospace" }}>{r.dst}</td>
                  <td>{Number(r.bytes_total).toLocaleString()}</td>
                  <td>{Number(r.packets_total).toLocaleString()}</td>
                  <td>{r.flows}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h2>By protocol</h2>
        {byProto.length === 0 ? (
          <div className="empty">No flow data yet.</div>
        ) : (
          <ReactECharts
            style={{ height: 280 }}
            option={{
              ...chartBase,
              tooltip: { ...chartBase.tooltip, trigger: "item", formatter: "{b}: {d}%" },
              legend: { ...chartBase.legend, bottom: 0 },
              series: [
                {
                  type: "pie",
                  radius: ["50%", "72%"],
                  itemStyle: { borderColor: "#ffffff", borderWidth: 2 },
                  label: { color: "#475467" },
                  data: byProto.map((p, i) => ({
                    name: PROTO_NAMES[p.proto] ?? `IP/${p.proto}`,
                    value: p.bytes_total,
                    itemStyle: { color: paletteColor(i) },
                  })),
                },
              ],
            }}
          />
        )}
      </div>
    </>
  );
}
