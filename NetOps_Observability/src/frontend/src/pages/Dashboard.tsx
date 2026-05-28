import { useEffect, useRef, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api, Alert, MetricTile, getToken } from "../services/api";
import { chartBase, axisStyle, areaGradient, paletteColor } from "../theme/charts";
import { severityClass, severityColor, severityKey } from "../theme/severity";

// Operations Overview — a Datadog-style board: a clean flat background with
// many compact panels (KPIs, live throughput, traffic trend, top talkers,
// severity mix, active alerts) laid out in a responsive 12-column grid.
//
// Data paths:
//   1) REST on mount: metric tiles, alerts, and flow analytics.
//   2) WebSocket /api/events: live metric_update / alert / telemetry events.
// All styling is bundled CSS (no external CDN), so it renders offline.

const TRAFFIC_BUCKETS = 30;

type TopTalker = { src: string; dst: string; bytes_total: number };
type TsRow = { bucket: string; bytes_total: number };

export default function Dashboard() {
  const [metrics, setMetrics] = useState<MetricTile[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [traffic, setTraffic] = useState<number[]>(Array.from({ length: TRAFFIC_BUCKETS }, () => 0));
  const [top, setTop] = useState<TopTalker[]>([]);
  const [ts, setTs] = useState<TsRow[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  // ---- initial REST load --------------------------------------------------
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [m, a, t, series] = await Promise.all([
          api.metricTiles(),
          api.alerts(),
          api.topTalkers(3600, 6).catch(() => null),
          api.flowsTimeseries(3600, 60).catch(() => null),
        ]);
        if (!alive) return;
        setMetrics(m ?? []);
        setAlerts((a ?? []).slice(0, 12));
        setTop(((t?.data as TopTalker[]) ?? []).slice(0, 6));
        setTs((series?.data as TsRow[]) ?? []);
      } catch (e) {
        console.error("overview initial load failed", e);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  // ---- WebSocket live stream ----------------------------------------------
  useEffect(() => {
    const token = getToken();
    if (!token) return;
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${location.host}/api/events?token=${encodeURIComponent(token)}`);
    wsRef.current = ws;
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);
    ws.onmessage = (event) => {
      let msg: { type?: string; data?: any } = {};
      try {
        msg = JSON.parse(event.data);
      } catch {
        return;
      }
      switch (msg.type) {
        case "metric_update":
          setMetrics((prev) => {
            const tile = msg.data as MetricTile;
            const i = prev.findIndex((m) => m.title === tile.title);
            if (i < 0) return [...prev, tile];
            const next = prev.slice();
            next[i] = tile;
            return next;
          });
          break;
        case "alert":
          setAlerts((prev) => [msg.data as Alert, ...prev].slice(0, 12));
          break;
        case "telemetry":
          setTraffic((prev) => [...prev.slice(1), Number(msg.data?.value ?? 0)]);
          break;
      }
    };
    return () => {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    };
  }, []);

  // Group active alerts by severity for the donut.
  const sevCounts = alerts.reduce<Record<string, number>>((acc, a) => {
    const k = severityKey(a.severity);
    acc[k] = (acc[k] ?? 0) + 1;
    return acc;
  }, {});
  const sevData = Object.entries(sevCounts).map(([k, v]) => ({
    name: k,
    value: v,
    itemStyle: { color: severityColor(k) },
  }));

  return (
    <div className="ov">
      <div className="ov-head">
        <h1 className="ov-title">
          Operations Overview <span>real-time NOC</span>
        </h1>
        <div className="ov-actions">
          <span className={`live-pill ${connected ? "on" : "off"}`} title="WebSocket /api/events">
            <span className="d" />
            {connected ? "LIVE" : "OFFLINE"}
          </span>
          <button className="dash-btn" onClick={() => (location.hash = "#/search/logs")}>
            Search
          </button>
          <button className="dash-btn accent" onClick={() => (location.hash = "#/alerts/rules")}>
            + Rule
          </button>
        </div>
      </div>

      <div className="ov-grid">
        {/* KPI tiles */}
        {metrics.length === 0 && (
          <div className="panel col-12 panel-empty">Waiting for metrics…</div>
        )}
        {metrics.map((m) => (
          <div className="panel kpi-tile col-3" key={m.title}>
            <h3>{m.title}</h3>
            <div className="kpi-num">{m.value}</div>
            {m.trend && <div className={`kpi-trend ${trendClass(m.trend)}`}>{m.trend}</div>}
          </div>
        ))}

        {/* Live throughput (WebSocket telemetry) */}
        <div className="panel col-8">
          <h3>Live throughput · last {TRAFFIC_BUCKETS} ticks</h3>
          <ReactECharts
            style={{ height: 240 }}
            option={{
              ...chartBase,
              grid: { left: 44, right: 12, top: 16, bottom: 24 },
              tooltip: { ...chartBase.tooltip, trigger: "axis" },
              xAxis: { type: "category", show: false, data: traffic.map((_, i) => i) },
              yAxis: { type: "value", ...axisStyle },
              series: [
                {
                  type: "line",
                  smooth: true,
                  showSymbol: false,
                  lineStyle: { color: paletteColor(0), width: 2 },
                  itemStyle: { color: paletteColor(0) },
                  areaStyle: { color: areaGradient(0) },
                  data: traffic,
                },
              ],
            }}
          />
        </div>

        {/* Active-alert severity mix */}
        <div className="panel col-4">
          <h3>Alerts by severity</h3>
          {sevData.length === 0 ? (
            <div className="panel-empty">All clear</div>
          ) : (
            <ReactECharts
              style={{ height: 240 }}
              option={{
                ...chartBase,
                tooltip: { ...chartBase.tooltip, trigger: "item", formatter: "{b}: {c}" },
                legend: { ...chartBase.legend, bottom: 0 },
                series: [
                  {
                    type: "pie",
                    radius: ["55%", "75%"],
                    itemStyle: { borderColor: "#0c0e13", borderWidth: 2 },
                    label: { show: false },
                    data: sevData,
                  },
                ],
              }}
            />
          )}
        </div>

        {/* Traffic over time (flows) */}
        <div className="panel col-6">
          <h3>Traffic over time</h3>
          {ts.length === 0 ? (
            <div className="panel-empty">No flow data yet.</div>
          ) : (
            <ReactECharts
              style={{ height: 220 }}
              option={{
                ...chartBase,
                grid: { left: 56, right: 12, top: 16, bottom: 24 },
                tooltip: { ...chartBase.tooltip, trigger: "axis" },
                xAxis: { type: "time", ...axisStyle },
                yAxis: { type: "value", name: "bytes", ...axisStyle },
                series: [
                  {
                    type: "line",
                    smooth: true,
                    showSymbol: false,
                    lineStyle: { color: paletteColor(1), width: 2 },
                    itemStyle: { color: paletteColor(1) },
                    areaStyle: { color: areaGradient(1) },
                    data: ts.map((r) => [r.bucket, r.bytes_total]),
                  },
                ],
              }}
            />
          )}
        </div>

        {/* Top talkers (flows) */}
        <div className="panel col-6">
          <h3>Top talkers · last 1h</h3>
          {top.length === 0 ? (
            <div className="panel-empty">No flow data yet.</div>
          ) : (
            <table className="mini-table">
              <tbody>
                {top.map((r, i) => (
                  <tr key={i}>
                    <td className="mono">{r.src}</td>
                    <td className="mono">{r.dst}</td>
                    <td style={{ textAlign: "right" }}>{Number(r.bytes_total).toLocaleString()} B</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Active alerts */}
        <div className="panel col-12">
          <h3>Active alerts</h3>
          {alerts.length === 0 ? (
            <div className="panel-empty">All clear — no active alerts.</div>
          ) : (
            alerts.map((a, i) => (
              <div className="mini-row" key={a.id ?? i}>
                <span className={`badge ${severityClass(a.severity)}`}>{a.severity || "info"}</span>
                <div className="mini-body">
                  <div className="mini-title">{a.summary || (a as any).message || "(no summary)"}</div>
                  <div className="mini-meta">
                    {a.rule}
                    {a.device_id ? ` · ${a.device_id}` : ""}
                    {a.fired_at ? ` · ${new Date(a.fired_at).toLocaleString()}` : ""}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function trendClass(trend?: string): string {
  const k = severityKey(trend);
  if (k === "critical" || k === "error") return "t-crit";
  if (k === "warning") return "t-warn";
  if (/clear|ok|live|up|healthy/i.test(trend ?? "")) return "t-ok";
  return "";
}
