import { useEffect, useRef, useState } from "react";
import {
  api,
  Alert,
  MetricTile,
  getToken,
} from "../services/api";

// GlassyNetOpsDashboard — the main NOC view.
//
// Two data paths:
//
//   1) REST (initial render): /api/metrics + /api/alerts so the page is
//      useful immediately, before the socket connects.
//   2) WebSocket (live updates): /api/events streams three event types —
//      metric_update, alert, telemetry. The hub broadcasts to every
//      connected client every few seconds.
//
// The browser WebSocket API can't set an Authorization header, so we
// pass the JWT in a `?token=` query string. The Go auth middleware
// recognises that specifically for /api/events.

const TRAFFIC_BUCKETS = 24;

export default function Dashboard() {
  const [metrics, setMetrics] = useState<MetricTile[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [traffic, setTraffic] = useState<number[]>(
    Array.from({ length: TRAFFIC_BUCKETS }, () => 0),
  );
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  // ---- initial REST load --------------------------------------------------
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [m, a] = await Promise.all([api.metricTiles(), api.alerts()]);
        if (!alive) return;
        setMetrics(m ?? []);
        setAlerts((a ?? []).slice(0, 10));
      } catch (e) {
        console.error("dashboard initial load failed", e);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  // ---- WebSocket live stream ----------------------------------------------
  useEffect(() => {
    const token = getToken();
    if (!token) return; // auth gate will already be showing the login screen

    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${location.host}/api/events?token=${encodeURIComponent(token)}`;

    const ws = new WebSocket(url);
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
          // Upsert by title.
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
          setAlerts((prev) => [msg.data as Alert, ...prev].slice(0, 10));
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

  const maxTraffic = Math.max(1, ...traffic);

  return (
    <div className="min-h-[80vh] -m-6 rounded-3xl bg-[radial-gradient(circle_at_top_left,_#1e293b,_#020617_55%)] text-white overflow-hidden relative">
      {/* Ambient glow */}
      <div className="pointer-events-none absolute top-0 left-0 w-96 h-96 bg-cyan-500/20 blur-3xl rounded-full" />
      <div className="pointer-events-none absolute bottom-0 right-0 w-96 h-96 bg-fuchsia-500/20 blur-3xl rounded-full" />

      <div className="relative z-10 p-8">
        {/* Header */}
        <header className="flex items-start justify-between mb-10 gap-6 flex-wrap">
          <div>
            <h1 className="text-4xl md:text-5xl font-black tracking-tight bg-gradient-to-r from-cyan-300 via-white to-fuchsia-300 bg-clip-text text-transparent">
              CortexFlow Live
            </h1>
            <p className="text-slate-300 mt-2 text-base md:text-lg">
              Real-time NetOps · Streaming Telemetry · AI Correlation
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span
              className={[
                "inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs border",
                connected
                  ? "border-emerald-400/40 bg-emerald-400/10 text-emerald-300"
                  : "border-rose-400/40 bg-rose-400/10 text-rose-300",
              ].join(" ")}
              title="WebSocket /api/events"
            >
              <span
                className={[
                  "w-2 h-2 rounded-full",
                  connected ? "bg-emerald-400 animate-pulse" : "bg-rose-400",
                ].join(" ")}
              />
              {connected ? "LIVE" : "OFFLINE"}
            </span>
            <button
              className="px-4 py-2 rounded-2xl bg-white/10 border border-white/20 backdrop-blur-xl text-sm hover:bg-white/15 transition"
              onClick={() => (location.hash = "logs")}
            >
              Global Search
            </button>
            <button
              className="px-4 py-2 rounded-2xl bg-cyan-400/20 border border-cyan-300/30 backdrop-blur-xl text-sm hover:bg-cyan-400/30 transition"
              onClick={() => (location.hash = "rules")}
            >
              + Automation
            </button>
          </div>
        </header>

        {/* Metric tiles */}
        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6 mb-8">
          {metrics.length === 0 && (
            <div className="col-span-full text-slate-400 italic text-center py-8">
              Waiting for metrics…
            </div>
          )}
          {metrics.map((m) => (
            <div
              key={m.title}
              className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-2xl shadow-[0_4px_30px_rgba(0,0,0,0.2)]"
            >
              <p className="text-slate-300 text-xs uppercase tracking-wider">
                {m.title}
              </p>
              <div className="mt-4 flex justify-between items-end gap-3">
                <h2 className="text-4xl font-bold">{m.value}</h2>
                <span
                  className={[
                    "text-sm",
                    m.trend === "critical"
                      ? "text-rose-300"
                      : m.trend === "warning"
                      ? "text-amber-300"
                      : "text-cyan-300",
                  ].join(" ")}
                >
                  {m.trend}
                </span>
              </div>
            </div>
          ))}
        </section>

        {/* Live telemetry */}
        <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-2xl mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl md:text-2xl font-bold">
              Live Telemetry Stream
            </h3>
            <span className="text-xs text-slate-400">
              last {TRAFFIC_BUCKETS} ticks · pushed every 2s
            </span>
          </div>
          <div className="h-[220px] flex items-end gap-2">
            {traffic.map((h, i) => {
              const pct = Math.max(2, Math.round((h / maxTraffic) * 100));
              return (
                <div
                  key={i}
                  className="flex-1 bg-gradient-to-t from-cyan-500 to-fuchsia-400 rounded-t-xl transition-all"
                  style={{ height: `${pct}%` }}
                  title={`${h}`}
                />
              );
            })}
          </div>
        </div>

        {/* Live alerts */}
        <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-2xl">
          <h3 className="text-xl md:text-2xl font-bold mb-4">Live Alerts</h3>
          {alerts.length === 0 ? (
            <div className="text-slate-400 italic py-4">
              All clear — no active alerts.
            </div>
          ) : (
            <div className="space-y-3">
              {alerts.map((a, i) => (
                <div
                  key={a.id ?? i}
                  className="p-4 rounded-2xl bg-black/30 border border-white/10 flex items-start gap-3"
                >
                  <span
                    className={[
                      "shrink-0 px-2 py-0.5 rounded-full text-[10px] uppercase tracking-wider",
                      sevClasses(a.severity),
                    ].join(" ")}
                  >
                    {a.severity || "info"}
                  </span>
                  <div className="flex-1">
                    <div className="text-sm">
                      {a.summary || (a as any).message || "(no summary)"}
                    </div>
                    <div className="text-xs text-slate-400 mt-1">
                      {a.rule}
                      {a.device_id ? ` · ${a.device_id}` : ""}
                      {a.fired_at ? ` · ${new Date(a.fired_at).toLocaleString()}` : ""}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function sevClasses(sev?: string): string {
  switch (sev) {
    case "critical":
      return "bg-rose-500/20 text-rose-200 border border-rose-400/30";
    case "warning":
      return "bg-amber-500/20 text-amber-200 border border-amber-400/30";
    default:
      return "bg-cyan-500/20 text-cyan-200 border border-cyan-400/30";
  }
}
