import { useEffect, useRef, useState } from "react";

// tgen dashboard — IXIA/Ostinato-style live view of the traffic the generator
// is crafting: rates, per-protocol / per-mode / per-app breakdowns, and live
// start/stop + stream config. Talks to the Python control API (same origin).

type Stats = {
  totals: { flows: number; tx_bytes: number; rx_bytes: number; pkts: number };
  rates: { fps: number; bps: number };
  per_app: { app: string; flows: number }[];
  per_proto: { proto: string; flows: number }[];
  per_mode: { mode: string; flows: number }[];
  workers: { id: string; mode: string; flows: number }[];
  config: Config;
  ts: number;
};
type Config = {
  collector: string; modes: string[]; apps: string[];
  fps: number; batch: number; workers: number; running: boolean;
};

const fmtBps = (b: number) => {
  const u = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]; let i = 0; let v = b;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; } return `${v.toFixed(2)} ${u[i]}`;
};
const fmtBytes = (b: number) => {
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = b;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } return `${v.toFixed(1)} ${u[i]}`;
};
const fmtNum = (n: number) => n.toLocaleString();

const PROTO_COLOR: Record<string, string> = { tcp: "#4f46e5", udp: "#06b6d4", icmp: "#f59e0b" };
const MODE_COLOR: Record<string, string> = { ipfix: "#4f46e5", netflow9: "#10b981", sflow: "#ec4899" };
const ALL_MODES = ["ipfix", "netflow9", "sflow"];

function Spark({ data, color = "#4f46e5" }: { data: number[]; color?: string }) {
  const w = 240, h = 48, max = Math.max(1, ...data);
  const pts = data.map((v, i) => `${(i / Math.max(1, data.length - 1)) * w},${h - (v / max) * (h - 4) - 2}`).join(" ");
  return (
    <svg width={w} height={h} className="spark">
      <polyline points={pts} fill="none" stroke={color} strokeWidth={2} />
    </svg>
  );
}

function Bars({ rows, total, colorOf }: { rows: { k: string; v: number }[]; total: number; colorOf: (k: string) => string }) {
  return (
    <div className="bars">
      {rows.map((r) => (
        <div className="bar-row" key={r.k}>
          <span className="bar-k">{r.k}</span>
          <div className="bar-track"><div className="bar-fill" style={{ width: `${total ? (r.v / total) * 100 : 0}%`, background: colorOf(r.k) }} /></div>
          <span className="bar-v">{fmtNum(r.v)}</span>
        </div>
      ))}
    </div>
  );
}

export default function App() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [hist, setHist] = useState<number[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [draft, setDraft] = useState<Partial<Config>>({});
  const catRef = useRef<{ name: string; category: string }[]>([]);

  useEffect(() => {
    fetch("api/catalog").then((r) => r.json()).then((c) => { catRef.current = c; }).catch(() => {});
  }, []);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const s: Stats = await (await fetch("api/stats")).json();
        if (!alive) return;
        setStats(s); setErr(null);
        setHist((h) => [...h.slice(-59), s.rates.fps]);
      } catch (e) { if (alive) setErr(String(e)); }
    };
    tick(); const id = setInterval(tick, 1500);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const cfg = stats?.config;
  const cur = (k: keyof Config) => (draft[k] !== undefined ? (draft as any)[k] : (cfg as any)?.[k]);
  const post = (action: string) =>
    fetch("api/control", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, config: draft }) }).then((r) => r.json()).then(() => setDraft({}));

  const catOf = (app: string) => catRef.current.find((c) => c.name === app)?.category ?? "";
  const totalFlows = stats?.totals.flows ?? 0;

  return (
    <div className="app">
      <header className="hdr">
        <div className="brand"><span className="dot" /> tgen <span className="sub">traffic generator</span></div>
        <div className="status">
          {cfg?.running ? <span className="pill on">● generating</span> : <span className="pill off">○ stopped</span>}
          <span className="collector">→ {cfg?.collector}</span>
        </div>
      </header>

      {err && <div className="err">control API unreachable: {err}</div>}

      {/* KPI strip */}
      <div className="kpis">
        <Kpi label="Flow rate" value={`${fmtNum(stats?.rates.fps ?? 0)} fps`} accent />
        <Kpi label="Bit rate" value={fmtBps(stats?.rates.bps ?? 0)} accent />
        <Kpi label="Total flows" value={fmtNum(totalFlows)} />
        <Kpi label="TX" value={fmtBytes(stats?.totals.tx_bytes ?? 0)} />
        <Kpi label="RX" value={fmtBytes(stats?.totals.rx_bytes ?? 0)} />
        <Kpi label="Packets" value={fmtNum(stats?.totals.pkts ?? 0)} />
      </div>

      <div className="grid">
        {/* Controls */}
        <section className="card">
          <h3>Streams</h3>
          <label className="fld">Protocols
            <div className="chips">
              {ALL_MODES.map((m) => {
                const on = (cur("modes") as string[] ?? []).includes(m);
                return <button key={m} className={`chip ${on ? "on" : ""}`} style={on ? { borderColor: MODE_COLOR[m], color: MODE_COLOR[m] } : {}}
                  onClick={() => { const set = new Set(cur("modes") as string[] ?? []); on ? set.delete(m) : set.add(m); setDraft({ ...draft, modes: [...set] }); }}>{m}</button>;
              })}
            </div>
          </label>
          <label className="fld">Apps / categories (comma; blank = all)
            <input value={(cur("apps") as string[] ?? []).join(",")} placeholder="AI, Collaboration, Salesforce…"
              onChange={(e) => setDraft({ ...draft, apps: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} />
          </label>
          <div className="row2">
            <label className="fld">Flow rate (fps)
              <input type="number" value={cur("fps") ?? 1500} onChange={(e) => setDraft({ ...draft, fps: +e.target.value })} /></label>
            <label className="fld">Workers
              <input type="number" value={cur("workers") ?? 2} onChange={(e) => setDraft({ ...draft, workers: +e.target.value })} /></label>
          </div>
          <div className="actions">
            <button className="btn primary" onClick={() => post(cfg?.running ? "update" : "start")}>{cfg?.running ? "Apply" : "Start"}</button>
            <button className="btn" onClick={() => post("stop")} disabled={!cfg?.running}>Stop</button>
          </div>
        </section>

        {/* Rate sparkline */}
        <section className="card">
          <h3>Flow rate</h3>
          <div className="big">{fmtNum(stats?.rates.fps ?? 0)} <span className="unit">fps</span></div>
          <Spark data={hist} />
          <div className="muted">{fmtBps(stats?.rates.bps ?? 0)} aggregate</div>
        </section>

        {/* Protocol breakdown */}
        <section className="card">
          <h3>By protocol</h3>
          <Bars rows={(stats?.per_proto ?? []).map((p) => ({ k: p.proto, v: p.flows }))} total={totalFlows}
            colorOf={(k) => PROTO_COLOR[k] ?? "#94a3b8"} />
          <h3 style={{ marginTop: 14 }}>By encoder</h3>
          <Bars rows={(stats?.per_mode ?? []).map((p) => ({ k: p.mode, v: p.flows }))} total={totalFlows}
            colorOf={(k) => MODE_COLOR[k] ?? "#94a3b8"} />
        </section>

        {/* Top apps */}
        <section className="card span2">
          <h3>Top applications</h3>
          <table className="apps">
            <thead><tr><th>Application</th><th>Category</th><th>Flows</th><th>Share</th></tr></thead>
            <tbody>
              {(stats?.per_app ?? []).map((a) => (
                <tr key={a.app}>
                  <td className="mono">{a.app}</td>
                  <td><span className="cat">{catOf(a.app)}</span></td>
                  <td className="num">{fmtNum(a.flows)}</td>
                  <td><div className="bar-track sm"><div className="bar-fill" style={{ width: `${totalFlows ? (a.flows / totalFlows) * 100 : 0}%`, background: "#4f46e5" }} /></div></td>
                </tr>
              ))}
              {!stats?.per_app.length && <tr><td colSpan={4} className="muted">No traffic yet — press Start.</td></tr>}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  );
}

function Kpi({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return <div className={`kpi ${accent ? "accent" : ""}`}><div className="kpi-v">{value}</div><div className="kpi-l">{label}</div></div>;
}
