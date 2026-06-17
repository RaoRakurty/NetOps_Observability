import { useEffect, useState } from "react";
import { api, PathHealthItem } from "../services/api";

// Path Behavior Health UI (docs/design/path-behavior-health.md). NOC wording only —
// no "percentile distance" / "p99 normalization" jargon. Answers, per path: is it
// bad? compared to what? how confident? who likely owns the fix? what's the
// evidence? Reused by NetworkPath and the front-page Hot-paths panel.

const STATE_META: Record<string, { label: string; color: string }> = {
  healthy: { label: "Healthy", color: "#16A34A" },
  watch: { label: "Watch", color: "#D97706" },
  degraded: { label: "Degraded", color: "#EA580C" },
  severe: { label: "Severe", color: "#E11D48" },
};
const CONF_LABEL: Record<string, string> = {
  low: "Low", medium_low: "Medium-low", medium: "Medium", high: "High",
};
const FAULT_LABEL: Record<string, string> = {
  insufficient_evidence: "Insufficient evidence",
  customer_lan: "Customer LAN",
  branch_edge_sdwan: "Branch edge / SD-WAN",
  isp_carrier: "ISP / carrier",
  cloud_provider_edge: "Cloud provider edge",
  saas_provider: "SaaS provider",
};

function PathHealthCard({ p }: { p: PathHealthItem }) {
  const st = STATE_META[p.health_state] ?? STATE_META.healthy;
  const badge: React.CSSProperties = {
    fontSize: 11, fontWeight: 800, letterSpacing: 0.3, padding: "1px 7px", borderRadius: 4,
    color: "#fff", background: st.color, whiteSpace: "nowrap",
  };
  const muted: React.CSSProperties = { color: "var(--muted)" };
  const row = (k: string, v: React.ReactNode) => (
    <>
      <span style={muted}>{k}</span>
      <span style={{ color: "var(--fg)" }}>{v}</span>
    </>
  );
  return (
    <div style={{
      border: "1px solid var(--border)", borderLeft: `3px solid ${st.color}`, borderRadius: 8,
      padding: "10px 12px", background: "var(--panel)", minWidth: 0,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={badge}>{st.label}</span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, overflowWrap: "anywhere" }}>{p.dst}</span>
        <span style={{ ...muted, fontSize: 12 }}>· {p.agent}</span>
        <span style={{ marginLeft: "auto", fontSize: 12, ...muted }}>Confidence: <b style={{ color: "var(--fg)" }}>{CONF_LABEL[p.confidence] ?? p.confidence}</b></span>
      </div>
      <div style={{ fontSize: 13, marginTop: 6, color: "var(--fg)", lineHeight: 1.45 }}>{p.reason}</div>
      <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "2px 12px", fontSize: 12.5, marginTop: 7 }}>
        {row("Current latency", `${p.current.latency_p95_5m} ms (last 5 min)`)}
        {row("Typical", `~${p.baseline.latency_p50} ms`)}
        {row("Bad range", `≥ ${p.baseline.latency_p99} ms`)}
        {p.current.jitter_p95_5m > 0 && row("Current jitter", `${p.current.jitter_p95_5m} ms`)}
        {p.current.loss_pct_5m > 0 && row("Packet loss", `${p.current.loss_pct_5m}%`)}
        {row("Likely owner", FAULT_LABEL[p.likely_fault_domain] ?? p.likely_fault_domain)}
        {row("Compared with", p.baseline.source_label)}
      </div>
      {p.evidence && p.evidence.length > 0 && (
        <details style={{ marginTop: 7 }}>
          <summary style={{ cursor: "pointer", fontSize: 12, color: "var(--accent, #4c8dff)" }}>Evidence ({p.evidence.length})</summary>
          <ul style={{ margin: "4px 0 0", paddingLeft: 18, fontSize: 12.5, lineHeight: 1.5, color: "var(--fg)" }}>
            {p.evidence.map((e, i) => <li key={i}>{e}</li>)}
          </ul>
        </details>
      )}
    </div>
  );
}

export default function PathHealthList({ limit }: { limit?: number }) {
  const [paths, setPaths] = useState<PathHealthItem[]>([]);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await api.pathsHealth();
        if (alive) { setPaths(r.paths ?? []); setErr(""); }
      } catch (e: any) {
        if (alive) setErr(String(e?.message ?? e));
      } finally {
        if (alive) setLoading(false);
      }
    };
    tick();
    const id = setInterval(tick, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, []);
  const rows = limit ? paths.slice(0, limit) : paths;
  if (err) return <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>;
  if (loading && rows.length === 0) return <div className="empty">Loading…</div>;
  if (rows.length === 0) {
    return (
      <div className="empty">
        No active path measurements yet. Enable STAMP path SLA (<code>FEATURE_ACTIVE_PROBE</code> +
        <code> STAMP_TARGETS</code>) or synthetic checks to light up Path Behavior Health.
      </div>
    );
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {rows.map((p) => <PathHealthCard key={p.path_id} p={p} />)}
    </div>
  );
}
