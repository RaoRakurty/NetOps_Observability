import { ReactNode, useEffect, useState } from "react";
import { api, CorrObject, FeedItem } from "../services/api";
import { useShell } from "../context/shell";
import PathHealthList from "../components/PathHealthList";
import { signatureNocTitle, ownerLabel, OWNER_EXTERNAL } from "../components/rca/labels";

// FrontPage (#69) — triage-first landing: "is anything broken, who does it hurt,
// what changed, what do I do first?" Built on causal correlation objects + the
// scope health score; fully valuable with zero services configured. Every panel
// degrades to an honest INACTIVE/DEGRADED state — never a blank or raw error.

type Health = "ok" | "inactive" | "degraded";

function usePoll<T>(fn: () => Promise<T>, ms = 20000): { data: T | null; err: boolean; loading: boolean } {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState(false);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try { const r = await fn(); if (alive) { setData(r); setErr(false); } }
      catch { if (alive) setErr(true); }
      finally { if (alive) setLoading(false); }
    };
    tick();
    const id = setInterval(tick, ms);
    return () => { alive = false; clearInterval(id); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return { data, err, loading };
}

function Panel({ title, state = "ok", note, action, children }: {
  title: string; state?: Health; note?: string; action?: ReactNode; children?: ReactNode;
}) {
  return (
    <div className="panel" style={{ minWidth: 0, display: "flex", flexDirection: "column" }}>
      <div className="panel-tools">
        <h3 style={{ margin: 0 }}>{title}</h3>
        {state === "degraded" && <span className="badge sev-warning" style={{ marginLeft: 6 }}>degraded</span>}
        {state === "inactive" && <span className="badge" style={{ marginLeft: 6, opacity: 0.7 }}>inactive</span>}
        {action}
      </div>
      {state === "degraded" ? (
        <div className="empty" style={{ color: "var(--muted)" }}>{note || "This data source is temporarily unavailable — the rest of the page is unaffected."}</div>
      ) : state === "inactive" ? (
        <div className="empty" style={{ color: "var(--muted)" }}>{note}</div>
      ) : children}
    </div>
  );
}

const BAND_COLOR: Record<string, string> = {
  healthy: "#16A34A", watch: "#D97706", degraded: "#EA580C", critical: "#E11D48", insufficient_telemetry: "#8A93A6",
};
const CONF_LABEL: Record<string, string> = { low: "Low", medium_low: "Medium-low", medium: "Medium", high: "High" };

// ── Panel 1 — Health strip ─────────────────────────────────────────────────
function HealthStrip() {
  const { data, err } = usePoll(() => api.healthScore("global"));
  if (err) return <Panel title="Network health" state="degraded" />;
  if (!data) return <Panel title="Network health"><div className="empty">Loading…</div></Panel>;
  const insufficient = data.coverage_status === "INSUFFICIENT_TELEMETRY" || data.score == null;
  const color = BAND_COLOR[data.band] ?? "#8A93A6";
  return (
    <Panel title="Network health">
      <div style={{ display: "flex", gap: 18, alignItems: "center", flexWrap: "wrap" }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", minWidth: 110 }}>
          <div style={{ fontSize: 44, fontWeight: 800, color, lineHeight: 1 }}>{insufficient ? "—" : data.score}</div>
          <div style={{ fontSize: 12, fontWeight: 700, color, textTransform: "capitalize" }}>{insufficient ? "Insufficient telemetry" : data.band}</div>
        </div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 12.5, color: "var(--muted)" }}>
            Confidence: <b style={{ color: "var(--fg)" }}>{CONF_LABEL[data.confidence] ?? data.confidence}</b>
            {" · based on "}{data.signal_classes_live.length} signal {data.signal_classes_live.length === 1 ? "class" : "classes"}
            {data.stale_inputs.length > 0 ? ` · ${data.stale_inputs.length} stale` : ""}
          </div>
          {insufficient ? (
            <div style={{ fontSize: 12.5, marginTop: 4, color: "var(--muted)" }}>
              Not enough independent signals to score the network yet (live: {data.signal_classes_live.join(", ") || "none"}).
              Connect more telemetry — this is honest, not broken.
            </div>
          ) : (
            <ul style={{ margin: "4px 0 0", paddingLeft: 18, fontSize: 12.5, lineHeight: 1.5 }}>
              {data.contributions.slice(0, 3).map((c, i) => (
                <li key={i}><b>{c.points}</b> pts — {c.reason}</li>
              ))}
              {data.contributions.length === 0 && <li style={{ color: "var(--muted)", listStyle: "none", marginLeft: -18 }}>No degraded contributors — all measured signals nominal.</li>}
            </ul>
          )}
        </div>
      </div>
    </Panel>
  );
}

// ── Panels 2 + 3 — Top Active Issues / Recommended Action ───────────────────
const VERDICT_NOC: Record<string, string> = { confirmed: "Confirmed", suspected: "Suspected", undetermined: "Not confirmed" };
function trusted(o: CorrObject): boolean {
  return (o.grounding ?? "none") !== "none" && !o.low_authority && !o.debug_excluded && o.top_hypothesis !== "undetermined";
}
function TopIssues() {
  const { navigate } = useShell();
  const { data, err } = usePoll(() => api.correlations(50, 86400, "open"));
  const items = (data?.data ?? []).filter((o) => o.verdict_tier !== "undetermined").slice(0, 6);
  if (err) return <Panel title="Top active issues" state="degraded" note="Correlation engine unreachable — stack health." />;
  if (items.length === 0) return <Panel title="Top active issues" state="inactive" note="No active correlated issues. A good sign." />;
  return (
    <Panel title="Top active issues" action={<span style={{ marginLeft: "auto", fontSize: 12 }}><a href="#/monitoring/correlations">all →</a></span>}>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {items.map((o) => {
          const tone = o.verdict_tier === "confirmed" ? "#E11D48" : "#D97706";
          return (
            <div key={o.correlation_id} role="button" onClick={() => navigate("monitoring/correlations")}
              style={{ cursor: "pointer", border: "1px solid var(--border)", borderLeft: `3px solid ${tone}`, borderRadius: 6, padding: "6px 9px" }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <span style={{ fontSize: 10.5, fontWeight: 800, color: "#fff", background: tone, padding: "1px 6px", borderRadius: 4 }}>{VERDICT_NOC[o.verdict_tier] ?? o.verdict_tier}</span>
                <span style={{ fontWeight: 600, fontSize: 13 }}>{signatureNocTitle(o.top_hypothesis)}</span>
                {o.owner && <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--muted)" }}>{ownerLabel(o.owner)}</span>}
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}
function RecommendedAction() {
  const { data, err } = usePoll(() => api.correlations(50, 86400, "open"));
  if (err) return <Panel title="Recommended action" state="degraded" />;
  const objs = (data?.data ?? []);
  const top = objs.find((o) => o.verdict_tier === "confirmed" && trusted(o)) ?? objs.find((o) => trusted(o));
  if (!top) return <Panel title="Recommended action" state="inactive" note="No action suggested — no trusted issue above the confidence floor." />;
  const confirmed = top.verdict_tier === "confirmed";
  const ext = top.owner && OWNER_EXTERNAL.has(top.owner);
  const verb = confirmed ? "Escalate" : "Hold";
  const tone = confirmed ? "#E11D48" : "#B45309";
  const text = confirmed
    ? (ext ? `Escalate to ${ownerLabel(top.owner!)} — confirmed boundary issue.` : `Escalate to the network team — confirmed ${signatureNocTitle(top.top_hypothesis).replace(/^Possible /, "").toLowerCase()}.`)
    : `Do not escalate yet — ${signatureNocTitle(top.top_hypothesis).replace(/^Possible /, "")} suspected; gather a second independent source to confirm.`;
  return (
    <Panel title="Recommended action">
      <div style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
        <span style={{ fontSize: 11.5, fontWeight: 800, letterSpacing: 0.4, color: tone, textTransform: "uppercase" }}>{verb}</span>
        <span style={{ fontSize: 13, fontWeight: 600 }}>{text}</span>
      </div>
    </Panel>
  );
}

// ── Panel 5 — RCA coverage ──────────────────────────────────────────────────
function RcaCoverage() {
  const { data, err } = usePoll(() => api.correlationsStats());
  if (err) return <Panel title="RCA coverage" state="degraded" />;
  if (!data) return <Panel title="RCA coverage"><div className="empty">Loading…</div></Panel>;
  const stat = (label: string, value: ReactNode) => (
    <div style={{ flex: 1, minWidth: 88 }}>
      <div style={{ fontSize: 22, fontWeight: 700 }}>{value}</div>
      <div style={{ fontSize: 11.5, color: "var(--muted)" }}>{label}</div>
    </div>
  );
  return (
    <Panel title="RCA coverage">
      <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
        {stat("open issues", data.open)}
        {stat("actionable", `${Math.round(data.actionable_pct)}%`)}
        {stat(`confirmed (${data.window_days}d)`, `${Math.round(data.confirmed_7d_pct)}%`)}
        {stat("signatures", data.signatures_matched)}
      </div>
    </Panel>
  );
}

// ── Panel 4 — What changed ──────────────────────────────────────────────────
const SEV_COLOR: Record<string, string> = { crit: "#E11D48", high: "#EA580C", warn: "#D97706", info: "#6B7280" };
function WhatChanged() {
  const { data, err } = usePoll(() => api.eventsFeed({ from: "24h", class: "changes", limit: "12" }));
  if (err) return <Panel title="What changed" state="degraded" />;
  const items: FeedItem[] = data?.items ?? [];
  if (items.length === 0) return <Panel title="What changed" state="inactive" note="No topology / inventory / alert changes in the last 24h." />;
  return (
    <Panel title="What changed">
      <div style={{ display: "flex", flexDirection: "column", gap: 4, maxHeight: 260, overflowY: "auto" }}>
        {items.map((it) => (
          <div key={it.signal_id} style={{ display: "flex", gap: 8, fontSize: 12.5, alignItems: "baseline" }}>
            <span style={{ width: 7, height: 7, borderRadius: 2, background: SEV_COLOR[it.severity] ?? "#6B7280", flexShrink: 0, marginTop: 4 }} />
            <span style={{ color: "var(--fg)", minWidth: 0 }}>{it.title}</span>
            <span style={{ marginLeft: "auto", color: "var(--muted)", whiteSpace: "nowrap" }}>{it.ts.slice(11, 16)}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ── Panel 9 — Impact summary (compact; full map on Topology) ─────────────────
function ImpactSummary() {
  const { data, err } = usePoll(() => api.correlations(100, 86400, "open"));
  if (err) return <Panel title="Impact" state="degraded" />;
  const objs = (data?.data ?? []).filter((o) => o.verdict_tier !== "undetermined");
  const devices = new Set<string>(); const sites = new Set<string>();
  for (const o of objs) {
    try {
      const a = JSON.parse(o.affected || "{}");
      (a.devices ?? []).forEach((d: string) => devices.add(d));
      (a.sites ?? []).forEach((s: string) => sites.add(s));
    } catch { /* ignore */ }
  }
  if (objs.length === 0) return <Panel title="Impact" state="inactive" note="Nothing impacted — no active issues." />;
  return (
    <Panel title="Impact" action={<span style={{ marginLeft: "auto", fontSize: 12 }}><a href="#/infrastructure/topology">topology →</a></span>}>
      <div style={{ display: "flex", gap: 18, fontSize: 13 }}>
        <div><b style={{ fontSize: 22 }}>{devices.size || "—"}</b><div style={{ fontSize: 11.5, color: "var(--muted)" }}>devices in active issues</div></div>
        <div><b style={{ fontSize: 22 }}>{sites.size || "—"}</b><div style={{ fontSize: 11.5, color: "var(--muted)" }}>sites affected</div></div>
        <div><b style={{ fontSize: 22 }}>{objs.length}</b><div style={{ fontSize: 11.5, color: "var(--muted)" }}>open issues</div></div>
      </div>
    </Panel>
  );
}

// ── Panel 10 — Capacity outlook ─────────────────────────────────────────────
function CapacityOutlook() {
  const { data, err } = usePoll(() => api.metricsForecast());
  if (err) return <Panel title="Capacity outlook" state="degraded" />;
  const rows = data?.interfaces ?? [];
  if (rows.length === 0) return <Panel title="Capacity outlook" state="inactive" note="No interface utilization data yet." />;
  const trending = rows.filter((r) => r.status === "trending" || r.status === "saturated");
  if (trending.length === 0) {
    const building = rows.filter((r) => r.status === "building_baseline").length;
    return <Panel title="Capacity outlook" state="inactive"
      note={building > 0
        ? `Building baseline — needs ${data!.min_days} days of history (${building} interface${building === 1 ? "" : "s"} still learning).`
        : "No interfaces trending toward saturation — all stable."} />;
  }
  return (
    <Panel title="Capacity outlook">
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {trending.slice(0, 6).map((r, i) => {
          const soon = r.status === "saturated" || r.days_to_90 < 14;
          const tone = soon ? "#E11D48" : r.days_to_90 < 30 ? "#D97706" : "var(--fg)";
          return (
            <div key={i} style={{ display: "flex", gap: 8, fontSize: 12.5, alignItems: "baseline" }}>
              <span style={{ fontFamily: "ui-monospace,monospace" }}>{r.device}</span>
              <span style={{ color: "var(--muted)" }}>{r.interface}</span>
              <span style={{ marginLeft: "auto", fontWeight: 700, color: tone }}>
                {r.status === "saturated" ? "at capacity" : `~${Math.round(r.days_to_90)}d to 90%`}
              </span>
              <span style={{ color: "var(--muted)", fontSize: 11.5 }}>{Math.round(r.current_util_pct)}% now</span>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

export default function FrontPage() {
  return (
    <div className="dm-board" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <HealthStrip />
      <div className="fp-grid" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: 12 }}>
        <TopIssues />
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <RecommendedAction />
          <RcaCoverage />
        </div>
        <WhatChanged />
        <Panel title="Hot paths">
          <PathHealthList limit={5} />
        </Panel>
        <ImpactSummary />
        <CapacityOutlook />
      </div>
    </div>
  );
}
