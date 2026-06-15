import { Component, ReactNode, useEffect, useState } from "react";
import { api, CorrObject, FeedItem } from "../services/api";
import { useShell } from "../context/shell";
import PathHealthList from "../components/PathHealthList";
import { signatureNocTitle, ownerLabel, OWNER_EXTERNAL, isInternalStackAffected } from "../components/rca/labels";

// FrontPage (#69) — the Operations Overview: an instrument-grade NOC console
// answering "is anything broken, who does it hurt, what changed, what do I do
// first?" Built on causal correlation objects + the scope health score. Every
// panel degrades to a deliberate INACTIVE/DEGRADED reading (honesty rule: never
// fake data, and a sparse environment must still look intentional). Visual spec:
// docs/design/front-page.md + the .fp-* chrome in styles.css.

// severity / band → semantic CSS var (theme-safe; never hardcode hex here).
const BAND_VAR: Record<string, string> = {
  healthy: "var(--ok)", watch: "var(--warn)", degraded: "var(--crit)",
  critical: "var(--crit)", insufficient_telemetry: "var(--fg-subtle)",
};
const VERDICT_VAR: Record<string, string> = { confirmed: "var(--crit)", suspected: "var(--warn)", undetermined: "var(--fg-subtle)" };
const VERDICT_NOC: Record<string, string> = { confirmed: "Confirmed", suspected: "Suspected", undetermined: "Not confirmed" };
const SEV_VAR: Record<string, string> = { crit: "var(--crit)", high: "var(--crit)", warn: "var(--warn)", info: "var(--fg-subtle)" };
const CONF_LABEL: Record<string, string> = { low: "Low", medium_low: "Medium-low", medium: "Medium", high: "High" };

type PanelState = "ok" | "inactive" | "degraded";

function usePoll<T>(fn: () => Promise<T>, ms = 20000): { data: T | null; err: boolean } {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState(false);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try { const r = await fn(); if (alive) { setData(r); setErr(false); } }
      catch { if (alive) setErr(true); }
    };
    tick();
    const id = setInterval(tick, ms);
    return () => { alive = false; clearInterval(id); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return { data, err };
}

// A deliberate instrument reading — never an alarming "error" look.
function EmptyReading({ t, h }: { t: string; h?: string }) {
  return (
    <div className="fp-empty">
      <span className="fp-empty-mark" />
      <div className="fp-empty-t">{t}</div>
      {h && <div className="fp-empty-h">{h}</div>}
    </div>
  );
}

function Panel({ title, action, state = "ok", note, hint, children }: {
  title: string; action?: ReactNode; state?: PanelState; note?: string; hint?: string; children?: ReactNode;
}) {
  return (
    <div className="fp-panel">
      <div className="fp-panel-h">
        <h3 className="fp-panel-t">{title}</h3>
        {state === "degraded" && <span className="fp-tag" style={{ color: "var(--warn)", border: "1px solid var(--warn)" }}>degraded</span>}
        {action && <span className="fp-panel-meta">{action}</span>}
      </div>
      <div className="fp-panel-b">
        {state === "degraded"
          ? <EmptyReading t={note || "This source is temporarily unavailable."} h="The rest of the page is unaffected." />
          : state === "inactive"
            ? <EmptyReading t={note || "No data in this window."} h={hint} />
            : children}
      </div>
    </div>
  );
}

function Tag({ tone, children }: { tone: string; children: ReactNode }) {
  return <span className="fp-tag" style={{ color: tone, border: `1px solid ${tone}` }}>{children}</span>;
}
function Kpi({ n, l }: { n: ReactNode; l: string }) {
  return <div className="fp-kpi"><div className="fp-kpi-n">{n}</div><div className="fp-kpi-l">{l}</div></div>;
}

// ── Panel 1 — Network Health Index (hero) ───────────────────────────────────
function HealthStrip() {
  const { data, err } = usePoll(() => api.healthScore("global"));
  const { data: stats } = usePoll(() => api.correlationsStats());
  if (err) return <Panel title="Network health index" state="degraded" />;
  if (!data) return <Panel title="Network health index" state="inactive" note="Reading…" />;
  const insufficient = data.coverage_status === "INSUFFICIENT_TELEMETRY" || data.score == null;
  const bandVar = BAND_VAR[data.band] ?? "var(--fg-subtle)";
  const live = data.signal_classes_live ?? [];
  const stale = data.stale_inputs ?? [];
  const contribs = data.contributions ?? [];
  const bandLabel = insufficient ? "Insufficient" : data.band;
  return (
    <Panel title="Network health index" action={insufficient ? "—" : <span className="fp-num">{data.score} / 100</span>}>
      <div className="fp-hero">
        <div className="fp-hero-score">
          <span className="fp-score" style={{ color: bandVar }}>{insufficient ? "—" : data.score}</span>
          <span className="fp-band" style={{ color: bandVar }}>{bandLabel}</span>
        </div>
        <div className="fp-hero-body">
          {!insufficient && (
            <div className="fp-meter">
              <span className="fp-meter-pin" style={{ left: `${Math.max(2, Math.min(98, data.score!))}%` }} />
            </div>
          )}
          <div className="fp-meta-line">
            Confidence <b style={{ color: "var(--fg)" }}>{CONF_LABEL[data.confidence] ?? data.confidence}</b>
            {" · "}{live.length} signal {live.length === 1 ? "class" : "classes"}
            {stale.length ? ` · ${stale.length} stale` : ""}
          </div>
          {/* RCA status — decoupled from health: the score can be critical from
              raw contributors while RCA has confirmed no root cause yet. */}
          {(() => {
            const conf = stats?.open_confirmed ?? 0, susp = stats?.open_suspected ?? 0;
            const tone = conf > 0 ? "var(--crit)" : susp > 0 ? "var(--warn)" : "var(--fg-muted)";
            const txt = conf > 0 ? `${conf} confirmed RCA incident${conf === 1 ? "" : "s"}`
              : susp > 0 ? `${susp} suspected · none confirmed`
              : "no confirmed root cause yet";
            return <div className="fp-meta-line">RCA status: <b style={{ color: tone }}>{txt}</b></div>;
          })()}
          {!insufficient && data.band !== "healthy" && (
            <div className="fp-meta-line" style={{ color: "var(--fg-muted)" }}>Score driven by the contributors below — not all reductions are confirmed incidents.</div>
          )}
          {insufficient ? (
            <div className="fp-empty-h" style={{ maxWidth: "52ch" }}>
              Not enough independent signals to score the network yet (live: {live.join(", ") || "none"}). Connect more telemetry — this is honest, not broken.
            </div>
          ) : contribs.length ? (
            <>
              <ul className="fp-contribs">
                {contribs.slice(0, 3).map((c, i) => <li key={i}><b className="fp-num">{c.points}</b> pts — {c.reason}</li>)}
              </ul>
              {contribs.length > 3 && (
                <details>
                  <summary style={{ cursor: "pointer", fontSize: 12, color: "var(--accent)" }}>View all {contribs.length} health contributors</summary>
                  <ul className="fp-contribs" style={{ marginTop: 4 }}>
                    {contribs.slice(3).map((c, i) => <li key={i}><b className="fp-num">{c.points}</b> pts — {c.reason}</li>)}
                  </ul>
                </details>
              )}
            </>
          ) : (
            <div className="fp-empty-h">No degraded contributors — all measured signals nominal.</div>
          )}
        </div>
      </div>
    </Panel>
  );
}

// ── Panel 2 — Top Active Issues ─────────────────────────────────────────────
function TopIssues() {
  const { navigate } = useShell();
  const { data, err } = usePoll(() => api.correlations(80, 2592000, "open"));
  const { data: health } = usePoll(() => api.healthScore("global"));
  // confirmed + suspected (not undetermined); exclude internal self-monitoring
  // (customer-network RCA only, decision #76). Wide window so open suspected of any
  // age show — matching the RCA-coverage count.
  const items = (data?.data ?? [])
    .filter((o) => o.verdict_tier !== "undetermined" && !isInternalStackAffected(o.affected))
    .slice(0, 6);
  if (err) return <Panel title="Top active issues" state="degraded" note="Correlation engine unreachable." />;
  if (items.length === 0) {
    // Honesty: if health is degraded/critical but RCA hasn't confirmed a cause,
    // do NOT say "nothing needs attention" — point at the health contributors.
    const band = health?.band;
    const unhealthy = band && band !== "healthy" && health?.coverage_status !== "INSUFFICIENT_TELEMETRY";
    if (unhealthy) {
      return <Panel title="Top active issues" state="inactive" note="No confirmed RCA incidents."
        hint={`Health is ${band} — see Network Health for the contributors driving it, and check those first.`} />;
    }
    return <Panel title="Top active issues" state="inactive" note="No active correlated issues." hint="A good sign — nothing needs attention right now." />;
  }
  return (
    <Panel title="Top active issues" action={<a href="#/monitoring/correlations">all →</a>}>
      {items.map((o) => {
        const tone = VERDICT_VAR[o.verdict_tier] ?? "var(--fg-subtle)";
        return (
          <div key={o.correlation_id} className="fp-row clk" style={{ borderLeftColor: tone }} role="button" onClick={() => navigate("monitoring/correlations")}>
            <Tag tone={tone}>{VERDICT_NOC[o.verdict_tier] ?? o.verdict_tier}</Tag>
            <span className="fp-row-t">{signatureNocTitle(o.top_hypothesis)}</span>
            {o.verdict_tier === "suspected" && <span style={{ fontSize: 10.5, color: "var(--fg-subtle)", letterSpacing: 0.04 }}>not confirmed</span>}
            {o.owner && <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--fg-muted)" }}>{ownerLabel(o.owner)}</span>}
          </div>
        );
      })}
    </Panel>
  );
}

function trusted(o: CorrObject): boolean {
  return (o.grounding ?? "none") !== "none" && !o.low_authority && !o.debug_excluded && o.top_hypothesis !== "undetermined";
}

// ── Panel 3 — Recommended Action ────────────────────────────────────────────
function RecommendedAction() {
  const { data, err } = usePoll(() => api.correlations(50, 86400, "open"));
  const { data: health } = usePoll(() => api.healthScore("global"));
  if (err) return <Panel title="Recommended action" state="degraded" />;
  const row = (verb: string, tone: string, text: string) => (
    <Panel title="Recommended action">
      <div className="fp-row" style={{ borderLeftColor: tone, cursor: "default" }}>
        <Tag tone={tone}>{verb}</Tag>
        <span style={{ fontSize: 13, fontWeight: 600, color: "var(--fg)" }}>{text}</span>
      </div>
    </Panel>
  );
  const objs = (data?.data ?? []).filter((o) => !isInternalStackAffected(o.affected));
  const top = objs.find((o) => o.verdict_tier === "confirmed" && trusted(o)) ?? objs.find((o) => trusted(o));
  if (top) {
    const confirmed = top.verdict_tier === "confirmed";
    const ext = top.owner && OWNER_EXTERNAL.has(top.owner);
    const tone = confirmed ? "var(--crit)" : "var(--warn)";
    const cause = signatureNocTitle(top.top_hypothesis).replace(/^Possible /, "");
    const text = confirmed
      ? (ext ? `Escalate to ${ownerLabel(top.owner!)} — confirmed boundary issue.` : `Escalate to the network team — confirmed ${cause.toLowerCase()}.`)
      : `Do not escalate yet — ${cause} suspected; gather a second independent source to confirm.`;
    return row(confirmed ? "Escalate" : "Hold", tone, text);
  }
  // No trusted RCA object — fall back to the top HEALTH contributors so a
  // critical page always tells the operator what to check next.
  if (health?.coverage_status === "INSUFFICIENT_TELEMETRY") {
    return row("Connect", "var(--info)", "Not enough telemetry to assess — connect more signal sources.");
  }
  const band = health?.band;
  const contribs = health?.contributions ?? [];
  if (band && band !== "healthy" && contribs.length) {
    const tone = band === "critical" ? "var(--crit)" : "var(--warn)";
    const list = contribs.slice(0, 3).map((c) => c.reason);
    const joined = list.length > 1 ? `${list.slice(0, -1).join(", ")}, and ${list[list.length - 1]}` : list[0];
    return row("Investigate", tone, `Investigate the top health contributors — ${joined}. No root cause is confirmed yet.`);
  }
  return <Panel title="Recommended action" state="inactive" note="No action needed." hint="Network nominal; no issue above the confidence floor." />;
}

// ── Panel 5 — RCA Coverage ──────────────────────────────────────────────────
function RcaCoverage() {
  const { data, err } = usePoll(() => api.correlationsStats());
  if (err) return <Panel title="RCA coverage" state="degraded" />;
  if (!data) return <Panel title="RCA coverage" state="inactive" note="Reading…" />;
  // "candidates" = open correlation objects incl. undetermined; confirmed/suspected
  // are the graded subset. Calling the raw count "open issues" overstated it.
  return (
    <Panel title="RCA coverage">
      <div className="fp-kpis">
        <Kpi n={data.open} l="RCA candidates" />
        <Kpi n={data.open_confirmed} l="confirmed" />
        <Kpi n={data.open_suspected} l="suspected" />
        <Kpi n={data.signatures_matched} l="signatures" />
      </div>
    </Panel>
  );
}

// ── Panel 4 — What Changed ──────────────────────────────────────────────────
function WhatChanged() {
  const { data, err } = usePoll(() => api.eventsFeed({ from: "24h", class: "changes", limit: "12" }));
  if (err) return <Panel title="What changed" state="degraded" />;
  const items: FeedItem[] = data?.items ?? [];
  if (items.length === 0) return <Panel title="What changed" state="inactive" note="No changes in the last 24h." hint="Topology, inventory, and alert-state changes appear here." />;
  return (
    <Panel title="What changed">
      <div style={{ display: "flex", flexDirection: "column", gap: 5, maxHeight: 280, overflowY: "auto" }}>
        {items.map((it) => (
          <div key={it.signal_id} style={{ display: "flex", gap: 9, fontSize: 12.5, alignItems: "baseline" }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: SEV_VAR[it.severity] ?? "var(--fg-subtle)", flexShrink: 0, marginTop: 4 }} />
            <span style={{ color: "var(--fg)", minWidth: 0 }}>{it.title}</span>
            <span className="fp-num" style={{ marginLeft: "auto", color: "var(--fg-muted)", whiteSpace: "nowrap" }}>{it.ts.slice(11, 16)}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ── Panel 9 — Impact ────────────────────────────────────────────────────────
function ImpactSummary() {
  const { data, err } = usePoll(() => api.correlations(100, 86400, "open"));
  if (err) return <Panel title="Impact" state="degraded" />;
  const objs = (data?.data ?? []).filter((o) => o.verdict_tier !== "undetermined" && !isInternalStackAffected(o.affected));
  const devices = new Set<string>(); const sites = new Set<string>();
  for (const o of objs) {
    try {
      const a = JSON.parse(o.affected || "{}");
      (a.devices ?? []).forEach((d: string) => devices.add(d));
      (a.sites ?? []).forEach((s: string) => sites.add(s));
    } catch { /* ignore */ }
  }
  // "Impact" = CONFIRMED service impact tied to RCA — distinct from raw health.
  // Don't claim "nothing impacted" (health may be critical from contributors).
  if (objs.length === 0) return <Panel title="Impact" state="inactive" note="No confirmed service impact." hint="No active RCA incident is currently tied to affected users, apps, or paths." />;
  return (
    <Panel title="Impact" action={<a href="#/infrastructure/topology">topology →</a>}>
      <div className="fp-kpis">
        <Kpi n={devices.size || "—"} l="devices affected" />
        <Kpi n={sites.size || "—"} l="sites" />
        <Kpi n={objs.length} l="open issues" />
      </div>
    </Panel>
  );
}

// ── Panel 10 — Capacity Outlook ─────────────────────────────────────────────
function CapacityOutlook() {
  const { data, err } = usePoll(() => api.metricsForecast());
  if (err) return <Panel title="Capacity outlook" state="degraded" />;
  const rows = data?.interfaces ?? [];
  if (rows.length === 0) return <Panel title="Capacity outlook" state="inactive" note="No interface utilization data yet." />;
  const trending = rows.filter((r) => r.status === "trending" || r.status === "saturated");
  if (trending.length === 0) {
    const building = rows.filter((r) => r.status === "building_baseline").length;
    return <Panel title="Capacity outlook" state="inactive"
      note={building > 0 ? "Building baseline" : "All interfaces stable"}
      hint={building > 0 ? `Needs ${data!.min_days} days of history — ${building} interface${building === 1 ? "" : "s"} still learning their trend.` : "No interfaces trending toward saturation."} />;
  }
  return (
    <Panel title="Capacity outlook">
      {trending.slice(0, 6).map((r, i) => {
        const tone = r.status === "saturated" || r.days_to_90 < 14 ? "var(--crit)" : r.days_to_90 < 30 ? "var(--warn)" : "var(--fg-subtle)";
        return (
          <div key={i} className="fp-row" style={{ borderLeftColor: tone, cursor: "default", gap: 9 }}>
            <span className="fp-num">{r.device}</span>
            <span style={{ color: "var(--fg-muted)" }}>{r.interface}</span>
            <span className="fp-num" style={{ marginLeft: "auto", fontWeight: 700, color: tone }}>
              {r.status === "saturated" ? "at capacity" : `~${Math.round(r.days_to_90)}d to 90%`}
            </span>
            <span className="fp-num" style={{ color: "var(--fg-muted)", fontSize: 11.5 }}>{Math.round(r.current_util_pct)}%</span>
          </div>
        );
      })}
    </Panel>
  );
}

// Error boundary so one bad panel degrades in isolation — never white-screens.
class Safe extends Component<{ children: ReactNode }, { err: boolean }> {
  state = { err: false };
  static getDerivedStateFromError() { return { err: true }; }
  render() {
    return this.state.err
      ? <div className="fp-panel"><div className="fp-panel-b"><EmptyReading t="This panel hit an error and was isolated." h="The rest of the page is unaffected." /></div></div>
      : this.props.children;
  }
}

export default function FrontPage() {
  return (
    <div className="fp dm-board">
      <div className="fp-masthead">
        <h1 className="fp-title">Operations Overview</h1>
        <span className="fp-sub">Network health, root cause &amp; impact — at a glance</span>
        <div className="fp-mast-meta">
          <span className="fp-live"><span className="fp-live-dot" /> Live</span>
          <span>Auto-refresh 20s</span>
        </div>
      </div>
      <Safe><HealthStrip /></Safe>
      <div className="fp-cols">
        <div className="fp-col" style={{ flex: "2 1 380px" }}>
          <Safe><TopIssues /></Safe>
          <Safe><Panel title="Hot paths"><PathHealthList limit={5} /></Panel></Safe>
        </div>
        <div className="fp-col" style={{ flex: "1 1 300px" }}>
          <Safe><RecommendedAction /></Safe>
          <Safe><RcaCoverage /></Safe>
          <Safe><ImpactSummary /></Safe>
        </div>
        <div className="fp-col" style={{ flex: "1 1 300px" }}>
          <Safe><WhatChanged /></Safe>
          <Safe><CapacityOutlook /></Safe>
        </div>
      </div>
    </div>
  );
}
