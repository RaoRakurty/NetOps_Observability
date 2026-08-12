import { Component, CSSProperties, ReactNode, useEffect, useState } from "react";
import { api, CorrObject, FeedItem, CorrTimeline } from "../services/api";
import { useShell } from "../context/shell";
import PathHealthList from "../components/PathHealthList";
import RcaPathCausality from "../components/rca/RcaPathCausality";
import { signatureNocTitle, signatureName, kindLabel, ownerLabel, OWNER_EXTERNAL, isInternalStackAffected, mentionsInternal } from "../components/rca/labels";
import { CorrSignal } from "../services/api";

// evidencePhrase turns one window signal into the concrete clause the headline
// sentence is built from — "Gi0/1 down", "BGP peer 10.99.0.2 down", "85% probe loss".
function evidencePhrase(s: CorrSignal): string {
  let a: Record<string, unknown> = {};
  try { a = JSON.parse(s.attrs || "{}"); } catch { /* ignore */ }
  const k = s.kind.replace(/_clear$/, "");
  const state = String(a.state || "down");
  if (k === "link_state_change") {
    const iface = String(a.interface || (s.entity_id.includes(":") ? s.entity_id.split(":").slice(1).join(":") : s.entity_id));
    return `${iface} ${state}`;
  }
  if (/adjacency/.test(k) && /^(bgp|ospf|isis)/.test(k)) {
    const proto = k.startsWith("bgp") ? "BGP" : k.startsWith("ospf") ? "OSPF" : "IS-IS";
    const peer = a.peer ? ` ${a.peer}` : "";
    return `${proto} peer${peer} ${state}`.replace(/\s+/g, " ").trim();
  }
  if (k === "probe_loss") return `${Math.round(Number(s.value) || 0)}% probe loss`;
  if (/rtt|latency/.test(k)) return "response-time anomaly";
  return kindLabel(k).toLowerCase();
}

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

// upProto — normalize protocol/provider acronyms to their canonical casing so the
// operator reads "BGP", "ISP", "AWS", not "bgp / isp / aws". Word-by-word, so it
// never mangles device names (wan-r2, lan-sw1 are left alone).
const PROTO_CASE: Record<string, string> = {
  bgp: "BGP", ospf: "OSPF", isis: "IS-IS", "is-is": "IS-IS", lldp: "LLDP", cdp: "CDP",
  bfd: "BFD", ldp: "LDP", mpls: "MPLS", vrf: "VRF", vpn: "VPN", dns: "DNS", isp: "ISP",
  aws: "AWS", azure: "Azure", gcp: "GCP", tgw: "TGW", sdwan: "SD-WAN", "sd-wan": "SD-WAN",
  mtu: "MTU", vlan: "VLAN", dhcp: "DHCP", nat: "NAT", qos: "QoS", http: "HTTP", https: "HTTPS",
  tcp: "TCP", udp: "UDP", sla: "SLA", api: "API", wan: "WAN", lan: "LAN", dc: "DC", dia: "DIA",
  icmp: "ICMP", stamp: "STAMP", snmp: "SNMP", gnmi: "gNMI", netflow: "NetFlow", ipfix: "IPFIX",
};
function upProto(s: string): string {
  return s.replace(/[A-Za-z][A-Za-z-]*/g, (w) => PROTO_CASE[w.toLowerCase()] ?? w);
}

// Spark — tiny dependency-free sparkline so each KPI tells its recent STORY, not a
// static number. Fed by a real client-side rolling history (no fabricated data).
function Spark({ pts, color }: { pts: number[]; color: string }) {
  const v = pts.filter((n) => Number.isFinite(n));
  if (v.length < 3) return <div style={{ height: 16, marginTop: 5 }} />; // reserve space; build a trend first
  const w = 64, h = 16, min = Math.min(...v), max = Math.max(...v), span = max - min || 1, step = w / (v.length - 1);
  const d = v.map((n, i) => `${i ? "L" : "M"}${(i * step).toFixed(1)},${(h - ((n - min) / span) * h).toFixed(1)}`).join(" ");
  const lastY = h - ((v[v.length - 1] - min) / span) * h;
  return (
    <svg width={w} height={h} style={{ display: "block", marginTop: 5, overflow: "visible" }} aria-hidden>
      <path d={d} fill="none" stroke={color} strokeWidth={1.5} opacity={0.9} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={w} cy={lastY} r={1.9} fill={color} />
    </svg>
  );
}
// KPI history persists (localStorage) so the trend is populated on reload — these
// are real observed samples accumulated each poll, capped to the recent window.
const KPI_HIST_KEY = "netops.fp.kpihist";
function loadKpiHist(): Record<string, number[]> { try { return JSON.parse(localStorage.getItem(KPI_HIST_KEY) || "{}"); } catch { return {}; } }

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

function Panel({ title, action, state = "ok", note, hint, to, children }: {
  title: string; action?: ReactNode; state?: PanelState; note?: string; hint?: string; to?: string; children?: ReactNode;
}) {
  // `to` makes the whole header a drill-through link (hash route; the SPA router
  // handles it) with a hover affordance + "→" when there's no explicit action.
  const head = (
    <div className="fp-panel-h">
      <h3 className="fp-panel-t">{title}</h3>
      {state === "degraded" && <span className="fp-tag" style={{ color: "var(--warn)", border: "1px solid var(--warn)" }}>degraded</span>}
      {action ? <span className="fp-panel-meta">{action}</span> : to ? <span className="fp-panel-meta" aria-hidden>→</span> : null}
    </div>
  );
  return (
    <div className="fp-panel">
      {to ? <a className="fp-panel-link" href={`#/${to}`}>{head}</a> : head}
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
function Kpi({ n, l, tone }: { n: ReactNode; l: string; tone?: string }) {
  return <div className="fp-kpi"><div className="fp-kpi-n" style={tone ? { color: tone } : undefined}>{n}</div><div className="fp-kpi-l">{l}</div></div>;
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
    <Panel title="Top active issues" action={<a href="#/investigate/rca">all →</a>}>
      {items.map((o) => {
        const tone = VERDICT_VAR[o.verdict_tier] ?? "var(--fg-subtle)";
        return (
          <div key={o.correlation_id} className="fp-row clk" style={{ borderLeftColor: tone }} role="button" onClick={() => navigate("investigate/rca")}>
            <Tag tone={tone}>{VERDICT_NOC[o.verdict_tier] ?? o.verdict_tier}</Tag>
            <span className="fp-row-t">{upProto(signatureNocTitle(o.top_hypothesis))}</span>
            {o.verdict_tier === "suspected" && <span style={{ fontSize: 10.5, color: "var(--fg-subtle)", letterSpacing: 0.04 }}>not confirmed</span>}
            {o.owner && <span className="fp-owner" style={{ marginLeft: "auto" }}>{upProto(ownerLabel(o.owner))}</span>}
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
    <Panel title="Recommended action" to="monitoring/correlations">
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
    <Panel title="RCA coverage" to="monitoring/correlations">
      <div className="fp-kpis">
        <Kpi n={data.open} l="RCA candidates" tone="var(--accent)" />
        <Kpi n={data.open_confirmed} l="confirmed" tone={data.open_confirmed > 0 ? "var(--crit)" : undefined} />
        <Kpi n={data.open_suspected} l="suspected" tone={data.open_suspected > 0 ? "var(--warn)" : undefined} />
        <Kpi n={data.signatures_matched} l="signatures" tone={data.signatures_matched > 0 ? "var(--ok)" : undefined} />
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
    <Panel title="What changed" to="monitoring/events">
      <div style={{ display: "flex", flexDirection: "column", gap: 5, maxHeight: 280, overflowY: "auto" }}>
        {items.map((it) => (
          <div key={it.signal_id} style={{ display: "flex", gap: 9, fontSize: 12.5, alignItems: "baseline" }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: SEV_VAR[it.severity] ?? "var(--fg-subtle)", flexShrink: 0, marginTop: 4 }} />
            <span style={{ color: "var(--fg)", minWidth: 0 }}>{upProto(it.title)}</span>
            <span className="fp-num" style={{ marginLeft: "auto", color: "var(--fg-muted)", whiteSpace: "nowrap" }}>{it.ts.slice(11, 16)}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ── Panel 9 — Impact ────────────────────────────────────────────────────────
function ImpactSummary() {
  // 30-day window to match the KPI strip + RCA coverage — a graded object older
  // than 24h must still count as impact (a narrower window silently emptied this).
  const { data, err } = usePoll(() => api.correlations(120, 2592000, "open"));
  if (err) return <Panel title="Impact" state="degraded" />;
  const objs = (data?.data ?? []).filter((o) => o.verdict_tier !== "undetermined" && !isInternalStackAffected(o.affected));
  const devices = new Set<string>(); const sites = new Set<string>();
  for (const o of objs) {
    try {
      const a = JSON.parse(o.affected || "{}");
      // #76: count only customer entities, not platform/agent infra mixed in.
      (a.devices ?? []).forEach((d: string) => { if (!mentionsInternal(d)) devices.add(d); });
      (a.sites ?? []).forEach((s: string) => { if (!mentionsInternal(s)) sites.add(s); });
    } catch { /* ignore */ }
  }
  // "Impact" = CONFIRMED service impact tied to RCA — distinct from raw health.
  // Don't claim "nothing impacted" (health may be critical from contributors).
  if (objs.length === 0) return <Panel title="Impact" state="inactive" note="No confirmed service impact." hint="No active RCA incident is currently tied to affected users, apps, or paths." />;
  return (
    <Panel title="Impact" action={<a href="#/infrastructure/topology">topology →</a>}>
      <div className="fp-kpis">
        <Kpi n={devices.size} l="devices affected" />
        <Kpi n={sites.size} l="sites" />
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
    <Panel title="Capacity outlook" to="infrastructure/ifperf">
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

// ── Panel 2 — Top Health Contributors ───────────────────────────────────────
function TopHealthContributors() {
  const { data, err } = usePoll(() => api.healthScore("global"));
  if (err) return <Panel title="Top health contributors" state="degraded" />;
  if (!data) return <Panel title="Top health contributors" state="inactive" note="Reading…" />;
  if (data.coverage_status === "INSUFFICIENT_TELEMETRY")
    return <Panel title="Top health contributors" state="inactive" note="Insufficient telemetry." hint="Connect more signal classes to assess contributors." />;
  const contribs = data.contributions ?? [];
  if (contribs.length === 0)
    return <Panel title="Top health contributors" state="inactive" note="No degraded contributors." hint="All measured signals are nominal." />;
  return (
    <Panel title="Top health contributors" action={<span>{contribs.length}</span>} to="monitoring/triggered">
      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        {contribs.slice(0, 8).map((c, i) => (
          <div key={i} style={{ display: "flex", gap: 8, alignItems: "baseline", fontSize: 12.5 }}>
            <span className="fp-num" style={{ fontWeight: 700, minWidth: 30, textAlign: "right", color: c.points >= 12 ? "var(--crit)" : c.points >= 6 ? "var(--warn)" : "var(--fg)" }}>{c.points}</span>
            <span style={{ fontSize: 10, color: "var(--fg-subtle)", textTransform: "uppercase", letterSpacing: 0.05, minWidth: 80, flexShrink: 0 }}>{c.signal_class.replace(/_/g, " ")}</span>
            <span style={{ color: "var(--fg)", minWidth: 0 }}>{c.reason}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ── Panel 6 — Telemetry Coverage / Freshness ────────────────────────────────
const SIGNAL_CLASS_LABEL: Record<string, string> = {
  availability: "Availability", device_health: "Device health", path_health: "Path checks", correlation: "Correlation",
};
function TelemetryCoverage() {
  const { data, err } = usePoll(() => api.healthScore("global"));
  if (err) return <Panel title="Telemetry coverage" state="degraded" />;
  if (!data) return <Panel title="Telemetry coverage" state="inactive" note="Reading…" />;
  const live = new Set(data.signal_classes_live ?? []);
  const stale = new Set(data.stale_inputs ?? []);
  const classes = ["availability", "device_health", "path_health", "correlation"];
  return (
    <Panel title="Telemetry coverage" action={<span>{live.size}/{classes.length} live</span>}>
      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        {classes.map((c) => {
          const isLive = live.has(c), isStale = stale.has(c);
          const tone = !isLive ? "var(--fg-subtle)" : isStale ? "var(--warn)" : "var(--ok)";
          const txt = !isLive ? "inactive" : isStale ? "stale" : "live";
          return (
            <div key={c} style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12.5 }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: tone, flexShrink: 0 }} />
              <span style={{ color: "var(--fg)" }}>{SIGNAL_CLASS_LABEL[c] ?? c}</span>
              <span style={{ marginLeft: "auto", fontSize: 10.5, textTransform: "uppercase", letterSpacing: 0.06, color: tone, fontWeight: 700 }}>{txt}</span>
            </div>
          );
        })}
      </div>
      <div className="fp-empty-h" style={{ marginTop: 2 }}>Trust the health score in proportion to live coverage (confidence: {CONF_LABEL[data.confidence] ?? data.confidence}).</div>
    </Panel>
  );
}

// ── Panel 5 — RCA Path View (where the top issue sits / likely fault location) ─
function RcaPathPanel() {
  const { data, err } = usePoll(() => api.correlations(80, 2592000, "open"));
  const [tl, setTl] = useState<CorrTimeline | null>(null);
  const objs = (data?.data ?? []).filter((o) => o.verdict_tier !== "undetermined" && !isInternalStackAffected(o.affected));
  const top = objs.find((o) => o.verdict_tier === "confirmed") ?? objs[0];
  const topId = top?.correlation_id;
  useEffect(() => {
    if (!topId) { setTl(null); return; }
    let alive = true;
    api.correlationTimeline(topId).then((t) => { if (alive) setTl(t); }).catch(() => { if (alive) setTl(null); });
    return () => { alive = false; };
  }, [topId]);
  if (err) return <Panel title="RCA path view" state="degraded" />;
  if (!top || !tl) return <Panel title="RCA path view" state="inactive" note="No issue to locate yet."
    hint="When an issue is suspected or confirmed, its path and likely fault location appear here." />;
  return (
    <Panel title="RCA path view" to="monitoring/correlations">
      {/* The merged single path view (pathModel.ts): the front page has no
          decoded attribution, so it renders the honest fallback chain —
          measured spine → routing adjacency → "path not fully discovered". */}
      <RcaPathCausality data={null} timeline={tl}
        ownership={top.owner ? ownerLabel(top.owner) : undefined} />
    </Panel>
  );
}

// ── Panel 10 — Site / Region Health ─────────────────────────────────────────
function SiteRegionHealth() {
  // Honest: per-site scoring needs site-tagged telemetry; never fabricate it.
  return <Panel title="Site / region health" state="inactive" note="Per-site health not available yet."
    hint="Add site labels (Source of Truth / geomap) so device + path signals can be scored per site." />;
}

// ── Panel 13 — Platform Health (admin / internal stack) ─────────────────────
const STACK_TONE: Record<string, string> = { healthy: "var(--ok)", degraded: "var(--warn)", down: "var(--crit)" };
function PlatformHealth() {
  const { data, err } = usePoll(() => api.stackHealth());
  if (err) return <Panel title="Platform health (internal)" state="degraded" />;
  if (!data) return <Panel title="Platform health (internal)" state="inactive" note="Reading…" />;
  const tone = STACK_TONE[data.overall] ?? "var(--fg-subtle)";
  return (
    <Panel title="Platform health (internal)">
      <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
        <span className="fp-tag" style={{ color: tone, border: `1px solid ${tone}`, textTransform: "capitalize" }}>{data.overall}</span>
        <span style={{ fontSize: 12.5, color: "var(--fg-muted)" }}>
          <b className="fp-num" style={{ color: "var(--ok)" }}>{data.up}</b> up
          {data.degraded > 0 && <> · <b className="fp-num" style={{ color: "var(--warn)" }}>{data.degraded}</b> degraded</>}
          {data.down > 0 && <> · <b className="fp-num" style={{ color: "var(--crit)" }}>{data.down}</b> down</>}
        </span>
      </div>
      <div className="fp-empty-h">The platform's own services — separate from the customer-network health above.</div>
    </Panel>
  );
}

// ── Panel 14 — Internal Monitoring Checks (admin) ───────────────────────────
function InternalMonitoringChecks() {
  const { navigate } = useShell();
  const { data } = usePoll(() => api.correlations(120, 2592000, "open"));
  const internal = (data?.data ?? []).filter((o) => isInternalStackAffected(o.affected));
  return (
    <Panel title="Internal monitoring checks" action={<a href="#/investigate/rca" onClick={(e) => { e.preventDefault(); navigate("investigate/rca"); }}>view →</a>}>
      <div style={{ fontSize: 12.5, color: "var(--fg-muted)" }}>
        <b className="fp-num" style={{ fontSize: 18, color: "var(--fg)" }}>{internal.length}</b> internal self-monitoring object{internal.length === 1 ? "" : "s"}
      </div>
      <div className="fp-empty-h">Hidden from customer RCA by design — the platform watching itself. Open Correlations → “Show internal/stack”.</div>
    </Panel>
  );
}

// ── Top KPI strip — dense operational state above the fold ───────────────────
function KpiStrip() {
  const { data: h } = usePoll(() => api.healthScore("global"));
  const { data: s } = usePoll(() => api.correlationsStats());
  const { data: c } = usePoll(() => api.correlations(120, 2592000, "open"));
  const objs = (c?.data ?? []).filter((o) => o.verdict_tier !== "undetermined" && !isInternalStackAffected(o.affected));
  const devs = new Set<string>(), sites = new Set<string>();
  for (const o of objs) {
    try {
      const a = JSON.parse(o.affected || "{}");
      (a.devices ?? []).forEach((d: string) => { if (!mentionsInternal(d)) devs.add(d); });
      (a.sites ?? []).forEach((x: string) => { if (!mentionsInternal(x)) sites.add(x); });
      // path endpoints are devices too ("wan-r2 → 10.0.0.2"); skip platform infra
      (a.paths ?? []).forEach((p: string) => p.split(/->|→/).forEach((n: string) => { const d = n.trim(); if (d && !mentionsInternal(d)) devs.add(d); }));
    } catch { /* ignore */ }
  }
  // Also count devices currently driving the health score (CPU/errors/etc.) — they
  // ARE impacted even if no graded RCA names them yet, so the strip isn't a flat 0
  // when the only correlated objects are internal/self-monitoring.
  for (const cn of (h?.contributions ?? [])) if (cn.entity && !mentionsInternal(cn.entity)) devs.add(cn.entity);
  const insufficient = !h || h.coverage_status === "INSUFFICIENT_TELEMETRY" || h.score == null;
  const scoreColor = BAND_VAR[h?.band ?? ""] ?? "var(--fg-subtle)";
  const live = (h?.signal_classes_live ?? []).length, stale = (h?.stale_inputs ?? []).length;
  const confirmed = s?.open_confirmed ?? 0, suspected = s?.open_suspected ?? 0;

  // Rolling KPI history — one real sample appended per poll, persisted so the
  // trend is populated on reload. Powers the per-cell sparkline + delta.
  const [hist, setHist] = useState<Record<string, number[]>>(loadKpiHist);
  useEffect(() => {
    if (!h && !s && !c) return;
    setHist((cur) => {
      const next = { ...cur };
      const push = (k: string, v: number) => { next[k] = (next[k] ?? []).concat(v).slice(-24); };
      push("health", insufficient ? NaN : (h?.score ?? NaN));
      push("confirmed", confirmed); push("suspected", suspected); push("sites", sites.size); push("devices", devs.size);
      try { localStorage.setItem(KPI_HIST_KEY, JSON.stringify(next)); } catch { /* quota */ }
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [h, s, c]);
  const deltaOf = (k: string): number | null => {
    const a = (hist[k] ?? []).filter(Number.isFinite);
    return a.length >= 3 ? a[a.length - 1] - a[0] : null;
  };

  // each cell drills through to its detail surface; `histKey` adds the sparkline +
  // delta so the cell tells a story ("Health 20 ▼ −14") rather than a flat number.
  // Same dense-card design as My Dashboard's KPI strip (.kpi/.kpi-grid): a small
  // box per KPI, big number tinted by its accent, label, sub, and the recent
  // sparkline. The per-cell accent rides on the --kpi-accent custom property.
  const cell = (label: string, value: ReactNode, tone?: string, sub?: string, to?: string, histKey?: string) => {
    const dl = histKey ? deltaOf(histKey) : null;
    const accent = tone || "var(--accent)";
    const inner = (
      <>
        <span className="kpi-label">{label}</span>
        <div className="kpi-numrow">
          <span className="kpi-num">{value}</span>
          {dl != null && dl !== 0 && <span className="fp-kpidelta">{dl > 0 ? "▲" : "▼"}{Math.abs(dl)}</span>}
        </div>
        {sub ? <span className="kpi-sub">{sub}</span> : <span className="kpi-sub">&nbsp;</span>}
        {histKey ? <Spark pts={hist[histKey] ?? []} color={tone || "var(--accent)"} /> : <div style={{ height: 26 }} />}
      </>
    );
    const style = { ["--kpi-accent"]: accent } as CSSProperties;
    return to
      ? <a className="kpi kpi-link" style={style} href={`#/${to}`}>{inner}</a>
      : <div className="kpi" style={style}>{inner}</div>;
  };
  return (
    <div className="kpi-grid">
      {cell("Health score", insufficient ? "—" : h!.score, scoreColor, insufficient ? "insufficient" : (h?.band ?? ""), "monitoring/triggered", "health")}
      {cell("Active incidents", confirmed, confirmed > 0 ? "var(--crit)" : undefined, "confirmed RCA", "monitoring/correlations?tier=confirmed", "confirmed")}
      {cell("Suspected RCA", suspected, suspected > 0 ? "var(--warn)" : undefined, "candidates", "monitoring/correlations?tier=suspected", "suspected")}
      {cell("Impacted sites", sites.size, undefined, sites.size ? undefined : "none tagged", "infrastructure/topology", "sites")}
      {cell("Impacted devices", devs.size, undefined, undefined, "infrastructure/topology", "devices")}
      {cell("Telemetry", `${live}/4`, stale > 0 ? "var(--warn)" : live >= 2 ? "var(--ok)" : "var(--fg-subtle)", stale > 0 ? `${stale} stale` : "signal classes", "monitoring/triggered")}
    </div>
  );
}

// ── Top issue spotlight — THE product sentence (explainable, network-native) ──
function TopIssueSpotlight() {
  const { data } = usePoll(() => api.correlations(80, 2592000, "open"));
  const [tl, setTl] = useState<CorrTimeline | null>(null);
  const objs = (data?.data ?? []).filter((o) => o.verdict_tier !== "undetermined" && !isInternalStackAffected(o.affected));
  const top = objs.find((o) => o.verdict_tier === "confirmed") ?? objs[0];
  const topId = top?.correlation_id;
  useEffect(() => {
    if (!topId) { setTl(null); return; }
    let alive = true;
    api.correlationTimeline(topId).then((t) => { if (alive) setTl(t); }).catch(() => { if (alive) setTl(null); });
    return () => { alive = false; };
  }, [topId]);
  if (!top) return null; // no headline when nothing suspected/confirmed
  const confirmed = top.verdict_tier === "confirmed";
  const tone = confirmed ? "var(--crit)" : "var(--warn)";
  let affected: Record<string, string[]> = {};
  try { affected = JSON.parse(top.affected || "{}"); } catch { /* ignore */ }
  const device = affected.devices?.[0] || (affected.interfaces?.[0]?.split(":")[0]) || "the network";
  const sig = top.top_hypothesis !== "undetermined" ? upProto(signatureName(top.top_hypothesis).toLowerCase()) : "network issue";
  const phrases: string[] = [];
  if (tl) {
    const seen = new Set<string>();
    for (const s of tl.signals) {
      if (s.kind.endsWith("_clear")) continue;
      const p = evidencePhrase(s);
      if (p && !seen.has(p)) { seen.add(p); phrases.push(p); }
      if (phrases.length >= 4) break;
    }
  }
  const tail = confirmed ? "" : " · needs independent confirmation";
  const sentence = `${confirmed ? "Confirmed" : "Suspected"} ${sig} on ${device}${phrases.length ? " — " + phrases.join(" · ") : ""}${tail}`;
  return (
    <a className="fp-panel-link" href="#/investigate/rca" style={{ display: "block" }}>
      <div className="fp-spot" style={{ borderLeft: `4px solid ${tone}` }}>
        <Tag tone={tone}>{confirmed ? "CONFIRMED" : "SUSPECTED"}</Tag>
        <span className="fp-spot-text">{sentence}</span>
        <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 10, whiteSpace: "nowrap" }}>
          {top.owner && <span className="fp-owner">{upProto(ownerLabel(top.owner))}</span>}
          <span style={{ color: "var(--accent)", fontSize: 13 }}>open →</span>
        </span>
      </div>
    </a>
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
  // Theme is now app-wide (the global picker in the top bar / icon rail sets
  // data-theme on <html>); the Operations Overview just reads the tokens.
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
      {/* Dense top: operational KPIs above the fold + the headline sentence
          (replaces the tall hero — density over whitespace, NOC-battle-station). */}
      <Safe><KpiStrip /></Safe>
      <Safe><TopIssueSpotlight /></Safe>
      {/* 3 columns matching the owner's 14-panel grid; each column groups related
          panels and masonry-packs so short/inactive panels don't leave row gaps.
          Order = priority (must-haves first down each column). */}
      <div className="fp-cols">
        <div className="fp-col" style={{ flex: "1 1 320px" }}>
          <Safe><RcaCoverage /></Safe>
          <Safe><TopHealthContributors /></Safe>
          <Safe><TopIssues /></Safe>
          <Safe><Panel title="Hot paths" to="infrastructure/flowtrace"><PathHealthList limit={5} /></Panel></Safe>
        </div>
        <div className="fp-col" style={{ flex: "1 1 320px" }}>
          <Safe><RecommendedAction /></Safe>
          <Safe><RcaPathPanel /></Safe>
          <Safe><SiteRegionHealth /></Safe>
          <Safe><CapacityOutlook /></Safe>
        </div>
        <div className="fp-col" style={{ flex: "1 1 320px" }}>
          <Safe><WhatChanged /></Safe>
          <Safe><ImpactSummary /></Safe>
          <Safe><TelemetryCoverage /></Safe>
          <Safe><PlatformHealth /></Safe>
          <Safe><InternalMonitoringChecks /></Safe>
        </div>
      </div>
    </div>
  );
}
