// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// rcaPanels.tsx — the answer-first panels of Overview, moved from the retired
// Operations Overview (pages/FrontPage.tsx, #69) and changed in one way: they
// take their data from the page's shared read (useOverviewData) instead of each
// polling the same three endpoints. Every panel still degrades to a deliberate
// reading: a source that did not answer says so, a source with nothing to show
// says that, and neither is ever a blank that looks healthy.

import { CSSProperties, ReactNode, useEffect, useState } from "react";
import { api, type CorrObject, type CorrSignal, type CorrStats, type CorrTimeline, type FeedItem, type HealthScoreResp, getActiveScope, sessionTenantKey } from "../../services/api";
import { useShell } from "../../context/shell";
import RcaPathCausality from "../../components/rca/RcaPathCausality";
import ErrorBoundary from "../../components/ErrorBoundary";
import { signatureNocTitle, signatureName, kindLabel, ownerLabel, OWNER_EXTERNAL } from "../../components/rca/labels";
import { usePolled } from "../panels";
import { impactOf } from "./overviewModel";
import { deviceDisplayName, useDeviceNames } from "../../lib/deviceNames";

// ── shared vocabulary ───────────────────────────────────────────────────────

const BAND_VAR: Record<string, string> = {
  healthy: "var(--ok)", watch: "var(--warn)", degraded: "var(--crit)",
  critical: "var(--crit)", insufficient_telemetry: "var(--fg-subtle)",
};
const VERDICT_VAR: Record<string, string> = { confirmed: "var(--crit)", suspected: "var(--warn)", undetermined: "var(--fg-subtle)" };
const VERDICT_NOC: Record<string, string> = { confirmed: "Confirmed", suspected: "Suspected", undetermined: "Not confirmed" };
const SEV_VAR: Record<string, string> = { crit: "var(--crit)", high: "var(--crit)", warn: "var(--warn)", info: "var(--fg-subtle)" };
const CONF_LABEL: Record<string, string> = { low: "Low", medium_low: "Medium-low", medium: "Medium", high: "High" };

// upProto — canonical casing for protocol/provider acronyms ("BGP", "ISP"),
// word by word, so device names (wan-r2) are left alone.
const PROTO_CASE: Record<string, string> = {
  bgp: "BGP", ospf: "OSPF", isis: "IS-IS", "is-is": "IS-IS", lldp: "LLDP", cdp: "CDP",
  bfd: "BFD", ldp: "LDP", mpls: "MPLS", vrf: "VRF", vpn: "VPN", dns: "DNS", isp: "ISP",
  aws: "AWS", azure: "Azure", gcp: "GCP", tgw: "TGW", sdwan: "SD-WAN", "sd-wan": "SD-WAN",
  mtu: "MTU", vlan: "VLAN", dhcp: "DHCP", nat: "NAT", qos: "QoS", http: "HTTP", https: "HTTPS",
  tcp: "TCP", udp: "UDP", sla: "SLA", api: "API", wan: "WAN", lan: "LAN", dc: "DC", dia: "DIA",
  icmp: "ICMP", stamp: "STAMP", snmp: "SNMP", gnmi: "gNMI", netflow: "NetFlow", ipfix: "IPFIX",
};
export function upProto(s: string): string {
  return s.replace(/[A-Za-z][A-Za-z-]*/g, (w) => PROTO_CASE[w.toLowerCase()] ?? w);
}

// evidencePhrase turns one window signal into the concrete clause the headline
// sentence is built from — "Gi0/1 down", "BGP peer 10.99.0.2 down".
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

type PanelState = "ok" | "inactive" | "degraded";

function EmptyReading({ t, h }: { t: string; h?: string }) {
  return (
    <div className="fp-empty">
      <span className="fp-empty-mark" />
      <div className="fp-empty-t">{t}</div>
      {h && <div className="fp-empty-h">{h}</div>}
    </div>
  );
}

export function RcaPanel({ title, action, state = "ok", note, hint, to, children }: {
  title: string; action?: ReactNode; state?: PanelState; note?: string; hint?: string; to?: string; children?: ReactNode;
}) {
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
            ? <EmptyReading t={note || "Nothing collected in this window."} h={hint} />
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

/** Per-panel isolation: one bad panel degrades on its own and the rest keep
 *  reading (the route boundary catches anything outside a panel). */
export function Safe({ children }: { children: ReactNode }) {
  return (
    <ErrorBoundary
      label="This panel"
      fallback={() => (
        <div className="fp-panel"><div className="fp-panel-b"><EmptyReading t="This panel hit an error and was isolated." h="The rest of the page is unaffected." /></div></div>
      )}
    >
      {children}
    </ErrorBoundary>
  );
}

function trusted(o: CorrObject): boolean {
  return (o.grounding ?? "none") !== "none" && !o.low_authority && !o.debug_excluded && o.top_hypothesis !== "undetermined";
}

/** The timeline of the top problem, re-read only when the top problem changes. */
function useTimeline(id: string | undefined): CorrTimeline | null {
  const [tl, setTl] = useState<CorrTimeline | null>(null);
  useEffect(() => {
    if (!id) { setTl(null); return; }
    let alive = true;
    api.correlationTimeline(id).then((t) => { if (alive) setTl(t); }).catch(() => { if (alive) setTl(null); });
    return () => { alive = false; };
  }, [id]);
  return tl;
}

// ── the headline sentence ───────────────────────────────────────────────────

export function TopIssueSpotlight({ top }: { top: CorrObject }) {
  const tl = useTimeline(top.correlation_id);
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
    <a className="fp-panel-link" href={`#/investigate/rca?id=${encodeURIComponent(top.correlation_id)}`} style={{ display: "block" }}>
      <div className="fp-spot" style={{ borderLeft: `4px solid ${tone}` }}>
        <Tag tone={tone}>{confirmed ? "CONFIRMED" : "SUSPECTED"}</Tag>
        <span className="fp-spot-text">{sentence}</span>
        <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 10, whiteSpace: "nowrap" }}>
          {top.owner && <span className="fp-owner">{upProto(ownerLabel(top.owner))}</span>}
          <span style={{ color: "var(--accent)", fontSize: 14 }}>open →</span>
        </span>
      </div>
    </a>
  );
}

// ── Recommended action ──────────────────────────────────────────────────────

export function RecommendedAction({ objs, health, err }: { objs: CorrObject[] | undefined; health: HealthScoreResp | undefined; err: boolean }) {
  if (err && !objs) return <RcaPanel title="Recommended action" state="degraded" />;
  const row = (verb: string, tone: string, text: string) => (
    <RcaPanel title="Recommended action" to="investigate/rca">
      <div className="fp-row" style={{ borderLeftColor: tone, cursor: "default" }}>
        <Tag tone={tone}>{verb}</Tag>
        <span style={{ fontSize: 14, fontWeight: 500, color: "var(--fg)" }}>{text}</span>
      </div>
    </RcaPanel>
  );
  const top = (objs ?? []).find((o) => o.verdict_tier === "confirmed" && trusted(o)) ?? (objs ?? []).find((o) => trusted(o));
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
  // No trusted case: point at the health contributors, so a degraded page
  // always says what to check next.
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
  if (!objs || !health) return <RcaPanel title="Recommended action" state="inactive" note="Reading…" />;
  return <RcaPanel title="Recommended action" state="inactive" note="No action needed." hint="Nothing is above the confidence floor and health is nominal." />;
}

// ── Open problems ───────────────────────────────────────────────────────────

export function TopIssues({ problems, health, err }: { problems: CorrObject[] | undefined; health: HealthScoreResp | undefined; err: boolean }) {
  const { navigate } = useShell();
  if (err && !problems) return <RcaPanel title="Top active issues" state="degraded" note="Correlation is not answering right now." />;
  if (!problems) return <RcaPanel title="Top active issues" state="inactive" note="Reading…" />;
  const items = problems.slice(0, 6);
  if (items.length === 0) {
    const band = health?.band;
    const unhealthy = band && band !== "healthy" && health?.coverage_status !== "INSUFFICIENT_TELEMETRY";
    if (unhealthy) {
      return <RcaPanel title="Top active issues" state="inactive" note="No confirmed RCA incidents."
        hint={`Health is ${band} — see the health contributors below, and check those first.`} />;
    }
    return <RcaPanel title="Top active issues" state="inactive" note="No active correlated issues." hint="No case is open." />;
  }
  return (
    <RcaPanel title="Top active issues" action={<a href="#/operations/queue">all →</a>}>
      {items.map((o) => {
        const tone = VERDICT_VAR[o.verdict_tier] ?? "var(--fg-subtle)";
        return (
          <div key={o.correlation_id} className="fp-row clk" style={{ borderLeftColor: tone }} role="button" tabIndex={0}
            onClick={() => navigate(`investigate/rca?id=${encodeURIComponent(o.correlation_id)}`)}
            onKeyDown={(e) => { if (e.key === "Enter") navigate(`investigate/rca?id=${encodeURIComponent(o.correlation_id)}`); }}>
            <Tag tone={tone}>{VERDICT_NOC[o.verdict_tier] ?? o.verdict_tier}</Tag>
            <span className="fp-row-t">{upProto(signatureNocTitle(o.top_hypothesis))}</span>
            {o.owner && <span className="fp-owner" style={{ marginLeft: "auto" }}>{upProto(ownerLabel(o.owner))}</span>}
          </div>
        );
      })}
    </RcaPanel>
  );
}

export function RcaPathPanel({ top, err }: { top: CorrObject | undefined; err: boolean }) {
  const tl = useTimeline(top?.correlation_id);
  if (err && !top) return <RcaPanel title="Where the fault is" state="degraded" />;
  if (!top || !tl) return <RcaPanel title="Where the fault is" state="inactive" note="No issue to locate yet."
    hint="When an issue is suspected or confirmed, its path and likely fault location appear here." />;
  return (
    <RcaPanel title="Where the fault is" to="investigate/rca">
      <RcaPathCausality data={null} timeline={tl} ownership={top.owner ? ownerLabel(top.owner) : undefined} />
    </RcaPanel>
  );
}

export function ImpactSummary({ problems, err }: { problems: CorrObject[] | undefined; err: boolean }) {
  if (err && !problems) return <RcaPanel title="Impact" state="degraded" />;
  if (!problems) return <RcaPanel title="Impact" state="inactive" note="Reading…" />;
  if (problems.length === 0) return <RcaPanel title="Impact" state="inactive" note="No confirmed service impact." hint="No open case is tied to affected devices, sites or paths." />;
  const { devices, sites } = impactOf(problems, undefined);
  return (
    <RcaPanel title="Impact" action={<a href="#/investigate/topology">topology →</a>}>
      <div className="fp-kpis">
        <Kpi n={devices.size} l="devices affected" />
        <Kpi n={sites.size} l="sites" />
        <Kpi n={problems.length} l="open issues" />
      </div>
    </RcaPanel>
  );
}

export function RcaCoverage({ stats, err }: { stats: CorrStats | undefined; err: boolean }) {
  if (err && !stats) return <RcaPanel title="RCA coverage" state="degraded" />;
  if (!stats) return <RcaPanel title="RCA coverage" state="inactive" note="Reading…" />;
  return (
    <RcaPanel title="RCA coverage" to="investigate/rca">
      <div className="fp-kpis">
        <Kpi n={stats.open} l="RCA candidates" tone="var(--accent)" />
        <Kpi n={stats.open_confirmed} l="confirmed" tone={stats.open_confirmed > 0 ? "var(--crit)" : undefined} />
        <Kpi n={stats.open_suspected} l="suspected" tone={stats.open_suspected > 0 ? "var(--warn)" : undefined} />
        <Kpi n={stats.signatures_matched} l="signatures" tone={stats.signatures_matched > 0 ? "var(--ok)" : undefined} />
      </div>
    </RcaPanel>
  );
}

// ── What is broken now ──────────────────────────────────────────────────────

export function TopHealthContributors({ health, err }: { health: HealthScoreResp | undefined; err: boolean }) {
  if (err && !health) return <RcaPanel title="Top health contributors" state="degraded" />;
  if (!health) return <RcaPanel title="Top health contributors" state="inactive" note="Reading…" />;
  if (health.coverage_status === "INSUFFICIENT_TELEMETRY")
    return <RcaPanel title="Top health contributors" state="inactive" note="Insufficient telemetry." hint="Connect more signal classes to assess contributors." />;
  const contribs = health.contributions ?? [];
  if (contribs.length === 0)
    return <RcaPanel title="Top health contributors" state="inactive" note="No degraded contributors." hint="All measured signals are nominal." />;
  return (
    <RcaPanel title="Top health contributors" action={<span>{contribs.length}</span>} to="operations/alerts">
      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        {contribs.slice(0, 8).map((c, i) => (
          <div key={i} style={{ display: "flex", gap: 8, alignItems: "baseline", fontSize: 14 }}>
            <span className="fp-num" style={{ fontWeight: 600, minWidth: 30, textAlign: "right", color: c.points >= 12 ? "var(--crit)" : c.points >= 6 ? "var(--warn)" : "var(--fg)" }}>{c.points}</span>
            <span style={{ fontSize: 12.5, color: "var(--fg-subtle)", textTransform: "uppercase", letterSpacing: 0.05, minWidth: 80, flexShrink: 0 }}>{c.signal_class.replace(/_/g, " ")}</span>
            <span style={{ color: "var(--fg)", minWidth: 0 }}>{c.reason}</span>
          </div>
        ))}
      </div>
    </RcaPanel>
  );
}

// ── What changed ────────────────────────────────────────────────────────────

export function WhatChanged() {
  const { data, err } = usePolled(() => api.eventsFeed({ from: "24h", class: "changes", limit: "12" }), 20_000);
  if (err && !data) return <RcaPanel title="What changed" state="degraded" />;
  if (!data) return <RcaPanel title="What changed" state="inactive" note="Reading…" />;
  const items: FeedItem[] = data.items ?? [];
  if (items.length === 0) return <RcaPanel title="What changed" state="inactive" note="No changes in the last 24h." hint="Topology, inventory and alert-state changes appear here." />;
  return (
    <RcaPanel title="What changed" to="explore/logs">
      <div style={{ display: "flex", flexDirection: "column", gap: 5, maxHeight: 280, overflowY: "auto" }}>
        {items.map((it) => (
          <div key={it.signal_id} style={{ display: "flex", gap: 9, fontSize: 14, alignItems: "baseline" }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: SEV_VAR[it.severity] ?? "var(--fg-subtle)", flexShrink: 0, marginTop: 4 }} />
            <span style={{ color: "var(--fg)", minWidth: 0 }}>{upProto(it.title)}</span>
            <span className="fp-num" style={{ marginLeft: "auto", color: "var(--fg-muted)", whiteSpace: "nowrap" }}>{it.ts.slice(11, 16)}</span>
          </div>
        ))}
      </div>
    </RcaPanel>
  );
}

export function CapacityOutlook() {
  const { data, err } = usePolled(() => api.metricsForecast(), 20_000);
  // The forecast keys rows by device id; an operator reads the hostname.
  const names = useDeviceNames();
  if (err && !data) return <RcaPanel title="Capacity outlook" state="degraded" />;
  if (!data) return <RcaPanel title="Capacity outlook" state="inactive" note="Reading…" />;
  const rows = data.interfaces ?? [];
  if (rows.length === 0) return <RcaPanel title="Capacity outlook" state="inactive" note="No interface utilization data yet." />;
  const trending = rows.filter((r) => r.status === "trending" || r.status === "saturated");
  if (trending.length === 0) {
    const building = rows.filter((r) => r.status === "building_baseline").length;
    // "unsteady": rising, but too unevenly to put a date on the 90 % crossing.
    const unsteady = rows.filter((r) => r.status === "unsteady").length;
    const plural = (n: number) => `${n} interface${n === 1 ? "" : "s"}`;
    return <RcaPanel title="Capacity outlook" state="inactive"
      note={building > 0 ? "Building baseline" : unsteady > 0 ? "No steady trend" : "All interfaces stable"}
      hint={building > 0
        ? `Needs ${data.min_days} days of history — ${plural(building)} still learning their trend.`
        : unsteady > 0
          ? `${plural(unsteady)} rising too unevenly to date a 90% crossing.`
          : "No interfaces trending toward saturation."} />;
  }
  return (
    <RcaPanel title="Capacity outlook" to="analytics/interface-performance">
      {trending.slice(0, 6).map((r, i) => {
        const tone = r.status === "saturated" || r.days_to_90 < 14 ? "var(--crit)" : r.days_to_90 < 30 ? "var(--warn)" : "var(--fg-subtle)";
        return (
          <div key={i} className="fp-row" style={{ borderLeftColor: tone, cursor: "default", gap: 9 }}>
            <span className="fp-num">{deviceDisplayName(r.device, names)}</span>
            <span style={{ color: "var(--fg-muted)" }}>{r.interface}</span>
            <span className="fp-num" style={{ marginLeft: "auto", fontWeight: 600, color: tone }}>
              {r.status === "saturated" ? "at capacity" : `~${Math.round(r.days_to_90)}d to 90%`}
            </span>
            <span className="fp-num" style={{ color: "var(--fg-muted)", fontSize: 12.5 }}>{Math.round(r.current_util_pct)}%</span>
          </div>
        );
      })}
    </RcaPanel>
  );
}

// ── Is data arriving ────────────────────────────────────────────────────────

const SIGNAL_CLASS_LABEL: Record<string, string> = {
  availability: "Availability", device_health: "Device health", path_health: "Path checks", correlation: "Correlation",
};
export function TelemetryCoverage({ health, err }: { health: HealthScoreResp | undefined; err: boolean }) {
  if (err && !health) return <RcaPanel title="Telemetry coverage" state="degraded" />;
  if (!health) return <RcaPanel title="Telemetry coverage" state="inactive" note="Reading…" />;
  const live = new Set(health.signal_classes_live ?? []);
  const stale = new Set(health.stale_inputs ?? []);
  const classes = ["availability", "device_health", "path_health", "correlation"];
  return (
    <RcaPanel title="Telemetry coverage" action={<span>{live.size}/{classes.length} live</span>}>
      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        {classes.map((c) => {
          const isLive = live.has(c), isStale = stale.has(c);
          const tone = !isLive ? "var(--fg-subtle)" : isStale ? "var(--warn)" : "var(--ok)";
          const txt = !isLive ? "inactive" : isStale ? "stale" : "live";
          return (
            <div key={c} style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 14 }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: tone, flexShrink: 0 }} />
              <span style={{ color: "var(--fg)" }}>{SIGNAL_CLASS_LABEL[c] ?? c}</span>
              <span style={{ marginLeft: "auto", fontSize: 12.5, textTransform: "uppercase", letterSpacing: 0.06, color: tone, fontWeight: 600 }}>{txt}</span>
            </div>
          );
        })}
      </div>
      <div className="fp-empty-h" style={{ marginTop: 2 }}>Trust the health score in proportion to live coverage (confidence: {CONF_LABEL[health.confidence] ?? health.confidence}).</div>
    </RcaPanel>
  );
}

// Platform health and internal checks are the platform admin's only: the stack
// read is cross-tenant, so a tenant user would see a permanently degraded panel.
const STACK_TONE: Record<string, string> = { healthy: "var(--ok)", degraded: "var(--warn)", down: "var(--crit)" };
export function PlatformHealth() {
  const { data, err } = usePolled(() => api.stackHealth(), 20_000);
  if (err && !data) return <RcaPanel title="Platform health (internal)" state="degraded" />;
  if (!data) return <RcaPanel title="Platform health (internal)" state="inactive" note="Reading…" />;
  const tone = STACK_TONE[data.overall] ?? "var(--fg-subtle)";
  return (
    <RcaPanel title="Platform health (internal)">
      <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
        <span className="fp-tag" style={{ color: tone, border: `1px solid ${tone}`, textTransform: "capitalize" }}>{data.overall}</span>
        <span style={{ fontSize: 14, color: "var(--fg-muted)" }}>
          <b className="fp-num" style={{ color: "var(--ok)" }}>{data.up}</b> up
          {data.degraded > 0 && <> · <b className="fp-num" style={{ color: "var(--warn)" }}>{data.degraded}</b> degraded</>}
          {data.down > 0 && <> · <b className="fp-num" style={{ color: "var(--crit)" }}>{data.down}</b> down</>}
        </span>
      </div>
      <div className="fp-empty-h">The platform's own services — separate from the customer-network health above.</div>
    </RcaPanel>
  );
}

export function InternalMonitoringChecks({ internal }: { internal: CorrObject[] }) {
  return (
    <RcaPanel title="Internal monitoring checks" to="investigate/rca">
      <div style={{ fontSize: 14, color: "var(--fg-muted)" }}>
        <b className="fp-num" style={{ fontSize: 18, color: "var(--fg)" }}>{internal.length}</b> internal self-monitoring object{internal.length === 1 ? "" : "s"}
      </div>
      <div className="fp-empty-h">Hidden from customer RCA by design — the platform watching itself.</div>
    </RcaPanel>
  );
}

// ── KPI strip ───────────────────────────────────────────────────────────────

// KPI history persists (localStorage) so the trend is populated on reload. The
// key is SCOPED BY TENANT (§3a, M21): a platform owner switching tenant, or a
// new user on a shared browser, never seeds a sparkline from another scope.
// clearSession() sweeps the whole netops.fp.kpihist.* family at session edges,
// so the prefix is kept as it was.
const KPI_HIST_PREFIX = "netops.fp.kpihist";
/** Exported for the M21 isolation regression test only — not a public API. */
export function kpiHistKey(): string {
  const scope = getActiveScope() || sessionTenantKey();
  return scope ? `${KPI_HIST_PREFIX}.${scope}` : KPI_HIST_PREFIX;
}
function loadKpiHist(): Record<string, number[]> { try { return JSON.parse(localStorage.getItem(kpiHistKey()) || "{}"); } catch { return {}; } }

function Spark({ pts, color }: { pts: number[]; color: string }) {
  const v = pts.filter((n) => Number.isFinite(n));
  if (v.length < 3) return <div style={{ height: 16, marginTop: 5 }} />;
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

export function KpiStrip({ problems, health, stats }: { problems: CorrObject[] | undefined; health: HealthScoreResp | undefined; stats: CorrStats | undefined }) {
  const { devices, sites } = impactOf(problems ?? [], health);
  const insufficient = !health || health.coverage_status === "INSUFFICIENT_TELEMETRY" || health.score == null;
  const scoreColor = BAND_VAR[health?.band ?? ""] ?? "var(--fg-subtle)";
  const live = (health?.signal_classes_live ?? []).length, stale = (health?.stale_inputs ?? []).length;
  const confirmed = stats?.open_confirmed ?? 0, suspected = stats?.open_suspected ?? 0;

  // One real sample per answer, persisted so the trend survives a reload.
  const [hist, setHist] = useState<Record<string, number[]>>(loadKpiHist);
  useEffect(() => {
    if (!health && !stats && !problems) return;
    setHist((cur) => {
      const next = { ...cur };
      const push = (k: string, v: number) => { next[k] = (next[k] ?? []).concat(v).slice(-24); };
      push("health", insufficient ? NaN : (health?.score ?? NaN));
      push("confirmed", confirmed); push("suspected", suspected); push("sites", sites.size); push("devices", devices.size);
      try { localStorage.setItem(kpiHistKey(), JSON.stringify(next)); } catch { /* quota */ }
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [health, stats, problems]);
  const deltaOf = (k: string): number | null => {
    const a = (hist[k] ?? []).filter(Number.isFinite);
    return a.length >= 3 ? a[a.length - 1] - a[0] : null;
  };
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
    <div className="kpi-grid" data-testid="overview-kpis">
      {cell("Health score", insufficient ? "—" : health!.score, scoreColor, insufficient ? "insufficient" : (health?.band ?? ""), "operations/alerts", "health")}
      {cell("Active incidents", confirmed, confirmed > 0 ? "var(--crit)" : undefined, "confirmed RCA", "investigate/rca?tier=confirmed", "confirmed")}
      {cell("Suspected RCA", suspected, suspected > 0 ? "var(--warn)" : undefined, "candidates", "investigate/rca?tier=suspected", "suspected")}
      {cell("Impacted sites", sites.size, undefined, sites.size ? undefined : "none tagged", "investigate/topology", "sites")}
      {cell("Impacted devices", devices.size, undefined, undefined, "investigate/topology", "devices")}
      {cell("Telemetry", `${live}/4`, stale > 0 ? "var(--warn)" : live >= 2 ? "var(--ok)" : "var(--fg-subtle)", stale > 0 ? `${stale} stale` : "signal classes", "operations/alerts")}
    </div>
  );
}
