// App Observability — shared UI primitives (#81 P3F).
//
// Every component here is built on the EXISTING design system — the `Chip` from
// noc.tsx, the `var(--*)` semantic tokens, and the `ds-*`/`cc-*` classes — so it
// inherits the app's fonts (Inter / Space Grotesk / IBM Plex Mono), theme colors,
// and light/dark switching for free. No new fonts, hex, or spacing are introduced.

import { ReactNode, useEffect } from "react";
import { Chip } from "../../components/noc";
import type { Confidence, Health, RootDomain, AttrSource } from "./types";

// Confidence ladder → tone. Higher confidence reads stronger; unknown is visible but
// calm (muted), not alarming — alarm is reserved for health/severity.
const CONF_TONE: Record<Confidence, string> = {
  confirmed: "var(--ok)",
  strong: "var(--accent)",
  suspected: "var(--warn)",
  weak: "var(--fg-subtle)",
  unknown: "var(--fg-subtle)",
};

export function ConfidenceBadge({ level, title }: { level: Confidence; title?: string }) {
  return <Chip label={level} tone={CONF_TONE[level]} title={title ?? `confidence: ${level}`} />;
}

// Health → tone. Down/degraded use the severity ramp; unknown stays muted (honest,
// not alarming) unless the row's traffic/impact elevates it elsewhere.
const HEALTH_TONE: Record<Health, string> = {
  healthy: "var(--ok)",
  degraded: "var(--warn)",
  down: "var(--crit)",
  unknown: "var(--fg-subtle)",
};

export function HealthBadge({ status }: { status: Health }) {
  return <Chip label={status} tone={HEALTH_TONE[status]} />;
}

// Root-domain badge — which domain owns the incident. Calm accent by default; the
// network/provider domains lean warn to read as "outside the app".
const DOMAIN_TONE: Partial<Record<RootDomain, string>> = {
  application: "var(--accent)",
  deployment: "var(--warn)",
  database_dependency: "var(--warn)",
  cloud_security_policy: "var(--warn)",
  cloud_network: "var(--warn)",
  hybrid_underlay: "var(--warn)",
  cloud_provider: "var(--crit)",
  external_saas: "var(--fg-subtle)",
  unknown: "var(--fg-subtle)",
};

export function RootDomainBadge({ domain }: { domain: RootDomain }) {
  if (domain === "unknown") return <span className="ao-muted">—</span>;
  return <Chip label={domain.replace(/_/g, " ")} tone={DOMAIN_TONE[domain] ?? "var(--accent)"} />;
}

// Identity pill — app name + the source that attributed it, so identity is never a
// bare label without its provenance.
const SRC_LABEL: Record<AttrSource, string> = {
  cloud_tag: "tag", cloud_graph: "graph", operator_catalog: "operator",
  firewall_appid: "firewall", domain: "domain", ip_catalog: "ip", unknown: "—",
};

export function AppIdentityPill({ app, source, confidence }: { app: string; source: AttrSource; confidence: Confidence }) {
  if (!app || confidence === "unknown") {
    return <span className="ao-unknown" title="no confident attribution">unknown</span>;
  }
  return (
    <span className="ao-pill" title={`attributed by ${SRC_LABEL[source]} · ${confidence}`}>
      <strong>{app}</strong>
      <span className="ao-pill-src">{SRC_LABEL[source]}</span>
    </span>
  );
}

// MetricCard — a KPI tile in the house style (uses the cc-kpi look via local class
// that maps to the same tokens). tone ∈ accent|good|warn|bad.
export function MetricCard({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: "accent" | "good" | "warn" | "bad" }) {
  return (
    <div className={`ao-card${tone ? " ao-card--" + tone : ""}`}>
      <div className="ao-card-v">{value}</div>
      <div className="ao-card-l">{label}</div>
      {sub != null && <div className="ao-card-s">{sub}</div>}
    </div>
  );
}

export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="ao-empty">
      <div className="ao-empty-t">{title}</div>
      {hint && <div className="ao-empty-h">{hint}</div>}
      {action}
    </div>
  );
}

// FilterBar — a thin row of labelled <select> chips, styled like the existing search.
export interface FilterDef {
  key: string;
  label: string;
  options: { value: string; label: string }[];
}

export function FilterBar({ filters, value, onChange, children }: {
  filters: FilterDef[];
  value: Record<string, string>;
  onChange: (key: string, v: string) => void;
  children?: ReactNode;
}) {
  return (
    <div className="ao-filterbar">
      {filters.map((f) => (
        <label key={f.key} className="ao-filter">
          <span className="ao-filter-l">{f.label}</span>
          <select className="ao-select" value={value[f.key] ?? ""} onChange={(e) => onChange(f.key, e.target.value)}>
            <option value="">all</option>
            {f.options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
      ))}
      {children}
    </div>
  );
}

// EvidenceDrawer — right-side panel (the ev-detail-scrim pattern Events uses), so an
// RCA/identity claim always shows its evidence + confidence + reason.
export function EvidenceDrawer({ title, subtitle, onClose, children }: { title: string; subtitle?: ReactNode; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="ev-detail-scrim" onClick={onClose}>
      <aside className="ev-detail ao-drawer" onClick={(e) => e.stopPropagation()}>
        <header className="ev-detail-h">
          <div>
            <div className="ao-drawer-t">{title}</div>
            {subtitle && <div className="ao-drawer-s">{subtitle}</div>}
          </div>
          <button className="ao-x" onClick={onClose} aria-label="Close">×</button>
        </header>
        <div className="ao-drawer-body">{children}</div>
      </aside>
    </div>
  );
}

// fmt helpers (shared by the tabs)
export const fmtBps = (n: number): string => {
  if (!n) return "—";
  const u = ["bps", "Kbps", "Mbps", "Gbps"]; let i = 0; let v = n;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
};
export const fmtBytes = (n: number): string => {
  if (!n) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
};
export const ago = (iso?: string): string => {
  if (!iso) return "—";
  const ms = Date.now() - new Date(iso).getTime();
  const m = Math.round(ms / 60000);
  if (m < 1) return "now"; if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60); if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
};
