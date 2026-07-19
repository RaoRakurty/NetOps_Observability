// App Observability — shared UI primitives (#81 P3F).
//
// Every component here is built on the EXISTING design system — the `Chip` from
// noc.tsx, the `var(--*)` semantic tokens, and the `ds-*`/`cc-*` classes — so it
// inherits the app's fonts (Inter / Space Grotesk / IBM Plex Mono), theme colors,
// and light/dark switching for free. No new fonts, hex, or spacing are introduced.

import { ReactNode, useEffect } from "react";
import { Chip } from "../../components/noc";
import { providerDescriptor, providerConsoleName, ProviderIcon } from "./providers";
import type { Confidence, Health, RootDomain, AttrSource, UnderlayState, RcaDrawerModel, EvidenceCategory } from "./types";

// ── Origin (which cloud an investigation comes from) ─────────────────────────
// Registry-driven (providers.tsx): the SAME descriptor serves the connector
// gallery, the wizard and every origin cell, so a provider looks identical
// everywhere in the product — and a newly registered provider renders here
// with zero edits. The mark is decorative; the adjacent text carries the
// meaning, so a screen reader hears the provider name once rather than twice.
// originName keeps the pre-registry origin vocabulary: AWS, Azure, Google Cloud
// (short form for the compact clouds, full name for Google Cloud — the exact
// labels these cells always used).
function originName(p: string): string {
  const d = providerDescriptor(p);
  return p === "gcp" ? d.label : d.short;
}

const originShort = (p: string): string => (p === "—" ? "—" : providerDescriptor(p).short);

export function ProviderMark({ provider, size = 14 }: { provider: string; size?: number }) {
  if (provider === "—") return null;
  return <ProviderIcon provider={provider} size={size} />;
}

export function ProviderBadge({ provider, compact = false }: { provider: string; compact?: boolean }) {
  if (provider === "—") return null;
  return (
    <span className="ao-prov" title={originName(provider)}>
      <span className="ao-prov-mark" aria-hidden="true"><ProviderMark provider={provider} /></span>
      <span className="ao-prov-l">{compact ? originShort(provider) : originName(provider)}</span>
    </span>
  );
}

// Origin cells sit inside FIXED-HEIGHT virtualized table rows, so the cell can
// never wrap to a second line (wrapped badges paint over the row below — user
// report 2026-07-16). At most this many badges render; the rest collapse into
// a "+N" chip whose tooltip (like the cell's) lists every cloud in full.
const ORIGIN_MAX_BADGES = 2;

// The Origin cell for an investigation. Shows EVERY cloud actually present in the
// object's evidence (a genuinely multi-cloud incident lists them all — we never
// collapse it to a single "primary" cloud we did not measure). No cloud in the
// evidence is NOT an unknown: it is an on-prem / network investigation, and it
// says so, with a tooltip explaining that the evidence carried no cloud signal.
// Multi-cloud cells use the short provider names (AWS · Azure · GCP — the same
// vocabulary as the Accounts table) so two clouds fit on ONE line.
export function OriginCell({ providers }: { providers: string[] }) {
  if (!providers.length) {
    return (
      <span className="ao-muted" title="No cloud signal is attached to this investigation — its evidence is network / on-premises telemetry.">
        On-prem
      </span>
    );
  }
  const full = providers.map((p) => originName(p)).join(" + ");
  const compact = providers.length > 1;
  const shown = providers.slice(0, ORIGIN_MAX_BADGES);
  const extra = providers.length - shown.length;
  return (
    <span className="ao-provs" title={full}>
      {shown.map((p) => <ProviderBadge key={p} provider={p} compact={compact} />)}
      {extra > 0 && <span className="ao-prov ao-prov--more" title={full}>+{extra}</span>}
    </span>
  );
}

// Finding-category badge — the anti-black-box ledger. Discriminating (the
// differentiator) reads as accent; contradicting as crit; missing stays muted
// (an honest gap, not an alarm); recovery and grounded read calm-positive.
const EV_CAT_META: Record<EvidenceCategory, { label: string; tone: string }> = {
  grounded: { label: "Grounded", tone: "var(--ok)" },
  contradicting: { label: "Contradicting", tone: "var(--crit)" },
  discriminating: { label: "Discriminating", tone: "var(--accent)" },
  missing: { label: "Missing", tone: "var(--fg-subtle)" },
  recovery: { label: "Recovery", tone: "var(--ok)" },
};

export function EvidenceCategoryBadge({ category }: { category: EvidenceCategory }) {
  const m = EV_CAT_META[category];
  return <Chip label={m.label} tone={m.tone} title={`evidence: ${m.label.toLowerCase()}`} />;
}

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

// Short, OFFICIAL labels — never truncate "DATABASE DEPENDE…". (Chip never clips; the
// .ao-root class keeps it on one line at a readable width.)
const ROOT_LABEL: Record<RootDomain, string> = {
  application: "Application", deployment: "Deployment", cloud_resource: "Cloud Resource",
  cloud_security_policy: "Cloud Policy", cloud_network: "Cloud Network",
  cloud_provider: "Cloud Provider", hybrid_underlay: "Hybrid Underlay",
  external_saas: "External SaaS", dns: "DNS", certificate_tls: "Certificate/TLS",
  identity_auth: "Identity/Auth", database_dependency: "Database", unknown: "Unknown",
};

export function RootDomainBadge({ domain }: { domain: RootDomain }) {
  return <span className="ao-root"><Chip label={ROOT_LABEL[domain]} tone={DOMAIN_TONE[domain] ?? "var(--fg-subtle)"} /></span>;
}

// Underlay involvement → explicit text + tone (never a bare "—").
export function underlayDisplay(u: UnderlayState): { text: string; tone: string } {
  switch (u.kind) {
    case "none": return { text: "No impact", tone: "var(--ok)" };
    case "suspected": return { text: `Suspected: ${u.seam}`, tone: "var(--warn)" };
    case "confirmed": return { text: `Confirmed: ${u.seam}`, tone: "var(--crit)" };
    case "not_checked": return { text: "Not checked", tone: "var(--fg-subtle)" };
    default: return { text: "Unknown", tone: "var(--fg-subtle)" };
  }
}

export function UnderlayCell({ u }: { u: UnderlayState }) {
  const d = underlayDisplay(u);
  return <span className="ao-underlay" style={{ color: d.tone }}>{d.text}</span>;
}

// Console pivot — the deep-link from a Correlix row into the provider's own
// console. The URL is server-built and re-validated at the mapping layer
// (safeConsoleUrl); an empty href renders nothing rather than a dead link.
// stopPropagation keeps the row's drawer from opening under the click.
export function consoleName(provider: string): string {
  return providerConsoleName(provider);
}

export function ConsoleLink({ href, label, compact }: { href: string; label: string; compact?: boolean }) {
  if (!href) return null;
  return (
    <a className={`ao-console-link${compact ? " is-compact" : ""}`} href={href}
      target="_blank" rel="noopener noreferrer" title={compact ? label : undefined}
      onClick={(e) => e.stopPropagation()}>
      {compact ? "↗" : <>{label} <span aria-hidden="true">↗</span></>}
    </a>
  );
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

// MetricCard — a NOC KPI tile: prominent number, small UPPERCASE label, optional
// trend subtext, and a subtle left severity accent (only when useful). All tokens.
export function MetricCard({ label, value, trend, sub, tone }: {
  label: string; value: ReactNode; trend?: ReactNode; sub?: ReactNode;
  tone?: "accent" | "good" | "warn" | "bad";
}) {
  const foot = trend ?? sub;
  return (
    <div className={`ao-card${tone ? " ao-card--" + tone : ""}`}>
      <div className="ao-card-l">{label}</div>
      <div className="ao-card-v">{value}</div>
      {foot != null && <div className="ao-card-s">{foot}</div>}
    </div>
  );
}

// CardGroup — a labelled operational group (Impact / Coverage / Change).
export function CardGroup({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="ao-group">
      <div className="ao-group-h">{title}</div>
      <div className="ao-group-cards">{children}</div>
    </section>
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

// RcaDrawer — the right-side RCA/evidence panel opened from an impacted-app row.
// Always shows root domain + confidence + supporting AND contradicting evidence +
// the recommended next action, so a verdict is never a bare label.
export function RcaDrawer({ rca, onClose, onViewDetail, onOpenEvidence, onViewUnderlay }: {
  rca: RcaDrawerModel; onClose: () => void;
  onViewDetail: () => void; onOpenEvidence: () => void; onViewUnderlay: () => void;
}) {
  const supporting = rca.evidence.filter((e) => e.kind === "supporting");
  const contradicting = rca.evidence.filter((e) => e.kind === "contradicting");
  return (
    <EvidenceDrawer
      title={rca.app}
      subtitle={<span className="ao-drawer-badges"><HealthBadge status={rca.health} /><RootDomainBadge domain={rca.rootDomain} /><ConfidenceBadge level={rca.confidence} /></span>}
      onClose={onClose}
    >
      <div className="ao-rca-drawer">
        <div className="ao-rca-row"><span className="ao-rca-k">Likely root domain</span><span><RootDomainBadge domain={rca.rootDomain} /></span></div>
        <div className="ao-rca-row"><span className="ao-rca-k">Confidence</span><span><ConfidenceBadge level={rca.confidence} /></span></div>
        <div className="ao-rca-row"><span className="ao-rca-k">Recommended owner</span><span className="ao-rca-owner">{rca.recommendedOwner}</span></div>

        <div className="ao-ev-h">Supporting evidence</div>
        <ul className="ao-ev-list">
          {supporting.map((e, i) => <li key={i} className="ao-ev ao-ev--ok"><span className="ao-ev-i">✓</span>{e.text}</li>)}
        </ul>

        <div className="ao-ev-h">Contradicting evidence</div>
        <ul className="ao-ev-list">
          {contradicting.length
            ? contradicting.map((e, i) => <li key={i} className="ao-ev ao-ev--no"><span className="ao-ev-i">✕</span>{e.text}</li>)
            : <li className="ao-ev ao-muted"><span className="ao-ev-i">–</span>none above floor</li>}
        </ul>

        <div className="ao-next">
          <div className="ao-next-h">Recommended next action</div>
          <div className="ao-next-v">{rca.nextAction}</div>
        </div>

        <div className="ao-drawer-actions">
          <button className="ao-btn ao-btn--primary" onClick={onViewDetail}>View App Detail</button>
          <button className="ao-btn" onClick={onOpenEvidence}>Open Evidence</button>
          <button className="ao-btn" onClick={onViewUnderlay}>View Underlay Path</button>
        </div>
      </div>
    </EvidenceDrawer>
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
