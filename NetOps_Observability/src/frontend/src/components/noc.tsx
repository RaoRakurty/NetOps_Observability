import { ReactNode } from "react";

// noc.tsx — the shared premium NOC workspace kit. One source of truth for the
// section header, status strip, KPI cards and badges so every Monitoring / Event
// Management surface reads as the SAME enterprise product (consistency mandate).
// Styling is token-driven (premium glass via the active theme), reusing the
// .cc-* style layer introduced with the Command Center. Identity faces.

// ── Page header: title + subtitle + status chips ───────────────────────────────
export function NocHeader({ title, subtitle, chips, children }: {
  title: string; subtitle: string; chips?: ReactNode; children?: ReactNode;
}) {
  return (
    <div className="cc-hero">
      <div className="cc-hero-head">
        <div>
          <h1 className="cc-h1">{title}</h1>
          <p className="cc-sub">{subtitle}</p>
        </div>
        {chips && <div className="cc-chips-row">{chips}</div>}
      </div>
      {children}
    </div>
  );
}

// ── Status chip ─────────────────────────────────────────────────────────────────
export function Chip({ label, tone = "var(--fg-subtle)", title }: { label: string; tone?: string; title?: string }) {
  return <span className="cc-badge" style={{ color: tone, borderColor: tone }} title={title}>{label}</span>;
}

// ── Live pulse chip ─────────────────────────────────────────────────────────────
export function LiveChip({ label = "Live", detail }: { label?: string; detail?: string }) {
  return <span className="cc-live"><span className="cc-live-dot" /> {label}{detail ? ` · ${detail}` : ""}</span>;
}

// ── KPI strip + card (summary metrics with operator interpretation) ─────────────
export function NocKpis({ children, cols }: { children: ReactNode; cols?: number }) {
  return <div className={`cc-kpis${cols === 4 ? " cc-kpis-4" : ""}`}>{children}</div>;
}
export function NocKpi({ n, label, interp, tone, href }: {
  n: ReactNode; label: string; interp?: string; tone?: string; href?: string;
}) {
  const body = (
    <>
      <div className="cc-kpi-n" style={tone ? { color: tone } : undefined}>{n}</div>
      <div className="cc-kpi-l">{label}</div>
      {interp && <div className="cc-kpi-i">{interp}</div>}
    </>
  );
  return href ? <a className="cc-kpi" href={href}>{body}</a> : <div className="cc-kpi">{body}</div>;
}

// ── Decision / context strip ────────────────────────────────────────────────────
export function NocDecision({ children }: { children: ReactNode }) {
  return <div className="cc-decision">{children}</div>;
}

// ── Badge (uppercase NOC chip; tone communicates operational meaning) ───────────
export function Badge({ label, tone = "var(--fg-muted)", title }: { label: string; tone?: string; title?: string }) {
  return <span className="cc-badge" style={{ color: tone, borderColor: tone }} title={title}>{label}</span>;
}

// Shared tone helpers so severity / state colour is identical everywhere.
export const sevTone = (s: string): string => {
  const k = (s || "").toLowerCase();
  if (k === "critical" || k === "crit" || k === "error") return "var(--crit)";
  if (k === "major" || k === "high") return "var(--warn)";
  if (k === "warning" || k === "warn" || k === "medium") return "var(--warn)";
  if (k === "ok" || k === "healthy" || k === "resolved" || k === "info") return "var(--ok)";
  return "var(--fg-subtle)";
};

// Meaningful empty/missing labels — never a bare "—".
export function Muted({ children }: { children: ReactNode }) {
  return <span style={{ color: "var(--fg-subtle)" }}>{children}</span>;
}
