// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { ReactNode } from "react";
import AskIris from "./AskIris";

// noc.tsx — the shared premium NOC workspace kit. One source of truth for the
// section header, status strip, KPI cards and badges so every Monitoring / Event
// Management surface reads as the SAME enterprise product (consistency mandate).
// Styling is token-driven (premium glass via the active theme), reusing the
// .cc-* style layer introduced with the Command Center. Identity faces.

// ── Page header: title + status chips ──────────────────────────────────────────
// `subtitle` is legacy and optional: a swept page passes `topic` instead, and the
// sentence that stood under the title becomes an authored explanation behind the
// `(i)` (docs/design/UI_WORDS_IRIS_EXPLAINS_2026-09-06.md).
export function NocHeader({ title, subtitle, topic, chips, children }: {
  title: string; subtitle?: string; topic?: string; chips?: ReactNode; children?: ReactNode;
}) {
  return (
    <div className="cc-hero">
      <div className="cc-hero-head">
        <div>
          <div className="cc-h1-row">
            <h1 className="cc-h1">{title}</h1>
            {topic && <AskIris topic={topic} label={title} />}
          </div>
          {subtitle && <p className="cc-sub">{subtitle}</p>}
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
// A swept tile passes `topic` and carries a number, a name and a 16px `(i)`.
// `interp` is the pre-sweep caption and stays only for the pages later sweeps
// have not reached; passing both is meaningless, so `topic` wins.
export function NocKpi({ n, label, interp, topic, tone, href }: {
  n: ReactNode; label: string; interp?: string; topic?: string; tone?: string; href?: string;
}) {
  const body = (
    <>
      <div className="cc-kpi-n" style={tone ? { color: tone } : undefined}>{n}</div>
      <div className="cc-kpi-l">{label}</div>
      {!topic && interp && <div className="cc-kpi-i">{interp}</div>}
    </>
  );
  const tile = href ? <a className="cc-kpi" href={href}>{body}</a> : <div className="cc-kpi">{body}</div>;
  if (!topic) return tile;
  return (
    <div className="cc-kpi-cell">
      {tile}
      <AskIris topic={topic} label={label} className="cc-kpi-ask" />
    </div>
  );
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
