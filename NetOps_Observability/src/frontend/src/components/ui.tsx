// Shared design-system primitives for the Datadog-style admin surfaces.
// Extracted from the Security Policy page so every Administration view shares
// one dense, status-coded, accessible visual language instead of re-rolling it.
// Plain CSS (ds-* classes in styles.css) — no new dependencies.

import { ReactNode, CSSProperties } from "react";
import Icon from "./Icon";

export type StatTone = "" | "accent" | "good" | "warn" | "bad";

// InfoTip — a quiet "i" affordance that reveals explanatory copy on hover/focus.
// Keeps dense surfaces free of verbose inline prose: the parameter and its
// control stay visible; the "why" is one hover away. `label` is the plain-text
// fallback announced to assistive tech (children may be rich markup).
export function InfoTip({ children, label }: { children: ReactNode; label: string }) {
  return (
    <span className="ds-info" tabIndex={0} role="note" aria-label={label}>
      <Icon name="info" size={13} />
      <span className="ds-tip" role="tooltip">{children}</span>
    </span>
  );
}

// StatStrip + Stat — the data-dense "indicators first" KPI row that leads a view.
export function StatStrip({ children }: { children: ReactNode }) {
  return <div className="ds-stats">{children}</div>;
}

export function Stat({ label, value, tone = "" }: { label: string; value: ReactNode; tone?: StatTone }) {
  return (
    <div className={`ds-stat ${tone}`}>
      <span className="ds-stat-num mono">{value}</span>
      <span className="ds-stat-label">{label}</span>
    </div>
  );
}

// Segmented — a soft segmented control for view/mode switches (tab semantics).
export function Segmented<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
}: {
  value: T;
  options: { value: T; label: string; title?: string }[];
  onChange: (v: T) => void;
  ariaLabel?: string;
}) {
  return (
    <div className="ds-seg" role="tablist" aria-label={ariaLabel}>
      {options.map((o) => (
        <button
          key={o.value}
          role="tab"
          aria-selected={value === o.value}
          title={o.title}
          className={value === o.value ? "active" : ""}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

// Skeleton — shimmer placeholder for >300ms loads (respects reduced-motion).
export function Skeleton({ w, h = 12, style }: { w?: number | string; h?: number; style?: CSSProperties }) {
  return <span className="ds-skeleton" style={{ width: w, height: h, display: "inline-block", ...style }} />;
}
