// Shared design-system primitives for the dense admin surfaces.
// Extracted from the Security Policy page so every Administration view shares
// one dense, status-coded, accessible visual language instead of re-rolling it.
// Plain CSS (ds-* classes in styles.css) — no new dependencies.

import { ReactNode, CSSProperties, useEffect, useRef } from "react";
import Icon from "./Icon";

export type StatTone = "" | "accent" | "good" | "warn" | "bad";

// Modal — a centered, accessible dialog shell shared by the guided-setup flows.
// Handles the scrim, the branded header (logo + title + subtitle + close), and
// the modal a11y contract: focus moves in on open and is restored on close,
// Escape and scrim-click dismiss, and background scroll is locked while open.
export function Modal({ title, subtitle, logo, onClose, children, wide }: {
  title: string;
  subtitle?: string;
  logo?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean; // near-full-viewport variant (panel zoom / deep-look views)
}) {
  const ref = useRef<HTMLDivElement>(null);
  // Keep the latest onClose without re-running the mount effect: parents often pass a
  // fresh onClose each render, and re-running this effect would call ref.focus() on
  // EVERY render — stealing focus from inputs after a single keystroke (the form-focus
  // bug). Effect must run ONCE on mount only.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    document.body.style.overflow = "hidden";
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { onCloseRef.current(); return; }
      // Focus containment (2.4.3): Tab cycles within the dialog — the page
      // behind stays rendered, so without this focus walks out of the modal.
      if (e.key === "Tab") {
        const root = ref.current;
        if (!root) return;
        const els = root.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        );
        if (els.length === 0) return;
        const first = els[0];
        const last = els[els.length - 1];
        const active = document.activeElement;
        if (!root.contains(active)) { e.preventDefault(); first.focus(); }
        else if (e.shiftKey && (active === first || active === root)) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && active === last) { e.preventDefault(); first.focus(); }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
      prev?.focus?.();
    };
  }, []);
  return (
    <div className="ds-modal-scrim" onClick={onClose}>
      <div className={`ds-modal${wide ? " ds-modal-wide" : ""}`} role="dialog" aria-modal="true" aria-label={title} ref={ref} tabIndex={-1} onClick={(e) => e.stopPropagation()}>
        <div className="ds-modal-head">
          {logo}
          <div className="ds-modal-title">
            <h2>{title}</h2>
            {subtitle && <p className="mini-meta">{subtitle}</p>}
          </div>
          <button className="drawer-close" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="ds-modal-body">{children}</div>
      </div>
    </div>
  );
}

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

// Segmented — a soft segmented control for view/mode switches. Exposed as a
// toggle-button group (aria-pressed), NOT an ARIA tablist: consumers render
// plain view swaps without tabpanel/roving-focus wiring, and plain buttons
// are fully keyboard operable as-is (4.1.2).
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
    <div className="ds-seg" role="group" aria-label={ariaLabel}>
      {options.map((o) => (
        <button
          key={o.value}
          aria-pressed={value === o.value}
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
