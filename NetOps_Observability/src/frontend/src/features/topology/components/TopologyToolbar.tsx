// TopologyToolbar — the top control bar. Left slot (children) carries the
// workflow + overlay selectors from the canvas; right slot holds the density
// control, labels toggle and zoom/fit actions. Calm, compact, icon-driven.

import type React from "react";

type Density = "executive" | "operator" | "engineer" | "incident";

const DENSITIES: { id: Density; label: string }[] = [
  { id: "executive", label: "Exec" },
  { id: "operator", label: "Operator" },
  { id: "engineer", label: "Engineer" },
  { id: "incident", label: "Incident" },
];

const iconBtn: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  width: 28,
  height: 28,
  border: "1px solid var(--border)",
  background: "var(--surface)",
  color: "var(--fg-muted)",
  borderRadius: 6,
  cursor: "pointer",
  fontSize: 14,
  lineHeight: 1,
};

export default function TopologyToolbar({
  onFit,
  onZoomIn,
  onZoomOut,
  showAllLabels,
  onToggleLabels,
  density,
  onDensityChange,
  onResetLayout,
  layoutPinned,
  children,
}: {
  onFit: () => void;
  onZoomIn: () => void;
  onZoomOut: () => void;
  showAllLabels: boolean;
  onToggleLabels: () => void;
  density: Density;
  onDensityChange: (d: Density) => void;
  onResetLayout?: () => void;
  layoutPinned?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "8px 12px",
        background: "var(--panel)",
        borderBottom: "1px solid var(--border)",
        flexWrap: "wrap",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>{children}</div>

      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
        <div
          role="group"
          aria-label="Density"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 2,
            padding: 2,
            border: "1px solid var(--border)",
            borderRadius: 7,
            background: "var(--surface)",
          }}
        >
          {DENSITIES.map((d) => {
            const active = d.id === density;
            return (
              <button
                key={d.id}
                type="button"
                onClick={() => onDensityChange(d.id)}
                aria-pressed={active}
                style={{
                  border: "none",
                  borderRadius: 5,
                  padding: "4px 9px",
                  fontSize: 11,
                  fontWeight: active ? 600 : 500,
                  cursor: "pointer",
                  whiteSpace: "nowrap",
                  background: active ? "var(--panel)" : "transparent",
                  color: active ? "var(--fg)" : "var(--fg-muted)",
                  boxShadow: active ? "0 1px 2px rgba(0,0,0,0.12)" : "none",
                }}
              >
                {d.label}
              </button>
            );
          })}
        </div>

        <button
          type="button"
          onClick={onToggleLabels}
          aria-pressed={showAllLabels}
          title={showAllLabels ? "Hide interface labels" : "Show all labels"}
          style={{
            border: "1px solid var(--border)",
            background: showAllLabels ? "var(--panel)" : "var(--surface)",
            color: showAllLabels ? "var(--fg)" : "var(--fg-muted)",
            borderRadius: 6,
            padding: "5px 10px",
            fontSize: 11,
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          Labels
        </button>

        {onResetLayout && (
          <button
            type="button"
            onClick={onResetLayout}
            disabled={!layoutPinned}
            title={layoutPinned ? "Reset to automatic (ELK) layout" : "No pinned positions"}
            style={{
              border: "1px solid var(--border)",
              background: "var(--surface)",
              color: layoutPinned ? "var(--fg-muted)" : "var(--fg-subtle)",
              borderRadius: 6,
              padding: "5px 10px",
              fontSize: 11,
              fontWeight: 600,
              cursor: layoutPinned ? "pointer" : "default",
              opacity: layoutPinned ? 1 : 0.55,
            }}
          >
            Reset layout
          </button>
        )}

        <div style={{ display: "inline-flex", gap: 4 }}>
          <button type="button" onClick={onZoomOut} title="Zoom out" aria-label="Zoom out" style={iconBtn}>
            −
          </button>
          <button type="button" onClick={onZoomIn} title="Zoom in" aria-label="Zoom in" style={iconBtn}>
            +
          </button>
          <button type="button" onClick={onFit} title="Fit to view" aria-label="Fit to view" style={iconBtn}>
            ⤢
          </button>
        </div>
      </div>
    </div>
  );
}
