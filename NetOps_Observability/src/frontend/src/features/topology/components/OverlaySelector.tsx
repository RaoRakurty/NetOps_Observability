// OverlaySelector — compact segmented control over the available overlays.
// Overlays the view can't satisfy (available:false) render disabled + muted so
// the operator sees what's possible without being misled by empty data.

import type { OverlayKind, TopologyOverlay } from "../api/topologyTypes";

export default function OverlaySelector({
  value,
  overlays,
  onChange,
}: {
  value: OverlayKind;
  overlays: TopologyOverlay[];
  onChange: (k: OverlayKind) => void;
}) {
  return (
    <div
      role="group"
      aria-label="Overlay"
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
      {overlays.map((o) => {
        const active = o.kind === value;
        const disabled = !o.available;
        return (
          <button
            key={o.kind}
            type="button"
            disabled={disabled}
            onClick={() => !disabled && onChange(o.kind)}
            title={o.description ?? (disabled ? `${o.label} — no data in this view` : o.label)}
            aria-pressed={active}
            style={{
              border: "none",
              borderRadius: 5,
              padding: "4px 9px",
              fontSize: 11,
              fontWeight: active ? 600 : 500,
              cursor: disabled ? "not-allowed" : "pointer",
              whiteSpace: "nowrap",
              background: active ? "var(--panel)" : "transparent",
              color: disabled ? "var(--fg-subtle)" : active ? "var(--fg)" : "var(--fg-muted)",
              opacity: disabled ? 0.5 : 1,
              boxShadow: active ? "0 1px 2px rgba(0,0,0,0.12)" : "none",
            }}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
