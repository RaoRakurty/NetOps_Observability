// OverlaySelector — compact segmented control over the overlays that ACTUALLY
// apply to the current view. Only AVAILABLE overlays are shown — a permanently
// greyed, do-nothing overlay (config-drift/syslog/golden-path/routing-changes have
// no data source; flow/rca-evidence/interface-errors/historical-diff light up in
// their own mode/data) reads as broken. They appear contextually instead: RCA
// evidence in Investigate, Flow dependencies in Dependency, Interface errors when a
// link reports errors, Historical diff when something changed. Health is always on.

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
  const shown = overlays.filter((o) => o.available);
  if (shown.length === 0) return null;
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
      {shown.map((o) => {
        const active = o.kind === value;
        return (
          <button
            key={o.kind}
            type="button"
            onClick={() => onChange(o.kind)}
            title={o.description ?? o.label}
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
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
