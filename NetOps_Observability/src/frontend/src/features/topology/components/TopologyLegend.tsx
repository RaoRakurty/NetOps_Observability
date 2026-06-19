// TopologyLegend — a small collapsible card explaining the canvas grammar:
// health colors (always paired with a glyph), edge styles, and the unresolved
// node treatment. The note adapts to the active overlay.

import { useState } from "react";
import type { OverlayKind, Health } from "../api/topologyTypes";
import { HEALTH_COLOR, HEALTH_GLYPH, HEALTH_LABEL } from "../utils/topologyHealth";

const OVERLAY_NOTE: Record<OverlayKind, string> = {
  health: "Node rings show health; edges keep their relationship style.",
  utilization: "Edge width scales with link utilization.",
  interface_errors: "Edges thicken / redden with error & discard rate.",
  routing_changes: "Highlighted edges changed routing in the window.",
  config_drift: "Flagged nodes drifted from intended config.",
  syslog: "Nodes flagged by syslog activity in the window.",
  flow: "Dashed edges are flow-observed dependencies (lower confidence).",
  rca_evidence: "Thick accent edges were used by the active RCA.",
  golden_path_delta: "Compares the live path against the golden path.",
  historical_diff: "Added / removed / changed objects vs the prior snapshot.",
};

const HEALTH_ORDER: Health[] = ["ok", "warning", "critical", "maintenance", "unknown"];

function Swatch({ color, glyph, label }: { color: string; glyph: string; label: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 11, color: "var(--fg-muted)" }}>
      <span
        style={{
          width: 14,
          height: 14,
          borderRadius: "50%",
          border: `2px solid ${color}`,
          background: "var(--surface)",
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 8,
          fontWeight: 700,
          color,
          fontFamily: "var(--font-mono, ui-monospace, monospace)",
        }}
      >
        {glyph}
      </span>
      {label}
    </div>
  );
}

function EdgeStyle({ label, render }: { label: string; render: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: "var(--fg-muted)" }}>
      <span style={{ width: 30, display: "inline-flex", alignItems: "center" }}>{render}</span>
      {label}
    </div>
  );
}

export default function TopologyLegend({ overlay }: { overlay: OverlayKind }) {
  // Collapsed by default: the canvas should open clean. Operators expand the
  // legend on demand rather than having it cover the lower-left on every visit.
  const [open, setOpen] = useState(false);

  return (
    <div
      style={{
        position: "absolute",
        bottom: 12,
        left: 12,
        zIndex: 15,
        width: open ? 232 : "auto",
        background: "var(--panel)",
        border: "1px solid var(--border)",
        borderRadius: 8,
        boxShadow: "0 4px 16px rgba(0,0,0,0.16)",
        overflow: "hidden",
      }}
    >
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 8,
          background: "transparent",
          border: "none",
          cursor: "pointer",
          padding: "8px 10px",
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: 0.4,
          textTransform: "uppercase",
          color: "var(--fg-subtle)",
        }}
      >
        Legend
        <span style={{ color: "var(--fg-muted)", fontSize: 10 }}>{open ? "▾" : "▸"}</span>
      </button>

      {open ? (
        <div style={{ padding: "0 10px 10px", display: "grid", gap: 9 }}>
          <div style={{ display: "grid", gap: 5 }}>
            {HEALTH_ORDER.map((h) => (
              <Swatch key={h} color={HEALTH_COLOR[h]} glyph={HEALTH_GLYPH[h]} label={HEALTH_LABEL[h]} />
            ))}
          </div>

          <div style={{ height: 1, background: "var(--border)" }} />

          <div style={{ display: "grid", gap: 5 }}>
            <EdgeStyle
              label="Confirmed link"
              render={<span style={{ width: 30, height: 2, background: "var(--fg-muted)", display: "block" }} />}
            />
            <EdgeStyle
              label="Inferred / flow"
              render={
                <span style={{ width: 30, borderTop: "2px dashed var(--fg-muted)", display: "block" }} />
              }
            />
            <EdgeStyle
              label="Degraded"
              render={
                <span style={{ width: 30, borderTop: "2px dashed var(--bad)", display: "block" }} />
              }
            />
            <EdgeStyle
              label="Path / RCA"
              render={<span style={{ width: 30, height: 3, background: "var(--accent)", display: "block" }} />}
            />
            <EdgeStyle
              label="Bundled (LAG)"
              render={
                <span style={{ width: 30, display: "block" }}>
                  <span style={{ display: "block", height: 2, background: "var(--fg-muted)" }} />
                  <span style={{ display: "block", height: 2, marginTop: 2, background: "var(--fg-muted)" }} />
                </span>
              }
            />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: "var(--fg-muted)" }}>
            <span
              style={{
                width: 14,
                height: 14,
                borderRadius: 3,
                border: "1px dashed var(--fg-subtle)",
                background: "var(--surface)",
                opacity: 0.6,
              }}
            />
            Unresolved node
          </div>

          <div style={{ height: 1, background: "var(--border)" }} />

          <div style={{ fontSize: 11, color: "var(--fg-subtle)", lineHeight: 1.4 }}>
            {OVERLAY_NOTE[overlay]}
          </div>
        </div>
      ) : null}
    </div>
  );
}
