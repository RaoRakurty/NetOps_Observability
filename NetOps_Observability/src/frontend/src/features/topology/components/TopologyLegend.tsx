// TopologyLegend — the canvas grammar as a key, not a lesson: health rings
// (always glyph-paired), edge styles, and the unresolved-node treatment.
//
// UI-words sweep 4 (tracker 270). The legend used to end in a sentence that
// TAUGHT what the active overlay does. Each of those ten sentences is now one
// authored file under ai/skills/explain/overlay.*, reachable from the `(i)`
// beside a three- or four-word line. The swatches themselves are the key and
// stay exactly as they were.

import { useState } from "react";
import type { OverlayKind, Health } from "../api/topologyTypes";
import { HEALTH_COLOR, HEALTH_GLYPH, HEALTH_LABEL } from "../utils/topologyHealth";
import { RCA_OVERLAY, RCA_OVERLAY_ORDER } from "../utils/rcaOverlay";
import AskIris from "../../../components/AskIris";

/** The short line the legend keeps, and the authored file that carries the rest. */
const OVERLAY_NOTE: Record<OverlayKind, { line: string; topic: string }> = {
  health: { line: "Rings carry health", topic: "overlay.health" },
  utilization: { line: "Width is link load", topic: "overlay.utilization" },
  interface_errors: { line: "Width is error rate", topic: "overlay.interface-errors" },
  routing_changes: { line: "Routing moved here", topic: "overlay.routing-changes" },
  config_drift: { line: "Config differs from intent", topic: "overlay.config-drift" },
  syslog: { line: "Device logged here", topic: "overlay.syslog" },
  flow: { line: "Dashed is flow-observed", topic: "overlay.flow" },
  rca_evidence: { line: "Used by this RCA", topic: "overlay.rca-evidence" },
  golden_path_delta: { line: "Live path versus golden", topic: "overlay.golden-path-delta" },
  historical_diff: { line: "Changed since the snapshot", topic: "overlay.historical-diff" },
};

const HEALTH_ORDER: Health[] = ["ok", "warning", "critical", "maintenance", "unknown"];

function Swatch({ color, glyph, label }: { color: string; glyph: string; label: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12.5, color: "var(--fg-muted)" }}>
      <span
        style={{
          width: 18,
          height: 18,
          flex: "0 0 auto",
          borderRadius: "50%",
          border: `2px solid ${color}`,
          background: "var(--surface)",
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 12.5,
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

function EdgeStyle({ label, render, ask }: { label: string; render: React.ReactNode; ask?: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5, color: "var(--fg-muted)" }}>
      <span style={{ width: 30, display: "inline-flex", alignItems: "center" }}>{render}</span>
      {label}
      {ask}
    </div>
  );
}

/** RCA state swatch: a glyph in the state colour (hollow ring for missing-evidence). */
function RcaSwatch({ color, glyph, label, hollow }: { color: string; glyph: string; label: string; hollow: boolean }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12.5, color: "var(--fg-muted)" }}>
      <span
        style={{
          width: 18,
          height: 18,
          flex: "0 0 auto",
          borderRadius: "50%",
          border: `2px ${hollow ? "dashed" : "solid"} ${color}`,
          background: hollow ? "transparent" : `color-mix(in srgb, ${color} 16%, transparent)`,
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 12.5,
          fontWeight: 700,
          color,
          fontFamily: "var(--font-mono, ui-monospace, monospace)",
        }}
      >
        {hollow ? "" : glyph}
      </span>
      {label}
    </div>
  );
}

export default function TopologyLegend({ overlay, showRca = false }: { overlay: OverlayKind; showRca?: boolean }) {
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
          fontSize: 12.5,
          fontWeight: 600,
          color: "var(--fg-subtle)",
        }}
      >
        Legend
        <span style={{ color: "var(--fg-muted)", fontSize: 12.5 }}>{open ? "▾" : "▸"}</span>
      </button>

      {open ? (
        <div style={{ padding: "0 10px 10px", display: "grid", gap: 9 }}>
          {showRca && (
            <>
              <div style={{ display: "grid", gap: 5 }}>
                <div style={{ fontSize: 12.5, fontWeight: 700, color: "var(--fg-subtle)" }}>
                  RCA verdict
                </div>
                {RCA_OVERLAY_ORDER.map((s) => (
                  <RcaSwatch key={s} color={RCA_OVERLAY[s].color} glyph={RCA_OVERLAY[s].glyph} label={RCA_OVERLAY[s].label} hollow={RCA_OVERLAY[s].hollow} />
                ))}
              </div>
              <div style={{ height: 1, background: "var(--border)" }} />
            </>
          )}

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
              ask={<AskIris topic="topo.edge-confidence" label="Inferred / flow" />}
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

          <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5, color: "var(--fg-muted)" }}>
            <span
              style={{
                width: 14,
                height: 14,
                borderRadius: 3,
                border: "1px dashed var(--fg-subtle)",
                background: "var(--surface)",
                opacity: 0.6,
                flex: "0 0 auto",
              }}
            />
            Unresolved node
            <AskIris topic="topo.unresolved" label="Unresolved node" />
          </div>

          <div style={{ height: 1, background: "var(--border)" }} />

          <div style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 12.5, color: "var(--fg-subtle)", lineHeight: 1.4 }}>
            {OVERLAY_NOTE[overlay].line}
            <AskIris topic={OVERLAY_NOTE[overlay].topic} label={OVERLAY_NOTE[overlay].line} />
          </div>
        </div>
      ) : null}
    </div>
  );
}
