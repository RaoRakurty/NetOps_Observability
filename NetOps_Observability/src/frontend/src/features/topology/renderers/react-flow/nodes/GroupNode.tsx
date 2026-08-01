// GroupNode.tsx — a group rendered two ways (Phase 2):
//   • EXPANDED  → a translucent rounded backdrop behind its devices, with a label
//     chip (name · worst-health dot · counts) and a collapse chevron.
//   • COLLAPSED → a solid aggregate card replacing its devices, showing name, node
//     count, critical/warning counts, link count and worst health — the anti-
//     hairball control. Click the chevron to expand.

import { Handle, Position, type NodeProps } from "@xyflow/react";
import { memo } from "react";
import type { RFGroupData } from "../rfTypes";
import { HEALTH_COLOR, HEALTH_TINT, HEALTH_LABEL, HEALTH_GLYPH } from "../../../utils/topologyHealth";
import { radiusForDepth } from "../../../layout/groupGeometry";

const GROUP_TYPE_LABEL: Record<string, string> = {
  site: "Site",
  pod: "Pod",
  rack: "Rack",
  cluster: "Cluster",
  zone: "Zone",
  region: "Region",
  vpc: "VPC",
  subnet: "Subnet",
  app: "App",
};

function Chevron({ collapsed }: { collapsed: boolean }) {
  return (
    <svg width={12} height={12} viewBox="0 0 24 24" fill="none" aria-hidden="true"
      style={{ transform: collapsed ? "none" : "rotate(90deg)", transition: "transform .12s ease" }}>
      <path d="M9 6l6 6-6 6" stroke="currentColor" strokeWidth={2.4} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function GroupNodeBase(props: NodeProps) {
  const data = props.data as unknown as RFGroupData;
  const { group, collapsed, emphasis, counts, health, onToggle } = data;
  const depth = data.depth ?? 0;
  const dim = emphasis === "dim";
  const spotlight = emphasis === "spotlight";
  const color = HEALTH_COLOR[health];
  const kindLabel = GROUP_TYPE_LABEL[group.group_type] ?? group.group_type;

  const toggle = (e: React.MouseEvent) => {
    e.stopPropagation();
    onToggle?.(group.id);
  };

  // ── COLLAPSED: aggregate card ────────────────────────────────────────────────
  if (collapsed) {
    return (
      <div
        style={{
          position: "relative",
          width: 208,
          minHeight: 84,
          boxSizing: "border-box",
          borderRadius: 14,
          padding: "9px 12px 11px",
          background: "var(--panel)",
          border: `1.5px solid ${spotlight ? "var(--accent)" : color}`,
          borderLeft: `4px solid ${color}`,
          boxShadow: dim ? "none" : "0 3px 10px rgba(16,24,40,0.14), 0 1px 2px rgba(16,24,40,0.09)",
          opacity: dim ? 0.4 : 1,
          color: "var(--fg)",
        }}
      >
        <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
        <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
        <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
          <span style={{ fontSize: 9.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: ".06em", color: "var(--fg-subtle)" }}>
            {kindLabel}
          </span>
          <button onClick={toggle} title="Expand group" aria-label="Expand group"
            style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 3, padding: "1px 6px", fontSize: 10,
              color: "var(--fg-muted)", background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 6, cursor: "pointer" }}>
            <Chevron collapsed /> {counts.total}
          </button>
        </div>
        <div style={{ marginTop: 3, display: "flex", alignItems: "center", gap: 7 }}>
          <span title={HEALTH_LABEL[health]} style={{ width: 16, height: 16, borderRadius: "50%", flex: "0 0 auto",
            display: "inline-flex", alignItems: "center", justifyContent: "center", border: `2px solid ${color}`,
            background: HEALTH_TINT[health], color, fontSize: 9, fontWeight: 700 }}>{HEALTH_GLYPH[health]}</span>
          <span style={{ fontSize: 14, fontWeight: 700, letterSpacing: "-0.01em", color: "var(--fg)", overflow: "hidden",
            textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{group.label}</span>
        </div>
        <div style={{ marginTop: 7, display: "flex", gap: 6, flexWrap: "wrap", fontSize: 10.5, fontWeight: 600 }}>
          <span style={{ color: "var(--fg-muted)" }}>{counts.total} nodes</span>
          {counts.critical > 0 && <span style={{ color: HEALTH_COLOR.critical }}>{counts.critical} crit</span>}
          {counts.warning > 0 && <span style={{ color: HEALTH_COLOR.warning }}>{counts.warning} warn</span>}
          <span style={{ color: "var(--fg-subtle)" }}>{counts.links} links</span>
        </div>
        <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
        <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
      </div>
    );
  }

  // ── EXPANDED: backdrop container ─────────────────────────────────────────────
  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        boxSizing: "border-box",
        borderRadius: radiusForDepth(depth),
        // PER-LEVEL STYLING. Every level drawn identically (a tint + a dashed
        // border) is what made nesting unreadable — a region and the VPCs inside
        // it looked like the same kind of thing. Following the convention the
        // cloud vendors converged on:
        //   depth 0 (region) — SHADED fill, hairline border. It is a backdrop.
        //   depth 1 (VPC)    — OPAQUE card on that shading, solid border. It is
        //                      an object sitting on the backdrop.
        //   depth 2+ (subnet/AZ) — no fill, DASHED. Dashed is reserved for
        //                      "subdivision / uncertain", never for "is a group".
        ...containerSkin(depth, color, spotlight),
        opacity: dim ? 0.5 : 1,
        pointerEvents: "none",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      {/* label chip top-left — interactive */}
      <div style={{ position: "absolute", top: 8, left: 10, display: "inline-flex", alignItems: "center", gap: 7,
        padding: "3px 6px 3px 9px", borderRadius: 9, background: "var(--panel)", border: "1px solid var(--border)",
        boxShadow: "0 1px 3px rgba(16,24,40,0.10)", pointerEvents: "auto" }}>
        <span title={HEALTH_LABEL[health]} style={{ width: 8, height: 8, borderRadius: "50%", background: color,
          boxShadow: `0 0 0 2px ${HEALTH_TINT[health]}`, flex: "0 0 auto" }} />
        <span style={{ fontSize: 9.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: ".05em", color: "var(--fg-subtle)" }}>{kindLabel}</span>
        <span style={{ fontSize: 11.5, fontWeight: 650, color: "var(--fg)", overflow: "hidden", textOverflow: "ellipsis",
          whiteSpace: "nowrap", maxWidth: 220 }}>{group.label}</span>
        <span style={{ fontSize: 10, color: "var(--fg-subtle)" }}>· {counts.total}</span>
        <button onClick={toggle} title="Collapse group" aria-label="Collapse group"
          style={{ display: "inline-flex", alignItems: "center", padding: "2px 4px", color: "var(--fg-muted)",
            background: "transparent", border: "1px solid var(--border)", borderRadius: 6, cursor: "pointer" }}>
          <Chevron collapsed={false} />
        </button>
      </div>
    </div>
  );
}

export const GroupNode = memo(GroupNodeBase);
export default GroupNode;

/** containerSkin renders the fill/border for one nesting level.
 *
 *  Separated from the component so the three levels are legible side by side —
 *  and so "what does depth 1 look like" is answerable without reading JSX. */
function containerSkin(depth: number, color: string, spotlight: boolean) {
  const accent = spotlight ? "var(--accent)" : undefined;
  if (depth <= 0) {
    return {
      background: `color-mix(in srgb, ${color} 4%, color-mix(in srgb, var(--surface) 70%, transparent))`,
      border: `1px solid ${accent ?? `color-mix(in srgb, ${color} 30%, var(--border))`}`,
    };
  }
  if (depth === 1) {
    return {
      // Opaque: a VPC must read as a card ON the region shading, not as another
      // wash of the same colour.
      background: "var(--panel)",
      border: `1.5px solid ${accent ?? `color-mix(in srgb, ${color} 45%, var(--border))`}`,
      boxShadow: "0 1px 3px rgba(16,24,40,0.10)",
    };
  }
  return {
    background: "transparent",
    border: `1px dashed ${accent ?? `color-mix(in srgb, ${color} 40%, var(--border))`}`,
  };
}
