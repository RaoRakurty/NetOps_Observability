// DeviceNode.tsx — the BASE topology card + the reusable <NodeCard> shell that
// every other device node (switch/router/firewall/cloud) composes. Calm by
// default (PDF §11): health is a small ring/badge top-right, never a full fill;
// emphasis tunes opacity/border/shadow only. No business logic — pure render.

import { Handle, Position, type NodeProps } from "@xyflow/react";
import { memo, type ReactNode } from "react";
import type { RFNodeData } from "../rfTypes";
import {
  HEALTH_COLOR,
  HEALTH_TINT,
  HEALTH_GLYPH,
  HEALTH_LABEL,
  confidencePct,
} from "../../../utils/topologyHealth";

const CARD_W = 188;
const CARD_MIN_H = 88;

const MONO = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";

/** Small health ring/badge (top-right) with an accessible glyph — never a fill. */
function HealthRing({ health }: { health: RFNodeData["node"]["health"] }) {
  const color = HEALTH_COLOR[health];
  const tint = HEALTH_TINT[health];
  return (
    <span
      title={HEALTH_LABEL[health]}
      aria-label={HEALTH_LABEL[health]}
      style={{
        width: 18,
        height: 18,
        borderRadius: "50%",
        flex: "0 0 auto",
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        border: `2px solid ${color}`,
        background: tint,
        color,
        fontSize: 10,
        fontWeight: 700,
        lineHeight: 1,
      }}
    >
      {HEALTH_GLYPH[health]}
    </span>
  );
}

/** Tiny dot used in compact mode. */
function HealthDot({ health }: { health: RFNodeData["node"]["health"] }) {
  return (
    <span
      title={HEALTH_LABEL[health]}
      aria-label={HEALTH_LABEL[health]}
      style={{
        width: 8,
        height: 8,
        borderRadius: "50%",
        flex: "0 0 auto",
        background: HEALTH_COLOR[health],
        boxShadow: `0 0 0 2px ${HEALTH_TINT[health]}`,
      }}
    />
  );
}

export type NodeCardProps = {
  data: RFNodeData;
  icon: ReactNode;
  accent: string;
};

/**
 * The shared card shell. Switch/Router/Firewall/Cloud nodes all call this with
 * their own icon + accent, so the anatomy stays identical and data-driven.
 */
function NodeCardBase({ data, icon, accent }: NodeCardProps) {
  const { node, emphasis, showLabel, metricsLine } = data;
  const compact = !showLabel;

  const spotlight = emphasis === "spotlight";
  const dim = emphasis === "dim";
  const opacity = dim ? 0.3 : spotlight ? 1 : 0.95;

  const healthColor = HEALTH_COLOR[node.health];
  // spotlight gets a stronger, role/health-tinted border + elevated shadow.
  const borderColor = spotlight ? accent : "var(--border)";
  const borderWidth = spotlight ? 1.5 : 1;
  const shadow = dim
    ? "none"
    : spotlight
      ? `0 10px 28px rgba(0,0,0,0.26), 0 0 0 1px ${healthColor}33`
      : "0 1px 3px rgba(0,0,0,0.10)";

  // ── compact mode: icon + health dot + truncated hostname only ────────────────
  if (compact) {
    return (
      <div
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 8,
          maxWidth: 168,
          padding: "8px 12px",
          borderRadius: 14,
          background: "var(--panel)",
          border: `${borderWidth}px solid ${borderColor}`,
          borderLeft: `3px solid ${accent}`,
          boxShadow: shadow,
          opacity,
          color: "var(--fg)",
        }}
      >
        <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
        <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
        <span style={{ display: "inline-flex", color: accent, flex: "0 0 auto" }}>{icon}</span>
        <HealthDot health={node.health} />
        <span
          style={{
            fontSize: 13,
            fontWeight: 600,
            color: "var(--fg)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {node.label}
        </span>
        <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
        <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
      </div>
    );
  }

  // ── full mode ───────────────────────────────────────────────────────────────
  const row2 = [node.vendor, node.model].filter(Boolean).join(" · ");
  const row3 = [node.site, node.role, node.owner].filter(Boolean).join(" · ");

  return (
    <div
      style={{
        position: "relative",
        width: CARD_W,
        minHeight: CARD_MIN_H,
        boxSizing: "border-box",
        padding: "11px 13px 13px 14px",
        borderRadius: 14,
        background: "var(--panel)",
        border: `${borderWidth}px solid ${borderColor}`,
        borderLeft: `3px solid ${accent}`,
        boxShadow: shadow,
        opacity,
        color: "var(--fg)",
        fontFamily: "inherit",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />

      {/* row1 — icon + hostname (dominant) + health badge */}
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ display: "inline-flex", color: accent, flex: "0 0 auto" }}>{icon}</span>
        <span
          style={{
            fontSize: 13,
            fontWeight: 600,
            lineHeight: 1.25,
            color: "var(--fg)",
            flex: "1 1 auto",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {node.label}
        </span>
        <HealthRing health={node.health} />
      </div>

      {/* row2 — vendor · model (primary meta, legible) */}
      {row2 && (
        <div
          style={{
            marginTop: 6,
            fontSize: 11,
            lineHeight: 1.35,
            color: "var(--fg-muted)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {row2}
        </div>
      )}

      {/* row3 — site · role · owner */}
      {row3 && (
        <div
          style={{
            marginTop: 3,
            fontSize: 11,
            lineHeight: 1.35,
            color: "var(--fg-muted)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {row3}
        </div>
      )}

      {/* row4 — metrics strip (mono, faint) */}
      {metricsLine && (
        <div
          style={{
            marginTop: 7,
            fontSize: 10,
            letterSpacing: ".01em",
            fontFamily: MONO,
            color: "var(--fg-subtle)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {metricsLine}
        </div>
      )}

      {/* confidence chip — bottom-right, faint */}
      <span
        title={`Confidence ${confidencePct(node.confidence)}`}
        style={{
          position: "absolute",
          right: 8,
          bottom: 6,
          fontSize: 10,
          fontFamily: MONO,
          color: "var(--fg-subtle)",
          opacity: 0.8,
        }}
      >
        {confidencePct(node.confidence)}
      </span>

      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
}

export const NodeCard = memo(NodeCardBase);

/** Generic chip/box icon for the base device card. */
export function DeviceIcon() {
  return (
    <svg width={18} height={18} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x={5} y={5} width={14} height={14} rx={2} stroke="currentColor" strokeWidth={1.6} />
      <rect x={9} y={9} width={6} height={6} rx={1} stroke="currentColor" strokeWidth={1.4} />
      {/* pins */}
      <path
        d="M8 2v3M12 2v3M16 2v3M8 19v3M12 19v3M16 19v3M2 8h3M2 12h3M2 16h3M19 8h3M19 12h3M19 16h3"
        stroke="currentColor"
        strokeWidth={1.3}
        strokeLinecap="round"
      />
    </svg>
  );
}

const DEVICE_ACCENT = "#64748b";

function DeviceNodeBase(props: NodeProps) {
  const data = props.data as unknown as RFNodeData;
  return <NodeCard data={data} icon={<DeviceIcon />} accent={DEVICE_ACCENT} />;
}

export const DeviceNode = memo(DeviceNodeBase);
export default DeviceNode;
