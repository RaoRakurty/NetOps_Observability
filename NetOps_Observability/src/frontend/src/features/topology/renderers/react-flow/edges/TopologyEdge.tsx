// TopologyEdge.tsx — the base, calm-by-default smoothstep edge, plus the shared
// `EdgeBody` helper every other edge variant reuses so the path math, label card
// and overlay treatments live in exactly one place (DRY, PDF §11).
//
// Emphasis is the heart of "calm by default": muted/normal edges are quiet grey;
// only `strong` edges (path / selected / unhealthy) get color + width + glow.

import {
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
  type EdgeProps,
} from "@xyflow/react";
import { memo } from "react";
import type { CSSProperties, ReactNode } from "react";
import type { RFEdgeData } from "../rfTypes";
import type { TopologyEdge as TopologyEdgeModel } from "../../../api/topologyTypes";

// ── emphasis → base stroke treatment (PDF §11) ──────────────────────────────────
type StrokeTreatment = { width: number; opacity: number };

export const EMPHASIS_TREATMENT: Record<RFEdgeData["emphasis"], StrokeTreatment> = {
  muted: { width: 1.2, opacity: 0.5 },
  normal: { width: 1.6, opacity: 0.85 },
  strong: { width: 2.8, opacity: 1 },
};

/**
 * Scale a base stroke width by an edge's utilization (0..100) when the
 * utilization overlay is active. Capped to a calm, readable band.
 */
export function utilizationWidth(base: number, utilization: number | undefined): number {
  const u = Math.max(0, Math.min(100, utilization ?? 0));
  // Map 0..100% → ~1.2..6px, then keep the larger of base/scaled so a 'strong'
  // edge never gets thinner than its emphasis already demands.
  const scaled = 1.2 + (u / 100) * 4.8;
  return Math.max(base, scaled);
}

/**
 * Compact single-line edge label: just *where the link goes* (ports if known,
 * else the target node). Intentionally NOT a detail dump — util/errors/evidence/
 * confidence live in the side drawer that opens when you click the edge or its
 * devices. A high-degree node (spine) can carry many highlighted links at once;
 * a one-line chip stays small and won't stack into an unreadable pile the way
 * the old three-line card did. (PDF §11 — calm by default.)
 */
export function EdgeLabelCard({ edge }: { edge: TopologyEdgeModel }): ReactNode {
  // "Where it goes": prefer the port pair, fall back to the far-end device.
  const text =
    edge.source_port || edge.target_port
      ? `${edge.source_port ?? "·"} → ${edge.target_port ?? "·"}`
      : `→ ${edge.target}`;
  return (
    <div
      style={{
        background: "var(--panel)",
        border: "1px solid var(--border)",
        borderRadius: 6,
        padding: "2px 6px",
        boxShadow: "0 2px 8px rgba(0,0,0,0.16)",
        fontSize: 10.5,
        lineHeight: 1.3,
        color: "var(--fg-muted)",
        fontVariantNumeric: "tabular-nums",
        whiteSpace: "nowrap",
        fontFamily:
          "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
      }}
    >
      {text}
    </div>
  );
}

// ── EdgeBody — the shared render core every variant reuses ───────────────────────
export type EdgeBodyProps = {
  props: EdgeProps;
  color: string;
  width: number;
  /** strokeDasharray, e.g. "5 5" — omit for solid. */
  dash?: string;
  /** Add a soft glow underlay (used by `strong` / path edges). */
  glow?: boolean;
  /** Extra SVG drawn on top of the base path (warning glyph, bundle line, …). */
  decoration?: (geom: EdgeGeometry) => ReactNode;
  /** Override the default label card (bundle chip etc.). */
  label?: (geom: EdgeGeometry) => ReactNode;
  /** Extra style merged onto the BaseEdge stroke. */
  style?: CSSProperties;
  /** Class on the base stroke (e.g. a reduced-motion-gated dash-flow animation). */
  className?: string;
};

export type EdgeGeometry = {
  path: string;
  labelX: number;
  labelY: number;
};

/**
 * Single source of truth for path geometry + stroke + (optional) glow underlay +
 * label rendering. All five edge variants funnel through here.
 */
export function EdgeBody({
  props,
  color,
  width,
  dash,
  glow,
  decoration,
  label,
  style,
  className,
}: EdgeBodyProps): ReactNode {
  const {
    id,
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    markerEnd,
  } = props;
  const data = props.data as unknown as RFEdgeData | undefined;
  const [path, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    borderRadius: 14,
  });
  const geom: EdgeGeometry = { path, labelX, labelY };
  const opacity = data?.emphasis === "muted" ? 0.5 : data?.emphasis === "normal" ? 0.85 : 1;

  return (
    <>
      {glow && (
        // Faint wide underlay for the "soft glow" of strong/path edges.
        <BaseEdge
          id={`${id}-glow`}
          path={path}
          style={{
            stroke: color,
            strokeWidth: width + 6,
            opacity: 0.16,
            strokeLinecap: "round",
            filter: "blur(2px)",
          }}
        />
      )}
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        className={className}
        style={{
          stroke: color,
          strokeWidth: width,
          opacity,
          strokeDasharray: dash,
          strokeLinecap: "round",
          ...style,
        }}
      />
      {decoration?.(geom)}
      {data?.showLabel && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: "absolute",
              transform: `translate(-50%,-50%) translate(${labelX}px,${labelY}px)`,
              // pointer-events MUST stay off: this card pops up on hover at the
              // edge midpoint — right under the cursor. If it captured the pointer
              // it would steal the hover from the edge's interaction path, fire
              // mouseleave→mouseenter in a loop, and the canvas would visibly
              // shake whenever the cursor skims an edge in "empty" space. The
              // label is informational (no clicks), so it never needs the pointer.
              pointerEvents: "none",
            }}
            className="nodrag nopan"
          >
            {label ? label(geom) : <EdgeLabelCard edge={data.edge} />}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

// ── the base topology edge ───────────────────────────────────────────────────────
function TopologyEdgeBase(props: EdgeProps) {
  const data = props.data as unknown as RFEdgeData | undefined;
  const emphasis = data?.emphasis ?? "normal";
  const t = EMPHASIS_TREATMENT[emphasis];
  const overlay = data?.overlay;
  const edge = data?.edge;

  // Muted/normal stay grey; only 'strong' tints toward the accent.
  const color = emphasis === "strong" ? "var(--accent)" : "var(--border)";

  let width = t.width;
  if (overlay === "utilization") width = utilizationWidth(width, edge?.utilization_pct);

  return (
    <EdgeBody
      props={props}
      color={color}
      width={width}
      glow={emphasis === "strong"}
      decoration={
        overlay === "interface_errors" && (edge?.errors ?? 0) > 0
          ? (geom) => <ErrorMarker x={geom.labelX} y={geom.labelY} />
          : undefined
      }
    />
  );
}

/** Small red dot warning marker placed near mid-path for the errors overlay. */
export function ErrorMarker({ x, y }: { x: number; y: number }): ReactNode {
  return (
    <g pointerEvents="none">
      <circle cx={x} cy={y} r={4.5} fill="#dc2626" stroke="var(--panel)" strokeWidth={1.5} />
    </g>
  );
}

export const TopologyEdge = memo(TopologyEdgeBase);
export default TopologyEdge;
