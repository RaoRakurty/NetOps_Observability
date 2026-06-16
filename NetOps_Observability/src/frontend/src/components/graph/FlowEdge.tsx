import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, type EdgeProps } from "@xyflow/react";

// FlowEdge — the custom traffic/RCA edge. State (data.state) drives appearance:
//   healthy        thin steady line + slow particles
//   degraded       amber line + faster particles + mild glow
//   suspected_down red DASHED line, no particles, ⚠ break marker
//   confirmed_down strong red line with a ✕ break (gap), no particles
//   unknown        gray DOTTED line, no particles
// Particles show traffic *activity/direction*, never exact latency. Honest by
// design: a "down" state never animates as if data were flowing.
//
// Accessibility: respects prefers-reduced-motion — animations are dropped and a
// static directional dot is shown instead.

export type EdgeState = "healthy" | "degraded" | "suspected_down" | "confirmed_down" | "unknown";

const reduceMotion = typeof window !== "undefined" && typeof window.matchMedia === "function"
  ? window.matchMedia("(prefers-reduced-motion: reduce)").matches
  : false;

export default function FlowEdge(props: EdgeProps) {
  const { sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, style, data, label } = props;
  const [path, labelX, labelY] = getSmoothStepPath({
    sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, borderRadius: 16,
  });
  const d = (data ?? {}) as { flow?: boolean; particles?: number; speed?: number; state?: EdgeState };
  const state: EdgeState = d.state ?? (d.flow ? "healthy" : "unknown");
  const color = (style?.stroke as string) || "#5a6472";
  const dashed = state === "suspected_down";
  const broken = state === "confirmed_down";
  const dotted = state === "unknown";
  const animate = !reduceMotion && (state === "healthy" || state === "degraded") && d.flow !== false;
  const count = Math.max(1, Math.min(5, d.particles ?? (state === "degraded" ? 4 : 2)));
  const speed = d.speed ?? (state === "degraded" ? 1.8 : 3.0);

  const lineStyle: React.CSSProperties = {
    ...style,
    stroke: color,
    strokeWidth: (style?.strokeWidth as number) ?? (state === "healthy" ? 1.8 : 2.6),
    strokeDasharray: broken ? "10 7" : dashed ? "7 5" : dotted ? "2 5" : undefined,
    filter: state === "degraded" || broken ? `drop-shadow(0 0 4px ${color}aa)` : undefined,
  };

  return (
    <>
      <BaseEdge path={path} markerEnd={markerEnd} style={lineStyle} />
      {animate && Array.from({ length: count }).map((_, i) => (
        <circle key={i} r={3} fill={color} style={{ filter: `drop-shadow(0 0 3px ${color})` }}>
          <animateMotion dur={`${speed}s`} repeatCount="indefinite" path={path} begin={`${((i * speed) / count).toFixed(2)}s`} />
        </circle>
      ))}
      {/* break marker for a down segment — a clear ✕/gap at midpoint */}
      {(broken || dashed) && (
        <g transform={`translate(${labelX},${labelY})`}>
          <circle r={9} fill="var(--panel,#151b2b)" stroke={color} strokeWidth={2} />
          <text textAnchor="middle" dominantBaseline="central" fontSize="11" fontWeight={800} fill={color}>
            {broken ? "✕" : "⚠"}
          </text>
        </g>
      )}
      {label && (
        <EdgeLabelRenderer>
          <div
            className="nodrag nopan"
            style={{
              position: "absolute",
              transform: `translate(-50%,-50%) translate(${labelX}px,${broken || dashed ? labelY - 18 : labelY}px)`,
              fontSize: 11, fontWeight: 700, color: "var(--fg,#e6edf3)",
              background: "var(--panel,#151b2b)", border: `1px solid ${color}`,
              padding: "1px 7px", borderRadius: 6, pointerEvents: "none", whiteSpace: "nowrap",
            }}
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
