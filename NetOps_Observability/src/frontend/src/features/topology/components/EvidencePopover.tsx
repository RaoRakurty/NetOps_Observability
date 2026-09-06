// EvidencePopover — a hover peek (design doc component list) at WHY a node/edge is
// on the canvas: its health/RCA verdict, the issue(s) driving it, and the top
// evidence rows — without a click into the side drawer. Read-only and
// pointer-events:none so it never intercepts the hover/spotlight underneath. The
// full record still lives one click away in TopologySideDrawer; this is the glance.

import type { ReactNode } from "react";
import type { TopologyView, EvidenceRef } from "../api/topologyTypes";
import { HEALTH_COLOR, HEALTH_LABEL, SOURCE_LABEL, confidencePct } from "../utils/topologyHealth";
import { RCA_OVERLAY } from "../utils/rcaOverlay";

const MONO = "var(--font-mono)";

function EvidenceRows({ evidence }: { evidence: EvidenceRef[] }) {
  if (!evidence || evidence.length === 0) return null;
  const rows = evidence.slice(0, 3);
  return (
    <div className="topo-evpop-ev">
      {rows.map((e, i) => (
        <div key={i} className="topo-evpop-evrow">
          <span className="topo-evpop-src">{SOURCE_LABEL[e.source] ?? e.source}</span>
          <span className="topo-evpop-sum" title={e.summary ?? e.detail ?? ""}>
            {e.summary ?? e.detail ?? "—"}
          </span>
          <span className="topo-evpop-conf" style={{ fontFamily: MONO }}>{confidencePct(e.confidence)}</span>
        </div>
      ))}
      {evidence.length > rows.length && (
        <div className="topo-evpop-more">+{evidence.length - rows.length} more</div>
      )}
    </div>
  );
}

export default function EvidencePopover({
  view, nodeId, edgeId, x, y,
}: {
  view: TopologyView;
  nodeId?: string;
  edgeId?: string;
  x: number;
  y: number;
}) {
  const node = nodeId ? view.nodes.find((n) => n.id === nodeId) : undefined;
  const edge = edgeId ? view.edges.find((e) => e.id === edgeId) : undefined;
  if (!node && !edge) return null;

  // Position: offset from the cursor, clamped so it never spills off the right/bottom.
  const vw = typeof window !== "undefined" ? window.innerWidth : 1280;
  const vh = typeof window !== "undefined" ? window.innerHeight : 800;
  const left = Math.min(x + 14, vw - 296);
  const top = Math.min(y + 14, vh - 180);

  let body: ReactNode;
  if (node) {
    const rca = node.rca_status ? RCA_OVERLAY[node.rca_status] : undefined;
    const showRca = !!rca && !rca.customerHidden;
    const tone = showRca ? rca!.color : HEALTH_COLOR[node.health];
    const stateLabel = showRca ? rca!.label : HEALTH_LABEL[node.health];
    const sub = [node.role || node.kind, node.vendor].filter(Boolean).join(" · ");
    const issues = (node.issues ?? []).slice(0, 2);
    body = (
      <>
        <div className="topo-evpop-head">
          <span className="topo-evpop-dot" style={{ background: tone }} aria-hidden="true" />
          <span className="topo-evpop-title">{node.label || node.id}</span>
          <span className="topo-evpop-state" style={{ color: tone }}>{stateLabel}</span>
        </div>
        {sub && <div className="topo-evpop-meta">{sub}</div>}
        {issues.length > 0 && (
          <div className="topo-evpop-issues">
            {issues.map((it, i) => (
              <div key={i} className="topo-evpop-issue" style={{ color: HEALTH_COLOR[it.severity === "critical" ? "critical" : "warning"] }}>
                <span aria-hidden="true">▸</span> {it.summary}
              </div>
            ))}
          </div>
        )}
        <EvidenceRows evidence={node.evidence} />
      </>
    );
  } else if (edge) {
    const src = view.nodes.find((n) => n.id === edge.source)?.label ?? edge.source;
    const tgt = view.nodes.find((n) => n.id === edge.target)?.label ?? edge.target;
    const meta = [
      edge.protocol ? (SOURCE_LABEL[edge.protocol] ?? edge.protocol) : null,
      edge.status,
      edge.utilization_pct != null ? `${Math.round(edge.utilization_pct)}% util` : null,
    ].filter(Boolean).join(" · ");
    body = (
      <>
        <div className="topo-evpop-head">
          <span className="topo-evpop-title" style={{ fontFamily: MONO }}>{src} → {tgt}</span>
        </div>
        {meta && <div className="topo-evpop-meta">{meta}</div>}
        <EvidenceRows evidence={edge.evidence} />
      </>
    );
  }

  return (
    <div className="topo-evpop" role="tooltip" style={{ left, top }}>
      {body}
    </div>
  );
}
