// TopologySideDrawer — the inspector. Answers the operator's five questions about
// the selected node/edge: what is it, is it healthy, what changed, what evidence,
// who owns it. Presentational only — selection + close are driven from above.

import type {
  TopologyView,
  TopologySelection,
  TopologyNode,
  TopologyEdge,
  ChangeState,
} from "../api/topologyTypes";
import { HEALTH_COLOR, HEALTH_GLYPH, HEALTH_LABEL, edgeEvidenceSummary } from "../utils/topologyHealth";
import ConfidencePanel from "./ConfidencePanel";
import EvidencePanel from "./EvidencePanel";

const CHANGE_LABEL: Record<ChangeState, string> = {
  added: "Added in window",
  removed: "Removed in window",
  changed: "Changed in window",
  unchanged: "Unchanged",
};

function HealthBadge({ health }: { health: TopologyNode["health"] }) {
  const color = HEALTH_COLOR[health];
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        fontSize: 11,
        fontWeight: 600,
        color,
        border: `1px solid ${color}`,
        borderRadius: 5,
        padding: "2px 8px",
      }}
    >
      <span style={{ fontFamily: "var(--font-mono, ui-monospace, monospace)", fontWeight: 700 }}>
        {HEALTH_GLYPH[health]}
      </span>
      {HEALTH_LABEL[health]}
    </span>
  );
}

const sectionTitle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 600,
  letterSpacing: 0.4,
  textTransform: "uppercase",
  color: "var(--fg-subtle)",
  marginBottom: 8,
};

function MetaRow({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <div style={{ display: "flex", gap: 8, fontSize: 12, lineHeight: 1.6 }}>
      <span style={{ color: "var(--fg-subtle)", minWidth: 78 }}>{label}</span>
      <span style={{ color: "var(--fg)", wordBreak: "break-word" }}>{value}</span>
    </div>
  );
}

function NodeBody({ node }: { node: TopologyNode }) {
  const metrics = Object.entries(node.metrics);
  return (
    <>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
        <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "var(--fg)" }}>{node.label}</h2>
        <HealthBadge health={node.health} />
      </div>
      <div style={{ fontSize: 11, color: "var(--fg-muted)", marginBottom: 14 }}>
        {[node.kind, node.role].filter(Boolean).join(" · ")}
      </div>

      <div style={{ display: "grid", gap: 2, marginBottom: 14 }}>
        <MetaRow label="Vendor" value={node.vendor} />
        <MetaRow label="Model" value={node.model} />
        <MetaRow label="Site" value={node.site} />
        <MetaRow label="Zone" value={node.zone} />
        <MetaRow label="Owner" value={node.ownership?.owner} />
        <MetaRow label="Team" value={node.ownership?.team} />
        <MetaRow label="Service" value={node.ownership?.business_service} />
        <MetaRow label="Criticality" value={node.ownership?.criticality} />
        <MetaRow label="Change" value={CHANGE_LABEL[node.time.change_state]} />
      </div>

      {metrics.length > 0 ? (
        <section style={{ marginBottom: 4 }}>
          <div style={sectionTitle}>Metrics</div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 8,
            }}
          >
            {metrics.map(([k, v]) => (
              <div
                key={k}
                style={{
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  background: "var(--surface)",
                  padding: "7px 9px",
                }}
              >
                <div style={{ fontSize: 10, color: "var(--fg-subtle)", textTransform: "uppercase", letterSpacing: 0.3 }}>
                  {k}
                </div>
                <div
                  style={{
                    fontSize: 14,
                    fontWeight: 600,
                    color: "var(--fg)",
                    fontFamily: "var(--font-mono, ui-monospace, monospace)",
                  }}
                >
                  {String(v)}
                </div>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      <ConfidencePanel confidence={node.confidence} evidence={node.evidence} />
      <EvidencePanel evidence={node.evidence} />
    </>
  );
}

function EdgeBody({ edge, view }: { edge: TopologyEdge; view: TopologyView }) {
  const src = view.nodes.find((n) => n.id === edge.source);
  const dst = view.nodes.find((n) => n.id === edge.target);
  const color = HEALTH_COLOR[edge.status];
  return (
    <>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
        <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: "var(--fg)" }}>
          {(src?.label ?? edge.source)} → {(dst?.label ?? edge.target)}
        </h2>
        <HealthBadge health={edge.status} />
      </div>
      <div style={{ fontSize: 11, color: "var(--fg-muted)", marginBottom: 14 }}>
        {edgeEvidenceSummary(edge)}
      </div>

      <div style={{ display: "grid", gap: 2, marginBottom: 14 }}>
        <MetaRow label="Relationship" value={edge.relationship} />
        <MetaRow label="Source port" value={edge.source_port} />
        <MetaRow label="Target port" value={edge.target_port} />
        <MetaRow label="Status" value={edge.status} />
        <MetaRow
          label="Utilization"
          value={edge.utilization != null ? `${edge.utilization}%` : undefined}
        />
        <MetaRow label="Errors" value={edge.errors != null ? String(edge.errors) : undefined} />
        <MetaRow
          label="Bundle"
          value={edge.bundle_count && edge.bundle_count > 1 ? `${edge.bundle_count}× members` : undefined}
        />
      </div>

      {(edge.utilization != null || edge.errors != null) ? (
        <section style={{ marginBottom: 4 }}>
          <div style={sectionTitle}>Link</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            {edge.utilization != null ? (
              <div style={{ border: "1px solid var(--border)", borderRadius: 6, background: "var(--surface)", padding: "7px 9px" }}>
                <div style={{ fontSize: 10, color: "var(--fg-subtle)", textTransform: "uppercase" }}>Utilization</div>
                <div style={{ fontSize: 14, fontWeight: 600, color, fontFamily: "var(--font-mono, ui-monospace, monospace)" }}>
                  {edge.utilization}%
                </div>
              </div>
            ) : null}
            {edge.errors != null ? (
              <div style={{ border: "1px solid var(--border)", borderRadius: 6, background: "var(--surface)", padding: "7px 9px" }}>
                <div style={{ fontSize: 10, color: "var(--fg-subtle)", textTransform: "uppercase" }}>Errors</div>
                <div style={{ fontSize: 14, fontWeight: 600, color: "var(--fg)", fontFamily: "var(--font-mono, ui-monospace, monospace)" }}>
                  {edge.errors}
                </div>
              </div>
            ) : null}
          </div>
        </section>
      ) : null}

      <ConfidencePanel confidence={edge.confidence} evidence={edge.evidence} />
      <EvidencePanel evidence={edge.evidence} />
    </>
  );
}

export default function TopologySideDrawer({
  view,
  selection,
  onClose,
}: {
  view: TopologyView;
  selection: TopologySelection;
  onClose: () => void;
}) {
  const node = selection.nodeId ? view.nodes.find((n) => n.id === selection.nodeId) : undefined;
  const edge = !node && selection.edgeId ? view.edges.find((e) => e.id === selection.edgeId) : undefined;

  if (!node && !edge) return null;

  return (
    <aside
      style={{
        position: "absolute",
        top: 0,
        right: 0,
        bottom: 0,
        width: 340,
        background: "var(--panel)",
        borderLeft: "1px solid var(--border)",
        boxShadow: "-8px 0 24px rgba(0,0,0,0.18)",
        overflowY: "auto",
        zIndex: 20,
        display: "flex",
        flexDirection: "column",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "flex-end",
          padding: "8px 10px 0",
          position: "sticky",
          top: 0,
        }}
      >
        <button
          type="button"
          onClick={onClose}
          aria-label="Close inspector"
          style={{
            border: "1px solid var(--border)",
            background: "var(--surface)",
            color: "var(--fg-muted)",
            borderRadius: 6,
            width: 26,
            height: 26,
            cursor: "pointer",
            fontSize: 15,
            lineHeight: 1,
          }}
        >
          ×
        </button>
      </div>

      <div style={{ padding: "4px 16px 20px" }}>
        {node ? <NodeBody node={node} /> : edge ? <EdgeBody edge={edge} view={view} /> : null}
      </div>
    </aside>
  );
}
