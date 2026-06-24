// TopologySideDrawer — the inspector. Answers the operator's five questions about
// the selected node/edge: what is it, is it healthy, what changed, what evidence,
// who owns it. Presentational only — selection + close are driven from above.

import type {
  TopologyView,
  TopologySelection,
  TopologyNode,
  TopologyEdge,
  TopologyGroup,
  ChangeState,
} from "../api/topologyTypes";
import {
  HEALTH_COLOR,
  HEALTH_GLYPH,
  HEALTH_LABEL,
  edgeEvidenceSummary,
  statusToHealth,
  rollupHealth,
  unresolvedReason,
} from "../utils/topologyHealth";
import type { Health } from "../api/topologyTypes";
import ConfidencePanel from "./ConfidencePanel";
import EvidencePanel from "./EvidencePanel";

const CHANGE_LABEL: Record<ChangeState, string> = {
  added: "Added in window",
  removed: "Removed in window",
  changed: "Changed in window",
  unchanged: "Unchanged",
  stale: "Stale (not re-observed)",
  unknown: "Unknown",
};

// Customer-facing wording for the link relationship — never the raw enum token.
const RELATIONSHIP_LABEL: Record<string, string> = {
  connected_to: "Connected",
  routed_adjacency: "Routed neighbor",
  dependency: "Depends on",
  inferred: "Inferred",
  flow: "Traffic dependency",
};

function HealthBadge({ health }: { health: Health }) {
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

const UNRESOLVED_ACTIONS = ["Resolve inventory", "Map alias", "Mark expected", "Ignore"];

function UnresolvedBlock({ node }: { node: TopologyNode }) {
  const rawId = node.tags?.raw_chassis ?? node.tags?.raw_id ?? node.label;
  const suggested = node.tags?.suggested_match;
  const missing = node.evidence.map((e) => e.missing_evidence_if_any).filter(Boolean)[0];
  return (
    <section
      style={{
        marginBottom: 14,
        border: "1px dashed var(--border)",
        borderRadius: 8,
        background: "var(--surface)",
        padding: "10px 11px",
      }}
    >
      <div style={{ ...sectionTitle, marginBottom: 6 }}>Unresolved — why it's here</div>
      <div style={{ fontSize: 12, color: "var(--fg)", marginBottom: 8 }}>{unresolvedReason(node.tags)}</div>
      <div style={{ display: "grid", gap: 2, marginBottom: 8 }}>
        <MetaRow label="Discovered as" value={rawId} />
        <MetaRow label="Suggested" value={suggested} />
        <MetaRow label="Missing" value={missing} />
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        {UNRESOLVED_ACTIONS.map((a) => (
          <button
            key={a}
            type="button"
            title={`${a} (Phase 2 stub — resolution backend lands later)`}
            style={{
              fontSize: 11, fontWeight: 600, padding: "4px 9px", cursor: "pointer",
              color: "var(--fg-muted)", background: "var(--panel)",
              border: "1px solid var(--border)", borderRadius: 6,
            }}
          >
            {a}
          </button>
        ))}
      </div>
    </section>
  );
}

const ISSUE_COLOR: Record<string, string> = {
  critical: "var(--danger, #e5484d)", crit: "var(--danger, #e5484d)", major: "var(--danger, #e5484d)",
  emergency: "var(--danger, #e5484d)", warning: "var(--warning, #f5a524)", warn: "var(--warning, #f5a524)",
  minor: "var(--warning, #f5a524)",
};
function issueColor(sev: string): string {
  return ISSUE_COLOR[sev.toLowerCase()] ?? "var(--fg-muted)";
}
function sinceLabel(ts?: string): string {
  if (!ts) return "";
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 90) return `${Math.round(s)}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 129600) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

// IssuesBlock — the "why is this device critical/warning" answer. The FIRST thing an
// operator needs on click: the active alerts driving the health, worst-first.
function IssuesBlock({ issues }: { issues: NonNullable<TopologyNode["issues"]> }) {
  if (!issues || issues.length === 0) return null;
  const worst = issueColor(issues[0].severity);
  return (
    <section
      style={{
        marginBottom: 14,
        border: `1px solid ${worst}`,
        borderRadius: 8,
        background: `color-mix(in srgb, ${worst} 8%, var(--surface))`,
        padding: "10px 11px",
      }}
    >
      <div style={{ ...sectionTitle, marginBottom: 8, color: "var(--fg)" }}>Active issues · {issues.length}</div>
      <div style={{ display: "grid", gap: 9 }}>
        {issues.map((iss, i) => (
          <div key={i} style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: issueColor(iss.severity), flex: "0 0 auto", marginTop: 4 }} />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 12, color: "var(--fg)", lineHeight: 1.45, wordBreak: "break-word" }}>{iss.summary}</div>
              <div style={{ fontSize: 10, color: "var(--fg-subtle)", textTransform: "uppercase", letterSpacing: 0.3, marginTop: 1 }}>
                {iss.severity}{sinceLabel(iss.since) ? ` · ${sinceLabel(iss.since)}` : ""}
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function NodeBody({ node }: { node: TopologyNode }) {
  const metrics = Object.entries(node.metrics ?? {});
  const unresolved = node.resolved === false || node.kind === "unresolved";
  return (
    <>
      {unresolved && <UnresolvedBlock node={node} />}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
        <h2 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: "var(--fg)" }}>{node.label}</h2>
        <HealthBadge health={node.health} />
      </div>
      <div style={{ fontSize: 11, color: "var(--fg-muted)", marginBottom: 14 }}>
        {[node.kind, node.role].filter(Boolean).join(" · ")}
      </div>

      <IssuesBlock issues={node.issues ?? []} />

      <div style={{ display: "grid", gap: 2, marginBottom: 14 }}>
        <MetaRow label="Vendor" value={node.vendor} />
        <MetaRow label="Model" value={node.model} />
        <MetaRow label="Mgmt IP" value={node.mgmt_ip} />
        <MetaRow label="Site" value={node.site} />
        <MetaRow label="Rack" value={node.rack} />
        <MetaRow label="Zone" value={node.zone} />
        <MetaRow label="Owner" value={node.owner} />
        <MetaRow label="Criticality" value={node.criticality} />
        <MetaRow label="First seen" value={node.first_seen} />
        <MetaRow label="Last seen" value={node.last_seen} />
        <MetaRow label="Change" value={node.change_state ? CHANGE_LABEL[node.change_state] : undefined} />
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
  const health = statusToHealth(edge.status);
  const color = HEALTH_COLOR[health];
  return (
    <>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
        <h2 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: "var(--fg)" }}>
          {(src?.label ?? edge.source)} → {(dst?.label ?? edge.target)}
        </h2>
        <HealthBadge health={health} />
      </div>
      <div style={{ fontSize: 11, color: "var(--fg-muted)", marginBottom: 14 }}>
        {edgeEvidenceSummary(edge)}
      </div>

      <div style={{ display: "grid", gap: 2, marginBottom: 14 }}>
        <MetaRow label="Relationship" value={RELATIONSHIP_LABEL[edge.relationship] ?? edge.relationship} />
        <MetaRow label="Source port" value={edge.source_port} />
        <MetaRow label="Target port" value={edge.target_port} />
        <MetaRow label="Status" value={edge.status} />
        <MetaRow
          label="Utilization"
          value={edge.utilization_pct != null ? `${edge.utilization_pct}%` : undefined}
        />
        <MetaRow label="Errors" value={edge.errors != null ? String(edge.errors) : undefined} />
        <MetaRow label="Last seen" value={edge.last_seen} />
        <MetaRow
          label="Bundle"
          value={edge.bundle_count && edge.bundle_count > 1 ? `${edge.bundle_count}× members` : undefined}
        />
      </div>

      {(edge.utilization_pct != null || edge.errors != null) ? (
        <section style={{ marginBottom: 4 }}>
          <div style={sectionTitle}>Link</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            {edge.utilization_pct != null ? (
              <div style={{ border: "1px solid var(--border)", borderRadius: 6, background: "var(--surface)", padding: "7px 9px" }}>
                <div style={{ fontSize: 10, color: "var(--fg-subtle)", textTransform: "uppercase" }}>Utilization</div>
                <div style={{ fontSize: 14, fontWeight: 600, color, fontFamily: "var(--font-mono, ui-monospace, monospace)" }}>
                  {edge.utilization_pct}%
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

function GroupBody({
  group,
  view,
  collapsed,
  onToggleGroup,
}: {
  group: TopologyGroup;
  view: TopologyView;
  collapsed: boolean;
  onToggleGroup?: (id: string) => void;
}) {
  const members = group.children
    .map((id) => view.nodes.find((n) => n.id === id))
    .filter(Boolean) as TopologyNode[];
  const worst = rollupHealth(members);
  const critical = members.filter((m) => m.health === "critical").length;
  const warning = members.filter((m) => m.health === "warning").length;
  const links = view.edges.filter((e) => group.children.includes(e.source) || group.children.includes(e.target)).length;
  return (
    <>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
        <h2 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: "var(--fg)" }}>{group.label}</h2>
        <HealthBadge health={worst} />
      </div>
      <div style={{ fontSize: 11, color: "var(--fg-muted)", marginBottom: 14 }}>
        {group.group_type} · {members.length} nodes
      </div>

      <div style={{ display: "grid", gap: 2, marginBottom: 14 }}>
        <MetaRow label="Nodes" value={String(members.length)} />
        <MetaRow label="Critical" value={critical ? String(critical) : undefined} />
        <MetaRow label="Warning" value={warning ? String(warning) : undefined} />
        <MetaRow label="Links" value={String(links)} />
        <MetaRow label="Owner" value={group.owner} />
        <MetaRow label="State" value={collapsed ? "Collapsed" : "Expanded"} />
      </div>

      <section style={{ marginBottom: 12 }}>
        <button
          type="button"
          onClick={() => onToggleGroup?.(group.id)}
          style={{
            width: "100%", padding: "8px 10px", fontSize: 12, fontWeight: 600, cursor: "pointer",
            color: "var(--fg)", background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 7,
          }}
        >
          {collapsed ? "Expand group" : "Collapse group"}
        </button>
      </section>

      <section>
        <div style={sectionTitle}>Members</div>
        <div style={{ display: "grid", gap: 4 }}>
          {members.map((m) => (
            <div key={m.id} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "var(--fg)" }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: HEALTH_COLOR[m.health], flex: "0 0 auto" }} />
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{m.label}</span>
              <span style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--fg-subtle)" }}>{m.role ?? m.kind}</span>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}

export default function TopologySideDrawer({
  view,
  selection,
  onClose,
  collapsedGroups,
  onToggleGroup,
}: {
  view: TopologyView;
  selection: TopologySelection;
  onClose: () => void;
  collapsedGroups?: Set<string>;
  onToggleGroup?: (id: string) => void;
}) {
  const node = selection.nodeId ? view.nodes.find((n) => n.id === selection.nodeId) : undefined;
  const edge = !node && selection.edgeId ? view.edges.find((e) => e.id === selection.edgeId) : undefined;
  const group = !node && !edge && selection.groupId ? view.groups.find((g) => g.id === selection.groupId) : undefined;

  if (!node && !edge && !group) return null;

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
        {node ? (
          <NodeBody node={node} />
        ) : edge ? (
          <EdgeBody edge={edge} view={view} />
        ) : group ? (
          <GroupBody
            group={group}
            view={view}
            collapsed={collapsedGroups?.has(group.id) ?? false}
            onToggleGroup={onToggleGroup}
          />
        ) : null}
      </div>
    </aside>
  );
}
