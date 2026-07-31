import { useMemo, useState } from "react";
import type { TopologyView, TopologyNode, TopologySelection } from "../api/topologyTypes";
import { HEALTH_COLOR, HEALTH_LABEL } from "../utils/topologyHealth";
import { ShapeSVG, kindForRole } from "../../../components/graph/shapes";

// TopologyInventoryPanel — the ContainerLab-style device list beside the canvas
// (vendor research §b): one mental model, two projections. Each row is a device
// from the SAME resolved view the canvas renders — status dot (health), role
// glyph (the shared shape kit, so list and future node glyphs agree), hostname,
// mgmt IP, and "observed since" (first_seen from the persisted graph — the
// honest proxy until an SNMP sysUpTime metric exists; last_seen otherwise).
// Selection is BIDIRECTIONAL: a row click centres+selects on the canvas
// (onPick), and the canvas selection highlights the row.

const dot = (health?: string): string => HEALTH_COLOR[(health ?? "unknown") as keyof typeof HEALTH_COLOR] ?? "var(--fg-subtle)";

/** Compact relative age: "3m" / "4h" / "12d" — list rows have no room for dates. */
function rel(iso?: string): string {
  if (!iso) return "";
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms) || ms < 0) return "";
  const m = Math.floor(ms / 60_000);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

function deviceRows(view: TopologyView): TopologyNode[] {
  return view.nodes
    .filter((n) => n.kind !== "group" && n.kind !== "site")
    .sort((a, b) => a.label.localeCompare(b.label));
}

export function TopologyInventoryPanel({ view, selection, onPick }: {
  view: TopologyView;
  selection: TopologySelection;
  onPick: (nodeId: string) => void;
}) {
  const [filter, setFilter] = useState("");
  const rows = useMemo(() => {
    const all = deviceRows(view);
    const q = filter.trim().toLowerCase();
    if (!q) return all;
    return all.filter((n) =>
      `${n.label} ${n.mgmt_ip ?? ""} ${n.role ?? ""} ${n.vendor ?? ""} ${n.site ?? ""}`.toLowerCase().includes(q),
    );
  }, [view, filter]);
  const total = useMemo(() => deviceRows(view).length, [view]);
  const down = useMemo(() => deviceRows(view).filter((n) => n.health === "critical").length, [view]);

  return (
    <aside className="topo-inventory" aria-label="Device inventory">
      <div className="topo-inventory-head">
        <strong>Devices</strong>
        <span className="topo-inventory-count">
          {total}
          {down > 0 && <span style={{ color: "var(--bad)" }}> · {down} critical</span>}
        </span>
      </div>
      <input
        className="topo-inventory-filter"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter devices…"
        aria-label="Filter the device inventory"
      />
      <div className="topo-inventory-list" role="listbox" aria-label="Devices">
        {rows.length === 0 && (
          <div className="topo-inventory-empty">{filter ? "No devices match the filter." : "No devices in this view."}</div>
        )}
        {rows.map((n) => {
          const selected = selection.nodeId === n.id;
          const since = rel(n.first_seen || n.last_seen);
          const unresolved = n.kind === "unresolved";
          return (
            <button
              key={n.id}
              type="button"
              role="option"
              aria-selected={selected}
              className={`topo-inventory-row${selected ? " on" : ""}`}
              onClick={() => onPick(n.id)}
              title={[
                n.label,
                n.mgmt_ip && `mgmt ${n.mgmt_ip}`,
                `health: ${HEALTH_LABEL[(n.health ?? "unknown") as keyof typeof HEALTH_LABEL] ?? n.health ?? "unknown"}`,
                n.first_seen ? `observed since ${n.first_seen}` : n.last_seen ? `last seen ${n.last_seen}` : null,
                ...(n.issues ?? []).slice(0, 3).map((i) => `⚠ ${i.summary}`),
              ].filter(Boolean).join("\n")}
            >
              <span
                className="topo-inventory-dot"
                style={{ background: dot(n.health), boxShadow: n.health === "ok" ? `0 0 0 3px ${dot(n.health)}22` : undefined }}
                aria-hidden
              />
              <span style={{ color: "var(--fg-muted)", display: "inline-flex", flex: "0 0 auto", opacity: unresolved ? 0.6 : 1 }}>
                <ShapeSVG kind={kindForRole(n.role || n.kind)} tone={dot(n.health)} size={18} />
              </span>
              <span className="topo-inventory-name">{n.label}</span>
              <span className="topo-inventory-meta">
                {n.mgmt_ip || (unresolved ? "unresolved" : "")}
                {since && <span className="topo-inventory-since"> · {since}</span>}
              </span>
            </button>
          );
        })}
      </div>
    </aside>
  );
}
