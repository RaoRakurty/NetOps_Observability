// CapacityPanel — the docked read-out for the Capacity workflow. Ranks the
// busiest measured links (utilization bar + endpoints + error/saturation badges)
// and lists ECMP sibling sets whose load has drifted out of balance. Pure
// presentation over topologyCapacity helpers; no graph mutation.

import { useState, type CSSProperties, type ReactNode } from "react";
import type { TopologyView } from "../api/topologyTypes";
import {
  rankHotLinks,
  ecmpGroups,
  linkHeadroom,
  simulateDrain,
  SATURATION_THRESHOLD,
  type HotLink,
} from "../utils/topologyCapacity";

const SECTION_LABEL: CSSProperties = {
  fontSize: 11,
  fontWeight: 600,
  letterSpacing: 0.4,
  textTransform: "uppercase",
  color: "var(--fg-subtle)",
  marginBottom: 8,
};
const MONO = "var(--font-mono, ui-monospace, monospace)";

/** Utilization → bar colour band (calm under load, hot near saturation). */
function utilColor(u: number): string {
  if (u >= SATURATION_THRESHOLD) return "var(--danger, #e5484d)";
  if (u >= 70) return "var(--warning, #f5a524)";
  return "var(--accent, #5b8def)";
}

function HotRow({ link }: { link: HotLink }) {
  const u = link.utilization;
  return (
    <li
      style={{
        padding: "8px 10px",
        border: "1px solid var(--border)",
        borderRadius: 6,
        background: "var(--surface)",
        display: "grid",
        gap: 6,
      }}
    >
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 8 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: "var(--fg)", fontFamily: MONO, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {link.sourceLabel} → {link.targetLabel}
        </span>
        <span style={{ fontSize: 12, fontWeight: 700, color: utilColor(u), fontFamily: MONO, flex: "0 0 auto" }}>
          {u}%
        </span>
      </div>
      {/* utilization bar */}
      <div style={{ height: 6, borderRadius: 3, background: "var(--panel)", overflow: "hidden" }}>
        <div style={{ width: `${Math.min(100, u)}%`, height: "100%", background: utilColor(u) }} />
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {link.saturated ? <Badge tone="danger">saturated</Badge> : null}
        {link.errored ? <Badge tone="warning">{link.edge.errors} errors</Badge> : null}
        {link.edge.bundle_id ? <Badge tone="muted">{link.edge.bundle_id}</Badge> : null}
        {link.edge.source_port ? (
          <span style={{ fontSize: 10, color: "var(--fg-subtle)", fontFamily: MONO }}>
            {link.edge.source_port}↔{link.edge.target_port}
          </span>
        ) : null}
      </div>
    </li>
  );
}

function Badge({ tone, children }: { tone: "danger" | "warning" | "muted"; children: ReactNode }) {
  const map = {
    danger: { fg: "var(--danger, #e5484d)", bg: "color-mix(in srgb, var(--danger, #e5484d) 14%, transparent)" },
    warning: { fg: "var(--warning, #f5a524)", bg: "color-mix(in srgb, var(--warning, #f5a524) 14%, transparent)" },
    muted: { fg: "var(--fg-subtle)", bg: "var(--panel)" },
  }[tone];
  return (
    <span style={{ fontSize: 10, fontWeight: 600, color: map.fg, background: map.bg, padding: "1px 6px", borderRadius: 999 }}>
      {children}
    </span>
  );
}

export default function CapacityPanel({ view }: { view: TopologyView }) {
  const hot = rankHotLinks(view, 6);
  const imbalance = ecmpGroups(view);
  const headroom = linkHeadroom(view).slice(0, 6);
  const [drainId, setDrainId] = useState<string | null>(null);
  const drain = drainId ? simulateDrain(view, drainId) : [];
  // Always show device names, never raw internal link ids (customer-facing language).
  const nodeName = (id: string) => view.nodes.find((n) => n.id === id)?.label ?? id;

  if (hot.length === 0) {
    return (
      <div style={{ fontSize: 12, color: "var(--fg-muted)", padding: 12, border: "1px dashed var(--border)", borderRadius: 6, background: "var(--surface)" }}>
        No measured link utilization in this view.
      </div>
    );
  }

  return (
    <section style={{ display: "grid", gap: 14 }}>
      <div>
        <div style={SECTION_LABEL}>Hot links · busiest {hot.length}</div>
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 6 }}>
          {hot.map((l) => (
            <HotRow key={l.edge.id} link={l} />
          ))}
        </ul>
      </div>

      <div>
        <div style={SECTION_LABEL}>Headroom &amp; what-if</div>
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 6 }}>
          {headroom.map((h) => {
            const open = drainId === h.edge.id;
            return (
              <li key={h.edge.id} style={{ padding: "7px 10px", border: "1px solid var(--border)", borderRadius: 6, background: "var(--surface)", display: "grid", gap: 5 }}>
                <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 8 }}>
                  <span style={{ fontSize: 11, fontWeight: 600, color: "var(--fg)", fontFamily: MONO, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {nodeName(h.edge.source)} ↔ {nodeName(h.edge.target)}
                  </span>
                  <span style={{ display: "inline-flex", gap: 6, alignItems: "baseline", flex: "0 0 auto" }}>
                    {h.spof ? <Badge tone="warning">no ECMP backup</Badge> : null}
                    <span style={{ fontSize: 11, fontWeight: 700, fontFamily: MONO, color: utilColor(SATURATION_THRESHOLD - h.headroom) }}>
                      {Math.round(h.headroom)}% headroom
                    </span>
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setDrainId(open ? null : h.edge.id)}
                  style={{ justifySelf: "start", fontSize: 10, fontWeight: 600, color: "var(--accent)", background: "none", border: "none", cursor: "pointer", padding: 0 }}
                >
                  {open ? "▾ hide" : "▸ what if this drains?"}
                </button>
                {open && (
                  <div style={{ display: "grid", gap: 4, borderTop: "1px dashed var(--border)", paddingTop: 5 }}>
                    {drain.map((d) =>
                      d.stranded ? (
                        <div key={d.node} style={{ fontSize: 10, color: "var(--danger, #e5484d)", fontWeight: 600 }}>
                          {d.nodeLabel}: STRANDED — no surviving path
                        </div>
                      ) : (
                        <div key={d.node} style={{ fontSize: 10, color: "var(--fg-subtle)", fontFamily: MONO }}>
                          {d.nodeLabel}: {d.redistributed
                            .map((r) => `${r.otherLabel} ${Math.round(r.before)}→${Math.round(r.after)}%${r.saturates ? " ⚠" : ""}`)
                            .join("  ·  ")}
                        </div>
                      ),
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      </div>

      <div>
        <div style={SECTION_LABEL}>
          ECMP imbalance {imbalance.length ? `· ${imbalance.length}` : ""}
        </div>
        {imbalance.length === 0 ? (
          <div style={{ fontSize: 11, color: "var(--fg-subtle)" }}>ECMP sibling sets are balanced.</div>
        ) : (
          <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 6 }}>
            {imbalance.map((g) => (
              <li
                key={g.node}
                style={{ padding: "8px 10px", border: "1px solid var(--border)", borderRadius: 6, background: "var(--surface)" }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: "var(--fg)", fontFamily: MONO }}>{g.nodeLabel}</span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: "var(--warning, #f5a524)", fontFamily: MONO }}>
                    Δ{g.spread}%
                  </span>
                </div>
                <div style={{ fontSize: 10, color: "var(--fg-subtle)", marginTop: 3, fontFamily: MONO }}>
                  {g.members.map((m) => `${m.otherLabel} ${m.utilization}%`).join("  ·  ")}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
