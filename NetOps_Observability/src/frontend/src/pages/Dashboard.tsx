import { useState } from "react";
import { fmtTime } from "../lib/time";
import { PANELS, useBoardHealth } from "./panels";
import { useShell } from "../context/shell";
import Icon from "../components/Icon";
import { Modal } from "../components/ui";

// My Dashboard — a fixed, dense, demo-ready operations board (rebuilt fresh).
// Not a build-your-own canvas: a curated single-screen story over the signals THIS
// tool collects (fleet health → resources → traffic/flows → WAN/sites → events &
// incidents → topology), every panel wired to its live source via the panel
// registry (panels.tsx). The "twist" is ours: numbered section eyebrows with an
// accent rule, a tight 12-col grid, and per-section hues from the Correlix palette.

type Cell = [type: string, span: number];
type Section = { id: string; label: string; caption: string; hue: string; cells: Cell[] };

// Curated layout. Each cell.type MUST exist in PANELS (registry = the wiring); a
// missing type is skipped so the board never renders a dead panel.
// Section order follows a NOC ops blueprint (FCAPS for ordering, USE for the
// per-resource panels, RED for active measurement): fleet health → saturation →
// traffic/flows → interfaces → errors → routing → path quality → events →
// topology. Every cell is a wired registry panel; a missing type is skipped.
const SECTIONS: Section[] = [
  { id: "health", label: "Service health", caption: "fleet posture at a glance", hue: "#3b82f6",
    cells: [["kpis", 12]] },
  { id: "resources", label: "Resource saturation", caption: "where headroom is thinning", hue: "#8b5cf6",
    cells: [["sat-cpu", 3], ["sat-mem", 3], ["sat-storage", 3], ["sat-temp", 3]] },
  { id: "traffic", label: "Traffic & flows", caption: "what's moving across the fabric", hue: "#06b6d4",
    cells: [["traffic", 8], ["top-hosts", 4], ["flows-proto", 4], ["tunnels-health", 4], ["devices-vendor", 4]] },
  { id: "wan", label: "WAN & interfaces", caption: "edge + per-interface live state", hue: "#14b8a6",
    cells: [["wan-interfaces", 6], ["if-util-topn", 6]] },
  { id: "errors", label: "Errors & quality", caption: "where the link is taking damage", hue: "#f97316",
    cells: [["if-errors-topn", 6], ["if-discards-topn", 6]] },
  { id: "routing", label: "Control-plane", caption: "is routing converged & stable", hue: "#0ea5e9",
    cells: [["bgp-peers", 6], ["ospf-nbrs", 6]] },
  { id: "path", label: "Path quality", caption: "experienced latency, jitter & loss", hue: "#a855f7",
    cells: [["probe-rtt", 4], ["probe-jitter", 4], ["probe-loss", 4]] },
  { id: "events", label: "Events & incidents", caption: "what needs a human", hue: "#ec4899",
    cells: [["alerts-severity", 12], ["active-alerts", 6], ["incidents", 6]] },
  { id: "topology", label: "Topology", caption: "how it's wired together", hue: "#22c55e",
    cells: [["topology", 12]] },
];

export default function Dashboard() {
  const { navigate } = useShell();
  const [zoom, setZoom] = useState<string | null>(null);
  // Liveness is DERIVED FROM REAL FETCHES, never from a wall clock. The old
  // header ran a local setInterval and printed "as of HH:MM" beside a pulsing
  // dot — a freshness claim decoupled from the network by construction, so a
  // total backend outage still read as a live board. Panels report every poll
  // outcome into the board-health signal; this header states what it says.
  const { lastOk, failing, feeds } = useBoardHealth();
  const degraded = failing > 0;
  const connecting = lastOk === null && !degraded;

  let n = 0;
  return (
    <div className="mydash">
      <div className="mydash-head">
        <div>
          <div className="mydash-eyebrow">Operations</div>
          <h1 className="mydash-title">Dashboard</h1>
        </div>
        <div className="mydash-head-meta" role="status" aria-live="polite">
          {degraded ? (
            <>
              <span className="mydash-live" style={{ color: "var(--bad)" }}>
                <span className="mydash-live-dot" style={{ background: "var(--bad)", animation: "none" }} /> Disconnected
              </span>
              <span className="mydash-asof">
                {failing} of {feeds} feed{feeds === 1 ? "" : "s"} failing
                {lastOk === null ? " · no data loaded" : ` · last data ${fmtTime(new Date(lastOk))}`}
              </span>
            </>
          ) : connecting ? (
            <>
              <span className="mydash-live" style={{ color: "var(--muted)" }}>
                <span className="mydash-live-dot" style={{ background: "var(--muted)", animation: "none" }} /> Connecting
              </span>
              <span className="mydash-asof">no data loaded yet</span>
            </>
          ) : (
            <>
              <span className="mydash-live"><span className="mydash-live-dot" /> Live</span>
              <span className="mydash-asof">as of {fmtTime(new Date(lastOk!))}</span>
            </>
          )}
        </div>
      </div>

      {SECTIONS.map((s) => {
        const cells = s.cells.filter(([type]) => PANELS[type]);
        if (cells.length === 0) return null;
        n += 1;
        const idx = String(n).padStart(2, "0");
        return (
          <section className="mydash-sec" key={s.id} style={{ ["--sec" as string]: s.hue } as React.CSSProperties}>
            <div className="mydash-sec-h">
              <span className="mydash-sec-n">{idx}</span>
              <h2 className="mydash-sec-t">{s.label}</h2>
              <span className="mydash-sec-cap">{s.caption}</span>
              <span className="mydash-sec-rule" />
            </div>
            <div className="ov-grid mydash-grid">
              {cells.map(([type, span], i) => {
                const def = PANELS[type];
                return (
                  <div className={`panel col-${span}`} key={`${type}-${i}`}>
                    <div className="panel-tools">
                      {/* Drill affordance is a real button INSIDE the heading —
                          a clickable <h3> is neither focusable nor keyboard
                          operable (2.1.1/4.1.2). */}
                      <h3>
                        {def.drill ? (
                          <button
                            type="button"
                            className="panel-title-link"
                            onClick={() => navigate(def.drill!)}
                            title="Open detail view"
                            aria-label={`${def.title} — open detail view`}
                          >
                            {def.title}
                            <Icon name="arrow-up-right" size={13} className="panel-drill-icon" />
                          </button>
                        ) : (
                          def.title
                        )}
                      </h3>
                      <div className="panel-tools-btns">
                        <button onClick={() => setZoom(type)} title="Enlarge" aria-label="Enlarge panel">⤢</button>
                      </div>
                    </div>
                    {def.render()}
                  </div>
                );
              })}
            </div>
          </section>
        );
      })}

      {zoom && PANELS[zoom] && (
        <Modal title={PANELS[zoom].title} wide onClose={() => setZoom(null)}>
          <div className="panel-zoom-body">{PANELS[zoom].render()}</div>
        </Modal>
      )}
    </div>
  );
}
