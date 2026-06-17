import { useEffect, useState } from "react";
import { PANELS } from "./panels";
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
const SECTIONS: Section[] = [
  { id: "health", label: "Service health", caption: "fleet posture at a glance", hue: "#3b82f6",
    cells: [["kpis", 12], ["site-availability", 4], ["stack-performance", 8]] },
  { id: "resources", label: "Resource saturation", caption: "where headroom is thinning", hue: "#8b5cf6",
    cells: [["gauge-cpu", 3], ["gauge-mem", 3], ["gauge-storage", 3], ["gauge-network", 3]] },
  { id: "traffic", label: "Traffic & flows", caption: "what's moving across the fabric", hue: "#06b6d4",
    cells: [["traffic", 8], ["top-hosts", 4], ["flows-proto", 4], ["tunnels-health", 4], ["devices-vendor", 4]] },
  { id: "wan", label: "WAN & interfaces", caption: "edge + per-interface live state", hue: "#14b8a6",
    cells: [["wan-interfaces", 12]] },
  { id: "events", label: "Events & incidents", caption: "what needs a human", hue: "#ec4899",
    cells: [["alerts-severity", 12], ["active-alerts", 6], ["incidents", 6]] },
  { id: "topology", label: "Topology", caption: "how it's wired together", hue: "#22c55e",
    cells: [["topology", 12]] },
];

export default function Dashboard() {
  const { navigate } = useShell();
  const [zoom, setZoom] = useState<string | null>(null);
  const [now, setNow] = useState(() => new Date());
  // light heartbeat so the "as of" clock reads live during a demo (panels own their
  // own refresh; this is just the header timestamp).
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 30_000); return () => clearInterval(t); }, []);

  let n = 0;
  return (
    <div className="mydash">
      <div className="mydash-head">
        <div>
          <div className="mydash-eyebrow">Operations</div>
          <h1 className="mydash-title">Dashboard</h1>
        </div>
        <div className="mydash-head-meta">
          <span className="mydash-live"><span className="mydash-live-dot" /> Live</span>
          <span className="mydash-asof">as of {now.toLocaleTimeString()}</span>
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
                      <h3
                        className={def.drill ? "panel-title-link" : undefined}
                        onClick={def.drill ? () => navigate(def.drill!) : undefined}
                        style={def.drill ? { cursor: "pointer" } : undefined}
                        title={def.drill ? "Open detail view" : undefined}
                      >
                        {def.title}
                        {def.drill && <Icon name="arrow-up-right" size={13} className="panel-drill-icon" />}
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
