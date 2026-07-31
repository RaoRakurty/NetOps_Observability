import { fmtTime } from "../lib/time";
import { PANELS, useBoardHealth } from "./panels";

// Demo Showcase — the marketing board: a single self-running screen that leads
// with motion and shape variety (gauge wheels, ranked bars, donuts, layered
// area trends) over the SAME live wiring every other board uses (the panel
// registry — nothing here is mocked). Style over depth is the point of this
// page and it says so in its eyebrow; the operational boards stay the honest
// dense ones. One rule is still non-negotiable: liveness derives from real
// fetches (useBoardHealth), never a wall clock — a demo that fakes "Live"
// during an outage would be the worst possible sales moment.

type Cell = [type: string, span: number];
type Section = { id: string; label: string; caption: string; hue: string; cells: Cell[] };

// Shape variety by design: wheels → bars → donut+area mix → layered trends.
const SECTIONS: Section[] = [
  { id: "pulse", label: "Network pulse", caption: "fleet vitals, spinning live", hue: "#06b6d4",
    cells: [["gauge-cpu", 3], ["gauge-mem", 3], ["gauge-network", 3], ["gauge-storage", 3]] },
  { id: "interfaces", label: "Interfaces under load", caption: "SNMP interface utilization, ranked", hue: "#8b5cf6",
    cells: [["if-util-topn", 6], ["if-errors-topn", 6]] },
  { id: "flows", label: "Traffic & NetFlow", caption: "who is talking, over what", hue: "#818cf8",
    cells: [["traffic", 8], ["flows-proto", 4], ["top-hosts", 4], ["devices-vendor", 4], ["tunnels-health", 4]] },
  { id: "trends", label: "Resource trends", caption: "CPU, memory, storage, heat — per device", hue: "#f59e0b",
    cells: [["sat-cpu", 3], ["sat-mem", 3], ["sat-storage", 3], ["sat-temp", 3]] },
  { id: "attention", label: "Needs attention", caption: "and what the platform already caught", hue: "#ec4899",
    cells: [["alerts-severity", 12]] },
];

export default function DemoShowcase() {
  const { lastOk, failing, feeds } = useBoardHealth();
  const degraded = failing > 0;
  const connecting = lastOk === null && !degraded;

  let n = 0;
  return (
    <div className="mydash demo-showcase">
      <div className="demo-hero">
        <div className="demo-hero-text">
          <div className="mydash-eyebrow">Correlix · live demo</div>
          <h1 className="demo-hero-title">One network. Every signal. Live.</h1>
          <p className="demo-hero-sub">
            SNMP telemetry, NetFlow, synthetic probes and events — correlated on one screen,
            straight from the running stack. Nothing on this page is a mock.
          </p>
        </div>
        <div className="mydash-head-meta" role="status" aria-live="polite">
          {degraded ? (
            <span className="mydash-live" style={{ color: "var(--bad)" }}>
              <span className="mydash-live-dot" style={{ background: "var(--bad)", animation: "none" }} />
              {failing} of {feeds} feeds failing
            </span>
          ) : connecting ? (
            <span className="mydash-live" style={{ color: "var(--muted)" }}>
              <span className="mydash-live-dot" style={{ background: "var(--muted)", animation: "none" }} /> Connecting
            </span>
          ) : (
            <span className="mydash-live"><span className="mydash-live-dot" /> Live · {fmtTime(new Date(lastOk!))}</span>
          )}
        </div>
      </div>

      <div className="ov-grid mydash-grid" style={{ marginBottom: 18 }}>
        <div className="panel col-12 demo-panel">
          <div className="panel-tools"><h3>{PANELS.kpis.title}</h3></div>
          {PANELS.kpis.render()}
        </div>
      </div>

      {SECTIONS.map((s) => {
        const cells = s.cells.filter(([type]) => PANELS[type]);
        if (cells.length === 0) return null;
        n += 1;
        return (
          <section className="mydash-sec" key={s.id} style={{ ["--sec" as string]: s.hue } as React.CSSProperties}>
            <div className="mydash-sec-h">
              <span className="mydash-sec-n">{String(n).padStart(2, "0")}</span>
              <h2 className="mydash-sec-t">{s.label}</h2>
              <span className="mydash-sec-cap">{s.caption}</span>
              <span className="mydash-sec-rule" />
            </div>
            <div className="ov-grid mydash-grid">
              {cells.map(([type, span], i) => (
                <div className={`panel col-${span} demo-panel`} key={`${type}-${i}`}>
                  <div className="panel-tools"><h3>{PANELS[type].title}</h3></div>
                  {PANELS[type].render()}
                </div>
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}
