import { useState } from "react";
import { PANELS, PANEL_ORDER, PanelDef } from "./panels";

// Operations Overview — a modular, Datadog/Zabbix-style board. The layout is a
// list of panels the user composes themselves: add from the panel library,
// resize (column span), and remove. Layout persists in localStorage so it
// survives reloads. Each panel (see panels.tsx) fetches its own live data.

type Item = { key: string; type: string; span: number };

const LS_KEY = "netops.overview.layout.v2";

// A rich, communicative default — mirrors what NOC overviews ship with:
// KPIs, resource gauges, a severity-coded alert row, traffic, top hosts,
// availability/health, active alerts, and the topology.
const DEFAULT_LAYOUT: Item[] = [
  { key: "d-kpis", type: "kpis", span: 12 },
  { key: "d-cpu", type: "gauge-cpu", span: 3 },
  { key: "d-mem", type: "gauge-mem", span: 3 },
  { key: "d-sto", type: "gauge-storage", span: 3 },
  { key: "d-net", type: "gauge-network", span: 3 },
  { key: "d-sev", type: "alerts-severity", span: 12 },
  { key: "d-traffic", type: "traffic", span: 8 },
  { key: "d-tophosts", type: "top-hosts", span: 4 },
  { key: "d-avail", type: "site-availability", span: 4 },
  { key: "d-perf", type: "stack-performance", span: 8 },
  { key: "d-alerts", type: "active-alerts", span: 12 },
  { key: "d-topo", type: "topology", span: 12 },
];

const SPANS = [3, 4, 6, 8, 12];

function loadLayout(): Item[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Item[];
      // Drop any panel types that no longer exist in the registry.
      const valid = parsed.filter((i) => PANELS[i.type]);
      if (valid.length) return valid;
    }
  } catch {
    /* fall through to default */
  }
  return DEFAULT_LAYOUT;
}

function uid(): string {
  return "p" + Date.now().toString(36) + Math.floor(Math.random() * 1e5).toString(36);
}

export default function Dashboard() {
  const [items, setItems] = useState<Item[]>(loadLayout);
  const [picking, setPicking] = useState(false);

  const persist = (next: Item[]) => {
    setItems(next);
    try {
      localStorage.setItem(LS_KEY, JSON.stringify(next));
    } catch {
      /* ignore quota errors */
    }
  };

  const add = (type: string) => {
    const def = PANELS[type];
    persist([...items, { key: uid(), type, span: def.defaultSpan }]);
    setPicking(false);
  };
  const remove = (key: string) => persist(items.filter((i) => i.key !== key));
  const resize = (key: string) =>
    persist(
      items.map((i) =>
        i.key === key ? { ...i, span: SPANS[(SPANS.indexOf(i.span) + 1) % SPANS.length] } : i,
      ),
    );
  const reset = () => {
    try {
      localStorage.removeItem(LS_KEY);
    } catch {
      /* ignore */
    }
    setItems(DEFAULT_LAYOUT);
  };

  return (
    <div className="ov">
      <div className="ov-head">
        <h1 className="ov-title">
          Operations Overview <span>real-time NOC</span>
        </h1>
        <div className="ov-actions">
          <button className="dash-btn accent" onClick={() => setPicking((p) => !p)}>
            + Add panel
          </button>
          <button className="dash-btn" onClick={reset} title="Restore the default layout">
            Reset
          </button>
        </div>
      </div>

      {picking && (
        <div className="panel-picker">
          {PANEL_ORDER.map((type) => (
            <button key={type} onClick={() => add(type)}>
              + {(PANELS[type] as PanelDef).title}
            </button>
          ))}
        </div>
      )}

      <div className="ov-grid">
        {items.length === 0 && (
          <div className="panel col-12 panel-empty">
            No panels — click “+ Add panel” to build your overview.
          </div>
        )}
        {items.map((item) => {
          const def = PANELS[item.type];
          if (!def) return null;
          return (
            <div className={`panel col-${item.span}`} key={item.key}>
              <div className="panel-tools">
                <h3>{def.title}</h3>
                <div className="panel-tools-btns">
                  <button onClick={() => resize(item.key)} title="Resize">⤢</button>
                  <button onClick={() => remove(item.key)} title="Remove">✕</button>
                </div>
              </div>
              {def.render()}
            </div>
          );
        })}
      </div>
    </div>
  );
}
