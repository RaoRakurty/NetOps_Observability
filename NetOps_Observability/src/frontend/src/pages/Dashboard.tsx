import { useState } from "react";
import { PANELS, PANEL_CATEGORIES, PanelDef } from "./panels";
import { useShell } from "../context/shell";
import Icon from "../components/Icon";

// Operations Overview — a modular, Zabbix-style board. The layout is a
// list of panels the user composes themselves: add from the panel library,
// resize (column span), and remove. Layout persists in localStorage so it
// survives reloads. Each panel (see panels.tsx) fetches its own live data.

type Item = { key: string; type: string; span: number };

// Bumped to v4: denser, fuller default board (more panels, smaller spans) so
// the Overview reads like a packed NOC wall rather than a sparse page. Older
// custom layouts are superseded once on upgrade.
const LS_KEY = "netops.overview.layout.v4";

// A rich, dense default in NOC reading order: top-line KPIs, then what's wrong
// right now (severity), resource gauges, a traffic row, an inventory/health row,
// the alert + incident streams side by side, and the topology.
const DEFAULT_LAYOUT: Item[] = [
  { key: "d-kpis", type: "kpis", span: 12 },
  { key: "d-sev", type: "alerts-severity", span: 12 },
  { key: "d-cpu", type: "gauge-cpu", span: 3 },
  { key: "d-mem", type: "gauge-mem", span: 3 },
  { key: "d-sto", type: "gauge-storage", span: 3 },
  { key: "d-net", type: "gauge-network", span: 3 },
  { key: "d-traffic", type: "traffic", span: 8 },
  { key: "d-tophosts", type: "top-hosts", span: 4 },
  { key: "d-proto", type: "flows-proto", span: 4 },
  { key: "d-tunnels", type: "tunnels-health", span: 4 },
  { key: "d-vendor", type: "devices-vendor", span: 4 },
  { key: "d-avail", type: "site-availability", span: 4 },
  { key: "d-perf", type: "stack-performance", span: 8 },
  { key: "d-alerts", type: "active-alerts", span: 6 },
  { key: "d-incidents", type: "incidents", span: 6 },
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
  const { navigate } = useShell();
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
          {PANEL_CATEGORIES.map(({ category, types }) => (
            <div className="panel-picker-group" key={category}>
              <div className="panel-picker-label">{category}</div>
              <div className="panel-picker-items">
                {types.map((type) => (
                  <button key={type} onClick={() => add(type)}>
                    + {(PANELS[type] as PanelDef).title}
                  </button>
                ))}
              </div>
            </div>
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
                <h3
                  className={def.drill ? "panel-title-link" : undefined}
                  onClick={def.drill ? () => navigate(def.drill!) : undefined}
                  style={def.drill ? { cursor: "pointer" } : undefined}
                  title={def.drill ? "Open detail view" : undefined}
                >
                  {def.title}
                  {def.drill && <span style={{ opacity: 0.45, marginLeft: 6, fontSize: 12 }}>↗</span>}
                </h3>
                <div className="panel-tools-btns">
                  <button onClick={() => resize(item.key)} title="Resize" aria-label="Resize panel">
                    <Icon name="maximize" size={13} />
                  </button>
                  <button onClick={() => remove(item.key)} title="Remove" aria-label="Remove panel">
                    <Icon name="close" size={13} />
                  </button>
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
