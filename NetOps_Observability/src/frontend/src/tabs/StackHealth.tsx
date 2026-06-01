import { useEffect, useState } from "react";
import { api, StackHealth as StackHealthData, StackComponent } from "../services/api";

// Stack Health — the platform's OWN infrastructure monitoring: the data
// backends, event bus, state stores and visualization that make up the stack
// behind the app. Platform-owner only (the API returns 403 otherwise); the nav
// already hides this from tenant-scoped users, this guard is the backstop.

const CATEGORY_LABELS: Record<string, string> = {
  search: "Search",
  metrics: "Metrics",
  olap: "OLAP / Flows",
  analytics: "Analytics",
  bus: "Event bus",
  state: "State",
  visualization: "Visualization",
};

function statusClass(status: string): string {
  if (status === "up") return "cell-ok";
  if (status === "degraded") return "cell-warn";
  return "cell-bad";
}

export default function StackHealth() {
  const [data, setData] = useState<StackHealthData | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const d = await api.stackHealth();
        if (alive) {
          setData(d);
          setErr(null);
        }
      } catch (e) {
        if (alive) setErr(e instanceof Error ? e.message : "failed to load stack health");
      }
    };
    tick();
    const id = setInterval(tick, 15000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  if (err) {
    return (
      <div className="panel" style={{ padding: 20 }}>
        <h3>Stack Health</h3>
        <p style={{ color: "var(--muted)" }}>
          {/* 403 → not the platform owner; anything else is a real error. */}
          {err.includes("403") || err.toLowerCase().includes("forbidden")
            ? "Infrastructure-stack monitoring is available to platform administrators only."
            : `Could not load stack health: ${err}`}
        </p>
      </div>
    );
  }
  if (!data) return <div style={{ padding: 20, color: "var(--muted)" }}>Loading…</div>;

  // Group components by category for a tidy, sectioned table.
  const byCategory = new Map<string, StackComponent[]>();
  for (const c of data.components) {
    const arr = byCategory.get(c.category) ?? [];
    arr.push(c);
    byCategory.set(c.category, arr);
  }

  return (
    <div className="page-stack">
      <div className="kpi-row">
        <div className={`kpi-tile ${statusClass(data.overall === "healthy" ? "up" : data.overall)}`}>
          <div className="kpi-value">{data.overall.toUpperCase()}</div>
          <div className="kpi-label">Stack status</div>
        </div>
        <div className="kpi-tile cell-ok">
          <div className="kpi-value">{data.up}</div>
          <div className="kpi-label">Up</div>
        </div>
        <div className="kpi-tile cell-warn">
          <div className="kpi-value">{data.degraded}</div>
          <div className="kpi-label">Degraded</div>
        </div>
        <div className="kpi-tile cell-bad">
          <div className="kpi-value">{data.down}</div>
          <div className="kpi-label">Down</div>
        </div>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>Component</th>
            <th>Status</th>
            <th>Latency</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {[...byCategory.entries()].map(([cat, comps]) => (
            <>
              <tr key={`cat-${cat}`} className="table-subhead">
                <td colSpan={4}>{CATEGORY_LABELS[cat] ?? cat}</td>
              </tr>
              {comps.map((c) => (
                <tr key={c.name}>
                  <td>{c.name}</td>
                  <td>
                    <span className={`pill ${statusClass(c.status)}`}>{c.status}</span>
                  </td>
                  <td>{c.latency_ms} ms</td>
                  <td style={{ color: "var(--muted)" }}>{c.detail}</td>
                </tr>
              ))}
            </>
          ))}
        </tbody>
      </table>
    </div>
  );
}
