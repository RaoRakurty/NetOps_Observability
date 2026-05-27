import { useEffect, useState } from "react";
import { api, Finding } from "../services/api";

// Findings are written by the Correlation/AI service into ClickHouse
// table netops.findings. This tab is a triage queue — most-recent first.

export default function Findings() {
  const [items, setItems] = useState<Finding[]>([]);
  const [severity, setSeverity] = useState<string>("");

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await api.findings(200, severity || undefined);
        if (alive) setItems(r?.data ?? []);
      } catch {
        if (alive) setItems([]);
      }
    };
    tick();
    const id = setInterval(tick, 10_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [severity]);

  return (
    <div className="card">
      <h2>Findings (correlation + anomaly detection)</h2>
      <div style={{ marginBottom: 12 }}>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="critical">Critical</option>
        </select>
      </div>
      {items.length === 0 ? (
        <div className="empty">
          No findings yet. The correlation engine writes here as it spots anomalies and event
          clusters.
        </div>
      ) : (
        <table>
          <thead>
            <tr>
              <th style={{ width: 170 }}>Time</th>
              <th style={{ width: 90 }}>Severity</th>
              <th style={{ width: 110 }}>Kind</th>
              <th style={{ width: 160 }}>Device</th>
              <th style={{ width: 120 }}>Component</th>
              <th>Summary</th>
              <th style={{ width: 60 }}>Score</th>
            </tr>
          </thead>
          <tbody>
            {items.map((f) => (
              <tr key={f.id}>
                <td style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>
                  {new Date(f.ts).toLocaleString()}
                </td>
                <td>
                  <span className={`badge ${sevClass(f.severity)}`}>{f.severity}</span>
                </td>
                <td>{f.kind}</td>
                <td style={{ fontFamily: "ui-monospace, monospace" }}>{f.device || "—"}</td>
                <td>{f.component || "—"}</td>
                <td>{f.summary}</td>
                <td>{f.score?.toFixed(1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function sevClass(s: string) {
  if (s === "critical") return "bad";
  if (s === "warning") return "warn";
  return "good";
}
