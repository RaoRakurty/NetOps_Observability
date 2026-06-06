import { useEffect, useMemo, useState } from "react";
import { api, Finding } from "../services/api";
import { severityClass, severityColor, severityRank } from "../theme/severity";
import DataTable, { Column } from "../components/DataTable";

// Findings are written by the Correlation/AI service into ClickHouse
// table netops.findings. This tab is a triage queue — most-recent first.

const mono: React.CSSProperties = { fontFamily: "ui-monospace, monospace", fontSize: 12 };

export default function Findings() {
  const [items, setItems] = useState<Finding[]>([]);
  const [severity, setSeverity] = useState<string>("");
  const columns = useMemo<Column<Finding>[]>(() => [
    { key: "ts", header: "Time", width: 168, sortable: true,
      sortValue: (f) => new Date(f.ts).getTime() || 0,
      render: (f) => <span style={mono}>{new Date(f.ts).toLocaleString()}</span> },
    { key: "severity", header: "Severity", width: 92, sortable: true,
      text: (f) => f.severity, sortValue: (f) => severityRank(f.severity),
      render: (f) => <span className={`badge ${severityClass(f.severity)}`}>{f.severity}</span> },
    { key: "kind", header: "Kind", width: 120, sortable: true, text: (f) => f.kind,
      render: (f) => <span title={f.kind}>{f.kind}</span> },
    { key: "device", header: "Device", width: 150, sortable: true, text: (f) => f.device ?? "",
      render: (f) => <span style={mono} title={f.device || ""}>{f.device || "—"}</span> },
    { key: "component", header: "Component", width: 120, text: (f) => f.component ?? "",
      render: (f) => <span title={f.component || ""}>{f.component || "—"}</span> },
    { key: "summary", header: "Summary", text: (f) => f.summary,
      render: (f) => <span title={f.summary}>{f.summary}</span> },
    { key: "score", header: "Score", width: 64, align: "right", sortable: true,
      sortValue: (f) => Number(f.score) || 0, render: (f) => f.score?.toFixed(1) },
  ], []);

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
        <DataTable<Finding>
          rows={items}
          columns={columns}
          rowKey={(f) => f.id}
          height="62vh"
          ariaLabel="Findings"
          rowAccent={(f) => severityColor(f.severity)}
          initialSort={{ key: "ts", dir: "desc" }}
        />
      )}
    </div>
  );
}
