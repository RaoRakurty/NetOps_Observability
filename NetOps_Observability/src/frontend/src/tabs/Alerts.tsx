import { useEffect, useMemo, useState } from "react";
import { api, Alert } from "../services/api";
import { severityClass, severityColor, severityRank } from "../theme/severity";
import DataTable, { Column } from "../components/DataTable";

export default function Alerts() {
  const [items, setItems] = useState<Alert[]>([]);
  const columns = useMemo<Column<Alert>[]>(() => [
    { key: "rule", header: "Rule", width: "18%", sortable: true, text: (a) => a.rule,
      render: (a) => <span title={a.rule}>{a.rule}</span> },
    { key: "severity", header: "Severity", width: 96, sortable: true,
      text: (a) => a.severity, sortValue: (a) => severityRank(a.severity),
      render: (a) => <span className={`badge ${severityClass(a.severity)}`}>{a.severity}</span> },
    { key: "device", header: "Device", width: 150, sortable: true, text: (a) => a.device_id ?? "",
      render: (a) => <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{a.device_id ?? "—"}</span> },
    { key: "summary", header: "Summary", text: (a) => a.summary,
      render: (a) => <span title={a.summary}>{a.summary}</span> },
    { key: "fired", header: "Fired", width: 168, sortable: true,
      sortValue: (a) => new Date(a.fired_at).getTime() || 0,
      render: (a) => new Date(a.fired_at).toLocaleString() },
  ], []);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const a = await api.alerts();
        if (alive) setItems(a ?? []);
      } catch {
        /* ignore — top-level health banner shows the failure */
      }
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  return (
    <div className="card">
      <h2>Active alerts</h2>
      {items.length === 0 ? (
        <div className="empty">No active alerts.</div>
      ) : (
        <DataTable<Alert>
          rows={items}
          columns={columns}
          rowKey={(a) => a.id}
          height="62vh"
          ariaLabel="Active alerts"
          rowAccent={(a) => severityColor(a.severity)}
          initialSort={{ key: "fired", dir: "desc" }}
        />
      )}
    </div>
  );
}
