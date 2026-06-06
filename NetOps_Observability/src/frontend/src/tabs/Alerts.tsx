import { useEffect, useMemo, useState } from "react";
import { api, Alert } from "../services/api";
import { severityClass, severityColor, severityRank } from "../theme/severity";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";
import Logs from "./Logs";

// Active alerts. Selecting a row opens the alert's context in the dockable
// Inspector (shell-v2, #45 §11) with a "View logs" pivot into the bottom drawer
// for the alerting device; v1 falls back to an inline detail section.

const mono: React.CSSProperties = { fontFamily: "var(--font-mono, monospace)", fontSize: 12 };

export default function Alerts() {
  const [items, setItems] = useState<Alert[]>([]);
  const [sel, setSel] = useState<string | null>(null);
  const ws = useWorkspace();

  const columns = useMemo<Column<Alert>[]>(() => [
    { key: "rule", header: "Rule", width: "18%", sortable: true, text: (a) => a.rule,
      render: (a) => <span title={a.rule}>{a.rule}</span> },
    { key: "severity", header: "Severity", width: 96, sortable: true,
      text: (a) => a.severity, sortValue: (a) => severityRank(a.severity),
      render: (a) => <span className={`badge ${severityClass(a.severity)}`}>{a.severity}</span> },
    { key: "device", header: "Device", width: 150, sortable: true, text: (a) => a.device_id ?? "",
      render: (a) => <span style={mono}>{a.device_id ?? "—"}</span> },
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

  // Row → Inspector (shell-v2) or inline section (v1). An alert tied to a device
  // gets a "View logs" pivot that docks that device's logs in the bottom drawer.
  const select = (a: Alert) => {
    setSel(a.id);
    if (ws.enabled) {
      ws.openInspector(
        <AlertDetailBody
          alert={a}
          onViewLogs={
            a.device_id
              ? () => ws.openDrawer(<Logs initialQuery={a.device_id} rangeMinutes={60} />, { title: `Logs · ${a.device_id}` })
              : undefined
          }
        />,
        { title: a.rule, subtitle: `${a.severity}${a.device_id ? ` · ${a.device_id}` : ""}` },
      );
    }
  };

  const selected = !ws.enabled && sel ? items.find((a) => a.id === sel) : undefined;

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
          onRowClick={(a) => select(a)}
          rowAccent={(a) => severityColor(a.severity)}
          rowClassName={(a) => (sel === a.id ? "dtv-selected" : "")}
          initialSort={{ key: "fired", dir: "desc" }}
        />
      )}

      {selected && (
        <div style={{ marginTop: 12, borderTop: "1px solid var(--border, #2a2f3a)", paddingTop: 12 }}>
          <AlertDetailBody alert={selected} />
        </div>
      )}
    </div>
  );
}

// AlertDetailBody — context for a single alert, rendered in the Inspector or
// inline (v1). `onViewLogs` (when the alert names a device) pivots into that
// device's logs in the bottom drawer.
export function AlertDetailBody({ alert: a, onViewLogs }: { alert: Alert; onViewLogs?: () => void }) {
  const row = (k: string, v: React.ReactNode) => (
    <div style={{ display: "flex", gap: 8, fontSize: 12, padding: "2px 0" }}>
      <span style={{ color: "var(--muted)", minWidth: 84 }}>{k}</span>
      <span>{v}</span>
    </div>
  );
  const labels = a.labels ? Object.entries(a.labels) : [];
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
        <span className={`badge ${severityClass(a.severity)}`}>{a.severity}</span>
        <span style={{ fontWeight: 600 }}>{a.rule}</span>
      </div>
      <div style={{ fontSize: 13 }}>{a.summary}</div>
      {a.description && (
        <p style={{ fontSize: 12, color: "var(--muted)", whiteSpace: "pre-wrap", margin: 0 }}>{a.description}</p>
      )}
      <div>
        {row("Fired", <span style={mono}>{new Date(a.fired_at).toLocaleString()}</span>)}
        {a.resolved_at && row("Resolved", <span style={mono}>{new Date(a.resolved_at).toLocaleString()}</span>)}
        {row("Device", <span style={mono}>{a.device_id || "—"}</span>)}
        {row("ID", <span style={mono}>{a.id}</span>)}
      </div>
      {labels.length > 0 && (
        <div>
          <div style={{ fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.4, marginBottom: 4 }}>
            Labels
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {labels.map(([k, v]) => (
              <span key={k} className="badge" title={`${k}=${v}`} style={{ fontSize: 11 }}>
                {k}={v}
              </span>
            ))}
          </div>
        </div>
      )}
      {onViewLogs && a.device_id && (
        <div>
          <button className="btn" onClick={onViewLogs}>View logs</button>
        </div>
      )}
    </div>
  );
}
