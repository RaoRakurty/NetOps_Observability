import { fmtDateTime } from "../lib/time";
import { useEffect, useMemo, useState } from "react";
import { api, Alert } from "../services/api";
import { severityClass, severityColor, severityRank } from "../theme/severity";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";
import { NocHeader, NocKpis, NocKpi, Chip, LiveChip } from "../components/noc";
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
      render: (a) => fmtDateTime(a.fired_at) },
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
              ? () => ws.openDrawer(<Logs initialQuery={`host:"${a.device_id}"`} initialSignal="syslog" rangeMinutes={60} />, { title: `Logs · ${a.device_id}` })
              : undefined
          }
        />,
        { title: a.rule, subtitle: `${a.severity}${a.device_id ? ` · ${a.device_id}` : ""}` },
      );
    }
  };

  const selected = !ws.enabled && sel ? items.find((a) => a.id === sel) : undefined;

  const aCrit = items.filter((a) => a.severity === "critical" || a.severity === "error").length;
  const aWarn = items.filter((a) => a.severity === "warning").length;
  const aAging = items.filter((a) => a.fired_at && Date.now() - Date.parse(a.fired_at) > 3600_000).length;
  return (
    <div className="dm-board cc-board">
      <NocHeader
        title="Active Alerts"
        subtitle="Monitor rules currently firing across devices, collectors and interfaces — triage before they correlate into incidents."
        chips={<><Chip label={`${items.length} firing`} tone={items.length ? "var(--warn)" : "var(--ok)"} /><LiveChip detail="rule evaluation" /></>}
      >
        <NocKpis cols={4}>
          <NocKpi n={items.length} label="Active alerts" interp="rules currently firing" tone={items.length ? "var(--warn)" : "var(--ok)"} />
          <NocKpi n={aCrit} label="Critical" interp="severe condition" tone={aCrit ? "var(--crit)" : undefined} />
          <NocKpi n={aWarn} label="Warning" interp="above threshold" tone={aWarn ? "var(--warn)" : undefined} />
          <NocKpi n={aAging} label="Aging > 1h" interp="firing over an hour" tone={aAging ? "var(--warn)" : undefined} />
        </NocKpis>
      </NocHeader>
      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Alert queue</h3>
          <span className="cc-panel-meta">{items.length} firing · click a row for detail</span>
        </div>
        <div style={{ padding: "11px 13px" }}>
          {items.length === 0 ? (
            <div className="empty">No active alerts — all monitored conditions are within threshold.</div>
          ) : (
            <DataTable<Alert>
              rows={items}
              columns={columns}
              rowKey={(a) => a.id}
              height="58vh"
              ariaLabel="Active alerts"
              onRowClick={(a) => select(a)}
              rowAccent={(a) => severityColor(a.severity)}
              rowClassName={(a) => (sel === a.id ? "dtv-selected" : "")}
              initialSort={{ key: "fired", dir: "desc" }}
            />
          )}
          {selected && (
            <div style={{ marginTop: 12, borderTop: "1px solid var(--border)", paddingTop: 12 }}>
              <AlertDetailBody alert={selected} />
            </div>
          )}
        </div>
      </div>
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
        {row("Fired", <span style={mono}>{fmtDateTime(a.fired_at)}</span>)}
        {a.resolved_at && row("Resolved", <span style={mono}>{fmtDateTime(a.resolved_at)}</span>)}
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
