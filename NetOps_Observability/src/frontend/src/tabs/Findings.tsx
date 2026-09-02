import { fmtDateTime, parseTs } from "../lib/time";
import { useEffect, useMemo, useState } from "react";
import { api, Finding } from "../services/api";
import { severityClass, severityColor, severityRank } from "../theme/severity";
import DataTable, { Column } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";
import { NocHeader, NocKpis, NocKpi, Chip, LiveChip } from "../components/noc";
import Logs from "./Logs";

// Findings are written by the Correlation/AI service into ClickHouse
// table netops.findings. This tab is a triage queue — most-recent first.
// Selecting a row opens its full context in the dockable Inspector (shell-v2,
// #45 §11) with a "View logs" pivot into the bottom drawer; v1 falls back to an
// inline detail card.

const mono: React.CSSProperties = { fontFamily: "var(--font-mono)", fontSize: 12 };

export default function Findings() {
  const [items, setItems] = useState<Finding[]>([]);
  // A failed read used to CLEAR the queue to empty next to a pulsing Live chip —
  // an active claim that the engine found nothing. Track it and say so instead.
  const [err, setErr] = useState<string | null>(null);
  const [severity, setSeverity] = useState<string>("");
  const [sel, setSel] = useState<string | null>(null);
  const ws = useWorkspace();

  const columns = useMemo<Column<Finding>[]>(() => [
    { key: "ts", header: "Time", width: 168, sortable: true,
      sortValue: (f) => parseTs(f.ts)?.getTime() || 0,
      render: (f) => <span style={mono}>{fmtDateTime(f.ts)}</span> },
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
        if (alive) { setItems(r?.data ?? []); setErr(null); }
      } catch (e) {
        // Keep the last good rows on screen; report the failed refresh.
        if (alive) setErr(e instanceof Error ? e.message : String(e));
      }
    };
    tick();
    const id = setInterval(tick, 10_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [severity]);

  // Row → Inspector (shell-v2) or inline card (v1). A finding tied to a device
  // gets a "View logs" pivot that opens that device's logs in the bottom drawer.
  const select = (f: Finding) => {
    setSel(f.id);
    if (ws.enabled) {
      ws.openInspector(
        <FindingDetailBody
          finding={f}
          onViewLogs={
            f.device
              ? () => ws.openDrawer(<Logs initialQuery={`host:"${f.device}"`} initialSignal="syslog" rangeMinutes={60} />, { title: `Logs · ${f.device}` })
              : undefined
          }
        />,
        { title: f.summary || f.kind, subtitle: `${f.severity}${f.device ? ` · ${f.device}` : ""}` },
      );
    }
  };

  const selected = !ws.enabled && sel ? items.find((f) => f.id === sel) : undefined;

  const fCrit = items.filter((f) => f.severity === "critical").length;
  const fWarn = items.filter((f) => f.severity === "warning").length;
  const fInfo = items.filter((f) => f.severity === "info").length;
  return (
    <div className="dm-board cc-board">
      <NocHeader
        title="Detected Findings"
        subtitle="Observations that deviate from baseline and may contribute to incidents or RCA candidates."
        chips={<><Chip label={`${items.length} findings`} /><LiveChip detail="anomaly + correlation" /></>}
      >
        <NocKpis cols={4}>
          <NocKpi n={items.length} label="Findings" interp="detected this window" />
          <NocKpi n={fCrit} label="Critical" interp="severe deviation" tone={fCrit ? "var(--crit)" : undefined} />
          <NocKpi n={fWarn} label="Warning" interp="above baseline" tone={fWarn ? "var(--warn)" : undefined} />
          <NocKpi n={fInfo} label="Informational" interp="low-severity signal" />
        </NocKpis>
      </NocHeader>
      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Findings</h3>
          <span className="cc-panel-meta">{items.length}</span>
        </div>
        <div style={{ padding: "11px 13px" }}>
          <div style={{ marginBottom: 10 }}>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All severities</option>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          {err && (
            <div className="empty" role="alert" style={{ color: "var(--bad)" }}>
              <strong>Findings could not be loaded.</strong>
              <div style={{ marginTop: 4 }}>{err}</div>
              <div style={{ marginTop: 4, color: "var(--muted)" }}>
                This is not "no findings" — the queue is unknown{items.length > 0 ? "; rows below are the last successful read" : ""}.
              </div>
            </div>
          )}
          {items.length === 0 ? (
            err ? null : (
              <div className="empty">No findings in this window. The correlation engine writes here as it detects anomalies and event clusters.</div>
            )
          ) : (
            <DataTable<Finding>
              rows={items}
              columns={columns}
              rowKey={(f) => f.id}
              height="58vh"
              ariaLabel="Findings"
              onRowClick={(f) => select(f)}
              rowAccent={(f) => severityColor(f.severity)}
              rowClassName={(f) => (sel === f.id ? "dtv-selected" : "")}
              initialSort={{ key: "ts", dir: "desc" }}
            />
          )}
          {selected && (
            <div style={{ marginTop: 12, borderTop: "1px solid var(--border)", paddingTop: 12 }}>
              <FindingDetailBody finding={selected} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// FindingDetailBody — read-only context for a single finding, rendered either in
// the dockable Inspector or inline (v1). `onViewLogs` (when the finding names a
// device) pivots into the device's logs in the bottom drawer.
export function FindingDetailBody({ finding: f, onViewLogs }: { finding: Finding; onViewLogs?: () => void }) {
  const row = (k: string, v: React.ReactNode) => (
    <div style={{ display: "flex", gap: 8, fontSize: 12, padding: "2px 0" }}>
      <span style={{ color: "var(--muted)", minWidth: 84 }}>{k}</span>
      <span>{v}</span>
    </div>
  );
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
        <span className={`badge ${severityClass(f.severity)}`}>{f.severity}</span>
        <span className="badge">{f.kind}</span>
        {typeof f.score === "number" && (
          <span style={{ fontSize: 12, color: "var(--muted)" }}>score {f.score.toFixed(1)}</span>
        )}
      </div>
      <div style={{ fontSize: 13, fontWeight: 600 }}>{f.summary}</div>
      {f.description && (
        <p style={{ fontSize: 12, color: "var(--muted)", whiteSpace: "pre-wrap", margin: 0 }}>{f.description}</p>
      )}
      <div>
        {row("Time", <span style={mono}>{fmtDateTime(f.ts)}</span>)}
        {row("Device", <span style={mono}>{f.device || "—"}</span>)}
        {row("Component", f.component || "—")}
        {row("ID", <span style={mono}>{f.id}</span>)}
      </div>
      {onViewLogs && f.device && (
        <div>
          <button className="btn" onClick={onViewLogs}>View logs</button>
        </div>
      )}
    </div>
  );
}
