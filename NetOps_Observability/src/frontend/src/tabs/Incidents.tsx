import { useEffect, useMemo, useState } from "react";
import { api, Incident, TimelineEntry } from "../services/api";
import { severityClass, severityColor, severityRank } from "../theme/severity";
import DataTable, { Column } from "../components/DataTable";
import Icon from "../components/Icon";
import { useWorkspace } from "../context/workspace";

// Incidents — the actionable system-of-record view. Lists incidents (deduped from
// alerts/anomalies), drives the lifecycle in-platform (ack → investigate →
// resolve), shows the full event timeline, and surfaces the optional external
// ITSM ticket. Distinct from Explore findings: an incident is a tracked record.
//
// Selecting a row pivots into the dockable Inspector (shell-v2, #45 §11) via the
// self-contained IncidentDetailBody; under v1 it falls back to an inline card.

const STATUSES = ["open", "acknowledged", "investigating", "resolved", "closed"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

type Action = "ack" | "resolve" | "investigate" | "close" | "reopen" | "note" | "assign";

const fmt = (s?: string) => (s ? new Date(s).toLocaleString() : "—");

export default function Incidents() {
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [items, setItems] = useState<Incident[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [sel, setSel] = useState<string | null>(null);
  const ws = useWorkspace();

  const load = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.listIncidents({ status: status || undefined, severity: severity || undefined });
      setItems(r ?? []);
      setUnavailable(false);
    } catch (e) {
      const m = (e as Error).message;
      if (m.includes("409")) {
        setUnavailable(true);
        setItems([]);
      } else {
        setError(m);
      }
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, severity]);

  // Row → Inspector (shell-v2) or inline card (v1). Selection id drives the row
  // highlight in both modes; the detail body owns its own timeline + lifecycle.
  const select = (i: Incident) => {
    setSel(i.id);
    if (ws.enabled) {
      ws.openInspector(<IncidentDetailBody incident={i} onChanged={load} />, {
        title: i.title,
        subtitle: `${i.severity} · ${i.status}`,
      });
    }
  };

  const ticketCell = (i: Incident) =>
    i.external_ticket_id ? (
      i.external_url ? (
        <a href={i.external_url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>
          {i.external_system}: {i.external_ticket_id}
        </a>
      ) : (
        <span>{i.external_system}: {i.external_ticket_id}</span>
      )
    ) : (
      <span className="badge" title={`sync: ${i.sync_status}`}>{i.sync_status === "pending" ? "syncing…" : "—"}</span>
    );

  const columns = useMemo<Column<Incident>[]>(() => [
    { key: "severity", header: "Severity", width: 84, sortable: true,
      text: (i) => i.severity, sortValue: (i) => severityRank(i.severity),
      render: (i) => <span className={`badge ${severityClass(i.severity)}`}>{i.severity}</span> },
    { key: "status", header: "Status", width: 110, sortable: true, text: (i) => i.status,
      render: (i) => i.status },
    { key: "title", header: "Title", text: (i) => i.title,
      render: (i) => <span title={i.title}>{i.title}</span> },
    { key: "count", header: "Count", width: 70, align: "right", sortable: true,
      sortValue: (i) => Number(i.occurrences) || 0, render: (i) => i.occurrences },
    { key: "source", header: "Source", width: 92, text: (i) => i.source_type,
      render: (i) => <span style={{ fontSize: 12, color: "var(--muted)" }}>{i.source_type}</span> },
    { key: "ticket", header: "Ticket", width: 140, text: (i) => i.external_ticket_id ?? "",
      render: (i) => <span style={{ fontSize: 12 }}>{ticketCell(i)}</span> },
    { key: "last_seen", header: "Last seen", width: 170, sortable: true,
      sortValue: (i) => new Date(i.last_seen_at ?? 0).getTime() || 0,
      render: (i) => <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{fmt(i.last_seen_at)}</span> },
  ], []);

  // v1 fallback: render the selected incident's detail inline (shell-v2 uses the
  // Inspector instead, so this only mounts when the workspace pane is disabled).
  const selected = !ws.enabled && sel ? items.find((i) => i.id === sel) : undefined;

  return (
    <>
      <div className="card">
        <h2>Incidents</h2>
        <p style={{ color: "var(--muted)", fontSize: 12, marginTop: 0 }}>
          Tracked operational problems — automatically opened from alerts (deduplicated), driven through
          their lifecycle here, and optionally mirrored to an external ticketing system.
        </p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <button className="btn" type="button" onClick={load} disabled={busy}>
            <Icon name="refresh" size={14} /> {busy ? "Loading…" : "Refresh"}
          </button>
        </div>
        {error && (
          <p style={{ color: "var(--bad)", marginTop: 10 }}>
            <strong>Error:</strong> {error}
          </p>
        )}
      </div>

      <div className="card">
        <h2>
          {status || "All"} ({items.length})
        </h2>
        {unavailable ? (
          <div className="empty">Incident management isn’t enabled in this environment yet.</div>
        ) : items.length === 0 ? (
          <div className="empty">{busy ? "Loading…" : "No incidents match. Quiet is good."}</div>
        ) : (
          <DataTable<Incident>
            rows={items}
            columns={columns}
            rowKey={(i) => i.id}
            height="55vh"
            ariaLabel="Incidents"
            onRowClick={(i) => select(i)}
            rowAccent={(i) => severityColor(i.severity)}
            rowClassName={(i) => (sel === i.id ? "dtv-selected" : "")}
            initialSort={{ key: "last_seen", dir: "desc" }}
          />
        )}
      </div>

      {selected && (
        <div className="card">
          <IncidentDetailBody incident={selected} onChanged={load} />
        </div>
      )}
    </>
  );
}

// IncidentDetailBody — a self-contained detail pane: it owns the timeline fetch,
// note entry, and lifecycle actions, refetching by incident id, so it renders
// correctly inside the dockable Inspector (a captured node) OR as an inline card.
// `onChanged` lets the parent refresh its list after a lifecycle action.
export function IncidentDetailBody({ incident, onChanged }: { incident: Incident; onChanged?: () => void }) {
  const [inc, setInc] = useState<Incident>(incident);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [note, setNote] = useState("");
  const [acting, setActing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = async () => {
    try {
      const d = await api.getIncidentTimeline(incident.id);
      setInc(d.incident);
      setTimeline(d.timeline);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    setInc(incident);
    setTimeline([]);
    setNote("");
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incident.id]);

  const act = async (action: Action, body?: { note?: string; owner?: string }) => {
    setActing(true);
    setError(null);
    try {
      await api.incidentAction(incident.id, action, body || {});
      setNote("");
      await reload();
      onChanged?.();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setActing(false);
    }
  };

  const open = inc.status !== "resolved" && inc.status !== "closed";

  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", flexWrap: "wrap", gap: 8 }}>
        <h2 style={{ margin: 0 }}>
          <span className={`badge ${severityClass(inc.severity)}`}>{inc.severity}</span> {inc.title}
        </h2>
        <span style={{ color: "var(--muted)", fontSize: 12 }}>
          {inc.status} · {inc.occurrences}× · opened {fmt(inc.first_seen_at)}
        </span>
      </div>
      {inc.description && <p style={{ color: "var(--muted)", fontSize: 13 }}>{inc.description}</p>}
      {inc.external_ticket_id && (
        <p style={{ fontSize: 12, margin: "2px 0 0" }}>
          {inc.external_url ? (
            <a href={inc.external_url} target="_blank" rel="noreferrer">
              {inc.external_system}: {inc.external_ticket_id}
            </a>
          ) : (
            <span>{inc.external_system}: {inc.external_ticket_id}</span>
          )}
        </p>
      )}
      {error && (
        <p style={{ color: "var(--bad)", fontSize: 12 }}>
          <strong>Error:</strong> {error}
        </p>
      )}

      {/* Lifecycle actions */}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "8px 0" }}>
        {open && (
          <>
            <button type="button" className="chip" disabled={acting} onClick={() => act("ack")}>
              Acknowledge
            </button>
            <button type="button" className="chip" disabled={acting} onClick={() => act("investigate")}>
              Investigate
            </button>
            <button type="button" className="chip chip-active" disabled={acting} onClick={() => act("resolve")}>
              Resolve
            </button>
          </>
        )}
        {inc.status === "resolved" && (
          <>
            <button type="button" className="chip" disabled={acting} onClick={() => act("close")}>
              Close
            </button>
            <button type="button" className="chip" disabled={acting} onClick={() => act("reopen")}>
              Reopen
            </button>
          </>
        )}
      </div>
      <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
        <input
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Add a note to the timeline…"
          style={{ flex: 1 }}
        />
        <button type="button" disabled={acting || !note.trim()} onClick={() => act("note", { note })}>
          Add note
        </button>
      </div>

      {/* Timeline — lifecycle events and ITSM sync events, merged chronologically */}
      <h3 style={{ fontSize: 13, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.4 }}>Timeline</h3>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {timeline.map((ev) => (
          <div
            key={ev.id}
            style={{
              display: "flex",
              gap: 10,
              fontSize: 12,
              alignItems: "baseline",
              borderLeft: `3px solid ${ev.kind === "sync" ? "var(--accent)" : "transparent"}`,
              paddingLeft: 8,
            }}
          >
            <span style={{ fontFamily: "var(--font-mono)", color: "var(--muted)", minWidth: 150 }}>
              {fmt(ev.at)}
            </span>
            {ev.kind === "sync" ? (
              <>
                <span className="badge" title={`${ev.direction ?? ""} sync via ${ev.provider ?? ""}`}>
                  {ev.direction === "inbound" ? "↓" : ev.direction === "outbound" ? "↑" : ""} {ev.provider}
                </span>
                <span style={{ color: "var(--muted)" }}>{ev.status}</span>
                <span>{renderSync(ev)}</span>
                {ev.correlation_id && (
                  <span
                    style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", color: "var(--muted)", opacity: 0.7 }}
                    title="Correlation id — grep this across logs to trace the sync end-to-end"
                  >
                    {ev.correlation_id}
                  </span>
                )}
              </>
            ) : (
              <>
                <span className="badge">{ev.event_type}</span>
                <span style={{ color: "var(--muted)" }}>{ev.actor}</span>
                <span>{renderPayload(ev)}</span>
              </>
            )}
          </div>
        ))}
        {timeline.length === 0 && <span style={{ fontSize: 12, color: "var(--muted)" }}>Loading timeline…</span>}
      </div>
    </>
  );
}

function renderPayload(ev: TimelineEntry): string {
  const p = ev.payload || {};
  switch (ev.event_type) {
    case "status_change":
      return `${p.from} → ${p.to}${p.note ? ` — ${p.note}` : ""}`;
    case "note":
      return String(p.note ?? "");
    case "assignment":
      return `owner → ${p.owner}`;
    case "sync":
      return `${p.system ?? ""} ${p.external_ticket_id ?? ""} (${p.sync_status ?? ""})`.trim();
    case "dedup":
      return "recurrence folded in";
    case "created":
      return String(p.source_type ? `from ${p.source_type}` : "created");
    default:
      return "";
  }
}

// renderSync describes an ITSM sync event: the ticket it touched and, when the
// event was dropped/failed, why (the reconciler verdict — e.g. stale, terminal).
function renderSync(ev: TimelineEntry): string {
  const ticket = ev.external_id ? `${ev.provider ?? ""} ${ev.external_id}`.trim() : "";
  const base = [ev.type, ticket].filter(Boolean).join(" · ");
  if (ev.status === "dropped" || ev.status === "failed" || ev.status === "dead") {
    return `${base}${ev.reason ? ` — ${ev.reason}` : ""}`.trim();
  }
  return base;
}
