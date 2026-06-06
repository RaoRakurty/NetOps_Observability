import { useEffect, useMemo, useState } from "react";
import { api, AuditEvent } from "../services/api";
import DataTable, { Column } from "../components/DataTable";

// Audit Log — the tenant-scoped trail of mutations and denials. The backend
// returns only events the caller may see (platform owner: all; tenant admin:
// own tenant). Admin-gated.

function decisionClass(d: string): string {
  if (d === "allow") return "cell-ok";
  if (d === "deny") return "cell-bad";
  return "cell-warn";
}

const muted: React.CSSProperties = { color: "var(--muted)" };

export default function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const columns = useMemo<Column<AuditEvent>[]>(() => [
    { key: "time", header: "Time", width: 168, sortable: true,
      sortValue: (e) => new Date(e.time).getTime() || 0,
      render: (e) => new Date(e.time).toLocaleString() },
    { key: "actor", header: "Actor", width: 150, sortable: true, text: (e) => e.actor ?? "",
      render: (e) => e.actor || <span style={muted}>—</span> },
    { key: "tenant", header: "Tenant", width: 110, text: (e) => (e.cross ? "platform" : e.tenant ?? ""),
      render: (e) => (e.cross ? <span style={muted}>platform</span> : e.tenant || "—") },
    { key: "action", header: "Action", text: (e) => `${e.method} ${e.path}`,
      render: (e) => <code title={`${e.method} ${e.path}`}>{e.method} {e.path}</code> },
    { key: "status", header: "Status", width: 64, align: "right", sortable: true,
      sortValue: (e) => e.status, render: (e) => e.status },
    { key: "decision", header: "Decision", width: 92, sortable: true, text: (e) => e.decision,
      render: (e) => <span className={`pill ${decisionClass(e.decision)}`}>{e.decision}</span> },
    { key: "from", header: "From", width: 130, text: (e) => e.remote ?? "",
      render: (e) => <span style={{ ...muted, fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{e.remote}</span> },
  ], []);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const e = await api.audit(300);
        if (alive) {
          setEvents(e);
          setErr(null);
        }
      } catch (e) {
        if (alive) setErr(e instanceof Error ? e.message : "failed to load audit log");
      }
    };
    tick();
    const id = setInterval(tick, 20000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  if (err) return <div className="panel" style={{ padding: 20, color: "var(--muted)" }}>Could not load audit log: {err}</div>;
  if (!events) return <div style={{ padding: 20, color: "var(--muted)" }}>Loading…</div>;
  if (events.length === 0) return <div style={{ padding: 20, color: "var(--muted)" }}>No audit events yet.</div>;

  return (
    <div className="page-stack">
      <DataTable<AuditEvent>
        rows={events}
        columns={columns}
        rowKey={(e) => e.id}
        height="68vh"
        ariaLabel="Audit log"
        rowAccent={(e) => (e.decision === "deny" ? "var(--crit)" : e.decision === "allow" ? undefined : "var(--warn)")}
        initialSort={{ key: "time", dir: "desc" }}
      />
    </div>
  );
}
