import { useEffect, useState } from "react";
import { api, AuditEvent } from "../services/api";

// Audit Log — the tenant-scoped trail of mutations and denials. The backend
// returns only events the caller may see (platform owner: all; tenant admin:
// own tenant). Admin-gated.

function decisionClass(d: string): string {
  if (d === "allow") return "cell-ok";
  if (d === "deny") return "cell-bad";
  return "cell-warn";
}

export default function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

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
      <table className="data-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Tenant</th>
            <th>Action</th>
            <th>Status</th>
            <th>Decision</th>
            <th>From</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td style={{ whiteSpace: "nowrap" }}>{new Date(e.time).toLocaleString()}</td>
              <td>{e.actor || <span style={{ color: "var(--muted)" }}>—</span>}</td>
              <td>{e.cross ? <span style={{ color: "var(--muted)" }}>platform</span> : e.tenant || "—"}</td>
              <td><code>{e.method} {e.path}</code></td>
              <td>{e.status}</td>
              <td><span className={`pill ${decisionClass(e.decision)}`}>{e.decision}</span></td>
              <td style={{ color: "var(--muted)" }}>{e.remote}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
