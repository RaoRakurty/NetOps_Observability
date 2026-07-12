// RcaTicketCard — the live external-ticket card for the RCA detail window (#78).
// It shows whether THIS correlation object has a ServiceNow incident (status,
// number → deep link, last sync + verdict), the action audit trail, and gives
// an operator with infrastructure:write a Create / Sync button that ENQUEUES the
// action to the outbox (ticketing never blocks correlation — the worker drains
// it). Self-contained slot like RcaTimeImpact: fetches its own data, renders an
// honest empty state, never invents a ticket that isn't there.

import { useCallback, useEffect, useState } from "react";
import { api, type CorrelationTickets, type TicketStatus } from "../../services/api";
import { ticketStateLabel, ticketStateTone, ticketActionLabel } from "./labels";

// A ticket is "live" (sync, not create) when it is open or updated.
const isLive = (state?: string) => state === "open" || state === "updated";

const SYSTEM_LABEL: Record<string, string> = { servicenow: "ServiceNow", pagerduty: "PagerDuty", slack: "Slack", jira: "Jira" };

function fmtWhen(iso?: string | null): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toLocaleString();
}

export default function RcaTicketCard({ correlationId }: { correlationId: string }) {
  const [data, setData] = useState<CorrelationTickets | null>(null);
  const [err, setErr] = useState("");
  const [canWrite, setCanWrite] = useState(false);
  const [busy, setBusy] = useState(false);
  const [queued, setQueued] = useState("");

  const load = useCallback(() => {
    if (!correlationId) return;
    api.correlationTickets(correlationId)
      .then((r) => setData(r))
      .catch(() => setErr("unavailable"));
  }, [correlationId]);

  useEffect(() => {
    setData(null); setErr(""); setQueued("");
    load();
    // Permissions gate the action buttons (infrastructure:write = level ≥ 2).
    api.permissions()
      .then((p) => setCanWrite((p.permissions?.infrastructure ?? 0) >= 2))
      .catch(() => setCanWrite(false));
  }, [correlationId, load]);

  const act = async (kind: "create" | "sync") => {
    setBusy(true); setQueued("");
    try {
      if (kind === "create") await api.correlationTicketCreate(correlationId);
      else await api.correlationTicketSync(correlationId);
      setQueued(kind === "create" ? "Ticket creation queued — the worker will open it shortly."
        : "Sync queued — the open ticket will update shortly.");
      // The action is enqueued, not synchronous; re-poll shortly to reflect it.
      setTimeout(load, 2500);
    } catch (e: any) {
      setQueued(`Could not queue the action: ${String(e?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  };

  if (err) return <div className="rw-panel"><h3>External ticket</h3><div className="rw-note">Ticket status unavailable.</div></div>;
  if (!data) return <div className="rw-panel"><h3>External ticket</h3><div className="rw-note">Loading ticket status…</div></div>;

  const st: TicketStatus = data.status ?? { state: "not_created" };
  const created = st.state && st.state !== "not_created";
  const live = isLive(st.state);
  const audit = data.audit ?? [];
  // Every destination this RCA was filed to (#103): prefer the destinations
  // array; older backends only carry the primary status (+ optional PagerDuty).
  const dests: TicketStatus[] = data.destinations
    ?? [...(created ? [st] : []), ...(data.pagerduty ? [data.pagerduty] : [])];

  return (
    <div className="rw-panel">
      <h3>{dests.length > 1 ? "External tickets & paging" : "External ticket"}</h3>

      {dests.length === 0 ? (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <span className={`rw-pill ${ticketStateTone(st.state)}`}>{ticketStateLabel(st.state)}</span>
          </div>
          <div className="rw-note">No external ticket has been opened for this RCA object yet.</div>
        </>
      ) : (
        <div style={{ display: "grid", gap: 8 }}>
          {dests.map((d) => (
            <div key={d.system ?? "servicenow"} style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span className={`rw-pill ${ticketStateTone(d.state)}`}>{ticketStateLabel(d.state)}</span>
              {d.ticket_number && (
                d.url
                  ? <a className="rw-value mono" href={d.url} target="_blank" rel="noreferrer" style={{ color: "var(--rw-blue)" }}>{d.ticket_number} ↗</a>
                  : <span className="rw-value mono">{d.ticket_number}</span>
              )}
              {d.system && <span className="rw-note" style={{ margin: 0 }}>in {SYSTEM_LABEL[d.system] ?? d.system}</span>}
              <span className="rw-note" style={{ margin: 0, marginLeft: "auto" }} title="last synced">{fmtWhen(d.last_synced_at)}</span>
            </div>
          ))}
        </div>
      )}

      {/* Action — create when none/failed, sync when an open ticket exists. */}
      {canWrite && (
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 12, flexWrap: "wrap" }}>
          {live ? (
            <button className="rw-btn" disabled={busy} onClick={() => act("sync")}>
              {busy ? "Queuing…" : "Sync ticket"}
            </button>
          ) : (
            <button className="rw-btn primary" disabled={busy} onClick={() => act("create")}>
              {busy ? "Queuing…" : created ? "Retry create" : "Create ticket"}
            </button>
          )}
          {queued && <span className="rw-note" style={{ margin: 0 }}>{queued}</span>}
        </div>
      )}
      {!canWrite && queued && <div className="rw-note">{queued}</div>}

      {/* Action history — the compliance trail (most recent first). */}
      {audit.length > 0 && (
        <div style={{ marginTop: 14 }}>
          <div className="rw-key" style={{ marginBottom: 6 }}>History</div>
          <div style={{ display: "grid", gap: 4 }}>
            {audit.slice().reverse().slice(0, 6).map((a, i) => (
              <div key={i} className="rw-note" style={{ margin: 0, display: "flex", gap: 8, flexWrap: "wrap" }}>
                <span style={{ fontFamily: "var(--rw-mono)" }}>{fmtWhen(a.at)}</span>
                <span><b>{ticketActionLabel(a.action)}</b></span>
                <span style={{ color: a.result === "ok" ? "var(--rw-green)" : a.result === "dead_letter" ? "var(--rw-red)" : "var(--rw-muted)" }}>
                  {a.result === "ok" ? "ok" : a.result}
                </span>
                {a.error && <span style={{ color: "var(--rw-red)" }}>{a.error}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
