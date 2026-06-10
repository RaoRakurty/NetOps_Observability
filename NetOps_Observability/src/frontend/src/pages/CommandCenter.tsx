import { useCallback, useEffect, useMemo, useState } from "react";
import { api, Incident, Alert } from "../services/api";
import { StatStrip, Stat } from "../components/ui";
import DataTable, { Column, Sev } from "../components/DataTable";
import Icon from "../components/Icon";

// Command Center (build-order #11) — the Incident Response cockpit. One screen
// that answers "what's burning, who's on it, and can we reach people": the
// unresolved-incident triage queue with inline ack/resolve, the live triggered
// feed, and response-channel readiness (notify + ITSM). Pure composition over
// existing APIs — incidents, alerts, credentials, ITSM status.

const fmtAge = (iso: string): string => {
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const m = Math.floor(ms / 60_000);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d`;
};

const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const sevCell = (s: string): Sev => (s === "critical" || s === "high" ? "crit" : s === "medium" ? "warn" : "ok");

// ── Triage queue ──────────────────────────────────────────────────────────────
function TriageQueue({ items, onAction, busyId }: {
  items: Incident[];
  onAction: (id: string, action: "ack" | "resolve") => void;
  busyId: string | null;
}) {
  const cols = useMemo<Column<Incident>[]>(() => [
    { key: "severity", header: "Sev", width: 76, sortable: true, sortValue: (i) => sevRank[i.severity] ?? 9, sev: (i) => sevCell(i.severity), render: (i) => i.severity },
    { key: "title", header: "Incident", sortable: true, text: (i) => i.title, render: (i) => i.title },
    { key: "status", header: "Status", width: 110, sortable: true, text: (i) => i.status, render: (i) => <span className="badge">{i.status}</span> },
    { key: "age", header: "Age", width: 76, align: "right", sortable: true, sortValue: (i) => -Date.parse(i.created_at), render: (i) => fmtAge(i.created_at) },
    { key: "occ", header: "Occurrences", width: 100, align: "right", sortable: true, sortValue: (i) => i.occurrences, render: (i) => i.occurrences },
    { key: "owner", header: "Owner", width: 110, render: (i) => i.owner || "—" },
    {
      key: "ticket", header: "Ticket", width: 110, render: (i) =>
        i.external_ticket_id ? (
          i.external_url ? (
            <a href={i.external_url} target="_blank" rel="noreferrer" style={{ color: "var(--accent)", fontWeight: 600 }}>{i.external_ticket_id}</a>
          ) : (
            i.external_ticket_id
          )
        ) : "—",
    },
    {
      key: "act", header: "", width: 150, render: (i) => (
        <span style={{ display: "inline-flex", gap: 6 }}>
          {i.status === "open" && (
            <button className="btn-ghost" style={{ fontSize: 11, padding: "2px 8px" }} disabled={busyId === i.id} onClick={() => onAction(i.id, "ack")}>Ack</button>
          )}
          <button className="btn-ghost" style={{ fontSize: 11, padding: "2px 8px", color: "var(--good)" }} disabled={busyId === i.id} onClick={() => onAction(i.id, "resolve")}>Resolve</button>
        </span>
      ),
    },
  ], [onAction, busyId]);

  return (
    <div className="panel" style={{ minWidth: 0 }}>
      <div className="panel-tools">
        <h3>Triage queue — unresolved incidents</h3>
        <a href="#/monitoring/incidents" style={{ color: "var(--accent)", fontWeight: 600, fontSize: 12 }}>Full incident view →</a>
      </div>
      {items.length === 0 ? (
        <div className="empty">Nothing unresolved. 🎉</div>
      ) : (
        <DataTable<Incident>
          rows={items}
          columns={cols}
          rowKey={(i) => i.id}
          rowAccent={(i) => sevCell(i.severity)}
          height={Math.min(420, 44 + items.length * 30)}
          ariaLabel="Unresolved incidents"
          initialSort={{ key: "severity", dir: "asc" }}
        />
      )}
    </div>
  );
}

// ── Response channels — can this incident reach a human? ─────────────────────
type Channel = { key: string; label: string; ready: boolean; detail: string; href: string };

function ResponseChannels() {
  const [channels, setChannels] = useState<Channel[] | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      // Each source is independent and optional — a 403 (tenant-scoped user) or
      // an unconfigured connector must not blank the whole panel.
      const [creds, sn, jira] = await Promise.all([
        api.credentials().catch(() => ({}) as Record<string, boolean>),
        api.itsmServiceNow().catch(() => null),
        api.itsmJira().catch(() => null),
      ]);
      if (!alive) return;
      setChannels([
        { key: "slack", label: "Slack", ready: !!creds.slack, detail: creds.slack ? "webhook + action buttons" : "not configured", href: "#/incident/notifications" },
        { key: "pagerduty", label: "PagerDuty", ready: !!creds.pagerduty, detail: creds.pagerduty ? "events routing" : "not configured", href: "#/incident/notifications" },
        { key: "email", label: "Email", ready: !!creds.smtp, detail: creds.smtp ? "SMTP" : "not configured", href: "#/incident/notifications" },
        { key: "sms", label: "SMS / voice", ready: !!creds.twilio, detail: creds.twilio ? "Twilio" : "not configured", href: "#/incident/notifications" },
        { key: "servicenow", label: "ServiceNow", ready: !!sn?.enabled && !!sn?.configured, detail: sn?.enabled ? `${sn.open_count ?? 0} open tickets` : "not configured", href: "#/incident/integrations" },
        { key: "jira", label: "Jira", ready: !!jira?.enabled && !!jira?.configured, detail: jira?.enabled ? `${jira.open_count ?? 0} open issues` : "not configured", href: "#/incident/integrations" },
      ]);
    };
    load();
    const id = setInterval(load, 60_000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  return (
    <div className="panel" style={{ minWidth: 0 }}>
      <div className="panel-tools"><h3>Response channels</h3></div>
      {channels === null ? (
        <div className="mini-meta">Checking channel readiness…</div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(170px, 1fr))", gap: 8 }}>
          {channels.map((c) => (
            <a key={c.key} href={c.href} className="panel" style={{ padding: "10px 12px", textDecoration: "none", color: "inherit", display: "flex", flexDirection: "column", gap: 4 }}>
              <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ width: 8, height: 8, borderRadius: "50%", background: c.ready ? "var(--good)" : "var(--muted)" }} />
                <strong style={{ fontSize: 13 }}>{c.label}</strong>
              </span>
              <span className="mini-meta" style={{ margin: 0 }}>{c.detail}</span>
            </a>
          ))}
        </div>
      )}
      <p className="mini-meta" style={{ margin: "8px 0 0" }}>
        Incidents route through <a href="#/incident/notifications" style={{ color: "var(--accent)", fontWeight: 600 }}>Notifications</a> (channels, contact points)
        and <a href="#/incident/integrations" style={{ color: "var(--accent)", fontWeight: 600 }}>Integrations</a> (ITSM ticketing, bidirectional sync).
      </p>
    </div>
  );
}

// ── Triggered now — the raw alert feed behind the incidents ──────────────────
function TriggeredNow() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const a = await api.alerts();
        if (alive) setAlerts((a ?? []).filter((x) => !x.resolved_at));
      } catch { /* feed is best-effort; the incidents queue is the authority */ }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const top = [...alerts]
    .sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9))
    .slice(0, 8);

  return (
    <div className="panel" style={{ minWidth: 0 }}>
      <div className="panel-tools">
        <h3>Triggered now</h3>
        <a href="#/monitoring/triggered" style={{ color: "var(--accent)", fontWeight: 600, fontSize: 12 }}>All alerts →</a>
      </div>
      {top.length === 0 ? (
        <div className="empty">No alerts firing.</div>
      ) : (
        <ul className="dm-list">
          {top.map((a) => (
            <li key={a.id}>
              <span><span className={`badge ${a.severity === "critical" || a.severity === "error" ? "bad" : a.severity === "warning" ? "warn" : ""}`}>{a.severity}</span> {a.summary || a.rule}</span>
              <strong>{fmtAge(a.fired_at)}</strong>
            </li>
          ))}
          {alerts.length > 8 && <li className="mini-meta">…and {alerts.length - 8} more firing</li>}
        </ul>
      )}
    </div>
  );
}

export default function CommandCenter() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await api.listIncidents({ limit: 500 });
      setIncidents(r ?? []);
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, [load]);

  const action = useCallback(async (id: string, act: "ack" | "resolve") => {
    setBusyId(id);
    try {
      await api.incidentAction(id, act);
      await load();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }, [load]);

  const unresolved = incidents.filter((i) => i.status !== "resolved" && i.status !== "closed");
  const open = unresolved.filter((i) => i.status === "open").length;
  const working = unresolved.filter((i) => i.status === "acknowledged" || i.status === "investigating").length;
  const critical = unresolved.filter((i) => i.severity === "critical").length;
  const ticketed = unresolved.filter((i) => i.sync_status === "synced").length;

  return (
    <div className="dm-board">
      <div className="card form-card" style={{ paddingBottom: 12 }}>
        <div className="form-head" style={{ marginBottom: 10 }}>
          <span className="form-head-icon"><Icon name="incident" size={18} /></span>
          <div>
            <h2>Command Center</h2>
            <p className="form-sub">What's burning, who's on it, and whether an incident can reach a human.</p>
          </div>
        </div>
        <StatStrip>
          <Stat label="Unresolved incidents" value={unresolved.length} tone={unresolved.length ? "warn" : "good"} />
          <Stat label="Critical" value={critical} tone={critical ? "bad" : "good"} />
          <Stat label="Untriaged (open)" value={open} tone={open ? "warn" : "good"} />
          <Stat label="Being worked" value={working} />
          <Stat label="Ticketed to ITSM" value={`${ticketed}/${unresolved.length}`} />
        </StatStrip>
        {err && <p style={{ color: "var(--bad)", fontSize: 13, margin: "8px 0 0" }}>{err}</p>}
      </div>

      <TriageQueue items={unresolved} onAction={action} busyId={busyId} />

      <div className="dm-grid">
        <TriggeredNow />
        <ResponseChannels />
      </div>
    </div>
  );
}
