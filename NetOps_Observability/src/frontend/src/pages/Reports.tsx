import { useEffect, useState } from "react";
import { api, SavedObject, ReportBody, ReportRun, ReportKind } from "../services/api";

// Reports — saved objects (type=report) the server-side scheduler renders on
// a cadence and delivers via the notify dispatcher (Slack/email/PagerDuty…).
// This page is the builder + monitor: create a report, see when it last/next
// fires, and trigger an out-of-band delivery with "Send now".

const KINDS: { value: ReportKind; label: string; hint: string }[] = [
  { value: "alerts_summary", label: "Active alerts summary", hint: "Counts by severity + the most recent alerts." },
  { value: "device_inventory", label: "Device inventory", hint: "Discovered devices and their addresses." },
  { value: "health_summary", label: "Stack health", hint: "API uptime, device count, active-alert count." },
];

const INTERVALS: { value: number; label: string }[] = [
  { value: 60, label: "Hourly" },
  { value: 360, label: "Every 6 hours" },
  { value: 720, label: "Every 12 hours" },
  { value: 1440, label: "Daily" },
  { value: 10080, label: "Weekly" },
];

const EMPTY: ReportBody = {
  kind: "alerts_summary",
  interval_minutes: 1440,
  severity: "info",
  enabled: true,
  description: "",
};

function fmt(ts?: string): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export default function Reports() {
  const [items, setItems] = useState<SavedObject[]>([]);
  const [runs, setRuns] = useState<Record<string, ReportRun>>({});
  const [name, setName] = useState("");
  const [draft, setDraft] = useState<ReportBody>(EMPTY);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [list, runState] = await Promise.all([api.listSaved("report"), api.reportRuns()]);
      setItems(list);
      setRuns(runState ?? {});
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    try {
      await api.createSaved("report", name.trim(), draft);
      setName("");
      setDraft(EMPTY);
      await load();
    } catch (err) {
      window.alert(`Create failed: ${(err as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  const sendNow = async (o: SavedObject) => {
    try {
      const run = await api.runReport(o.id);
      setRuns((prev) => ({ ...prev, [o.id]: run }));
    } catch (err) {
      window.alert(`Send failed: ${(err as Error).message}`);
    }
  };

  const remove = async (o: SavedObject) => {
    if (!window.confirm(`Delete report "${o.name}"?`)) return;
    try {
      await api.deleteSaved(o.id);
      setItems((prev) => prev.filter((x) => x.id !== o.id));
    } catch (err) {
      window.alert(`Delete failed: ${(err as Error).message}`);
    }
  };

  const kindLabel = (k?: string) => KINDS.find((x) => x.value === k)?.label ?? k ?? "—";
  const intervalLabel = (m?: number) =>
    INTERVALS.find((x) => x.value === m)?.label ?? (m ? `Every ${m} min` : "—");

  return (
    <>
      <div className="card">
        <h2>New report</h2>
        <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 0 }}>
          Pick what to report and how often. The scheduler renders it and delivers
          through whichever notify channels are enabled (Slack, email, PagerDuty).
        </p>
        <form onSubmit={create} style={{ display: "grid", gap: 8, maxWidth: 520 }}>
          <input
            placeholder="Report name (e.g. Daily alert digest)"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <select
            value={draft.kind}
            onChange={(e) => setDraft({ ...draft, kind: e.target.value as ReportKind })}
          >
            {KINDS.map((k) => (
              <option key={k.value} value={k.value}>
                {k.label}
              </option>
            ))}
          </select>
          <span style={{ color: "var(--muted)", fontSize: 12 }}>
            {KINDS.find((k) => k.value === draft.kind)?.hint}
          </span>
          <select
            value={draft.interval_minutes}
            onChange={(e) => setDraft({ ...draft, interval_minutes: Number(e.target.value) })}
          >
            {INTERVALS.map((i) => (
              <option key={i.value} value={i.value}>
                {i.label}
              </option>
            ))}
          </select>
          <select
            value={draft.severity}
            onChange={(e) => setDraft({ ...draft, severity: e.target.value })}
            title="Severity stamped on the delivered message"
          >
            <option value="info">info</option>
            <option value="notice">notice</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </select>
          <input
            placeholder="Optional note prepended to the report body"
            value={draft.description ?? ""}
            onChange={(e) => setDraft({ ...draft, description: e.target.value })}
          />
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
              style={{ width: "auto" }}
            />
            Enabled (scheduler delivers on the cadence above)
          </label>
          <button disabled={busy} type="submit">
            {busy ? "Saving…" : "Create report"}
          </button>
        </form>
      </div>

      <div className="card">
        <h2>Reports ({items.length})</h2>
        {error && <p style={{ color: "var(--bad)" }}>{error}</p>}
        {loading ? (
          <div className="empty">Loading…</div>
        ) : items.length === 0 ? (
          <div className="empty">No reports yet. Create one above.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Content</th>
                <th>Cadence</th>
                <th>Status</th>
                <th>Last sent</th>
                <th>Next</th>
                <th style={{ width: 150 }}></th>
              </tr>
            </thead>
            <tbody>
              {items.map((o) => {
                const body = (o.body ?? {}) as Partial<ReportBody>;
                const run = runs[o.id] ?? {};
                const enabled = body.enabled !== false;
                return (
                  <tr key={o.id}>
                    <td>{o.name}</td>
                    <td>{kindLabel(body.kind)}</td>
                    <td>{enabled ? intervalLabel(body.interval_minutes) : "Paused"}</td>
                    <td>
                      <span style={{ color: run.status === "error" ? "var(--bad)" : "var(--muted)" }}>
                        {run.status ?? "—"}
                      </span>
                    </td>
                    <td style={{ color: "var(--muted)", fontSize: 12 }}>{fmt(run.last_run)}</td>
                    <td style={{ color: "var(--muted)", fontSize: 12 }}>
                      {enabled ? fmt(run.next_run) : "—"}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button onClick={() => sendNow(o)} title="Deliver now">Send now</button>{" "}
                      <button onClick={() => remove(o)} title="Delete">✕</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
