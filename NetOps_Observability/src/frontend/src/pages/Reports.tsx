import { useEffect, useState } from "react";
import { api, SavedObject, ReportBody, ReportRun, ReportKind, ContactPoint } from "../services/api";

// Reports — saved objects (type=report) the server-side scheduler renders on
// a cadence and delivers via the notify dispatcher (Slack/email/PagerDuty…).
// This page is the builder + monitor: create a report, see when it last/next
// fires, and trigger an out-of-band delivery with "Send now".

const KINDS: { value: ReportKind; label: string; hint: string }[] = [
  { value: "alerts_summary", label: "Active alerts summary", hint: "Counts by severity + the most recent alerts." },
  { value: "device_inventory", label: "Device inventory", hint: "Discovered devices and their addresses." },
  { value: "health_summary", label: "Stack health", hint: "API uptime, device count, active-alert count." },
  // Executive reports (modelled on Datadog/Zabbix scheduled summaries).
  { value: "wan_utilization", label: "WAN circuit utilization", hint: "Per-WAN/overlay link load, status, loss & QoE." },
  { value: "security_threats", label: "Security threats", hint: "Findings by severity (24h) + critical alerts." },
  { value: "device_utilization", label: "Device utilization", hint: "Top devices by CPU and memory." },
  { value: "latency_jitter_sla", label: "Latency, jitter & SLA", hint: "Per-link latency/jitter/loss + availability SLA." },
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
  // Configured notify channels + the "Send now" channel-picker state.
  const [channels, setChannels] = useState<string[]>([]);
  // Reusable contact points (defined in the Notifications section) a report can
  // be delivered to.
  const [contactPoints, setContactPoints] = useState<ContactPoint[]>([]);
  const [picker, setPicker] = useState<{ report: SavedObject; selected: string[] } | null>(null);
  const [sending, setSending] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const [list, runState, chans, cps] = await Promise.all([
        api.listSaved("report"),
        api.reportRuns(),
        api.reportChannels().catch(() => [] as string[]),
        api.contactPoints().catch(() => [] as ContactPoint[]),
      ]);
      setItems(list);
      setRuns(runState ?? {});
      setChannels(chans ?? []);
      setContactPoints(cps ?? []);
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

  // Send now: if delivery channels are configured, open the picker so the
  // operator chooses where it goes; otherwise deliver straight away (the server
  // falls back to all channels). Selecting none in the picker also means "all".
  const sendNow = (o: SavedObject) => {
    if (channels.length === 0) {
      void deliver(o, []);
      return;
    }
    setPicker({ report: o, selected: [...channels] });
  };

  const deliver = async (o: SavedObject, chans: string[]) => {
    setSending(true);
    try {
      const run = await api.runReport(o.id, chans);
      setRuns((prev) => ({ ...prev, [o.id]: run }));
      setPicker(null);
    } catch (err) {
      window.alert(`Send failed: ${(err as Error).message}`);
    } finally {
      setSending(false);
    }
  };

  const toggleChannel = (name: string) =>
    setPicker((p) =>
      !p
        ? p
        : {
            ...p,
            selected: p.selected.includes(name)
              ? p.selected.filter((c) => c !== name)
              : [...p.selected, name],
          },
    );

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

          {/* Recipients — reusable contact points defined in Notifications. */}
          <div style={{ display: "grid", gap: 4 }}>
            <span style={{ fontSize: 13, fontWeight: 600 }}>Recipients (contact points)</span>
            {contactPoints.length === 0 ? (
              <span style={{ color: "var(--muted)", fontSize: 12 }}>
                No contact points yet — create email groups in Administration → Notifications.
              </span>
            ) : (
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: 6,
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  padding: 8,
                }}
              >
                {contactPoints.map((cp) => {
                  const selected = (draft.contact_points ?? []).includes(cp.id);
                  return (
                    <label
                      key={cp.id}
                      title={cp.type === "email" ? (cp.email ?? []).join(", ") : cp.target}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 12,
                        padding: "2px 8px",
                        borderRadius: 12,
                        cursor: "pointer",
                        background: selected ? "var(--accent, #5b5bd6)" : "var(--chip-bg, #f0f0f4)",
                        color: selected ? "#fff" : "var(--fg)",
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={selected}
                        onChange={() =>
                          setDraft((d) => {
                            const cur = d.contact_points ?? [];
                            return {
                              ...d,
                              contact_points: cur.includes(cp.id)
                                ? cur.filter((x) => x !== cp.id)
                                : [...cur, cp.id],
                            };
                          })
                        }
                        style={{ width: "auto" }}
                      />
                      {cp.name} <span style={{ opacity: 0.7 }}>· {cp.type}</span>
                    </label>
                  );
                })}
              </div>
            )}
          </div>

          {/* Delivery mode — how contact-point recipients receive the report. */}
          <label style={{ fontSize: 13, display: "grid", gap: 4 }}>
            Delivery
            <select
              value={draft.delivery_mode ?? "body"}
              onChange={(e) => setDraft({ ...draft, delivery_mode: e.target.value as "body" | "link" })}
              title="How contact-point recipients receive the report"
            >
              <option value="body">Email the report</option>
              <option value="link">Secure link (rolling out)</option>
            </select>
          </label>

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

      {picker && (
        <div
          className="modal-backdrop"
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.45)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
          onClick={() => !sending && setPicker(null)}
        >
          <div
            className="card"
            style={{ minWidth: 360, maxWidth: 460 }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 style={{ marginTop: 0 }}>Send “{picker.report.name}”</h3>
            <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 0 }}>
              Choose delivery channels. Leave all unchecked to send to every
              configured channel.
            </p>
            <div style={{ display: "grid", gap: 6, margin: "12px 0" }}>
              {channels.map((c) => (
                <label key={c} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <input
                    type="checkbox"
                    checked={picker.selected.includes(c)}
                    onChange={() => toggleChannel(c)}
                  />
                  <span style={{ textTransform: "capitalize" }}>{c}</span>
                </label>
              ))}
            </div>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button onClick={() => setPicker(null)} disabled={sending}>
                Cancel
              </button>
              <button
                className="primary"
                onClick={() => deliver(picker.report, picker.selected)}
                disabled={sending}
                title={
                  picker.selected.length
                    ? `Send to: ${picker.selected.join(", ")}`
                    : "Send to all configured channels"
                }
              >
                {sending
                  ? "Sending…"
                  : picker.selected.length
                  ? `Send to ${picker.selected.length} channel${picker.selected.length === 1 ? "" : "s"}`
                  : "Send to all"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
