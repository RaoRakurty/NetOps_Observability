import { Fragment, useEffect, useState } from "react";
import {
  api,
  SavedObject,
  ReportBody,
  ReportRun,
  ReportKind,
  ContactPoint,
  Recurrence,
  Weekday,
  ReportFormat,
  ReportExecution,
  ReportExecutionDetail,
} from "../services/api";
import Icon from "../components/Icon";

// Reports — build a report (what + when + who + which formats), monitor its
// runs, and drill into the async execution history (phase timeline, per-recipient
// delivery, downloadable HTML/Excel/PDF artifacts). The server renders the
// dataset to every chosen format in parallel and delivers via contact points.

const KINDS: { value: ReportKind; label: string; hint: string }[] = [
  { value: "alerts_summary", label: "Active alerts summary", hint: "Counts by severity + the most recent alerts." },
  { value: "device_inventory", label: "Device inventory", hint: "Discovered devices and their addresses." },
  { value: "health_summary", label: "Stack health", hint: "API uptime, device count, active-alert count." },
  { value: "wan_utilization", label: "WAN circuit utilization", hint: "Per-WAN/overlay link load, status, loss & QoE." },
  { value: "security_threats", label: "Security threats", hint: "Findings by severity (24h) + critical alerts." },
  { value: "device_utilization", label: "Device utilization", hint: "Top devices by CPU and memory." },
  { value: "latency_jitter_sla", label: "Latency, jitter & SLA", hint: "Per-link latency/jitter/loss + availability SLA." },
];

const FORMATS: { value: ReportFormat; label: string }[] = [
  { value: "html", label: "HTML (email body)" },
  { value: "xlsx", label: "Excel" },
  { value: "pdf", label: "PDF" },
];

// Guided-wizard goals map executive-friendly outcomes to report kinds.
const GOALS: { icon: string; label: string; kind: ReportKind; blurb: string }[] = [
  { icon: "📈", label: "Executive Overview", kind: "health_summary", blurb: "Uptime, devices, and active issues at a glance." },
  { icon: "🩺", label: "Network Health", kind: "alerts_summary", blurb: "Active alerts by severity + the latest events." },
  { icon: "🎯", label: "SLA Summary", kind: "latency_jitter_sla", blurb: "Per-link latency, jitter, loss and availability." },
  { icon: "📊", label: "Capacity Trends", kind: "device_utilization", blurb: "Busiest devices by CPU and memory." },
  { icon: "🛡️", label: "Security Summary", kind: "security_threats", blurb: "Findings by severity (24h) + critical alerts." },
  { icon: "🌐", label: "WAN / Circuits", kind: "wan_utilization", blurb: "Per-WAN/overlay link load, status and QoE." },
];

const AUDIENCES: { label: string; severity: string; note: string }[] = [
  { label: "Executives", severity: "info", note: "For leadership — concise, outcome-focused." },
  { label: "NOC Team", severity: "warning", note: "For the NOC — operational detail and live issues." },
  { label: "Operations", severity: "notice", note: "For ops — inventory and utilization detail." },
  { label: "Customer", severity: "info", note: "For an external customer — SLA and health summary." },
];

const TZS = [
  "UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
  "Europe/London", "Europe/Berlin", "Asia/Kolkata", "Asia/Singapore", "Australia/Sydney",
];
const WEEKDAYS: { v: Weekday; l: string }[] = [
  { v: "mon", l: "Monday" }, { v: "tue", l: "Tuesday" }, { v: "wed", l: "Wednesday" },
  { v: "thu", l: "Thursday" }, { v: "fri", l: "Friday" }, { v: "sat", l: "Saturday" }, { v: "sun", l: "Sunday" },
];

function browserTZ(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

const EMPTY: ReportBody = {
  kind: "alerts_summary",
  interval_minutes: 1440,
  severity: "info",
  enabled: true,
  description: "",
  formats: ["html"],
  schedule: { tz: browserTZ(), hour: 7, minute: 0, weekday: "mon" },
};

function fmt(ts?: string): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

function time12(hour: number, minute: number): string {
  const h = hour % 12 === 0 ? 12 : hour % 12;
  const ap = hour < 12 ? "AM" : "PM";
  return `${h}:${String(minute).padStart(2, "0")} ${ap}`;
}

// nlSchedule renders a human-readable description of a report's cadence.
function nlSchedule(b: Partial<ReportBody>): string {
  const s = b.schedule;
  if (s) {
    const at = `at ${time12(s.hour, s.minute)} (${s.tz || "UTC"})`;
    if (s.dom && s.dom > 0) return `Monthly on day ${s.dom} ${at}`;
    if (s.weekday) return `Every ${WEEKDAYS.find((w) => w.v === s.weekday)?.l ?? s.weekday} ${at}`;
    return `Daily ${at}`;
  }
  const m = b.interval_minutes ?? 0;
  if (m === 60) return "Hourly";
  if (m === 360) return "Every 6 hours";
  if (m === 720) return "Every 12 hours";
  if (m === 1440) return "Daily";
  if (m === 10080) return "Weekly";
  return m > 0 ? `Every ${m} min` : "Not scheduled";
}

type Freq = "hourly" | "6h" | "12h" | "daily" | "weekly" | "monthly";
function freqOf(b: Partial<ReportBody>): Freq {
  if (b.schedule) {
    if (b.schedule.dom && b.schedule.dom > 0) return "monthly";
    if (b.schedule.weekday) return "weekly";
    return "daily";
  }
  const m = b.interval_minutes ?? 0;
  if (m === 360) return "6h";
  if (m === 720) return "12h";
  return "hourly";
}

function statusSev(status?: string): string {
  switch (status) {
    case "completed": return "ok";
    case "failed": return "critical";
    case "running": return "info";
    case "cancelled": return "warning";
    default: return "debug";
  }
}

// ScheduleControl — a human-readable cadence editor that writes either a calendar
// `schedule` (Recurrence) or the legacy `interval_minutes`, with a NL preview.
function ScheduleControl({ body, onChange }: { body: ReportBody; onChange: (b: ReportBody) => void }) {
  const freq = freqOf(body);
  const sched: Recurrence = body.schedule ?? { tz: browserTZ(), hour: 7, minute: 0 };

  const setFreq = (f: Freq) => {
    if (f === "hourly" || f === "6h" || f === "12h") {
      const m = f === "hourly" ? 60 : f === "6h" ? 360 : 720;
      onChange({ ...body, interval_minutes: m, schedule: undefined });
      return;
    }
    const base: Recurrence = { tz: sched.tz || browserTZ(), hour: sched.hour, minute: sched.minute };
    if (f === "daily") onChange({ ...body, schedule: { ...base } });
    if (f === "weekly") onChange({ ...body, schedule: { ...base, weekday: sched.weekday || "mon" } });
    if (f === "monthly") onChange({ ...body, schedule: { ...base, dom: sched.dom && sched.dom > 0 ? sched.dom : 1 } });
  };
  const patch = (p: Partial<Recurrence>) => onChange({ ...body, schedule: { ...sched, ...p } });

  return (
    <div style={{ display: "grid", gap: 8 }}>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
        <span style={{ fontSize: 13, color: "var(--muted)" }}>Send</span>
        <select value={freq} onChange={(e) => setFreq(e.target.value as Freq)}>
          <option value="hourly">Hourly</option>
          <option value="6h">Every 6 hours</option>
          <option value="12h">Every 12 hours</option>
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="monthly">Monthly</option>
        </select>

        {freq === "weekly" && (
          <>
            <span style={{ fontSize: 13, color: "var(--muted)" }}>on</span>
            <select value={sched.weekday || "mon"} onChange={(e) => patch({ weekday: e.target.value as Weekday })}>
              {WEEKDAYS.map((w) => <option key={w.v} value={w.v}>{w.l}</option>)}
            </select>
          </>
        )}
        {freq === "monthly" && (
          <>
            <span style={{ fontSize: 13, color: "var(--muted)" }}>on day</span>
            <select value={sched.dom ?? 1} onChange={(e) => patch({ dom: Number(e.target.value) })}>
              {Array.from({ length: 31 }, (_, i) => i + 1).map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
          </>
        )}

        {(freq === "daily" || freq === "weekly" || freq === "monthly") && (
          <>
            <span style={{ fontSize: 13, color: "var(--muted)" }}>at</span>
            <select value={sched.hour} onChange={(e) => patch({ hour: Number(e.target.value) })}>
              {Array.from({ length: 24 }, (_, h) => h).map((h) => <option key={h} value={h}>{time12(h, 0).replace(":00", "")}</option>)}
            </select>
            <select value={sched.minute} onChange={(e) => patch({ minute: Number(e.target.value) })}>
              {[0, 15, 30, 45].map((m) => <option key={m} value={m}>:{String(m).padStart(2, "0")}</option>)}
            </select>
            <select value={sched.tz} onChange={(e) => patch({ tz: e.target.value })}>
              {[browserTZ(), ...TZS.filter((t) => t !== browserTZ())].map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </>
        )}
      </div>
      <span className="mini-meta">{nlSchedule(body)}</span>
    </div>
  );
}

export default function Reports() {
  const [items, setItems] = useState<SavedObject[]>([]);
  const [runs, setRuns] = useState<Record<string, ReportRun>>({});
  const [name, setName] = useState("");
  const [draft, setDraft] = useState<ReportBody>(EMPTY);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [channels, setChannels] = useState<string[]>([]);
  const [contactPoints, setContactPoints] = useState<ContactPoint[]>([]);
  const [picker, setPicker] = useState<{ report: SavedObject; selected: string[] } | null>(null);
  const [sending, setSending] = useState(false);
  const [preview, setPreview] = useState<{ html: string } | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [history, setHistory] = useState<SavedObject | null>(null);
  const [wizard, setWizard] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const [list, runState, chans, cps] = await Promise.all([
        api.listSaved("report"),
        api.reportRuns().catch(() => ({} as Record<string, ReportRun>)),
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

  useEffect(() => { load(); }, []);

  const resetForm = () => { setName(""); setDraft(EMPTY); setEditingId(null); };

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    try {
      if (editingId) await api.updateSaved(editingId, name.trim(), draft);
      else await api.createSaved("report", name.trim(), draft);
      resetForm();
      await load();
    } catch (err) {
      window.alert(`Save failed: ${(err as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  const edit = (o: SavedObject) => {
    setEditingId(o.id);
    setName(o.name);
    setDraft({ ...EMPTY, ...(o.body as ReportBody) });
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const doPreview = async () => {
    setPreviewing(true);
    try {
      const html = await api.reportPreview(name || "Preview", draft, "html");
      setPreview({ html });
    } catch (err) {
      window.alert(`Preview failed: ${(err as Error).message}`);
    } finally {
      setPreviewing(false);
    }
  };

  const sendNow = (o: SavedObject) => {
    if (channels.length === 0) { void deliver(o, []); return; }
    setPicker({ report: o, selected: [...channels] });
  };

  const deliver = async (o: SavedObject, chans: string[]) => {
    setSending(true);
    try {
      await api.runReport(o.id, chans);
      setPicker(null);
      await load();
      setHistory(o); // jump to the freshly-queued execution
    } catch (err) {
      window.alert(`Send failed: ${(err as Error).message}`);
    } finally {
      setSending(false);
    }
  };

  const toggleChannel = (n: string) =>
    setPicker((p) => (!p ? p : { ...p, selected: p.selected.includes(n) ? p.selected.filter((c) => c !== n) : [...p.selected, n] }));

  const remove = async (o: SavedObject) => {
    if (!window.confirm(`Delete report "${o.name}"?`)) return;
    try {
      await api.deleteSaved(o.id);
      setItems((prev) => prev.filter((x) => x.id !== o.id));
    } catch (err) {
      window.alert(`Delete failed: ${(err as Error).message}`);
    }
  };

  const toggleFormat = (f: ReportFormat) =>
    setDraft((d) => {
      const cur = d.formats ?? ["html"];
      if (f === "html") return d; // html always on
      return { ...d, formats: cur.includes(f) ? cur.filter((x) => x !== f) : [...cur, f] };
    });

  const kindLabel = (k?: string) => KINDS.find((x) => x.value === k)?.label ?? k ?? "—";

  if (wizard) {
    return (
      <ReportWizard
        contactPoints={contactPoints}
        onCancel={() => setWizard(false)}
        onDone={async () => { setWizard(false); await load(); }}
      />
    );
  }

  return (
    <>
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h2 style={{ margin: 0 }}>{editingId ? "Edit report" : "New report"}</h2>
          {!editingId && <button type="button" className="dash-btn accent" onClick={() => setWizard(true)}>✨ Guided setup</button>}
        </div>
        <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 8 }}>
          Choose what to report, when to send it, who receives it, and which formats to produce.
          The server renders HTML, Excel and PDF in parallel and emails them to your contact points.
        </p>
        <form onSubmit={save} style={{ display: "grid", gap: 10, maxWidth: 560 }}>
          <input placeholder="Report name (e.g. Weekly exec health)" value={name} onChange={(e) => setName(e.target.value)} />

          <label style={{ display: "grid", gap: 4, fontSize: 13 }}>
            Content
            <select value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value as ReportKind })}>
              {KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
            </select>
            <span className="mini-meta">{KINDS.find((k) => k.value === draft.kind)?.hint}</span>
          </label>

          <ScheduleControl body={draft} onChange={setDraft} />

          {/* Output formats */}
          <div style={{ display: "grid", gap: 4 }}>
            <span style={{ fontSize: 13, fontWeight: 600 }}>Output formats</span>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {FORMATS.map((f) => {
                const on = (draft.formats ?? ["html"]).includes(f.value);
                return (
                  <button type="button" key={f.value} className={`chip${on ? " chip-active" : ""}`}
                    onClick={() => toggleFormat(f.value)} disabled={f.value === "html"}
                    title={f.value === "html" ? "HTML is always produced (the email body)" : ""}>
                    {on ? "✓ " : ""}{f.label}
                  </button>
                );
              })}
            </div>
          </div>

          <label style={{ display: "grid", gap: 4, fontSize: 13 }}>
            Severity
            <select value={draft.severity} onChange={(e) => setDraft({ ...draft, severity: e.target.value })}>
              <option value="info">info</option>
              <option value="notice">notice</option>
              <option value="warning">warning</option>
              <option value="critical">critical</option>
            </select>
          </label>

          <input placeholder="Optional note prepended to the report" value={draft.description ?? ""}
            onChange={(e) => setDraft({ ...draft, description: e.target.value })} />

          {/* Recipients — reusable contact points defined in Notifications. */}
          <div style={{ display: "grid", gap: 4 }}>
            <span style={{ fontSize: 13, fontWeight: 600 }}>Recipients (contact points)</span>
            {contactPoints.length === 0 ? (
              <span className="mini-meta">No contact points yet — create email groups in Administration → Notifications.</span>
            ) : (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {contactPoints.map((cp) => {
                  const selected = (draft.contact_points ?? []).includes(cp.id);
                  return (
                    <button type="button" key={cp.id} className={`chip${selected ? " chip-active" : ""}`}
                      title={cp.type === "email" ? (cp.email ?? []).join(", ") : cp.target}
                      onClick={() => setDraft((d) => {
                        const cur = d.contact_points ?? [];
                        return { ...d, contact_points: cur.includes(cp.id) ? cur.filter((x) => x !== cp.id) : [...cur, cp.id] };
                      })}>
                      {selected ? "✓ " : ""}{cp.name} · {cp.type}
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          <label style={{ fontSize: 13, display: "grid", gap: 4 }}>
            Delivery
            <select value={draft.delivery_mode ?? "body"} onChange={(e) => setDraft({ ...draft, delivery_mode: e.target.value as "body" | "link" })}>
              <option value="body">Email the report</option>
              <option value="link">Secure link (rolling out)</option>
            </select>
          </label>

          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
            <input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} style={{ width: "auto" }} />
            Enabled (scheduler delivers on the cadence above)
          </label>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button className="dash-btn accent" disabled={busy} type="submit">
              {busy ? "Saving…" : editingId ? "Save changes" : "Create report"}
            </button>
            <button className="dash-btn" type="button" onClick={doPreview} disabled={previewing}>
              {previewing ? "Rendering…" : "Preview"}
            </button>
            {editingId && <button className="dash-btn" type="button" onClick={resetForm}>Cancel</button>}
          </div>
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
                <th>Name</th><th>Content</th><th>Schedule</th><th>Formats</th><th>Status</th><th>Last sent</th><th>Next</th><th style={{ width: 230 }}></th>
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
                    <td>{enabled ? nlSchedule(body) : "Paused"}</td>
                    <td className="mini-meta">{(body.formats ?? ["html"]).join(", ")}</td>
                    <td>{run.status ? <span className={`badge sev-${statusSev(run.status)}`}>{run.status}</span> : "—"}</td>
                    <td className="mini-meta">{fmt(run.last_run)}</td>
                    <td className="mini-meta">{enabled ? fmt(run.next_run) : "—"}</td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      <button className="dash-btn" onClick={() => setHistory(o)} title="Execution history">History</button>{" "}
                      <button className="dash-btn" onClick={() => sendNow(o)} title="Deliver now">Send now</button>{" "}
                      <button className="dash-btn" onClick={() => edit(o)} title="Edit">Edit</button>{" "}
                      <button className="dash-btn" onClick={() => remove(o)} title="Delete">✕</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {preview && <PreviewModal html={preview.html} onClose={() => setPreview(null)} />}
      {history && <ExecutionsDrawer report={history} onClose={() => setHistory(null)} />}

      {picker && (
        <div className="modal-backdrop" style={backdrop} onClick={() => !sending && setPicker(null)}>
          <div className="card" style={{ minWidth: 360, maxWidth: 460 }} onClick={(e) => e.stopPropagation()}>
            <h3 style={{ marginTop: 0 }}>Send “{picker.report.name}”</h3>
            <p className="mini-meta" style={{ marginTop: 0 }}>
              Choose named channels (Slack/PagerDuty…). Contact-point email always goes per the report's recipients.
            </p>
            <div style={{ display: "grid", gap: 6, margin: "12px 0" }}>
              {channels.map((c) => (
                <label key={c} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <input type="checkbox" checked={picker.selected.includes(c)} onChange={() => toggleChannel(c)} />
                  <span style={{ textTransform: "capitalize" }}>{c}</span>
                </label>
              ))}
            </div>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button className="dash-btn" onClick={() => setPicker(null)} disabled={sending}>Cancel</button>
              <button className="dash-btn accent" onClick={() => deliver(picker.report, picker.selected)} disabled={sending}>
                {sending ? "Sending…" : "Send"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

const backdrop: React.CSSProperties = {
  position: "fixed", inset: 0, background: "rgba(0,0,0,0.45)",
  display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000,
};

// ReportWizard — a guided 5-step flow (goal → audience → schedule → recipients
// → preview) for non-technical users, producing a standard report.
function ReportWizard({ contactPoints, onCancel, onDone }: { contactPoints: ContactPoint[]; onCancel: () => void; onDone: () => Promise<void> }) {
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [draft, setDraft] = useState<ReportBody>(EMPTY);
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [busy, setBusy] = useState(false);
  const STEPS = ["Goal", "Audience", "Schedule", "Recipients", "Preview"];

  const pickGoal = (g: (typeof GOALS)[number]) => { setDraft((d) => ({ ...d, kind: g.kind })); if (!name) setName(g.label); setStep(1); };
  const pickAudience = (a: (typeof AUDIENCES)[number]) => { setDraft((d) => ({ ...d, severity: a.severity, description: a.note })); setStep(2); };
  const toggleFormat = (f: ReportFormat) => setDraft((d) => {
    if (f === "html") return d;
    const cur = d.formats ?? ["html"];
    return { ...d, formats: cur.includes(f) ? cur.filter((x) => x !== f) : [...cur, f] };
  });
  const toggleCp = (id: string) => setDraft((d) => {
    const cur = d.contact_points ?? [];
    return { ...d, contact_points: cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id] };
  });

  useEffect(() => {
    if (step !== 4) return;
    let live = true;
    setPreviewing(true);
    api.reportPreview(name || "Preview", draft, "html")
      .then((h) => { if (live) setPreviewHtml(h); })
      .catch((e) => { if (live) window.alert(`Preview failed: ${(e as Error).message}`); })
      .finally(() => { if (live) setPreviewing(false); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  const create = async () => {
    if (!name.trim()) { window.alert("Give the report a name."); return; }
    setBusy(true);
    try { await api.createSaved("report", name.trim(), draft); await onDone(); }
    catch (e) { window.alert(`Create failed: ${(e as Error).message}`); }
    finally { setBusy(false); }
  };

  const cardBtn = (active: boolean): React.CSSProperties => ({ textAlign: "left", padding: 14, borderColor: active ? "var(--accent)" : undefined });

  return (
    <div className="card" style={{ maxWidth: 760 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h2 style={{ margin: 0 }}>Guided report setup</h2>
        <button className="dash-btn" onClick={onCancel}>Close</button>
      </div>
      <div style={{ display: "flex", gap: 14, margin: "14px 0 18px", flexWrap: "wrap" }}>
        {STEPS.map((s, i) => (
          <div key={s} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: i === step ? "var(--accent)" : "var(--muted)", fontWeight: i === step ? 700 : 400 }}>
            <span style={{ width: 20, height: 20, borderRadius: 999, display: "inline-flex", alignItems: "center", justifyContent: "center", background: i < step ? "var(--good)" : i === step ? "var(--accent)" : "var(--panel-border)", color: "#fff", fontSize: 11 }}>{i < step ? "✓" : i + 1}</span>
            {s}
          </div>
        ))}
      </div>

      {step === 0 && (
        <div>
          <p className="mini-meta">What's the goal of this report?</p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(210px, 1fr))", gap: 10 }}>
            {GOALS.map((g) => (
              <button key={g.label} className="dash-btn" style={cardBtn(draft.kind === g.kind)} onClick={() => pickGoal(g)}>
                <div style={{ fontSize: 22 }}>{g.icon}</div>
                <div style={{ fontWeight: 700, marginTop: 4 }}>{g.label}</div>
                <div className="mini-meta">{g.blurb}</div>
              </button>
            ))}
          </div>
        </div>
      )}

      {step === 1 && (
        <div>
          <p className="mini-meta">Who is this report for?</p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(210px, 1fr))", gap: 10 }}>
            {AUDIENCES.map((a) => (
              <button key={a.label} className="dash-btn" style={cardBtn(draft.description === a.note)} onClick={() => pickAudience(a)}>
                <div style={{ fontWeight: 700 }}>{a.label}</div>
                <div className="mini-meta">{a.note}</div>
              </button>
            ))}
          </div>
        </div>
      )}

      {step === 2 && (
        <div>
          <p className="mini-meta">How often should it go out?</p>
          <ScheduleControl body={draft} onChange={setDraft} />
        </div>
      )}

      {step === 3 && (
        <div style={{ display: "grid", gap: 14 }}>
          <div>
            <p className="mini-meta">Who receives it? (contact points)</p>
            {contactPoints.length === 0 ? (
              <span className="mini-meta">No contact points yet — add email groups in Administration → Notifications.</span>
            ) : (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {contactPoints.map((cp) => {
                  const on = (draft.contact_points ?? []).includes(cp.id);
                  return <button key={cp.id} className={`chip${on ? " chip-active" : ""}`} onClick={() => toggleCp(cp.id)}>{on ? "✓ " : ""}{cp.name} · {cp.type}</button>;
                })}
              </div>
            )}
          </div>
          <div>
            <p className="mini-meta">Formats</p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {FORMATS.map((f) => {
                const on = (draft.formats ?? ["html"]).includes(f.value);
                return <button key={f.value} className={`chip${on ? " chip-active" : ""}`} disabled={f.value === "html"} onClick={() => toggleFormat(f.value)}>{on ? "✓ " : ""}{f.label}</button>;
              })}
            </div>
          </div>
          <label style={{ fontSize: 13, display: "grid", gap: 4 }}>
            Delivery
            <select value={draft.delivery_mode ?? "body"} onChange={(e) => setDraft({ ...draft, delivery_mode: e.target.value as "body" | "link" })}>
              <option value="body">Email the report</option>
              <option value="link">Secure link</option>
            </select>
          </label>
        </div>
      )}

      {step === 4 && (
        <div style={{ display: "grid", gap: 10 }}>
          <input placeholder="Report name" value={name} onChange={(e) => setName(e.target.value)} />
          <div className="mini-meta">{nlSchedule(draft)} · {(draft.formats ?? ["html"]).join(", ")} · {(draft.contact_points ?? []).length} recipient group(s)</div>
          <div style={{ height: 360, border: "1px solid var(--panel-border)", borderRadius: 8, background: "#fff", overflow: "hidden" }}>
            {previewing ? <div className="empty">Rendering preview…</div> : previewHtml ? <iframe title="preview" sandbox="" srcDoc={previewHtml} style={{ width: "100%", height: "100%", border: 0 }} /> : <div className="empty">No preview</div>}
          </div>
        </div>
      )}

      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 18 }}>
        <button className="dash-btn" disabled={step === 0} onClick={() => setStep((s) => Math.max(0, s - 1))}>Back</button>
        {step < 4 ? (
          <button className="dash-btn accent" onClick={() => setStep((s) => Math.min(4, s + 1))}>Next</button>
        ) : (
          <button className="dash-btn accent" disabled={busy} onClick={create}>{busy ? "Creating…" : "Create report"}</button>
        )}
      </div>
    </div>
  );
}

function PreviewModal({ html, onClose }: { html: string; onClose: () => void }) {
  return (
    <div className="modal-backdrop" style={backdrop} onClick={onClose}>
      <div className="card" style={{ width: "min(820px, 94vw)", height: "min(80vh, 760px)", display: "flex", flexDirection: "column" }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h3 style={{ margin: 0 }}>Preview</h3>
          <button className="dash-btn" onClick={onClose}>Close</button>
        </div>
        <iframe title="report preview" sandbox="" srcDoc={html}
          style={{ flex: 1, width: "100%", border: "1px solid var(--panel-border)", borderRadius: 8, marginTop: 10, background: "#fff" }} />
      </div>
    </div>
  );
}

// ExecutionsDrawer — the async execution history for one report: a run list, an
// expandable phase timeline, per-recipient delivery status, and artifact downloads.
function ExecutionsDrawer({ report, onClose }: { report: SavedObject; onClose: () => void }) {
  const [execs, setExecs] = useState<ReportExecution[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [detail, setDetail] = useState<Record<string, ReportExecutionDetail>>({});

  const load = async () => {
    try {
      setExecs(await api.reportExecutions(report.id, { limit: 50 }));
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [report.id]);

  const expand = async (id: string) => {
    if (open === id) { setOpen(null); return; }
    setOpen(id);
    if (!detail[id]) {
      try {
        const d = await api.reportExecution(id);
        setDetail((m) => ({ ...m, [id]: d }));
      } catch { /* ignore */ }
    }
  };

  const dur = (a?: string, b?: string) => {
    if (!a || !b) return "—";
    const ms = new Date(b).getTime() - new Date(a).getTime();
    return isNaN(ms) ? "—" : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
  };

  return (
    <div className="modal-backdrop" style={backdrop} onClick={onClose}>
      <div className="card" style={{ width: "min(900px, 96vw)", maxHeight: "88vh", overflow: "auto" }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h3 style={{ margin: 0 }}>Execution history — {report.name}</h3>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="dash-btn" onClick={load}><Icon name="refresh" size={13} /> Refresh</button>
            <button className="dash-btn" onClick={onClose}>Close</button>
          </div>
        </div>
        {err && <p className="mini-meta" style={{ color: "var(--warn)" }}>{err.includes("409") ? "Execution history requires the Postgres backend." : err}</p>}
        {!execs ? (
          <div className="empty">Loading…</div>
        ) : execs.length === 0 ? (
          <div className="empty">No runs yet. Use “Send now”, or wait for the schedule.</div>
        ) : (
          <table style={{ marginTop: 10 }}>
            <thead>
              <tr><th></th><th>Fired</th><th>Status</th><th>Duration</th><th>Recipients</th><th>Artifacts</th></tr>
            </thead>
            <tbody>
              {execs.map((e) => {
                const okN = (e.delivery_status ?? []).filter((d) => d.ok).length;
                const total = (e.delivery_status ?? []).length;
                const d = detail[e.id];
                return (
                  <Fragment key={e.id}>
                    <tr style={{ cursor: "pointer" }} onClick={() => expand(e.id)}>
                      <td>{open === e.id ? "▾" : "▸"}</td>
                      <td className="mini-meta">{fmt(e.fire_time)}</td>
                      <td><span className={`badge sev-${statusSev(e.status)}`}>{e.status}</span></td>
                      <td className="mini-meta">{dur(e.started_at, e.completed_at)}</td>
                      <td className="mini-meta">{total ? `${okN}/${total} ok` : "—"}</td>
                      <td onClick={(ev) => ev.stopPropagation()}>
                        {(e.artifacts ?? []).map((a) => (
                          <button key={a.format} className="dash-btn" style={{ marginRight: 4 }}
                            onClick={() => api.downloadArtifact(e.id, a.format).catch((x) => window.alert(String(x)))}>
                            {a.format}
                          </button>
                        ))}
                      </td>
                    </tr>
                    {open === e.id && (
                      <tr>
                        <td colSpan={6} style={{ background: "var(--bg)" }}>
                          {e.error && <p style={{ color: "var(--bad)", margin: "6px 0" }}>{e.error}</p>}
                          <div style={{ display: "flex", gap: 24, flexWrap: "wrap", padding: "8px 4px" }}>
                            <div style={{ minWidth: 240 }}>
                              <div className="mini-meta" style={{ fontWeight: 700, marginBottom: 4 }}>Phase timeline</div>
                              {(d?.events ?? []).length === 0 ? <span className="mini-meta">—</span> : (
                                <table className="mini-table">
                                  <tbody>
                                    {d!.events!.map((ev, i) => {
                                      const prev = i > 0 ? d!.events![i - 1].at : undefined;
                                      return (
                                        <tr key={i}>
                                          <td style={{ textTransform: "capitalize" }}>{ev.phase}</td>
                                          <td className="mini-meta">{new Date(ev.at).toLocaleTimeString()}</td>
                                          <td className="mini-meta">{prev ? `+${dur(prev, ev.at)}` : ""}</td>
                                        </tr>
                                      );
                                    })}
                                  </tbody>
                                </table>
                              )}
                            </div>
                            <div style={{ minWidth: 280 }}>
                              <div className="mini-meta" style={{ fontWeight: 700, marginBottom: 4 }}>Delivery</div>
                              {(e.delivery_status ?? []).length === 0 ? <span className="mini-meta">—</span> : (
                                <table className="mini-table">
                                  <tbody>
                                    {e.delivery_status!.map((ds, i) => (
                                      <tr key={i}>
                                        <td>{ds.recipient}</td>
                                        <td className="mini-meta">{ds.channel}</td>
                                        <td><span className={`badge sev-${ds.ok ? "ok" : "critical"}`}>{ds.ok ? "ok" : "fail"}</span></td>
                                        <td className="mini-meta">{ds.error ?? ""}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
