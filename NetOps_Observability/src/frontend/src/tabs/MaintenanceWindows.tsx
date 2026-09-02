import { useCallback, useEffect, useMemo, useState } from "react";
import { fmtDateTime } from "../lib/time";
import { api, MaintenanceWindow, MaintenanceWindowInput } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { Chip } from "../components/noc";
import { operatorError } from "../lib/errors";
// Maintenance Windows (item 121): declared planned-work periods. A covering
// window pauses alert NOTIFICATIONS for the scoped devices/sites/rules — the
// alerts still fire and stay visible (the mute/snooze honesty rule) — and
// stamps incidents inside the window as planned maintenance so MTBF and
// chronic-offender math stop counting planned reboots as failures.

const fmt = (iso?: string) => (iso ? fmtDateTime(iso) : "—");

type Shape = "one_shot" | "recurring";

type FormState = {
  name: string;
  description: string;
  device_ids: string; // comma-separated in the form; split on save
  sites: string;
  rules: string;
  shape: Shape;
  starts_at: string; // datetime-local
  ends_at: string;
  weekdays: string[];
  start_time: string; // HH:MM
  duration_minutes: string;
  tz: string;
  enabled: boolean;
};

const EMPTY_FORM: FormState = {
  name: "", description: "", device_ids: "", sites: "", rules: "",
  shape: "one_shot", starts_at: "", ends_at: "",
  weekdays: [], start_time: "22:00", duration_minutes: "120", tz: "",
  enabled: true,
};

const WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const;

const splitList = (s: string) =>
  s.split(",").map((v) => v.trim()).filter(Boolean);

// datetime-local carries no zone; the API takes RFC3339 — send the browser's
// local instant honestly rather than pretending it was UTC.
const toRFC3339 = (local: string) => (local ? new Date(local).toISOString() : "");
const toLocalInput = (iso?: string) => {
  if (!iso) return "";
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

function validate(f: FormState): string | null {
  if (!f.name.trim()) return "A name is required.";
  if (f.shape === "one_shot") {
    if (!f.starts_at || !f.ends_at) return "A one-shot window needs both start and end.";
    if (new Date(f.ends_at) <= new Date(f.starts_at)) return "End must be after start.";
  } else {
    const dur = Number(f.duration_minutes);
    if (!Number.isFinite(dur) || dur < 1) return "Duration must be at least 1 minute.";
    if (!/^\d{2}:\d{2}$/.test(f.start_time)) return "Start time must be HH:MM.";
  }
  return null;
}

function toInput(f: FormState): MaintenanceWindowInput {
  const base: MaintenanceWindowInput = {
    name: f.name.trim(),
    description: f.description.trim() || undefined,
    device_ids: splitList(f.device_ids),
    sites: splitList(f.sites),
    rules: splitList(f.rules),
    enabled: f.enabled,
  };
  if (f.shape === "one_shot") {
    base.starts_at = toRFC3339(f.starts_at);
    base.ends_at = toRFC3339(f.ends_at);
  } else {
    const [h, m] = f.start_time.split(":").map(Number);
    base.schedule = {
      tz: f.tz.trim() || undefined,
      weekdays: f.weekdays,
      start_hour: h,
      start_minute: m,
      duration_minutes: Number(f.duration_minutes),
    };
  }
  return base;
}

function fromWindow(w: MaintenanceWindow): FormState {
  return {
    name: w.name,
    description: w.description ?? "",
    device_ids: (w.device_ids ?? []).join(", "),
    sites: (w.sites ?? []).join(", "),
    rules: (w.rules ?? []).join(", "),
    shape: w.schedule ? "recurring" : "one_shot",
    starts_at: toLocalInput(w.starts_at),
    ends_at: toLocalInput(w.ends_at),
    weekdays: w.schedule?.weekdays ?? [],
    start_time: w.schedule
      ? `${String(w.schedule.start_hour).padStart(2, "0")}:${String(w.schedule.start_minute).padStart(2, "0")}`
      : "22:00",
    duration_minutes: String(w.schedule?.duration_minutes ?? 120),
    tz: w.schedule?.tz ?? "",
    enabled: w.enabled,
  };
}

const scopeSummary = (w: MaintenanceWindow) => {
  const parts: string[] = [];
  if (w.device_ids?.length) parts.push(`${w.device_ids.length} device${w.device_ids.length === 1 ? "" : "s"}`);
  if (w.sites?.length) parts.push(`${w.sites.length} site${w.sites.length === 1 ? "" : "s"}`);
  if (w.rules?.length) parts.push(`${w.rules.length} rule${w.rules.length === 1 ? "" : "s"}`);
  return parts.length ? parts.join(" · ") : "Whole tenant";
};

const whenSummary = (w: MaintenanceWindow) => {
  if (!w.schedule) return `${fmt(w.starts_at)} → ${fmt(w.ends_at)}`;
  const s = w.schedule;
  const days = s.weekdays?.length ? s.weekdays.join("/") : "daily";
  const hh = String(s.start_hour).padStart(2, "0");
  const mm = String(s.start_minute).padStart(2, "0");
  return `${days} ${hh}:${mm} ${s.tz || "UTC"} for ${s.duration_minutes}m`;
};

const isActiveNow = (w: MaintenanceWindow) => {
  // One-shot only — recurring evaluation lives server-side; the list shows the
  // schedule instead of guessing occurrence state in the browser.
  if (!w.enabled || w.schedule || !w.starts_at || !w.ends_at) return false;
  const now = Date.now();
  return Date.parse(w.starts_at) <= now && now < Date.parse(w.ends_at);
};

function WindowForm({ initial, onSaved, onCancel }: {
  initial: { id?: string; form: FormState };
  onSaved: () => void;
  onCancel: () => void;
}) {
  const [f, setF] = useState<FormState>(initial.form);
  const [err, setErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setF((p) => ({ ...p, [k]: v }));

  const save = async () => {
    const v = validate(f);
    if (v) { setErr(v); return; }
    setSaving(true);
    try {
      if (initial.id) await api.maintenanceWindowUpdate(initial.id, toInput(f));
      else await api.maintenanceWindowCreate(toInput(f));
      onSaved();
    } catch (e) {
      setErr(operatorError(e, "Maintenance windows could not be loaded."));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="cc-panel" style={{ marginTop: 12 }}>
      <div className="cc-panel-h">
        <h3 className="cc-panel-t">{initial.id ? "Edit maintenance window" : "New maintenance window"}</h3>
      </div>
      <div style={{ padding: "11px 13px", display: "grid", gap: 10 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <label className="ccw-field">
            <span className="ccw-label">Name <span className="ccw-req">*</span></span>
            <input className="ccw-input" value={f.name} onChange={(e) => set("name", e.target.value)}
              placeholder="CHG-2026-0801 core switch upgrade" maxLength={128} />
          </label>
          <label className="ccw-field">
            <span className="ccw-label">Description</span>
            <input className="ccw-input" value={f.description} onChange={(e) => set("description", e.target.value)}
              placeholder="What is being worked on, and by whom" maxLength={1024} />
          </label>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
          <label className="ccw-field">
            <span className="ccw-label">Devices</span>
            <input className="ccw-input" value={f.device_ids} onChange={(e) => set("device_ids", e.target.value)}
              placeholder="comma-separated device ids · empty = all" />
          </label>
          <label className="ccw-field">
            <span className="ccw-label">Sites</span>
            <input className="ccw-input" value={f.sites} onChange={(e) => set("sites", e.target.value)}
              placeholder="comma-separated site slugs · empty = all" />
          </label>
          <label className="ccw-field">
            <span className="ccw-label">Monitor rules</span>
            <input className="ccw-input" value={f.rules} onChange={(e) => set("rules", e.target.value)}
              placeholder="comma-separated rule names · empty = all" />
          </label>
        </div>
        <div className="ccw-hint">
          Scopes combine with AND: a window listing devices <em>and</em> sites only covers alerts matching both.
          An alert whose site is unknown is never covered by a sites-scoped window.
        </div>

        <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
          <label style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
            <input type="radio" checked={f.shape === "one_shot"} onChange={() => set("shape", "one_shot")} />
            One-time
          </label>
          <label style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
            <input type="radio" checked={f.shape === "recurring"} onChange={() => set("shape", "recurring")} />
            Recurring
          </label>
          <label style={{ display: "inline-flex", gap: 6, alignItems: "center", marginLeft: "auto" }}>
            <input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />
            Enabled
          </label>
        </div>

        {f.shape === "one_shot" ? (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <label className="ccw-field">
              <span className="ccw-label">Starts <span className="ccw-req">*</span></span>
              <input className="ccw-input" type="datetime-local" value={f.starts_at}
                onChange={(e) => set("starts_at", e.target.value)} />
            </label>
            <label className="ccw-field">
              <span className="ccw-label">Ends <span className="ccw-req">*</span></span>
              <input className="ccw-input" type="datetime-local" value={f.ends_at}
                onChange={(e) => set("ends_at", e.target.value)} />
            </label>
          </div>
        ) : (
          <div style={{ display: "grid", gap: 10 }}>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {WEEKDAYS.map((d) => (
                <label key={d} style={{ display: "inline-flex", gap: 4, alignItems: "center" }}>
                  <input
                    type="checkbox"
                    checked={f.weekdays.includes(d)}
                    onChange={(e) =>
                      set("weekdays", e.target.checked ? [...f.weekdays, d] : f.weekdays.filter((x) => x !== d))}
                  />
                  {d}
                </label>
              ))}
              <span className="ccw-hint">no day selected = every day</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
              <label className="ccw-field">
                <span className="ccw-label">Start time <span className="ccw-req">*</span></span>
                <input className="ccw-input" type="time" value={f.start_time}
                  onChange={(e) => set("start_time", e.target.value)} />
              </label>
              <label className="ccw-field">
                <span className="ccw-label">Duration (minutes) <span className="ccw-req">*</span></span>
                <input className="ccw-input" type="number" min={1} max={10080} value={f.duration_minutes}
                  onChange={(e) => set("duration_minutes", e.target.value)} />
              </label>
              <label className="ccw-field">
                <span className="ccw-label">Timezone</span>
                <input className="ccw-input" value={f.tz} onChange={(e) => set("tz", e.target.value)}
                  placeholder="America/Chicago · empty = UTC" />
              </label>
            </div>
          </div>
        )}

        {err && <div role="alert" style={{ color: "var(--bad)" }}>{err}</div>}
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-primary" onClick={save} disabled={saving}>
            {saving ? "Saving…" : initial.id ? "Save changes" : "Create window"}
          </button>
          <button className="btn" onClick={onCancel} disabled={saving}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

export default function MaintenanceWindows() {
  const [items, setItems] = useState<MaintenanceWindow[] | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ id?: string; form: FormState } | null>(null);
  const [nonce, setNonce] = useState(0);

  const load = useCallback(async () => {
    try {
      const r = await api.maintenanceWindows();
      setItems(r.windows ?? []);
      setLoadErr(null);
    } catch (e) {
      setLoadErr(operatorError(e, "Maintenance windows could not be loaded."));
    }
  }, []);
  useEffect(() => { void load(); }, [load, nonce]);

  const remove = async (w: MaintenanceWindow) => {
    if (!window.confirm(`Delete maintenance window "${w.name}"? Alerts in its scope will notify again immediately.`)) return;
    try {
      await api.maintenanceWindowDelete(w.id);
      setNonce((n) => n + 1);
    } catch (e) {
      setLoadErr(operatorError(e, "Maintenance windows could not be loaded."));
    }
  };

  const columns = useMemo<Column<MaintenanceWindow>[]>(() => [
    { key: "name", header: "Window", width: "22%", sortable: true, text: (w) => w.name,
      render: (w) => <span title={w.description || w.name}>{w.name}</span> },
    { key: "status", header: "Status", width: 170, sortable: true,
      text: (w) => (w.enabled ? (isActiveNow(w) ? "active" : "enabled") : "disabled"),
      render: (w) => (
        <span style={{ display: "inline-flex", gap: 4 }}>
          {isActiveNow(w) && <Chip label="Suppressing now" tone="var(--warn)"
            title="This window is active — notifications in its scope are paused." />}
          {!isActiveNow(w) && w.enabled && <Chip label="Enabled" tone="var(--ok)" />}
          {!w.enabled && <Chip label="Disabled" tone="var(--fg-subtle)" />}
        </span>
      ) },
    { key: "scope", header: "Scope", width: "18%", text: scopeSummary, render: (w) => scopeSummary(w) },
    { key: "when", header: "When", width: "26%", text: whenSummary,
      render: (w) => <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{whenSummary(w)}</span> },
    { key: "updated", header: "Updated", width: 156, sortable: true,
      sortValue: (w) => Date.parse(w.updated_at) || 0, render: (w) => fmt(w.updated_at) },
    { key: "actions", header: "", width: 130,
      render: (w) => (
        <span style={{ display: "inline-flex", gap: 6 }}>
          <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); setEditing({ id: w.id, form: fromWindow(w) }); }}>
            Edit
          </button>
          <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); void remove(w); }}>
            Delete
          </button>
        </span>
      ) },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], []);

  return (
    <div>
      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Maintenance windows</h3>
          <span className="cc-panel-meta" style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
            {loadErr ? "unavailable" : `${items?.length ?? 0} window${(items?.length ?? 0) === 1 ? "" : "s"}`}
            <button className="btn btn-sm btn-primary" onClick={() => setEditing({ form: EMPTY_FORM })}>
              New window
            </button>
          </span>
        </div>
        <div style={{ padding: "11px 13px" }}>
          <div className="ccw-hint" style={{ marginBottom: 8 }}>
            During a covering window, alert <strong>notifications are paused</strong> — alerts still fire and stay
            visible, and incidents inside the window are counted as <strong>planned maintenance</strong> in the
            Recovery Scorecard instead of unplanned downtime.
          </div>
          {loadErr && (
            <div className="empty" role="alert" style={{ color: "var(--bad)" }}>
              <strong>Maintenance windows could not be loaded.</strong>
              <div style={{ marginTop: 4 }}>{loadErr}</div>
            </div>
          )}
          {!loadErr && items !== null && items.length === 0 && (
            <div className="empty">No maintenance windows declared. Planned work currently pages like an outage.</div>
          )}
          {!loadErr && items !== null && items.length > 0 && (
            <DataTable<MaintenanceWindow>
              rows={items}
              columns={columns}
              rowKey={(w) => w.id}
              height="52vh"
              ariaLabel="Maintenance windows"
              initialSort={{ key: "updated", dir: "desc" }}
            />
          )}
        </div>
      </div>
      {editing && (
        <WindowForm
          initial={editing}
          onSaved={() => { setEditing(null); setNonce((n) => n + 1); }}
          onCancel={() => setEditing(null)}
        />
      )}
    </div>
  );
}
