// MonitorsSettings — the cloud monitor authoring card (Wave 5 #14 slice 3),
// following the Wave 4 #11 Settings-card pattern (GovernanceSettings): load →
// list → inline create/toggle/delete, every failure shown, no fake saves.
// Each row shows the evaluator's LAST verdict verbatim — "never evaluated" and
// "no data" are their own states, never rendered as ok.

import { useEffect, useState } from "react";
import { api } from "../../services/api";
import type { CloudMonitorRow } from "../../services/api";
import { Chip } from "../../components/noc";
import { EmptyState, ago } from "./badges";
import { CLOUD_METRIC_FALLBACK } from "./metricsPanel";
import {
  EMPTY_MONITOR_DRAFT, describeMonitor, draftToInput, monitorStateLabel,
  monitorStateTone, rowToInput, validateMonitorDraft,
} from "./monitors";
import type { MonitorDraft } from "./monitors";

export default function MonitorsSettings() {
  const [rows, setRows] = useState<CloudMonitorRow[]>([]);
  const [maxMonitors, setMaxMonitors] = useState(50);
  const [busy, setBusy] = useState(true);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState<MonitorDraft>(EMPTY_MONITOR_DRAFT);

  const reload = () => api.cloudMonitors().then((r) => {
    setRows(r.monitors); setMaxMonitors(r.max_monitors);
  });

  useEffect(() => {
    reload().catch((e) => setErr((e as Error).message)).finally(() => setBusy(false));
  }, []);

  const run = async (call: () => Promise<unknown>): Promise<boolean> => {
    setErr(""); setSaving(true);
    try {
      await call();
      await reload();
      return true;
    } catch (e) {
      const msg = (e as Error).message;
      setErr(/403|forbidden/i.test(msg) ? "changing monitors requires alerts write access" : msg);
      return false;
    } finally {
      setSaving(false);
    }
  };

  const create = async () => {
    const v = validateMonitorDraft(draft);
    if (v) { setErr(v); return; }
    // The form only closes on a REAL save — a refused create keeps the input.
    if (await run(() => api.createCloudMonitor(draftToInput(draft)))) {
      setDraft(EMPTY_MONITOR_DRAFT); setAdding(false);
    }
  };

  const set = <K extends keyof MonitorDraft>(k: K, v: MonitorDraft[K]) =>
    setDraft((d) => ({ ...d, [k]: v }));

  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Cloud monitors
        <span className="ao-panel-meta">threshold / anomaly rules on the cloud metric lane · evaluated every minute</span>
      </div>
      <p className="ao-set-d">
        A monitor watches one cloud metric across your inventory (or one resource)
        and notifies on the configured contact points when it fires.
        {/* role=alert announces the failure; the wording (not only the color)
            identifies it as an error (3.3.1/1.4.1). */}
        {err && <span role="alert" style={{ color: "var(--crit)" }}> · Error: {err}</span>}
      </p>

      {busy ? <div className="ao-muted" role="status">Loading…</div> : (
        <>
          {rows.length === 0 && !adding && (
            <EmptyState title="No cloud monitors defined"
              hint="Create one below — it evaluates against the metrics your connected cloud accounts actually ingest; a metric with no samples reads 'no data', never 'ok'." />
          )}

          {rows.length > 0 && (
            <ul className="ao-mon-list">
              {rows.map((r) => (
                <li key={r.id} className="ao-mon-row">
                  <div className="ao-mon-main">
                    <strong>{r.name}</strong>{" "}
                    <Chip label={monitorStateLabel(r.last_state)} tone={monitorStateTone(r.last_state)} />
                    <div className="ao-set-d" style={{ margin: 0 }}>{describeMonitor(r)}</div>
                    {r.last_reason && (
                      <div className="ao-muted ao-mon-reason">
                        {r.last_reason}{r.last_eval_at ? ` · evaluated ${ago(r.last_eval_at)}` : ""}
                      </div>
                    )}
                    {!r.last_reason && r.last_state === "never_evaluated" && (
                      <div className="ao-muted ao-mon-reason">no evaluation has run yet</div>
                    )}
                  </div>
                  <div className="ao-mon-actions">
                    <button className="ao-btn" disabled={saving}
                      onClick={() => run(() => api.updateCloudMonitor(r.id, rowToInput(r, !r.enabled)))}>
                      {r.enabled ? "Disable" : "Enable"}
                    </button>
                    <button className="ao-btn" disabled={saving}
                      onClick={() => run(() => api.deleteCloudMonitor(r.id))}>
                      Delete
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}

          {!adding ? (
            <button className="ao-btn ao-btn--primary" disabled={rows.length >= maxMonitors}
              onClick={() => setAdding(true)}>
              New monitor
            </button>
          ) : (
            <div className="ao-mon-form">
              <input className="ao-input" placeholder="Monitor name" aria-label="Monitor name"
                value={draft.name} onChange={(e) => set("name", e.target.value)} />
              <select className="app-select" aria-label="Metric" value={draft.metric}
                onChange={(e) => set("metric", e.target.value)}>
                {CLOUD_METRIC_FALLBACK.map((m) => <option key={m.name} value={m.name}>{m.label}</option>)}
              </select>
              <select className="app-select" aria-label="Mode" value={draft.mode}
                onChange={(e) => set("mode", e.target.value as MonitorDraft["mode"])}>
                <option value="threshold">threshold</option>
                <option value="anomaly">anomaly</option>
              </select>
              {draft.mode === "threshold" && (
                <>
                  <select className="app-select" aria-label="Condition" value={draft.condition}
                    onChange={(e) => set("condition", e.target.value as MonitorDraft["condition"])}>
                    <option value="above">above</option>
                    <option value="below">below</option>
                  </select>
                  <input className="ao-input" style={{ width: 110 }} placeholder="threshold"
                    aria-label="Threshold" value={draft.threshold}
                    onChange={(e) => set("threshold", e.target.value)} />
                </>
              )}
              <input className="ao-input" placeholder="resource id (optional — blank = all)"
                aria-label="Resource id" value={draft.resourceId}
                onChange={(e) => set("resourceId", e.target.value)} />
              <button className="ao-btn ao-btn--primary" disabled={saving} aria-busy={saving} onClick={create}>
                {saving ? "Saving…" : "Create"}
              </button>
              <button className="ao-btn" disabled={saving}
                onClick={() => { setAdding(false); setErr(""); }}>Cancel</button>
            </div>
          )}
          {rows.length >= maxMonitors && (
            <p className="ao-set-d">Limit reached — at most {maxMonitors} monitors per tenant.</p>
          )}
        </>
      )}
    </div>
  );
}
