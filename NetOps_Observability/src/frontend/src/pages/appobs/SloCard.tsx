// SloCard — target vs actual vs budget remaining for one app (Wave 5 #14
// slice 2). Actuals are MEASURED from the provider status-check lane; an SLO
// whose data is absent says "not measurable" with the exact reason — never a
// green 100%. Editing follows the Settings-card pattern (GovernanceSettings):
// inline save, 403 shown honestly, tenant stamped server-side.

import { useEffect, useState } from "react";
import { api } from "../../services/api";
import type { CloudSloResponse } from "../../services/api";
import { MetricCard } from "./badges";
import { budgetTone, fmtSloPct, removeSlo, sloForApp, upsertSlo, validateSloTarget } from "./slo";

const WINDOW_CHOICES = [7, 14, 30];

export default function SloCard({ appName }: { appName: string }) {
  const [resp, setResp] = useState<CloudSloResponse | null>(null);
  const [busy, setBusy] = useState(true);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string>("");
  const [editing, setEditing] = useState(false);
  const [target, setTarget] = useState("99.9");
  const [windowDays, setWindowDays] = useState(30);

  useEffect(() => {
    let live = true;
    api.cloudSlos()
      .then((r) => { if (live) setResp(r); })
      .catch((e) => { if (live) setErr((e as Error).message); })
      .finally(() => { if (live) setBusy(false); });
    return () => { live = false; };
  }, [appName]);

  const slo = sloForApp(resp, appName);

  const persist = async (defs: Parameters<typeof api.setCloudSlos>[0]) => {
    setErr(""); setSaving(true);
    try {
      // Removing the last objective = an empty list, which the API expresses
      // as an explicit reset (it refuses an empty slos array by design).
      const r = defs.length === 0 ? await api.resetCloudSlos() : await api.setCloudSlos(defs);
      setResp(r);
      setEditing(false);
    } catch (e) {
      const msg = (e as Error).message;
      setErr(/403|forbidden/i.test(msg) ? "saving an SLO requires an administrator" : msg);
    } finally {
      setSaving(false);
    }
  };

  const save = () => {
    const v = validateSloTarget(target);
    if (v) { setErr(v); return; }
    persist(upsertSlo(resp?.slos ?? [], appName, Number(target), windowDays));
  };

  if (busy) return <div className="ao-panel"><div className="ao-panel-h">SLO</div><div className="ao-muted">Loading…</div></div>;

  return (
    <div className="ao-panel">
      <div className="ao-panel-h">SLO / error budget
        <span className="ao-panel-meta">availability from provider status checks · measured, never assumed</span>
      </div>
      {err && <p className="ao-set-d" style={{ color: "var(--crit)" }}>{err}</p>}

      {!slo && !editing && (
        <p className="ao-set-d">
          No SLO defined for {appName}.{" "}
          <button className="ao-link" onClick={() => setEditing(true)}>Set a target</button>
        </p>
      )}

      {slo && !editing && (
        <>
          <div className="ao-cards">
            <MetricCard label="Target" value={fmtSloPct(slo.target_pct)} sub={`over ${slo.window_days}d`} />
            <MetricCard label="Actual"
              value={slo.status?.measurable ? fmtSloPct(slo.status.actual_pct) : <span className="ao-muted">—</span>}
              sub={slo.status?.measurable
                ? `${slo.status.resources_reporting} of ${slo.status.resources_total} resources reporting`
                : "not measurable"}
              tone={budgetTone(slo.status)} />
            <MetricCard label="Budget remaining"
              value={slo.status?.measurable ? fmtSloPct(slo.status.budget_remaining_pct) : <span className="ao-muted">—</span>}
              sub={slo.status?.measurable
                ? `burn ${((slo.status.burn_ratio ?? 0) * 100).toFixed(0)}% of ${fmtSloPct(slo.status.budget_pct)} budget`
                : "not measurable"}
              tone={budgetTone(slo.status)} />
          </div>
          <p className="ao-set-d">{slo.status?.basis ?? ""}</p>
          <div>
            <button className="ao-btn" onClick={() => {
              setTarget(String(slo.target_pct)); setWindowDays(slo.window_days); setEditing(true);
            }}>Edit</button>{" "}
            <button className="ao-btn" disabled={saving}
              onClick={() => persist(removeSlo(resp?.slos ?? [], appName))}>Remove</button>
          </div>
        </>
      )}

      {editing && (
        <div className="ao-metrics-ctl">
          <label className="ao-set-d" htmlFor="slo-target">Target %</label>
          <input id="slo-target" className="ao-input" style={{ width: 90 }} value={target}
            onChange={(e) => setTarget(e.target.value)} aria-label="SLO target percent" />
          <select className="app-select" value={windowDays} aria-label="SLO window"
            onChange={(e) => setWindowDays(Number(e.target.value))}>
            {WINDOW_CHOICES.map((d) => <option key={d} value={d}>{d}d</option>)}
          </select>
          <button className="ao-btn ao-btn--primary" disabled={saving} onClick={save}>
            {saving ? "Saving…" : "Save"}
          </button>
          <button className="ao-btn" disabled={saving} onClick={() => { setEditing(false); setErr(""); }}>Cancel</button>
        </div>
      )}
    </div>
  );
}
