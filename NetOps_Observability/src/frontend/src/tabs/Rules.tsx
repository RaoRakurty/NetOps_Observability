import { useEffect, useState } from "react";
import { api, Rule } from "../services/api";
import Icon from "../components/Icon";
import { NocHeader, Chip, LiveChip } from "../components/noc";

const EMPTY: Rule = { name: "", expr: "", for: 300, severity: "warning" };

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [draft, setDraft] = useState<Rule>(EMPTY);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const load = async () => setRules((await api.rules()) ?? []);
  useEffect(() => {
    load();
  }, []);

  const remove = async (name: string) => {
    if (!window.confirm(`Delete monitor "${name}"? Its active alerts resolve on the next evaluation.`)) return;
    setMsg(null);
    try {
      await api.deleteRule(name);
      await load();
      setMsg({ kind: "ok", text: `Deleted ${name}.` });
    } catch (err) {
      setMsg({ kind: "err", text: (err as Error).message });
    }
  };

  const valid = draft.name.trim() !== "" && draft.expr.trim() !== "";

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    if (!valid) return;
    setBusy(true);
    try {
      await api.addRule(draft);
      setDraft(EMPTY);
      await load();
      setMsg({ kind: "ok", text: "Rule saved." });
    } catch (err) {
      setMsg({ kind: "err", text: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="dm-board cc-board">
      <NocHeader
        title="Monitor Rules"
        subtitle="Define alert conditions, review built-in rules, and manage custom monitors over your telemetry."
        chips={<><Chip label={`${rules.length} rules`} /><LiveChip detail="live evaluation" /></>}
      />
      <div className="card form-card">
        <div className="form-head">
          <span className="form-head-icon"><Icon name="alerts" size={18} /></span>
          <div>
            <h2>Add rule</h2>
            <p className="form-sub">Define an alerting condition over your metrics; it fires when the expression holds for the duration below.</p>
          </div>
        </div>

        <form onSubmit={submit} className="form-grid">
          <div className="form-field wide">
            <label className="form-label" htmlFor="rule-name">Name<span className="form-req">*</span></label>
            <input
              id="rule-name"
              className="form-input"
              placeholder="e.g. HighCPU"
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            />
            <span className="form-hint">A unique identifier for the rule.</span>
          </div>

          <div className="form-field wide">
            <label className="form-label" htmlFor="rule-expr">Expression<span className="form-req">*</span></label>
            <input
              id="rule-expr"
              className="form-input mono"
              placeholder="e.g. cpu_usage > 90"
              value={draft.expr}
              onChange={(e) => setDraft({ ...draft, expr: e.target.value })}
            />
            <span className="form-hint">PromQL / z-score condition evaluated against the metric store.</span>
          </div>

          <div className="form-field">
            <label className="form-label" htmlFor="rule-severity">Severity</label>
            <select
              id="rule-severity"
              className="form-select"
              value={draft.severity}
              onChange={(e) => setDraft({ ...draft, severity: e.target.value })}
            >
              <option value="info">info</option>
              <option value="warning">warning</option>
              <option value="critical">critical</option>
            </select>
          </div>

          <div className="form-field">
            <label className="form-label" htmlFor="rule-for">For</label>
            <div className="form-suffix-wrap">
              <input
                id="rule-for"
                className="form-input"
                type="number"
                min={0}
                value={draft.for}
                onChange={(e) => setDraft({ ...draft, for: Number(e.target.value) || 0 })}
              />
              <span className="form-suffix">seconds</span>
            </div>
            <span className="form-hint">How long the condition must hold before firing.</span>
          </div>

          <div className="form-actions">
            <button className="btn-accent" disabled={!valid || busy} type="submit">
              {busy ? "Saving…" : "Save rule"}
            </button>
            {msg && (
              <p className={`form-msg ${msg.kind}`} role={msg.kind === "err" ? "alert" : "status"} aria-live="polite">
                {msg.kind === "ok" && <Icon name="check" size={14} />} {msg.text}
              </p>
            )}
          </div>
        </form>
      </div>

      <div className="card">
        <h2>Rules ({rules.length})</h2>
        <p className="mini-meta" style={{ marginTop: -6 }}>
          Built-in rules ship with the platform (rules file); custom monitors are yours — created here or via{" "}
          <a href="#/monitoring/new" style={{ color: "var(--accent)", fontWeight: 600 }}>New Monitor</a> — and only those can be deleted.
        </p>
        {rules.length === 0 ? (
          <div className="empty">No rules configured.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Source</th>
                <th>Severity</th>
                <th>Expression</th>
                <th>For</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => {
                const custom = r.labels?.origin === "ui";
                return (
                  <tr key={r.name}>
                    <td>{r.name}</td>
                    <td><span className={`badge ${custom ? "accent-badge" : ""}`}>{custom ? "custom" : "built-in"}</span></td>
                    <td>{r.severity}</td>
                    <td>
                      <code>{r.expr}</code>
                    </td>
                    <td>{r.for}s</td>
                    <td>
                      {custom && (
                        <button
                          className="btn-ghost"
                          style={{ fontSize: 11, padding: "2px 8px", color: "var(--bad)" }}
                          title="Delete this monitor"
                          onClick={() => remove(r.name)}
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
