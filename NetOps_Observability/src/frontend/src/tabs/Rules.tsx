import { useEffect, useState } from "react";
import { api, Rule } from "../services/api";
import Icon from "../components/Icon";
import { NocHeader, Chip, LiveChip } from "../components/noc";
import Wizard from "../components/Wizard";
import { Modal } from "../components/ui";

const EMPTY: Rule = { name: "", expr: "", for: 300, severity: "warning" };

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [draft, setDraft] = useState<Rule>(EMPTY);
  const [showAdd, setShowAdd] = useState(false);
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

  const openAdd = () => {
    setDraft(EMPTY);
    setMsg(null);
    setShowAdd(true);
  };

  // Wizard onFinish: persist the rule. Throwing surfaces the error inline in the
  // wizard (it catches + displays); success closes the window and refreshes.
  const submit = async () => {
    const name = draft.name.trim();
    setBusy(true);
    try {
      await api.addRule(draft);
      setShowAdd(false);
      setDraft(EMPTY);
      await load();
      setMsg({ kind: "ok", text: `Saved monitor “${name}”.` });
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
      {msg && (
        <p className={`form-msg ${msg.kind}`} role={msg.kind === "err" ? "alert" : "status"} aria-live="polite" style={{ margin: "0 2px" }}>
          {msg.kind === "ok" && <Icon name="check" size={14} />} {msg.text}
        </p>
      )}

      <div className="card">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
          <h2 style={{ margin: 0 }}>Rules ({rules.length})</h2>
          <button className="btn-accent" onClick={openAdd}>
            <Icon name="alerts" size={14} /> Add rule
          </button>
        </div>
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

      {showAdd && (
        <Modal title="Add rule" subtitle="Define an alerting condition over your telemetry" onClose={() => setShowAdd(false)}>
          <Wizard
            finishLabel={busy ? "Saving…" : "Save rule"}
            onCancel={() => setShowAdd(false)}
            onFinish={submit}
            steps={[
              {
                id: "define",
                title: "Define",
                hint: "Name the monitor and set how loud it should be.",
                isValid: () => draft.name.trim() !== "",
                render: () => (
                  <div className="form-grid">
                    <div className="form-field wide">
                      <label className="form-label" htmlFor="rule-name">Name<span className="form-req">*</span></label>
                      <input id="rule-name" className="form-input" placeholder="e.g. HighCPU" autoFocus
                        value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
                      <span className="form-hint">A unique identifier for the rule.</span>
                    </div>
                    <div className="form-field">
                      <label className="form-label" htmlFor="rule-severity">Severity</label>
                      <select id="rule-severity" className="form-select" value={draft.severity}
                        onChange={(e) => setDraft({ ...draft, severity: e.target.value })}>
                        <option value="info">info</option>
                        <option value="warning">warning</option>
                        <option value="critical">critical</option>
                      </select>
                    </div>
                  </div>
                ),
              },
              {
                id: "condition",
                title: "Condition",
                hint: "Write the expression and how long it must hold before firing.",
                isValid: () => draft.expr.trim() !== "",
                render: () => (
                  <div className="form-grid">
                    <div className="form-field wide">
                      <label className="form-label" htmlFor="rule-expr">Expression<span className="form-req">*</span></label>
                      <input id="rule-expr" className="form-input mono" placeholder="e.g. device_cpu_percent > 90"
                        value={draft.expr} onChange={(e) => setDraft({ ...draft, expr: e.target.value })} />
                      <span className="form-hint">Metric query or z-score condition, evaluated against the metric store.</span>
                    </div>
                    <div className="form-field">
                      <label className="form-label" htmlFor="rule-for">Must hold for</label>
                      <div className="form-suffix-wrap">
                        <input id="rule-for" className="form-input" type="number" min={0}
                          value={draft.for} onChange={(e) => setDraft({ ...draft, for: Number(e.target.value) || 0 })} />
                        <span className="form-suffix">seconds</span>
                      </div>
                      <span className="form-hint">0 fires on the first matching evaluation (every 30s).</span>
                    </div>
                  </div>
                ),
              },
            ]}
          />
        </Modal>
      )}
    </div>
  );
}
