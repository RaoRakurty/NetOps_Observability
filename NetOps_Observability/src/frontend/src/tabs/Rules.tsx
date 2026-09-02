import { useEffect, useState } from "react";
import { api, Rule } from "../services/api";
import Icon from "../components/Icon";
import DataTable, { type Column } from "../components/DataTable";
import { NocHeader, Chip, LiveChip } from "../components/noc";
import Wizard from "../components/Wizard";
import { Modal } from "../components/ui";
import { operatorError } from "../lib/errors";
const EMPTY: Rule = { name: "", expr: "", for: 300, severity: "warning" };

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [draft, setDraft] = useState<Rule>(EMPTY);
  const [showAdd, setShowAdd] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  // Without this the load's rejection was unhandled and the list stayed [] —
  // rendering "No rules configured", i.e. a fetch failure reported as "nothing is
  // being monitored", the most dangerous possible misreading of this page.
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const load = async () => {
    try {
      setRules((await api.rules()) ?? []);
      setLoadErr(null);
    } catch (e) {
      setLoadErr(operatorError(e, "Monitor rules could not be loaded."));
    }
  };
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
        chips={
          loadErr
            ? <Chip label="Rule list unavailable" tone="var(--crit)" title="The rules API did not answer — the monitor set is unknown." />
            : <><Chip label={`${rules.length} rules`} /><LiveChip detail="live evaluation" /></>
        }
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
          <a href="#/operations/new" style={{ color: "var(--accent)", fontWeight: 600 }}>New Monitor</a> — and only those can be deleted.
        </p>
        {loadErr && rules.length === 0 ? (
          <div className="empty" role="alert" style={{ color: "var(--bad)" }}>
            <strong>The monitor list could not be loaded.</strong>
            <div style={{ marginTop: 4 }}>{loadErr}</div>
            <div style={{ marginTop: 4, color: "var(--muted)" }}>
              This does NOT mean no rules are configured — evaluation may be running normally.
            </div>
          </div>
        ) : rules.length === 0 ? (
          <div className="empty">No rules configured.</div>
        ) : (
          <DataTable<Rule>
            rows={rules}
            rowKey={(r) => r.name}
            initialSort={{ key: "name", dir: "asc" }}
            columns={ruleColumns(remove)}
          />
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

// Column set for the rules DataTable (item 5, 2026-08-25): the raw <table>
// neither sorted nor matched the site's listing idiom. Delete stays scoped to
// custom monitors — built-ins ship with the platform.
function ruleColumns(remove: (name: string) => void): Column<Rule>[] {
  return [
    { key: "name", header: "Name", sortable: true, width: "26%", text: (r) => r.name, render: (r) => <strong>{r.name}</strong> },
    {
      key: "source", header: "Source", sortable: true, width: 110,
      sortValue: (r) => (r.labels?.origin === "ui" ? 0 : 1), text: (r) => (r.labels?.origin === "ui" ? "custom" : "built-in"),
      render: (r) => <span className={`badge ${r.labels?.origin === "ui" ? "accent-badge" : ""}`}>{r.labels?.origin === "ui" ? "custom" : "built-in"}</span>,
    },
    { key: "severity", header: "Severity", sortable: true, width: 110, text: (r) => r.severity, render: (r) => r.severity },
    { key: "expr", header: "Expression", text: (r) => r.expr, render: (r) => <code>{r.expr}</code> },
    { key: "for", header: "For", sortable: true, width: 80, align: "right", sortValue: (r) => Number(r.for) || 0, text: (r) => `${r.for}s`, render: (r) => `${r.for}s` },
    {
      key: "actions", header: "", width: 90, align: "right",
      render: (r) => r.labels?.origin === "ui" ? (
        <button className="btn-ghost" style={{ fontSize: 11, padding: "2px 8px", color: "var(--bad)" }}
          title="Delete this monitor" onClick={() => remove(r.name)}>
          Delete
        </button>
      ) : null,
    },
  ];
}
