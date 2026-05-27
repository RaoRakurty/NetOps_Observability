import { useEffect, useState } from "react";
import { api, Rule } from "../services/api";

const EMPTY: Rule = { name: "", expr: "", for: 300, severity: "warning" };

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [draft, setDraft] = useState<Rule>(EMPTY);
  const [busy, setBusy] = useState(false);

  const load = async () => setRules((await api.rules()) ?? []);
  useEffect(() => {
    load();
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!draft.name || !draft.expr) return;
    setBusy(true);
    try {
      await api.addRule(draft);
      setDraft(EMPTY);
      await load();
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="card">
        <h2>Add rule</h2>
        <form onSubmit={submit} style={{ display: "grid", gap: 8 }}>
          <input
            placeholder="name (e.g. HighCPU)"
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          />
          <input
            placeholder="expr (e.g. cpu_usage > 90)"
            value={draft.expr}
            onChange={(e) => setDraft({ ...draft, expr: e.target.value })}
          />
          <select
            value={draft.severity}
            onChange={(e) => setDraft({ ...draft, severity: e.target.value })}
          >
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </select>
          <button disabled={busy} type="submit">
            {busy ? "Saving…" : "Save rule"}
          </button>
        </form>
      </div>

      <div className="card">
        <h2>Rules ({rules.length})</h2>
        {rules.length === 0 ? (
          <div className="empty">No rules configured.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Severity</th>
                <th>Expression</th>
                <th>For</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.name}>
                  <td>{r.name}</td>
                  <td>{r.severity}</td>
                  <td>
                    <code>{r.expr}</code>
                  </td>
                  <td>{r.for}s</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
