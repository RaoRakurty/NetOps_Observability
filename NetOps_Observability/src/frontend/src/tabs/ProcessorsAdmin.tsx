import { useCallback, useEffect, useMemo, useState } from "react";
import { fmtDateTime } from "../lib/time";
import {
  api, ProcessorLane, ProcessorMatch, ProcessorRule, ProcessorRuleInput, ProcessorRuleType,
} from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { Chip } from "../components/noc";

// Pipeline Processors (item 121): the per-tenant processor editor. Structured
// redact / drop-field / set-field rules — never free-form VRL or regex — that
// the API compiles into the ingest router's config with a tenant guard around
// every action. Changes hot-apply to the pipeline (no restart); the Preview
// panel dry-runs the caller's rules against a pasted sample event server-side
// (the incident-policy simulator pattern).
//
// Honest limitation shown in the page copy: rules shape what is STORED
// (OpenSearch / ClickHouse). The correlation engine consumes the bus before
// this hook, so derived correlation signals are not shaped in v1.

const LANES: ProcessorLane[] = ["applogs", "syslog", "snmptrap", "cloudlogs", "flows"];
const TYPES: { v: ProcessorRuleType; label: string; hint: string }[] = [
  { v: "redact_pattern", label: "Redact pattern", hint: "Replace matches inside a field with ***" },
  { v: "redact_field", label: "Redact field", hint: "Replace the whole field value with ***" },
  { v: "drop_field", label: "Drop field", hint: "Delete the field before storage" },
  { v: "set_field", label: "Set field", hint: "Set the field to a fixed value" },
];
const BUILTINS = ["email", "ipv4", "mac"];

const fmt = (iso?: string) => (iso ? fmtDateTime(iso) : "—");

type FormState = {
  lane: ProcessorLane;
  type: ProcessorRuleType;
  field: string;
  pattern_kind: "builtin" | "literal";
  pattern: string;
  value: string;
  useMatch: boolean;
  match: ProcessorMatch;
  description: string;
  enabled: boolean;
};

const EMPTY_FORM: FormState = {
  lane: "syslog", type: "redact_pattern", field: "message",
  pattern_kind: "builtin", pattern: "email", value: "",
  useMatch: false, match: { field: "", op: "equals", value: "" },
  description: "", enabled: true,
};

function toInput(f: FormState): ProcessorRuleInput {
  const out: ProcessorRuleInput = {
    lane: f.lane, type: f.type, field: f.field.trim(),
    description: f.description.trim() || undefined, enabled: f.enabled,
  };
  if (f.type === "redact_pattern") {
    out.pattern_kind = f.pattern_kind;
    out.pattern = f.pattern.trim();
  }
  if (f.type === "set_field") out.value = f.value;
  if (f.useMatch && f.match.field.trim()) {
    out.match = { field: f.match.field.trim(), op: f.match.op, value: f.match.value };
  }
  return out;
}

function fromRule(r: ProcessorRule): FormState {
  return {
    lane: r.lane, type: r.type, field: r.field,
    pattern_kind: r.pattern_kind ?? "builtin", pattern: r.pattern ?? "email",
    value: r.value ?? "",
    useMatch: !!r.match, match: r.match ?? { field: "", op: "equals", value: "" },
    description: r.description ?? "", enabled: r.enabled,
  };
}

const ruleSummary = (r: ProcessorRule) => {
  switch (r.type) {
    case "redact_pattern":
      return `redact ${r.pattern_kind === "builtin" ? r.pattern : `"${r.pattern}"`} in .${r.field}`;
    case "redact_field": return `redact .${r.field}`;
    case "drop_field": return `drop .${r.field}`;
    case "set_field": return `set .${r.field} = "${r.value ?? ""}"`;
    default: return r.type;
  }
};

function RuleForm({ initial, onSaved, onCancel }: {
  initial: { id?: string; form: FormState };
  onSaved: () => void;
  onCancel: () => void;
}) {
  const [f, setF] = useState<FormState>(initial.form);
  const [err, setErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setF((p) => ({ ...p, [k]: v }));

  const save = async () => {
    if (!f.field.trim()) { setErr("A target field is required."); return; }
    if (f.type === "redact_pattern" && f.pattern_kind === "literal" && !f.pattern.trim()) {
      setErr("A literal pattern must not be empty."); return;
    }
    setSaving(true);
    try {
      if (initial.id) await api.processorRuleUpdate(initial.id, toInput(f));
      else await api.processorRuleCreate(toInput(f));
      onSaved();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="cc-panel" style={{ marginTop: 12 }}>
      <div className="cc-panel-h">
        <h3 className="cc-panel-t">{initial.id ? "Edit processor rule" : "New processor rule"}</h3>
      </div>
      <div style={{ padding: "11px 13px", display: "grid", gap: 10 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
          <label className="ccw-field">
            <span className="ccw-label">Lane</span>
            <select className="app-select" value={f.lane} onChange={(e) => set("lane", e.target.value as ProcessorLane)}>
              {LANES.map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
          </label>
          <label className="ccw-field">
            <span className="ccw-label">Action</span>
            <select className="app-select" value={f.type} onChange={(e) => set("type", e.target.value as ProcessorRuleType)}>
              {TYPES.map((t) => <option key={t.v} value={t.v} title={t.hint}>{t.label}</option>)}
            </select>
          </label>
          <label className="ccw-field">
            <span className="ccw-label">Target field <span className="ccw-req">*</span></span>
            <input className="ccw-input" value={f.field} onChange={(e) => set("field", e.target.value)}
              placeholder="message · nested.field" />
          </label>
        </div>

        {f.type === "redact_pattern" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 10 }}>
            <label className="ccw-field">
              <span className="ccw-label">Pattern kind</span>
              <select className="app-select" value={f.pattern_kind}
                onChange={(e) => set("pattern_kind", e.target.value as "builtin" | "literal")}>
                <option value="builtin">Built-in pattern</option>
                <option value="literal">Literal text</option>
              </select>
            </label>
            {f.pattern_kind === "builtin" ? (
              <label className="ccw-field">
                <span className="ccw-label">Built-in</span>
                <select className="app-select" value={f.pattern} onChange={(e) => set("pattern", e.target.value)}>
                  {BUILTINS.map((b) => <option key={b} value={b}>{b}</option>)}
                </select>
              </label>
            ) : (
              <label className="ccw-field">
                <span className="ccw-label">Literal text <span className="ccw-req">*</span></span>
                <input className="ccw-input" value={f.pattern} onChange={(e) => set("pattern", e.target.value)}
                  placeholder="exact text to replace with ***" maxLength={256} />
              </label>
            )}
          </div>
        )}
        {f.type === "set_field" && (
          <label className="ccw-field">
            <span className="ccw-label">Value</span>
            <input className="ccw-input" value={f.value} onChange={(e) => set("value", e.target.value)} maxLength={256} />
          </label>
        )}

        <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
          <label style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={f.useMatch} onChange={(e) => set("useMatch", e.target.checked)} />
            Only when a field matches…
          </label>
          <label style={{ display: "inline-flex", gap: 6, alignItems: "center", marginLeft: "auto" }}>
            <input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />
            Enabled
          </label>
        </div>
        {f.useMatch && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
            <label className="ccw-field">
              <span className="ccw-label">Match field</span>
              <input className="ccw-input" value={f.match.field}
                onChange={(e) => set("match", { ...f.match, field: e.target.value })} placeholder="vendor" />
            </label>
            <label className="ccw-field">
              <span className="ccw-label">Operator</span>
              <select className="app-select" value={f.match.op}
                onChange={(e) => set("match", { ...f.match, op: e.target.value as ProcessorMatch["op"] })}>
                <option value="equals">equals</option>
                <option value="contains">contains</option>
                <option value="prefix">starts with</option>
              </select>
            </label>
            <label className="ccw-field">
              <span className="ccw-label">Value</span>
              <input className="ccw-input" value={f.match.value}
                onChange={(e) => set("match", { ...f.match, value: e.target.value })} maxLength={256} />
            </label>
          </div>
        )}

        <label className="ccw-field">
          <span className="ccw-label">Description</span>
          <input className="ccw-input" value={f.description} onChange={(e) => set("description", e.target.value)}
            placeholder="Why this rule exists (shown in the list)" maxLength={256} />
        </label>

        {err && <div role="alert" style={{ color: "var(--bad)" }}>{err}</div>}
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-primary" onClick={save} disabled={saving}>
            {saving ? "Saving…" : initial.id ? "Save changes" : "Create rule"}
          </button>
          <button className="btn" onClick={onCancel} disabled={saving}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

const SAMPLE_EVENT = `{
  "message": "login failure for jsmith@example.org from 10.1.2.3",
  "vendor": "fortinet",
  "severity": "warning"
}`;

function PreviewPanel() {
  const [lane, setLane] = useState<ProcessorLane>("syslog");
  const [sample, setSample] = useState(SAMPLE_EVENT);
  const [result, setResult] = useState<string | null>(null);
  const [applied, setApplied] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const run = async () => {
    setErr(null);
    let ev: Record<string, unknown>;
    try {
      ev = JSON.parse(sample) as Record<string, unknown>;
    } catch {
      setErr("The sample event must be valid JSON.");
      return;
    }
    try {
      const r = await api.processorPreview(lane, ev);
      setResult(JSON.stringify(r.event, null, 2));
      setApplied(r.applied.map((a) => `${a.type} .${a.field}${a.description ? ` — ${a.description}` : ""}`));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="cc-panel" style={{ marginTop: 12 }}>
      <div className="cc-panel-h">
        <h3 className="cc-panel-t">Preview</h3>
        <span className="cc-panel-meta">dry-run your rules against a sample event — nothing is stored</span>
      </div>
      <div style={{ padding: "11px 13px", display: "grid", gap: 10 }}>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <label className="ccw-field" style={{ minWidth: 160 }}>
            <span className="ccw-label">Lane</span>
            <select className="app-select" value={lane} onChange={(e) => setLane(e.target.value as ProcessorLane)}>
              {LANES.map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
          </label>
          <button className="btn btn-primary" style={{ alignSelf: "end" }} onClick={() => void run()}>
            Run preview
          </button>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <label className="ccw-field">
            <span className="ccw-label">Sample event (JSON)</span>
            <textarea className="ccw-input" rows={8} value={sample} onChange={(e) => setSample(e.target.value)}
              style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }} />
          </label>
          <label className="ccw-field">
            <span className="ccw-label">After your rules</span>
            <textarea className="ccw-input" rows={8} value={result ?? ""} readOnly
              placeholder="Run the preview to see the shaped event"
              style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }} />
          </label>
        </div>
        {applied.length > 0 && (
          <div className="ccw-hint">Applied: {applied.join(" · ")}</div>
        )}
        {err && <div role="alert" style={{ color: "var(--bad)" }}>{err}</div>}
      </div>
    </div>
  );
}

export default function ProcessorsAdmin() {
  const [items, setItems] = useState<ProcessorRule[] | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ id?: string; form: FormState } | null>(null);
  const [nonce, setNonce] = useState(0);

  const load = useCallback(async () => {
    try {
      const r = await api.processorRules();
      setItems(r.rules ?? []);
      setLoadErr(null);
    } catch (e) {
      setLoadErr(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => { void load(); }, [load, nonce]);

  const remove = async (r: ProcessorRule) => {
    if (!window.confirm(`Delete rule "${ruleSummary(r)}"? Ingested data stops being shaped by it immediately.`)) return;
    try {
      await api.processorRuleDelete(r.id);
      setNonce((n) => n + 1);
    } catch (e) {
      setLoadErr(e instanceof Error ? e.message : String(e));
    }
  };

  const columns = useMemo<Column<ProcessorRule>[]>(() => [
    { key: "lane", header: "Lane", width: 100, sortable: true, text: (r) => r.lane,
      render: (r) => <span className="badge">{r.lane}</span> },
    { key: "rule", header: "Rule", width: "34%", text: ruleSummary,
      render: (r) => (
        <span title={r.description || ruleSummary(r)}
          style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>
          {ruleSummary(r)}
        </span>
      ) },
    { key: "match", header: "Condition", width: "18%",
      text: (r) => (r.match ? `${r.match.field} ${r.match.op} ${r.match.value}` : ""),
      render: (r) => r.match
        ? <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{`.${r.match.field} ${r.match.op} "${r.match.value}"`}</span>
        : <span style={{ color: "var(--fg-subtle)" }}>always</span> },
    { key: "status", header: "Status", width: 110, sortable: true,
      text: (r) => (r.enabled ? "enabled" : "disabled"),
      render: (r) => (r.enabled
        ? <Chip label="Enabled" tone="var(--ok)" />
        : <Chip label="Disabled" tone="var(--fg-subtle)" />) },
    { key: "updated", header: "Updated", width: 156, sortable: true,
      sortValue: (r) => Date.parse(r.updated_at) || 0, render: (r) => fmt(r.updated_at) },
    { key: "actions", header: "", width: 130,
      render: (r) => (
        <span style={{ display: "inline-flex", gap: 6 }}>
          <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); setEditing({ id: r.id, form: fromRule(r) }); }}>
            Edit
          </button>
          <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); void remove(r); }}>
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
          <h3 className="cc-panel-t">Pipeline processors</h3>
          <span className="cc-panel-meta" style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
            {loadErr ? "unavailable" : `${items?.length ?? 0} rule${(items?.length ?? 0) === 1 ? "" : "s"}`}
            <button className="btn btn-sm btn-primary" onClick={() => setEditing({ form: EMPTY_FORM })}>
              New rule
            </button>
          </span>
        </div>
        <div style={{ padding: "11px 13px" }}>
          <div className="ccw-hint" style={{ marginBottom: 8 }}>
            Rules shape your tenant's telemetry <strong>before it is stored</strong> — redact sensitive values,
            drop fields, or normalize vendor quirks. Changes apply to the live pipeline within about a minute,
            with no restart. Rules affect stored logs and flows; correlation signals derived on the bus are not
            shaped in this version.
          </div>
          {loadErr && (
            <div className="empty" role="alert" style={{ color: "var(--bad)" }}>
              <strong>Processor rules could not be loaded.</strong>
              <div style={{ marginTop: 4 }}>{loadErr}</div>
            </div>
          )}
          {!loadErr && items !== null && items.length === 0 && (
            <div className="empty">No processor rules yet. Telemetry is stored exactly as it arrives.</div>
          )}
          {!loadErr && items !== null && items.length > 0 && (
            <DataTable<ProcessorRule>
              rows={items}
              columns={columns}
              rowKey={(r) => r.id}
              height="44vh"
              ariaLabel="Processor rules"
              initialSort={{ key: "updated", dir: "desc" }}
            />
          )}
        </div>
      </div>
      {editing && (
        <RuleForm
          initial={editing}
          onSaved={() => { setEditing(null); setNonce((n) => n + 1); }}
          onCancel={() => setEditing(null)}
        />
      )}
      <PreviewPanel />
    </div>
  );
}
