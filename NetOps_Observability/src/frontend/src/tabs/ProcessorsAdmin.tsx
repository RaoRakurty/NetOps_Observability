import { useCallback, useEffect, useMemo, useState } from "react";
import { fmtDateTime } from "../lib/time";
import {
  api, ManagedRule, ProcessorCatalog, ProcessorLane, ProcessorMatch, ProcessorMatchOp,
  ProcessorPreview, ProcessorRule, ProcessorRuleInput, ProcessorRuleType, ProcessorVersion,
} from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { Modal } from "../components/ui";
import { Chip } from "../components/noc";

// Pipeline Processors — the tenant's log-processing chain.
//
// The page renders from the ENGINE's own catalog (/catalog): registered
// actions, matchers and managed rules. A newly-registered plugin therefore
// appears in the wizard with no frontend change — the registries are the
// extension point, and this UI is a view over them, not a second definition.
//
// Honest limitation shown in the page copy: processors shape what is STORED.
// The correlation engine consumes the bus upstream of these hooks, so derived
// correlation signals are not shaped in this version.

const fmt = (iso?: string) => (iso ? fmtDateTime(iso) : "—");

type FormState = {
  name: string;
  lane: ProcessorLane;
  type: ProcessorRuleType;
  field: string;
  pattern_kind: "builtin" | "literal" | "regex";
  pattern: string;
  replacement: string;
  keep_last: string;
  keys: string;
  value: string;
  useMatch: boolean;
  match: ProcessorMatch;
  description: string;
  order: string;
  enabled: boolean;
};

const EMPTY_FORM: FormState = {
  name: "", lane: "syslog", type: "redact_pattern", field: "message",
  pattern_kind: "builtin", pattern: "email", replacement: "", keep_last: "4", keys: "", value: "",
  useMatch: false, match: { field: "", op: "equals", value: "" },
  description: "", order: "10", enabled: true,
};

function toInput(f: FormState): ProcessorRuleInput {
  const out: ProcessorRuleInput = {
    name: f.name.trim() || undefined,
    lane: f.lane, type: f.type,
    field: f.type === "drop_event" ? "" : f.field.trim(),
    description: f.description.trim() || undefined,
    order: Number(f.order) || 0,
    enabled: f.enabled,
  };
  if (f.type === "redact_pattern") {
    out.pattern_kind = f.pattern_kind;
    out.pattern = f.pattern.trim();
  }
  if (f.type === "mask") out.keep_last = Number(f.keep_last) || 4;
  if (f.type === "redact_keys") {
    out.keys = f.keys.split(",").map((k) => k.trim()).filter(Boolean);
  }
  if (f.type === "set_field") out.value = f.value;
  if (["redact_field", "redact_pattern", "redact_keys", "tag"].includes(f.type)) {
    out.replacement = f.replacement.trim() || undefined;
  }
  if (f.type === "tag") {
    out.pattern_kind = f.pattern_kind;
    out.pattern = f.pattern.trim();
  }
  if (f.useMatch && f.match.field.trim()) {
    out.match = { field: f.match.field.trim(), op: f.match.op, value: f.match.value };
  }
  return out;
}

function fromRule(r: ProcessorRule): FormState {
  return {
    name: r.name ?? "", lane: r.lane, type: r.type, field: r.field ?? "",
    pattern_kind: r.pattern_kind ?? "builtin", pattern: r.pattern ?? "email",
    replacement: r.replacement ?? "", keep_last: String(r.keep_last ?? 4),
    keys: (r.keys ?? []).join(", "), value: r.value ?? "",
    useMatch: !!r.match, match: r.match ?? { field: "", op: "equals", value: "" },
    description: r.description ?? "", order: String(r.order ?? 0), enabled: r.enabled,
  };
}

const summarize = (r: ProcessorRule): string => {
  switch (r.type) {
    case "redact_pattern":
      return `redact ${r.pattern_kind === "builtin" ? r.pattern : `"${r.pattern}"`} in ${r.field === "*" ? "every field" : `.${r.field}`} → ${r.replacement || "***"}`;
    case "redact_field": return `redact .${r.field} → ${r.replacement || "***"}`;
    case "mask": return `mask .${r.field}, keep last ${r.keep_last ?? 4}`;
    case "redact_keys": return `redact fields named ${(r.keys ?? []).slice(0, 3).join(", ")}${(r.keys ?? []).length > 3 ? "…" : ""}`;
    case "hash": return `hash .${r.field}`;
    case "tag": return `tag ${r.pattern_kind === "builtin" ? r.pattern : "matches"} as "${r.replacement || "sensitive"}"`;
    case "drop_field": return `remove .${r.field}`;
    case "set_field": return `set .${r.field} = "${r.value ?? ""}"`;
    case "drop_event": return "drop matching events";
    default: return r.type;
  }
};

// A representative sample per LANE, so the preview step works wherever the
// operator is working — not just syslog. Shapes mirror what each lane actually
// carries after the router's normalization.
const SAMPLES: Record<ProcessorLane, string> = {
  syslog: `{
  "message": "login failure for jsmith@example.org from 10.1.2.3 Bearer abc123def456",
  "hostname": "edge-fw-01",
  "vendor": "fortinet",
  "severity": "warning"
}`,
  applogs: `{
  "message": "charge authorized",
  "card": "4111111111111111",
  "password": "hunter2",
  "service": "billing"
}`,
  snmptrap: `{
  "message": "linkDown on Gi0/3",
  "community": "public",
  "oid": "1.3.6.1.6.3.1.1.5.3",
  "device": "core-sw-02"
}`,
  cloudlogs: `{
  "message": "AssumeRole by arn:aws:iam::123456789012:user/deploy",
  "user_email": "deploy@example.org",
  "provider": "aws",
  "region": "us-east-1"
}`,
  flows: `{
  "src_addr": "10.1.2.3",
  "dst_addr": "52.94.236.248",
  "dst_port": 443,
  "proto": 6,
  "bytes": 84213
}`,
};

/** The field a managed rule most usefully targets on each lane. */
const DEFAULT_FIELD: Record<ProcessorLane, string> = {
  syslog: "message", applogs: "message", snmptrap: "message",
  cloudlogs: "message", flows: "src_addr",
};

// ── the 4-step create wizard ────────────────────────────────────────────────

function Wizard({ catalog, initial, editingId, onDone, onCancel }: {
  catalog: ProcessorCatalog;
  initial: FormState;
  editingId?: string;
  onDone: () => void;
  onCancel: () => void;
}) {
  // Editing opens on the ACTION step (the thing you came to change), not the
  // preview — landing on a read-only pane to edit a rule is a small daily
  // insult (review C).
  const [step, setStep] = useState(editingId ? 2 : 0);
  const [f, setF] = useState<FormState>(initial);
  const [err, setErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [sample, setSample] = useState(SAMPLES[initial.lane] ?? SAMPLES.syslog);
  const [preview, setPreview] = useState<ProcessorPreview | null>(null);
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setF((p) => ({ ...p, [k]: v }));

  const action = catalog.actions.find((a) => a.type === f.type);
  const needsField = action?.targets_field !== false;

  const save = async () => {
    setSaving(true);
    setErr(null);
    try {
      if (editingId) await api.processorRuleUpdate(editingId, toInput(f));
      else await api.processorRuleCreate(toInput(f));
      onDone();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  // The preview runs the SAVED chain server-side; an unsaved draft is shown
  // with an honest note rather than a fabricated "after" the engine never ran.
  const runPreview = async () => {
    setErr(null);
    let ev: Record<string, unknown>;
    try {
      ev = JSON.parse(sample) as Record<string, unknown>;
    } catch {
      setErr("The sample event must be valid JSON.");
      return;
    }
    try {
      // Send the DRAFT so step 4 shows what THIS rule does, not just what the
      // already-saved chain does.
      setPreview(await api.processorPreview(f.lane, ev, toInput(f)));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const STEPS = ["Processor", "Matcher", "Action", "Preview"];
  return (
    <Modal title={editingId ? "Edit processor" : "New processor"} wide onClose={onCancel}>
      <div className="pp-steps" role="tablist" aria-label="Wizard steps">
        {STEPS.map((s, i) => (
          <button key={s} role="tab" aria-selected={step === i}
            className={`pp-step${step === i ? " on" : ""}${i < step ? " done" : ""}`}
            onClick={() => setStep(i)}>
            <span className="pp-step-n">{i + 1}</span> {s}
          </button>
        ))}
      </div>

      <div className="pp-wizard-body">
        {step === 0 && (
          <div style={{ display: "grid", gap: 10 }}>
            <div className="ccw-hint">What should this processor do to matching events?</div>
            <div className="pp-pick-grid">
              {catalog.actions.map((a) => (
                <button key={a.type} type="button"
                  className={`pp-pick${f.type === a.type ? " on" : ""}`}
                  onClick={() => set("type", a.type as ProcessorRuleType)}>
                  <strong>{a.label}</strong>
                  <span className="pp-pick-sub">{a.targets_field === false ? "whole event" : "one field"}</span>
                </button>
              ))}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
              <label className="ccw-field">
                <span className="ccw-label">Name</span>
                <input className="ccw-input" value={f.name} onChange={(e) => set("name", e.target.value)}
                  placeholder="Redact customer emails" maxLength={128} />
              </label>
              <label className="ccw-field">
                <span className="ccw-label">Lane</span>
                <select className="app-select" value={f.lane}
                  onChange={(e) => { set("lane", e.target.value as ProcessorLane); setSample(SAMPLES[e.target.value as ProcessorLane] ?? SAMPLES.syslog); }}>
                  {catalog.lanes.map((l) => <option key={l} value={l}>{l}</option>)}
                </select>
              </label>
              <label className="ccw-field">
                <span className="ccw-label">Order</span>
                <input className="ccw-input" type="number" min={0} max={9999} value={f.order}
                  onChange={(e) => set("order", e.target.value)} />
                <span className="ccw-hint">lower runs first</span>
              </label>
            </div>
          </div>
        )}

        {step === 1 && (
          <div style={{ display: "grid", gap: 10 }}>
            <div className="ccw-hint">
              Which events should it touch? {f.type === "drop_event"
                ? "A drop processor REQUIRES a condition — an unguarded drop would discard the whole lane."
                : "Leave off to apply to every event in the lane."}
            </div>
            <label style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
              <input type="checkbox" checked={f.useMatch || f.type === "drop_event"}
                disabled={f.type === "drop_event"}
                onChange={(e) => set("useMatch", e.target.checked)} />
              Only when a field matches…
            </label>
            {(f.useMatch || f.type === "drop_event") && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
                <label className="ccw-field">
                  <span className="ccw-label">Field</span>
                  <input className="ccw-input" value={f.match.field}
                    onChange={(e) => set("match", { ...f.match, field: e.target.value })} placeholder="service" />
                </label>
                <label className="ccw-field">
                  <span className="ccw-label">Matcher</span>
                  <select className="app-select" value={f.match.op}
                    onChange={(e) => set("match", { ...f.match, op: e.target.value as ProcessorMatchOp })}>
                    {catalog.matchers.map((m) => <option key={m.type} value={m.type}>{m.label}</option>)}
                  </select>
                </label>
                <label className="ccw-field">
                  <span className="ccw-label">Value</span>
                  <input className="ccw-input" value={f.match.value}
                    onChange={(e) => set("match", { ...f.match, value: e.target.value })} maxLength={256}
                    placeholder={f.match.op === "regex" ? "^auth(-svc)?$" : "authentication"} />
                  {f.match.op === "regex" && <span className="ccw-hint">RE2 syntax · validated on save</span>}
                </label>
              </div>
            )}
          </div>
        )}

        {step === 2 && (
          <div style={{ display: "grid", gap: 10 }}>
            {needsField && (
              <label className="ccw-field">
                <span className="ccw-label">Target field <span className="ccw-req">*</span></span>
                <input className="ccw-input" value={f.field} onChange={(e) => set("field", e.target.value)}
                  placeholder="message · user.email · request.headers.authorization" />
                <span className="ccw-hint">
                  JSON dot-path (user.email), or <code>*</code> to scan every field — which is what a
                  detector normally wants, since sensitive values rarely sit in <code>message</code>.
                </span>
              </label>
            )}
            {f.type === "redact_keys" && (
              <label className="ccw-field">
                <span className="ccw-label">Field names to redact <span className="ccw-req">*</span></span>
                <input className="ccw-input" value={f.keys} onChange={(e) => set("keys", e.target.value)}
                  placeholder="password, api_key, authorization" />
                <span className="ccw-hint">
                  Matches by field NAME, wherever it sits (including one level inside fields/body/headers).
                  A value pattern cannot see keys — this is what catches {'"password": "hunter2"'}.
                </span>
              </label>
            )}
            {(f.type === "redact_pattern" || f.type === "tag") && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 10 }}>
                <label className="ccw-field">
                  <span className="ccw-label">Pattern source</span>
                  <select className="app-select" value={f.pattern_kind}
                    onChange={(e) => set("pattern_kind", e.target.value as FormState["pattern_kind"])}>
                    <option value="builtin">Managed rule</option>
                    <option value="literal">Literal text</option>
                    <option value="regex">Custom regex</option>
                  </select>
                </label>
                {f.pattern_kind === "builtin" ? (
                  <label className="ccw-field">
                    <span className="ccw-label">Managed rule</span>
                    <select className="app-select" value={f.pattern}
                      onChange={(e) => {
                        const mr = catalog.managed_rules.find((m) => m.id === e.target.value);
                        setF((p) => ({ ...p, pattern: e.target.value, replacement: p.replacement || (mr?.replacement ?? "") }));
                      }}>
                      {catalog.managed_rules.map((m) => (
                        <option key={m.id} value={m.id}>{m.name} (v{m.version})</option>
                      ))}
                    </select>
                  </label>
                ) : (
                  <label className="ccw-field">
                    <span className="ccw-label">
                      {f.pattern_kind === "regex" ? "Regex (RE2)" : "Literal text"} <span className="ccw-req">*</span>
                    </span>
                    <input className="ccw-input" value={f.pattern} onChange={(e) => set("pattern", e.target.value)}
                      maxLength={256} placeholder={f.pattern_kind === "regex" ? "Bearer\\s+[A-Za-z0-9._-]+" : "exact text"} />
                  </label>
                )}
              </div>
            )}
            {["redact_field", "redact_pattern", "redact_keys", "tag"].includes(f.type) && (
              <label className="ccw-field">
                <span className="ccw-label">{f.type === "tag" ? "Tag" : "Replacement"}</span>
                <input className="ccw-input" value={f.replacement} onChange={(e) => set("replacement", e.target.value)}
                  placeholder={f.type === "tag" ? "PCI · stamped on cx_sensitive" : "[EMAIL] · defaults to ***"} maxLength={64} />
                {f.type === "tag" && <span className="ccw-hint">Detect only — the value is NOT modified.</span>}
                {f.type === "hash" && <span className="ccw-hint">Stable digest: unreadable, still joinable.</span>}
              </label>
            )}
            {f.type === "mask" && (
              <label className="ccw-field">
                <span className="ccw-label">Keep last N characters</span>
                <input className="ccw-input" type="number" min={0} max={64} value={f.keep_last}
                  onChange={(e) => set("keep_last", e.target.value)} />
                <span className="ccw-hint">4111111111111111 → ************1111</span>
              </label>
            )}
            {f.type === "set_field" && (
              <label className="ccw-field">
                <span className="ccw-label">Value</span>
                <input className="ccw-input" value={f.value} onChange={(e) => set("value", e.target.value)} maxLength={256} />
              </label>
            )}
            <label className="ccw-field">
              <span className="ccw-label">Description</span>
              <input className="ccw-input" value={f.description} onChange={(e) => set("description", e.target.value)}
                placeholder="Why this processor exists" maxLength={256} />
            </label>
            <label style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
              <input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />
              Enabled
            </label>
          </div>
        )}

        {step === 3 && (
          <div style={{ display: "grid", gap: 10 }}>
            <div className="ccw-hint">
              Dry run against a sample event — nothing is stored, and the pipeline is not touched.
              This includes the rule you are writing <em>plus</em> your already-saved processors, in execution order.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <label className="ccw-field">
                <span className="ccw-label">Before</span>
                <textarea className="ccw-input" rows={9} value={sample} onChange={(e) => setSample(e.target.value)}
                  style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }} />
              </label>
              <label className="ccw-field">
                <span className="ccw-label">After</span>
                <textarea className="ccw-input" rows={9} readOnly
                  value={preview ? JSON.stringify(preview.event, null, 2) : ""}
                  placeholder="Run the preview to see the processed event"
                  style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }} />
              </label>
            </div>
            <div>
              <button className="btn btn-sm" onClick={() => void runPreview()}>Run preview</button>
            </div>
            {preview?.dropped && (
              <div role="alert" style={{ color: "var(--warn)" }}>
                A drop processor matched — this event would <strong>not be stored</strong>.
              </div>
            )}
            {preview && preview.applied.length > 0 && (
              <div className="ccw-hint">
                Matched: {preview.applied.map((a) => a.managed_rule || a.processor).join(" · ")}
              </div>
            )}
            {preview && preview.applied.length === 0 && !preview.dropped && (
              <div className="ccw-hint">
                Nothing matched this sample. Check that the target field exists in the event above —
                a detector aimed at <code>message</code> will not find a value that lives in another field
                (use <code>*</code> to scan every field).
              </div>
            )}
          </div>
        )}
      </div>

      {err && <div role="alert" style={{ color: "var(--bad)", marginTop: 8 }}>{err}</div>}
      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <button className="btn" onClick={() => setStep((s) => Math.max(0, s - 1))} disabled={step === 0}>Back</button>
        {step < 3 ? (
          <button className="btn btn-primary" onClick={() => setStep((s) => Math.min(3, s + 1))}>Next</button>
        ) : null}
        <button className="btn btn-primary" onClick={() => void save()} disabled={saving} style={{ marginLeft: "auto" }}>
          {saving ? "Saving…" : editingId ? "Save changes" : "Create processor"}
        </button>
        <button className="btn" onClick={onCancel} disabled={saving}>Cancel</button>
      </div>
    </Modal>
  );
}

// ── history drawer ──────────────────────────────────────────────────────────

function HistoryModal({ rule, onClose, onRolledBack }: {
  rule: ProcessorRule; onClose: () => void; onRolledBack: () => void;
}) {
  const [versions, setVersions] = useState<ProcessorVersion[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    void (async () => {
      try {
        setVersions((await api.processorVersions(rule.id)).versions ?? []);
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [rule.id]);

  const rollback = async (v: number) => {
    if (!window.confirm(`Restore version ${v}? This is recorded as a new version — history is never rewritten.`)) return;
    try {
      await api.processorRollback(rule.id, v);
      onRolledBack();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Modal title={`History — ${rule.name || summarize(rule)}`} onClose={onClose}>
      {err && <div role="alert" style={{ color: "var(--bad)" }}>{err}</div>}
      {versions === null && !err && <div className="ccw-hint">Loading…</div>}
      {versions && versions.length === 0 && <div className="ccw-hint">No history recorded yet.</div>}
      <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: "50vh", overflowY: "auto" }}>
        {(versions ?? []).map((v) => (
          <div key={v.version} className="pp-version">
            <strong>v{v.version}</strong>
            <span className="pp-version-kind">{v.change_kind}</span>
            <span className="pp-version-meta">
              {fmt(v.created_at)}{v.changed_by ? ` · ${v.changed_by}` : ""}
            </span>
            <span className="pp-version-sum">{summarize(v.config)}</span>
            {v.version !== rule.version && (
              <button className="btn btn-sm" onClick={() => void rollback(v.version)}>Restore</button>
            )}
          </div>
        ))}
      </div>
    </Modal>
  );
}

// ── page ────────────────────────────────────────────────────────────────────

export default function ProcessorsAdmin() {
  const [items, setItems] = useState<ProcessorRule[] | null>(null);
  const [catalog, setCatalog] = useState<ProcessorCatalog | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [wizard, setWizard] = useState<{ initial: FormState; editingId?: string } | null>(null);
  const [history, setHistory] = useState<ProcessorRule | null>(null);
  const [showCatalog, setShowCatalog] = useState(false);
  const [cloneLane, setCloneLane] = useState<ProcessorLane>("syslog");
  const [cloneField, setCloneField] = useState("message");
  const [nonce, setNonce] = useState(0);

  const load = useCallback(async () => {
    try {
      const [rules, cat] = await Promise.all([api.processorRules(), api.processorCatalog()]);
      setItems(rules.rules ?? []);
      setCatalog(cat);
      setLoadErr(null);
    } catch (e) {
      setLoadErr(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => { void load(); }, [load, nonce]);
  const refresh = () => setNonce((n) => n + 1);

  const remove = async (r: ProcessorRule) => {
    if (!window.confirm(`Delete "${r.name || summarize(r)}"? Ingested data stops being shaped by it immediately.`)) return;
    try {
      await api.processorRuleDelete(r.id);
      refresh();
    } catch (e) {
      setLoadErr(e instanceof Error ? e.message : String(e));
    }
  };
  const toggle = async (r: ProcessorRule) => {
    try {
      // Send only the EDITABLE shape — spreading the full row shipped
      // server-owned stamps (id/version/source/created_by) back in the PUT.
      await api.processorRuleUpdate(r.id, { ...toInput(fromRule(r)), enabled: !r.enabled });
      refresh();
    } catch (e) {
      setLoadErr(e instanceof Error ? e.message : String(e));
    }
  };
  const clone = async (m: ManagedRule, lane: ProcessorLane, field: string) => {
    try {
      await api.processorClone({ managed_rule_id: m.id, lane, field });
      setShowCatalog(false);
      refresh();
    } catch (e) {
      setLoadErr(e instanceof Error ? e.message : String(e));
    }
  };

  const columns = useMemo<Column<ProcessorRule>[]>(() => [
    { key: "order", header: "#", width: 56, sortable: true, sortValue: (r) => r.order,
      text: (r) => String(r.order), render: (r) => <span style={{ color: "var(--muted)" }}>{r.order}</span> },
    { key: "name", header: "Processor", width: "34%", sortable: true, text: (r) => r.name || summarize(r),
      render: (r) => (
        <span className="pp-name" title={r.description || summarize(r)}>
          <strong>{r.name || summarize(r)}</strong>
          <span className="pp-name-sum">{summarize(r)}</span>
        </span>
      ) },
    { key: "lane", header: "Lane", width: 82, sortable: true, text: (r) => r.lane,
      render: (r) => <span className="badge">{r.lane}</span> },
    { key: "source", header: "Source", width: 92, sortable: true, text: (r) => r.source ?? "custom",
      render: (r) => r.source === "managed"
        ? <Chip label="Managed" tone="var(--accent)" title={`Adopted from the managed rule "${r.managed_rule_id}"`} />
        : <Chip label="Custom" tone="var(--fg-subtle)" /> },
    { key: "status", header: "Status", width: 96, sortable: true, text: (r) => (r.enabled ? "enabled" : "disabled"),
      render: (r) => (r.enabled ? <Chip label="Enabled" tone="var(--ok)" /> : <Chip label="Disabled" tone="var(--fg-subtle)" />) },
    { key: "updated", header: "Last updated", width: 128, sortable: true,
      sortValue: (r) => Date.parse(r.updated_at) || 0,
      render: (r) => <span title={`version ${r.version}`}>{fmt(r.updated_at)} · v{r.version}</span> },
    // 4 buttons never fit 240px — Delete was clipped off the right edge. The
    // column is sized to its content and the buttons are compact + no-wrap.
    { key: "actions", header: "", width: 268,
      render: (r) => (
        <span className="pp-actions">
          <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); setWizard({ initial: fromRule(r), editingId: r.id }); }}>Edit</button>
          <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); void toggle(r); }}>
            {r.enabled ? "Disable" : "Enable"}
          </button>
          <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); setHistory(r); }}>History</button>
          <button className="btn btn-sm pp-danger" onClick={(e) => { e.stopPropagation(); void remove(r); }}>Delete</button>
        </span>
      ) },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], []);

  return (
    <div>
      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Pipeline processors</h3>
          <span className="cc-panel-meta" style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            {loadErr ? "unavailable" : `${items?.length ?? 0} processor${(items?.length ?? 0) === 1 ? "" : "s"}`}
            <button className="btn btn-sm" onClick={() => setShowCatalog(true)} disabled={!catalog}>Managed rules</button>
            <button className="btn btn-sm btn-primary" onClick={() => setWizard({ initial: EMPTY_FORM })} disabled={!catalog}>
              + New processor
            </button>
          </span>
        </div>
        <div style={{ padding: "11px 13px" }}>
          <div className="ccw-hint" style={{ marginBottom: 8 }}>
            Processors run <strong>in order</strong> against your tenant's events before storage — redact sensitive
            values, mask numbers, remove fields, or drop noise. Changes apply to the live pipeline within about a
            minute, with no restart. They shape stored logs and flows; correlation signals derived on the bus are
            not shaped in this version.
          </div>
          {loadErr && (
            <div className="empty" role="alert" style={{ color: "var(--bad)" }}>
              <strong>Pipeline processors could not be loaded.</strong>
              <div style={{ marginTop: 4 }}>{loadErr}</div>
            </div>
          )}
          {!loadErr && items !== null && items.length === 0 && (
            <div className="empty">No processors yet — telemetry is stored exactly as it arrives.</div>
          )}
          {!loadErr && items !== null && items.length > 0 && (
            <DataTable<ProcessorRule>
              rows={items}
              columns={columns}
              rowKey={(r) => r.id}
              height="52vh"
              ariaLabel="Pipeline processors"
              initialSort={{ key: "order", dir: "asc" }}
            />
          )}
        </div>
      </div>

      {wizard && catalog && (
        <Wizard
          catalog={catalog}
          initial={wizard.initial}
          editingId={wizard.editingId}
          onDone={() => { setWizard(null); refresh(); }}
          onCancel={() => setWizard(null)}
        />
      )}
      {history && (
        <HistoryModal rule={history} onClose={() => setHistory(null)}
          onRolledBack={() => { setHistory(null); refresh(); }} />
      )}
      {showCatalog && catalog && (
        <Modal title="Managed rules" wide onClose={() => setShowCatalog(false)}>
          <div className="ccw-hint" style={{ marginBottom: 10 }}>
            Curated, versioned detectors maintained by the platform. They are read-only — clone one to get an
            editable processor of your own.
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "flex-end", marginBottom: 10 }}>
            <label className="ccw-field" style={{ minWidth: 150 }}>
              <span className="ccw-label">Clone into lane</span>
              <select className="app-select" value={cloneLane}
                onChange={(e) => {
                  const l = e.target.value as ProcessorLane;
                  setCloneLane(l);
                  setCloneField(DEFAULT_FIELD[l] ?? "message");
                }}>
                {catalog.lanes.map((l) => <option key={l} value={l}>{l}</option>)}
              </select>
            </label>
            <label className="ccw-field" style={{ minWidth: 200 }}>
              <span className="ccw-label">Target field</span>
              <input className="ccw-input" value={cloneField} onChange={(e) => setCloneField(e.target.value)}
                placeholder="message" />
            </label>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: "55vh", overflowY: "auto" }}>
            {catalog.managed_rules.map((m) => (
              <div key={m.id} className="pp-managed">
                <strong>{m.name}</strong>
                <Chip label={m.category} tone="var(--accent)" />
                <span className="pp-managed-desc">{m.description}</span>
                <span className="pp-version-meta">v{m.version} → {m.replacement}</span>
                <button className="btn btn-sm" onClick={() => void clone(m, cloneLane, cloneField.trim() || DEFAULT_FIELD[cloneLane] || "message")}>
                  Clone here
                </button>
              </div>
            ))}
          </div>
        </Modal>
      )}
    </div>
  );
}
