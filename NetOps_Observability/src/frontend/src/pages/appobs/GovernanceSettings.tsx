// GovernanceSettings — the REAL per-tenant Settings editors (Wave 4 #11).
//
// Each card edits one persisted, audited, admin-gated tenant setting via
// /api/settings/*; reads are open to any authenticated user, writes return
// 403 for non-admins (surfaced inline — the card never pretends to save).
// These replace the "(platform default — not yet editable)" placeholder rows.

import { useEffect, useState } from "react";
import { api } from "../../services/api";
import { invalidateCloudInventory } from "./api";

// ── pure helpers (unit-tested in governanceSettings.test.ts) ─────────────────

export const REQUIRED_TAGS_MAX = 32;

// Mirror of the server's tag-key validation (tenant_governance.go): lowercase;
// letters/digits/._:/- only; 1..64 chars. Returns the normalized key or null.
export function normalizeTagKey(raw: string): string | null {
  const tag = raw.trim().toLowerCase();
  if (!tag || tag.length > 64) return null;
  return /^[a-z0-9._:/-]+$/.test(tag) ? tag : null;
}

// Window presets the picker offers (all within the server's 1..168 clamp).
export const RCA_WINDOW_PRESETS = [
  { hours: 1, label: "1 hour" },
  { hours: 6, label: "6 hours" },
  { hours: 24, label: "24 hours" },
  { hours: 72, label: "3 days" },
  { hours: 168, label: "7 days" },
];

// ── RCA window editor ────────────────────────────────────────────────────────

export function RcaWindowCard() {
  const [hours, setHours] = useState(24);
  const [isDefault, setIsDefault] = useState(true);
  const [defaultHours, setDefaultHours] = useState(24);
  const [busy, setBusy] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.getRcaWindow()
      .then((r) => { setHours(r.rca_window_hours); setIsDefault(r.is_default); setDefaultHours(r.default_hours); })
      .catch((e) => setErr((e as Error).message))
      .finally(() => setBusy(false));
  }, []);

  const persist = async (call: () => Promise<{ rca_window_hours: number; is_default: boolean }>) => {
    setErr(null); setSaved(false);
    try {
      const r = await call();
      setHours(r.rca_window_hours); setIsDefault(r.is_default);
      setSaved(true); setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <div className="ao-panel">
      <div className="ao-panel-h">RCA Window{" "}
        <span className="ao-panel-meta">{isDefault ? "platform default" : "tenant override"} · admin-set, audited</span>
      </div>
      <p className="ao-set-d">
        Default read window for this tenant&apos;s cloud RCA surfaces (health signals, change events,
        evidence ledger, service map) when a view hasn&apos;t picked a range. An explicit range selection
        always wins per request; the server bounds every read to 7 days.
        {err && <span style={{ color: "var(--crit)" }}> · {err}</span>}
        {saved && <span style={{ color: "var(--ok)" }}> · saved</span>}
      </p>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <select className="app-select" value={hours} disabled={busy} aria-label="Default RCA window"
          onChange={(e) => persist(() => api.setRcaWindow(Number(e.target.value)))}>
          {RCA_WINDOW_PRESETS.map((p) => <option key={p.hours} value={p.hours}>{p.label}</option>)}
          {!RCA_WINDOW_PRESETS.some((p) => p.hours === hours) && <option value={hours}>{hours} hours</option>}
        </select>
        {!isDefault && (
          <button className="ao-btn" disabled={busy}
            onClick={() => persist(() => api.resetRcaWindow())}>Reset to default ({defaultHours}h)</button>
        )}
      </div>
    </div>
  );
}

// ── Required tags editor ─────────────────────────────────────────────────────

export function RequiredTagsCard() {
  const [tags, setTags] = useState<string[]>([]);
  const [isDefault, setIsDefault] = useState(true);
  const [draft, setDraft] = useState("");
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(true);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const load = () => {
    api.getRequiredTags()
      .then((r) => { setTags(r.required_tags); setIsDefault(r.is_default); setDirty(false); })
      .catch((e) => setErr((e as Error).message))
      .finally(() => setBusy(false));
  };
  useEffect(load, []);

  const add = () => {
    setErr(null);
    const tag = normalizeTagKey(draft);
    if (!tag) { setErr("tag keys are lowercase letters, digits, . _ : / - (max 64 chars)"); return; }
    if (tags.includes(tag)) { setDraft(""); return; }
    if (tags.length >= REQUIRED_TAGS_MAX) { setErr(`at most ${REQUIRED_TAGS_MAX} required tags`); return; }
    setTags([...tags, tag]); setDraft(""); setDirty(true);
  };
  const remove = (tag: string) => { setErr(null); setTags(tags.filter((t) => t !== tag)); setDirty(true); };

  const persist = async (call: () => Promise<{ required_tags: string[]; is_default: boolean }>) => {
    setErr(null); setSaved(false); setSaving(true);
    try {
      const r = await call();
      setTags(r.required_tags); setIsDefault(r.is_default); setDirty(false);
      invalidateCloudInventory(); // missing-tags columns re-read the new list
      setSaved(true); setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Required Tags{" "}
        <span className="ao-panel-meta">{isDefault ? "platform default" : "tenant override"} · admin-set, audited</span>
      </div>
      <p className="ao-set-d">
        Tags this tenant requires on every cloud resource — drives the &quot;missing tags&quot; columns and the
        coverage compliance report. <code>app</code>/<code>owner</code>/<code>env</code> accept their usual alias
        keys (application, team, stage, …); other keys match exactly (case-insensitive).
        {err && <span style={{ color: "var(--crit)" }}> · {err}</span>}
        {saved && <span style={{ color: "var(--ok)" }}> · saved</span>}
      </p>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, margin: "8px 0" }}>
        {tags.map((t) => (
          <span key={t} style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 12, padding: "2px 8px", background: "var(--panel-2, rgba(127,127,127,0.06))", border: "1px solid var(--panel-border)", borderRadius: 999 }}>
            <span className="ao-mono">{t}</span>
            <button className="ao-rowaction" aria-label={`Remove required tag ${t}`} disabled={busy || saving}
              onClick={() => remove(t)} style={{ padding: "0 4px" }}>×</button>
          </span>
        ))}
        {!busy && tags.length === 0 && <span className="ao-muted">no required tags — add at least one to save</span>}
      </div>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <input className="ao-search" style={{ maxWidth: 220 }} value={draft} disabled={busy || saving}
          placeholder="add a tag key, e.g. cost_center"
          aria-label="New required tag key"
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") add(); }} />
        <button className="ao-btn" onClick={add} disabled={busy || saving || !draft.trim()}>Add</button>
        <button className="ao-btn ao-btn--primary" disabled={busy || saving || !dirty || tags.length === 0}
          onClick={() => persist(() => api.setRequiredTags(tags))}>
          {saving ? "Saving…" : "Save"}
        </button>
        {!isDefault && (
          <button className="ao-btn" disabled={busy || saving}
            onClick={() => persist(() => api.resetRequiredTags())}>Reset to default</button>
        )}
      </div>
    </div>
  );
}
