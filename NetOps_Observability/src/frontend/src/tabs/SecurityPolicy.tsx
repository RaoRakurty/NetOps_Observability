// Security Policy (#24) — the admin surface over the deterministic policy engine
// (src/backend/policy/* + policy_http.go). Two views:
//
//   Editor    — pick a scope (System → Tenant → Role → User) and author overrides
//               on the NIST-aligned control catalog, grouped into four domain
//               cards. Each setting shows its EFFECTIVE value, the scope it was
//               inherited from, and its lock/harden affordances, with a typed
//               inline control (toggle / number / select / multiselect).
//   Simulator — resolve the effective policy for any subject and inspect the full
//               System→Tenant→Role→User inheritance trail per setting.
//
// Data-dense, status-coded, light/dark via the shared CSS tokens. Authoring is
// gated to what the caller may write (system/global = platform owner only); the
// backend enforces the same boundary independently.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  PolicyCatalog,
  PolicySetting,
  PolicyValue,
  PolicyConstraint,
  PolicyResolved,
  PolicyScope,
  PolicyDomain,
  PolicyDocument,
  PolicySubject,
  PolicyRef,
} from "../services/api";
import { useAuth } from "../hooks/useAuth";
import Icon from "../components/Icon";
import { InfoTip } from "../components/ui";

// ---- domain + scope presentation ------------------------------------------

const DOMAIN_LABEL: Record<PolicyDomain, string> = {
  authentication: "Authentication",
  password: "Password",
  session: "Session",
  account_lifecycle: "Account Lifecycle",
};
const SCOPE_LABEL: Record<PolicyScope, string> = {
  system: "System",
  tenant: "Tenant",
  role: "Role",
  user: "User",
};
const SCOPE_ORDER: PolicyScope[] = ["system", "tenant", "role", "user"];

// ---- value helpers ---------------------------------------------------------

const UNIT_SECONDS: Record<string, number> = { seconds: 1, minutes: 60, hours: 3600, days: 86400 };

function durationUnit(c: PolicyConstraint): { factor: number; label: string } {
  const u = c.unit && UNIT_SECONDS[c.unit] ? c.unit : "seconds";
  return { factor: UNIT_SECONDS[u], label: u };
}

// toDisplayNum converts a stored numeric value into its display unit (durations
// are stored as whole seconds but edited in minutes/hours/days).
function toDisplayNum(v: PolicyValue, c: PolicyConstraint): number {
  if (v.kind === "duration") return Math.round((v.num ?? 0) / durationUnit(c).factor);
  return v.num ?? 0;
}
function fromDisplayNum(n: number, kind: PolicyValue["kind"], c: PolicyConstraint): PolicyValue {
  if (kind === "duration") return { kind, num: Math.max(0, Math.round(n * durationUnit(c).factor)) };
  return { kind, num: Math.max(0, Math.round(n)) };
}

function humanizeDuration(seconds: number): string {
  if (seconds <= 0) return "0";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const parts: string[] = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (s && !d && !h) parts.push(`${s}s`);
  return parts.join(" ") || "0";
}

function formatValue(v: PolicyValue, s: PolicySetting): string {
  switch (v.kind) {
    case "bool":
      return v.bool ? "On" : "Off";
    case "int":
      return `${v.num ?? 0}${s.constraint.unit ? ` ${s.constraint.unit}` : ""}`;
    case "duration":
      return v.num === 0 ? "Off" : humanizeDuration(v.num ?? 0);
    case "enum":
      return v.str || "—";
    case "list":
      return (v.list ?? []).join(", ") || "none";
  }
}

function valuesEqual(a: PolicyValue, b: PolicyValue): boolean {
  if (a.kind !== b.kind) return false;
  switch (a.kind) {
    case "bool":
      return !!a.bool === !!b.bool;
    case "int":
    case "duration":
      return (a.num ?? 0) === (b.num ?? 0);
    case "enum":
      return (a.str ?? "") === (b.str ?? "");
    case "list":
      return JSON.stringify(a.list ?? []) === JSON.stringify(b.list ?? []);
  }
}

// ---- small presentational atoms -------------------------------------------

function SourceBadge({ r, scope }: { r: PolicyResolved; scope: PolicyScope }) {
  if (r.from_default) return <span className="badge pol-badge-muted">Default</span>;
  if (r.source === scope) return <span className="badge accent-badge">Set here</span>;
  return <span className="badge pol-badge-muted">Inherited · {SCOPE_LABEL[r.source!]}</span>;
}

// hardenNote describes, in prose, the inheritance constraint on a setting — it
// is surfaced inside the InfoTip rather than as an inline chip.
function hardenNote(s: PolicySetting): string | null {
  if (s.harden === "higher") return "More-specific scopes may only raise this (stricter), never weaken it.";
  if (s.harden === "lower") return "More-specific scopes may only lower this (stricter), never weaken it.";
  return null;
}

// ---- typed value control ---------------------------------------------------

function ValueControl({
  setting,
  value,
  onChange,
  disabled,
}: {
  setting: PolicySetting;
  value: PolicyValue;
  onChange: (v: PolicyValue) => void;
  disabled: boolean;
}) {
  const c = setting.constraint;
  switch (setting.kind) {
    case "bool":
      return (
        <button
          type="button"
          role="switch"
          aria-checked={!!value.bool}
          aria-label={setting.label}
          disabled={disabled}
          className={`pol-toggle ${value.bool ? "on" : ""}`}
          onClick={() => onChange({ kind: "bool", bool: !value.bool })}
        >
          <span className="pol-toggle-knob" />
        </button>
      );
    case "int":
    case "duration": {
      const du = setting.kind === "duration" ? durationUnit(c) : null;
      return (
        <div className="pol-num">
          <input
            type="number"
            disabled={disabled}
            value={String(toDisplayNum(value, c))}
            min={du ? Math.round((c.min ?? 0) / du.factor) : c.min}
            max={du ? Math.round((c.max ?? 0) / du.factor) : c.max}
            onChange={(e) => onChange(fromDisplayNum(Number(e.target.value), setting.kind, c))}
            aria-label={setting.label}
          />
          <span className="mini-meta">{du ? du.label : c.unit || ""}</span>
        </div>
      );
    }
    case "enum":
      return (
        <select
          disabled={disabled}
          value={value.str ?? ""}
          aria-label={setting.label}
          onChange={(e) => onChange({ kind: "enum", str: e.target.value })}
          className="pol-select"
        >
          {(c.enum ?? []).map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      );
    case "list": {
      const sel = new Set(value.list ?? []);
      const toggle = (o: string) => {
        const next = new Set(sel);
        next.has(o) ? next.delete(o) : next.add(o);
        // preserve catalog order so the stored list is deterministic
        onChange({ kind: "list", list: (c.enum ?? []).filter((x) => next.has(x)) });
      };
      return (
        <div className="pol-chips">
          {(c.enum ?? []).map((o) => (
            <button
              key={o}
              type="button"
              disabled={disabled}
              aria-pressed={sel.has(o)}
              className={`pol-chip-toggle ${sel.has(o) ? "on" : ""}`}
              onClick={() => toggle(o)}
            >
              {o}
            </button>
          ))}
        </div>
      );
    }
  }
}

// ---- one setting row (editor) ---------------------------------------------

function SettingRow({
  setting,
  resolved,
  overriddenHere,
  scope,
  canWrite,
  onApply,
  onClear,
}: {
  setting: PolicySetting;
  resolved: PolicyResolved;
  overriddenHere: boolean;
  scope: PolicyScope;
  canWrite: boolean;
  onApply: (key: string, v: PolicyValue, locked: boolean) => Promise<string | null>;
  onClear: (key: string) => Promise<void>;
}) {
  const [draft, setDraft] = useState<PolicyValue>(resolved.value);
  const [locked, setLocked] = useState<boolean>(scope === resolved.locked_at && !!resolved.locked);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Re-sync when the resolved value changes (scope/selector switch or reload).
  useEffect(() => {
    setDraft(resolved.value);
    setLocked(scope === resolved.locked_at && !!resolved.locked);
    setErr(null);
  }, [resolved, scope]);

  const lockedAbove = !!resolved.locked && resolved.locked_at !== scope;
  const editable = canWrite && !lockedAbove;
  const lockChanged = setting.lockable && locked !== (scope === resolved.locked_at && !!resolved.locked);
  const dirty = !valuesEqual(draft, resolved.value) || lockChanged;

  const apply = async () => {
    setBusy(true);
    setErr(null);
    const e = await onApply(setting.key, draft, locked);
    if (e) setErr(e);
    setBusy(false);
  };
  const revert = async () => {
    setBusy(true);
    setErr(null);
    await onClear(setting.key);
    setBusy(false);
  };

  return (
    <div className="pol-row">
      <div className="pol-row-main">
        <div className="pol-row-head">
          <span className="pol-row-label">{setting.label}</span>
          <InfoTip label={setting.description}>
            <span className="ds-tip-lead">{setting.description}</span>
            {setting.rationale && <span className="ds-tip-note">{setting.rationale}</span>}
            {hardenNote(setting) && <span className="ds-tip-note">{hardenNote(setting)}</span>}
          </InfoTip>
          {setting.tier === "advanced" && <span className="pol-chip pol-chip-quiet">advanced</span>}
          {resolved.locked && (
            <span className="pol-chip pol-chip-lock" title={`Locked at ${SCOPE_LABEL[resolved.locked_at!]}`}>
              <Icon name="lock" size={12} /> locked · {SCOPE_LABEL[resolved.locked_at!]}
            </span>
          )}
        </div>
        <div className="pol-row-meta">
          <SourceBadge r={resolved} scope={scope} />
        </div>
        {err && <p className="pol-row-err" role="alert">{err}</p>}
      </div>

      <div className="pol-row-ctl">
        <ValueControl setting={setting} value={draft} onChange={setDraft} disabled={!editable || busy} />
        {setting.lockable && editable && (
          <label className="pol-locktoggle" title="Lock this setting against more-specific scopes">
            <input type="checkbox" checked={locked} disabled={!editable || busy} onChange={(e) => setLocked(e.target.checked)} />
            <Icon name={locked ? "lock" : "unlock"} size={13} /> lock
          </label>
        )}
        {editable && dirty && (
          <div className="pol-row-actions">
            <button className="dash-btn accent" disabled={busy} onClick={apply}>
              Apply
            </button>
            <button className="dash-btn" disabled={busy} onClick={() => { setDraft(resolved.value); setErr(null); }}>
              Reset
            </button>
          </div>
        )}
        {editable && overriddenHere && !dirty && (
          <button className="pol-link" disabled={busy} onClick={revert}>
            Revert to inherited
          </button>
        )}
        {lockedAbove && <span className="mini-meta">read-only (locked above)</span>}
        {!canWrite && !lockedAbove && <span className="mini-meta">read-only</span>}
      </div>
    </div>
  );
}

// ---- editor KPI strip + loading skeleton -----------------------------------

function PolicyStats({
  stats,
  scope,
}: {
  stats: { total: number; set: number; inherited: number; locked: number };
  scope: PolicyScope;
}) {
  const items = [
    { label: "Controls", value: stats.total, tone: "" },
    { label: `Set at ${SCOPE_LABEL[scope]}`, value: stats.set, tone: stats.set ? "accent" : "" },
    { label: "Inherited", value: stats.inherited, tone: "" },
    { label: "Locked", value: stats.locked, tone: stats.locked ? "warn" : "" },
  ];
  return (
    <div className="pol-stats">
      {items.map((it) => (
        <div key={it.label} className={`pol-stat ${it.tone}`}>
          <span className="pol-stat-num mono">{it.value}</span>
          <span className="pol-stat-label">{it.label}</span>
        </div>
      ))}
    </div>
  );
}

function EditorSkeleton() {
  return (
    <div className="pol-grid" aria-busy="true" aria-label="Loading effective policy">
      {[0, 1].map((c) => (
        <section key={c} className="card pol-card">
          <header className="pol-card-head">
            <span className="pol-skeleton" style={{ width: 120, height: 12 }} />
          </header>
          <div className="pol-rows">
            {[0, 1, 2].map((r) => (
              <div key={r} className="pol-row">
                <div className="pol-row-main">
                  <span className="pol-skeleton" style={{ width: "55%", height: 13 }} />
                  <span className="pol-skeleton" style={{ width: "80%", height: 11, marginTop: 8 }} />
                </div>
                <div className="pol-row-ctl">
                  <span className="pol-skeleton" style={{ width: 84, height: 28 }} />
                </div>
              </div>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

// ---- editor view -----------------------------------------------------------

function PolicyEditor({
  catalog,
  scope,
  ref_,
  subject,
  canWrite,
  tier,
}: {
  catalog: PolicyCatalog;
  scope: PolicyScope;
  ref_: PolicyRef;
  subject: PolicySubject;
  canWrite: boolean;
  tier: "basic" | "advanced";
}) {
  const [resolved, setResolved] = useState<Record<string, PolicyResolved>>({});
  const [doc, setDoc] = useState<PolicyDocument | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const [eff, d] = await Promise.all([
        api.policyEffective(subject),
        api.policyDocument(scope, ref_.selector, ref_.tenant),
      ]);
      const byKey: Record<string, PolicyResolved> = {};
      for (const r of eff.resolved) byKey[r.key] = r;
      setResolved(byKey);
      setDoc(d.document);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, ref_.selector, ref_.tenant, subject.tenant, subject.role, subject.user]);

  useEffect(() => {
    reload();
  }, [reload]);

  const onApply = async (key: string, v: PolicyValue, locked: boolean): Promise<string | null> => {
    try {
      await api.setPolicyOverride(ref_, key, v, locked);
      await reload();
      return null;
    } catch (e) {
      return (e as Error).message.replace(/^\d+ [^:]+:\s*/, "");
    }
  };
  const onClear = async (key: string) => {
    try {
      await api.clearPolicyOverride(ref_, key);
      await reload();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  if (err) return <div className="card pol-note bad">{err}</div>;
  if (loading) return <EditorSkeleton />;

  const overrides = doc?.overrides ?? {};
  const allSettings = catalog.domains.flatMap((d) => d.settings);
  const stats = {
    total: allSettings.length,
    set: allSettings.filter((s) => overrides[s.key]).length,
    inherited: allSettings.filter((s) => {
      const r = resolved[s.key];
      return r && !r.from_default && r.source !== scope;
    }).length,
    locked: allSettings.filter((s) => resolved[s.key]?.locked).length,
  };
  return (
    <>
      <PolicyStats stats={stats} scope={scope} />
      <div className="pol-grid">
        {catalog.domains.map((dm) => {
        const settings = dm.settings.filter((s) => (tier === "advanced" ? true : s.tier === "basic"));
        if (settings.length === 0) return null;
        return (
          <section key={dm.domain} className="card pol-card">
            <header className="pol-card-head">
              <h2>{DOMAIN_LABEL[dm.domain]}</h2>
              <span className="mini-meta">{settings.length} controls</span>
            </header>
            <div className="pol-rows">
              {settings.map((s) => {
                const r = resolved[s.key];
                if (!r) return null;
                return (
                  <SettingRow
                    key={s.key}
                    setting={s}
                    resolved={r}
                    overriddenHere={!!overrides[s.key]}
                    scope={scope}
                    canWrite={canWrite}
                    onApply={onApply}
                    onClear={onClear}
                  />
                );
              })}
            </div>
          </section>
        );
        })}
      </div>
    </>
  );
}

// ---- simulator view --------------------------------------------------------

function TrailRow({ r, settings }: { r: PolicyResolved; settings: Record<string, PolicySetting> }) {
  const [open, setOpen] = useState(false);
  const s = settings[r.key];
  if (!s) return null;
  const hasTrail = (r.trail ?? []).length > 0;
  return (
    <div className="pol-sim-row">
      <button className="pol-sim-rowhead" onClick={() => hasTrail && setOpen((o) => !o)} aria-expanded={open}>
        <span className={`pol-caret ${open ? "open" : ""}`}>
          {hasTrail ? <Icon name="chevron-right" size={14} /> : <span style={{ width: 14, display: "inline-block" }} />}
        </span>
        <span className="pol-sim-label">{s.label}</span>
        <span className="pol-sim-value mono">{formatValue(r.value, s)}</span>
        {r.from_default ? (
          <span className="badge pol-badge-muted">Default</span>
        ) : (
          <span className="badge accent-badge">{SCOPE_LABEL[r.source!]}</span>
        )}
        {r.locked && (
          <span className="pol-chip pol-chip-lock">
            <Icon name="lock" size={11} /> {SCOPE_LABEL[r.locked_at!]}
          </span>
        )}
      </button>
      {open && hasTrail && (
        <ol className="pol-trail">
          {r.trail!.map((step, i) => (
            <li key={i} className={`pol-trail-step ${step.applied ? "applied" : "ignored"}`}>
              <span className="pol-trail-scope">{SCOPE_LABEL[step.scope]}{step.selector ? ` · ${step.selector}` : ""}</span>
              <span className="mono">{formatValue(step.value, s)}</span>
              {step.locked && <Icon name="lock" size={11} />}
              <span className="mini-meta">{step.applied ? "applied" : step.note || "ignored"}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function PolicySimulator({ catalog }: { catalog: PolicyCatalog }) {
  const { user } = useAuth();
  const platform = !!user?.platform_admin;
  const [tenant, setTenant] = useState(platform ? "" : user?.tenant_id ?? "");
  const [role, setRole] = useState("");
  const [usr, setUsr] = useState("");
  const [resolved, setResolved] = useState<PolicyResolved[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const settings = useMemo(() => {
    const m: Record<string, PolicySetting> = {};
    for (const dm of catalog.domains) for (const s of dm.settings) m[s.key] = s;
    return m;
  }, [catalog]);

  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      const res = await api.policyEffective({ tenant: tenant || undefined, role: role || undefined, user: usr || undefined });
      setResolved(res.resolved);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const byDomain = useMemo(() => {
    const m: Record<string, PolicyResolved[]> = {};
    for (const r of resolved ?? []) (m[r.domain] ||= []).push(r);
    return m;
  }, [resolved]);

  return (
    <div>
      <div className="card pol-sim-controls">
        <div className="pol-sim-inputs">
          <label>
            <span>Tenant</span>
            <input value={tenant} disabled={!platform} placeholder={platform ? "tenant id" : tenant} onChange={(e) => setTenant(e.target.value)} />
          </label>
          <label>
            <span>Role</span>
            <input value={role} placeholder="role id (optional)" onChange={(e) => setRole(e.target.value)} />
          </label>
          <label>
            <span>User</span>
            <input value={usr} placeholder="username (optional)" onChange={(e) => setUsr(e.target.value)} />
          </label>
          <button className="dash-btn accent" disabled={busy} onClick={run}>
            Resolve
          </button>
        </div>
        <p className="admin-sub" style={{ marginTop: 8 }}>
          Resolves the effective policy this subject would receive, walking System → Tenant → Role → User. Expand a row to see the inheritance trail and why each scope was applied or clamped.
        </p>
        {!platform && <p className="mini-meta">You can simulate within your own tenant only.</p>}
      </div>

      {err && <div className="card pol-note bad">{err}</div>}
      {resolved &&
        catalog.domains.map((dm) =>
          byDomain[dm.domain] ? (
            <section key={dm.domain} className="card pol-card" style={{ marginTop: 12 }}>
              <header className="pol-card-head">
                <h2>{DOMAIN_LABEL[dm.domain]}</h2>
              </header>
              <div className="pol-sim-rows">
                {byDomain[dm.domain].map((r) => (
                  <TrailRow key={r.key} r={r} settings={settings} />
                ))}
              </div>
            </section>
          ) : null,
        )}
    </div>
  );
}

// ---- page shell ------------------------------------------------------------

// SecurityPolicy. `scopeTenant` is passed when embedded in Identity & Access:
// "" → Global (System defaults), a tenant id → that tenant's policy (pre-seeds the
// Tenant scope, wiring it to the chosen tenant instead of a raw id field).
export default function SecurityPolicy({ scopeTenant }: { scopeTenant?: string } = {}) {
  const { user } = useAuth();
  const platform = !!user?.platform_admin;

  const [catalog, setCatalog] = useState<PolicyCatalog | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [mode, setMode] = useState<"editor" | "simulator">("editor");

  // Editor scope target. Default to System (populated immediately, no selector
  // needed); a one-time effect rehomes a scoped admin to its own tenant once
  // auth resolves (useAuth is async, so the initial render has no user yet).
  // When embedded with scopeTenant, start on that scope directly.
  const [scope, setScope] = useState<PolicyScope>(scopeTenant ? "tenant" : "system");
  const [tenant, setTenant] = useState(scopeTenant ?? "");
  const [name, setName] = useState(""); // role id / username for role|user scopes
  const [tier, setTier] = useState<"basic" | "advanced">("basic");

  useEffect(() => {
    api.policyCatalog().then(setCatalog).catch((e) => setErr((e as Error).message));
  }, []);

  const didInit = useRef(false);
  useEffect(() => {
    if (!user || didInit.current) return;
    didInit.current = true;
    if (!user.platform_admin && user.tenant_id) {
      setScope("tenant");
      setTenant(user.tenant_id);
    }
  }, [user]);

  const ref_: PolicyRef = useMemo(() => {
    switch (scope) {
      case "system":
        return { scope: "system" };
      case "tenant":
        return { scope: "tenant", selector: tenant, tenant };
      case "role":
        return { scope: "role", selector: name, tenant };
      case "user":
        return { scope: "user", selector: name, tenant };
    }
  }, [scope, tenant, name]);

  const subject: PolicySubject = useMemo(() => {
    switch (scope) {
      case "system":
        return {};
      case "tenant":
        return { tenant };
      case "role":
        return { tenant, role: name };
      case "user":
        return { tenant, user: name };
    }
  }, [scope, tenant, name]);

  // Can the caller WRITE the chosen scope? Mirrors the backend authz.
  const canWrite = useMemo(() => {
    if (scope === "system") return platform;
    if (platform) return true;
    return !!tenant && tenant === (user?.tenant_id ?? "");
  }, [scope, platform, tenant, user]);

  // Is the chosen scope fully specified enough to resolve/edit?
  const needsTenant = scope !== "system";
  const needsName = scope === "role" || scope === "user";
  const ready = (!needsTenant || !!tenant) && (!needsName || !!name);

  if (err) return <div className="card pol-note bad">{err}</div>;
  if (!catalog) return <div className="card pol-note">Loading catalog…</div>;

  return (
    <div className="pol-page">
      <header className="pol-page-head">
        <div className="pol-title">
          <Icon name="shield" size={22} />
          <div>
            <h1>Security Policy</h1>
            <p className="admin-sub">
              NIST-aligned authentication, password, session and account-lifecycle controls, resolved deterministically through System → Tenant → Role → User.
            </p>
          </div>
        </div>
        <div className="pol-seg" role="tablist" aria-label="View">
          <button role="tab" aria-selected={mode === "editor"} className={mode === "editor" ? "active" : ""} onClick={() => setMode("editor")}>
            Editor
          </button>
          <button role="tab" aria-selected={mode === "simulator"} className={mode === "simulator" ? "active" : ""} onClick={() => setMode("simulator")}>
            Simulator
          </button>
        </div>
      </header>

      {mode === "editor" ? (
        <>
          <div className="card pol-target">
            <div className="pol-target-row">
              <div className="pol-target-field">
                <label className="mini-meta">Scope</label>
                <div className="pol-seg" role="tablist" aria-label="Scope">
                  {SCOPE_ORDER.map((sc) => (
                    <button
                      key={sc}
                      title={sc === "system" && !platform ? "System baseline — read-only (platform owner edits it)" : ""}
                      className={scope === sc ? "active" : ""}
                      onClick={() => setScope(sc)}
                    >
                      {SCOPE_LABEL[sc]}
                    </button>
                  ))}
                </div>
              </div>
              {needsTenant && (
                <div className="pol-target-field">
                  <label className="mini-meta">Tenant</label>
                  <input
                    className="pol-input"
                    value={tenant}
                    disabled={!platform}
                    placeholder="tenant id"
                    onChange={(e) => setTenant(e.target.value)}
                  />
                </div>
              )}
              {needsName && (
                <div className="pol-target-field">
                  <label className="mini-meta">{scope === "role" ? "Role" : "Username"}</label>
                  <input className="pol-input" value={name} placeholder={scope === "role" ? "role id" : "username"} onChange={(e) => setName(e.target.value)} />
                </div>
              )}
              <div className="pol-target-field pol-target-tier">
                <label className="mini-meta">Show</label>
                <div className="pol-seg">
                  <button className={tier === "basic" ? "active" : ""} onClick={() => setTier("basic")}>Basic</button>
                  <button className={tier === "advanced" ? "active" : ""} onClick={() => setTier("advanced")}>Advanced</button>
                </div>
              </div>
            </div>
            <p className="mini-meta" style={{ marginTop: 8 }}>
              {scope === "system"
                ? "The platform-wide baseline. More-specific scopes may only tighten hardened controls, never weaken them."
                : canWrite
                  ? `Editing ${SCOPE_LABEL[scope]} policy. Inherited values flow down from higher scopes; set a control to override it here.`
                  : "Read-only — this scope belongs to another tenant or the platform."}
            </p>
          </div>

          {ready ? (
            <PolicyEditor catalog={catalog} scope={scope} ref_={ref_} subject={subject} canWrite={canWrite} tier={tier} />
          ) : (
            <div className="card pol-note">
              {needsName ? `Enter a ${scope === "role" ? "role id" : "username"}${needsTenant && !tenant ? " and tenant" : ""} to view its policy.` : "Enter a tenant id to view its policy."}
            </div>
          )}
        </>
      ) : (
        <PolicySimulator catalog={catalog} />
      )}
    </div>
  );
}
