// Administration — Identity, Access, API and ITSM. All sections are LIVE against
// the Go API:
//   - Users · Roles · Tenants · API Access  → file-backed identity stores
//     (src/backend/{users,rbac,tenants,apikeys}.go)
//   - Authentication → live SSO config (/api/auth/sso/config); OIDC/SAML/LDAP
//     are brokered by Keycloak (oidc.go) with rotating refresh tokens (refresh.go)
//   - API Access → live OpenAPI reference (/api/openapi.json, openapi.go)
//   - ITSM → live ServiceNow + Jira auto-ticketing status
//     (/api/itsm/servicenow, /api/itsm/jira)
// See docs/IDENTITY_ACCESS.md · docs/API_ACCESS.md · docs/ITSM_INTEGRATION.md.

import { fmtDate, fmtDateTime } from "../lib/time";
import { useCallback, useEffect, useState } from "react";
import { api, AdminUser, AdminSession, Role, Tenant, Org, Region, RoleBinding, SecuritySettings as SecuritySettingsT, ApiKey, CreateApiKeyRequest, LdapConfig, TacacsConfig, OidcConfig, AuthTestResult, LdapRoleMapping, TokenPolicy, ExportPolicy, SmtpConfig, TwilioConfig, NtfyConfig, SlackConfig, PagerDutyConfig, TeamsConfig, SNSConfig, ContactPoint, ContactPointType, ItsmConfig, ItsmConfigInput, IntegrationConfig, ServiceNowStatus, JiraStatus, IncidentPolicy, IncidentPolicyTestFacts, TicketPolicyDecision } from "../services/api";
import { BRAND } from "../brand";
import Wizard, { WizardStep } from "../components/Wizard";
import { SsoIdpPanel } from "./AdminSsoIdp";
import { StatStrip, Stat, Skeleton, InfoTip, Modal, Segmented } from "../components/ui";
import { Group } from "../components/board/panels";
import { AwsLogo } from "../components/ConnectorLogos";
import ConnectorGlyph from "../components/ConnectorGlyph";
import { teamsErrors, snsErrors, hasErrors, FieldErrors } from "../lib/notifyValidation";
import Icon from "../components/Icon";
import { useAuth } from "../hooks/useAuth";

// ---- shared chrome ---------------------------------------------------------

function AdminHead({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="admin-head">
      <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>{title}</h2>
      <p className="admin-sub">{sub}</p>
    </div>
  );
}

// role=alert announces the failure to assistive tech when it appears (WCAG
// 3.3.1/4.1.3) — used by every admin form, so the fix lands everywhere at once.
function ErrLine({ msg }: { msg: string | null }) {
  if (!msg) return null;
  return <p role="alert" style={{ color: "var(--bad)", fontSize: "var(--fs-meta)", margin: "0 0 var(--sp-2)" }}>{msg}</p>;
}

// useReload gives a [data, error, reload, setError] tuple over an async loader.
// Curated, safe landing targets an admin can pick for the default page. Shared by
// the per-tenant override (Tenants table) and the platform default (Settings).
// (2026-08 nav redesign: same five semantics, canonical routes. The old
// "#/incident/overview" and "#/dashboards/home" both rendered the Command
// Center — the duplicate slot now points at the Operations Overview instead.
// Previously-saved legacy landings keep validating via the nav alias table.)
export const LANDING_OPTIONS: { route: string; label: string }[] = [
  { route: "#/overview/home", label: "Command Center" },
  { route: "#/overview/operations", label: "Operations Overview" },
  { route: "#/investigate/rca", label: "RCA" },
  { route: "#/operations/incidents", label: "Incidents" },
  { route: "#/investigate/topology", label: "Topology" },
];

function useReload<T>(loader: () => Promise<T>): [T | undefined, string | null, () => void, (e: string | null) => void] {
  const [data, setData] = useState<T>();
  const [err, setErr] = useState<string | null>(null);
  const reload = useCallback(() => {
    loader().then(setData).catch((e) => setErr((e as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(reload, [reload]);
  return [data, err, reload, setErr];
}

// Permission level helpers (mirror backend none<read<write<admin = 0..3).
const LEVELS = ["none", "read", "write", "admin"];
const LEVEL_VAR: Record<string, string> = {
  none: "var(--muted)", read: "var(--sev-info)", write: "var(--sev-warning)", admin: "var(--accent)",
};

// ---- Users -----------------------------------------------------------------

const BLANK_USER = { username: "", email: "", display_name: "", password: "", role: "read-only", tenant_id: "", status: "active" };

// Directory scope: just two — Global (the global tenant; tenant_id === "") or a
// specific tenant. (Collapsed from the old three-way All/Global/tenant filter.)
const SCOPE_GLOBAL = "__global__";

// UsersAdmin. When embedded in the Identity & Access page, `scopeTenant` locks the
// directory to one scope and hides the internal selector: "" = Global, a tenant id
// = that tenant. Standalone (prop undefined), it keeps its own Global/tenant picker.
export function UsersAdmin({ scopeTenant, scopeName, scopeNoun = "Tenant" }: { scopeTenant?: string; scopeName?: string; scopeNoun?: string } = {}) {
  const { user } = useAuth();
  // A super-admin in the global tenant manages every tenant's users and can scope
  // the directory to Global (the global tenant) or a specific tenant — "go into a
  // tenant to manage its users". A tenant admin is implicitly locked to its own
  // tenant (the backend only ever returns/accepts that tenant's users).
  const platform = !!user?.platform_admin;
  const locked = scopeTenant !== undefined; // embedded → scope fixed by the parent

  const [users, err, reload, setErr] = useReload(() => api.listUsers());
  const [roles] = useReload(() => api.listRoles());
  const [tenants] = useReload(() => api.listTenants());
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ ...BLANK_USER });
  const [q, setQ] = useState("");
  const [scopeState, setScope] = useState<string>(SCOPE_GLOBAL); // Global or a specific tenant
  // Effective scope: the parent's lock when embedded, else the local picker.
  const scope = locked ? (scopeTenant ? scopeTenant : SCOPE_GLOBAL) : scopeState;
  // Directory-level selection: pick one or more users, then act on them with the
  // toolbar knobs (Reset / Lock / Unlock / Delete) — no per-row action buttons.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  const roleList = roles?.roles ?? [];
  const tenantList = tenants ?? [];
  // The tenant a newly-created user should default to, given the active scope.
  const scopeTenantId = scope === SCOPE_GLOBAL ? "" : scope;
  // Provider users are associated with NOTHING (no org/tenant); tenant users are
  // fixed to their tenant. isProvider = the platform realm.
  const isProvider = scopeTenantId === "";
  // scopeName lets a non-tenant scope (an organization) supply its display name —
  // the directory is keyed by id either way, so org users get tenant_id = org id
  // (strictly associated, never global) without needing a tenant record to exist.
  const scopeTenantName = scopeName || tenantList.find((t) => t.id === scopeTenantId)?.name || scopeTenantId;
  const startAdd = () => { setErr(null); setForm({ ...BLANK_USER, tenant_id: scopeTenantId }); setAdding(true); };
  const closeAdd = () => { setAdding(false); setForm({ ...BLANK_USER }); };
  // The security settings that apply to every user created in this scope. Editable
  // right here in the Create-User dialog — `secBaseline` lets us persist them only
  // when the operator actually changed something (they're scope-wide, not per-user).
  const secScope = scopeTenantId || "provider";
  const [secSettings, setSecSettings] = useState<SecuritySettingsT | null>(null);
  const [secBaseline, setSecBaseline] = useState("");
  useEffect(() => {
    api.getSecuritySettings(secScope)
      .then((v) => { setSecSettings(v); setSecBaseline(JSON.stringify(v)); })
      .catch(() => { setSecSettings(null); setSecBaseline(""); });
  }, [secScope]);
  const updSec = (patch: Partial<SecuritySettingsT>) =>
    setSecSettings((p) => (p ? { ...p, ...patch } : p));

  const submit = async () => {
    setErr(null);
    try {
      // Scope-wide policy is saved first (only if touched), then the account.
      if (secSettings && JSON.stringify(secSettings) !== secBaseline) {
        const saved = await api.saveSecuritySettings(secScope, secSettings);
        setSecSettings(saved); setSecBaseline(JSON.stringify(saved));
      }
      await api.createUser(form);
      setForm({ ...BLANK_USER });
      setAdding(false);
      reload();
    } catch (e) { setErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); }
  };
  const changeRole = async (u: AdminUser, role: string) => {
    setErr(null);
    try { await api.updateUser(u.username, { role }); reload(); } catch (e) { setErr((e as Error).message); }
  };

  const all = users ?? [];
  // Tenant scope (super-admin only): narrow the directory to Global or a tenant.
  // "Global" = the platform namespace: untagged users plus the global tenant
  // (both resolve to the platform owner), so they aren't split across two options.
  const list = !platform
    ? all
    : scope === SCOPE_GLOBAL
      ? all.filter((u) => !u.tenant_id || u.tenant_id === "global")
      : all.filter((u) => u.tenant_id === scope);
  const isAdminRole = (role: string) => role === "super-admin" || role === "admin";
  const stats = {
    total: list.length,
    admins: list.filter((u) => isAdminRole(u.role)).length,
    disabled: list.filter((u) => u.status === "disabled").length,
    federated: list.filter((u) => u.auth_source && u.auth_source !== "local").length,
  };
  const ql = q.trim().toLowerCase();
  const shown = ql
    ? list.filter((u) => [u.username, u.email, u.display_name, u.role, u.tenant_id].some((f) => (f ?? "").toLowerCase().includes(ql)))
    : list;

  // ---- selection + bulk actions --------------------------------------------
  const toggle = (name: string) =>
    setSelected((s) => { const n = new Set(s); n.has(name) ? n.delete(name) : n.add(name); return n; });
  const allShownSelected = shown.length > 0 && shown.every((u) => selected.has(u.username));
  const toggleAll = () => setSelected(allShownSelected ? new Set() : new Set(shown.map((u) => u.username)));
  const clearSel = () => setSelected(new Set());
  const selUsers = all.filter((u) => selected.has(u.username));
  const selCount = selUsers.length;
  const isLocal = (u: AdminUser) => !u.auth_source || u.auth_source === "local";

  const runBatch = async (fn: (u: AdminUser) => Promise<unknown>) => {
    setErr(null); setBusy(true);
    try {
      for (const u of selUsers) await fn(u);
      clearSel();
      reload();
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  const lock = () => runBatch((u) => api.updateUser(u.username, { status: "disabled" }));
  const unlock = () => runBatch((u) => api.updateUser(u.username, { status: "active" }));
  const del = () => {
    if (!window.confirm(`Delete ${selCount} user${selCount > 1 ? "s" : ""}? This cannot be undone.`)) return;
    runBatch((u) => api.deleteUser(u.username));
  };
  const resetMfa = () => {
    if (!window.confirm(`Reset two-factor for ${selCount} user${selCount > 1 ? "s" : ""}? They'll sign in with just their password until they set it up again.`)) return;
    runBatch((u) => api.adminResetMfa(u.username));
  };
  const resetPw = async () => {
    if (selCount !== 1) return;
    const u = selUsers[0];
    const pw = window.prompt(`Set a new password for "${u.username}" (must meet the password policy):`);
    if (!pw) return;
    setErr(null); setBusy(true);
    try { await api.updateUser(u.username, { password: pw }); clearSel(); reload(); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };

  // Knob enablement reflects what the selection can actually do.
  const canReset = selCount === 1 && isLocal(selUsers[0]);
  const canLock = selCount > 0 && selUsers.some((u) => u.status !== "disabled");
  const canUnlock = selCount > 0 && selUsers.some((u) => u.status === "disabled");

  return (
    <>
      <AdminHead title="Users" sub={`People with access to ${BRAND}. Local accounts today; federated users (SSO/LDAP) arrive once an identity provider is configured.`} />
      <StatStrip>
        <Stat label="Users" value={users ? stats.total : <Skeleton w={26} h={22} />} />
        <Stat label="Admins" value={users ? stats.admins : "—"} tone="accent" />
        <Stat label="Disabled" value={users ? stats.disabled : "—"} tone={stats.disabled ? "warn" : ""} />
        <Stat label="Federated" value={users ? stats.federated : "—"} />
      </StatStrip>
      <div className="card">
        <div className="admin-card-head">
          <h2>Directory</h2>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            {/* Super-admin: scope the directory to Global or a specific tenant.
                Hidden when embedded in Identity & Access (the parent owns scope). */}
            {platform && !locked && (
              <select className="inline-select" value={scope} onChange={(e) => { setScope(e.target.value); clearSel(); }} aria-label="Tenant scope" title="Show users for">
                <option value={SCOPE_GLOBAL}>Global</option>
                {tenantList.filter((t) => t.id !== "global").map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            )}
            {selCount > 0 && <span className="mini-meta">{selCount} selected</span>}
            <button className="dash-btn" disabled={!canReset || busy} onClick={resetPw}
              title={selCount !== 1 ? "Select one user" : canReset ? "Set a new password" : "Federated accounts reset at the identity provider"}>
              Reset password
            </button>
            <button className="dash-btn" disabled={!canLock || busy} onClick={lock} title="Disable sign-in for the selected users">Lock</button>
            <button className="dash-btn" disabled={!canUnlock || busy} onClick={unlock} title="Re-enable the selected users">Unlock</button>
            <button className="dash-btn" disabled={selCount === 0 || busy} onClick={resetMfa} title="Reset two-factor for the selected users (lost device recovery)">Reset MFA</button>
            <button className="dash-btn" disabled={selCount === 0 || busy} onClick={del} title="Delete the selected users">Delete</button>
            <button className="dash-btn accent" onClick={startAdd}>＋ Add user</button>
          </div>
        </div>
        <ErrLine msg={err} />
        {adding && (
          <Modal
            title={isProvider ? "New Provider user" : `New user · ${scopeTenantName}`}
            subtitle={isProvider
              ? "A platform-level account — not tied to any organization or tenant. Grant it access under Access."
              : `An account scoped to ${scopeTenantName}.`}
            logo={<span className="conn-logo uf-logo"><Icon name="user" size={24} /></span>}
            onClose={closeAdd}
          >
            <ErrLine msg={err} />
            <div className="uf2-sec">Account</div>
            <div className="uf-grid">
              <label className="req-field"><span>Username <Req /></span>
                <input autoFocus value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
              <label><span>Display name</span>
                <input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></label>
              <label><span>Email</span>
                <input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
              <label className="req-field"><span>Password <Req /></span>
                <input type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
              <label><span>Role</span>
                <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                  {roleList.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
                </select></label>
              <label><span>Status</span>
                <select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
                  <option value="active">Active</option>
                  <option value="disabled">Disabled — can't sign in</option>
                </select></label>
              {/* Provider users are associated with nothing. Tenant users are fixed
                  to their tenant (no picker). Only the standalone directory picks one. */}
              {!isProvider && (
                locked ? (
                  <label><span>{scopeNoun}</span><div className="uf-fixed">{scopeTenantName}</div></label>
                ) : (
                  <label><span>{scopeNoun}</span>
                    <select value={form.tenant_id} onChange={(e) => setForm({ ...form, tenant_id: e.target.value })}>
                      <option value="">— tenant —</option>
                      {tenantList.filter((t) => t.id !== "global").map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                    </select></label>
                )
              )}
            </div>

            {secSettings && (() => {
              const ss = secSettings;
              const tog = (k: keyof SecuritySettingsT, label: string) => (
                <label className="uf-switch">
                  <input type="checkbox" checked={!!ss[k]} onChange={(e) => updSec({ [k]: e.target.checked } as Partial<SecuritySettingsT>)} />
                  <span className="uf-switch-track" aria-hidden /><span>{label}</span>
                </label>
              );
              const num = (k: keyof SecuritySettingsT, w = 84) => (
                <input className="uf-num" type="number" min={0} style={{ width: w }} value={ss[k] as number}
                  onChange={(e) => updSec({ [k]: Number(e.target.value) } as Partial<SecuritySettingsT>)} />
              );
              return (
                <>
                  <div className="uf2-sec">
                    Security settings
                    <span className="mini-meta">applies to all {isProvider ? "Provider" : scopeTenantName} users</span>
                  </div>
                  <div className="uf-secgrid">
                    <label className="uf-field"><span>Minimum password length</span>{num("min_password_length")}</label>
                    <div className="uf-field uf-span"><span>Complexity</span>
                      <div className="uf-switchrow">
                        {tog("require_uppercase", "Uppercase")}{tog("require_lowercase", "Lowercase")}
                        {tog("require_number", "Number")}{tog("require_special", "Special")}
                      </div>
                    </div>
                    <div className="uf-field uf-span"><span>Account policy</span>
                      <div className="uf-switchrow">
                        {tog("reset_on_first_login", "Must change at first login")}
                        {tog("password_history", "Remember password history")}
                      </div>
                    </div>
                    <label className="uf-field"><span>Expire password</span>
                      <div className="uf-inline">{tog("password_expire_enabled", "Enabled")}
                        {ss.password_expire_enabled && <>after {num("password_expire_days", 64)} days</>}</div>
                    </label>
                    <label className="uf-field"><span>Lockout after</span>
                      <div className="uf-inline">{num("login_attempts_allowed", 64)} tries, unlock in {num("unlock_time_seconds", 80)}s</div>
                    </label>
                    <div className="uf-field"><span>Sessions</span>
                      <Segmented<"single" | "multi">
                        value={ss.concurrent_login === "deny" ? "single" : "multi"}
                        options={[{ value: "single", label: "Single" }, { value: "multi", label: "Concurrent" }]}
                        onChange={(v) => updSec({ concurrent_login: v === "single" ? "deny" : "allow" })}
                        ariaLabel="Concurrent sessions"
                      />
                    </div>
                  </div>
                </>
              );
            })()}

            <div className="uf2-foot">
              <RequiredLegend />
              <div className="uf2-foot-btns">
                <button className="dash-btn" onClick={closeAdd}>Cancel</button>
                <button className="dash-btn accent" disabled={!form.username.trim() || !form.password} onClick={submit}>Create user</button>
              </div>
            </div>
          </Modal>
        )}
        <div className="ds-toolbar">
          <input className="ds-search" placeholder="Search users…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search users" />
          <span className="mini-meta">{shown.length} of {list.length}</span>
        </div>
        <table className="ds-table">
          <thead>
            <tr>
              <th style={{ width: 28 }}>
                <input type="checkbox" checked={allShownSelected} onChange={toggleAll} aria-label="Select all users" />
              </th>
              <th>User</th><th>Email</th><th>Role</th><th>Tenant</th><th>Auth</th><th>MFA</th><th>Status</th><th>Last active</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((u) => (
              <tr key={u.username} className={selected.has(u.username) ? "row-selected" : ""}>
                <td>
                  <input type="checkbox" checked={selected.has(u.username)} onChange={() => toggle(u.username)} aria-label={`Select ${u.username}`} />
                </td>
                <td style={{ fontWeight: 600 }}>{u.display_name || u.username}</td>
                <td className="mono">{u.email || "—"}</td>
                <td>
                  <select className="inline-select" value={u.role} onChange={(e) => changeRole(u, e.target.value)}>
                    {roleList.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
                    {!roleList.find((r) => r.id === u.role) && <option value={u.role}>{u.role}</option>}
                  </select>
                </td>
                <td>{u.tenant_id || "—"}</td>
                <td><span className="badge">{u.auth_source || "local"}</span></td>
                <td>{u.mfa_enabled ? <span className="badge good" title="Two-factor enabled">On</span> : <span className="mini-meta">—</span>}</td>
                <td><span className={`badge ${u.status === "disabled" ? "warn" : "good"}`}>{u.status || "active"}</span></td>
                <td>{u.last_login_at ? fmtDateTime(u.last_login_at) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {users && shown.length === 0 && <div className="empty">{list.length === 0 ? "No users yet." : "No users match your search."}</div>}
      </div>
    </>
  );
}

// ---- Roles (RBAC) ----------------------------------------------------------

// RolesAdmin. `scopeTenant` (a tenant id) is passed when embedded under a tenant
// in Identity & Access. Role DEFINITIONS are platform-wide today, so we surface a
// note in that case rather than implying per-tenant role editing (a backend
// follow-up). Global scope ("" / undefined) shows the normal editor.
// variant: "builtin" = the standard User Roles (read-only), "custom" = Custom
// User Roles (create/edit), "all" = both in one matrix (legacy).
export function RolesAdmin({ scopeTenant, variant = "all" }: { scopeTenant?: string; variant?: "all" | "builtin" | "custom" } = {}) {
  const [data, err, reload, setErr] = useReload(() => api.listRoles());
  const modules = data?.modules ?? [];
  const allRoles = data?.roles ?? [];
  const roles = variant === "builtin" ? allRoles.filter((r) => r.builtin)
    : variant === "custom" ? allRoles.filter((r) => !r.builtin)
    : allRoles;
  const tenantScoped = !!scopeTenant;
  const canCreate = variant !== "builtin" && !tenantScoped;

  // Click a cell on a CUSTOM role to cycle its level; persists immediately.
  const cycle = async (role: Role, module: string) => {
    if (role.builtin) return;
    const cur = role.permissions[module] ?? 0;
    const next = { ...role, permissions: { ...role.permissions, [module]: (cur + 1) % 4 } };
    setErr(null);
    try { await api.saveRole(next); reload(); } catch (e) { setErr((e as Error).message); }
  };
  const addRole = async () => {
    const name = window.prompt("New role name (e.g. NOC Engineer)");
    if (!name) return;
    setErr(null);
    try { await api.saveRole({ name, permissions: {} }); reload(); } catch (e) { setErr((e as Error).message); }
  };
  const remove = async (role: Role) => {
    setErr(null);
    try { await api.deleteRole(role.id!); reload(); } catch (e) { setErr((e as Error).message); }
  };

  const title = variant === "builtin" ? "User Roles" : variant === "custom" ? "Custom User Roles" : "Roles & Permissions";
  const sub = variant === "builtin"
    ? "The standard roles and what each can see and change. These are fixed."
    : variant === "custom"
    ? "Roles you define. Each cell sets a role’s access level."
    : "Control what each role can see and change. Built-in roles are fixed; each cell on a custom role sets its access.";
  return (
    <>
      <div className="admin-head-row">
        <AdminHead title={title} sub={sub} />
        {canCreate && <button className="dash-btn accent" onClick={addRole}>＋ New custom role</button>}
      </div>
      {tenantScoped && (
        <div className="card" style={{ fontSize: 12, color: "var(--muted)", borderLeft: "3px solid var(--accent)" }}>
          These roles are shared across the platform and shown here for reference. Assign them to this tenant's
          people in <b>Users</b>. Tenant-specific roles are not available yet.
        </div>
      )}
      <div className="card">
        <ErrLine msg={err} />
        {roles.length === 0 ? (
          <div className="empty">{variant === "custom" ? "No custom roles yet — create one to tailor access." : "No roles."}</div>
        ) : (
        <table className="ds-table">
          <thead>
            <tr><th>Role</th>{modules.map((m) => <th key={m} style={{ textTransform: "capitalize" }}>{m}</th>)}<th></th></tr>
          </thead>
          <tbody>
            {roles.map((r) => (
              <tr key={r.id}>
                <td>
                  <div style={{ fontWeight: 700 }}>{r.name} {!r.builtin && <span className="badge accent-badge">custom</span>}</div>
                  <div className="mini-meta">{r.description || (r.builtin ? "built-in" : "custom role")}</div>
                </td>
                {modules.map((m) => {
                  const lvl = LEVELS[r.permissions[m] ?? 0];
                  return (
                    <td key={m}>
                      <button
                        className="perm-pill"
                        disabled={r.builtin}
                        title={r.builtin ? "Built-in — cannot be changed" : "Change access level"}
                        style={{ color: LEVEL_VAR[lvl], borderColor: LEVEL_VAR[lvl], cursor: r.builtin ? "default" : "pointer" }}
                        onClick={() => cycle(r, m)}
                      >{lvl}</button>
                    </td>
                  );
                })}
                <td>{!r.builtin && <button className="dash-btn" onClick={() => remove(r)}>Delete</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        )}
      </div>
    </>
  );
}

// ---- Tenants (multi-tenancy) ----------------------------------------------

export function TenantsAdmin({ onManageTenant, orgId }: { onManageTenant?: (id: string, name: string) => void; orgId?: string } = {}) {
  const [tenants, err, reload, setErr] = useReload(() => api.listTenants());
  const [orgs] = useReload(() => api.listOrgs());
  const [regions] = useReload(() => api.listRegions());
  const [name, setName] = useState("");
  const [note, setNote] = useState("");
  // When embedded under an organization, the org is fixed to that org.
  const [org, setOrg] = useState(orgId ?? "global");
  const [region, setRegion] = useState("");
  const [hideGlobal, setHideGlobal] = useState(false);
  const [adding, setAdding] = useState(false); // create form hidden until clicked
  const orgName = (id?: string) => (orgs ?? []).find((o) => o.id === (id || "global"))?.name || (id || "global");
  const regionLabel = (id?: string) => id ? ((regions ?? []).find((r) => r.id === id)?.label || id) : "";
  const orgRegion = (orgId?: string) => (orgs ?? []).find((o) => o.id === (orgId || "global"))?.home_region;
  const changeTenantRegion = async (t: Tenant, value: string) => {
    setErr(null);
    try { await api.setTenantRegion(t.id, value); reload(); } catch (e) { setErr((e as Error).message); }
  };
  // Admin-configurable default landing page. Curated to real, safe nav leaves.
  // Editing the parent (global) tenant sets the PLATFORM default; a child tenant
  // overrides it for that tenant ("" = inherit).
  const changeTenantLanding = async (t: Tenant, value: string) => {
    setErr(null);
    try { await api.setTenantLanding(t.id, value); reload(); } catch (e) { setErr((e as Error).message); }
  };
  // Type-to-confirm delete modal state.
  const [delTarget, setDelTarget] = useState<Tenant | null>(null);
  const [delTyped, setDelTyped] = useState("");
  const [delForce, setDelForce] = useState(false);
  const [delErr, setDelErr] = useState<string | null>(null);
  const [delBusy, setDelBusy] = useState(false);
  // Break-glass (time-boxed, audited access into a restricted tenant) modal state.
  const [bgTarget, setBgTarget] = useState<Tenant | null>(null);
  const [bgReason, setBgReason] = useState("");
  const [bgMins, setBgMins] = useState(60);
  const [bgErr, setBgErr] = useState<string | null>(null);
  const [bgBusy, setBgBusy] = useState(false);
  const openBreakGlass = async () => {
    if (!bgTarget || !bgReason.trim()) return;
    setBgErr(null); setBgBusy(true);
    try { await api.openBreakGlass(bgTarget.id, bgReason.trim(), bgMins); setBgTarget(null); setBgReason(""); }
    catch (e) { setBgErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); }
    finally { setBgBusy(false); }
  };

  const create = async () => {
    const useOrg = orgId || org;
    if (!name.trim() || !useOrg) return;
    setErr(null);
    try { await api.createTenant(name.trim(), note.trim(), hideGlobal, useOrg, region); setName(""); setNote(""); setOrg(orgId ?? "global"); setRegion(""); setHideGlobal(false); setAdding(false); reload(); } catch (e) { setErr((e as Error).message); }
  };
  const openDelete = (t: Tenant) => { setDelTarget(t); setDelTyped(""); setDelForce(false); setDelErr(null); };
  const confirmDelete = async () => {
    if (!delTarget) return;
    setDelErr(null); setDelBusy(true);
    try {
      await api.deleteTenant(delTarget.id, delTyped.trim(), delForce);
      setDelTarget(null); reload();
    } catch (e) {
      const m = (e as Error).message;
      // 409 = tenant still has users; reveal the force option.
      if (/\b409\b|still has/.test(m)) setDelForce(true);
      setDelErr(m.replace(/^\d+[^:]*:\s*/, ""));
    } finally { setDelBusy(false); }
  };
  const toggleGlobalVisibility = async (t: Tenant) => {
    setErr(null);
    const hide = !t.operator_restricted;
    if (hide && !window.confirm(`Hide "${t.name}" from the global view?\n\nGlobal/platform-level users will no longer see this tenant's logs, flows, findings or metrics. The tenant's own users are unaffected. Use this for data-privacy / compliance.`)) return;
    try { await api.setTenantOperatorRestricted(t.id, hide); reload(); } catch (e) { setErr((e as Error).message); }
  };
  const toggleStatus = async (t: Tenant) => {
    setErr(null);
    const suspend = (t.status || "active") !== "suspended";
    if (suspend && !window.confirm(`Suspend "${t.name}"?\n\nIts users (and API keys) will be unable to sign in or make requests until you reactivate it. The platform operator is unaffected.`)) return;
    try { await api.setTenantStatus(t.id, suspend ? "suspended" : "active"); reload(); } catch (e) { setErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); }
  };

  const list = (tenants ?? []).filter((t) => !orgId || (t.org_id || "global") === orgId);
  return (
    <>
      <div className="admin-head-row">
        <AdminHead title="Tenants" sub={orgId
          ? "Optional isolation units inside this organization — create one only when you need to split (prod/dev/region). Each tenant is its own namespace."
          : "Isolation boundaries within an organization. Each tenant is its own namespace — devices, dashboards, alerts and users are scoped to it."} />
        {!adding && <button className="dash-btn accent" onClick={() => { setAdding(true); setErr(null); }}>＋ Create tenant</button>}
      </div>
      {adding && (
        <div className="card">
          <div className="admin-card-head"><h2>New tenant</h2></div>
          <ErrLine msg={err} />
          <div className="admin-form">
            <label className="req-field">
              <span>Tenant name <Req /></span>
              <input autoFocus placeholder="e.g. acme" value={name} onChange={(e) => setName(e.target.value)} />
            </label>
            {orgId ? (
              <label><span>Organization</span><div className="uf-fixed">{orgName(orgId)}</div></label>
            ) : (
              <label title="Optional — leave as Provider unless you're grouping tenants into a customer/BU org.">
                <span>Organization <span style={{ fontWeight: 400, color: "var(--muted)" }}>(optional)</span></span>
                <select value={org || "global"} onChange={(e) => { setOrg(e.target.value); setRegion(""); }}>
                  {!(orgs ?? []).some((o) => o.id === "global") && <option value="global">Provider (default)</option>}
                  {(orgs ?? []).map((o) => <option key={o.id} value={o.id}>{o.id === "global" ? `${o.name} (default)` : o.name}</option>)}
                </select>
              </label>
            )}
            <label>
              <span>Region</span>
              <select value={region} onChange={(e) => setRegion(e.target.value)}>
                <option value="">{org ? `${regionLabel(orgRegion(org))} (org)` : "From organization"}</option>
                {(regions ?? []).map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
              </select>
            </label>
            <label style={{ flex: 2 }}>
              <span>Note</span>
              <input placeholder="optional" value={note} onChange={(e) => setNote(e.target.value)} />
            </label>
            <button className="dash-btn" onClick={() => { setAdding(false); setName(""); setOrg(orgId ?? "global"); setRegion(""); setNote(""); setHideGlobal(false); setErr(null); }}>Cancel</button>
            <button className="dash-btn accent" disabled={!name.trim()} onClick={create}>Create tenant</button>
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "var(--muted)", marginTop: 8 }}>
            <input type="checkbox" checked={hideGlobal} onChange={(e) => setHideGlobal(e.target.checked)} />
            Hide this tenant's data from the global view (data privacy — global/platform users won't see its logs, flows, findings or metrics)
          </label>
          <RequiredLegend />
        </div>
      )}
      {!adding && <ErrLine msg={err} />}
      <div className="card" style={{ paddingTop: 8 }}>
        {list.length === 0 ? (
          <div className="empty">No tenants yet.</div>
        ) : (
          <table className="ds-table" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th>Tenant</th>
                <th>Type</th>
                <th>Status</th>
                <th>Organization</th>
                <th>Region</th>
                <th title="Default page users land on after sign-in (parent = platform default; child overrides)">Landing</th>
                <th>Global visibility</th>
                <th>Note</th>
                <th>ID</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {list.map((t) => {
                const isParent = t.id === "global";
                return (
                  <tr key={t.id}>
                    <td style={{ fontWeight: 600 }}>
                      {t.name}
                      <div className="mini-meta" style={{ fontFamily: "var(--mono, monospace)" }} title={t.id}>{t.slug}</div>
                    </td>
                    <td>
                      <span className={`badge ${isParent ? "accent" : ""}`}>
                        {isParent ? "Parent Tenant" : "Child Tenant"}
                      </span>
                    </td>
                    <td>
                      {!isParent && (t.status || "active") === "suspended"
                        ? <span className="badge bad">Suspended</span>
                        : <span className="badge good">Active</span>}
                    </td>
                    <td style={{ color: "var(--muted)", fontSize: 12 }}>{orgName(t.org_id)}</td>
                    <td>
                      {isParent ? (
                        <span style={{ color: "var(--muted)", fontSize: 12 }}>{regionLabel(t.region || orgRegion(t.org_id))}</span>
                      ) : (
                        <select
                          className="ds-mini-select"
                          value={t.region || ""}
                          onChange={(e) => changeTenantRegion(t, e.target.value)}
                          title="Data-residency region (blank = the organization's region)"
                        >
                          <option value="">{regionLabel(orgRegion(t.org_id))}</option>
                          {(regions ?? []).map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
                        </select>
                      )}
                    </td>
                    <td>
                      <select
                        className="ds-mini-select"
                        value={t.default_landing || ""}
                        onChange={(e) => changeTenantLanding(t, e.target.value)}
                        title={isParent
                          ? "Platform-wide default landing page (applies to tenants with no override)"
                          : "This tenant's landing page (blank = inherit the platform default)"}
                      >
                        <option value="">{isParent ? "Built-in (Dashboards)" : "Inherit platform default"}</option>
                        {LANDING_OPTIONS.map((o) => <option key={o.route} value={o.route}>{o.label}</option>)}
                      </select>
                    </td>
                    <td>
                      {isParent ? (
                        <span style={{ color: "var(--muted)", fontSize: 12 }}>—</span>
                      ) : (
                        <button
                          type="button"
                          role="switch"
                          aria-checked={!t.operator_restricted}
                          className={`vis-toggle${t.operator_restricted ? "" : " on"}`}
                          onClick={() => toggleGlobalVisibility(t)}
                          title={t.operator_restricted ? "Hidden from the global view" : "Visible in the global view"}
                        >
                          <span className="vis-knob" />
                          <span className="vis-label">{t.operator_restricted ? "No" : "Yes"}</span>
                        </button>
                      )}
                    </td>
                    <td style={{ color: "var(--muted)" }}>{t.note || "—"}</td>
                    <td className="mono" style={{ color: "var(--muted)", fontSize: 12 }}>{t.id}</td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      {!isParent && t.operator_restricted && (
                        <button className="dash-btn" style={{ marginRight: 6 }} title="Request time-boxed, audited access to this restricted tenant" onClick={() => { setBgTarget(t); setBgReason(""); setBgErr(null); }}>Break-glass</button>
                      )}
                      {!isParent && onManageTenant && (
                        <button className="dash-btn accent" style={{ marginRight: 6 }} onClick={() => onManageTenant(t.id, t.name)}>Manage →</button>
                      )}
                      {!isParent && (
                        <button className="dash-btn" style={{ marginRight: 6 }} onClick={() => toggleStatus(t)} title={(t.status || "active") === "suspended" ? "Reactivate this tenant" : "Suspend this tenant (block its users' sign-in)"}>
                          {(t.status || "active") === "suspended" ? "Reactivate" : "Suspend"}
                        </button>
                      )}
                      {!isParent && <button className="dash-btn" onClick={() => openDelete(t)}>Delete</button>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {bgTarget && (
        <Modal title="Break-glass access" subtitle={`Time-boxed, audited access to ${bgTarget.name}`} onClose={() => setBgTarget(null)}>
          <div className="dc">
            <p className="dc-lead">
              This tenant's data is hidden for compliance. Opening a break-glass session grants you access for a limited time. The reason and the session are recorded.
            </p>
            <label className="dc-field">
              <span>Reason <Req /></span>
              <input value={bgReason} autoFocus placeholder="e.g. INC-1234 investigation" onChange={(e) => setBgReason(e.target.value)} />
            </label>
            <label className="dc-field">
              <span>Duration</span>
              <select value={bgMins} onChange={(e) => setBgMins(Number(e.target.value))}>
                <option value={15}>15 minutes</option>
                <option value={60}>1 hour</option>
                <option value={240}>4 hours</option>
                <option value={480}>8 hours (max)</option>
              </select>
            </label>
            {bgErr && <p className="dc-err">{bgErr}</p>}
            <div className="dc-actions">
              <button className="dc-btn ghost" onClick={() => setBgTarget(null)} disabled={bgBusy}>Cancel</button>
              <button className="dc-btn danger" disabled={bgBusy || !bgReason.trim()} onClick={openBreakGlass}>{bgBusy ? "Opening…" : "Open break-glass session"}</button>
            </div>
          </div>
        </Modal>
      )}

      {delTarget && (
        <Modal
          title="Delete tenant"
          subtitle="This action can't be undone"
          logo={<span className="dc-badge" aria-hidden><Icon name="alerts" size={18} /></span>}
          onClose={() => setDelTarget(null)}
        >
          {(() => {
            const matches = delTyped.trim().toLowerCase() === delTarget.name.toLowerCase();
            return (
              <div className="dc">
                <p className="dc-lead">
                  You're about to permanently delete <b>{delTarget.name}</b>. This also removes everything in it:
                </p>
                <ul className="dc-list">
                  <li><Icon name="user" size={14} /> Users &amp; roles</li>
                  <li><Icon name="infrastructure" size={14} /> Devices &amp; inventory</li>
                  <li><Icon name="dashboards" size={14} /> Dashboards &amp; saved views</li>
                  <li><Icon name="alerts" size={14} /> Alerts &amp; incidents</li>
                  <li><Icon name="explore" size={14} /> Logs, flows &amp; metrics</li>
                </ul>
                <label className="dc-field">
                  <span>Type <code className="dc-chip">{delTarget.name}</code> to confirm</span>
                  <div className={`dc-input${matches ? " ok" : ""}`}>
                    <input
                      value={delTyped}
                      autoFocus
                      autoComplete="off"
                      spellCheck={false}
                      placeholder={delTarget.name}
                      onChange={(e) => setDelTyped(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter" && matches && !delBusy) confirmDelete(); }}
                    />
                    {matches && <Icon name="check" size={16} />}
                  </div>
                </label>
                {delForce && (
                  <label className="dc-force">
                    <input type="checkbox" checked={delForce} onChange={(e) => setDelForce(e.target.checked)} />
                    <span>This tenant still has users — <b>force delete anyway</b> (their accounts are orphaned).</span>
                  </label>
                )}
                {delErr && <p className="dc-err">{delErr}</p>}
                <div className="dc-actions">
                  <button className="dc-btn ghost" onClick={() => setDelTarget(null)} disabled={delBusy}>Cancel</button>
                  <button className="dc-btn danger" disabled={delBusy || !matches} onClick={confirmDelete}>
                    {delBusy ? "Deleting…" : "Delete tenant"}
                  </button>
                </div>
              </div>
            );
          })()}
        </Modal>
      )}
    </>
  );
}

// ---- Organizations (the account layer above tenants) ----------------------
//
// An Organization is the top-level customer/account. Each tenant belongs to one
// org; data region and sign-in are set on the org and inherited by its tenants.
export function OrgsAdmin({ onManageOrg }: { onManageOrg?: (id: string, name: string) => void } = {}) {
  const [orgs, err, reload, setErr] = useReload(() => api.listOrgs());
  const [regions] = useReload(() => api.listRegions());
  const [tenants] = useReload(() => api.listTenants());
  const [users] = useReload(() => api.listUsers());
  const [edit, setEdit] = useState<Org | null>(null);

  const regionLabel = (id: string) => (regions ?? []).find((r) => r.id === id)?.label || id;
  const tenantCount = (orgId: string) =>
    (tenants ?? []).filter((t) => (t.org_id || "global") === orgId).length;
  // Org members = accounts strictly associated with the org (tenant_id = org id),
  // mirroring tenant-user logic — no tenant record required. Provider members are
  // the platform-realm accounts (untagged or the global tenant), matching the
  // Users directory's Global scope.
  const memberCount = (orgId: string) =>
    orgId === "global"
      ? (users ?? []).filter((u) => !u.tenant_id || u.tenant_id === "global").length
      : (users ?? []).filter((u) => u.tenant_id === orgId).length;

  const remove = async (o: Org) => {
    if (!window.confirm(`Delete organization "${o.name}"?\n\nThis can't be undone. An organization that still has tenants can't be deleted — move or remove its tenants first.`)) return;
    setErr(null);
    try { await api.deleteOrg(o.id); reload(); }
    catch (e) { setErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); }
  };

  const list = orgs ?? [];
  return (
    <>
      <div className="admin-head-row">
        <AdminHead title="Organizations" sub="Open one to manage its users, tenants, roles and security — ＋ Add is the guided way to create anything new." />
      </div>
      <StatStrip>
        <Stat label="Organizations" value={orgs ? list.length : <Skeleton w={26} h={22} />} />
      </StatStrip>
      <ErrLine msg={err} />
      <div className="card" style={{ paddingTop: 8 }}>
        {list.length === 0 ? (
          <div className="empty">No organizations yet.</div>
        ) : (
          <table className="ds-table" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th>Organization</th>
                <th style={{ width: 150 }}>Data region</th>
                <th style={{ width: 80 }}>Users</th>
                <th style={{ width: 80 }}>Tenants</th>
                <th style={{ width: 160 }}>Sign-in</th>
                <th>Note</th>
                <th style={{ width: 1 }}></th>
              </tr>
            </thead>
            <tbody>
              {list.map((o) => {
                const isRoot = o.id === "global";
                return (
                  <tr key={o.id}>
                    <td style={{ fontWeight: 600 }}>
                      {onManageOrg
                        ? <button className="ia-linkname" onClick={() => onManageOrg(o.id, o.name)}>{o.name}</button>
                        : o.name}
                      {isRoot && <span className="badge accent" style={{ marginLeft: 6 }}>Provider</span>}
                      <div className="mini-meta" style={{ fontFamily: "var(--mono, monospace)" }} title={o.id}>{o.slug}</div>
                    </td>
                    <td><span className="badge">{regionLabel(o.home_region)}</span></td>
                    <td style={{ color: "var(--muted)" }}>{memberCount(o.id)}</td>
                    <td style={{ color: "var(--muted)" }}>{tenantCount(o.id)}</td>
                    <td style={{ color: "var(--muted)", fontSize: 12 }}>{o.sso_connection || "Platform default"}</td>
                    <td style={{ color: "var(--muted)" }}>{o.note || "—"}</td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      {onManageOrg && <button className="dash-btn accent" style={{ marginRight: 6 }} onClick={() => onManageOrg(o.id, o.name)}>Manage</button>}
                      <button className="dash-btn" style={{ marginRight: 6 }} onClick={() => setEdit(o)}>Edit</button>
                      {!isRoot && <button className="dash-btn" onClick={() => remove(o)}>Delete</button>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {edit && (
        <OrgEditModal
          org={edit}
          regions={regions ?? []}
          onClose={() => setEdit(null)}
          onSaved={() => { setEdit(null); reload(); }}
        />
      )}
    </>
  );
}

// OrgEditModal edits an org's mutable settings: data region, sign-in connection, note.
function OrgEditModal({ org, regions, onClose, onSaved }: { org: Org; regions: Region[]; onClose: () => void; onSaved: () => void }) {
  const [region, setRegion] = useState(org.home_region);
  const [sso, setSso] = useState(org.sso_connection || "");
  const [note, setNote] = useState(org.note || "");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setErr(null); setBusy(true);
    try {
      await api.updateOrg(org.id, { home_region: region, sso_connection: sso.trim(), note: note.trim() });
      onSaved();
    } catch (e) { setErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); }
    finally { setBusy(false); }
  };
  return (
    <Modal title={org.name} subtitle="Organization settings" onClose={onClose}>
      <div className="dc">
        <label className="dc-field">
          <span>Data region</span>
          <select value={region} onChange={(e) => setRegion(e.target.value)}>
            {regions.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
          </select>
        </label>
        <label className="dc-field">
          <span>Sign-in connection</span>
          <input value={sso} placeholder="Platform default" onChange={(e) => setSso(e.target.value)} />
        </label>
        <label className="dc-field">
          <span>Note</span>
          <input value={note} placeholder="optional" onChange={(e) => setNote(e.target.value)} />
        </label>
        {err && <p className="dc-err">{err}</p>}
        <div className="dc-actions">
          <button className="dc-btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="dc-btn" disabled={busy} onClick={save}>{busy ? "Saving…" : "Save changes"}</button>
        </div>
      </div>
    </Modal>
  );
}

// ---- Regions (the control-plane → routing → data-plane topology) -----------
//
// A platform-level view of the SaaS region model: one global control plane
// (orgs/identity/tenants), the routing layer (tenant→region mapping), and the
// per-region data planes. Single-region today (every region maps to the local
// stack); a region with a configured data plane shows as remote — the model is
// ready for real regions without code changes.
export function RegionsAdmin() {
  const [topo, err] = useReload(() => api.regionTopology());
  const cp = topo?.control_plane;
  const rows = topo?.regions ?? [];
  const active = rows.filter((r) => r.tenants > 0 || r.orgs > 0);
  return (
    <>
      <AdminHead title="Regions" sub="Where each tenant's data lives. Every tenant is routed to its assigned data region automatically." />
      <ErrLine msg={err} />
      <StatStrip>
        <Stat label="Management" value="Global" />
        <Stat label="Regions in use" value={topo ? active.length : <Skeleton w={20} h={20} />} tone="accent" />
        <Stat label="Tenants" value={cp?.tenants ?? "—"} />
        <Stat label="Organizations" value={cp?.orgs ?? "—"} />
      </StatStrip>

      <div className="card">
        <div className="region-topo">
          <div className="region-topo-cp">
            <div className="region-topo-tag">Global management</div>
            <div className="region-topo-sub">Organizations · Identity · Access · Tenants · Billing</div>
          </div>
          <div className="region-topo-arrow">routes by tenant → region ↓</div>
          <div className="region-topo-planes">
            {rows.map((r) => {
              const used = r.tenants > 0 || r.orgs > 0;
              return (
                <div key={r.id} className={`region-plane${used ? " used" : ""}`}>
                  <div className="region-plane-head">
                    <b>{r.label}</b>
                    <span className={`badge ${r.data_plane.local ? "" : "accent"}`}>{r.data_plane.local ? "Primary" : "Dedicated"}</span>
                  </div>
                  <div className="region-plane-meta">{r.tenants} tenant{r.tenants === 1 ? "" : "s"} · {r.orgs} org{r.orgs === 1 ? "" : "s"}</div>
                  <div className="region-plane-stack">Metrics · Logs · Flows · Analytics</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="card" style={{ paddingTop: 8 }}>
        <table className="ds-table" style={{ width: "100%" }}>
          <thead>
            <tr>
              <th>Region</th>
              <th style={{ width: 120 }}>Data plane</th>
              <th style={{ width: 90 }}>Tenants</th>
              <th style={{ width: 90 }}>Orgs</th>
              <th>Endpoint</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td style={{ fontWeight: 600 }}>{r.label}</td>
                <td><span className={`badge ${r.data_plane.local ? "" : "accent"}`}>{r.data_plane.local ? "Local" : "Dedicated"}</span></td>
                <td style={{ color: "var(--muted)" }}>{r.tenants}</td>
                <td style={{ color: "var(--muted)" }}>{r.orgs}</td>
                <td className="mono" style={{ color: "var(--muted)", fontSize: 11 }}>
                  {r.data_plane.local ? "in-cluster" : "dedicated deployment"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mini-meta" style={{ marginTop: 8 }}>
          Single-region today: every region routes to the local stack. To stand up a real region, point its data plane at a regional deployment — no code change.
        </p>
      </div>
    </>
  );
}

// ---- Identity & Access (Provider · Organizations · Tenants) ----------------
//
// One page that consolidates Users · Roles · Security Settings, split into a
// Provider section (platform-wide), per-organization, and per-tenant scopes.
// Each item is the existing admin panel, scoped via `scopeTenant`
// ("" = Global, a tenant id = that tenant). Per-tenant ROLE definitions and the MFA
// feature are backend follow-ups; surfaced here as a note / "coming soon".

type IATab = "users" | "access" | "userroles" | "customroles" | "sso" | "security" | "tenants";
const IA_TABS: { id: IATab; label: string }[] = [
  { id: "users", label: "Users" },
  { id: "userroles", label: "User Roles" },
  { id: "customroles", label: "Custom User Roles" },
  { id: "sso", label: "External SSO Roles" },
  { id: "security", label: "Security Settings" },
];
// The Provider realm manages only its own users + scope-wide security. Roles
// (built-in/custom) and external SSO role mappings are governed per-organization.
const IA_TABS_PROVIDER = IA_TABS.filter((t) => t.id === "users" || t.id === "security");
// An organization additionally owns its (optional) Tenants — isolation units it
// creates only when it needs to split (prod/dev/region). Tenants live HERE, under
// their org, not as a top-level peer.
// Org drill-in tabs: Users, then a contextual Access tab (assign from here),
// then roles/sso/security, then the org's Tenants.
const IA_TABS_ORG: { id: IATab; label: string }[] = [
  IA_TABS[0], { id: "access", label: "Access" }, ...IA_TABS.slice(1), { id: "tenants", label: "Tenants" },
];

// SecuritySettings — the scope-wide "User Global Settings": password, lockout and
// session rules that apply to everyone in this scope (provider = the platform, or
// a tenant). Per-user security (MFA, temp account, idle timeout) lives on the user.
function SecuritySettings({ scopeTenant }: { scopeTenant: string }) {
  const scope = scopeTenant || "provider";
  const [s, setS] = useState<SecuritySettingsT | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [savedTick, setSavedTick] = useState(false);
  useEffect(() => { setS(null); api.getSecuritySettings(scope).then(setS).catch((e) => setErr((e as Error).message)); }, [scope]);
  const upd = (patch: Partial<SecuritySettingsT>) => setS((p) => (p ? { ...p, ...patch } : p));
  const save = async () => {
    if (!s) return; setErr(null); setBusy(true);
    try { setS(await api.saveSecuritySettings(scope, s)); setSavedTick(true); setTimeout(() => setSavedTick(false), 1800); }
    catch (e) { setErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); } finally { setBusy(false); }
  };
  if (!s) return <div className="card"><Skeleton w={220} h={20} /></div>;
  const num = (k: keyof SecuritySettingsT) => (
    <input type="number" value={s[k] as number} onChange={(e) => upd({ [k]: Number(e.target.value) } as Partial<SecuritySettingsT>)} style={{ width: 110 }} />
  );
  const tog = (k: keyof SecuritySettingsT, label: string) => (
    <label className="ss-tog">
      <input type="checkbox" checked={s[k] as boolean} onChange={(e) => upd({ [k]: e.target.checked } as Partial<SecuritySettingsT>)} />
      {label}
    </label>
  );
  return (
    <>
      <div className="admin-head-row">
        <AdminHead title="Security Settings" sub="Password, lockout and session rules that apply to everyone in this scope. Per-person settings (2FA, temporary account) are on the user." />
        <button className="dash-btn accent" disabled={busy} onClick={save}>{busy ? "Saving…" : savedTick ? "✓ Saved" : "Save settings"}</button>
      </div>
      <ErrLine msg={err} />
      <div className="card">
        <div className="admin-card-head"><h2>Password</h2></div>
        <div className="ss-grid">
          <label><span>Minimum length</span>{num("min_password_length")}</label>
          <div className="ss-checks">
            {tog("require_uppercase", "Uppercase")}{tog("require_lowercase", "Lowercase")}
            {tog("require_number", "Number")}{tog("require_special", "Special character")}
          </div>
          <label><span>Expire password</span><div className="ss-inline">{tog("password_expire_enabled", "Enabled")}{s.password_expire_enabled && <>after {num("password_expire_days")} days</>}</div></label>
          <div className="ss-checks">{tog("password_history", "Remember password history")}{tog("reset_on_first_login", "Reset on first login")}</div>
        </div>
      </div>
      <div className="card">
        <div className="admin-card-head"><h2>Lockout &amp; session</h2></div>
        <div className="ss-grid">
          <label><span>Login attempts allowed</span>{num("login_attempts_allowed")}</label>
          <label><span>Unlock time (seconds)</span>{num("unlock_time_seconds")}</label>
          <label><span>Account validity (days)</span>{num("account_validity_days")}</label>
          <label><span>Account inactivity (days)</span>{num("account_inactivity_days")}</label>
          <label><span>Concurrent login</span>
            <select value={s.concurrent_login} onChange={(e) => upd({ concurrent_login: e.target.value })}>
              <option value="allow">Allow</option><option value="deny">Deny</option>
            </select>
          </label>
          <label>
            <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
              Sign out after inactivity (min)
              <InfoTip label="Idle timeout: users inactive longer than this are signed out at their next request. Configurable per Provider, Organization and Tenant. Sessions also have a fixed maximum lifetime enforced behind the scenes.">
                Idle timeout — a session with no activity for this many minutes is ended (checked at the token-refresh boundary). Set per scope. A fixed maximum session lifetime applies on top, as a standard default.
              </InfoTip>
            </span>
            {num("idle_timeout_minutes")}
          </label>
        </div>
      </div>
    </>
  );
}

// BindingsAdmin — the Access screen (L2 governance, /admin/bindings): a
// principal's role bindings (principal → role → scope). Grant a user access to a
// tenant or org, deny, or revoke. The server enforces no-escalation (an org-admin
// can only grant within its org, never super-admin / platform).
export function BindingsAdmin() {
  const [bindings, err, reload, setErr] = useReload(() => api.listBindings());
  const [roles] = useReload(() => api.listRoles());
  const [tenants] = useReload(() => api.listTenants());
  const [orgs] = useReload(() => api.listOrgs());
  const [users] = useReload(() => api.listUsers());
  const [granting, setGranting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [principal, setPrincipal] = useState("");
  const [roleId, setRoleId] = useState("operator");
  const [scopeId, setScopeId] = useState("");
  const [effect, setEffect] = useState("allow");

  // Scope is ORGANIZATIONS only — the Provider realm (global) is excluded (it has
  // its own dedicated console) and tenants are hidden for now. So an operator
  // grants a person access to an organization, then picks their role.
  const scopeOptions = (orgs ?? [])
    .filter((o) => o.id !== "global")
    .map((o) => ({ id: `org:${o.id}`, label: o.name }));
  const userList = (users ?? []).slice().sort((a, b) =>
    (a.display_name || a.username).localeCompare(b.display_name || b.username));

  const openGrant = () => {
    setErr(null); setPrincipal(""); setRoleId("operator");
    setScopeId(scopeOptions.length === 1 ? scopeOptions[0].id : ""); setEffect("allow");
    setGranting(true);
  };
  const grant = async () => {
    if (!principal || !scopeId) return;
    setErr(null); setBusy(true);
    try {
      await api.grantBinding({ principal_id: principal, role_id: roleId, scope_id: scopeId, effect });
      setGranting(false); reload();
    } catch (e) { setErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); } finally { setBusy(false); }
  };
  const revoke = async (b: RoleBinding) => {
    if (!window.confirm(`Revoke ${b.role_id} on ${labelScope(b.scope_id)} for ${b.principal_id}?`)) return;
    setErr(null);
    try { await api.revokeBinding(b.id); reload(); } catch (e) { setErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); }
  };

  const list = bindings ?? [];
  // Friendly scope labels for the table (covers org / tenant / platform bindings).
  function labelScope(id: string) {
    if (id === "platform") return "Platform";
    const [kind, rest] = id.split(":");
    if (kind === "org") return (orgs ?? []).find((o) => o.id === rest)?.name || id;
    if (kind === "tenant") return (tenants ?? []).find((t) => t.id === rest)?.name || id;
    return id;
  }
  return (
    <>
      <div className="admin-head-row">
        <AdminHead title="Assign access" sub="Who can do what, where. Give a person a role on an organization; access can be revoked any time. You can also assign from an org's Access tab." />
        <button className="dash-btn accent" onClick={openGrant}>＋ Assign access</button>
      </div>
      <StatStrip>
        <Stat label="Bindings" value={bindings ? list.length : <Skeleton w={26} h={22} />} />
        <Stat label="People with access" value={bindings ? new Set(list.map((b) => b.principal_id)).size : "—"} tone="accent" />
      </StatStrip>
      <ErrLine msg={err} />

      {granting && (
        <Modal
          title="Grant access"
          subtitle="Give a person a role on an organization."
          logo={<span className="conn-logo uf-logo"><Icon name="key" size={22} /></span>}
          onClose={() => setGranting(false)}
        >
          <ErrLine msg={err} />
          <div className="grant-form">
            <label className="req-field"><span>Person <Req /></span>
              <select autoFocus value={principal} onChange={(e) => setPrincipal(e.target.value)}>
                <option value="">Select a person…</option>
                {userList.map((u) => (
                  <option key={u.username} value={u.username}>
                    {u.display_name ? `${u.display_name} (${u.username})` : u.username}
                  </option>
                ))}
              </select>
              {userList.length === 0 && <span className="mini-meta">No users yet — create one under Provider → Users first.</span>}
            </label>
            <label className="req-field"><span>Organization <Req /></span>
              <select value={scopeId} onChange={(e) => setScopeId(e.target.value)}>
                <option value="">Select an organization…</option>
                {scopeOptions.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
              </select>
              {scopeOptions.length === 0 && <span className="mini-meta">No organizations yet — create one under Organizations first.</span>}
            </label>
            <label><span>Role</span>
              <select value={roleId} onChange={(e) => setRoleId(e.target.value)}>
                {(roles?.roles ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </select>
            </label>
            <div className="uf-field"><span>Effect</span>
              <Segmented<"allow" | "deny">
                value={effect as "allow" | "deny"}
                options={[{ value: "allow", label: "Allow" }, { value: "deny", label: "Deny" }]}
                onChange={(v) => setEffect(v)}
                ariaLabel="Effect"
              />
            </div>
          </div>
          <div className="uf2-foot">
            <RequiredLegend />
            <div className="uf2-foot-btns">
              <button className="dash-btn" onClick={() => setGranting(false)} disabled={busy}>Cancel</button>
              <button className="dash-btn accent" disabled={!principal || !scopeId || busy} onClick={grant}>{busy ? "Granting…" : "Grant access"}</button>
            </div>
          </div>
        </Modal>
      )}

      <div className="card" style={{ paddingTop: 8 }}>
        {list.length === 0 ? (
          <div className="empty">No access bindings yet.</div>
        ) : (
          <table className="ds-table" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th>Person</th>
                <th style={{ width: 130 }}>Role</th>
                <th>Scope</th>
                <th style={{ width: 90 }}>Effect</th>
                <th>Granted by</th>
                <th style={{ width: 1 }}></th>
              </tr>
            </thead>
            <tbody>
              {list.map((b) => (
                <tr key={b.id}>
                  <td style={{ fontWeight: 600 }}>{b.principal_id}</td>
                  <td><span className="badge">{b.role_id}</span></td>
                  <td style={{ color: "var(--muted)", fontSize: 12 }}>{labelScope(b.scope_id)}</td>
                  <td>{b.effect === "deny" ? <span className="badge" style={{ color: "var(--bad)" }}>Deny</span> : <span className="badge accent">Allow</span>}</td>
                  <td style={{ color: "var(--muted)", fontSize: 12 }}>{b.granted_by || "—"}</td>
                  <td style={{ textAlign: "right" }}>
                    <button className="dash-btn" onClick={() => revoke(b)}>Revoke</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

// IAItems renders the per-scope identity panels. All scopes use the same account
// directory (UsersAdmin), keyed by id — an organization is just another scope id,
// so org users get tenant_id = org id (strictly associated, never global) using
// the exact tenant logic, WITHOUT requiring a tenant record to exist. `tabs` lets
// the Provider show a slimmer set (roles + SSO mappings live per-organization).
function IAItems({ kind, id = "", name, tabs = IA_TABS, deepTab }: {
  kind: "provider" | "tenant" | "org"; id?: string; name?: string; tabs?: { id: IATab; label: string }[];
  /** Flyout deep-link (#/admin/identity/<sub>): switch to this tab when it
   *  exists in this scope's tab set; ignored otherwise (e.g. provider realm
   *  has no roles/SSO tabs — the closest honest view is its default). */
  deepTab?: IATab;
}) {
  const [tab, setTab] = useState<IATab>(deepTab && tabs.some((t) => t.id === deepTab) ? deepTab : tabs[0]?.id ?? "users");
  // Re-apply when the suffix changes while mounted (flyout click on this page).
  useEffect(() => {
    if (deepTab && tabs.some((t) => t.id === deepTab)) setTab(deepTab);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deepTab]);
  const cur = tabs.some((t) => t.id === tab) ? tab : (tabs[0]?.id ?? "users");
  const roleScope = kind === "provider" ? undefined : id;  // platform-wide role defs; scoped note when set
  return (
    <>
      <div className="ia-tabs" role="tablist">
        {tabs.map((t) => (
          <button key={t.id} role="tab" aria-selected={cur === t.id} className={cur === t.id ? "on" : ""} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      {cur === "users" && <UsersAdmin scopeTenant={id} scopeName={kind === "org" ? name : undefined} scopeNoun={kind === "org" ? "Organization" : "Tenant"} />}
      {cur === "access" && <OrgAccessPanel orgId={id} orgName={name} />}
      {cur === "userroles" && <RolesAdmin scopeTenant={roleScope} variant="builtin" />}
      {cur === "customroles" && <RolesAdmin scopeTenant={roleScope} variant="custom" />}
      {cur === "sso" && <SsoRolesPanel />}
      {cur === "security" && <SecuritySettings scopeTenant={id} />}
      {cur === "tenants" && <OrgTenants orgId={id} orgName={name || id} />}
    </>
  );
}

// OrgTenants — the (optional) Tenants tab inside an organization. Lists only this
// org's tenants and drills into one to manage its users/roles/security — the same
// IAItems, one level deeper. Tenants are created here, pre-bound to the org.
function OrgTenants({ orgId, orgName }: { orgId: string; orgName: string }) {
  const [sel, setSel] = useState<{ id: string; name: string } | null>(null);
  if (sel) {
    return (
      <>
        <div className="ia-crumb">
          <button className="dash-btn" onClick={() => setSel(null)}>← {orgName} tenants</button>
          <span className="ia-crumb-name">{sel.name}</span>
          <span className="mini-meta">tenant — configured independently</span>
        </div>
        <IAItems kind="tenant" id={sel.id} name={sel.name} />
      </>
    );
  }
  return <TenantsAdmin orgId={orgId} onManageTenant={(id, name) => setSel({ id, name })} />;
}

// OrgAccessPanel — the contextual "Access" tab on an org drill-in (Phase 4):
// who has a role in THIS org, plus Assign-access here (scope pre-fixed to the
// org). Same grantBinding model as the global Access screen, scoped.
function OrgAccessPanel({ orgId, orgName }: { orgId: string; orgName?: string }) {
  const scope = `org:${orgId}`;
  const [bindings, err, reload, setErr] = useReload(() => api.listBindings());
  const [roles] = useReload(() => api.listRoles());
  const [users] = useReload(() => api.listUsers());
  const [assigning, setAssigning] = useState(false);
  const [principal, setPrincipal] = useState("");
  const [roleId, setRoleId] = useState("operator");
  const [busy, setBusy] = useState(false);

  const list = (bindings ?? []).filter((b) => b.scope_id === scope);
  const roleList = roles?.roles ?? [];
  const userList = (users ?? []).slice().sort((a, b) => (a.display_name || a.username).localeCompare(b.display_name || b.username));

  const assign = async () => {
    if (!principal) return;
    setErr(null); setBusy(true);
    try { await api.grantBinding({ principal_id: principal, role_id: roleId, scope_id: scope, effect: "allow" }); setAssigning(false); reload(); }
    catch (e) { setErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); } finally { setBusy(false); }
  };
  const revoke = async (b: RoleBinding) => {
    if (!window.confirm(`Revoke ${b.role_id} for ${b.principal_id} in ${orgName || "this organization"}?`)) return;
    setErr(null);
    try { await api.revokeBinding(b.id); reload(); } catch (e) { setErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); }
  };

  return (
    <>
      <div className="admin-head-row">
        <AdminHead title="Access" sub={`Who has a role in ${orgName || "this organization"}. Assign an existing user a role — scope is this org.`} />
        <button className="dash-btn accent" onClick={() => { setPrincipal(""); setRoleId("operator"); setErr(null); setAssigning(true); }}>＋ Assign access</button>
      </div>
      <ErrLine msg={err} />
      <div className="card" style={{ paddingTop: 8 }}>
        {bindings && list.length === 0 ? (
          <div className="empty">No one is assigned to {orgName || "this organization"} yet. Use <b>Assign access</b> to grant an existing user a role here.</div>
        ) : (
          <table className="ds-table" style={{ width: "100%" }}>
            <thead><tr><th>User</th><th>Role</th><th style={{ width: 1 }}></th></tr></thead>
            <tbody>
              {list.map((b) => (
                <tr key={b.id}>
                  <td style={{ fontWeight: 600 }}>{b.principal_id}</td>
                  <td><span className="badge">{b.role_id}</span></td>
                  <td style={{ textAlign: "right" }}><button className="dash-btn" onClick={() => revoke(b)}>Revoke</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {assigning && (
        <Modal title="Assign access" subtitle={`Give a person a role in ${orgName || "this organization"}.`} logo={<span className="conn-logo uf-logo"><Icon name="key" size={22} /></span>} onClose={() => setAssigning(false)}>
          <ErrLine msg={err} />
          <div className="admin-form">
            <label className="req-field"><span>User <Req /></span>
              <select value={principal} onChange={(e) => setPrincipal(e.target.value)}>
                <option value="">Select a user…</option>
                {userList.map((u) => <option key={u.username} value={u.username}>{u.display_name || u.username}</option>)}
              </select></label>
            <label className="req-field"><span>Role <Req /></span>
              <select value={roleId} onChange={(e) => setRoleId(e.target.value)}>
                {roleList.length === 0 ? <option value="operator">operator</option> : roleList.map((r) => <option key={r.id} value={r.id}>{r.name || r.id}</option>)}
              </select></label>
            <label><span>Scope</span><div className="uf-fixed">{orgName || orgId}</div></label>
          </div>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 12 }}>
            <button className="dash-btn" onClick={() => setAssigning(false)}>Cancel</button>
            <button className="dash-btn accent" disabled={!principal || busy} onClick={assign}>{busy ? "Assigning…" : "Assign"}</button>
          </div>
        </Modal>
      )}
    </>
  );
}

// SsoRolesPanel — external SSO/IdP group → role mappings live in Authentication
// today; this surfaces the link until they're moved inline.
function SsoRolesPanel() {
  return (
    <div className="card" style={{ color: "var(--muted)" }}>
      External SSO role mappings (IdP group → role) are configured under
      <b> Administration → Authentication</b> for each connected identity provider.
      They'll move inline here next.
    </div>
  );
}

// GuidedSetupWizard — THE single "＋ Add" path for Identity & Access. One guided
// flow replaces every entry point that used to be a separate button or screen
// (create organization / onboard customer / create tenant / create user / assign
// access): the first step picks WHAT to set up, the remaining steps adapt.
// Nothing is created until Finish.
type AddMode = "org" | "tenant" | "user" | "access";
function GuidedSetupWizard({ onDone, onClose }: { onDone: () => void; onClose: () => void }) {
  const [regions, setRegions] = useState<Region[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  useEffect(() => {
    Promise.all([
      api.listRegions().catch(() => [] as Region[]),
      api.listRoles().catch(() => ({ modules: [], roles: [] as Role[] })),
      api.listOrgs().catch(() => [] as Org[]),
      api.listTenants().catch(() => [] as Tenant[]),
      api.listUsers().catch(() => [] as AdminUser[]),
    ]).then(([r, rl, o, t, u]) => { setRegions(r); setRoles(rl.roles || []); setOrgs(o); setTenants(t); setUsers(u); });
  }, []);
  const rlabel = (id?: string) => (id ? (regions.find((r) => r.id === id)?.label || id) : "");
  const customerOrgs = orgs.filter((o) => o.id !== "global");

  const [mode, setMode] = useState<AddMode>("org");

  // Organization (org mode).
  const [oName, setOName] = useState(""); const [oRegion, setORegion] = useState("us-east"); const [oSso, setOSso] = useState("");
  // Tenant — optional first tenant in org mode; the subject in tenant mode.
  const [makeTenant, setMakeTenant] = useState(true);
  const [tName, setTName] = useState(""); const [tRegion, setTRegion] = useState("");
  const [tOrg, setTOrg] = useState("global"); // tenant mode: where the tenant lives
  // User — optional in org/tenant modes; the subject in user mode.
  const [makeUser, setMakeUser] = useState(true);
  const [uName, setUName] = useState(""); const [uEmail, setUEmail] = useState(""); const [uPass, setUPass] = useState(""); const [uRole, setURole] = useState("operator");
  const [uScope, setUScope] = useState(""); // user mode placement: "" = Provider, else org/tenant id
  // Access grant (access mode).
  const [aPrincipal, setAPrincipal] = useState(""); const [aRole, setARole] = useState("operator");
  const [aScope, setAScope] = useState(""); const [aEffect, setAEffect] = useState<"allow" | "deny">("allow");

  const opt = <span style={{ fontWeight: 400, color: "var(--muted)" }}>(optional)</span>;
  const roleOptions = roles.length === 0
    ? <option value="operator">operator</option>
    : roles.map((r) => <option key={r.id} value={r.id}>{r.name || r.id}</option>);
  const userList = users.slice().sort((a, b) => (a.display_name || a.username).localeCompare(b.display_name || b.username));
  const scopeName = (id: string) =>
    id === "" ? "Provider (platform)" :
    orgs.find((o) => o.id === id)?.name || tenants.find((t) => t.id === id)?.name || id;

  const finish = async () => {
    if (mode === "access") {
      await api.grantBinding({ principal_id: aPrincipal, role_id: aRole, scope_id: aScope, effect: aEffect });
      onDone(); return;
    }
    if (mode === "user") {
      await api.createUser({ username: uName.trim(), email: uEmail.trim() || undefined, display_name: uName.trim(), password: uPass || undefined, role: uRole, tenant_id: uScope, status: "active" });
      onDone(); return;
    }
    // org / tenant modes: create the chain in order.
    let orgId = tOrg;
    if (mode === "org") {
      const o = await api.createOrg(oName.trim(), { homeRegion: oRegion, ssoConnection: oSso.trim() || undefined });
      orgId = o.id;
    }
    let userHome = orgId; // no tenant → the user is an org (or Provider) member
    if (mode === "tenant" || makeTenant) {
      const t = await api.createTenant(tName.trim(), "", false, orgId, tRegion);
      userHome = t.id;
    }
    if (makeUser) {
      await api.createUser({ username: uName.trim(), email: uEmail.trim() || undefined, display_name: uName.trim(), password: uPass || undefined, role: uRole, tenant_id: userHome === "global" ? "" : userHome, status: "active" });
    }
    onDone();
  };

  const sRow = (n: string, label: string, val: string, muted?: boolean) => (
    <div style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
      <span style={{ width: 18, height: 18, borderRadius: 9, background: "var(--surface-2)", color: "var(--muted)", fontSize: 11, display: "inline-grid", placeItems: "center", flexShrink: 0 }}>{n}</span>
      <span style={{ color: "var(--muted)", minWidth: 96 }}>{label}</span>
      <span style={{ color: muted ? "var(--muted)" : "var(--fg)", fontWeight: muted ? 400 : 600 }}>{val}</span>
    </div>
  );

  // Step 1 — what to add. The four cards are the four things this wizard creates.
  const MODES: { id: AddMode; name: string; desc: string }[] = [
    { id: "org", name: "Customer organization", desc: "A customer or business-unit grouping — optionally with its first tenant and user." },
    { id: "tenant", name: "Tenant", desc: "A workspace that holds devices & data — under the Provider or an organization." },
    { id: "user", name: "User", desc: "A person — under the Provider, an organization or a tenant, with a role." },
    { id: "access", name: "Access grant", desc: "Give an existing person a role on an organization." },
  ];
  const modeStep: WizardStep = {
    id: "what", title: "What to add", hint: "One guided path for everything — pick what you want to set up.",
    isValid: () => true,
    render: () => (
      <div style={{ display: "grid", gap: 8 }}>
        {MODES.map((m) => (
          <label key={m.id} style={{
            display: "flex", gap: 10, alignItems: "flex-start", padding: "10px 12px", borderRadius: 8, cursor: "pointer",
            border: `1px solid ${mode === m.id ? "var(--accent)" : "var(--border, var(--panel-border))"}`,
            background: mode === m.id ? "var(--accent-soft)" : "var(--surface-2)",
          }}>
            <input type="radio" name="add-mode" checked={mode === m.id} onChange={() => setMode(m.id)} style={{ marginTop: 3 }} />
            <span style={{ display: "grid", gap: 2 }}>
              <span style={{ fontWeight: 650 }}>{m.name}</span>
              <span className="mini-meta">{m.desc}</span>
            </span>
          </label>
        ))}
      </div>
    ),
  };

  const orgStep: WizardStep = {
    id: "org", title: "Organization", hint: "The customer/BU account. Its tenants inherit region and sign-in.",
    isValid: () => !!oName.trim(),
    render: () => (
      <div className="admin-form">
        <label className="req-field"><span>Organization name <Req /></span><input autoFocus placeholder="e.g. Acme Corp" value={oName} onChange={(e) => setOName(e.target.value)} /></label>
        <label><span>Home region</span><select value={oRegion} onChange={(e) => setORegion(e.target.value)}>{regions.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}</select></label>
        <label style={{ flex: 2 }}><span>SSO connection {opt}</span><input placeholder="e.g. okta (bind later in Authentication)" value={oSso} onChange={(e) => setOSso(e.target.value)} /></label>
      </div>
    ),
  };

  const tenantStep = (required: boolean): WizardStep => ({
    id: "tenant",
    title: required ? "Tenant" : "First tenant",
    hint: required ? "The workspace that holds devices & data." : "Optional — add the organization's first tenant now.",
    isValid: () => (required || makeTenant ? !!tName.trim() : true),
    render: () => (
      <div style={{ display: "grid", gap: 12 }}>
        {!required && (
          <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input type="checkbox" checked={makeTenant} onChange={(e) => setMakeTenant(e.target.checked)} />
            <span>Create a first tenant now</span>
          </label>
        )}
        {(required || makeTenant) && (
          <div className="admin-form">
            <label className="req-field"><span>Tenant name <Req /></span><input autoFocus placeholder="e.g. acme-prod" value={tName} onChange={(e) => setTName(e.target.value)} /></label>
            {required ? (
              <label><span>Organization</span>
                <select value={tOrg} onChange={(e) => setTOrg(e.target.value)}>
                  <option value="global">Provider (platform)</option>
                  {customerOrgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
                </select></label>
            ) : (
              <label><span>Organization</span><div className="uf-fixed">{oName.trim() || "new organization"}</div></label>
            )}
            <label><span>Region <span style={{ fontWeight: 400, color: "var(--muted)" }}>(inherited)</span></span>
              <select value={tRegion} onChange={(e) => setTRegion(e.target.value)}>
                <option value="">{required ? "From the organization" : `From ${oName.trim() || "organization"} (${rlabel(oRegion)})`}</option>
                {regions.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
              </select></label>
          </div>
        )}
      </div>
    ),
  });

  // User fields — shared by every mode that can create a person. In user mode the
  // person also picks WHERE they live (Provider / org / tenant); in org/tenant
  // modes placement follows what the wizard just created.
  const userFields = (withScope: boolean, autoFocus: boolean) => (
    <div className="admin-form">
      {withScope && (
        <label><span>Belongs to</span>
          <select value={uScope} onChange={(e) => setUScope(e.target.value)}>
            <option value="">Provider (platform)</option>
            {customerOrgs.length > 0 && (
              <optgroup label="Organizations">
                {customerOrgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
              </optgroup>
            )}
            {tenants.length > 0 && (
              <optgroup label="Tenants">
                {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </optgroup>
            )}
          </select></label>
      )}
      <label className="req-field"><span>Username <Req /></span><input autoFocus={autoFocus} placeholder="e.g. jdoe" value={uName} onChange={(e) => setUName(e.target.value)} /></label>
      <label><span>Email {opt}</span><input placeholder="jdoe@example.com" value={uEmail} onChange={(e) => setUEmail(e.target.value)} /></label>
      <label><span>Password {opt}</span><input type="password" placeholder="blank = set later / via SSO" value={uPass} onChange={(e) => setUPass(e.target.value)} /></label>
      <label><span>Role</span><select value={uRole} onChange={(e) => setURole(e.target.value)}>{roleOptions}</select></label>
    </div>
  );

  const userOptStep: WizardStep = {
    id: "user", title: "First user", hint: "Optional — create a person here, with their role (access included).",
    isValid: () => !makeUser || !!uName.trim(),
    render: () => (
      <div style={{ display: "grid", gap: 12 }}>
        <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <input type="checkbox" checked={makeUser} onChange={(e) => setMakeUser(e.target.checked)} />
          <span>Create a first user</span>
        </label>
        {makeUser && userFields(false, false)}
      </div>
    ),
  };

  const userStep: WizardStep = {
    id: "user", title: "User & access", hint: "Create the person and their role in one step — where they belong decides what they see.",
    isValid: () => !!uName.trim(),
    render: () => userFields(true, true),
  };

  const accessStep: WizardStep = {
    id: "access", title: "Access grant", hint: "Give an existing person a role on an organization. Revocable any time.",
    isValid: () => !!aPrincipal && !!aScope,
    render: () => (
      <div className="admin-form">
        <label className="req-field"><span>Person <Req /></span>
          <select autoFocus value={aPrincipal} onChange={(e) => setAPrincipal(e.target.value)}>
            <option value="">Select a person…</option>
            {userList.map((u) => <option key={u.username} value={u.username}>{u.display_name ? `${u.display_name} (${u.username})` : u.username}</option>)}
          </select></label>
        <label className="req-field"><span>Organization <Req /></span>
          <select value={aScope} onChange={(e) => setAScope(e.target.value)}>
            <option value="">Select an organization…</option>
            {customerOrgs.map((o) => <option key={o.id} value={`org:${o.id}`}>{o.name}</option>)}
          </select></label>
        <label><span>Role</span><select value={aRole} onChange={(e) => setARole(e.target.value)}>{roleOptions}</select></label>
        <label><span>Effect</span>
          <select value={aEffect} onChange={(e) => setAEffect(e.target.value as "allow" | "deny")}>
            <option value="allow">Allow</option><option value="deny">Deny</option>
          </select></label>
      </div>
    ),
  };

  const reviewStep: WizardStep = {
    id: "review", title: "Review & create", hint: "Here's what will be set up, in order.",
    isValid: () => true,
    render: () => (
      <div style={{ display: "grid", gap: 10, fontSize: 13 }}>
        {mode === "org" && (<>
          {sRow("1", "Organization", `${oName.trim() || "—"} · ${rlabel(oRegion)}`)}
          {makeTenant ? sRow("2", "Tenant", `${tName.trim() || "—"} · ${tRegion ? rlabel(tRegion) : "inherited region"}`) : sRow("2", "Tenant", "skipped — add one later", true)}
          {makeUser ? sRow("3", "User", `${uName.trim() || "—"} · role ${uRole}`) : sRow("3", "User", "skipped", true)}
        </>)}
        {mode === "tenant" && (<>
          {sRow("1", "Tenant", `${tName.trim() || "—"} · under ${scopeName(tOrg === "global" ? "" : tOrg)} · ${tRegion ? rlabel(tRegion) : "inherited region"}`)}
          {makeUser ? sRow("2", "User", `${uName.trim() || "—"} · role ${uRole}`) : sRow("2", "User", "skipped", true)}
        </>)}
        {mode === "user" && sRow("1", "User", `${uName.trim() || "—"} · role ${uRole} · under ${scopeName(uScope)}`)}
        {mode === "access" && sRow("1", "Access", `${aPrincipal || "—"} → ${aRole} (${aEffect}) on ${aScope ? scopeName(aScope.replace(/^org:/, "")) : "—"}`)}
        <div className="mini-meta" style={{ marginTop: 6 }}>Click Create to set this up. Everything here can be managed later from the Organizations tree.</div>
      </div>
    ),
  };

  const steps: WizardStep[] =
    mode === "org" ? [modeStep, orgStep, tenantStep(false), userOptStep, reviewStep] :
    mode === "tenant" ? [modeStep, tenantStep(true), userOptStep, reviewStep] :
    mode === "user" ? [modeStep, userStep, reviewStep] :
    [modeStep, accessStep, reviewStep];

  return (
    <Modal title="Add" subtitle="One guided path — organization, tenant, user or access grant." onClose={onClose}>
      <Wizard steps={steps} onFinish={finish} onCancel={onClose} finishLabel="Create" />
    </Modal>
  );
}
// Flyout deep-link vocabulary for Identity & Access (#/admin/identity/<sub>) —
// the nav sub-items. Same suffix mechanism as admin/api's tiles.
const IDENTITY_SUBS = ["users", "roles", "sso", "orgs"] as const;
const IDENTITY_DEEP_TAB: Record<string, IATab> = { users: "users", roles: "userroles", sso: "sso" };
function identitySub(): string {
  const seg = window.location.hash.replace(/^#\/?/, "").split("?")[0].split("/")[2] ?? "";
  return (IDENTITY_SUBS as readonly string[]).includes(seg) ? seg : "";
}

export function IdentityAccess() {
  const { user } = useAuth();
  const platform = !!user?.platform_admin;
  const [sel, setSel] = useState<{ id: string; name: string } | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [refresh, setRefresh] = useState(0);
  // Deep-link suffix (users/roles/sso/orgs), re-read on hashchange so a flyout
  // sub-item click while ALREADY here switches views instead of looking dead.
  const [deepSub, setDeepSub] = useState<string>(identitySub);
  useEffect(() => {
    const read = () => setDeepSub(identitySub());
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, []);
  // "orgs" returns the platform view to the Organizations tree; users/roles/sso
  // pick the matching tab in whichever scope is open (tenant admins have no
  // tree — their IAItems gets the tab directly).
  useEffect(() => {
    if (deepSub === "orgs") setSel(null);
  }, [deepSub]);
  const deepTab = IDENTITY_DEEP_TAB[deepSub];

  // A tenant admin governs only its own tenant — no Provider, no picker.
  if (!platform) {
    return (
      <>
        <AdminHead title="Identity & Access" sub="Users, roles and security settings for your tenant." />
        <IAItems kind="tenant" id={user?.tenant_id || ""} deepTab={deepTab} />
      </>
    );
  }

  // One tree: Organizations, with the Provider (the platform's own realm) as a
  // clickable root-level row. Users live under whichever org/tenant they belong
  // to; ＋ Add is the single guided way to create anything here.
  const isProvider = sel?.id === "global";
  return (
    <>
      <div className="admin-head-row">
        <AdminHead title="Identity & Access" sub="Organizations, their tenants, and the people inside them — one tree. Open the Provider row to manage the platform's own users." />
        <button className="dash-btn accent" onClick={() => setShowAdd(true)}>＋ Add</button>
      </div>
      {showAdd && <GuidedSetupWizard onClose={() => setShowAdd(false)} onDone={() => { setShowAdd(false); setSel(null); setRefresh((r) => r + 1); }} />}

      {sel ? (
        <>
          <div className="ia-crumb">
            <button className="dash-btn" onClick={() => setSel(null)}>← Organizations</button>
            <span className="ia-crumb-name">{sel.name}</span>
            <span className="mini-meta">{isProvider ? "the platform's own realm — users · security" : "users · access · roles · security · tenants"}</span>
          </div>
          {isProvider
            ? <IAItems kind="provider" tabs={IA_TABS_PROVIDER} deepTab={deepTab} />
            : <IAItems kind="org" id={sel.id} name={sel.name} tabs={IA_TABS_ORG} deepTab={deepTab} />}
        </>
      ) : (
        <OrgsAdmin key={refresh} onManageOrg={(id, name) => setSel({ id, name })} />
      )}
    </>
  );
}

// ---- Sessions (admin: live session listing + revocation) -------------------

export function SessionsAdmin() {
  const [sessions, err, reload, setErr] = useReload(() => api.listSessions());
  const [q, setQ] = useState("");
  const list = sessions ?? [];
  const active = list.filter((s) => s.status === "active");
  const ql = q.trim().toLowerCase();
  const shown = ql
    ? list.filter((s) => [s.user_id, s.display_name, s.issued_ip, s.tenant_id].some((f) => (f ?? "").toLowerCase().includes(ql)))
    : list;
  const revoke = async (s: AdminSession) => {
    if (!window.confirm(`Revoke this session for ${s.display_name || s.user_id}?\n\nThey'll be signed out immediately.`)) return;
    setErr(null);
    try { await api.revokeSession(s.id); reload(); } catch (e) { setErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); }
  };
  const fmt = (t?: string) => (t ? fmtDateTime(t) : "—");
  const statusBadge = (st: string) => {
    const tone = st === "active" ? "good" : st === "revoked" ? "warn" : "";
    const label = st === "expired_idle" ? "idle-out" : st === "expired_absolute" ? "expired" : st;
    return <span className={`badge ${tone}`}>{label}</span>;
  };
  return (
    <>
      <div className="admin-head-row">
        <AdminHead title="Sessions" sub="Live sign-in sessions. Revoke one to sign that person out immediately. Idle and maximum-lifetime limits apply automatically per the scope's Security Settings." />
        <button className="dash-btn" onClick={reload}>↻ Refresh</button>
      </div>
      <StatStrip>
        <Stat label="Active" value={sessions ? active.length : <Skeleton w={26} h={22} />} tone="accent" />
        <Stat label="Total" value={sessions ? list.length : "—"} />
        <Stat label="People" value={sessions ? new Set(active.map((s) => s.user_id)).size : "—"} />
      </StatStrip>
      <ErrLine msg={err} />
      <div className="card" style={{ paddingTop: 8 }}>
        <div className="ds-toolbar">
          <input className="ds-search" placeholder="Search sessions…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search sessions" />
          <span className="mini-meta">{shown.length} of {list.length}</span>
        </div>
        {sessions && shown.length === 0 ? (
          <div className="empty">No sessions.</div>
        ) : (
          <table className="ds-table" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th>Person</th><th>Tenant</th><th>IP</th><th>Status</th>
                <th>Started</th><th>Last activity</th><th style={{ width: 70 }}>Idle</th><th style={{ width: 1 }}></th>
              </tr>
            </thead>
            <tbody>
              {shown.map((s) => (
                <tr key={s.id}>
                  <td style={{ fontWeight: 600 }}>{s.display_name || s.user_id}</td>
                  <td style={{ color: "var(--muted)", fontSize: 12 }}>{s.tenant_id || "—"}</td>
                  <td className="mono">{s.issued_ip || "—"}</td>
                  <td>{statusBadge(s.status)}</td>
                  <td style={{ color: "var(--muted)", fontSize: 12 }}>{fmt(s.created_at)}</td>
                  <td style={{ color: "var(--muted)", fontSize: 12 }}>{fmt(s.last_activity_at)}</td>
                  <td style={{ color: "var(--muted)", fontSize: 12 }}>{s.idle_timeout_sec ? `${Math.round(s.idle_timeout_sec / 60)}m` : "off"}</td>
                  <td style={{ textAlign: "right" }}>{s.status === "active" && <button className="dash-btn" onClick={() => revoke(s)}>Revoke</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

// ---- API Access ------------------------------------------------------------

// Scope vocabulary — mirrors internal/apikey.KnownScopes() EXACTLY. The server
// validates every requested scope against that closed list and refuses one that
// would give the KEY more authority than the caller holds (403), so:
//   * an option offered here that the API rejects is a broken promise, and
//   * an option withheld here that the caller may legitimately mint is the
//     tracker-226 gap this list closes — the wizard could only ever mint
//     read-only keys, so tenant creation, device assignment, scans and rule
//     toggles could not be automated with a UI-minted key at all.
// The server stays the authority; this list only avoids offering a mint that is
// going to 403. Scope table + semantics: docs/API_ACCESS.md.
export type ScopeKind = "read" | "write" | "service" | "admin";
export type ScopeOption = {
  id: string;
  kind: ScopeKind;
  /** What the credential may do, in the operator's words (shown as the chip's title). */
  what: string;
};

export const SCOPE_OPTIONS: ScopeOption[] = [
  { id: "read:metrics", kind: "read", what: "Read metrics, health and topology state." },
  { id: "read:alerts", kind: "read", what: "Read alerts, incidents and their history." },
  { id: "read:devices", kind: "read", what: "Read the device inventory and its attributes." },
  { id: "read:flows", kind: "read", what: "Read flows, logs and traces." },
  { id: "read:*", kind: "read", what: "Read everything this tenant can see." },
  { id: "write:incidents", kind: "write", what: "Acknowledge, silence and annotate incidents." },
  { id: "write:alerts", kind: "write", what: "Create, edit and toggle alert rules." },
  { id: "write:devices", kind: "write", what: "Add, edit, monitor and scan devices." },
  { id: "write:*", kind: "write", what: "Operator authority: every write above." },
  { id: "ingest:cloud", kind: "service", what: "Cloud-ingest poller service credential (platform realm only)." },
  { id: "admin:*", kind: "admin", what: "Administer the tenant: tenants, users, devices, rules, scans." },
];

/** The product areas the permission grid is keyed by (mirrors rbac.Modules). */
const RBAC_MODULES = [
  "overview", "explore", "alerts", "infrastructure", "topology", "reports",
  "administration", "sensitive_data",
];

/**
 * scopeAllowed mirrors the server's rule (authorizeKeyScopes): the ROLE a key
 * will act under may not out-rank the caller on any module, and an
 * administrative scope in the platform realm is platform-admin-only.
 *
 * Derived roles, from auth.go roleFromScopes:
 *   read:… / ingest:…  → read-only  (read on every module except administration)
 *   write:…            → operator   (that, plus write on alerts + infrastructure)
 *   admin:*            → administrator of the key's tenant
 *
 * Default-closed: an unknown/absent grid offers nothing.
 */
export function scopeAllowed(opt: ScopeOption, perms: Record<string, number>, platformAdmin: boolean): boolean {
  const level = (m: string) => perms[m] ?? 0;
  const readsEverything = RBAC_MODULES.every((m) => m === "administration" || level(m) >= 1);
  switch (opt.kind) {
    case "read":
      return readsEverything;
    case "write":
      return readsEverything && level("alerts") >= 2 && level("infrastructure") >= 2;
    case "service":
      // ingest:cloud is only honoured for a platform-realm credential, so only
      // the platform owner can mint one that would ever work.
      return platformAdmin && readsEverything;
    case "admin":
      // admin:* derives the administrator role — admin on EVERY module — so the
      // caller must hold that much itself, not merely administration:admin.
      return RBAC_MODULES.every((m) => level(m) >= 3);
    default:
      return false;
  }
}

/** The scopes this caller may actually mint, in display order. */
export function allowedScopeOptions(perms: Record<string, number> | null, platformAdmin: boolean): ScopeOption[] {
  if (!perms) return [];
  return SCOPE_OPTIONS.filter((o) => scopeAllowed(o, perms, platformAdmin));
}

/** An administrative key is a different kind of credential — it needs a confirmation. */
export function isAdministrativeScope(scope: string): boolean {
  return scope === "admin:*";
}

const SCOPE_GROUPS: { kind: ScopeKind; title: string; blurb: string }[] = [
  { kind: "read", title: "Read", blurb: "The key can look, never change." },
  { kind: "write", title: "Write", blurb: "Operator authority — the key can change operational state." },
  { kind: "service", title: "Service", blurb: "Dedicated machine credential for one platform service." },
  { kind: "admin", title: "Administrative", blurb: "Full administration through the API. Mint one only for automation you own." },
];

/**
 * ScopePicker renders the scopes THIS caller may mint, grouped by the authority
 * they confer, with the administrative group behind an explicit confirmation.
 * Exported so the gating and the wording are testable on their own.
 */
export function ScopePicker({
  options, selected, onToggle, platformAdmin, confirmed, onConfirm,
}: {
  options: ScopeOption[];
  selected: string[];
  onToggle: (scope: string) => void;
  platformAdmin: boolean;
  confirmed: boolean;
  onConfirm: (v: boolean) => void;
}) {
  if (options.length === 0) {
    return <p className="mini-meta" style={{ margin: 0 }}>Checking which scopes your role may issue…</p>;
  }
  const adminSelected = selected.some(isAdministrativeScope);
  return (
    <>
      {SCOPE_GROUPS.map((g) => {
        const inGroup = options.filter((o) => o.kind === g.kind);
        if (inGroup.length === 0) return null;
        return (
          <div key={g.kind} style={{ marginBottom: 12 }}>
            <h3 style={{ margin: "0 0 2px", fontSize: "var(--fs-meta)", textTransform: "uppercase", letterSpacing: ".04em", color: "var(--muted)" }}>
              {g.title}
            </h3>
            <p className="mini-meta" style={{ margin: "0 0 6px" }}>{g.blurb}</p>
            <div className="scope-row">
              {inGroup.map((o) => (
                <label key={o.id} className={`scope-chip ${selected.includes(o.id) ? "on" : ""}`} title={o.what}>
                  <input type="checkbox" checked={selected.includes(o.id)} onChange={() => onToggle(o.id)} /> {o.id}
                </label>
              ))}
            </div>
          </div>
        );
      })}
      {adminSelected && (
        <div className="planned-banner" style={{ borderColor: "var(--warn)" }}>
          <span className="badge warn">Administrative key</span>
          <span>
            {platformAdmin
              ? "This credential administers the whole platform — every tenant, every user, every device. Treat it like a root password: give it a source-IP allowlist and an expiry."
              : "This credential administers your tenant — its users, devices, rules and scans. It can never reach another tenant."}
            <label style={{ display: "block", marginTop: 6 }}>
              <input type="checkbox" checked={confirmed} onChange={(e) => onConfirm(e.target.checked)} />{" "}
              I understand, and I am issuing an administrative key.
            </label>
          </span>
        </div>
      )}
    </>
  );
}

const GRANT_TYPE_OPTIONS = ["authorization_code", "client_credentials", "refresh_token"];

type ApiTile = "keys" | "token" | "rest";

export function ApiAccessAdmin() {
  const [keys, err, reload, setErr] = useReload(() => api.listApiKeys());
  const { user } = useAuth();
  const [label, setLabel] = useState("");
  const [scopes, setScopes] = useState<string[]>(["read:metrics"]);
  // The caller's OWN permission grid: the wizard offers only scopes this
  // principal may actually mint (the server refuses the rest with 403).
  const [perms, setPerms] = useState<Record<string, number> | null>(null);
  const [adminConfirmed, setAdminConfirmed] = useState(false);
  const [rate, setRate] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  // Credential metadata
  const [grantTypes, setGrantTypes] = useState<string[]>(["client_credentials"]);
  const [clientUri, setClientUri] = useState("");
  const [logoUri, setLogoUri] = useState("");
  const [sourceCidrs, setSourceCidrs] = useState("");
  // Expiry
  const [clientExpires, setClientExpires] = useState("");
  const [secretExpires, setSecretExpires] = useState("");
  // Contacts
  const [contactEmail, setContactEmail] = useState("");
  const [contactPhone, setContactPhone] = useState("");
  // Which tile's modal is open (also driven by the flyout deep-link #/admin/api/<tile>).
  const [open, setOpen] = useState<ApiTile | null>(null);

  useEffect(() => {
    let live = true;
    api.permissions()
      .then((p) => { if (live) setPerms(p.permissions ?? {}); })
      .catch(() => { if (live) setPerms({}); }); // default-closed: offer nothing
    return () => { live = false; };
  }, []);

  useEffect(() => {
    const read = () => {
      const seg = window.location.hash.replace(/^#\/?/, "").split("/")[2];
      if (seg === "keys" || seg === "token" || seg === "rest") setOpen(seg);
    };
    read();
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, []);
  const openTile = (t: ApiTile) => { setOpen(t); if (window.location.hash !== `#/admin/api/${t}`) window.history.replaceState(null, "", `#/admin/api/${t}`); };
  const closeTile = () => { setOpen(null); window.history.replaceState(null, "", "#/admin/api"); };

  const toggleScope = (s: string) =>
    setScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  const toggleGrant = (g: string) =>
    setGrantTypes((cur) => (cur.includes(g) ? cur.filter((x) => x !== g) : [...cur, g]));

  const splitList = (v: string) => v.split(",").map((x) => x.trim()).filter(Boolean);
  const toIso = (v: string) => (v.trim() ? new Date(v).toISOString() : undefined);

  const generate = async () => {
    if (!label.trim()) return;
    setErr(null);
    const req: CreateApiKeyRequest = {
      label: label.trim(),
      scopes,
      rate_limit_per_min: rate.trim() ? Math.max(0, parseInt(rate, 10) || 0) : undefined,
      grant_types: grantTypes.length ? grantTypes : undefined,
      client_uri: clientUri.trim() || undefined,
      logo_uri: logoUri.trim() || undefined,
      source_cidrs: splitList(sourceCidrs).length ? splitList(sourceCidrs) : undefined,
      client_expires_at: toIso(clientExpires),
      secret_expires_at: toIso(secretExpires),
      contacts: contactEmail.trim() ? splitList(contactEmail) : undefined,
      contact_phone: contactPhone.trim() || undefined,
    };
    const res = await api.createApiKey(req); // throws → surfaced by the Wizard
    setSecret(res.secret);
    setLabel(""); setRate(""); setClientUri(""); setLogoUri(""); setSourceCidrs("");
    setAdminConfirmed(false);
    setClientExpires(""); setSecretExpires(""); setContactEmail(""); setContactPhone("");
    reload();
  };
  const revoke = async (k: ApiKey) => {
    setErr(null);
    try { await api.revokeApiKey(k.id); reload(); } catch (e) { setErr((e as Error).message); }
  };

  const list = keys ?? [];
  const active = list.filter((k) => !k.revoked_at).length;
  const TILES: { id: ApiTile; name: string; tagline: string; icon: string; meta: string }[] = [
    { id: "keys", name: "Generate API key", icon: "key", tagline: "Mint a scoped client credential for machine clients.", meta: keys ? `${active} active · ${list.length - active} revoked` : "…" },
    { id: "token", name: "Token Policy", icon: "shield", tagline: "Access & refresh token lifetimes for sessions.", meta: "Clamped to safe bounds" },
    { id: "rest", name: "REST API Reference", icon: "docs", tagline: "Browse every endpoint; export the OpenAPI spec.", meta: "Live, generated from the API" },
  ];

  return (
    <div className="dm-board">
      <Group title="API access" hue="#3B82F6">
      <StatStrip>
        <Stat label="Keys" value={keys ? list.length : <Skeleton w={26} h={22} />} />
        <Stat label="Active" value={keys ? active : "—"} tone="good" />
        <Stat label="Revoked" value={keys ? list.length - active : "—"} tone={list.some((k) => k.revoked_at) ? "warn" : ""} />
        <Stat label="Rate-limited" value={keys ? list.filter((k) => (k.rate_limit_per_min || 0) > 0).length : "—"} />
      </StatStrip>
      <p className="mini-meta" style={{ margin: 0 }}>
        {BRAND} is API-first — mint <strong>scoped credentials</strong> for machine clients, tune <strong>session-token</strong> lifetimes,
        and browse the live <strong>REST reference</strong>. A key never exceeds its scopes.
      </p>

      <div className="conn-grid">
        {TILES.map((t) => (
          <button key={t.id} className="conn-tile" onClick={() => openTile(t.id)} aria-label={t.name}>
            <span className={`conn-logo api-${t.id}`}><Icon name={t.icon} size={24} /></span>
            <span className="conn-body">
              <span className="conn-name">{t.name}</span>
              <span className="conn-tag">{t.tagline}</span>
              <span className="conn-meta">{t.meta}</span>
            </span>
            <span className="conn-cta">Open →</span>
          </button>
        ))}
      </div>

      <div className="card">
        <div className="admin-card-head">
          <h2>API keys</h2>
          <button className="dash-btn accent" onClick={() => openTile("keys")}>+ Generate key</button>
        </div>
        <ErrLine msg={err} />
        <table className="ds-table">
          <thead>
            <tr><th>Label</th><th>Client ID</th><th>Scopes</th><th>Grant types</th><th>Source CIDRs</th><th>Rate / min</th><th>Usage</th><th>Created</th><th>Expires</th><th>Last used</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {list.map((k) => {
              const cap = k.rate_limit_per_min || 0;
              const near = cap > 0 && k.window_used >= cap * 0.8;
              return (
              <tr key={k.id}>
                <td style={{ fontWeight: 600 }}>{k.client_uri ? <a href={k.client_uri} target="_blank" rel="noreferrer">{k.label}</a> : k.label}</td>
                <td className="mono">{k.prefix}</td>
                <td className="mono" style={{ fontSize: "var(--fs-meta)" }}>
                  {(k.scopes || []).some(isAdministrativeScope) && <span className="badge warn" style={{ marginRight: 6 }}>admin</span>}
                  {(k.scopes || []).join(", ") || "—"}
                </td>
                <td className="mono" style={{ fontSize: "var(--fs-meta)" }}>{(k.grant_types || []).join(", ") || "—"}</td>
                <td className="mono" style={{ fontSize: "var(--fs-meta)" }}>{(k.source_cidrs || []).join(", ") || "any"}</td>
                <td className="mono">{cap > 0 ? <span className={near ? "badge warn" : ""}>{k.window_used}/{cap}</span> : <span className="mini-meta">unlimited</span>}</td>
                <td className="mono">{(k.use_count ?? 0).toLocaleString()}</td>
                <td>{k.created_at ? fmtDate(k.created_at) : "—"}</td>
                <td>{k.client_expires_at || k.secret_expires_at ? fmtDate(k.client_expires_at || k.secret_expires_at || "") : "never"}</td>
                <td>{k.last_used_at ? fmtDateTime(k.last_used_at) : "never"}</td>
                <td>{k.revoked_at ? <span className="badge warn">revoked</span> : <span className="badge good">active</span>}</td>
                <td>{!k.revoked_at && <button className="dash-btn" onClick={() => revoke(k)}>Revoke</button>}</td>
              </tr>
            );})}
            {list.length === 0 && <tr><td colSpan={12} className="panel-empty">No API keys yet.</td></tr>}
          </tbody>
        </table>
      </div>

      {open === "keys" && (
        <Modal title="Generate API key" subtitle="A scoped client credential for machine clients." logo={<span className="conn-logo api-keys"><Icon name="key" size={26} /></span>} onClose={closeTile}>
          <ErrLine msg={err} />
          {secret && (
            <div className="planned-banner" style={{ background: "var(--sev-ok-bg)", borderColor: "var(--good)" }}>
              <span className="badge good">Client secret</span>
              <span>Copy it now — it won't be shown again:&nbsp;<code style={{ userSelect: "all" }}>{secret}</code>
                <InfoTip label="Present it as Authorization: Bearer <secret> or the X-API-Key header. The key resolves to the same tenant + RBAC context as its scopes — never more.">Present it as <code>Authorization: Bearer …</code> or <code>X-API-Key</code>. The key never exceeds its scopes.</InfoTip>
              </span>
              <button className="dash-btn" style={{ marginLeft: "auto" }} onClick={() => setSecret(null)}>Dismiss</button>
            </div>
          )}
          <Wizard
            finishLabel="Generate key"
            onFinish={generate}
            steps={[
              {
                id: "identity", title: "Identity",
                hint: "Name the credential and (optionally) cap its request rate.",
                isValid: () => !!label.trim(),
                render: () => (
                  <>
                    <div className="form-grid">
                      <LabeledInput label="Label" value={label} onChange={setLabel} placeholder="e.g. ci-pipeline" required info="A human name for this credential — shown in the keys table and audit log." />
                      <LabeledInput label="Rate limit / min" type="number" value={rate} onChange={setRate} placeholder="blank = default (600)" info="Max requests per minute. Blank inherits the server default (600); 0 means unlimited." />
                    </div>
                    <RequiredLegend />
                  </>
                ),
              },
              {
                id: "scopes", title: "Scopes & grant",
                hint: "What the credential may do; its RBAC role is derived from the scopes.",
                // An administrative key needs the operator to say so explicitly.
                isValid: () => !scopes.some(isAdministrativeScope) || adminConfirmed,
                render: () => (
                  <>
                    <ScopePicker
                      options={allowedScopeOptions(perms, !!user?.platform_admin)}
                      selected={scopes}
                      onToggle={toggleScope}
                      platformAdmin={!!user?.platform_admin}
                      confirmed={adminConfirmed}
                      onConfirm={setAdminConfirmed}
                    />
                    <h3 style={{ margin: "16px 0 4px", fontSize: "var(--fs-meta)", textTransform: "uppercase", letterSpacing: ".04em", color: "var(--muted)", display: "flex", alignItems: "center", gap: 5 }}>
                      Grant types<InfoTip label="The OAuth 2.0 grant types this credential supports. client_credentials is the usual machine-to-machine flow.">OAuth 2.0 flows this credential supports. <code>client_credentials</code> is the usual machine-to-machine flow.</InfoTip>
                    </h3>
                    <div className="scope-row">
                      {GRANT_TYPE_OPTIONS.map((g) => (
                        <label key={g} className={`scope-chip ${grantTypes.includes(g) ? "on" : ""}`}>
                          <input type="checkbox" checked={grantTypes.includes(g)} onChange={() => toggleGrant(g)} /> {g}
                        </label>
                      ))}
                    </div>
                  </>
                ),
              },
              {
                id: "client", title: "Client & network",
                hint: "Optional client metadata and a source-IP allowlist.",
                isValid: () => true,
                render: () => (
                  <div className="form-grid">
                    <LabeledInput label="Client URL" value={clientUri} onChange={setClientUri} placeholder="https://app.example.com" info="Public homepage of the client app (RFC 7591 metadata). Optional." />
                    <LabeledInput label="Logo URL" value={logoUri} onChange={setLogoUri} placeholder="https://app.example.com/logo.png" info="Image shown on consent screens (RFC 7591 metadata). Optional." />
                    <LabeledInput label="Allowed source IP / CIDR" value={sourceCidrs} onChange={setSourceCidrs} placeholder="10.0.0.0/8, 192.168.1.0/24" info="Comma-separated allowlist of source networks. Blank allows any source IP." />
                  </div>
                ),
              },
              {
                id: "expiry", title: "Expiry & contacts",
                hint: "Optional lifetime and owner contacts. Review, then generate.",
                isValid: () => true,
                render: () => (
                  <>
                    <div className="form-grid">
                      <LabeledInput label="Client expires on" type="date" value={clientExpires} onChange={setClientExpires} info="Date the whole credential stops working. Blank = never expires." />
                      <LabeledInput label="Secret expires on" type="date" value={secretExpires} onChange={setSecretExpires} info="Date the client secret must be rotated by. Blank = never expires." />
                      <LabeledInput label="Contact email" value={contactEmail} onChange={setContactEmail} placeholder="ops@example.com" info="Owner email(s) for expiry/abuse notices. Comma-separated for multiple." />
                      <LabeledInput label="Contact phone" value={contactPhone} onChange={setContactPhone} placeholder="+1 555 0100" info="Optional owner phone for the credential." />
                    </div>
                  </>
                ),
              },
            ]}
          />
        </Modal>
      )}

      {open === "token" && (
        <Modal title="Token Policy" subtitle="Session access & refresh token lifetimes." logo={<span className="conn-logo api-token"><Icon name="shield" size={26} /></span>} onClose={closeTile}>
          <TokenPolicyForm embedded />
        </Modal>
      )}

      {open === "rest" && (
        <Modal title="REST API Reference" subtitle="Every endpoint, generated live from the API." logo={<span className="conn-logo api-rest"><Icon name="docs" size={26} /></span>} onClose={closeTile}>
          <OpenAPIReference embedded />
        </Modal>
      )}
      </Group>
    </div>
  );
}

// GraphQLExplorer is an in-app, GraphiQL-style console for the typed
// /api/graphql endpoint. No external GraphiQL/CDN bundle — a query editor, a set
// of example queries, and a JSON result pane, all behind the same auth as the
// rest of the SPA. The backend supports devices/alerts/rules/health (+ __schema).
const GQL_EXAMPLES: { label: string; query: string }[] = [
  { label: "Devices", query: "{ devices { id name address vendor } }" },
  { label: "Active alerts", query: "{ alerts { id rule severity device_id summary } }" },
  { label: "Rules", query: "{ rules { id severity } }" },
  { label: "Health", query: "{ health }" },
  { label: "Schema", query: "{ __schema }" },
];

export function GraphQLExplorer() {
  const [query, setQuery] = useState(GQL_EXAMPLES[0].query);
  const [result, setResult] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      const res = await api.graphql(query);
      setResult(JSON.stringify(res, null, 2));
    } catch (e) {
      setErr((e as Error).message);
      setResult("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <div className="admin-card-head">
        <h2>GraphQL explorer</h2>
        <a className="dash-btn" href="/api/graphql" target="_blank" rel="noreferrer">/api/graphql <Icon name="external" size={12} /></a>
      </div>
      <p className="mini-meta" style={{ marginTop: 0 }}>
        Single typed endpoint over <code>devices</code> · <code>alerts</code> · <code>rules</code> ·{" "}
        <code>health</code> (+ <code>__schema</code> introspection). Results are tenant-scoped, just like REST.
      </p>
      <div className="scope-row" style={{ marginBottom: 10 }}>
        {GQL_EXAMPLES.map((ex) => (
          <button key={ex.label} className="scope-chip" onClick={() => setQuery(ex.query)}>{ex.label}</button>
        ))}
      </div>
      <div className="ov-grid">
        <div className="panel col-6" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <textarea
            spellCheck={false}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            rows={9}
            className="mono"
            style={{ width: "100%", resize: "vertical", fontSize: "var(--fs-meta)", padding: 10, borderRadius: "var(--r-2)", border: "1px solid var(--panel-border)", background: "var(--panel)", color: "var(--fg)" }}
          />
          <div>
            <button className="dash-btn accent" onClick={run} disabled={busy}>{busy ? "Running…" : "Run query"}</button>
          </div>
          <ErrLine msg={err} />
        </div>
        <div className="panel col-6">
          <pre className="mono" style={{ margin: 0, maxHeight: 280, overflow: "auto", fontSize: "var(--fs-meta)", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
            {result || "// run a query to see the JSON response"}
          </pre>
        </div>
      </div>
    </div>
  );
}

// OpenAPIReference renders a live, grouped index of the REST surface from the
// generated /api/openapi.json — no external Swagger UI / CDN (offline-friendly).
function OpenAPIReference({ embedded = false }: { embedded?: boolean }) {
  const [spec, err] = useReload(() => api.openapi());
  if (err) return null;
  const groups: Record<string, { method: string; path: string; summary?: string }[]> = {};
  for (const [path, ops] of Object.entries(spec?.paths ?? {})) {
    for (const [method, op] of Object.entries(ops)) {
      const tag = op.tags?.[0] ?? "Other";
      (groups[tag] ||= []).push({ method: method.toUpperCase(), path, summary: op.summary });
    }
  }
  const METHOD_COLOR: Record<string, string> = {
    GET: "var(--sev-info)", POST: "var(--good)", PUT: "var(--sev-warning)", PATCH: "var(--sev-warning)", DELETE: "var(--bad)",
  };
  const inner = (
    <>
      {!embedded && (
        <div className="admin-card-head">
          <h2>REST API reference</h2>
          <a className="dash-btn" href="/api/openapi.json" target="_blank" rel="noreferrer">openapi.json <Icon name="external" size={12} /></a>
        </div>
      )}
      <p className="mini-meta" style={{ marginTop: 0, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <span>{spec?.info?.title} · v{spec?.info?.version} · OpenAPI {spec?.openapi}. Generated from the Go handlers; import it into Postman or any OpenAPI client.</span>
        {embedded && <a className="dash-btn" href="/api/openapi.json" target="_blank" rel="noreferrer" style={{ marginLeft: "auto" }}>openapi.json <Icon name="external" size={12} /></a>}
      </p>
      <div className="ov-grid">
        {Object.entries(groups).map(([tag, rows]) => (
          <div className="panel col-6" key={tag}>
            <h3>{tag}</h3>
            <table>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ color: METHOD_COLOR[r.method] || "var(--muted)", fontWeight: 700, width: 70 }}>{r.method}</td>
                    <td className="mono" style={{ fontSize: "var(--fs-meta)" }}>{r.path}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>
    </>
  );
  return embedded ? inner : <div className="card">{inner}</div>;
}

// ---- Authentication (SSO / LDAP / TACACS+) ---------------------------------

// Small status pill for a provider section.
function ProviderBadge({ enabled }: { enabled: boolean }) {
  return <span className={`badge ${enabled ? "good" : "accent-badge"}`}>{enabled ? "Enabled" : "Disabled"}</span>;
}

// Renders a test-connection result (Okta-style: the headline is the role).
function TestResult({ r }: { r: AuthTestResult | null }) {
  if (!r) return null;
  const color = r.ok ? "var(--good)" : "var(--bad)";
  return (
    // role=status: the async "Test connection" outcome is announced (4.1.3);
    // the OK/FAIL badge text (not only the color) carries the verdict.
    <div role="status" style={{ marginTop: 8, padding: "8px 10px", borderRadius: 6, border: `1px solid ${color}`, background: "var(--panel)", fontSize: 13 }}>
      <span className={`badge ${r.ok ? "good" : "bad"}`}>{r.ok ? "OK" : "FAIL"}</span>{" "}
      <span className="mini-meta">[{r.stage}]</span> {r.message}
      {r.resolved_dn && <div className="mono mini-meta" style={{ marginTop: 4 }}>DN: {r.resolved_dn}</div>}
      {r.groups && r.groups.length > 0 && <div className="mini-meta">groups: {r.groups.join(", ")}</div>}
      {r.assigned_role && <div style={{ marginTop: 4 }}>→ would be assigned role <b>{r.assigned_role}</b></div>}
    </div>
  );
}

// Red asterisk marking a mandatory field.
function Req() {
  return <span style={{ color: "var(--bad)" }} title="Required" aria-label="required"> *</span>;
}

// FieldLabel — the label row shared by the typed inputs. Renders the field name,
// an optional required asterisk, and an optional hover "i" InfoTip carrying a
// brief description of what the field is for.
function FieldLabel({ label, required, info }: { label: string; required?: boolean; info?: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
      {label}{required && <Req />}{info && <InfoTip label={info}>{info}</InfoTip>}
    </span>
  );
}

function LabeledInput({ label, value, onChange, type = "text", placeholder = "", hint, info, required = false }: {
  label: string; value: string; onChange: (v: string) => void; type?: string; placeholder?: string; hint?: string; info?: string; required?: boolean;
}) {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
      <FieldLabel label={label} required={required} info={info} />
      <input type={type} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)}
        style={{ padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" }} />
      {hint && <span className="mini-meta">{hint}</span>}
    </label>
  );
}

function LabeledSelect({ label, value, onChange, options, info }: {
  label: string; value: string; onChange: (v: string) => void; options: string[]; info?: string;
}) {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
      <FieldLabel label={label} info={info} />
      <select value={value} onChange={(e) => onChange(e.target.value)}
        style={{ padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" }}>
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  );
}

// Legend explaining the asterisk on config forms.
function RequiredLegend() {
  return <p className="mini-meta" style={{ marginTop: 4 }}><Req /> required when the provider is enabled</p>;
}

// ---- LDAP / Active Directory form ----
function LdapAdminForm({ roleIds, embedded = false }: { roleIds: string[]; embedded?: boolean }) {
  const [cfg, setCfg] = useState<LdapConfig | null>(null);
  const [pw, setPw] = useState(""); // typed bind password (only sent if non-empty)
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testUser, setTestUser] = useState("");
  const [testPass, setTestPass] = useState("");
  const [result, setResult] = useState<AuthTestResult | null>(null);

  useEffect(() => {
    api.ldapConfig()
      .then((r) => setCfg({ ...r.config, role_mappings: r.config.role_mappings ?? [] }))
      .catch((e) => setMsg((e as Error).message));
  }, []);
  if (!cfg) return embedded ? <p className="mini-meta">Loading…</p> : <div className="card"><h2>LDAP / Active Directory</h2><p className="mini-meta">Loading…</p></div>;

  const set = (patch: Partial<LdapConfig>) => setCfg({ ...cfg, ...patch });
  const enc = cfg.use_tls ? "ldaps" : cfg.start_tls ? "starttls" : "none";
  const setEnc = (v: string) => set({ use_tls: v === "ldaps", start_tls: v === "starttls" });
  const setMapping = (i: number, patch: Partial<LdapRoleMapping>) => {
    const m = cfg.role_mappings.slice(); m[i] = { ...m[i], ...patch }; set({ role_mappings: m });
  };

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const body: Partial<LdapConfig> & { bind_password?: string } = { ...cfg };
      if (pw) body.bind_password = pw; // only override the secret when re-typed
      const r = await api.saveLdapConfig(body);
      setCfg(r.config); setPw(""); setMsg("Saved.");
    } catch (e) { setMsg((e as Error).message); } finally { setBusy(false); }
  };
  const test = async () => {
    setBusy(true); setResult(null);
    try { setResult(await api.testLdap(testUser || undefined, testPass || undefined)); }
    catch (e) { setResult({ ok: false, stage: "error", message: (e as Error).message }); }
    finally { setBusy(false); }
  };

  const enableToggle = (
    <label className="auth-enable"><input type="checkbox" checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled</label>
  );
  return (
    <div className={embedded ? "auth-form" : "card"}>
      {embedded ? (
        <div className="auth-embed-head"><ProviderBadge enabled={cfg.enabled} />{enableToggle}</div>
      ) : (
        <div className="admin-card-head">
          <h2>LDAP / Active Directory <ProviderBadge enabled={cfg.enabled} /></h2>
          <label style={{ fontSize: 13 }}>
            <input type="checkbox" checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled
          </label>
        </div>
      )}
      <p className="admin-sub">Native stdlib LDAP bind (RFC 4511). Directory groups map onto NetOps roles (first match by privilege wins). The bind password is write-only — leave blank to keep the stored one.</p>
      <Wizard
        finishLabel="Save"
        onFinish={save}
        steps={[
          {
            id: "connect",
            title: "Connection",
            hint: "Reach the directory. Host and Base DN are required; the bind password is write-only.",
            isValid: () => !!cfg.host.trim() && !!cfg.base_dn.trim(),
            render: () => (
              <>
                <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                  <LabeledInput label="Host" value={cfg.host} onChange={(v) => set({ host: v })} placeholder="ldap.example.com" required />
                  <LabeledInput label="Port (0 = auto)" type="number" value={String(cfg.port)} onChange={(v) => set({ port: Number(v) || 0 })} />
                  <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
                    Encryption
                    <select value={enc} onChange={(e) => setEnc(e.target.value)}>
                      <option value="none">None (389)</option>
                      <option value="starttls">StartTLS</option>
                      <option value="ldaps">LDAPS (636)</option>
                    </select>
                  </label>
                  <LabeledInput label="Bind DN (service acct)" value={cfg.bind_dn} onChange={(v) => set({ bind_dn: v })} placeholder="cn=svc,dc=example,dc=com" info="Distinguished Name of the service account used to search the directory. Leave blank for anonymous bind." />
                  <LabeledInput label="Bind password" type="password" value={pw} onChange={setPw} placeholder={cfg.bind_password_set ? "•••••• (unchanged)" : "(none)"} info="Password for the bind DN service account. Write-only — blank keeps stored." />
                  <LabeledInput label="Base DN" value={cfg.base_dn} onChange={(v) => set({ base_dn: v })} placeholder="dc=example,dc=com" required info="The directory subtree under which user searches start, e.g. dc=example,dc=com." />
                  <label style={{ fontSize: 12, color: "var(--muted)", alignSelf: "end" }}>
                    <input type="checkbox" checked={cfg.insecure_skip_verify} onChange={(e) => set({ insecure_skip_verify: e.target.checked })} /> Skip TLS verify (lab only)
                  </label>
                </div>
                <RequiredLegend />
              </>
            ),
          },
          {
            id: "users",
            title: "Users & groups",
            hint: "How users are found and how directory groups resolve. User filter is required.",
            isValid: () => !!cfg.user_filter.trim(),
            render: () => (
              <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                <LabeledInput label="User filter" value={cfg.user_filter} onChange={(v) => set({ user_filter: v })} hint="%s = username, e.g. (uid=%s) or (sAMAccountName=%s)" required />
                <LabeledInput label="Group base DN" value={cfg.group_base_dn} onChange={(v) => set({ group_base_dn: v })} placeholder="(defaults to Base DN)" />
                <LabeledInput label="Group filter" value={cfg.group_filter} onChange={(v) => set({ group_filter: v })} hint="%s = user DN, e.g. (member=%s)" />
                <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
                  Default role
                  <select value={cfg.default_role} onChange={(e) => set({ default_role: e.target.value })}>
                    {roleIds.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </label>
                <LabeledInput label="Default tenant" value={cfg.default_tenant} onChange={(v) => set({ default_tenant: v })} />
              </div>
            ),
          },
          {
            id: "roles",
            title: "Roles & test",
            hint: "Map directory groups to roles (highest-privilege match wins), then test and save.",
            isValid: () => true,
            render: () => (
              <>
                {cfg.role_mappings.map((m, i) => (
                  <div key={i} className="admin-form" style={{ marginBottom: 6 }}>
                    <input value={m.group} aria-label="Directory group DN" placeholder="cn=netops-admins,ou=groups,dc=example,dc=com" onChange={(e) => setMapping(i, { group: e.target.value })} />
                    <select value={m.role} aria-label="Mapped role" onChange={(e) => setMapping(i, { role: e.target.value })}>
                      {roleIds.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                    <button onClick={() => set({ role_mappings: cfg.role_mappings.filter((_, j) => j !== i) })}>Remove</button>
                  </div>
                ))}
                <button onClick={() => set({ role_mappings: [...cfg.role_mappings, { group: "", role: roleIds[0] || "read-only" }] })}>+ Add mapping</button>
                <div style={{ marginTop: 16, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <input aria-label="Test username (optional)" placeholder="test username (optional)" value={testUser} onChange={(e) => setTestUser(e.target.value)} style={{ padding: 6 }} />
                  <input type="password" aria-label="Test password" placeholder="test password" value={testPass} onChange={(e) => setTestPass(e.target.value)} style={{ padding: 6 }} />
                  <button disabled={busy} onClick={test}>Test connection</button>
                </div>
                <TestResult r={result} />
              </>
            ),
          },
        ]}
      />
      {msg && <p className="mini-meta" style={{ marginTop: 6 }}>{msg}</p>}
    </div>
  );
}

// ---- TACACS+ form ----
function TacacsAdminForm({ roleIds, embedded = false }: { roleIds: string[]; embedded?: boolean }) {
  const [cfg, setCfg] = useState<TacacsConfig | null>(null);
  const [secret, setSecret] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testUser, setTestUser] = useState("");
  const [testPass, setTestPass] = useState("");
  const [result, setResult] = useState<AuthTestResult | null>(null);

  useEffect(() => { api.tacacsConfig().then((r) => setCfg(r.config)).catch((e) => setMsg((e as Error).message)); }, []);
  if (!cfg) return embedded ? <p className="mini-meta">Loading…</p> : <div className="card"><h2>TACACS+</h2><p className="mini-meta">Loading…</p></div>;
  const set = (patch: Partial<TacacsConfig>) => setCfg({ ...cfg, ...patch });

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const body: Partial<TacacsConfig> & { secret?: string } = { ...cfg };
      if (secret) body.secret = secret;
      const r = await api.saveTacacsConfig(body);
      setCfg(r.config); setSecret(""); setMsg("Saved.");
    } catch (e) { setMsg((e as Error).message); } finally { setBusy(false); }
  };
  const test = async () => {
    setBusy(true); setResult(null);
    try { setResult(await api.testTacacs(testUser || undefined, testPass || undefined)); }
    catch (e) { setResult({ ok: false, stage: "error", message: (e as Error).message }); }
    finally { setBusy(false); }
  };

  const enableToggle = (
    <label className="auth-enable"><input type="checkbox" checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled</label>
  );
  return (
    <div className={embedded ? "auth-form" : "card"}>
      {embedded ? (
        <div className="auth-embed-head"><ProviderBadge enabled={cfg.enabled} />{enableToggle}</div>
      ) : (
        <div className="admin-card-head">
          <h2>TACACS+ <ProviderBadge enabled={cfg.enabled} /></h2>
          <label style={{ fontSize: 13 }}>
            <input type="checkbox" checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled
          </label>
        </div>
      )}
      <p className="admin-sub">Native stdlib TACACS+ PAP (RFC 8907) — authenticate operators against the same AAA server that fronts your routers/switches. The shared secret is write-only.</p>
      <Wizard
        finishLabel="Save"
        onFinish={save}
        steps={[
          {
            id: "connect",
            title: "Connection",
            hint: "Reach your TACACS+ AAA server. Host is required; the shared secret is write-only.",
            isValid: () => !!cfg.host.trim(),
            render: () => (
              <>
                <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                  <LabeledInput label="Host" value={cfg.host} onChange={(v) => set({ host: v })} placeholder="tacacs.example.com" required />
                  <LabeledInput label="Port" type="number" value={String(cfg.port)} onChange={(v) => set({ port: Number(v) || 49 })} />
                  <LabeledInput label="Shared secret" type="password" value={secret} onChange={setSecret} placeholder={cfg.secret_set ? "•••••• (unchanged)" : "(none)"} info="The TACACS+ shared key configured on the AAA server for this client. Write-only — blank keeps stored." />
                  <LabeledInput label="Timeout (s)" type="number" value={String(cfg.timeout_seconds)} onChange={(v) => set({ timeout_seconds: Number(v) || 5 })} />
                </div>
                <RequiredLegend />
              </>
            ),
          },
          {
            id: "defaults",
            title: "Defaults & test",
            hint: "Role/tenant for authenticated users, then test and save.",
            isValid: () => true,
            render: () => (
              <>
                <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                  <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
                    Default role
                    <select value={cfg.default_role} onChange={(e) => set({ default_role: e.target.value })}>
                      {roleIds.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </label>
                  <LabeledInput label="Default tenant" value={cfg.default_tenant} onChange={(v) => set({ default_tenant: v })} />
                </div>
                <div style={{ marginTop: 16, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <input aria-label="Test username (optional)" placeholder="test username (optional)" value={testUser} onChange={(e) => setTestUser(e.target.value)} style={{ padding: 6 }} />
                  <input type="password" aria-label="Test password" placeholder="test password" value={testPass} onChange={(e) => setTestPass(e.target.value)} style={{ padding: 6 }} />
                  <button disabled={busy} onClick={test}>Test connection</button>
                </div>
                <TestResult r={result} />
              </>
            ),
          },
        ]}
      />
      {msg && <p className="mini-meta" style={{ marginTop: 6 }}>{msg}</p>}
    </div>
  );
}

type AuthProviderId = "local" | "sso" | "ldap" | "tacacs";
const AUTH_PROVIDERS: { id: AuthProviderId; name: string; tagline: string; icon: string }[] = [
  { id: "local", name: "Local accounts", tagline: "Username + password (PBKDF2) with JWT + rotating refresh tokens — the always-on fallback.", icon: "lock" },
  { id: "sso", name: "Single Sign-On", tagline: "Federate sign-in to your OIDC identity provider (Okta, Azure AD, Google…).", icon: "key" },
  { id: "ldap", name: "LDAP / Active Directory", tagline: "Bind directly to your directory (RFC 4511); directory groups map onto roles.", icon: "directory" },
  { id: "tacacs", name: "TACACS+", tagline: "Authenticate operators against the AAA server fronting your routers and switches.", icon: "server" },
];

export function AuthenticationAdmin() {
  const [roles] = useReload(() => api.listRoles());
  const roleIds = (roles?.roles ?? []).map((r) => r.id).filter((x): x is string => !!x);
  const fallbackRoles = roleIds.length ? roleIds : ["super-admin", "operator", "read-only"];

  const [open, setOpen] = useState<AuthProviderId | null>(null);
  const [sso, setSso] = useState<{ enabled: boolean; ready: boolean } | null>(null);
  const [ldap, setLdap] = useState<{ enabled: boolean; configured: boolean } | null>(null);
  const [tac, setTac] = useState<{ enabled: boolean; configured: boolean } | null>(null);

  const reloadStatus = useCallback(() => {
    api.oidcConfig().then((r) => setSso({ enabled: r.config.enabled, ready: r.ready })).catch(() => {});
    api.ldapConfig().then((r) => setLdap({ enabled: r.config.enabled, configured: !!r.config.host })).catch(() => {});
    api.tacacsConfig().then((r) => setTac({ enabled: r.config.enabled, configured: !!r.config.host })).catch(() => {});
  }, []);
  useEffect(reloadStatus, [reloadStatus]);

  const loaded = sso !== null && ldap !== null && tac !== null;
  const enabledCount = 1 + [sso?.enabled, ldap?.enabled, tac?.enabled].filter(Boolean).length; // local always on

  // Per-tile status pill + meta line.
  const statusFor = (id: AuthProviderId): { tag: string; tone: string; meta: string } => {
    if (id === "local") return { tag: "Always on", tone: "good", meta: "Built-in · always available" };
    if (!loaded) return { tag: "…", tone: "", meta: "Loading…" };
    if (id === "sso") {
      if (!sso!.enabled) return { tag: "Off", tone: "", meta: "Not configured" };
      return sso!.ready ? { tag: "On", tone: "good", meta: "OIDC ready" } : { tag: "On", tone: "warn", meta: "Enabled — finish issuer & client ID" };
    }
    const s = id === "ldap" ? ldap! : tac!;
    if (!s.enabled) return { tag: "Off", tone: "", meta: s.configured ? "Configured — disabled" : "Not configured" };
    return { tag: "On", tone: "good", meta: s.configured ? "Enabled" : "Enabled — needs a host" };
  };

  return (
    <>
      <AdminHead title="Authentication" sub="How people sign in. Local accounts always work; pick a provider tile to federate sign-in via SSO (OIDC), or authenticate directly against LDAP/AD or TACACS+." />
      <StatStrip>
        <Stat label="Providers" value={AUTH_PROVIDERS.length} />
        <Stat label="Active" value={loaded ? enabledCount : <Skeleton w={26} h={22} />} tone="good" />
        <Stat label="Local fallback" value="On" tone="good" />
      </StatStrip>

      <div className="conn-grid">
        {AUTH_PROVIDERS.map((p) => {
          const st = statusFor(p.id);
          return (
            <button key={p.id} className="conn-tile" onClick={() => setOpen(p.id)} aria-label={`Configure ${p.name}`}>
              <span className={`conn-logo auth-${p.id}`}><Icon name={p.icon} size={24} /></span>
              <span className="conn-body">
                <span className="conn-name">{p.name}<span className={`conn-status ${st.tone}`}>{st.tag}</span></span>
                <span className="conn-tag">{p.tagline}</span>
                <span className="conn-meta">{st.meta}</span>
              </span>
              <span className="conn-cta">{p.id === "local" ? "Details" : "Configure"} →</span>
            </button>
          );
        })}
      </div>

      {open && (() => {
        const p = AUTH_PROVIDERS.find((x) => x.id === open)!;
        return (
          <Modal title={p.name} subtitle={p.tagline} logo={<span className={`conn-logo auth-${p.id}`}><Icon name={p.icon} size={26} /></span>} onClose={() => { setOpen(null); reloadStatus(); }}>
            {open === "local" && (
              <>
                <p className="admin-sub">Local accounts are always available — even when an external IdP is down. They authenticate with username + password (PBKDF2) and issue JWT access tokens with rotating, single-use refresh tokens.</p>
                <p className="mini-meta">Manage individual accounts under <strong>Identity &amp; Access → Users</strong>. Password complexity, lockout and session lifetimes are governed by the per-scope <strong>Security Settings</strong>.</p>
              </>
            )}
            {open === "sso" && <SsoAdminForm roleIds={fallbackRoles} embedded />}
            {open === "ldap" && <LdapAdminForm roleIds={fallbackRoles} embedded />}
            {open === "tacacs" && <TacacsAdminForm roleIds={fallbackRoles} embedded />}
          </Modal>
        );
      })()}
    </>
  );
}

// ---- Single Sign-On (OIDC) form ----
// Mirrors the LDAP/TACACS forms: a kv-persisted overlay over the env defaults,
// with the client secret write-only. Saving rebuilds the live provider on the
// server, so SSO can be turned on without editing .env or restarting.
function SsoAdminForm({ roleIds, embedded = false }: { roleIds: string[]; embedded?: boolean }) {
  const [cfg, setCfg] = useState<OidcConfig | null>(null);
  const [ready, setReady] = useState(false);
  const [secret, setSecret] = useState(""); // typed client secret (only sent if non-empty)
  const [msg, setMsg] = useState<string | null>(null);
  // Top-level view: the relying-party connection wizard vs the Keycloak-brokered
  // upstream identity providers (GUI-configurable SSO, AdminSsoIdp.tsx).
  const [view, setView] = useState<"connection" | "idps">("connection");
  const redirectHint = `${window.location.origin}/api/auth/sso/callback`;

  useEffect(() => {
    api.oidcConfig()
      .then((r) => { setCfg(r.config); setReady(r.ready); })
      .catch((e) => setMsg((e as Error).message));
  }, []);
  if (!cfg) return embedded ? <p className="mini-meta">{msg ?? "Loading…"}</p> : <div className="card"><h2>Single Sign-On (OIDC)</h2><p className="mini-meta">{msg ?? "Loading…"}</p></div>;

  const set = (patch: Partial<OidcConfig>) => setCfg({ ...cfg, ...patch });

  // Throws on error so the Wizard surfaces it; sets a success note otherwise.
  const save = async () => {
    setMsg(null);
    const body: Partial<OidcConfig> & { client_secret?: string } = { ...cfg };
    if (secret) body.client_secret = secret; // only override the secret when re-typed
    const r = await api.saveOidcConfig(body);
    setCfg(r.config); setReady(r.ready); setSecret(""); setMsg("Saved.");
  };

  const head = (
    <>
      <ProviderBadge enabled={cfg.enabled} />
      <span className={`badge ${ready ? "good" : "accent-badge"}`}>{ready ? "Ready" : "Not ready"}</span>
      <label className="auth-enable"><input type="checkbox" checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled</label>
    </>
  );
  return (
    <div className={embedded ? "auth-form" : "card"}>
      {embedded ? (
        <div className="auth-embed-head">{head}</div>
      ) : (
        <div className="admin-card-head">
          <h2>Single Sign-On (OIDC) <ProviderBadge enabled={cfg.enabled} />{" "}
            <span className={`badge ${ready ? "good" : "accent-badge"}`}>{ready ? "Ready" : "Not ready"}</span>
          </h2>
          <label style={{ fontSize: 13 }}>
            <input type="checkbox" checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled
          </label>
        </div>
      )}
      <p className="admin-sub">Federate sign-in to your OIDC identity provider (Authorization Code flow). The platform brokers the login and re-issues its own session. Upstream IdPs such as Okta, Azure AD, Google or any standards-compliant provider are supported. The client secret is write-only — leave blank to keep the stored one.</p>
      <div style={{ marginBottom: 10 }}>
        <Segmented
          ariaLabel="SSO configuration section"
          value={view}
          onChange={setView}
          options={[
            { value: "connection", label: "Connection", title: "Relying-party settings: issuer, client, role mapping, sign-in" },
            { value: "idps", label: "Identity Providers", title: "Upstream SAML/OIDC providers brokered through Keycloak" },
          ]}
        />
      </div>
      {view === "idps" && <SsoIdpPanel roleIds={roleIds} defaultRole={cfg.default_role} />}
      {view === "connection" && <Wizard
        finishLabel="Save"
        onFinish={save}
        steps={[
          {
            id: "connect",
            title: "Connection",
            hint: "Point at your OIDC provider. Issuer and Client ID are required; the secret is write-only.",
            isValid: () => !!cfg.issuer.trim() && !!cfg.client_id.trim(),
            render: () => (
              <>
                <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                  <LabeledInput label="Issuer / Discovery URL" value={cfg.issuer} onChange={(v) => set({ issuer: v })} placeholder="https://idp.example.com/realms/netops" hint="Base issuer URL; /.well-known/openid-configuration is appended." required />
                  <LabeledInput label="Client ID" value={cfg.client_id} onChange={(v) => set({ client_id: v })} placeholder="netops" required info="The OAuth client/application ID registered for NetOps in your identity provider." />
                  <LabeledInput label="Client secret" type="password" value={secret} onChange={setSecret} placeholder={cfg.client_secret_set ? "•••••• (unchanged)" : "(none / public client)"} />
                  <LabeledInput label="Scopes" value={cfg.scopes} onChange={(v) => set({ scopes: v })} placeholder="openid email profile" />
                </div>
                <p className="mini-meta" style={{ marginTop: 8 }}>
                  Register this Redirect URI with your identity provider:{" "}
                  <code className="mono" style={{ userSelect: "all" }}>{redirectHint}</code>
                </p>
                <RequiredLegend />
              </>
            ),
          },
          {
            id: "mapping",
            title: "Role mapping",
            hint: "How IdP identities map to platform roles and tenant.",
            isValid: () => true,
            render: () => (
              <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
                  Default role
                  <select value={cfg.default_role} onChange={(e) => set({ default_role: e.target.value })}>
                    {roleIds.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </label>
                <LabeledInput label="Default tenant" value={cfg.default_tenant} onChange={(v) => set({ default_tenant: v })} />
                <LabeledInput label="Admin roles" value={cfg.admin_roles} onChange={(v) => set({ admin_roles: v })} placeholder="super-admin,admin,netops-admin" hint="Comma-separated IdP roles/groups mapped to super-admin." />
                <LabeledInput label="Operator roles" value={cfg.operator_roles} onChange={(v) => set({ operator_roles: v })} placeholder="operator,netops-operator" hint="Comma-separated IdP roles/groups mapped to operator." />
                <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, marginTop: 6 }}>
                  <input type="checkbox" checked={!!cfg.require_mfa} onChange={(e) => set({ require_mfa: e.target.checked })} />
                  Require multi-factor authentication (reject sign-ins your identity provider didn't verify with a second factor)
                </label>
                {cfg.require_mfa && (
                  <LabeledInput label="MFA assurance values (optional)" value={cfg.mfa_acr ?? ""} onChange={(v) => set({ mfa_acr: v })} placeholder="urn:okta:loa:2fa,gold" hint="Comma-separated acr values your IdP sends for MFA. Leave blank to detect MFA from the sign-in methods (amr)." />
                )}
              </div>
            ),
          },
          {
            id: "signin",
            title: "Sign-in & redirect",
            hint: "Optional sign-in buttons and post-login behavior. Review, then save.",
            isValid: () => true,
            render: () => (
              <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                <LabeledInput label="Providers" value={cfg.providers} onChange={(v) => set({ providers: v })} placeholder="okta:Okta:oidc,ad:Azure AD:saml" hint="Optional sign-in buttons: id:Label:kind, comma-separated. Blank = one default button." />
                <LabeledInput label="Post-login URL" value={cfg.post_login_url} onChange={(v) => set({ post_login_url: v })} placeholder="/" hint="Where the browser lands after a successful login." />
                <LabeledInput label="Redirect URL override" value={cfg.redirect_url} onChange={(v) => set({ redirect_url: v })} placeholder="(derived from request)" hint="Optional; leave blank to derive from the incoming request." />
              </div>
            ),
          },
        ]}
      />}
      {msg && <p className="mini-meta" style={{ marginTop: 6 }}>{msg}</p>}
    </div>
  );
}

// Editable token-lifetime policy. Access TTL is entered in minutes, refresh in
// days; both are clamped server-side to the RFC 9700 / NIST 800-63B bounds.
function TokenPolicyForm({ embedded = false }: { embedded?: boolean }) {
  const [tp, setTp] = useState<TokenPolicy | null>(null);
  const [accessMin, setAccessMin] = useState("");   // minutes
  const [refreshDays, setRefreshDays] = useState(""); // days
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = (p: TokenPolicy) => {
    setTp(p);
    setAccessMin(String(Math.round(p.access_ttl_seconds / 60)));
    setRefreshDays(String(Math.round(p.refresh_ttl_seconds / 86400)));
  };
  useEffect(() => { api.tokenPolicy().then(load).catch((e) => setMsg((e as Error).message)); }, []);
  if (!tp) return embedded ? <p className="mini-meta">{msg ?? "Loading…"}</p> : <div className="card"><h2>Token policy</h2><p className="mini-meta">{msg ?? "Loading…"}</p></div>;

  const b = tp.bounds;
  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const p = await api.saveTokenPolicy({
        access_ttl_seconds: Math.max(1, Math.round(Number(accessMin) * 60)),
        refresh_ttl_seconds: Math.max(1, Math.round(Number(refreshDays) * 86400)),
      });
      load(p); setMsg("Saved. Access TTL applies to new logins immediately; refresh TTL applies to newly issued tokens.");
    } catch (e) { setMsg((e as Error).message); } finally { setBusy(false); }
  };

  const inner = (
    <>
      <p className="admin-sub">Session token lifetimes, clamped to safe bounds (RFC 9700 / NIST 800-63B); out-of-range entries are adjusted on save.</p>
      <div className="form-grid">
        <LabeledInput label="Access token TTL (minutes)" type="number" value={accessMin} onChange={setAccessMin} required
          info={`How long an access token stays valid. Allowed ${Math.round(b.access_min_seconds / 60)}–${Math.round(b.access_max_seconds / 60)} min · recommended ≤ ${Math.round(b.access_recommended_seconds / 60)} min.`} />
        <LabeledInput label="Refresh token TTL (days)" type="number" value={refreshDays} onChange={setRefreshDays} required
          info={`How long a refresh token can renew a session. Allowed ${Math.round(b.refresh_min_seconds / 86400) || 1}–${Math.round(b.refresh_max_seconds / 86400)} days · recommended ≤ ${Math.round(b.refresh_recommended_seconds / 86400)} days.`} />
      </div>
      <dl className="kv-form" style={{ marginTop: 12 }}>
        <dt>Refresh rotation</dt><dd>single-use with reuse detection (reuse revokes the lineage)</dd>
        <dt>Local tokens</dt><dd className="mono">HS256, signed with the server secret</dd>
        <dt>Federated tokens</dt><dd className="mono">RS256, verified against the identity provider's JWKS</dd>
      </dl>
      <RequiredLegend />
      <div className="admin-actions">
        <button className="dash-btn accent" disabled={busy} onClick={save}>Save policy</button>
        {msg && <span className="mini-meta">{msg}</span>}
      </div>
    </>
  );
  return embedded ? inner : <div className="card"><h2>Token policy</h2>{inner}</div>;
}

// ExportPolicyForm — runtime-tunable log-export limits (anti-exfiltration
// guardrails). Applies live; only the platform owner can save (a tenant must not
// be able to raise its own caps). Rendered in Settings.
export function ExportPolicyForm() {
  const [p, setP] = useState<ExportPolicy | null>(null);
  const [f, setF] = useState<Record<string, string>>({});
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = (pol: ExportPolicy) => {
    setP(pol);
    setF({
      rate: String(pol.rate_per_min),
      rows: String(pol.max_rows),
      sizeMB: String(Math.round(pol.max_bytes / (1024 * 1024))),
      runtimeMin: String(Math.round(pol.max_runtime_seconds / 60)),
      rangeHours: String(pol.max_range_hours),
      linkMin: String(Math.round(pol.link_ttl_seconds / 60)),
      syncRows: String(pol.sync_max_rows),
    });
  };
  useEffect(() => { api.exportPolicy().then(load).catch((e) => setMsg((e as Error).message)); }, []);
  if (!p) return <div className="card"><h2>Log export limits</h2><p className="mini-meta">{msg ?? "Loading…"}</p></div>;

  const set = (k: string) => (v: string) => setF((s) => ({ ...s, [k]: v }));
  const num = (v: string, min = 1) => Math.max(min, Math.round(Number(v) || 0));
  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const out = await api.saveExportPolicy({
        rate_per_min: num(f.rate),
        max_rows: num(f.rows),
        max_bytes: num(f.sizeMB) * 1024 * 1024,
        max_runtime_seconds: num(f.runtimeMin) * 60,
        max_range_hours: num(f.rangeHours),
        link_ttl_seconds: num(f.linkMin) * 60,
        sync_max_rows: num(f.syncRows),
      });
      load(out); setMsg("Saved. New limits apply to all exports immediately.");
    } catch (e) { setMsg((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <div className="card">
      <h2>Log export limits</h2>
      <p className="admin-sub">Guardrails for log exports (anti-exfiltration / abuse). Applied live — no restart. Only the platform owner can change them. Download links are clamped to 5–15 minutes.</p>
      <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
        <LabeledInput label="Rate limit (exports / min / tenant)" type="number" value={f.rate} onChange={set("rate")} required />
        <LabeledInput label="Max rows per export" type="number" value={f.rows} onChange={set("rows")} required />
        <LabeledInput label="Max size (MB)" type="number" value={f.sizeMB} onChange={set("sizeMB")} required />
        <LabeledInput label="Max runtime (minutes)" type="number" value={f.runtimeMin} onChange={set("runtimeMin")} required />
        <LabeledInput label="Max time window (hours)" type="number" value={f.rangeHours} onChange={set("rangeHours")} required />
        <LabeledInput label="Download link TTL (minutes)" type="number" value={f.linkMin} onChange={set("linkMin")} hint="clamped 5–15 min" required />
        <LabeledInput label="Sync → async threshold (rows)" type="number" value={f.syncRows} onChange={set("syncRows")} required />
      </div>
      <RequiredLegend />
      <div style={{ marginTop: 12 }}>
        <button className="dash-btn" disabled={busy} onClick={save}>Save limits</button>
      </div>
      {msg && <p className="mini-meta" style={{ marginTop: 6 }}>{msg}</p>}
    </div>
  );
}

// ---- ITSM Integrations — planned -------------------------------------------

// ---- Integrations: connector gallery + combined guided setup ---------------
//
// One tile per system-of-record connector (ServiceNow, Jira). Clicking a tile
// opens a single guided-setup modal that combines EVERYTHING for that connector
// — connection, ticket routing AND bidirectional sync — in one place, instead
// of the old split between an inline form and a separate "bidirectional sync"
// section. Each step refuses to advance until its required fields validate.
// PagerDuty & Slack are alert channels and are configured under Notifications.
//
// Each tile is identified by the vendor's NAME as plain text plus the generic
// FUNCTIONAL glyph its category maps to in components/ConnectorGlyph.tsx
// (ServiceNow → ITSM ticket, Jira → work-item board). No vendor mark and no
// brand colour is rendered anywhere on this surface — tracker 239.

type ConnectorId = "servicenow" | "jira";

const CONNECTORS: { id: ConnectorId; name: string; tagline: string; noun: string }[] = [
  { id: "servicenow", name: "ServiceNow", noun: "incidents", tagline: "Promote critical incidents to ServiceNow via the Table API; auto-resolve when the alert clears." },
  { id: "jira", name: "Jira", noun: "issues", tagline: "One deduped Jira issue per RCA root cause (policy-driven); transitioned to Done on resolve." },
];

const SEV = ["info", "low", "medium", "high", "critical"];

const blankIntegration = (id: string): IntegrationConfig =>
  ({ provider: id, enabled: false, sync_mode: "outbound", webhook_enabled: false, webhook_secret_set: false, state_map: null });

export function IntegrationsAdmin() {
  const [cfg, setCfg] = useState<ItsmConfig | undefined>(undefined);
  const [integrations, setIntegrations] = useState<IntegrationConfig[] | undefined>(undefined);
  const [inboundEnabled, setInboundEnabled] = useState(false);
  const [sn, setSn] = useState<ServiceNowStatus | undefined>(undefined);
  const [jira, setJira] = useState<JiraStatus | undefined>(undefined);
  const [open, setOpen] = useState<ConnectorId | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    api.itsmConfig().then(setCfg).catch((e) => setErr((e as Error).message));
    api.integrations().then((r) => { setIntegrations(r.integrations); setInboundEnabled(r.inbound_enabled); }).catch(() => {});
    api.itsmServiceNow().then(setSn).catch(() => {});
    api.itsmJira().then(setJira).catch(() => {});
  }, []);
  useEffect(load, [load]);

  const sectionFor = (id: ConnectorId) => (id === "servicenow" ? cfg?.servicenow : cfg?.jira);
  const statusFor = (id: ConnectorId) => (id === "servicenow" ? sn : jira);
  const integrationFor = (id: ConnectorId) => integrations?.find((i) => i.provider === id) ?? blankIntegration(id);

  const loaded = cfg !== undefined;
  const configuredCount = [sectionFor("servicenow"), sectionFor("jira")].filter((s) => s?.configured).length;
  const connectedCount = [sectionFor("servicenow"), sectionFor("jira")].filter((s) => s?.configured && s?.enabled).length;
  const openTickets = (sn?.open_count ?? 0) + (jira?.open_count ?? 0);

  return (
    <>
      <AdminHead title="Integrations" sub="Connect NetOps to your system of record. Pick a connector to set up its connection, ticket routing and two-way sync — all in one guided flow." />
      <StatStrip>
        <Stat label="Connectors" value={loaded ? CONNECTORS.length : <Skeleton w={26} h={22} />} />
        <Stat label="Configured" value={loaded ? configuredCount : "—"} tone={configuredCount ? "accent" : ""} />
        <Stat label="Connected" value={loaded ? connectedCount : "—"} tone={connectedCount ? "good" : ""} />
        <Stat label="Open tickets" value={loaded ? openTickets : "—"} tone={openTickets ? "accent" : ""} />
      </StatStrip>

      {err && <div className="card pol-note bad">{err}</div>}

      <div className="conn-grid">
        {CONNECTORS.map((c) => {
          const sec = sectionFor(c.id);
          const st = statusFor(c.id);
          const configured = !!sec?.configured;
          const enabled = !!sec?.enabled;
          const tone = !configured ? "" : enabled ? "good" : "warn";
          const tag = !loaded ? "…" : !configured ? "Not connected" : enabled ? "Connected" : "Disabled";
          return (
            <button key={c.id} className="conn-tile" onClick={() => setOpen(c.id)} aria-label={`Configure ${c.name}`}>
              <span className={`conn-logo ${c.id}`}><ConnectorGlyph connector={c.id} size={40} /></span>
              <span className="conn-body">
                <span className="conn-name">
                  {c.name}
                  <span className={`conn-status ${tone}`}>{tag}</span>
                </span>
                <span className="conn-tag">{c.tagline}</span>
                <span className="conn-meta">
                  {configured && enabled
                    ? `${st?.open_count ?? 0} open ${c.noun} · tickets ≥ ${sec?.min_severity ?? "critical"}`
                    : configured
                      ? "Configured — currently disabled"
                      : "Not set up"}
                </span>
              </span>
              <span className="conn-cta">{configured ? "Manage" : "Set up"} →</span>
            </button>
          );
        })}
      </div>

      {/* Live open tickets per connected connector — real operational data, not config. */}
      {sn?.enabled && (sn.open?.length ?? 0) > 0 && (
        <div className="card">
          <div className="admin-card-head"><h2>ServiceNow — open incidents</h2><span className="badge good">{sn.open_count ?? sn.open!.length}</span></div>
          <table className="ds-table">
            <thead><tr><th>Incident</th><th>Severity</th><th>Device</th><th>Summary</th><th>Opened</th></tr></thead>
            <tbody>
              {sn.open!.map((t) => (
                <tr key={t.fingerprint}>
                  <td className="mono" style={{ fontWeight: 600 }}>{t.number}</td>
                  <td><span className="badge">{t.severity}</span></td>
                  <td className="mono">{t.device || "—"}</td>
                  <td>{t.summary || "—"}</td>
                  <td>{t.opened_at ? fmtDateTime(t.opened_at) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {jira?.enabled && (jira.open?.length ?? 0) > 0 && (
        <div className="card">
          <div className="admin-card-head"><h2>Jira — open issues</h2><span className="badge good">{jira.open_count ?? jira.open!.length}</span></div>
          <table className="ds-table">
            <thead><tr><th>Issue</th><th>Severity</th><th>Device</th><th>Summary</th><th>Opened</th></tr></thead>
            <tbody>
              {jira.open!.map((t) => (
                <tr key={t.fingerprint}>
                  <td className="mono" style={{ fontWeight: 600 }}>{t.key}</td>
                  <td><span className="badge">{t.severity}</span></td>
                  <td className="mono">{t.device || "—"}</td>
                  <td>{t.summary || "—"}</td>
                  <td>{t.opened_at ? fmtDateTime(t.opened_at) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {open && cfg && (
        <ConnectorSetup
          id={open}
          cfg={cfg}
          integration={integrationFor(open)}
          inboundEnabled={inboundEnabled}
          onClose={() => setOpen(null)}
          onSaved={async () => { setOpen(null); load(); }}
        />
      )}
    </>
  );
}

// ConnectorSetup — the combined guided modal for one connector: Connect →
// Routing → Sync → Review. Writes BOTH the ITSM connector config (connection +
// routing) and the Integration-Platform sync config in one save, preserving the
// other connector's stored settings. Secrets (password / API token / webhook
// signing secret) are write-only: a blank field keeps the stored value.
function ConnectorSetup({ id, cfg, integration, inboundEnabled, onClose, onSaved }: {
  id: ConnectorId;
  cfg: ItsmConfig;
  integration: IntegrationConfig;
  inboundEnabled: boolean;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const meta = CONNECTORS.find((c) => c.id === id)!;
  const isSN = id === "servicenow";
  const snInit = cfg.servicenow, jrInit = cfg.jira;

  // Editable drafts. Secret fields start blank (write-only → blank keeps stored).
  const [sn, setSn] = useState({ ...snInit, password: "" });
  const [jr, setJr] = useState({ ...jrInit, api_token: "" });
  const [enabled, setEnabled] = useState(isSN ? snInit.enabled : jrInit.enabled);
  const [syncMode, setSyncMode] = useState<IntegrationConfig["sync_mode"]>(integration.sync_mode);
  const [webhookEnabled, setWebhookEnabled] = useState(integration.webhook_enabled);
  const [secret, setSecret] = useState("");
  const [copied, setCopied] = useState(false);

  const fullUrl = integration.webhook_url ? window.location.origin + integration.webhook_url : "";

  // Step validation — gates the wizard's Next/Save so a half-filled config can't ship.
  const connectValid = isSN
    ? /^https?:\/\//.test(sn.instance_url.trim())
    : /^https?:\/\//.test(jr.base_url.trim()) && !!jr.project_key.trim();
  // Bidirectional inbound needs a signing secret (typed now, or already stored).
  const syncValid = !(syncMode === "bidirectional" && webhookEnabled && !integration.webhook_secret_set && !secret.trim());

  const copy = async () => {
    try { await navigator.clipboard.writeText(fullUrl); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* ignore */ }
  };

  const save = async () => {
    // Preserve the OTHER connector verbatim; only the edited one takes the drafts.
    const body: ItsmConfigInput = {
      servicenow: isSN
        ? { enabled, instance_url: sn.instance_url, user: sn.user, password: sn.password || "", min_severity: sn.min_severity, assignment_group: sn.assignment_group }
        : { enabled: snInit.enabled, instance_url: snInit.instance_url, user: snInit.user, password: "", min_severity: snInit.min_severity, assignment_group: snInit.assignment_group },
      jira: !isSN
        ? { enabled, base_url: jr.base_url, email: jr.email, api_token: jr.api_token || "", project_key: jr.project_key, issue_type: jr.issue_type, min_severity: jr.min_severity, resolve_transition: jr.resolve_transition }
        : { enabled: jrInit.enabled, base_url: jrInit.base_url, email: jrInit.email, api_token: "", project_key: jrInit.project_key, issue_type: jrInit.issue_type, min_severity: jrInit.min_severity, resolve_transition: jrInit.resolve_transition },
    };
    await api.saveItsmConfig(body);
    const intBody: Partial<{ enabled: boolean; sync_mode: string; webhook_enabled: boolean; webhook_secret: string }> = { enabled, sync_mode: syncMode, webhook_enabled: webhookEnabled };
    if (secret.trim()) intBody.webhook_secret = secret.trim();
    await api.saveIntegration(id, intBody);
    await onSaved();
  };

  const steps: WizardStep[] = [
    {
      id: "connect", title: "Connect",
      hint: isSN ? "Where your ServiceNow instance lives and how to authenticate." : "Where your Jira site lives and how to authenticate.",
      isValid: () => connectValid,
      render: () => (
        <>
          <label className="scope-chip" style={{ marginBottom: 12 }}>
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enable this connector
          </label>
          {isSN ? (
            <div className="form-grid">
              <LabeledInput label="Instance URL" value={sn.instance_url} onChange={(v) => setSn({ ...sn, instance_url: v })} placeholder="https://dev12345.service-now.com" required info="Your ServiceNow instance base URL. Incidents are created here via the Table API." />
              <LabeledInput label="User" value={sn.user} onChange={(v) => setSn({ ...sn, user: v })} info="ServiceNow account used to authenticate the REST calls (HTTP basic auth)." />
              <LabeledInput label="Password" type="password" value={sn.password} onChange={(v) => setSn({ ...sn, password: v })} placeholder={snInit.has_password ? "•••••• (unchanged)" : ""} info="Password for the ServiceNow user. Write-only — leave blank to keep the stored value." />
            </div>
          ) : (
            <div className="form-grid">
              <LabeledInput label="Base URL" value={jr.base_url} onChange={(v) => setJr({ ...jr, base_url: v })} placeholder="https://your-org.atlassian.net" required info="Your Jira Cloud site URL. Issues are created here via the Jira REST API." />
              <LabeledInput label="Project key" value={jr.project_key} onChange={(v) => setJr({ ...jr, project_key: v })} placeholder="NOC" required info="The short project key (e.g. NOC) new issues are filed under." />
              <LabeledInput label="Email" value={jr.email} onChange={(v) => setJr({ ...jr, email: v })} placeholder="svc@your-org.com" info="Atlassian account email paired with the API token for authentication." />
              <LabeledInput label="API token" type="password" value={jr.api_token} onChange={(v) => setJr({ ...jr, api_token: v })} placeholder={jrInit.has_token ? "•••••• (unchanged)" : ""} info="Atlassian API token for the account (id.atlassian.com → Security → API tokens). Write-only — blank keeps stored." />
            </div>
          )}
          <RequiredLegend />
        </>
      ),
    },
    {
      id: "routing", title: "Routing",
      hint: "Which alerts cut a ticket, and where they land.",
      isValid: () => true,
      render: () => (
        isSN ? (
          <div className="form-grid">
            <LabeledSelect label="Min severity to ticket" value={sn.min_severity} onChange={(v) => setSn({ ...sn, min_severity: v })} options={SEV} info="Only alerts at or above this severity open a ServiceNow incident." />
            <LabeledInput label="Assignment group (optional)" value={sn.assignment_group} onChange={(v) => setSn({ ...sn, assignment_group: v })} info="ServiceNow assignment group new incidents are routed to. Leave blank to use the instance default." />
          </div>
        ) : (
          <div className="form-grid">
            <LabeledSelect label="Min severity to ticket" value={jr.min_severity} onChange={(v) => setJr({ ...jr, min_severity: v })} options={SEV} info="Only alerts at or above this severity open a Jira issue." />
            <LabeledInput label="Issue type (optional)" value={jr.issue_type} onChange={(v) => setJr({ ...jr, issue_type: v })} placeholder="Incident" info="Jira issue type created for new alerts (e.g. Incident, Bug). Defaults to the project's standard type." />
            <LabeledInput label="Resolve transition (optional)" value={jr.resolve_transition} onChange={(v) => setJr({ ...jr, resolve_transition: v })} placeholder="Done" info="Workflow transition used to close the issue when the alert clears (e.g. Done, Resolve)." />
          </div>
        )
      ),
    },
    {
      id: "sync", title: "Sync",
      hint: "Outbound promotes your incidents to tickets. Bidirectional also applies inbound state changes (close, reassign) back onto the incident via a registered webhook.",
      isValid: () => syncValid,
      render: () => (
        <>
          <div className="form-grid">
            <LabeledSelect label="Sync mode" value={syncMode} onChange={(v) => setSyncMode(v as IntegrationConfig["sync_mode"])} options={["outbound", "bidirectional"]} info="Outbound promotes incidents to tickets. Bidirectional also applies inbound state changes (close, reassign) back onto the incident." />
            <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>Inbound webhook<InfoTip label="Let the provider push state changes back via a registered, HMAC-signed webhook. Requires bidirectional mode + a signing secret.">Let the provider push state changes back via a registered, HMAC-signed webhook. Requires bidirectional mode + a signing secret.</InfoTip></span>
              <label className="mini-meta" style={{ display: "flex", gap: 6, alignItems: "center", padding: "8px 0" }}>
                <input type="checkbox" checked={webhookEnabled} disabled={syncMode !== "bidirectional"} onChange={(e) => setWebhookEnabled(e.target.checked)} /> Accept inbound state changes
              </label>
            </label>
            <LabeledInput label={`Webhook signing secret${integration.webhook_secret_set ? " (stored)" : ""}`} type="password" value={secret} onChange={setSecret} placeholder={integration.webhook_secret_set ? "•••••• (unchanged)" : "shared secret for HMAC verification"} info="Shared secret used to HMAC-verify inbound webhooks from the provider. Write-only — blank keeps stored." />
          </div>
          {syncMode === "bidirectional" && webhookEnabled && !integration.webhook_secret_set && !secret.trim() && (
            <p className="pol-row-err" role="alert">A signing secret is required to accept inbound webhooks.</p>
          )}
          {fullUrl && (
            <div style={{ marginTop: 12 }}>
              <span className="mini-meta">Inbound webhook URL — register this with {meta.name}</span>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 4 }}>
                <input readOnly value={fullUrl} onFocus={(e) => e.currentTarget.select()} className="mono" style={{ flex: 1, padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" }} />
                <button className="dash-btn" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
              </div>
            </div>
          )}
          {!inboundEnabled && (
            <p className="mini-meta" style={{ marginTop: 8 }}>Inbound webhooks are recorded but not yet driving incident state — pending platform enablement.</p>
          )}
        </>
      ),
    },
    {
      id: "review", title: "Review",
      isValid: () => true,
      render: () => (
        <div style={{ display: "grid", gap: 8 }}>
          <p className="mini-meta">Saving hot-swaps the connector live — no restart.</p>
          <dl className="kv-form">
            <dt>Status</dt><dd>{enabled ? "Enabled" : "Disabled"}</dd>
            <dt>{isSN ? "Instance" : "Site"}</dt><dd className="mono">{isSN ? (sn.instance_url || "—") : (jr.base_url || "—")}</dd>
            {!isSN && <><dt>Project</dt><dd className="mono">{jr.project_key || "—"}</dd></>}
            <dt>Tickets at</dt><dd>{(isSN ? sn.min_severity : jr.min_severity)} and worse</dd>
            <dt>Sync</dt><dd>{syncMode}{syncMode === "bidirectional" && webhookEnabled ? " · inbound webhook on" : ""}</dd>
          </dl>
        </div>
      ),
    },
  ];

  return (
    <Modal title={meta.name} subtitle={meta.tagline} logo={<span className={`conn-logo ${id}`}><ConnectorGlyph connector={id} size={28} /></span>} onClose={onClose}>
      <Wizard steps={steps} onFinish={save} onCancel={onClose} finishLabel="Save & connect" />
    </Modal>
  );
}

// ---- Notifications (SMTP / Twilio / ntfy) ----------------------------------

const SEVERITIES = ["info", "notice", "warning", "error", "critical"];

// Notification channels presented as a branded tile gallery (same pattern as
// Integrations). SMS (Twilio) and Push (ntfy) are grouped into one "SMS & Push"
// tile since both are phone-delivery channels. EVERY tile — third-party
// destinations included — uses a generic functional stroke glyph plus the
// destination's name as text (components/ConnectorGlyph.tsx, tracker 239); no
// vendor artwork and no brand colour is rendered here.
type ChannelId = "email" | "mobile" | "slack" | "pagerduty" | "teams" | "sns";
const CHANNELS: { id: ChannelId; name: string; tagline: string; logo: JSX.Element }[] = [
  { id: "email", name: "Email", tagline: "SMTP relay — route alert emails to your NOC distribution list.", logo: <Icon name="mail" size={26} /> },
  { id: "mobile", name: "SMS & Push", tagline: "Phone alerts — SMS via Twilio and free push via ntfy.", logo: <Icon name="smartphone" size={26} /> },
  { id: "slack", name: "Slack", tagline: "Post alerts to a Slack channel via an Incoming Webhook.", logo: <ConnectorGlyph connector="slack" size={26} /> },
  { id: "pagerduty", name: "PagerDuty", tagline: "On-call escalation via the PagerDuty Events API v2.", logo: <ConnectorGlyph connector="pagerduty" size={26} /> },
  { id: "teams", name: "Microsoft Teams", tagline: "Post alerts to a Teams channel via an Incoming Webhook.", logo: <ConnectorGlyph connector="teams" size={26} /> },
  { id: "sns", name: "Amazon SNS", tagline: "Publish to an SNS topic or SMS phone numbers — AWS credentials come from the deployment environment.", logo: <AwsLogo size={30} /> },
];

// FieldError — the inline, field-level validation message shown under an input
// when the client-side mirror of a server validator rejects what was typed. Kept
// as one component so every channel form reports a rejection identically.
function FieldError({ msg }: { msg?: string }) {
  if (!msg) return null;
  return <p className="pol-row-err" role="alert" style={{ margin: "2px 0 0" }}>{msg}</p>;
}

function SeveritySelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
      <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>Send on severity ≥<InfoTip label="Only alerts at or above this severity are delivered to this channel.">Only alerts at or above this severity are delivered to this channel.</InfoTip></span>
      <select value={value} onChange={(e) => onChange(e.target.value)}
        style={{ padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" }}>
        {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>
    </label>
  );
}

// SyncSettings — collapsible bidirectional-sync controls for a provider, shown
// inside that provider's home card (PagerDuty/Slack under Notifications;
// ServiceNow/Jira have the same controls in their Integrations connector setup).
// Outbound promotes incidents to the system; bidirectional also applies inbound
// state changes back via a registered, HMAC-signed webhook. Writes through the
// Integration Platform (saveIntegration). Signing secret is write-only.
function SyncSettings({ integration, inboundEnabled, webhookHint, onSaved }: {
  integration: IntegrationConfig;
  inboundEnabled: boolean;
  webhookHint: string;
  onSaved: (next: IntegrationConfig) => void;
}) {
  const [enabled, setEnabled] = useState(integration.enabled);
  const [syncMode, setSyncMode] = useState<IntegrationConfig["sync_mode"]>(integration.sync_mode);
  const [webhookEnabled, setWebhookEnabled] = useState(integration.webhook_enabled);
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const fullUrl = integration.webhook_url ? window.location.origin + integration.webhook_url : "";
  const needsSecret = syncMode === "bidirectional" && webhookEnabled && !integration.webhook_secret_set && !secret.trim();
  const summary = !enabled ? "Off" : syncMode === "bidirectional" ? "Two-way" : "Outbound";

  const copy = async () => {
    try { await navigator.clipboard.writeText(fullUrl); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* ignore */ }
  };
  const save = async () => {
    if (needsSecret) { setMsg("A signing secret is required to accept inbound webhooks."); return; }
    setBusy(true); setMsg(null);
    try {
      const body: Partial<{ enabled: boolean; sync_mode: string; webhook_enabled: boolean; webhook_secret: string }> = { enabled, sync_mode: syncMode, webhook_enabled: webhookEnabled };
      if (secret.trim()) body.webhook_secret = secret.trim();
      const next = await api.saveIntegration(integration.provider, body);
      onSaved(next); setSecret(""); setMsg("Saved.");
    } catch (e) { setMsg((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <details className="sync-block">
      <summary>Bidirectional sync <span className={`conn-status ${enabled ? "good" : ""}`}>{summary}</span></summary>
      <p className="mini-meta">Outbound promotes incidents to this system. Bidirectional also applies inbound state changes (ack, resolve, reassign) back onto the incident via a registered webhook.</p>
      <label className="scope-chip" style={{ marginBottom: 8 }}>
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enable two-way sync
      </label>
      <div className="form-grid">
        <LabeledSelect label="Sync mode" value={syncMode} onChange={(v) => setSyncMode(v as IntegrationConfig["sync_mode"])} options={["outbound", "bidirectional"]} />
        <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
          <span>Inbound webhook</span>
          <label className="mini-meta" style={{ display: "flex", gap: 6, alignItems: "center", padding: "8px 0" }}>
            <input type="checkbox" checked={webhookEnabled} disabled={syncMode !== "bidirectional"} onChange={(e) => setWebhookEnabled(e.target.checked)} /> Accept inbound state changes
          </label>
        </label>
        <LabeledInput label={`Webhook signing secret${integration.webhook_secret_set ? " (stored)" : ""}`} type="password" value={secret} onChange={setSecret} placeholder={integration.webhook_secret_set ? "•••••• (unchanged)" : "shared secret for HMAC verification"} hint="write-only — blank keeps stored" />
      </div>
      {needsSecret && <p className="pol-row-err" role="alert">A signing secret is required to accept inbound webhooks.</p>}
      {fullUrl && (
        <div style={{ marginTop: 12 }}>
          <span className="mini-meta">Inbound webhook URL — register this with the provider</span>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 4 }}>
            <input readOnly value={fullUrl} onFocus={(e) => e.currentTarget.select()} className="mono" style={{ flex: 1, padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" }} />
            <button className="dash-btn" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
          </div>
          <p className="mini-meta" style={{ marginTop: 4 }}>{webhookHint}</p>
        </div>
      )}
      {!inboundEnabled && <p className="mini-meta" style={{ marginTop: 8 }}>Inbound webhooks are recorded but not yet driving incident state — pending platform enablement.</p>}
      <div className="admin-actions">
        <button onClick={save} disabled={busy}>{busy ? "Saving…" : "Save sync"}</button>
        {msg && <span className="mini-meta">{msg}</span>}
      </div>
    </details>
  );
}

export function NotificationsAdmin() {
  // The five delivery channels (SMTP, Twilio SMS, ntfy push, Slack, PagerDuty)
  // are platform-GLOBAL plumbing — every config endpoint behind their tiles is
  // platform-gated, so for a tenant admin the tiles are only 403'd loads and
  // dead forms. Render them (and fetch their config) only for the resolved
  // platform principal; contact points ARE tenant-scoped and stay for everyone.
  const { user, loading: authLoading } = useAuth();
  const platform = !authLoading && !!user?.platform_admin;
  const [smtp, setSmtp] = useState<SmtpConfig | null>(null);
  const [twilio, setTwilio] = useState<TwilioConfig | null>(null);
  const [ntfy, setNtfy] = useState<NtfyConfig | null>(null);
  const [slack, setSlack] = useState<SlackConfig | null>(null);
  const [pager, setPager] = useState<PagerDutyConfig | null>(null);
  const [teams, setTeams] = useState<TeamsConfig | null>(null);
  const [sns, setSns] = useState<SNSConfig | null>(null);
  // Bidirectional-sync config (Integration Platform) for the channels that
  // support it — PagerDuty & Slack live here; ServiceNow/Jira sync lives in the
  // Integrations connector setup.
  const [integrations, setIntegrations] = useState<IntegrationConfig[] | null>(null);
  const [inboundEnabled, setInboundEnabled] = useState(false);
  const [openCh, setOpenCh] = useState<ChannelId | null>(null); // which channel's setup modal is open
  const [secret, setSecret] = useState({ smtp: "", twilio: "", ntfy: "", slack: "", pager: "", teams: "" });
  const [msg, setMsg] = useState<Record<string, string>>({});
  // Contact points (reusable delivery audiences referenced by reports).
  const [cps, setCps] = useState<ContactPoint[]>([]);
  const emptyCP: Partial<ContactPoint> = { name: "", type: "email", email: [], target: "", enabled: true };
  const [cpDraft, setCpDraft] = useState<Partial<ContactPoint>>(emptyCP);
  const [cpEmails, setCpEmails] = useState(""); // comma-separated editor for email type

  const loadCps = () => api.contactPoints().then(setCps).catch(() => {});

  useEffect(() => {
    loadCps();
  }, []);

  // Channel config is platform-gated server-side — don't fire five calls that
  // can only 403 for a tenant admin; wait until auth resolves platform.
  useEffect(() => {
    if (!platform) return;
    api.smtpConfig().then(setSmtp).catch(() => {});
    api.twilioConfig().then(setTwilio).catch(() => {});
    api.ntfyConfig().then(setNtfy).catch(() => {});
    api.slackConfig().then(setSlack).catch(() => {});
    api.pagerDutyConfig().then(setPager).catch(() => {});
    api.notifyTeams().then(setTeams).catch(() => {});
    api.notifySNS().then(setSns).catch(() => {});
    api.integrations().then((r) => { setIntegrations(r.integrations); setInboundEnabled(r.inbound_enabled); }).catch(() => {});
  }, [platform]);

  const integrationFor = (id: string): IntegrationConfig => integrations?.find((i) => i.provider === id) ?? blankIntegration(id);
  const onIntegrationSaved = (next: IntegrationConfig) =>
    setIntegrations((cur) => {
      const arr = (cur ?? []).slice();
      const i = arr.findIndex((x) => x.provider === next.provider);
      if (i >= 0) arr[i] = next; else arr.push(next);
      return arr;
    });

  const editCp = (cp: ContactPoint) => {
    setCpDraft({ ...cp });
    setCpEmails((cp.email ?? []).join(", "));
  };
  const resetCp = () => { setCpDraft(emptyCP); setCpEmails(""); };
  const saveCp = async () => {
    try {
      const body: Partial<ContactPoint> = { ...cpDraft };
      if (cpDraft.type === "email") {
        body.email = cpEmails.split(",").map((s) => s.trim()).filter(Boolean);
        body.target = "";
      } else {
        body.email = [];
      }
      await api.saveContactPoint(body);
      resetCp();
      await loadCps();
      flash("cp", "Saved.");
    } catch (e) { flash("cp", (e as Error).message); }
  };
  const deleteCp = async (cp: ContactPoint) => {
    if (!window.confirm(`Delete contact point "${cp.name}"?`)) return;
    try { await api.deleteContactPoint(cp.id); await loadCps(); }
    catch (e) { flash("cp", (e as Error).message); }
  };

  const flash = (k: string, m: string) => setMsg((p) => ({ ...p, [k]: m }));

  const saveSmtp = async () => {
    if (!smtp) return;
    try {
      const body: Partial<SmtpConfig> = { ...smtp };
      if (secret.smtp) body.pass = secret.smtp;
      setSmtp(await api.saveSmtpConfig(body)); setSecret((s) => ({ ...s, smtp: "" })); flash("smtp", "Saved.");
    } catch (e) { flash("smtp", (e as Error).message); }
  };
  const saveTwilio = async () => {
    if (!twilio) return;
    try {
      const body: Partial<TwilioConfig> = { ...twilio };
      if (secret.twilio) body.auth_token = secret.twilio;
      setTwilio(await api.saveTwilioConfig(body)); setSecret((s) => ({ ...s, twilio: "" })); flash("twilio", "Saved.");
    } catch (e) { flash("twilio", (e as Error).message); }
  };
  const saveNtfy = async () => {
    if (!ntfy) return;
    try {
      const body: Partial<NtfyConfig> = { ...ntfy };
      if (secret.ntfy) body.token = secret.ntfy;
      setNtfy(await api.saveNtfyConfig(body)); setSecret((s) => ({ ...s, ntfy: "" })); flash("ntfy", "Saved.");
    } catch (e) { flash("ntfy", (e as Error).message); }
  };
  const saveSlack = async () => {
    if (!slack) return;
    try {
      const body: Partial<SlackConfig> = { ...slack };
      if (secret.slack) body.webhook_url = secret.slack;
      setSlack(await api.saveSlackConfig(body)); setSecret((s) => ({ ...s, slack: "" })); flash("slack", "Saved.");
    } catch (e) { flash("slack", (e as Error).message); }
  };
  const savePager = async () => {
    if (!pager) return;
    try {
      const body: Partial<PagerDutyConfig> = { ...pager };
      if (secret.pager) body.routing_key = secret.pager;
      setPager(await api.savePagerDutyConfig(body)); setSecret((s) => ({ ...s, pager: "" })); flash("pager", "Saved.");
    } catch (e) { flash("pager", (e as Error).message); }
  };
  // Teams / SNS (G10). Validation mirrors the API's own validators
  // (lib/notifyValidation) so a rejection names the field inline instead of
  // arriving as an opaque 400 — the server still re-validates every PUT.
  const teamsErrs: FieldErrors = teams
    ? teamsErrors({ enabled: teams.enabled, webhookSet: !!teams.webhook_set, typedWebhook: secret.teams })
    : {};
  const snsErrs: FieldErrors = sns
    ? snsErrors({ enabled: sns.enabled, topic_arn: sns.topic_arn, region: sns.region, phone_numbers: sns.phone_numbers, scope: sns.scope })
    : {};

  const saveTeams = async () => {
    if (!teams) return;
    if (hasErrors(teamsErrs)) { flash("teams", "Fix the highlighted fields first."); return; }
    try {
      // The webhook is write-only: send it ONLY when the operator typed a
      // replacement. Omitting it is what tells the API to keep the stored one.
      const body: Partial<TeamsConfig> = { enabled: teams.enabled, min_severity: teams.min_severity };
      if (secret.teams.trim()) body.webhook_url = secret.teams.trim();
      setTeams(await api.notifyTeamsUpdate(body)); setSecret((s) => ({ ...s, teams: "" })); flash("teams", "Saved.");
    } catch (e) { flash("teams", (e as Error).message); }
  };
  const saveSns = async () => {
    if (!sns) return;
    if (hasErrors(snsErrs)) { flash("sns", "Fix the highlighted fields first."); return; }
    try {
      // credentials_set is a read-only status field — never echo it back.
      const body: Partial<SNSConfig> = {
        enabled: sns.enabled, topic_arn: sns.topic_arn.trim(), region: sns.region.trim(),
        phone_numbers: sns.phone_numbers.trim(), min_severity: sns.min_severity, scope: sns.scope,
      };
      setSns(await api.notifySNSUpdate(body)); flash("sns", "Saved.");
    } catch (e) { flash("sns", (e as Error).message); }
  };
  const test = async (k: string, fn: () => Promise<{ status: string }>) => {
    try { await fn(); flash(k, "Test sent — check your inbox/phone."); }
    catch (e) { flash(k, "Test failed: " + (e as Error).message); }
  };

  return (
    <>
      <AdminHead
        title="Notifications"
        sub={platform
          ? "Email, SMS and push channels. Critical alerts route here; secrets are write-only."
          : "Reusable contact points that scheduled reports deliver to. Delivery channels are operated at the platform level."}
      />
      {platform ? (() => {
        const loaded = smtp !== null;
        const groups = [!!smtp?.enabled, !!(twilio?.enabled || ntfy?.enabled), !!slack?.enabled, !!pager?.enabled, !!teams?.enabled, !!sns?.enabled];
        const enabled = groups.filter(Boolean).length;
        return (
          <StatStrip>
            <Stat label="Channels" value={loaded ? CHANNELS.length : <Skeleton w={26} h={22} />} />
            <Stat label="Enabled" value={loaded ? enabled : "—"} tone={enabled ? "good" : ""} />
            <Stat label="Contact points" value={cps.length} tone="accent" />
          </StatStrip>
        );
      })() : (
        <StatStrip>
          <Stat label="Contact points" value={cps.length} tone="accent" />
        </StatStrip>
      )}

      {/* Channel gallery — pick a channel to open its guided setup. Platform
          principal only: every tile's API surface is requirePlatformAdmin. */}
      {platform && <div className="conn-grid">
        {CHANNELS.map((c) => {
          const loaded = smtp !== null;
          let enabled = false, configured = false, metaLine = "";
          if (c.id === "email") {
            enabled = !!smtp?.enabled; configured = !!smtp?.host;
            metaLine = configured ? `Relay ${smtp?.host}` : "Not set up";
          } else if (c.id === "mobile") {
            enabled = !!(twilio?.enabled || ntfy?.enabled);
            configured = !!(twilio?.account_sid || ntfy?.topic);
            metaLine = [twilio?.account_sid ? "SMS" : null, ntfy?.topic ? "Push" : null].filter(Boolean).join(" · ") || "Not set up";
          } else if (c.id === "slack") {
            enabled = !!slack?.enabled; configured = !!slack?.webhook_set;
            metaLine = configured ? "Webhook configured" : "Not set up";
          } else if (c.id === "pagerduty") {
            enabled = !!pager?.enabled; configured = !!pager?.routing_set;
            metaLine = configured ? "Routing key configured" : "Not set up";
          } else if (c.id === "teams") {
            enabled = !!teams?.enabled; configured = !!teams?.webhook_set;
            metaLine = configured ? "Webhook configured" : "Not set up";
          } else {
            enabled = !!sns?.enabled; configured = !!(sns?.topic_arn || sns?.phone_numbers);
            metaLine = !configured ? "Not set up"
              : [sns?.topic_arn ? "Topic" : null, sns?.phone_numbers ? "SMS" : null].filter(Boolean).join(" \u00b7 ");
          }
          const tone = !configured ? "" : enabled ? "good" : "warn";
          const tag = !loaded ? "…" : !configured ? "Not set up" : enabled ? "On" : "Off";
          return (
            <button key={c.id} className="conn-tile" onClick={() => setOpenCh(c.id)} aria-label={`Configure ${c.name}`}>
              <span className={`conn-logo ${c.id}`}>{c.logo}</span>
              <span className="conn-body">
                <span className="conn-name">{c.name}<span className={`conn-status ${tone}`}>{tag}</span></span>
                <span className="conn-tag">{c.tagline}</span>
                <span className="conn-meta">{metaLine}</span>
              </span>
              <span className="conn-cta">{configured ? "Manage" : "Set up"} →</span>
            </button>
          );
        })}
      </div>}

      {/* Channel setup modal — the selected channel's full configuration. */}
      {platform && openCh && (() => {
        const ch = CHANNELS.find((c) => c.id === openCh)!;
        return (
          <Modal title={ch.name} subtitle={ch.tagline} logo={<span className={`conn-logo ${ch.id}`}>{ch.logo}</span>} onClose={() => setOpenCh(null)}>
            {openCh === "email" && smtp && (
              <>
                <label className="scope-chip" style={{ marginBottom: 12 }}>
                  <input type="checkbox" checked={smtp.enabled} onChange={(e) => setSmtp({ ...smtp, enabled: e.target.checked })} /> Enable email delivery
                </label>
                <div className="form-grid">
                  <LabeledInput label="Host" value={smtp.host} onChange={(v) => setSmtp({ ...smtp, host: v })} required placeholder="smtp.example.com" info="Hostname of your SMTP relay (e.g. smtp.example.com)." />
                  <LabeledInput label="Port" type="number" value={String(smtp.port)} onChange={(v) => setSmtp({ ...smtp, port: Number(v) || 0 })} required placeholder="587" info="SMTP port — 587 for STARTTLS, 465 for TLS-on-connect, 25 for plain relay." />
                  <LabeledInput label="From" value={smtp.from} onChange={(v) => setSmtp({ ...smtp, from: v })} required placeholder="noc@example.com" info="The From address alert emails are sent as." />
                  <LabeledInput label="Recipients (comma-separated)" value={smtp.to} onChange={(v) => setSmtp({ ...smtp, to: v })} required info="One or more addresses that receive alert emails, comma-separated." />
                  <LabeledInput label="Username" value={smtp.user} onChange={(v) => setSmtp({ ...smtp, user: v })} info="SMTP auth username. Leave blank for an unauthenticated relay." />
                  <LabeledInput label={`Password${smtp.pass_set ? " (stored)" : ""}`} type="password" value={secret.smtp} onChange={(v) => setSecret((s) => ({ ...s, smtp: v }))} placeholder={smtp.pass_set ? "•••••• (unchanged)" : ""} info="SMTP auth password. Write-only — blank keeps the stored value." />
                  <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>Security<InfoTip label="Transport encryption: STARTTLS (587), implicit TLS on connect (465), or none (plain, insecure).">Transport encryption: STARTTLS (587), implicit TLS on connect (465), or none (plain, insecure).</InfoTip></span>
                    <select value={smtp.security} onChange={(e) => setSmtp({ ...smtp, security: e.target.value })} style={{ padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" }}>
                      <option value="starttls">STARTTLS (587, secure)</option>
                      <option value="tls">TLS on connect (465, secure)</option>
                      <option value="none">None (plain relay, insecure)</option>
                    </select>
                  </label>
                  <SeveritySelect value={smtp.min_severity} onChange={(v) => setSmtp({ ...smtp, min_severity: v })} />
                </div>
                <RequiredLegend />
                <div className="admin-actions">
                  <button onClick={saveSmtp}>Save</button>
                  <button className="ghost" onClick={() => test("smtp", api.testSmtp)}>Send test</button>
                  {msg.smtp && <span className="mini-meta">{msg.smtp}</span>}
                </div>
              </>
            )}

            {openCh === "mobile" && (
              <>
                <h3 className="ds-modal-section"><ConnectorGlyph connector="twilio" size={18} /> SMS · Twilio</h3>
                <p className="mini-meta">Phone SMS for critical alerts. Twilio is metered — use ntfy below for free testing.</p>
                {twilio && (
                  <>
                    <label className="scope-chip" style={{ margin: "10px 0" }}>
                      <input type="checkbox" checked={twilio.enabled} onChange={(e) => setTwilio({ ...twilio, enabled: e.target.checked })} /> Enable SMS delivery
                    </label>
                    <div className="form-grid">
                      <LabeledInput label="Account SID" value={twilio.account_sid} onChange={(v) => setTwilio({ ...twilio, account_sid: v })} required info="Your Twilio Account SID (starts with AC…), from the Twilio Console dashboard." />
                      <LabeledInput label={`Auth token${twilio.token_set ? " (stored)" : ""}`} type="password" value={secret.twilio} onChange={(v) => setSecret((s) => ({ ...s, twilio: v }))} placeholder={twilio.token_set ? "•••••• (unchanged)" : ""} info="Twilio auth token paired with the SID. Write-only — blank keeps stored." />
                      <LabeledInput label="From number" value={twilio.from} onChange={(v) => setTwilio({ ...twilio, from: v })} required placeholder="+15555550123" info="A Twilio phone number in E.164 format that messages are sent from." />
                      <LabeledInput label="To numbers (comma-separated)" value={twilio.to} onChange={(v) => setTwilio({ ...twilio, to: v })} required info="Recipient phone numbers in E.164 format, comma-separated." />
                      <SeveritySelect value={twilio.min_severity} onChange={(v) => setTwilio({ ...twilio, min_severity: v })} />
                    </div>
                    <div className="admin-actions">
                      <button onClick={saveTwilio}>Save SMS</button>
                      <button className="ghost" onClick={() => test("twilio", api.testTwilio)}>Send test</button>
                      {msg.twilio && <span className="mini-meta">{msg.twilio}</span>}
                    </div>
                  </>
                )}
                <h3 className="ds-modal-section" style={{ marginTop: 18 }}><Icon name="bell" size={16} /> Push · ntfy</h3>
                <p className="mini-meta">Free push to phone/desktop — subscribe to the topic in the ntfy app. Great for testing critical-alert pushes without Twilio.</p>
                {ntfy && (
                  <>
                    <label className="scope-chip" style={{ margin: "10px 0" }}>
                      <input type="checkbox" checked={ntfy.enabled} onChange={(e) => setNtfy({ ...ntfy, enabled: e.target.checked })} /> Enable push delivery
                    </label>
                    <div className="form-grid">
                      <LabeledInput label="Server" value={ntfy.server} onChange={(v) => setNtfy({ ...ntfy, server: v })} placeholder="https://ntfy.sh" info="ntfy server base URL — the public https://ntfy.sh or your self-hosted instance." />
                      <LabeledInput label="Topic" value={ntfy.topic} onChange={(v) => setNtfy({ ...ntfy, topic: v })} required placeholder="netops-xxxxxx" info="The ntfy topic to publish to — subscribe to it in the ntfy app to receive pushes." />
                      <LabeledInput label={`Token (optional)${ntfy.token_set ? " (stored)" : ""}`} type="password" value={secret.ntfy} onChange={(v) => setSecret((s) => ({ ...s, ntfy: v }))} placeholder={ntfy.token_set ? "•••••• (unchanged)" : "for protected topics"} info="Access token for protected topics. Write-only — blank keeps stored." />
                      <SeveritySelect value={ntfy.min_severity} onChange={(v) => setNtfy({ ...ntfy, min_severity: v })} />
                    </div>
                    <div className="admin-actions">
                      <button onClick={saveNtfy}>Save push</button>
                      <button className="ghost" onClick={() => test("ntfy", api.testNtfy)}>Send test</button>
                      {msg.ntfy && <span className="mini-meta">{msg.ntfy}</span>}
                    </div>
                  </>
                )}
                <RequiredLegend />
              </>
            )}

            {openCh === "slack" && slack && (
              <>
                <label className="scope-chip" style={{ marginBottom: 12 }}>
                  <input type="checkbox" checked={slack.enabled} onChange={(e) => setSlack({ ...slack, enabled: e.target.checked })} /> Enable Slack delivery
                </label>
                <div className="form-grid">
                  <LabeledInput label={`Webhook URL${slack.webhook_set ? " (stored)" : ""}`} type="password" value={secret.slack} onChange={(v) => setSecret((s) => ({ ...s, slack: v }))} placeholder={slack.webhook_set ? "•••••• (unchanged)" : "https://hooks.slack.com/services/…"} required={!slack.webhook_set} info="Slack Incoming Webhook URL (api.slack.com → Incoming Webhooks). It embeds a secret, so it's write-only." />
                  <SeveritySelect value={slack.min_severity} onChange={(v) => setSlack({ ...slack, min_severity: v })} />
                </div>
                <RequiredLegend />
                <div className="admin-actions">
                  <button onClick={saveSlack}>Save</button>
                  <button className="ghost" onClick={() => test("slack", api.testSlack)}>Send test</button>
                  {msg.slack && <span className="mini-meta">{msg.slack}</span>}
                </div>
                <SyncSettings integration={integrationFor("slack")} inboundEnabled={inboundEnabled} webhookHint="Paste into your Slack app's Interactivity & Shortcuts request URL." onSaved={onIntegrationSaved} />
              </>
            )}

            {openCh === "pagerduty" && pager && (
              <>
                <label className="scope-chip" style={{ marginBottom: 12 }}>
                  <input type="checkbox" checked={pager.enabled} onChange={(e) => setPager({ ...pager, enabled: e.target.checked })} /> Enable PagerDuty delivery
                </label>
                <div className="form-grid">
                  <LabeledInput label={`Routing key${pager.routing_set ? " (stored)" : ""}`} type="password" value={secret.pager} onChange={(v) => setSecret((s) => ({ ...s, pager: v }))} placeholder={pager.routing_set ? "•••••• (unchanged)" : "32-char integration key"} required={!pager.routing_set} info="Events API v2 integration (routing) key from your PagerDuty service. Write-only — blank keeps stored." />
                  <SeveritySelect value={pager.min_severity} onChange={(v) => setPager({ ...pager, min_severity: v })} />
                </div>
                <RequiredLegend />
                <div className="admin-actions">
                  <button onClick={savePager}>Save</button>
                  <button className="ghost" onClick={() => test("pager", api.testPagerDuty)}>Send test</button>
                  {msg.pager && <span className="mini-meta">{msg.pager}</span>}
                </div>
                <SyncSettings integration={integrationFor("pagerduty")} inboundEnabled={inboundEnabled} webhookHint="Paste into a PagerDuty v3 webhook subscription." onSaved={onIntegrationSaved} />
              </>
            )}

            {openCh === "teams" && teams && (
              <>
                <label className="scope-chip" style={{ marginBottom: 12 }}>
                  <input type="checkbox" checked={teams.enabled} onChange={(e) => setTeams({ ...teams, enabled: e.target.checked })} /> Enable Teams delivery
                </label>
                <div className="form-grid">
                  <div>
                    <LabeledInput label={`Webhook URL${teams.webhook_set ? " (stored)" : ""}`} type="password" value={secret.teams} onChange={(v) => setSecret((s) => ({ ...s, teams: v }))} placeholder={teams.webhook_set ? "\u2022\u2022\u2022\u2022\u2022\u2022 (unchanged)" : "https://\u2026.webhook.office.com/webhookb2/\u2026"} required={!teams.webhook_set} info="Teams Incoming Webhook URL (channel \u2192 Connectors \u2192 Incoming Webhook). It embeds a bearer token, so it is write-only \u2014 blank keeps the stored value." />
                    <FieldError msg={teamsErrs.webhook_url} />
                    {teams.webhook_set && <p className="mini-meta" style={{ marginTop: 2 }}>A webhook is stored. Type a new one to replace it; leave blank to keep it.</p>}
                  </div>
                  <SeveritySelect value={teams.min_severity} onChange={(v) => setTeams({ ...teams, min_severity: v })} />
                </div>
                <RequiredLegend />
                <div className="admin-actions">
                  <button onClick={saveTeams}>Save</button>
                  <button className="ghost" onClick={() => test("teams", api.notifyTeamsTest)}>Send test</button>
                  {msg.teams && <span className="mini-meta">{msg.teams}</span>}
                </div>
              </>
            )}

            {openCh === "sns" && sns && (
              <>
                <label className="scope-chip" style={{ marginBottom: 12 }}>
                  <input type="checkbox" checked={sns.enabled} onChange={(e) => setSns({ ...sns, enabled: e.target.checked })} /> Enable SNS delivery
                </label>
                <div className="form-grid">
                  <div>
                    <LabeledInput label="Topic ARN" value={sns.topic_arn} onChange={(v) => setSns({ ...sns, topic_arn: v })} placeholder="arn:aws:sns:us-east-1:123456789012:netops-alerts" info="The SNS topic alerts are published to. Optional if you deliver to phone numbers only." />
                    <FieldError msg={snsErrs.topic_arn} />
                  </div>
                  <div>
                    <LabeledInput label="Region" value={sns.region} onChange={(v) => setSns({ ...sns, region: v })} placeholder="us-east-1" info="AWS region of the SNS endpoint. Blank derives it from the topic ARN." />
                    <FieldError msg={snsErrs.region} />
                  </div>
                  <div>
                    <LabeledInput label="Phone numbers (comma-separated)" value={sns.phone_numbers} onChange={(v) => setSns({ ...sns, phone_numbers: v })} placeholder="+14155550123, +14155550124" info="Optional E.164 numbers to SMS directly, in addition to (or instead of) the topic." />
                    <FieldError msg={snsErrs.phone_numbers} />
                  </div>
                  <div>
                    <LabeledSelect label="Scope" value={sns.scope} onChange={(v) => setSns({ ...sns, scope: v })} options={["all", "platform"]} info={"\"platform\" restricts this globally-credentialled pager to Correlix self-health alerts; \"all\" sends every alert that clears the severity floor."} />
                    <FieldError msg={snsErrs.scope} />
                  </div>
                  <SeveritySelect value={sns.min_severity} onChange={(v) => setSns({ ...sns, min_severity: v })} />
                </div>
                {/* AWS credentials are deliberately NOT editable here: they live in
                    the deployment environment and are never stored or returned by
                    the API, so the surface can only report their presence. */}
                <div className="ds-readonly-note">
                  <span className="mini-meta">
                    AWS credentials come from the environment (<code>AWS_ACCESS_KEY_ID</code> / <code>AWS_SECRET_ACCESS_KEY</code>) and are never stored or shown here.
                  </span>
                  <span className={`conn-status ${sns.credentials_set ? "good" : "warn"}`}>
                    {sns.credentials_set ? "Credentials detected" : "Credentials not set"}
                  </span>
                </div>
                <RequiredLegend />
                <div className="admin-actions">
                  <button onClick={saveSns}>Save</button>
                  <button className="ghost" onClick={() => test("sns", api.notifySNSTest)}>Send test</button>
                  {msg.sns && <span className="mini-meta">{msg.sns}</span>}
                </div>
              </>
            )}
          </Modal>
        );
      })()}

      {/* Contact points — reusable, tenant-scoped delivery audiences referenced
          by Reports. Email-type points resolve to addresses the scheduler emails
          directly; slack/webhook types are stored for future routing. */}
      <div className="card">
        <div className="admin-card-head">
          <h2>Contact points</h2>
        </div>
        <p className="mini-meta">
          Reusable delivery audiences (email groups, Slack, webhooks) that Reports
          deliver to. Scoped to the current tenant.
        </p>

        {cps.length > 0 && (
          <table className="ds-table" style={{ width: "100%", marginBottom: 12 }}>
            <thead>
              <tr><th>Name</th><th>Type</th><th>Recipients</th><th>Enabled</th><th></th></tr>
            </thead>
            <tbody>
              {cps.map((cp) => (
                <tr key={cp.id}>
                  <td>{cp.name}</td>
                  <td>{cp.type}</td>
                  <td className="mini-meta">{cp.type === "email" ? (cp.email ?? []).join(", ") : cp.target}</td>
                  <td>{cp.enabled ? "Yes" : "No"}</td>
                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    <button className="ghost" onClick={() => editCp(cp)}>Edit</button>
                    <button className="ghost" onClick={() => deleteCp(cp)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="form-grid">
          <LabeledInput label="Name" value={cpDraft.name ?? ""} onChange={(v) => setCpDraft({ ...cpDraft, name: v })} required placeholder="NOC on-call" />
          <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
            <span>Type</span>
            <select value={cpDraft.type ?? "email"} onChange={(e) => setCpDraft({ ...cpDraft, type: e.target.value as ContactPointType })}
              style={{ padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" }}>
              {(["email", "slack", "webhook"] as ContactPointType[]).map((t) => <option key={t} value={t}>{t === "email" ? "Email" : t === "slack" ? "Slack" : "Webhook"}</option>)}
            </select>
          </label>
          {cpDraft.type === "email" ? (
            <LabeledInput label="Email recipients (comma-separated)" value={cpEmails} onChange={setCpEmails} required placeholder="a@example.com, b@example.com" />
          ) : (
            <LabeledInput label="Target (webhook URL / Slack channel)" value={cpDraft.target ?? ""} onChange={(v) => setCpDraft({ ...cpDraft, target: v })} required />
          )}
          <label className="mini-meta" style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={cpDraft.enabled ?? true} onChange={(e) => setCpDraft({ ...cpDraft, enabled: e.target.checked })} /> Enabled
          </label>
        </div>
        <RequiredLegend />
        <div className="admin-actions">
          <button onClick={saveCp}>{cpDraft.id ? "Update" : "Add"}</button>
          {cpDraft.id && <button className="ghost" onClick={resetCp}>Cancel</button>}
          {msg.cp && <span className="mini-meta">{msg.cp}</span>}
        </div>
      </div>
    </>
  );
}

// ---- RCA Auto-Ticketing — Incident Policies (#78) --------------------------
// Per-tenant policies that decide when an RCA correlation object opens an
// external (ServiceNow) ticket. Tenant-scoped + administration-gated by the API;
// the connection itself is configured in Incident Response → Integrations.

function PolicyCheck({ label, info, checked, onChange, disabled }: {
  label: string; info?: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean;
}) {
  return (
    <label className="scope-chip" style={{ opacity: disabled ? 0.6 : 1 }}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <FieldLabel label={label} info={info} />
    </label>
  );
}

function blankPolicy(): IncidentPolicy {
  return {
    id: "", name: "", external_system: "servicenow", enabled: true, min_verdict: "suspected",
    require_customer_facing: true, allow_probe_only: false, allow_internal_monitoring: false,
    suspected_requires_critical: true, require_persistence_seconds: 0, suppress_flapping_seconds: 0,
    assignment_group: "", default_impact: 2, default_urgency: 2,
  };
}

// gate summary chips for the list row.
function policyGates(p: IncidentPolicy): string[] {
  const g: string[] = [`≥ ${p.min_verdict}`];
  if (p.suspected_requires_critical) g.push("suspected needs critical");
  if (p.require_customer_facing) g.push("customer-facing");
  if (p.allow_probe_only) g.push("probe-only allowed");
  if (p.allow_internal_monitoring) g.push("internal allowed");
  if (p.require_persistence_seconds > 0) g.push(`persist ${p.require_persistence_seconds}s`);
  return g;
}

function PolicyEditor({ policy, canWrite, onSaved, onCancel, inModal }: {
  policy: IncidentPolicy; canWrite: boolean; onSaved: () => void; onCancel: () => void; inModal?: boolean;
}) {
  const [p, setP] = useState<IncidentPolicy>(policy);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof IncidentPolicy>(k: K, v: IncidentPolicy[K]) => setP((cur) => ({ ...cur, [k]: v }));

  // Simulator (only meaningful for a saved policy — /test loads it server-side).
  const [facts, setFacts] = useState<IncidentPolicyTestFacts>({ verdict: "confirmed", peak_severity: "crit", has_affected_entity: true });
  const [decision, setDecision] = useState<TicketPolicyDecision | null>(null);

  const save = async () => {
    if (!p.name.trim()) { setErr("Name is required."); return; }
    setBusy(true); setErr(null);
    try {
      if (p.id) await api.incidentPolicyUpdate(p.id, p);
      else await api.incidentPolicyCreate(p);
      onSaved();
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(false); }
  };
  const del = async () => {
    if (!p.id) { onCancel(); return; }
    if (!window.confirm(`Delete policy "${p.name}"? RCA objects will stop auto-ticketing under it.`)) return;
    setBusy(true); setErr(null);
    try { await api.incidentPolicyDelete(p.id); onSaved(); } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(false); }
  };
  const simulate = async () => {
    if (!p.id) { setErr("Save the policy first, then simulate."); return; }
    setErr(null);
    try { setDecision(await api.incidentPolicyTest(p.id, facts)); } catch (e: any) { setErr(String(e?.message ?? e)); }
  };

  return (
    <div className={inModal ? "" : "card"} style={inModal ? undefined : { padding: "var(--sp-4)" }}>
      {!inModal && (
        <div className="admin-head-row">
          <h3 style={{ margin: 0 }}>{p.id ? "Edit incident policy" : "New incident policy"}</h3>
          <button className="btn" onClick={onCancel}>← Back to list</button>
        </div>
      )}
      <ErrLine msg={err} />

      <div className="form-grid" style={{ marginTop: "var(--sp-3)" }}>
        <LabeledInput label="Policy name" required value={p.name} onChange={(v) => set("name", v)}
          placeholder="e.g. Customer-impacting outages" info="A label for this policy; shown in the list and audit." />
        <LabeledSelect label="External system" value={p.external_system} onChange={(v) => set("external_system", v)}
          options={["servicenow", "pagerduty", "slack", "jira"]}
          info="Where this policy delivers: ServiceNow opens ITSM incidents; PagerDuty pages the on-call; Slack posts to the tenant's channel; Jira opens issues in the tenant's project. One enabled policy per system — a tenant can run any combination." />
        <LabeledSelect label="Minimum verdict" value={p.min_verdict} onChange={(v) => set("min_verdict", v)}
          options={["suspected", "confirmed"]} info="The lowest RCA verdict that may open a ticket." />
        {p.external_system === "servicenow" && (
          <LabeledInput label="Assignment group" value={p.assignment_group ?? ""} onChange={(v) => set("assignment_group", v)}
            placeholder="(optional) ServiceNow group" info="Routes the incident to a ServiceNow assignment group." />
        )}
        <LabeledInput label="Default impact (1–4)" type="number" value={String(p.default_impact)} onChange={(v) => set("default_impact", Number(v) || 0)} />
        <LabeledInput label="Default urgency (1–4)" type="number" value={String(p.default_urgency)} onChange={(v) => set("default_urgency", Number(v) || 0)} />
        <LabeledInput label="Min persistence (seconds)" type="number" value={String(p.require_persistence_seconds)} onChange={(v) => set("require_persistence_seconds", Number(v) || 0)}
          info="Hold a fault this long before ticketing (flap suppression on the way in). 0 = off." />
        <LabeledInput label="Flap suppression (seconds)" type="number" value={String(p.suppress_flapping_seconds)} onChange={(v) => set("suppress_flapping_seconds", Number(v) || 0)}
          info="After a ticket resolves, suppress re-opening within this window. 0 = off." />
      </div>

      {p.external_system === "pagerduty" && (
        <p className="mini-meta" style={{ margin: "var(--sp-2) 0 0" }}>
          Pages are deduplicated per root cause: one PagerDuty incident per correlated incident, updated in place and
          auto-resolved on recovery. Urgency above maps to page severity (1 = critical). Connect the routing key under
          PagerDuty paging connection on this page. Raw alerts never page directly.
        </p>
      )}
      {p.external_system === "slack" && (
        <p className="mini-meta" style={{ margin: "var(--sp-2) 0 0" }}>
          One rich message per root-cause lifecycle transition (opened / materially updated / resolved) in this tenant's
          own channel — never per raw alert. Connect the webhook under Slack channel connection on this page.
        </p>
      )}
      {p.external_system === "jira" && (
        <p className="mini-meta" style={{ margin: "var(--sp-2) 0 0" }}>
          One deduplicated Jira issue per root cause, updated in place and transitioned to Done on resolve — never per
          raw alert. Connect the Jira site (base URL, project, token) in <b>Incident Response → Integrations</b>. Jira
          policies are strictly opt-in: no Jira policy, no issues.
        </p>
      )}
      {p.external_system === "servicenow" && (<>
      {/* Per-verdict ticket priority mapping — the ITSM derives Priority from Impact x Urgency. */}
      <h4 style={{ margin: "var(--sp-3) 0 var(--sp-1)" }}>Ticket priority mapping</h4>
      <p className="mini-meta" style={{ margin: "0 0 var(--sp-2)" }}>
        The ticketing system derives Priority from Impact x Urgency. 0 = automatic: a confirmed critical fault files at
        1 / 1 (highest priority), a confirmed fault raises Urgency to High, and a suspected fault uses the defaults above.
      </p>
      <div className="form-grid">
        <LabeledInput label="Impact — confirmed critical" type="number" value={String(p.impact_confirmed_critical ?? 0)}
          onChange={(v) => set("impact_confirmed_critical", Number(v) || 0)} info="0 = automatic (1)." />
        <LabeledInput label="Urgency — confirmed critical" type="number" value={String(p.urgency_confirmed_critical ?? 0)}
          onChange={(v) => set("urgency_confirmed_critical", Number(v) || 0)} info="0 = automatic (1)." />
        <LabeledInput label="Impact — confirmed" type="number" value={String(p.impact_confirmed ?? 0)}
          onChange={(v) => set("impact_confirmed", Number(v) || 0)} info="0 = automatic (the default impact above)." />
        <LabeledInput label="Urgency — confirmed" type="number" value={String(p.urgency_confirmed ?? 0)}
          onChange={(v) => set("urgency_confirmed", Number(v) || 0)} info="0 = automatic (High)." />
      </div>
      </>)}

      <div style={{ display: "flex", flexWrap: "wrap", gap: "var(--sp-2)", marginTop: "var(--sp-3)" }}>
        <PolicyCheck label="Enabled" info="When off, this policy never opens tickets (a tenant opt-out)." checked={p.enabled} onChange={(v) => set("enabled", v)} />
        <PolicyCheck label="Require customer-facing" info="Only ticket objects with a meaningful affected device/path/app." checked={p.require_customer_facing} onChange={(v) => set("require_customer_facing", v)} />
        <PolicyCheck label="Suspected needs critical" info="A suspected (not yet confirmed) verdict only tickets at critical severity." checked={p.suspected_requires_critical} onChange={(v) => set("suspected_requires_critical", v)} />
        <PolicyCheck label="Allow probe-only" info="Allow ticketing when the only evidence is an active probe (overrides the ≥2-stream rule)." checked={p.allow_probe_only} onChange={(v) => set("allow_probe_only", v)} />
        <PolicyCheck label="Allow internal monitoring" info="Allow ticketing internal-only monitoring (off keeps non-customer noise out)." checked={p.allow_internal_monitoring} onChange={(v) => set("allow_internal_monitoring", v)} />
      </div>
      <RequiredLegend />

      {canWrite && (
        <div className="admin-actions" style={{ marginTop: "var(--sp-3)" }}>
          <button className="btn primary" disabled={busy} onClick={save}>{busy ? "Saving…" : "Save policy"}</button>
          {p.id && <button className="btn" disabled={busy} onClick={del} style={{ color: "var(--bad)" }}>Delete</button>}
        </div>
      )}

      {/* Simulator — a pure dry-run: would a hypothetical object ticket under this policy? */}
      <div className="card" style={{ padding: "var(--sp-3)", marginTop: "var(--sp-4)", background: "var(--bg)" }}>
        <h4 style={{ margin: "0 0 var(--sp-2)" }}>Simulate a decision</h4>
        <p className="mini-meta" style={{ marginTop: 0 }}>Dry-run this policy against a hypothetical RCA object — no ticket is created.</p>
        <div className="form-grid">
          <LabeledSelect label="Verdict" value={facts.verdict} onChange={(v) => setFacts((f) => ({ ...f, verdict: v }))} options={["undetermined", "suspected", "confirmed"]} />
          <LabeledSelect label="Peak severity" value={facts.peak_severity ?? "crit"} onChange={(v) => setFacts((f) => ({ ...f, peak_severity: v }))} options={["info", "warn", "high", "crit"]} />
          <LabeledInput label="Persistence (seconds)" type="number" value={String(facts.persistence_seconds ?? 0)} onChange={(v) => setFacts((f) => ({ ...f, persistence_seconds: Number(v) || 0 }))} />
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "var(--sp-2)", marginTop: "var(--sp-2)" }}>
          <PolicyCheck label="Internal monitoring" checked={!!facts.internal} onChange={(v) => setFacts((f) => ({ ...f, internal: v }))} />
          <PolicyCheck label="Probe-only" checked={!!facts.probe_only} onChange={(v) => setFacts((f) => ({ ...f, probe_only: v }))} />
          <PolicyCheck label="Low-authority probe" checked={!!facts.low_authority_probe} onChange={(v) => setFacts((f) => ({ ...f, low_authority_probe: v }))} />
          <PolicyCheck label="Has affected entity" checked={!!facts.has_affected_entity} onChange={(v) => setFacts((f) => ({ ...f, has_affected_entity: v }))} />
        </div>
        <div className="admin-actions" style={{ marginTop: "var(--sp-2)" }}>
          <button className="btn" onClick={simulate} disabled={!p.id} title={p.id ? "" : "Save the policy first"}>Simulate</button>
        </div>
        {decision && (
          <div style={{ marginTop: "var(--sp-2)" }}>
            <p style={{ margin: 0 }}>
              <span className={`badge ${decision.create ? "good" : "warn"}`}>{decision.create ? "Would open a ticket" : "Held"}</span>{" "}
              <span className="mini-meta">{decision.reason}</span>
            </p>
            {decision.policy_name && (
              <p className="mini-meta" style={{ margin: "var(--sp-1) 0 0" }}>
                Evaluated policy: <b>{decision.policy_name}</b>
                {decision.policy_updated_at ? ` · saved ${fmtDateTime(decision.policy_updated_at)}` : ""}
              </p>
            )}
            {decision.runtime_state === "shadowed" && (
              <p className="mini-meta" style={{ margin: "var(--sp-1) 0 0", color: "var(--warn, #b45309)" }}>
                Not the live policy — “{decision.runtime_policy_name || "another policy"}” currently governs auto-ticketing
                for this tenant, so this dry-run does not reflect live behavior.
              </p>
            )}
            {decision.runtime_state === "held" && (
              <p className="mini-meta" style={{ margin: "var(--sp-1) 0 0", color: "var(--bad, #b91c1c)" }}>
                Auto-ticketing is HELD for this tenant — more than one policy is enabled. Disable all but one to resume.
              </p>
            )}
            {decision.runtime_state === "opted_out" && (
              <p className="mini-meta" style={{ margin: "var(--sp-1) 0 0" }}>
                Auto-ticketing is switched off for this tenant — no policy is enabled, so no ticket would open automatically.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function PagerDutyPagingConnection() {
  const [cfg, setCfg] = useState<ItsmConfig | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [key, setKey] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  useEffect(() => {
    api.itsmConfig().then((c) => { setCfg(c); setEnabled(!!c.pagerduty?.enabled); }).catch((e) => setErr((e as Error).message));
  }, []);
  const save = async () => {
    setErr(""); setMsg("");
    try {
      const out = await api.saveItsmPagerDutyRCA({ enabled, ...(key.trim() ? { routing_key: key.trim() } : {}) });
      setCfg(out); setKey(""); setMsg("Saved.");
    } catch (e) { setErr((e as Error).message); }
  };
  const hasKey = !!cfg?.pagerduty?.has_routing_key;
  return (
    <div className="cc-panel" style={{ padding: "var(--sp-3)", marginBottom: "var(--sp-3)" }}>
      <h4 style={{ margin: 0 }}>PagerDuty paging connection</h4>
      <p className="mini-meta" style={{ margin: "var(--sp-1) 0 var(--sp-2)" }}>
        This tenant's own Events API v2 routing key — used ONLY by PagerDuty incident policies below
        (one page per correlated root cause, auto-resolved on recovery). Raw alerts never page directly.
      </p>
      <div style={{ display: "flex", gap: "var(--sp-2)", alignItems: "center", flexWrap: "wrap" }}>
        <label className="scope-chip"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
        <input className="app-input" type="password" style={{ minWidth: 280 }} value={key}
          placeholder={hasKey ? "routing key set — leave blank to keep" : "Events API v2 integration key"}
          onChange={(e) => setKey(e.target.value)} autoComplete="new-password" />
        <button className="btn btn-primary" onClick={() => { void save(); }}>Save</button>
        {hasKey && <span className="mini-meta">key stored (write-only)</span>}
        {msg && <span className="mini-meta">{msg}</span>}
      </div>
      <ErrLine msg={err} />
    </div>
  );
}

function SlackChannelConnection() {
  const [cfg, setCfg] = useState<ItsmConfig | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [url, setUrl] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  useEffect(() => {
    api.itsmConfig().then((c) => { setCfg(c); setEnabled(!!c.slack?.enabled); }).catch((e) => setErr((e as Error).message));
  }, []);
  const save = async () => {
    setErr(""); setMsg("");
    try {
      const out = await api.saveItsmSlackRCA({ enabled, ...(url.trim() ? { webhook_url: url.trim() } : {}) });
      setCfg(out); setUrl(""); setMsg("Saved.");
    } catch (e) { setErr((e as Error).message); }
  };
  const hasHook = !!cfg?.slack?.has_webhook;
  return (
    <div className="cc-panel" style={{ padding: "var(--sp-3)", marginBottom: "var(--sp-3)" }}>
      <h4 style={{ margin: 0 }}>Slack channel connection</h4>
      <p className="mini-meta" style={{ margin: "var(--sp-1) 0 var(--sp-2)" }}>
        This tenant's own incoming-webhook URL — used ONLY by Slack incident policies below (one message per
        correlated root cause lifecycle, never per raw alert).
      </p>
      <div style={{ display: "flex", gap: "var(--sp-2)", alignItems: "center", flexWrap: "wrap" }}>
        <label className="scope-chip"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
        <input className="app-input" type="password" style={{ minWidth: 280 }} value={url}
          placeholder={hasHook ? "Webhook is set — leave blank to keep it" : "https://hooks.slack.com/services/…"}
          onChange={(e) => setUrl(e.target.value)} autoComplete="new-password" />
        <button className="btn btn-primary" onClick={() => { void save(); }}>Save</button>
        {hasHook && <span className="mini-meta">webhook stored (write-only)</span>}
        {msg && <span className="mini-meta">{msg}</span>}
      </div>
      <ErrLine msg={err} />
    </div>
  );
}

export function IncidentPoliciesAdmin() {
  const { user } = useAuth();
  const [policies, setPolicies] = useState<IncidentPolicy[] | null>(null);
  const [sel, setSel] = useState<IncidentPolicy | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [canWrite, setCanWrite] = useState(false);

  // At most ONE policy may be enabled per ticketing system — the backend holds
  // all auto-ticketing when legacy data violates that, so surface it loudly.
  const conflictSystems = new Set(
    Object.entries(
      (policies ?? []).filter((p) => p.enabled).reduce<Record<string, number>>((acc, p) => {
        const sys = p.external_system || "servicenow";
        acc[sys] = (acc[sys] ?? 0) + 1;
        return acc;
      }, {}),
    ).filter(([, n]) => n > 1).map(([sys]) => sys),
  );

  const load = useCallback(() => {
    setErr(null);
    api.incidentPolicies().then((r) => setPolicies(r.policies ?? [])).catch((e) => {
      setPolicies([]);
      setErr(String(e?.message ?? e).includes("403") ? "You need administration access to manage incident policies." : String(e?.message ?? e));
    });
  }, []);
  useEffect(() => {
    load();
    api.permissions().then((p) => setCanWrite((p.permissions?.administration ?? 0) >= 2)).catch(() => setCanWrite(false));
  }, [load]);

  return (
    <>
      {sel && (
        <Modal
          title={sel.id ? "Edit incident policy" : "New incident policy"}
          subtitle="Decide when an RCA correlation object reaches this destination — one ticket/page per root cause."
          wide
          onClose={() => setSel(null)}
        >
          <PolicyEditor policy={sel} canWrite={canWrite} inModal onCancel={() => setSel(null)} onSaved={() => { setSel(null); load(); }} />
        </Modal>
      )}
      <AdminHead title="RCA Auto-Ticketing" sub="Incident policies that decide when an RCA correlation object opens a ServiceNow ticket or Jira issue, pages PagerDuty, or posts to Slack — one ticket/page per root cause, never per raw alert." />
      <p className="mini-meta" style={{ marginTop: "calc(-1 * var(--sp-2))" }}>
        Configure the ServiceNow and Jira connections in <b>Incident Response → Integrations</b>; the PagerDuty routing key and
        Slack webhook below. A tenant with no policy uses a safe ServiceNow default (customer-facing confirmed faults open an
        incident; internal / probe-only / undetermined are held). Every other destination is strictly opt-in: no policy, no delivery.
      </p>
      <PagerDutyPagingConnection />
      <SlackChannelConnection />
      <ErrLine msg={err} />
      {conflictSystems.size > 0 && (
        <ErrLine msg={"More than one policy is enabled — auto-ticketing is HELD for this tenant until exactly one policy is enabled. Disable the extra policies below."} />
      )}

      <div className="admin-head-row" style={{ marginTop: "var(--sp-2)" }}>
        <StatStrip>
          <Stat label="Policies" value={policies?.length ?? "—"} />
          <Stat label="Active" value={policies ? policies.filter((p) => p.enabled).length : "—"} tone={conflictSystems.size > 0 ? "bad" : "good"} />
        </StatStrip>
        {canWrite && <button className="btn primary" onClick={() => setSel(blankPolicy())}>+ New policy</button>}
      </div>

      {policies === null ? (
        <Skeleton h={120} style={{ marginTop: "var(--sp-3)" }} />
      ) : policies.length === 0 ? (
        <p className="mini-meta" style={{ marginTop: "var(--sp-3)" }}>
          No policies yet — the safe default applies. {canWrite ? "Create one to tune ticketing for this tenant." : ""}
        </p>
      ) : (
        <table className="ds-table" style={{ marginTop: "var(--sp-3)" }}>
          <thead>
            <tr><th>Name</th><th>Status</th><th>Gates</th><th>Routing</th><th /></tr>
          </thead>
          <tbody>
            {policies.map((p) => (
              <tr key={p.id} style={{ cursor: "pointer" }} onClick={() => setSel(p)}>
                {/* Row click is a pointer shortcut; the name button is the
                    keyboard-operable way in (2.1.1). */}
                <td>
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); setSel(p); }}
                    style={{ background: "none", border: 0, padding: 0, font: "inherit", color: "inherit", cursor: "pointer" }}
                  >
                    <b>{p.name || "(unnamed)"}</b>
                  </button>
                </td>
                <td>
                  {p.enabled && conflictSystems.has(p.external_system || "servicenow")
                    ? <span className="badge bad">Conflict — ticketing held</span>
                    : <span className={`badge ${p.enabled ? "good" : ""}`}>{p.enabled ? "Active" : "Disabled"}</span>}
                </td>
                <td className="mini-meta">{policyGates(p).join(" · ")}</td>
                <td className="mini-meta">{p.assignment_group || "—"}</td>
                <td style={{ textAlign: "right" }}><button className="btn" onClick={(e) => { e.stopPropagation(); setSel(p); }}>{canWrite ? "Edit" : "View"}</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {!canWrite && policies && policies.length >= 0 && (
        <p className="mini-meta" style={{ marginTop: "var(--sp-2)" }}>Read-only — administration write access is required to change policies.</p>
      )}
      {user && null}
    </>
  );
}
