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

import { useCallback, useEffect, useState } from "react";
import { api, AdminUser, AdminSession, Role, Tenant, Org, Region, RoleBinding, SecuritySettings as SecuritySettingsT, ApiKey, CreateApiKeyRequest, LdapConfig, TacacsConfig, OidcConfig, AuthTestResult, LdapRoleMapping, TokenPolicy, ExportPolicy, SmtpConfig, TwilioConfig, NtfyConfig, SlackConfig, PagerDutyConfig, ContactPoint, ContactPointType, ItsmConfig, ItsmConfigInput, IntegrationConfig, ServiceNowStatus, JiraStatus } from "../services/api";
import { BRAND } from "../brand";
import Wizard, { WizardStep } from "../components/Wizard";
import { StatStrip, Stat, Skeleton, InfoTip, Modal, Segmented } from "../components/ui";
import { ServiceNowLogo, JiraLogo, SlackLogo, TwilioLogo, PagerDutyLogo } from "../components/ConnectorLogos";
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

function ErrLine({ msg }: { msg: string | null }) {
  if (!msg) return null;
  return <p style={{ color: "var(--bad)", fontSize: "var(--fs-meta)", margin: "0 0 var(--sp-2)" }}>{msg}</p>;
}

// useReload gives a [data, error, reload, setError] tuple over an async loader.
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
                <td>{u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "—"}</td>
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
    ? "Roles you define. Click a cell to set its access level."
    : "Control what each role can see and change. Built-in roles are fixed; click a cell on a custom role to set its access.";
  return (
    <>
      <div className="admin-head-row">
        <AdminHead title={title} sub={sub} />
        {canCreate && <button className="dash-btn accent" onClick={addRole}>＋ New custom role</button>}
      </div>
      {tenantScoped && (
        <div className="card" style={{ fontSize: 12, color: "var(--muted)", borderLeft: "3px solid var(--accent)" }}>
          These roles are shared across the platform and shown here for reference. Assign them to this tenant's
          people in <b>Users</b>. Tenant-specific roles are coming soon.
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
                        title={r.builtin ? "built-in (read-only)" : "click to cycle"}
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
  const [org, setOrg] = useState(orgId ?? "");
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
    try { await api.createTenant(name.trim(), note.trim(), hideGlobal, useOrg, region); setName(""); setNote(""); setOrg(orgId ?? ""); setRegion(""); setHideGlobal(false); setAdding(false); reload(); } catch (e) { setErr((e as Error).message); }
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
              <label className="req-field">
                <span>Organization <Req /></span>
                <select value={org} onChange={(e) => { setOrg(e.target.value); setRegion(""); }}>
                  <option value="">Select organization…</option>
                  {(orgs ?? []).map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
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
            <button className="dash-btn" onClick={() => { setAdding(false); setName(""); setOrg(orgId ?? ""); setRegion(""); setNote(""); setHideGlobal(false); setErr(null); }}>Cancel</button>
            <button className="dash-btn accent" disabled={!name.trim() || !(orgId || org)} onClick={create}>Create tenant</button>
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
                <th>Organization</th>
                <th>Region</th>
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
                    <td style={{ fontWeight: 600 }}>{t.name}</td>
                    <td>
                      <span className={`badge ${isParent ? "accent" : ""}`}>
                        {isParent ? "Parent Tenant" : "Child Tenant"}
                      </span>
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
                      {isParent ? (
                        <span style={{ color: "var(--muted)", fontSize: 12 }}>—</span>
                      ) : (
                        <button
                          type="button"
                          role="switch"
                          aria-checked={!t.operator_restricted}
                          className={`vis-toggle${t.operator_restricted ? "" : " on"}`}
                          onClick={() => toggleGlobalVisibility(t)}
                          title={t.operator_restricted ? "Hidden from the global view — click to make visible" : "Visible in the global view — click to hide (data privacy)"}
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
  const [name, setName] = useState("");
  const [region, setRegion] = useState("");
  const [sso, setSso] = useState("");
  const [note, setNote] = useState("");
  const [edit, setEdit] = useState<Org | null>(null);
  const [adding, setAdding] = useState(false); // create form is hidden until clicked

  const regionLabel = (id: string) => (regions ?? []).find((r) => r.id === id)?.label || id;
  const tenantCount = (orgId: string) =>
    (tenants ?? []).filter((t) => (t.org_id || "global") === orgId).length;
  // Org members = accounts strictly associated with the org (tenant_id = org id),
  // mirroring tenant-user logic — no tenant record required.
  const memberCount = (orgId: string) =>
    (users ?? []).filter((u) => u.tenant_id === orgId).length;

  const create = async () => {
    if (!name.trim()) return;
    setErr(null);
    try {
      await api.createOrg(name.trim(), { homeRegion: region, ssoConnection: sso.trim(), note: note.trim() });
      setName(""); setRegion(""); setSso(""); setNote(""); setAdding(false); reload();
    } catch (e) { setErr((e as Error).message); }
  };
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
        <AdminHead title="Organizations" sub="Top-level accounts. Each organization has a home data region and sign-in, inherited by the tenants inside it." />
        {!adding && <button className="dash-btn accent" onClick={() => { setAdding(true); setErr(null); }}>＋ Create organization</button>}
      </div>
      <StatStrip>
        <Stat label="Organizations" value={orgs ? list.length : <Skeleton w={26} h={22} />} />
      </StatStrip>
      {adding && (
        <div className="card">
          <div className="admin-card-head"><h2>New organization</h2></div>
          <ErrLine msg={err} />
          <div className="admin-form">
            <label className="req-field">
              <span>Name <Req /></span>
              <input autoFocus placeholder="e.g. Acme Corp" value={name} onChange={(e) => setName(e.target.value)} />
            </label>
            <label className="req-field">
              <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                Region <Req />
                <InfoTip label="The data-residency region for this organization — where its tenants' telemetry is meant to live. Tenants inherit it unless overridden.">
                  The data-residency region for this organization — where its tenants' telemetry is meant to live. Tenants inherit this unless you override it per tenant.
                </InfoTip>
              </span>
              <select value={region} onChange={(e) => setRegion(e.target.value)}>
                <option value="">Select region…</option>
                {(regions ?? []).map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
              </select>
            </label>
            <label>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                Sign-in connection
                <InfoTip label="Optional. Binds this organization to its own identity provider so its people sign in through their company's SSO; leave blank to use the platform's default sign-in.">
                  Optional. Bind this organization to its own identity provider (SSO) so its people sign in through their company's login. Leave blank to use the platform default.
                </InfoTip>
              </span>
              <input placeholder="optional" value={sso} onChange={(e) => setSso(e.target.value)} />
            </label>
            <label style={{ flex: 2 }}>
              <span>Note</span>
              <input placeholder="optional" value={note} onChange={(e) => setNote(e.target.value)} />
            </label>
            <button className="dash-btn" onClick={() => { setAdding(false); setName(""); setRegion(""); setSso(""); setNote(""); setErr(null); }}>Cancel</button>
            <button className="dash-btn accent" disabled={!name.trim() || !region} onClick={create}>Create organization</button>
          </div>
          <RequiredLegend />
        </div>
      )}
      {!adding && <ErrLine msg={err} />}
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
                      {onManageOrg && !isRoot
                        ? <button className="ia-linkname" onClick={() => onManageOrg(o.id, o.name)}>{o.name}</button>
                        : o.name}
                      {isRoot && <span className="badge accent" style={{ marginLeft: 6 }}>Parent Organization</span>}
                    </td>
                    <td><span className="badge">{regionLabel(o.home_region)}</span></td>
                    <td style={{ color: "var(--muted)" }}>{isRoot ? "—" : memberCount(o.id)}</td>
                    <td style={{ color: "var(--muted)" }}>{tenantCount(o.id)}</td>
                    <td style={{ color: "var(--muted)", fontSize: 12 }}>{o.sso_connection || "Platform default"}</td>
                    <td style={{ color: "var(--muted)" }}>{o.note || "—"}</td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      {onManageOrg && !isRoot && <button className="dash-btn accent" style={{ marginRight: 6 }} onClick={() => onManageOrg(o.id, o.name)}>Manage</button>}
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
      <AdminHead title="Regions" sub="Where each tenant's data lives. One global control plane routes tenants to a regional data plane by their assigned region." />
      <ErrLine msg={err} />
      <StatStrip>
        <Stat label="Control plane" value="Global" />
        <Stat label="Regions in use" value={topo ? active.length : <Skeleton w={20} h={20} />} tone="accent" />
        <Stat label="Tenants" value={cp?.tenants ?? "—"} />
        <Stat label="Organizations" value={cp?.orgs ?? "—"} />
      </StatStrip>

      <div className="card">
        <div className="region-topo">
          <div className="region-topo-cp">
            <div className="region-topo-tag">Control plane · Global</div>
            <div className="region-topo-sub">Orgs · Identity · RBAC · Tenants · Billing</div>
          </div>
          <div className="region-topo-arrow">routes by tenant → region ↓</div>
          <div className="region-topo-planes">
            {rows.map((r) => {
              const used = r.tenants > 0 || r.orgs > 0;
              return (
                <div key={r.id} className={`region-plane${used ? " used" : ""}`}>
                  <div className="region-plane-head">
                    <b>{r.label}</b>
                    <span className={`badge ${r.data_plane.local ? "" : "accent"}`}>{r.data_plane.local ? "Local stack" : "Dedicated"}</span>
                  </div>
                  <div className="region-plane-meta">{r.tenants} tenant{r.tenants === 1 ? "" : "s"} · {r.orgs} org{r.orgs === 1 ? "" : "s"}</div>
                  <div className="region-plane-stack">ClickHouse · OpenSearch · Kafka · VictoriaMetrics</div>
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
                  {r.data_plane.local ? "in-cluster" : (r.data_plane.clickhouse || "configured")}
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

type IATab = "users" | "userroles" | "customroles" | "sso" | "security" | "tenants";
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
const IA_TABS_ORG: { id: IATab; label: string }[] = [...IA_TABS, { id: "tenants", label: "Tenants" }];

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
        <AdminHead title="Access" sub="Who can do what, where. Grant a person access to an organization, then pick their role. Access can be revoked any time." />
        <button className="dash-btn accent" onClick={openGrant}>＋ Grant access</button>
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
function IAItems({ kind, id = "", name, tabs = IA_TABS }: {
  kind: "provider" | "tenant" | "org"; id?: string; name?: string; tabs?: { id: IATab; label: string }[];
}) {
  const [tab, setTab] = useState<IATab>(tabs[0]?.id ?? "users");
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

export function IdentityAccess() {
  const { user } = useAuth();
  const platform = !!user?.platform_admin;
  const [section, setSection] = useState<"provider" | "orgs">("provider");
  const [sel, setSel] = useState<{ id: string; name: string } | null>(null);

  // A tenant admin governs only its own tenant — no Provider, no picker.
  if (!platform) {
    return (
      <>
        <AdminHead title="Identity & Access" sub="Users, roles and security settings for your tenant." />
        <IAItems kind="tenant" id={user?.tenant_id || ""} />
      </>
    );
  }

  return (
    <>
      <AdminHead title="Identity & Access" sub="People, roles and security — for the Provider (platform) or per organization. Tenants are optional units inside an organization." />
      <div style={{ marginBottom: 12 }}>
        <Segmented
          ariaLabel="Identity scope"
          value={section}
          onChange={(v) => { setSection(v); setSel(null); }}
          options={[{ value: "provider", label: "Provider" }, { value: "orgs", label: "Organizations" }]}
        />
      </div>

      {section === "provider" && <IAItems kind="provider" tabs={IA_TABS_PROVIDER} />}

      {section === "orgs" && (
        sel ? (
          <>
            <div className="ia-crumb">
              <button className="dash-btn" onClick={() => setSel(null)}>← Organizations</button>
              <span className="ia-crumb-name">{sel.name}</span>
              <span className="mini-meta">users · roles · security · tenants</span>
            </div>
            <IAItems kind="org" id={sel.id} name={sel.name} tabs={IA_TABS_ORG} />
          </>
        ) : (
          <OrgsAdmin onManageOrg={(id, name) => setSel({ id, name })} />
        )
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
  const fmt = (t?: string) => (t ? new Date(t).toLocaleString() : "—");
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

const SCOPE_OPTIONS = ["read:metrics", "read:alerts", "read:devices", "read:flows", "read:*", "write:incidents"];

const GRANT_TYPE_OPTIONS = ["authorization_code", "client_credentials", "refresh_token"];

type ApiTile = "keys" | "token" | "rest";

export function ApiAccessAdmin() {
  const [keys, err, reload, setErr] = useReload(() => api.listApiKeys());
  const [label, setLabel] = useState("");
  const [scopes, setScopes] = useState<string[]>(["read:metrics"]);
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
    <>
      <AdminHead title="API Access" sub={`${BRAND} is API-first — mint scoped credentials for machine clients and tune session tokens.`} />
      <StatStrip>
        <Stat label="Keys" value={keys ? list.length : <Skeleton w={26} h={22} />} />
        <Stat label="Active" value={keys ? active : "—"} tone="good" />
        <Stat label="Revoked" value={keys ? list.length - active : "—"} tone={list.some((k) => k.revoked_at) ? "warn" : ""} />
        <Stat label="Rate-limited" value={keys ? list.filter((k) => (k.rate_limit_per_min || 0) > 0).length : "—"} />
      </StatStrip>

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
                <td className="mono" style={{ fontSize: "var(--fs-meta)" }}>{(k.scopes || []).join(", ") || "—"}</td>
                <td className="mono" style={{ fontSize: "var(--fs-meta)" }}>{(k.grant_types || []).join(", ") || "—"}</td>
                <td className="mono" style={{ fontSize: "var(--fs-meta)" }}>{(k.source_cidrs || []).join(", ") || "any"}</td>
                <td className="mono">{cap > 0 ? <span className={near ? "badge warn" : ""}>{k.window_used}/{cap}</span> : <span className="mini-meta">unlimited</span>}</td>
                <td className="mono">{(k.use_count ?? 0).toLocaleString()}</td>
                <td>{k.created_at ? new Date(k.created_at).toLocaleDateString() : "—"}</td>
                <td>{k.client_expires_at || k.secret_expires_at ? new Date(k.client_expires_at || k.secret_expires_at || "").toLocaleDateString() : "never"}</td>
                <td>{k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "never"}</td>
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
                isValid: () => true,
                render: () => (
                  <>
                    <div className="scope-row">
                      {SCOPE_OPTIONS.map((s) => (
                        <label key={s} className={`scope-chip ${scopes.includes(s) ? "on" : ""}`}>
                          <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggleScope(s)} /> {s}
                        </label>
                      ))}
                    </div>
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
    </>
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
    <div style={{ marginTop: 8, padding: "8px 10px", borderRadius: 6, border: `1px solid ${color}`, background: "var(--panel)", fontSize: 13 }}>
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
                    <input value={m.group} placeholder="cn=netops-admins,ou=groups,dc=example,dc=com" onChange={(e) => setMapping(i, { group: e.target.value })} />
                    <select value={m.role} onChange={(e) => setMapping(i, { role: e.target.value })}>
                      {roleIds.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                    <button onClick={() => set({ role_mappings: cfg.role_mappings.filter((_, j) => j !== i) })}>Remove</button>
                  </div>
                ))}
                <button onClick={() => set({ role_mappings: [...cfg.role_mappings, { group: "", role: roleIds[0] || "read-only" }] })}>+ Add mapping</button>
                <div style={{ marginTop: 16, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <input placeholder="test username (optional)" value={testUser} onChange={(e) => setTestUser(e.target.value)} style={{ padding: 6 }} />
                  <input type="password" placeholder="test password" value={testPass} onChange={(e) => setTestPass(e.target.value)} style={{ padding: 6 }} />
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
                  <input placeholder="test username (optional)" value={testUser} onChange={(e) => setTestUser(e.target.value)} style={{ padding: 6 }} />
                  <input type="password" placeholder="test password" value={testPass} onChange={(e) => setTestPass(e.target.value)} style={{ padding: 6 }} />
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
      if (!sso!.enabled) return { tag: "Off", tone: "", meta: "Click to configure" };
      return sso!.ready ? { tag: "On", tone: "good", meta: "OIDC ready" } : { tag: "On", tone: "warn", meta: "Enabled — finish issuer & client ID" };
    }
    const s = id === "ldap" ? ldap! : tac!;
    if (!s.enabled) return { tag: "Off", tone: "", meta: s.configured ? "Configured — disabled" : "Click to configure" };
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
      <Wizard
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
      />
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

type ConnectorId = "servicenow" | "jira";

const CONNECTORS: { id: ConnectorId; name: string; tagline: string; noun: string; Logo: (p: { size?: number; className?: string }) => JSX.Element }[] = [
  { id: "servicenow", name: "ServiceNow", noun: "incidents", tagline: "Promote critical incidents to ServiceNow via the Table API; auto-resolve when the alert clears.", Logo: ServiceNowLogo },
  { id: "jira", name: "Jira", noun: "issues", tagline: "Open deduped Jira issues at or above your threshold; transition to Done on clear.", Logo: JiraLogo },
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
              <span className={`conn-logo ${c.id}`}><c.Logo size={40} /></span>
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
                      : "Click to set up"}
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
                  <td>{t.opened_at ? new Date(t.opened_at).toLocaleString() : "—"}</td>
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
                  <td>{t.opened_at ? new Date(t.opened_at).toLocaleString() : "—"}</td>
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
    <Modal title={meta.name} subtitle={meta.tagline} logo={<span className={`conn-logo ${id}`}><meta.Logo size={28} /></span>} onClose={onClose}>
      <Wizard steps={steps} onFinish={save} onCancel={onClose} finishLabel="Save & connect" />
    </Modal>
  );
}

// ---- Notifications (SMTP / Twilio / ntfy) ----------------------------------

const SEVERITIES = ["info", "notice", "warning", "error", "critical"];

// Notification channels presented as a branded tile gallery (same pattern as
// Integrations). SMS (Twilio) and Push (ntfy) are grouped into one "SMS & Push"
// tile since both are phone-delivery channels. Branded channels (Slack,
// PagerDuty) use their real logos; generic ones use modern stroke icons.
type ChannelId = "email" | "mobile" | "slack" | "pagerduty";
const CHANNELS: { id: ChannelId; name: string; tagline: string; logo: JSX.Element }[] = [
  { id: "email", name: "Email", tagline: "SMTP relay — route alert emails to your NOC distribution list.", logo: <Icon name="mail" size={26} /> },
  { id: "mobile", name: "SMS & Push", tagline: "Phone alerts — SMS via Twilio and free push via ntfy.", logo: <Icon name="smartphone" size={26} /> },
  { id: "slack", name: "Slack", tagline: "Post alerts to a Slack channel via an Incoming Webhook.", logo: <SlackLogo size={30} /> },
  { id: "pagerduty", name: "PagerDuty", tagline: "On-call escalation via the PagerDuty Events API v2.", logo: <PagerDutyLogo size={30} /> },
];

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
  const [smtp, setSmtp] = useState<SmtpConfig | null>(null);
  const [twilio, setTwilio] = useState<TwilioConfig | null>(null);
  const [ntfy, setNtfy] = useState<NtfyConfig | null>(null);
  const [slack, setSlack] = useState<SlackConfig | null>(null);
  const [pager, setPager] = useState<PagerDutyConfig | null>(null);
  // Bidirectional-sync config (Integration Platform) for the channels that
  // support it — PagerDuty & Slack live here; ServiceNow/Jira sync lives in the
  // Integrations connector setup.
  const [integrations, setIntegrations] = useState<IntegrationConfig[] | null>(null);
  const [inboundEnabled, setInboundEnabled] = useState(false);
  const [openCh, setOpenCh] = useState<ChannelId | null>(null); // which channel's setup modal is open
  const [secret, setSecret] = useState({ smtp: "", twilio: "", ntfy: "", slack: "", pager: "" });
  const [msg, setMsg] = useState<Record<string, string>>({});
  // Contact points (reusable delivery audiences referenced by reports).
  const [cps, setCps] = useState<ContactPoint[]>([]);
  const emptyCP: Partial<ContactPoint> = { name: "", type: "email", email: [], target: "", enabled: true };
  const [cpDraft, setCpDraft] = useState<Partial<ContactPoint>>(emptyCP);
  const [cpEmails, setCpEmails] = useState(""); // comma-separated editor for email type

  const loadCps = () => api.contactPoints().then(setCps).catch(() => {});

  useEffect(() => {
    api.smtpConfig().then(setSmtp).catch(() => {});
    api.twilioConfig().then(setTwilio).catch(() => {});
    api.ntfyConfig().then(setNtfy).catch(() => {});
    api.slackConfig().then(setSlack).catch(() => {});
    api.pagerDutyConfig().then(setPager).catch(() => {});
    api.integrations().then((r) => { setIntegrations(r.integrations); setInboundEnabled(r.inbound_enabled); }).catch(() => {});
    loadCps();
  }, []);

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
  const test = async (k: string, fn: () => Promise<{ status: string }>) => {
    try { await fn(); flash(k, "Test sent — check your inbox/phone."); }
    catch (e) { flash(k, "Test failed: " + (e as Error).message); }
  };

  return (
    <>
      <AdminHead title="Notifications" sub="Email, SMS and push channels. Critical alerts route here; secrets are write-only." />
      {(() => {
        const loaded = smtp !== null;
        const groups = [!!smtp?.enabled, !!(twilio?.enabled || ntfy?.enabled), !!slack?.enabled, !!pager?.enabled];
        const enabled = groups.filter(Boolean).length;
        return (
          <StatStrip>
            <Stat label="Channels" value={loaded ? CHANNELS.length : <Skeleton w={26} h={22} />} />
            <Stat label="Enabled" value={loaded ? enabled : "—"} tone={enabled ? "good" : ""} />
            <Stat label="Contact points" value={cps.length} tone="accent" />
          </StatStrip>
        );
      })()}

      {/* Channel gallery — pick a channel to open its guided setup. */}
      <div className="conn-grid">
        {CHANNELS.map((c) => {
          const loaded = smtp !== null;
          let enabled = false, configured = false, metaLine = "";
          if (c.id === "email") {
            enabled = !!smtp?.enabled; configured = !!smtp?.host;
            metaLine = configured ? `Relay ${smtp?.host}` : "Click to set up";
          } else if (c.id === "mobile") {
            enabled = !!(twilio?.enabled || ntfy?.enabled);
            configured = !!(twilio?.account_sid || ntfy?.topic);
            metaLine = [twilio?.account_sid ? "SMS" : null, ntfy?.topic ? "Push" : null].filter(Boolean).join(" · ") || "Click to set up";
          } else if (c.id === "slack") {
            enabled = !!slack?.enabled; configured = !!slack?.webhook_set;
            metaLine = configured ? "Webhook configured" : "Click to set up";
          } else {
            enabled = !!pager?.enabled; configured = !!pager?.routing_set;
            metaLine = configured ? "Routing key configured" : "Click to set up";
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
      </div>

      {/* Channel setup modal — the selected channel's full configuration. */}
      {openCh && (() => {
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
                <h3 className="ds-modal-section"><TwilioLogo size={18} /> SMS · Twilio</h3>
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
              {(["email", "slack", "webhook"] as ContactPointType[]).map((t) => <option key={t} value={t}>{t}</option>)}
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
