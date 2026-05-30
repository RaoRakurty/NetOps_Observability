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
import { api, AdminUser, Role, Tenant, ApiKey } from "../services/api";
import { BRAND } from "../brand";

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

const BLANK_USER = { username: "", email: "", display_name: "", password: "", role: "read-only", tenant_id: "" };

export function UsersAdmin() {
  const [users, err, reload, setErr] = useReload(() => api.listUsers());
  const [roles] = useReload(() => api.listRoles());
  const [tenants] = useReload(() => api.listTenants());
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ ...BLANK_USER });

  const roleList = roles?.roles ?? [];
  const tenantList = tenants ?? [];

  const submit = async () => {
    setErr(null);
    try {
      await api.createUser(form);
      setForm({ ...BLANK_USER });
      setAdding(false);
      reload();
    } catch (e) { setErr((e as Error).message); }
  };
  const changeRole = async (u: AdminUser, role: string) => {
    setErr(null);
    try { await api.updateUser(u.username, { role }); reload(); } catch (e) { setErr((e as Error).message); }
  };
  const remove = async (u: AdminUser) => {
    setErr(null);
    try { await api.deleteUser(u.username); reload(); } catch (e) { setErr((e as Error).message); }
  };

  return (
    <>
      <AdminHead title="Users" sub={`People with access to ${BRAND}. Local accounts today; federated users (SSO/LDAP) arrive once Keycloak is wired.`} />
      <div className="card">
        <div className="admin-card-head">
          <h2>Directory</h2>
          <button className="dash-btn accent" onClick={() => setAdding((v) => !v)}>{adding ? "Cancel" : "+ Add user"}</button>
        </div>
        <ErrLine msg={err} />
        {adding && (
          <div className="admin-form">
            <input placeholder="username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            <input placeholder="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
            <input placeholder="display name" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
            <input type="password" placeholder="password (min 8)" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
              {roleList.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
            <select value={form.tenant_id} onChange={(e) => setForm({ ...form, tenant_id: e.target.value })}>
              <option value="">— tenant —</option>
              {tenantList.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
            <button className="dash-btn accent" onClick={submit}>Create</button>
          </div>
        )}
        <table>
          <thead>
            <tr><th>User</th><th>Email</th><th>Role</th><th>Tenant</th><th>Auth</th><th>Status</th><th>Last active</th><th></th></tr>
          </thead>
          <tbody>
            {(users ?? []).map((u) => (
              <tr key={u.username}>
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
                <td><span className={`badge ${u.status === "disabled" ? "warn" : "good"}`}>{u.status || "active"}</span></td>
                <td>{u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "—"}</td>
                <td><button className="dash-btn" onClick={() => remove(u)}>Delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ---- Roles (RBAC) ----------------------------------------------------------

export function RolesAdmin() {
  const [data, err, reload, setErr] = useReload(() => api.listRoles());
  const modules = data?.modules ?? [];
  const roles = data?.roles ?? [];

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

  return (
    <>
      <AdminHead title="Roles & Permissions" sub="Granular, module-level RBAC. Built-in roles are fixed; click a cell on a custom role to cycle none→read→write→admin." />
      <div className="card">
        <div className="admin-card-head">
          <h2>Permission matrix</h2>
          <button className="dash-btn accent" onClick={addRole}>+ New custom role</button>
        </div>
        <ErrLine msg={err} />
        <table>
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
      </div>
    </>
  );
}

// ---- Tenants (multi-tenancy) ----------------------------------------------

export function TenantsAdmin() {
  const [tenants, err, reload, setErr] = useReload(() => api.listTenants());
  const [name, setName] = useState("");
  const [note, setNote] = useState("");

  const create = async () => {
    if (!name.trim()) return;
    setErr(null);
    try { await api.createTenant(name.trim(), note.trim()); setName(""); setNote(""); reload(); } catch (e) { setErr((e as Error).message); }
  };
  const remove = async (t: Tenant) => {
    setErr(null);
    try { await api.deleteTenant(t.id); reload(); } catch (e) { setErr((e as Error).message); }
  };

  return (
    <>
      <AdminHead title="Tenants" sub="Logical isolation boundaries. Devices, dashboards, alerts and users are scoped per tenant." />
      <div className="card">
        <div className="admin-card-head"><h2>New tenant</h2></div>
        <ErrLine msg={err} />
        <div className="admin-form">
          <input placeholder="tenant name" value={name} onChange={(e) => setName(e.target.value)} />
          <input placeholder="note (optional)" value={note} onChange={(e) => setNote(e.target.value)} style={{ flex: 2 }} />
          <button className="dash-btn accent" onClick={create}>Create tenant</button>
        </div>
      </div>
      <div className="ov-grid">
        {(tenants ?? []).map((t) => (
          <div className="panel col-4" key={t.id}>
            <div className="provider-head">
              <h3>{t.name}</h3>
              {t.id !== "global" && <button className="dash-btn" onClick={() => remove(t)}>Delete</button>}
            </div>
            <p className="mini-meta" style={{ marginTop: 6 }}>{t.note || "—"}</p>
            <p className="mini-meta mono" style={{ marginTop: 6 }}>id: {t.id}</p>
          </div>
        ))}
      </div>
    </>
  );
}

// ---- API Access ------------------------------------------------------------

const SCOPE_OPTIONS = ["read:metrics", "read:alerts", "read:devices", "read:flows", "read:*", "write:incidents"];

export function ApiAccessAdmin() {
  const [keys, err, reload, setErr] = useReload(() => api.listApiKeys());
  const [label, setLabel] = useState("");
  const [scopes, setScopes] = useState<string[]>(["read:metrics"]);
  const [rate, setRate] = useState("");
  const [secret, setSecret] = useState<string | null>(null);

  const toggleScope = (s: string) =>
    setScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  const generate = async () => {
    if (!label.trim()) return;
    setErr(null);
    try {
      const limit = rate.trim() ? Math.max(0, parseInt(rate, 10) || 0) : undefined;
      const res = await api.createApiKey(label.trim(), scopes, limit);
      setSecret(res.secret);
      setLabel("");
      setRate("");
      reload();
    } catch (e) { setErr((e as Error).message); }
  };
  const revoke = async (k: ApiKey) => {
    setErr(null);
    try { await api.revokeApiKey(k.id); reload(); } catch (e) { setErr((e as Error).message); }
  };

  return (
    <>
      <AdminHead title="API Access" sub={`${BRAND} is API-first. Mint scoped keys for machine clients; present them as a Bearer token or X-API-Key header.`} />
      <div className="card">
        <div className="admin-card-head"><h2>Generate API key</h2></div>
        <ErrLine msg={err} />
        {secret && (
          <div className="planned-banner" style={{ background: "var(--sev-ok-bg)", borderColor: "var(--good)" }}>
            <span className="badge good">New key</span>
            <span>Copy it now — it won't be shown again: <code style={{ userSelect: "all" }}>{secret}</code></span>
            <button className="dash-btn" style={{ marginLeft: "auto" }} onClick={() => setSecret(null)}>Dismiss</button>
          </div>
        )}
        <div className="admin-form">
          <input placeholder="key label (e.g. ci-pipeline)" value={label} onChange={(e) => setLabel(e.target.value)} />
          <input
            type="number"
            min={0}
            style={{ maxWidth: 170 }}
            placeholder="rate limit / min (blank = default)"
            value={rate}
            onChange={(e) => setRate(e.target.value)}
          />
          <button className="dash-btn accent" onClick={generate}>Generate key</button>
        </div>
        <div className="scope-row">
          {SCOPE_OPTIONS.map((s) => (
            <label key={s} className={`scope-chip ${scopes.includes(s) ? "on" : ""}`}>
              <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggleScope(s)} /> {s}
            </label>
          ))}
        </div>
      </div>
      <div className="card">
        <div className="admin-card-head"><h2>API keys</h2></div>
        <table>
          <thead>
            <tr><th>Label</th><th>Key</th><th>Scopes</th><th>Rate / min</th><th>Usage</th><th>Created</th><th>Last used</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {(keys ?? []).map((k) => {
              const cap = k.rate_limit_per_min || 0;
              const near = cap > 0 && k.window_used >= cap * 0.8;
              return (
              <tr key={k.id}>
                <td style={{ fontWeight: 600 }}>{k.label}</td>
                <td className="mono">{k.prefix}</td>
                <td className="mono" style={{ fontSize: "var(--fs-meta)" }}>{(k.scopes || []).join(", ") || "—"}</td>
                <td className="mono">
                  {cap > 0
                    ? <span className={near ? "badge warn" : ""}>{k.window_used}/{cap}</span>
                    : <span className="mini-meta">unlimited</span>}
                </td>
                <td className="mono">{(k.use_count ?? 0).toLocaleString()}</td>
                <td>{k.created_at ? new Date(k.created_at).toLocaleDateString() : "—"}</td>
                <td>{k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "never"}</td>
                <td>{k.revoked_at ? <span className="badge warn">revoked</span> : <span className="badge good">active</span>}</td>
                <td>{!k.revoked_at && <button className="dash-btn" onClick={() => revoke(k)}>Revoke</button>}</td>
              </tr>
            );})}
            {(keys ?? []).length === 0 && <tr><td colSpan={9} className="panel-empty">No API keys yet.</td></tr>}
          </tbody>
        </table>
        <p className="mini-meta" style={{ marginTop: 8 }}>
          Each key is rate-limited per minute (fixed window) — leave the field blank to inherit the
          server default (<code>APIKEY_RATE_LIMIT_PER_MIN</code>), or set 0 for unlimited. Over-cap
          calls get <code>429 Too Many Requests</code> with a <code>Retry-After</code>. The Rate
          column shows live current-minute usage; Usage is lifetime authenticated calls.
        </p>
      </div>
      <GraphQLExplorer />
      <OpenAPIReference />
      <div className="ov-grid">
        <div className="panel col-6"><h3>Authentication</h3><p className="mini-meta">Present a key as <code>Authorization: Bearer ntk_…</code> or <code>X-API-Key</code>. Keys resolve to the same tenant + RBAC context as a user — a key never exceeds its scopes.</p></div>
      </div>
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

function GraphQLExplorer() {
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
        <a className="dash-btn" href="/api/graphql" target="_blank" rel="noreferrer">/api/graphql ↗</a>
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
function OpenAPIReference() {
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
  return (
    <div className="card">
      <div className="admin-card-head">
        <h2>REST API reference</h2>
        <a className="dash-btn" href="/api/openapi.json" target="_blank" rel="noreferrer">openapi.json ↗</a>
      </div>
      <p className="mini-meta" style={{ marginTop: 0 }}>
        {spec?.info?.title} · v{spec?.info?.version} · OpenAPI {spec?.openapi}. Generated from the Go handlers; import it into Postman or any OpenAPI client.
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
    </div>
  );
}

// ---- Authentication (SSO / SAML / LDAP via Keycloak) -----------------------

// kindTag labels a federated provider by how Keycloak brokers it.
const KIND_LABEL: Record<string, string> = { oidc: "OAuth 2.0 / OIDC", saml: "SAML 2.0", ldap: "LDAP / Active Directory" };

export function AuthenticationAdmin() {
  const [sso] = useReload(() => api.ssoConfig());
  const enabled = !!sso?.enabled;
  const providers = sso?.providers ?? [];

  return (
    <>
      <AdminHead title="Authentication" sub="How people sign in. Local accounts always work; OIDC/SAML/LDAP are brokered by Keycloak — the Go API only validates the resulting tokens." />
      <div className="planned-banner" style={{ background: "var(--sev-ok-bg)", borderColor: "var(--good)" }}>
        <span className="badge good">{enabled ? "SSO enabled" : "Active"}</span>
        <span>
          JWT auth with rotating, single-use refresh tokens (reuse detection) is live.
          {enabled
            ? " Single Sign-On is configured: the providers below appear on the login screen."
            : " Single Sign-On is available — set OIDC_ENABLED=true + the Keycloak realm details to light up the providers below."}
        </span>
      </div>
      <div className="ov-grid">
        <div className="panel col-6 provider-card">
          <div className="provider-head">
            <h3>Local accounts</h3>
            <span className="badge good">Active</span>
          </div>
          <p className="mini-meta">Username + password (PBKDF2) with JWT. Always available as a fallback even when an external IdP is down.</p>
        </div>
        {(enabled ? providers : [{ id: "oidc", name: "OAuth 2.0 / OIDC", kind: "oidc" }, { id: "saml", name: "SAML 2.0", kind: "saml" }, { id: "ldap", name: "LDAP / Active Directory", kind: "ldap" }]).map((p) => (
          <div className="panel col-6 provider-card" key={p.id || p.kind}>
            <div className="provider-head">
              <h3>{p.name || KIND_LABEL[p.kind]}</h3>
              <span className={`badge ${enabled ? "good" : "accent-badge"}`}>{enabled ? "Enabled" : "Available"}</span>
            </div>
            <p className="mini-meta">{KIND_LABEL[p.kind] || p.kind} via Keycloak. {p.kind === "saml" ? "Per-IdP metadata & attribute mapping configured in Keycloak." : p.kind === "ldap" ? "Bind + group sync maps directory groups onto roles." : "Authorization Code flow; Okta/Azure AD/Google brokered upstream."}</p>
            {enabled && (
              <a className="dash-btn" href={api.ssoLoginUrl(p.id)} style={{ marginTop: 10, display: "inline-block" }}>Test sign-in →</a>
            )}
          </div>
        ))}
      </div>
      <div className="card">
        <h2>Token policy</h2>
        <dl className="kv-form">
          <dt>Access token TTL</dt><dd>1 hour <span className="mini-meta">(ACCESS_TOKEN_TTL; signed with JWT_SECRET)</span></dd>
          <dt>Refresh token TTL</dt><dd>rotating, 7 days <span className="mini-meta">(single-use; reuse revokes the lineage)</span></dd>
          <dt>Federated tokens</dt><dd className="mono">RS256, verified against Keycloak JWKS</dd>
        </dl>
      </div>
    </>
  );
}

// ---- ITSM Integrations — planned -------------------------------------------

const ITSM = [
  { id: "servicenow", name: "ServiceNow", desc: "Critical alerts cut an incident via the Table API (deduped by fingerprint) and auto-resolve when the alert clears. Enable with FEATURE_SERVICENOW_NOTIFICATIONS. Bi-directional sync & CMDB lookup are next.", tag: "Available" },
  { id: "jira", name: "Jira", desc: "Alerts at/above the threshold open a deduped Jira issue (REST v2) and transition to Done when the alert clears. Enable with FEATURE_JIRA_NOTIFICATIONS + JIRA_PROJECT_KEY.", tag: "Available" },
  { id: "pagerduty", name: "PagerDuty", desc: "On-call routing & escalation (notifier already exists in the backend).", tag: "Available" },
  { id: "slack", name: "Slack", desc: "Channel notifications & alert actions (notifier already exists).", tag: "Available" },
];

export function IntegrationsAdmin() {
  const [sn] = useReload(() => api.itsmServiceNow());
  const [jira] = useReload(() => api.itsmJira());
  const snLive = !!sn?.configured;
  const jiraLive = !!jira?.configured;

  return (
    <>
      <AdminHead title="ITSM & Ticketing" sub="Turn alerts and incidents into tickets in your system of record." />
      <div className="planned-banner" style={{ background: "var(--sev-ok-bg)", borderColor: "var(--good)" }}>
        <span className="badge good">Active</span>
        <span>
          ServiceNow and Jira auto-ticketing are both live: an alert at/above the
          threshold opens a deduped ticket and auto-resolves it when the alert clears.
        </span>
      </div>

      {sn?.enabled && (
        <div className="card">
          <div className="admin-card-head">
            <h2>ServiceNow — live</h2>
            <span className="badge good">connected</span>
          </div>
          <dl className="kv-form">
            <dt>Ticket threshold</dt><dd className="mono">{sn.threshold} and worse</dd>
            <dt>Auto-resolve</dt><dd>{sn.auto_close ? "on — incident closed when the alert clears" : "off"}</dd>
            <dt>Open incidents</dt><dd>{sn.open_count ?? 0}</dd>
          </dl>
          {(sn.open?.length ?? 0) > 0 && (
            <table>
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
          )}
        </div>
      )}

      {jira?.enabled && (
        <div className="card">
          <div className="admin-card-head">
            <h2>Jira — live</h2>
            <span className="badge good">connected</span>
          </div>
          <dl className="kv-form">
            <dt>Project</dt><dd className="mono">{jira.project || "—"}</dd>
            <dt>Ticket threshold</dt><dd className="mono">{jira.threshold} and worse</dd>
            <dt>Auto-resolve</dt><dd>{jira.auto_close ? "on — issue transitioned to Done when the alert clears" : "off"}</dd>
            <dt>Open issues</dt><dd>{jira.open_count ?? 0}</dd>
          </dl>
          {(jira.open?.length ?? 0) > 0 && (
            <table>
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
          )}
        </div>
      )}

      <div className="ov-grid">
        {ITSM.map((i) => {
          // ServiceNow/Jira flip to a "connected" badge once the connector is live.
          const tag =
            (i.id === "servicenow" && snLive) || (i.id === "jira" && jiraLive)
              ? "Connected"
              : i.tag;
          const good = tag === "Available" || tag === "Connected";
          return (
            <div className="panel col-6 provider-card" key={i.id}>
              <div className="provider-head">
                <h3>{i.name}</h3>
                <span className={`badge ${good ? "good" : "accent-badge"}`}>{tag}</span>
              </div>
              <p className="mini-meta">{i.desc}</p>
              <button className="dash-btn" disabled style={{ marginTop: 10 }}>
                {i.id === "servicenow" || i.id === "jira" ? "Configured via env" : "Configure"}
              </button>
            </div>
          );
        })}
      </div>
    </>
  );
}
