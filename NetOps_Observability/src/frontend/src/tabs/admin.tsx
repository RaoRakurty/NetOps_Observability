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
import { api, AdminUser, Role, Tenant, ApiKey, CreateApiKeyRequest, LdapConfig, TacacsConfig, OidcConfig, AuthTestResult, LdapRoleMapping, TokenPolicy, ExportPolicy, SmtpConfig, TwilioConfig, NtfyConfig, SlackConfig, PagerDutyConfig, ContactPoint, ContactPointType, ItsmConfig, ItsmServiceNowConfig, ItsmJiraConfig, IntegrationConfig } from "../services/api";
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
      <AdminHead title="Users" sub={`People with access to ${BRAND}. Local accounts today; federated users (SSO/LDAP) arrive once an identity provider is configured.`} />
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

const GRANT_TYPE_OPTIONS = ["authorization_code", "client_credentials", "refresh_token"];

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

  const toggleScope = (s: string) =>
    setScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  const toggleGrant = (g: string) =>
    setGrantTypes((cur) => (cur.includes(g) ? cur.filter((x) => x !== g) : [...cur, g]));

  // splitList turns a comma-separated input into a trimmed, non-empty list.
  const splitList = (v: string) => v.split(",").map((x) => x.trim()).filter(Boolean);
  // toIso converts a yyyy-mm-dd date input into an RFC 3339 timestamp.
  const toIso = (v: string) => (v.trim() ? new Date(v).toISOString() : undefined);

  const generate = async () => {
    if (!label.trim()) return;
    setErr(null);
    try {
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
      const res = await api.createApiKey(req);
      setSecret(res.secret);
      setLabel("");
      setRate("");
      setClientUri("");
      setLogoUri("");
      setSourceCidrs("");
      setClientExpires("");
      setSecretExpires("");
      setContactEmail("");
      setContactPhone("");
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
        <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
          <LabeledInput label="Label" value={label} onChange={setLabel} placeholder="e.g. ci-pipeline" required />
          <LabeledInput label="Rate limit / min" type="number" value={rate} onChange={setRate} placeholder="blank = default (600)" hint="default 600 · 0 = unlimited · blank = inherit default" />
        </div>
        <div className="scope-row" style={{ marginTop: 12 }}>
          {SCOPE_OPTIONS.map((s) => (
            <label key={s} className={`scope-chip ${scopes.includes(s) ? "on" : ""}`}>
              <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggleScope(s)} /> {s}
            </label>
          ))}
        </div>

        <h3 style={{ margin: "16px 0 4px", fontSize: "var(--fs-meta)", textTransform: "uppercase", letterSpacing: ".04em", color: "var(--muted)" }}>Credential</h3>
        <div className="scope-row">
          {GRANT_TYPE_OPTIONS.map((g) => (
            <label key={g} className={`scope-chip ${grantTypes.includes(g) ? "on" : ""}`}>
              <input type="checkbox" checked={grantTypes.includes(g)} onChange={() => toggleGrant(g)} /> {g}
            </label>
          ))}
        </div>
        <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginTop: 12 }}>
          <LabeledInput label="Client URL" value={clientUri} onChange={setClientUri} placeholder="https://app.example.com" hint="Public homepage of the client." />
          <LabeledInput label="Logo URL" value={logoUri} onChange={setLogoUri} placeholder="https://app.example.com/logo.png" hint="Image shown on consent screens." />
          <LabeledInput label="Allowed source IP / CIDR" value={sourceCidrs} onChange={setSourceCidrs} placeholder="10.0.0.0/8, 192.168.1.0/24" hint="Comma-separated; blank = any source." />
        </div>

        <h3 style={{ margin: "16px 0 4px", fontSize: "var(--fs-meta)", textTransform: "uppercase", letterSpacing: ".04em", color: "var(--muted)" }}>Expiry</h3>
        <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
          <LabeledInput label="Client expires on" type="date" value={clientExpires} onChange={setClientExpires} hint="Optional; blank = never." />
          <LabeledInput label="Secret expires on" type="date" value={secretExpires} onChange={setSecretExpires} hint="Optional; blank = never." />
        </div>

        <h3 style={{ margin: "16px 0 4px", fontSize: "var(--fs-meta)", textTransform: "uppercase", letterSpacing: ".04em", color: "var(--muted)" }}>Contacts</h3>
        <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
          <LabeledInput label="Contact email" value={contactEmail} onChange={setContactEmail} placeholder="ops@example.com" hint="Comma-separated for multiple." />
          <LabeledInput label="Contact phone" value={contactPhone} onChange={setContactPhone} placeholder="+1 555 0100" />
        </div>

        <div style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 12 }}>
          <button className="dash-btn accent" onClick={generate}>Generate key</button>
          <RequiredLegend />
        </div>
      </div>
      <div className="card">
        <div className="admin-card-head"><h2>API keys</h2></div>
        <table>
          <thead>
            <tr><th>Label</th><th>Key</th><th>Scopes</th><th>Grant types</th><th>Source CIDRs</th><th>Rate / min</th><th>Usage</th><th>Created</th><th>Expires</th><th>Last used</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {(keys ?? []).map((k) => {
              const cap = k.rate_limit_per_min || 0;
              const near = cap > 0 && k.window_used >= cap * 0.8;
              return (
              <tr key={k.id}>
                <td style={{ fontWeight: 600 }}>
                  {k.client_uri ? <a href={k.client_uri} target="_blank" rel="noreferrer">{k.label}</a> : k.label}
                </td>
                <td className="mono">{k.prefix}</td>
                <td className="mono" style={{ fontSize: "var(--fs-meta)" }}>{(k.scopes || []).join(", ") || "—"}</td>
                <td className="mono" style={{ fontSize: "var(--fs-meta)" }}>{(k.grant_types || []).join(", ") || "—"}</td>
                <td className="mono" style={{ fontSize: "var(--fs-meta)" }}>{(k.source_cidrs || []).join(", ") || "any"}</td>
                <td className="mono">
                  {cap > 0
                    ? <span className={near ? "badge warn" : ""}>{k.window_used}/{cap}</span>
                    : <span className="mini-meta">unlimited</span>}
                </td>
                <td className="mono">{(k.use_count ?? 0).toLocaleString()}</td>
                <td>{k.created_at ? new Date(k.created_at).toLocaleDateString() : "—"}</td>
                <td>{k.client_expires_at || k.secret_expires_at
                  ? new Date(k.client_expires_at || k.secret_expires_at || "").toLocaleDateString()
                  : "never"}</td>
                <td>{k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "never"}</td>
                <td>{k.revoked_at ? <span className="badge warn">revoked</span> : <span className="badge good">active</span>}</td>
                <td>{!k.revoked_at && <button className="dash-btn" onClick={() => revoke(k)}>Revoke</button>}</td>
              </tr>
            );})}
            {(keys ?? []).length === 0 && <tr><td colSpan={12} className="panel-empty">No API keys yet.</td></tr>}
          </tbody>
        </table>
        <p className="mini-meta" style={{ marginTop: 8 }}>
          Each key is rate-limited per minute (fixed window). Allowed values: any whole number ≥ 1
          (requests/min), <code>0</code> for unlimited, or blank to inherit the server default of
          <strong> 600/min</strong> (<code>APIKEY_RATE_LIMIT_PER_MIN</code>). Over-cap
          calls get <code>429 Too Many Requests</code> with a <code>Retry-After</code>. The Rate
          column shows live current-minute usage; Usage is lifetime authenticated calls.
        </p>
      </div>
      <TokenPolicyForm />
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

function LabeledInput({ label, value, onChange, type = "text", placeholder = "", hint, required = false }: {
  label: string; value: string; onChange: (v: string) => void; type?: string; placeholder?: string; hint?: string; required?: boolean;
}) {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
      <span>{label}{required && <Req />}</span>
      <input type={type} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)}
        style={{ padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" }} />
      {hint && <span className="mini-meta">{hint}</span>}
    </label>
  );
}

function LabeledSelect({ label, value, onChange, options }: {
  label: string; value: string; onChange: (v: string) => void; options: string[];
}) {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
      <span>{label}</span>
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
function LdapAdminForm({ roleIds }: { roleIds: string[] }) {
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
  if (!cfg) return <div className="card"><h2>LDAP / Active Directory</h2><p className="mini-meta">Loading…</p></div>;

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

  return (
    <div className="card">
      <div className="admin-card-head">
        <h2>LDAP / Active Directory <ProviderBadge enabled={cfg.enabled} /></h2>
        <label style={{ fontSize: 13 }}>
          <input type="checkbox" checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled
        </label>
      </div>
      <p className="admin-sub">Native stdlib LDAP bind (RFC 4511). Directory groups map onto NetOps roles (first match by privilege wins). The bind password is write-only — leave blank to keep the stored one.</p>
      <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
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
        <LabeledInput label="Bind DN (service acct)" value={cfg.bind_dn} onChange={(v) => set({ bind_dn: v })} placeholder="cn=svc,dc=example,dc=com" />
        <LabeledInput label="Bind password" type="password" value={pw} onChange={setPw} placeholder={cfg.bind_password_set ? "•••••• (unchanged)" : "(none)"} />
        <LabeledInput label="Base DN" value={cfg.base_dn} onChange={(v) => set({ base_dn: v })} placeholder="dc=example,dc=com" required />
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
        <label style={{ fontSize: 12, color: "var(--muted)", alignSelf: "end" }}>
          <input type="checkbox" checked={cfg.insecure_skip_verify} onChange={(e) => set({ insecure_skip_verify: e.target.checked })} /> Skip TLS verify (lab only)
        </label>
      </div>

      <RequiredLegend />

      <h3 style={{ marginTop: 16 }}>Group → role mapping <span className="mini-meta">(highest-privilege match wins; otherwise default role)</span></h3>
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
        <button className="dash-btn" disabled={busy} onClick={save}>Save</button>
        <span style={{ flex: 1 }} />
        <input placeholder="test username (optional)" value={testUser} onChange={(e) => setTestUser(e.target.value)} style={{ padding: 6 }} />
        <input type="password" placeholder="test password" value={testPass} onChange={(e) => setTestPass(e.target.value)} style={{ padding: 6 }} />
        <button disabled={busy} onClick={test}>Test connection</button>
      </div>
      {msg && <p className="mini-meta" style={{ marginTop: 6 }}>{msg}</p>}
      <TestResult r={result} />
    </div>
  );
}

// ---- TACACS+ form ----
function TacacsAdminForm({ roleIds }: { roleIds: string[] }) {
  const [cfg, setCfg] = useState<TacacsConfig | null>(null);
  const [secret, setSecret] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testUser, setTestUser] = useState("");
  const [testPass, setTestPass] = useState("");
  const [result, setResult] = useState<AuthTestResult | null>(null);

  useEffect(() => { api.tacacsConfig().then((r) => setCfg(r.config)).catch((e) => setMsg((e as Error).message)); }, []);
  if (!cfg) return <div className="card"><h2>TACACS+</h2><p className="mini-meta">Loading…</p></div>;
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

  return (
    <div className="card">
      <div className="admin-card-head">
        <h2>TACACS+ <ProviderBadge enabled={cfg.enabled} /></h2>
        <label style={{ fontSize: 13 }}>
          <input type="checkbox" checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled
        </label>
      </div>
      <p className="admin-sub">Native stdlib TACACS+ PAP (RFC 8907) — authenticate operators against the same AAA server that fronts your routers/switches. The shared secret is write-only.</p>
      <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
        <LabeledInput label="Host" value={cfg.host} onChange={(v) => set({ host: v })} placeholder="tacacs.example.com" required />
        <LabeledInput label="Port" type="number" value={String(cfg.port)} onChange={(v) => set({ port: Number(v) || 49 })} />
        <LabeledInput label="Shared secret" type="password" value={secret} onChange={setSecret} placeholder={cfg.secret_set ? "•••••• (unchanged)" : "(none)"} />
        <LabeledInput label="Timeout (s)" type="number" value={String(cfg.timeout_seconds)} onChange={(v) => set({ timeout_seconds: Number(v) || 5 })} />
        <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
          Default role
          <select value={cfg.default_role} onChange={(e) => set({ default_role: e.target.value })}>
            {roleIds.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>
        <LabeledInput label="Default tenant" value={cfg.default_tenant} onChange={(v) => set({ default_tenant: v })} />
      </div>
      <RequiredLegend />
      <div style={{ marginTop: 16, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button className="dash-btn" disabled={busy} onClick={save}>Save</button>
        <span style={{ flex: 1 }} />
        <input placeholder="test username (optional)" value={testUser} onChange={(e) => setTestUser(e.target.value)} style={{ padding: 6 }} />
        <input type="password" placeholder="test password" value={testPass} onChange={(e) => setTestPass(e.target.value)} style={{ padding: 6 }} />
        <button disabled={busy} onClick={test}>Test connection</button>
      </div>
      {msg && <p className="mini-meta" style={{ marginTop: 6 }}>{msg}</p>}
      <TestResult r={result} />
    </div>
  );
}

export function AuthenticationAdmin() {
  const [roles] = useReload(() => api.listRoles());
  const roleIds = (roles?.roles ?? []).map((r) => r.id).filter((x): x is string => !!x);
  const fallbackRoles = roleIds.length ? roleIds : ["super-admin", "operator", "read-only"];

  return (
    <>
      <AdminHead title="Authentication" sub="How people sign in. Local accounts always work. SSO (OIDC) is brokered by your identity provider; native LDAP/AD and TACACS+ authenticate directly. All three are configured below." />
      <div className="ov-grid">
        <div className="panel col-12 provider-card">
          <div className="provider-head"><h3>Local accounts</h3><span className="badge good">Active</span></div>
          <p className="mini-meta">Username + password (PBKDF2) with JWT + rotating single-use refresh tokens. Always available as a fallback even when an external IdP is down.</p>
        </div>
      </div>

      <SsoAdminForm roleIds={fallbackRoles} />
      <LdapAdminForm roleIds={fallbackRoles} />
      <TacacsAdminForm roleIds={fallbackRoles} />
    </>
  );
}

// ---- Single Sign-On (OIDC) form ----
// Mirrors the LDAP/TACACS forms: a kv-persisted overlay over the env defaults,
// with the client secret write-only. Saving rebuilds the live provider on the
// server, so SSO can be turned on without editing .env or restarting.
function SsoAdminForm({ roleIds }: { roleIds: string[] }) {
  const [cfg, setCfg] = useState<OidcConfig | null>(null);
  const [ready, setReady] = useState(false);
  const [secret, setSecret] = useState(""); // typed client secret (only sent if non-empty)
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const redirectHint = `${window.location.origin}/api/auth/sso/callback`;

  useEffect(() => {
    api.oidcConfig()
      .then((r) => { setCfg(r.config); setReady(r.ready); })
      .catch((e) => setMsg((e as Error).message));
  }, []);
  if (!cfg) return <div className="card"><h2>Single Sign-On (OIDC)</h2><p className="mini-meta">{msg ?? "Loading…"}</p></div>;

  const set = (patch: Partial<OidcConfig>) => setCfg({ ...cfg, ...patch });

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const body: Partial<OidcConfig> & { client_secret?: string } = { ...cfg };
      if (secret) body.client_secret = secret; // only override the secret when re-typed
      const r = await api.saveOidcConfig(body);
      setCfg(r.config); setReady(r.ready); setSecret(""); setMsg("Saved.");
    } catch (e) { setMsg((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <div className="card">
      <div className="admin-card-head">
        <h2>
          Single Sign-On (OIDC) <ProviderBadge enabled={cfg.enabled} />{" "}
          <span className={`badge ${ready ? "good" : "accent-badge"}`}>{ready ? "Ready" : "Not ready"}</span>
        </h2>
        <label style={{ fontSize: 13 }}>
          <input type="checkbox" checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled
        </label>
      </div>
      <p className="admin-sub">Federate sign-in to your OIDC identity provider (Authorization Code flow). The platform brokers the login and re-issues its own session. Upstream IdPs such as Okta, Azure AD, Google or any standards-compliant provider are supported. The client secret is write-only — leave blank to keep the stored one.</p>
      <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
        <LabeledInput label="Issuer / Discovery URL" value={cfg.issuer} onChange={(v) => set({ issuer: v })} placeholder="https://idp.example.com/realms/netops" hint="Base issuer URL; /.well-known/openid-configuration is appended." required />
        <LabeledInput label="Client ID" value={cfg.client_id} onChange={(v) => set({ client_id: v })} placeholder="netops" required />
        <LabeledInput label="Client secret" type="password" value={secret} onChange={setSecret} placeholder={cfg.client_secret_set ? "•••••• (unchanged)" : "(none / public client)"} />
        <LabeledInput label="Scopes" value={cfg.scopes} onChange={(v) => set({ scopes: v })} placeholder="openid email profile" />
        <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
          Default role
          <select value={cfg.default_role} onChange={(e) => set({ default_role: e.target.value })}>
            {roleIds.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>
        <LabeledInput label="Default tenant" value={cfg.default_tenant} onChange={(v) => set({ default_tenant: v })} />
        <LabeledInput label="Admin roles" value={cfg.admin_roles} onChange={(v) => set({ admin_roles: v })} placeholder="super-admin,admin,netops-admin" hint="Comma-separated IdP roles/groups mapped to super-admin." />
        <LabeledInput label="Operator roles" value={cfg.operator_roles} onChange={(v) => set({ operator_roles: v })} placeholder="operator,netops-operator" hint="Comma-separated IdP roles/groups mapped to operator." />
        <LabeledInput label="Providers" value={cfg.providers} onChange={(v) => set({ providers: v })} placeholder="okta:Okta:oidc,ad:Azure AD:saml" hint="Optional sign-in buttons: id:Label:kind, comma-separated. Blank = one default button." />
        <LabeledInput label="Post-login URL" value={cfg.post_login_url} onChange={(v) => set({ post_login_url: v })} placeholder="/" hint="Where the browser lands after a successful login." />
        <LabeledInput label="Redirect URL override" value={cfg.redirect_url} onChange={(v) => set({ redirect_url: v })} placeholder="(derived from request)" hint="Optional; leave blank to derive from the incoming request." />
      </div>
      <p className="mini-meta" style={{ marginTop: 8 }}>
        Register this Redirect URI with your identity provider:{" "}
        <code className="mono" style={{ userSelect: "all" }}>{redirectHint}</code>
      </p>
      <RequiredLegend />
      <div style={{ marginTop: 16, display: "flex", gap: 8, alignItems: "center" }}>
        <button className="dash-btn" disabled={busy} onClick={save}>Save</button>
      </div>
      {msg && <p className="mini-meta" style={{ marginTop: 6 }}>{msg}</p>}
    </div>
  );
}

// Editable token-lifetime policy. Access TTL is entered in minutes, refresh in
// days; both are clamped server-side to the RFC 9700 / NIST 800-63B bounds.
function TokenPolicyForm() {
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
  if (!tp) return <div className="card"><h2>Token policy</h2><p className="mini-meta">{msg ?? "Loading…"}</p></div>;

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

  return (
    <div className="card">
      <h2>Token policy</h2>
      <p className="admin-sub">Session token lifetimes. Values are clamped to safe bounds (RFC 9700 / NIST 800-63B); out-of-range entries are adjusted on save.</p>
      <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
        <LabeledInput label="Access token TTL (minutes)" type="number" value={accessMin} onChange={setAccessMin}
          hint={`allowed ${Math.round(b.access_min_seconds / 60)}–${Math.round(b.access_max_seconds / 60)} min · recommended ≤ ${Math.round(b.access_recommended_seconds / 60)} min`} required />
        <LabeledInput label="Refresh token TTL (days)" type="number" value={refreshDays} onChange={setRefreshDays}
          hint={`allowed ${Math.round(b.refresh_min_seconds / 86400) || 1}–${Math.round(b.refresh_max_seconds / 86400)} days · recommended ≤ ${Math.round(b.refresh_recommended_seconds / 86400)} days`} required />
      </div>
      <dl className="kv-form" style={{ marginTop: 12 }}>
        <dt>Refresh rotation</dt><dd>single-use with reuse detection (reuse revokes the lineage)</dd>
        <dt>Local tokens</dt><dd className="mono">HS256, signed with the server secret</dd>
        <dt>Federated tokens</dt><dd className="mono">RS256, verified against the identity provider's JWKS</dd>
      </dl>
      <RequiredLegend />
      <div style={{ marginTop: 12 }}>
        <button className="dash-btn" disabled={busy} onClick={save}>Save policy</button>
      </div>
      {msg && <p className="mini-meta" style={{ marginTop: 6 }}>{msg}</p>}
    </div>
  );
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

const ITSM = [
  { id: "servicenow", name: "ServiceNow", desc: "Critical alerts cut an incident via the Table API (deduped by fingerprint) and auto-resolve when the alert clears; critical incidents auto-promote too. Configure it in the form above — no restart.", tag: "Available" },
  { id: "jira", name: "Jira", desc: "Alerts at/above the threshold open a deduped Jira issue (REST v2) and transition to Done when the alert clears. Configure it in the form above — no restart.", tag: "Available" },
];

// ITSMConfigForm — admin-editable ServiceNow + Jira connector config (replaces the
// old "Configured via env" greyed cards). Saves to PUT /api/notify/itsm, which
// rebuilds + hot-swaps the live connectors (no restart). Secrets are write-only:
// leave the password/token blank to keep the stored one. Platform-owner only —
// the API 403s otherwise, surfaced as a save error.
function ITSMConfigForm() {
  const [cfg, setCfg] = useState<ItsmConfig | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.itsmConfig().then(setCfg).catch((e) => setMsg((e as Error).message)); }, []);
  if (!cfg) return <div className="card"><h2>ServiceNow & Jira configuration</h2><p className="mini-meta">{msg ?? "Loading…"}</p></div>;

  const sn = cfg.servicenow, jr = cfg.jira;
  const setSN = (p: Partial<ItsmServiceNowConfig>) => setCfg({ ...cfg, servicenow: { ...cfg.servicenow, ...p } });
  const setJR = (p: Partial<ItsmJiraConfig>) => setCfg({ ...cfg, jira: { ...cfg.jira, ...p } });
  const SEV = ["info", "low", "medium", "high", "critical"];

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const out = await api.saveItsmConfig({
        servicenow: { enabled: sn.enabled, instance_url: sn.instance_url, user: sn.user, password: sn.password || "", min_severity: sn.min_severity, assignment_group: sn.assignment_group },
        jira: { enabled: jr.enabled, base_url: jr.base_url, email: jr.email, api_token: jr.api_token || "", project_key: jr.project_key, issue_type: jr.issue_type, min_severity: jr.min_severity, resolve_transition: jr.resolve_transition },
      });
      setCfg(out); setMsg("Saved — connectors updated live (no restart).");
    } catch (e) { setMsg((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <div className="card">
      <div className="admin-card-head"><h2>ServiceNow & Jira configuration</h2><RequiredLegend /></div>
      <p className="admin-sub">Configure your system-of-record connectors here — no environment variables or restart needed. These apply to <strong>your tenant</strong>: your incidents promote to your own ServiceNow/Jira. Secrets are write-only: leave blank to keep the stored value.</p>

      <h3 style={{ marginTop: 14 }}>ServiceNow {sn.configured && <span className="badge good">connected</span>}</h3>
      <label className="scope-chip" style={{ marginBottom: 8 }}>
        <input type="checkbox" checked={sn.enabled} onChange={(e) => setSN({ enabled: e.target.checked })} /> Enable ServiceNow ticketing
      </label>
      <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
        <LabeledInput label="Instance URL" value={sn.instance_url} onChange={(v) => setSN({ instance_url: v })} placeholder="https://dev12345.service-now.com" required={sn.enabled} />
        <LabeledInput label="User" value={sn.user} onChange={(v) => setSN({ user: v })} />
        <LabeledInput label="Password" type="password" value={sn.password ?? ""} onChange={(v) => setSN({ password: v })} placeholder={sn.has_password ? "•••••• (unchanged)" : ""} hint="write-only — blank keeps stored" />
        <LabeledSelect label="Min severity to ticket" value={sn.min_severity} onChange={(v) => setSN({ min_severity: v })} options={SEV} />
        <LabeledInput label="Assignment group (optional)" value={sn.assignment_group} onChange={(v) => setSN({ assignment_group: v })} />
      </div>

      <h3 style={{ marginTop: 18 }}>Jira {jr.configured && <span className="badge good">connected</span>}</h3>
      <label className="scope-chip" style={{ marginBottom: 8 }}>
        <input type="checkbox" checked={jr.enabled} onChange={(e) => setJR({ enabled: e.target.checked })} /> Enable Jira ticketing
      </label>
      <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
        <LabeledInput label="Base URL" value={jr.base_url} onChange={(v) => setJR({ base_url: v })} placeholder="https://your-org.atlassian.net" required={jr.enabled} />
        <LabeledInput label="Project key" value={jr.project_key} onChange={(v) => setJR({ project_key: v })} placeholder="NOC" required={jr.enabled} />
        <LabeledInput label="Email" value={jr.email} onChange={(v) => setJR({ email: v })} placeholder="svc@your-org.com" />
        <LabeledInput label="API token" type="password" value={jr.api_token ?? ""} onChange={(v) => setJR({ api_token: v })} placeholder={jr.has_token ? "•••••• (unchanged)" : ""} hint="write-only — blank keeps stored" />
        <LabeledInput label="Issue type (optional)" value={jr.issue_type} onChange={(v) => setJR({ issue_type: v })} placeholder="Incident" />
        <LabeledInput label="Resolve transition (optional)" value={jr.resolve_transition} onChange={(v) => setJR({ resolve_transition: v })} placeholder="Done" />
        <LabeledSelect label="Min severity to ticket" value={jr.min_severity} onChange={(v) => setJR({ min_severity: v })} options={SEV} />
      </div>

      <button className="dash-btn primary" style={{ marginTop: 14 }} onClick={save} disabled={busy}>{busy ? "Saving…" : "Save ITSM configuration"}</button>
      {msg && <p className="mini-meta" style={{ marginTop: 8 }}>{msg}</p>}
    </div>
  );
}

// ITSMWizard — a guided flow (system → connect → routing → review) for wiring a
// tenant's ServiceNow/Jira, mirroring the Reports guided setup. Builds an
// ItsmConfigInput and saves it (connectors hot-swap live, no restart).
function ITSMWizard({ onCancel, onDone }: { onCancel: () => void; onDone: () => Promise<void> }) {
  const [step, setStep] = useState(0);
  const [pick, setPick] = useState<"servicenow" | "jira" | "both">("servicenow");
  const [sn, setSn] = useState({ instance_url: "", user: "", password: "", min_severity: "critical", assignment_group: "" });
  const [jr, setJr] = useState({ base_url: "", project_key: "", email: "", api_token: "", issue_type: "", resolve_transition: "", min_severity: "critical" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const STEPS = ["System", "Connect", "Routing", "Review"];
  const SEV = ["info", "low", "medium", "high", "critical"];
  const wantSN = pick === "servicenow" || pick === "both";
  const wantJR = pick === "jira" || pick === "both";

  const SYSTEMS: { id: typeof pick; icon: string; label: string; blurb: string }[] = [
    { id: "servicenow", icon: "🧰", label: "ServiceNow", blurb: "Cut incidents via the Table API; auto-resolve when the alert clears." },
    { id: "jira", icon: "📋", label: "Jira", blurb: "Open deduped issues via REST v2; transition to Done on clear." },
    { id: "both", icon: "🔗", label: "Both", blurb: "Wire ServiceNow and Jira together." },
  ];

  const valid = () => {
    if (wantSN && !/^https?:\/\//.test(sn.instance_url)) return "ServiceNow instance URL must start with http(s)://";
    if (wantJR && !/^https?:\/\//.test(jr.base_url)) return "Jira base URL must start with http(s)://";
    if (wantJR && !jr.project_key.trim()) return "Jira project key is required";
    return null;
  };

  const save = async () => {
    const v = valid();
    if (v) { setMsg(v); setStep(1); return; }
    setBusy(true); setMsg(null);
    try {
      await api.saveItsmConfig({
        servicenow: { enabled: wantSN, instance_url: sn.instance_url, user: sn.user, password: sn.password, min_severity: sn.min_severity, assignment_group: sn.assignment_group },
        jira: { enabled: wantJR, base_url: jr.base_url, email: jr.email, api_token: jr.api_token, project_key: jr.project_key, issue_type: jr.issue_type, min_severity: jr.min_severity, resolve_transition: jr.resolve_transition },
      });
      await onDone();
    } catch (e) { setMsg((e as Error).message); } finally { setBusy(false); }
  };
  const cardBtn = (active: boolean): React.CSSProperties => ({ textAlign: "left", padding: 14, borderColor: active ? "var(--accent)" : undefined });

  return (
    <div className="card" style={{ maxWidth: 760 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h2 style={{ margin: 0 }}>Guided ITSM setup</h2>
        <button className="dash-btn" onClick={onCancel}>Close</button>
      </div>
      <p className="mini-meta">Wires your tenant's ticketing — your incidents promote to your own system of record.</p>
      <div style={{ display: "flex", gap: 14, margin: "14px 0 18px", flexWrap: "wrap" }}>
        {STEPS.map((s, i) => (
          <div key={s} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: i === step ? "var(--accent)" : "var(--muted)", fontWeight: i === step ? 700 : 400 }}>
            <span style={{ width: 20, height: 20, borderRadius: 999, display: "inline-flex", alignItems: "center", justifyContent: "center", background: i < step ? "var(--good)" : i === step ? "var(--accent)" : "var(--panel-border)", color: "#fff", fontSize: 11 }}>{i < step ? "✓" : i + 1}</span>
            {s}
          </div>
        ))}
      </div>

      {step === 0 && (
        <div>
          <p className="mini-meta">Which system of record do you use?</p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(210px, 1fr))", gap: 10 }}>
            {SYSTEMS.map((g) => (
              <button key={g.id} className="dash-btn" style={cardBtn(pick === g.id)} onClick={() => { setPick(g.id); setStep(1); }}>
                <div style={{ fontSize: 22 }}>{g.icon}</div>
                <div style={{ fontWeight: 700, marginTop: 4 }}>{g.label}</div>
                <div className="mini-meta">{g.blurb}</div>
              </button>
            ))}
          </div>
        </div>
      )}

      {step === 1 && (
        <div style={{ display: "grid", gap: 16 }}>
          {wantSN && (
            <div>
              <h3 style={{ margin: "0 0 8px" }}>ServiceNow</h3>
              <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                <LabeledInput label="Instance URL" value={sn.instance_url} onChange={(v) => setSn({ ...sn, instance_url: v })} placeholder="https://dev12345.service-now.com" required />
                <LabeledInput label="User" value={sn.user} onChange={(v) => setSn({ ...sn, user: v })} />
                <LabeledInput label="Password" type="password" value={sn.password} onChange={(v) => setSn({ ...sn, password: v })} hint="write-only" />
              </div>
            </div>
          )}
          {wantJR && (
            <div>
              <h3 style={{ margin: "0 0 8px" }}>Jira</h3>
              <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                <LabeledInput label="Base URL" value={jr.base_url} onChange={(v) => setJr({ ...jr, base_url: v })} placeholder="https://your-org.atlassian.net" required />
                <LabeledInput label="Project key" value={jr.project_key} onChange={(v) => setJr({ ...jr, project_key: v })} placeholder="NOC" required />
                <LabeledInput label="Email" value={jr.email} onChange={(v) => setJr({ ...jr, email: v })} placeholder="svc@your-org.com" />
                <LabeledInput label="API token" type="password" value={jr.api_token} onChange={(v) => setJr({ ...jr, api_token: v })} hint="write-only" />
              </div>
            </div>
          )}
          <RequiredLegend />
        </div>
      )}

      {step === 2 && (
        <div style={{ display: "grid", gap: 16 }}>
          {wantSN && (
            <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
              <LabeledSelect label="ServiceNow — min severity to ticket" value={sn.min_severity} onChange={(v) => setSn({ ...sn, min_severity: v })} options={SEV} />
              <LabeledInput label="Assignment group (optional)" value={sn.assignment_group} onChange={(v) => setSn({ ...sn, assignment_group: v })} />
            </div>
          )}
          {wantJR && (
            <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
              <LabeledSelect label="Jira — min severity to ticket" value={jr.min_severity} onChange={(v) => setJr({ ...jr, min_severity: v })} options={SEV} />
              <LabeledInput label="Issue type (optional)" value={jr.issue_type} onChange={(v) => setJr({ ...jr, issue_type: v })} placeholder="Incident" />
              <LabeledInput label="Resolve transition (optional)" value={jr.resolve_transition} onChange={(v) => setJr({ ...jr, resolve_transition: v })} placeholder="Done" />
            </div>
          )}
        </div>
      )}

      {step === 3 && (
        <div style={{ display: "grid", gap: 8 }}>
          <p className="mini-meta">Review — connectors hot-swap live on save (no restart).</p>
          {wantSN && <div className="mini-meta">🧰 <strong>ServiceNow</strong> → {sn.instance_url || "—"} · tickets at <strong>{sn.min_severity}</strong> and worse{sn.assignment_group ? ` · group ${sn.assignment_group}` : ""}</div>}
          {wantJR && <div className="mini-meta">📋 <strong>Jira</strong> → {jr.base_url || "—"} · project <strong>{jr.project_key || "—"}</strong> · issues at <strong>{jr.min_severity}</strong> and worse</div>}
          {msg && <p className="mini-meta" style={{ color: "var(--bad)" }}>{msg}</p>}
        </div>
      )}

      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 18 }}>
        <button className="dash-btn" disabled={step === 0} onClick={() => setStep((s) => Math.max(0, s - 1))}>Back</button>
        {step < 3 ? (
          <button className="dash-btn accent" onClick={() => setStep((s) => Math.min(3, s + 1))}>Next</button>
        ) : (
          <button className="dash-btn accent" disabled={busy} onClick={save}>{busy ? "Saving…" : "Save & connect"}</button>
        )}
      </div>
    </div>
  );
}

export function IntegrationsAdmin() {
  const [sn, , reloadSN] = useReload(() => api.itsmServiceNow());
  const [jira, , reloadJira] = useReload(() => api.itsmJira());
  const [wizard, setWizard] = useState(false);
  const snLive = !!sn?.configured;
  const jiraLive = !!jira?.configured;

  if (wizard) {
    return (
      <>
        <AdminHead title="ITSM & Ticketing" sub="Turn alerts and incidents into tickets in your system of record." />
        <ITSMWizard onCancel={() => setWizard(false)} onDone={async () => { setWizard(false); await reloadSN(); await reloadJira(); }} />
      </>
    );
  }

  return (
    <>
      <AdminHead title="ITSM & Ticketing" sub="Turn alerts and incidents into tickets in your system of record." />
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 8 }}>
        <button className="dash-btn accent" onClick={() => setWizard(true)}>✨ Guided setup</button>
      </div>
      <ITSMConfigForm />

      <BidirectionalSyncAdmin />

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
              <button className="dash-btn" disabled={i.id !== "servicenow" && i.id !== "jira"} style={{ marginTop: 10 }}
                onClick={() => { if (i.id === "servicenow" || i.id === "jira") window.scrollTo({ top: 0, behavior: "smooth" }); }}>
                {i.id === "servicenow" || i.id === "jira" ? "Configure above ↑" : "Configure"}
              </button>
            </div>
          );
        })}
      </div>
    </>
  );
}

// ---- Bidirectional sync (Integration Platform) -----------------------------

// Per-provider hint on where to paste the inbound webhook URL.
const SYNC_PROVIDERS: { id: string; name: string; webhookHint: string }[] = [
  { id: "servicenow", name: "ServiceNow", webhookHint: "Paste into a ServiceNow Business Rule (REST call on incident update)." },
  { id: "jira", name: "Jira", webhookHint: "Paste into a Jira webhook (Settings → System → Webhooks)." },
  { id: "pagerduty", name: "PagerDuty", webhookHint: "Paste into a PagerDuty v3 webhook subscription." },
  { id: "slack", name: "Slack", webhookHint: "Paste into your Slack app's Interactivity & Shortcuts request URL." },
];

// One provider's bidirectional-sync card: enable, sync mode, inbound webhook
// toggle + write-only signing secret, and (once a token exists) the full inbound
// webhook URL to register with the provider. The signing secret is write-only —
// blank keeps the stored one.
function SyncProviderCard({ cfg, name, webhookHint, onSaved }: {
  cfg: IntegrationConfig; name: string; webhookHint: string;
  onSaved: (next: IntegrationConfig) => void;
}) {
  const [enabled, setEnabled] = useState(cfg.enabled);
  const [syncMode, setSyncMode] = useState(cfg.sync_mode);
  const [webhookEnabled, setWebhookEnabled] = useState(cfg.webhook_enabled);
  const [secret, setSecret] = useState(""); // typed signing secret (only sent if non-empty)
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Full URL to register with the provider (the API returns a path only).
  const fullUrl = cfg.webhook_url ? window.location.origin + cfg.webhook_url : "";

  const copy = async () => {
    try { await navigator.clipboard.writeText(fullUrl); setCopied(true); setTimeout(() => setCopied(false), 1500); }
    catch { setMsg("Copy failed — select the URL and copy manually."); }
  };

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const body: Partial<{ enabled: boolean; sync_mode: string; webhook_enabled: boolean; webhook_secret: string }> = {
        enabled, sync_mode: syncMode, webhook_enabled: webhookEnabled,
      };
      if (secret) body.webhook_secret = secret; // write-only — omit when blank to keep stored
      const next = await api.saveIntegration(cfg.provider, body);
      onSaved(next); setSecret(""); setMsg("Saved.");
    } catch (e) { setMsg((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <div className="card">
      <div className="admin-card-head">
        <h2>{name} <ProviderBadge enabled={enabled} /></h2>
        <label className="mini-meta" style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled
        </label>
      </div>
      <div className="form-grid">
        <LabeledSelect label="Sync mode" value={syncMode} onChange={(v) => setSyncMode(v as IntegrationConfig["sync_mode"])} options={["outbound", "bidirectional"]} />
        <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
          <span>Inbound webhook</span>
          <label className="mini-meta" style={{ display: "flex", gap: 6, alignItems: "center", padding: "8px 0" }}>
            <input type="checkbox" checked={webhookEnabled} onChange={(e) => setWebhookEnabled(e.target.checked)} /> Accept inbound state changes
          </label>
        </label>
        <LabeledInput label={`Webhook signing secret${cfg.webhook_secret_set ? " (stored)" : ""}`} type="password" value={secret} onChange={setSecret} placeholder={cfg.webhook_secret_set ? "•••••• (unchanged)" : "shared secret for HMAC verification"} hint="write-only — blank keeps stored" />
      </div>

      {fullUrl && (
        <div style={{ marginTop: 12 }}>
          <span className="mini-meta">Inbound webhook URL</span>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 4 }}>
            <input readOnly value={fullUrl} onFocus={(e) => e.currentTarget.select()} className="mono"
              style={{ flex: 1, padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" }} />
            <button className="dash-btn" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
          </div>
          <p className="mini-meta" style={{ marginTop: 4 }}>{webhookHint}</p>
        </div>
      )}

      <div className="admin-actions">
        <button onClick={save} disabled={busy}>{busy ? "Saving…" : "Save"}</button>
        {msg && <span className="mini-meta">{msg}</span>}
      </div>
    </div>
  );
}

// BidirectionalSyncAdmin — the Integration Platform's two-way sync config. Lists
// one card per provider (ServiceNow / Jira / PagerDuty / Slack) for enabling
// outbound-only vs. bidirectional sync and registering inbound webhooks. The
// banner reflects whether the server is actually driving incident state from
// inbound webhooks (FEATURE_ITSM_INBOUND), which an operator enables.
export function BidirectionalSyncAdmin() {
  const [integrations, setIntegrations] = useState<IntegrationConfig[] | null>(null);
  const [inboundEnabled, setInboundEnabled] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.integrations()
      .then((r) => { setIntegrations(r.integrations); setInboundEnabled(r.inbound_enabled); })
      .catch((e) => setErr((e as Error).message));
  }, []);

  // Replace a single provider's config in place after a save.
  const onSaved = (next: IntegrationConfig) =>
    setIntegrations((cur) => (cur ?? []).map((i) => (i.provider === next.provider ? next : i)));

  // Resolve the config for a provider (fall back to a sane default if absent).
  const cfgFor = (id: string): IntegrationConfig =>
    integrations?.find((i) => i.provider === id) ??
    { provider: id, enabled: false, sync_mode: "outbound", webhook_enabled: false, webhook_secret_set: false, state_map: null };

  return (
    <div className="card">
      <div className="admin-card-head"><h2>Bidirectional sync</h2></div>
      <p className="admin-sub">Sync incident state two ways with your ticketing systems. Outbound promotes your incidents to tickets; bidirectional also applies inbound state changes (close, reassign) back onto the incident when a registered webhook fires.</p>

      {inboundEnabled
        ? <p style={{ margin: "0 0 12px", padding: "8px 12px", borderRadius: 6, fontSize: 13, border: "1px solid var(--good)", background: "var(--sev-ok-bg)", color: "var(--good)" }}>Inbound sync is active — registered webhooks drive incident state.</p>
        : <p style={{ margin: "0 0 12px", padding: "8px 12px", borderRadius: 6, fontSize: 13, border: "1px solid var(--panel-border)", background: "var(--bg)", color: "var(--muted)" }}>Inbound webhooks are being recorded but not yet driving incident state — pending platform enablement.</p>}

      {err && <p className="mini-meta">{err}</p>}
      {!integrations && !err && <p className="mini-meta">Loading…</p>}

      {integrations && SYNC_PROVIDERS.map((p) => (
        <SyncProviderCard key={p.id} cfg={cfgFor(p.id)} name={p.name} webhookHint={p.webhookHint} onSaved={onSaved} />
      ))}
    </div>
  );
}

// ---- Notifications (SMTP / Twilio / ntfy) ----------------------------------

const SEVERITIES = ["info", "notice", "warning", "error", "critical"];

function SeveritySelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
      <span>Send on severity ≥</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}
        style={{ padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" }}>
        {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>
    </label>
  );
}

export function NotificationsAdmin() {
  const [smtp, setSmtp] = useState<SmtpConfig | null>(null);
  const [twilio, setTwilio] = useState<TwilioConfig | null>(null);
  const [ntfy, setNtfy] = useState<NtfyConfig | null>(null);
  const [slack, setSlack] = useState<SlackConfig | null>(null);
  const [pager, setPager] = useState<PagerDutyConfig | null>(null);
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
    loadCps();
  }, []);

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

      {/* SMTP */}
      <div className="card">
        <div className="admin-card-head">
          <h2>Email (SMTP)</h2>
          <label className="mini-meta" style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={!!smtp?.enabled} onChange={(e) => smtp && setSmtp({ ...smtp, enabled: e.target.checked })} /> Enabled
          </label>
        </div>
        {smtp && (
          <>
            <div className="form-grid">
              <LabeledInput label="Host" value={smtp.host} onChange={(v) => setSmtp({ ...smtp, host: v })} required placeholder="smtp.example.com" />
              <LabeledInput label="Port" type="number" value={String(smtp.port)} onChange={(v) => setSmtp({ ...smtp, port: Number(v) || 0 })} required placeholder="587" />
              <LabeledInput label="From" value={smtp.from} onChange={(v) => setSmtp({ ...smtp, from: v })} required placeholder="noc@example.com" />
              <LabeledInput label="Recipients (comma-separated)" value={smtp.to} onChange={(v) => setSmtp({ ...smtp, to: v })} required />
              <LabeledInput label="Username" value={smtp.user} onChange={(v) => setSmtp({ ...smtp, user: v })} />
              <LabeledInput label={`Password${smtp.pass_set ? " (stored)" : ""}`} type="password" value={secret.smtp} onChange={(v) => setSecret((s) => ({ ...s, smtp: v }))} placeholder={smtp.pass_set ? "•••••• (unchanged)" : ""} />
              <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--muted)" }}>
                <span>Security</span>
                <select value={smtp.security} onChange={(e) => setSmtp({ ...smtp, security: e.target.value })}
                  style={{ padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" }}>
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
      </div>

      {/* Twilio */}
      <div className="card">
        <div className="admin-card-head">
          <h2>SMS (Twilio)</h2>
          <label className="mini-meta" style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={!!twilio?.enabled} onChange={(e) => twilio && setTwilio({ ...twilio, enabled: e.target.checked })} /> Enabled
          </label>
        </div>
        <p className="mini-meta">Phone SMS for critical alerts. Twilio is metered — use ntfy below for free testing.</p>
        {twilio && (
          <>
            <div className="form-grid">
              <LabeledInput label="Account SID" value={twilio.account_sid} onChange={(v) => setTwilio({ ...twilio, account_sid: v })} required />
              <LabeledInput label={`Auth token${twilio.token_set ? " (stored)" : ""}`} type="password" value={secret.twilio} onChange={(v) => setSecret((s) => ({ ...s, twilio: v }))} placeholder={twilio.token_set ? "•••••• (unchanged)" : ""} />
              <LabeledInput label="From number" value={twilio.from} onChange={(v) => setTwilio({ ...twilio, from: v })} required placeholder="+15555550123" />
              <LabeledInput label="To numbers (comma-separated)" value={twilio.to} onChange={(v) => setTwilio({ ...twilio, to: v })} required />
              <SeveritySelect value={twilio.min_severity} onChange={(v) => setTwilio({ ...twilio, min_severity: v })} />
            </div>
            <RequiredLegend />
            <div className="admin-actions">
              <button onClick={saveTwilio}>Save</button>
              <button className="ghost" onClick={() => test("twilio", api.testTwilio)}>Send test</button>
              {msg.twilio && <span className="mini-meta">{msg.twilio}</span>}
            </div>
          </>
        )}
      </div>

      {/* ntfy */}
      <div className="card">
        <div className="admin-card-head">
          <h2>Push (ntfy.sh)</h2>
          <label className="mini-meta" style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={!!ntfy?.enabled} onChange={(e) => ntfy && setNtfy({ ...ntfy, enabled: e.target.checked })} /> Enabled
          </label>
        </div>
        <p className="mini-meta">Free push to phone/desktop — subscribe to the topic in the ntfy app. Great for testing critical-alert pushes without Twilio.</p>
        {ntfy && (
          <>
            <div className="form-grid">
              <LabeledInput label="Server" value={ntfy.server} onChange={(v) => setNtfy({ ...ntfy, server: v })} placeholder="https://ntfy.sh" />
              <LabeledInput label="Topic" value={ntfy.topic} onChange={(v) => setNtfy({ ...ntfy, topic: v })} required placeholder="netops-xxxxxx" />
              <LabeledInput label={`Token (optional)${ntfy.token_set ? " (stored)" : ""}`} type="password" value={secret.ntfy} onChange={(v) => setSecret((s) => ({ ...s, ntfy: v }))} placeholder={ntfy.token_set ? "•••••• (unchanged)" : "for protected topics"} />
              <SeveritySelect value={ntfy.min_severity} onChange={(v) => setNtfy({ ...ntfy, min_severity: v })} />
            </div>
            <RequiredLegend />
            <div className="admin-actions">
              <button onClick={saveNtfy}>Save</button>
              <button className="ghost" onClick={() => test("ntfy", api.testNtfy)}>Send test</button>
              {msg.ntfy && <span className="mini-meta">{msg.ntfy}</span>}
            </div>
          </>
        )}
      </div>

      {/* Slack */}
      <div className="card">
        <div className="admin-card-head">
          <h2>Slack</h2>
          <label className="mini-meta" style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={!!slack?.enabled} onChange={(e) => slack && setSlack({ ...slack, enabled: e.target.checked })} /> Enabled
          </label>
        </div>
        <p className="mini-meta">Posts alerts to a Slack Incoming Webhook. Create one at api.slack.com → Incoming Webhooks; the URL embeds a secret, so it is write-only.</p>
        {slack && (
          <>
            <div className="form-grid">
              <LabeledInput label={`Webhook URL${slack.webhook_set ? " (stored)" : ""}`} type="password" value={secret.slack} onChange={(v) => setSecret((s) => ({ ...s, slack: v }))} placeholder={slack.webhook_set ? "•••••• (unchanged)" : "https://hooks.slack.com/services/…"} required={!slack.webhook_set} />
              <SeveritySelect value={slack.min_severity} onChange={(v) => setSlack({ ...slack, min_severity: v })} />
            </div>
            <RequiredLegend />
            <div className="admin-actions">
              <button onClick={saveSlack}>Save</button>
              <button className="ghost" onClick={() => test("slack", api.testSlack)}>Send test</button>
              {msg.slack && <span className="mini-meta">{msg.slack}</span>}
            </div>
          </>
        )}
      </div>

      {/* PagerDuty */}
      <div className="card">
        <div className="admin-card-head">
          <h2>PagerDuty</h2>
          <label className="mini-meta" style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={!!pager?.enabled} onChange={(e) => pager && setPager({ ...pager, enabled: e.target.checked })} /> Enabled
          </label>
        </div>
        <p className="mini-meta">On-call escalation via the Events API v2. Add an Events API v2 integration to a PagerDuty service and paste its integration (routing) key.</p>
        {pager && (
          <>
            <div className="form-grid">
              <LabeledInput label={`Routing key${pager.routing_set ? " (stored)" : ""}`} type="password" value={secret.pager} onChange={(v) => setSecret((s) => ({ ...s, pager: v }))} placeholder={pager.routing_set ? "•••••• (unchanged)" : "32-char integration key"} required={!pager.routing_set} />
              <SeveritySelect value={pager.min_severity} onChange={(v) => setPager({ ...pager, min_severity: v })} />
            </div>
            <RequiredLegend />
            <div className="admin-actions">
              <button onClick={savePager}>Save</button>
              <button className="ghost" onClick={() => test("pager", api.testPagerDuty)}>Send test</button>
              {msg.pager && <span className="mini-meta">{msg.pager}</span>}
            </div>
          </>
        )}
      </div>

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
          <table style={{ width: "100%", marginBottom: 12 }}>
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
