// GUI-configurable SSO — the "Identity Providers" panel inside the SSO tile
// modal (Administration → Authentication → Single Sign-On). Lists the Keycloak-
// brokered upstream IdPs, and edits one at a time: SAML (metadata URL / pasted
// or uploaded XML, optional signing cert with a client-side expiry banner) or
// OIDC (discovery URL + client credentials), plus the user-attribute mappings
// and the ordered group→role mapping table (first match wins).
//
// Design brief: docs/research/sso-admin-ui-vendor-patterns.md §6 — SP values
// read-only with copy-to-clipboard, mapping table as the heart of the UI,
// test-connection with per-check ✓/✗, and the 30d/7d cert-expiry banner.
// Plain React + native inputs; talks to /api/auth/sso/idp (platform-admin).

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, SsoIdP, SsoIdpAttrMapping, SsoIdpRoleMapping, SsoIdpTestResult } from "../services/api";
import { certExpiry, parseCertNotAfter } from "../lib/x509";
import AskIris from "../components/AskIris";

// ---- pure helpers (exported for tests) -------------------------------------

// AWS-style external-IdP defaults: the three attributes every directory maps.
export const DEFAULT_ATTR_MAPPINGS: SsoIdpAttrMapping[] = [
  { idp_attr: "email", user_attr: "email" },
  { idp_attr: "firstName", user_attr: "firstName" },
  { idp_attr: "lastName", user_attr: "lastName" },
];

export function blankIdp(protocol: "saml" | "oidc"): SsoIdP {
  return {
    alias: "",
    display_name: "",
    protocol,
    enabled: true,
    groups_attr: "groups",
    attr_mappings: DEFAULT_ATTR_MAPPINGS.map((m) => ({ ...m })),
    role_mappings: [],
  };
}

// moveRow — reorder an ordered mapping list by one position (up/down buttons;
// no drag dependency). Out-of-range moves return the input unchanged.
export function moveRow<T>(rows: T[], i: number, delta: -1 | 1): T[] {
  const j = i + delta;
  if (i < 0 || i >= rows.length || j < 0 || j >= rows.length) return rows;
  const next = rows.slice();
  const [row] = next.splice(i, 1);
  next.splice(j, 0, row);
  return next;
}

// The SP-side values an IdP admin must register on their side (Keycloak broker
// endpoints). Derived from the page origin like the existing redirect-URI hint.
export function spValues(origin: string, realm: string, alias: string, protocol: "saml" | "oidc"): { label: string; value: string }[] {
  const r = realm || "<realm>";
  const a = alias || "<alias>";
  const base = `${origin}/auth/realms/${r}`;
  if (protocol === "saml") {
    return [
      { label: "ACS URL (POST binding)", value: `${base}/broker/${a}/endpoint` },
      { label: "Audience / SP Entity ID", value: base },
    ];
  }
  return [
    { label: "Redirect URI (callback)", value: `${base}/broker/${a}/endpoint` },
    { label: "Audience / issuer to trust", value: base },
  ];
}

// Editor-side validity: what must be filled before Save makes sense.
export function idpIsValid(idp: SsoIdP): boolean {
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(idp.alias)) return false;
  if (!idp.display_name.trim()) return false;
  if (idp.protocol === "saml") return !!(idp.metadata_url?.trim() || idp.metadata_xml?.trim());
  return !!(idp.discovery_url?.trim() && idp.client_id?.trim());
}

// ---- tiny local field primitives (match admin.tsx LabeledInput styling) ----

const inputStyle: React.CSSProperties = { padding: 8, color: "var(--fg)", border: "1px solid var(--panel-border)", borderRadius: 6, background: "var(--bg)" };
const labelStyle: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 4, fontSize: "var(--fs-meta)", color: "var(--muted)" };

function Field({ label, value, onChange, type = "text", placeholder = "", hint, disabled = false }: {
  label: string; value: string; onChange: (v: string) => void; type?: string; placeholder?: string; hint?: string; disabled?: boolean;
}) {
  return (
    <label style={labelStyle}>
      {label}
      <input type={type} value={value} placeholder={placeholder} disabled={disabled} onChange={(e) => onChange(e.target.value)} style={inputStyle} />
      {hint && <span className="adm-line">{hint}</span>}
    </label>
  );
}

// Read a picked file as text into a callback (metadata XML / cert PEM uploads).
function FilePick({ label, onText }: { label: string; onText: (text: string) => void }) {
  return (
    <label style={{ ...labelStyle, flexDirection: "row", alignItems: "center", gap: 8 }}>
      {label}
      <input
        type="file"
        aria-label={label}
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          const r = new FileReader();
          r.onload = () => onText(String(r.result ?? ""));
          r.readAsText(f);
          e.target.value = ""; // allow re-picking the same file
        }}
      />
    </label>
  );
}

function CopyValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* ignore */ }
  };
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
      <span className="adm-line" style={{ minWidth: 180 }}>{label}</span>
      <code className="mono" style={{ userSelect: "all", fontSize: "var(--fs-meta)" }}>{value}</code>
      <button type="button" onClick={copy} aria-label={`Copy ${label}`}>{copied ? "Copied" : "Copy"}</button>
    </div>
  );
}

// ---- cert-expiry banner (§6: >30d none · ≤30d warn · ≤7d/expired crit) -----

export function CertExpiryBanner({ notAfter, now }: { notAfter: Date | null; now?: Date }) {
  if (!notAfter) return null;
  const e = certExpiry(notAfter, now);
  const date = notAfter.toISOString().slice(0, 10);
  if (e.level === "ok") {
    return <p className="adm-line">Signing certificate valid until {date}.</p>;
  }
  if (e.level === "warn") {
    return (
      <div className="banner warn" role="status">
        Signing certificate expires in {e.days} days (NotAfter {date}). Plan rotation.
      </div>
    );
  }
  return (
    <div className="banner crit" role="alert">
      {e.expired
        ? `Signing certificate EXPIRED (NotAfter ${date}) — SSO logins may fail. Rotate now.`
        : `Signing certificate expires in ${e.days} days (NotAfter ${date}) — SSO logins may fail. Rotate now.`}
    </div>
  );
}

// ---- user-attribute mapping table (IdP attribute → user attribute) ---------

export function AttrMappingTable({ rows, onChange }: {
  rows: SsoIdpAttrMapping[];
  onChange: (rows: SsoIdpAttrMapping[]) => void;
}) {
  const setRow = (i: number, patch: Partial<SsoIdpAttrMapping>) =>
    onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <table className="map-table">
      <thead>
        <tr><th>IdP attribute / claim</th><th>User attribute</th><th aria-label="actions" /></tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>
            <td><input aria-label={`IdP attribute ${i + 1}`} value={r.idp_attr} placeholder="mail" onChange={(e) => setRow(i, { idp_attr: e.target.value })} /></td>
            <td><input aria-label={`User attribute ${i + 1}`} value={r.user_attr} placeholder="email" onChange={(e) => setRow(i, { user_attr: e.target.value })} /></td>
            <td><button type="button" aria-label={`Remove attribute mapping ${i + 1}`} onClick={() => onChange(rows.filter((_, j) => j !== i))}>Remove</button></td>
          </tr>
        ))}
      </tbody>
      <tfoot>
        <tr>
          <td colSpan={3}>
            <button type="button" onClick={() => onChange([...rows, { idp_attr: "", user_attr: "" }])}>+ Add attribute</button>
          </td>
        </tr>
      </tfoot>
    </table>
  );
}

// ---- group → role mapping table (ordered; first match wins) ----------------

export function RoleMappingTable({ rows, roleIds, defaultRole, onChange }: {
  rows: SsoIdpRoleMapping[];
  roleIds: string[];
  defaultRole: string;
  onChange: (rows: SsoIdpRoleMapping[]) => void;
}) {
  const setRow = (i: number, patch: Partial<SsoIdpRoleMapping>) =>
    onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <>
      <p className="adm-line">Top to bottom — the <strong>first match wins</strong>.</p>
      <table className="map-table">
        <thead>
          <tr><th style={{ width: 64 }}>Order</th><th>Group / claim value</th><th style={{ width: 64 }}>Match</th><th>Correlix role</th><th aria-label="actions" /></tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              <td>
                <button type="button" aria-label={`Move mapping ${i + 1} up`} disabled={i === 0} onClick={() => onChange(moveRow(rows, i, -1))}>↑</button>
                <button type="button" aria-label={`Move mapping ${i + 1} down`} disabled={i === rows.length - 1} onClick={() => onChange(moveRow(rows, i, 1))}>↓</button>
              </td>
              <td><input aria-label={`Group or claim value ${i + 1}`} value={r.value} placeholder="cn=netops-admins,ou=groups,dc=corp" onChange={(e) => setRow(i, { value: e.target.value })} /></td>
              <td className="adm-line">exact</td>
              <td>
                <select aria-label={`Mapped role ${i + 1}`} value={r.role} onChange={(e) => setRow(i, { role: e.target.value })}>
                  {roleIds.map((id) => <option key={id} value={id}>{id}</option>)}
                </select>
              </td>
              <td><button type="button" aria-label={`Remove mapping ${i + 1}`} onClick={() => onChange(rows.filter((_, j) => j !== i))}>Remove</button></td>
            </tr>
          ))}
          {/* Pinned fallback row: what happens when NO row matches. Amber so the
              read-only-by-default landing is visible, not a surprise. */}
          <tr className="default-row" data-testid="default-role-row">
            <td aria-hidden="true">—</td>
            <td>* (anything else)</td>
            <td className="adm-line">default</td>
            <td><strong>{defaultRole || "(none)"}</strong></td>
            <td />
          </tr>
        </tbody>
        <tfoot>
          <tr>
            <td colSpan={5}>
              <button type="button" onClick={() => onChange([...rows, { value: "", role: roleIds[0] || "read-only" }])}>+ Add mapping</button>
            </td>
          </tr>
        </tfoot>
      </table>
      <p className="adm-line">
        No match means the default role <strong>{defaultRole || "(none)"}</strong>.
        <AskIris topic="sso.default-role" label="the default role" />
      </p>
    </>
  );
}

// ---- test-connection results (per-check ✓/✗) -------------------------------

function IdpTestChecks({ result }: { result: SsoIdpTestResult }) {
  return (
    <div role="status" style={{ marginTop: 8, padding: "8px 10px", borderRadius: 6, border: `1px solid ${result.ok ? "var(--good)" : "var(--bad)"}`, background: "var(--panel)" }}>
      <span className={`badge ${result.ok ? "good" : "bad"}`}>{result.ok ? "OK" : "FAIL"}</span>
      <ul style={{ listStyle: "none", padding: 0, margin: "6px 0 0" }}>
        {result.checks.map((c, i) => (
          <li key={i} className={`result ${c.ok ? "ok" : "err"}`}>
            {c.ok ? "✓" : "✗"} <strong>{c.name}</strong>{c.detail ? ` — ${c.detail}` : ""}
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---- per-IdP editor --------------------------------------------------------

function IdpEditor({ initial, isNew, realm, roleIds, defaultRole, onBack, onSaved }: {
  initial: SsoIdP;
  isNew: boolean;
  realm: string;
  roleIds: string[];
  defaultRole: string;
  onBack: () => void;
  onSaved: () => void;
}) {
  const [idp, setIdp] = useState<SsoIdP>(initial);
  const [secret, setSecret] = useState(""); // typed client secret (only sent if non-empty)
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [applied, setApplied] = useState(true);
  const [test, setTest] = useState<SsoIdpTestResult | null>(null);
  const set = (patch: Partial<SsoIdP>) => setIdp((cur) => ({ ...cur, ...patch }));

  // Cert NotAfter: prefer the server-verified one from the last test run, else
  // parse the pasted/uploaded PEM client-side so the banner is immediate.
  const notAfter = useMemo(() => {
    if (test?.cert_not_after) {
      const d = new Date(test.cert_not_after);
      if (!isNaN(d.getTime())) return d;
    }
    return idp.signing_cert_pem ? parseCertNotAfter(idp.signing_cert_pem) : null;
  }, [idp.signing_cert_pem, test?.cert_not_after]);

  const save = async () => {
    setBusy(true); setMsg(null); setWarnings([]);
    try {
      const body: SsoIdP = { ...idp };
      delete body.client_secret;
      if (secret) body.client_secret = secret; // write-only: blank keeps stored
      const r = await api.saveSsoIdp(body);
      setIdp(r.idp); setSecret("");
      setApplied(r.applied); setWarnings(r.warnings ?? []);
      setMsg(r.applied ? "Saved and applied to Keycloak." : null);
      onSaved();
    } catch (e) { setMsg((e as Error).message); } finally { setBusy(false); }
  };

  const runTest = async () => {
    setBusy(true); setTest(null); setMsg(null);
    try { setTest(await api.testSsoIdp(idp.alias)); }
    catch (e) { setTest({ ok: false, checks: [{ name: "request", ok: false, detail: (e as Error).message }] }); }
    finally { setBusy(false); }
  };

  const remove = async () => {
    if (!window.confirm(`Delete identity provider "${idp.alias}"? Users signing in through it will lose access.`)) return;
    setBusy(true); setMsg(null);
    try { await api.deleteSsoIdp(idp.alias); onSaved(); onBack(); }
    catch (e) { setMsg((e as Error).message); setBusy(false); }
  };

  const valid = idpIsValid(idp);
  return (
    <div className="auth-form adm">
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
        <button type="button" onClick={onBack}>← Providers</button>
        <strong>{isNew ? "New identity provider" : idp.alias}</strong>
        <span className={`badge ${idp.enabled ? "good" : "accent-badge"}`}>{idp.enabled ? "Enabled" : "Disabled"}</span>
        <label className="auth-enable"><input type="checkbox" checked={idp.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled</label>
      </div>

      {(!applied || warnings.length > 0) && (
        <div className="banner warn" role="alert">
          {!applied && <div><strong>Saved but NOT applied</strong> — Keycloak did not accept the change yet; it will be re-applied when reachable.</div>}
          {warnings.map((w, i) => <div key={i}>{w}</div>)}
        </div>
      )}

      <CertExpiryBanner notAfter={notAfter} />

      <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
        <Field label="Alias (URL-safe id)" value={idp.alias} onChange={(v) => set({ alias: v })} placeholder="okta" disabled={!isNew}
          hint={isNew ? "Lowercase letters, digits, - and _." : "Fixed after creation."} />
        <Field label="Display name" value={idp.display_name} onChange={(v) => set({ display_name: v })} placeholder="Okta" hint="Shown on the sign-in button." />
        <label style={labelStyle}>
          Protocol
          <select aria-label="Protocol" value={idp.protocol} disabled={!isNew} onChange={(e) => set({ protocol: e.target.value as "saml" | "oidc" })} style={inputStyle}>
            <option value="saml">SAML 2.0</option>
            <option value="oidc">OpenID Connect</option>
          </select>
        </label>
        <Field label="Groups attribute / claim" value={idp.groups_attr} onChange={(v) => set({ groups_attr: v })} placeholder="groups"
          hint="The attribute or claim carrying group membership." />
      </div>

      {idp.protocol === "saml" ? (
        <div style={{ marginTop: 12 }}>
          <h4 style={{ margin: "0 0 6px" }}>SAML settings</h4>
          <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
            <Field label="IdP metadata URL" value={idp.metadata_url ?? ""} onChange={(v) => set({ metadata_url: v })}
              placeholder="https://idp.example.com/app/metadata.xml" hint="Fetched and kept fresh." />
            <label style={labelStyle}>
              …or IdP metadata XML (paste or upload)
              <textarea aria-label="IdP metadata XML" rows={4} value={idp.metadata_xml ?? ""} onChange={(e) => set({ metadata_xml: e.target.value })}
                placeholder="<EntityDescriptor …>" style={{ ...inputStyle, fontFamily: "var(--mono, monospace)", fontSize: "var(--fs-meta)" }} />
              <FilePick label="Upload metadata file" onText={(t) => set({ metadata_xml: t })} />
            </label>
            <label style={labelStyle}>
              IdP signing certificate (PEM, optional)
              <textarea aria-label="IdP signing certificate PEM" rows={4} value={idp.signing_cert_pem ?? ""} onChange={(e) => set({ signing_cert_pem: e.target.value })}
                placeholder="-----BEGIN CERTIFICATE-----" style={{ ...inputStyle, fontFamily: "var(--mono, monospace)", fontSize: "var(--fs-meta)" }} />
              <FilePick label="Upload certificate file" onText={(t) => set({ signing_cert_pem: t })} />
              {idp.signing_cert_pem?.trim() && !notAfter && <span className="result err">✗ Could not parse a certificate from this PEM.</span>}
            </label>
          </div>
        </div>
      ) : (
        <div style={{ marginTop: 12 }}>
          <h4 style={{ margin: "0 0 6px" }}>OpenID Connect settings</h4>
          <div className="snmp-form" style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
            <Field label="Discovery URL" value={idp.discovery_url ?? ""} onChange={(v) => set({ discovery_url: v })}
              placeholder="https://idp.example.com/.well-known/openid-configuration" />
            <Field label="Client ID" value={idp.client_id ?? ""} onChange={(v) => set({ client_id: v })} placeholder="correlix" />
            <Field label="Client secret" type="password" value={secret} onChange={setSecret}
              placeholder={idp.client_secret_set ? "•••••• (unchanged)" : "(none / public client)"}
              hint="Write-only — leave blank to keep the stored secret." />
          </div>
        </div>
      )}

      <div style={{ marginTop: 12, padding: "8px 10px", border: "1px solid var(--panel-border)", borderRadius: 6 }}>
        <h4 style={{ margin: "0 0 6px" }}>Service-provider values</h4>
        <p className="adm-line">Register these with your IdP.</p>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {spValues(window.location.origin, realm, idp.alias, idp.protocol).map((v) => <CopyValue key={v.label} label={v.label} value={v.value} />)}
        </div>
      </div>

      <div style={{ marginTop: 12 }}>
        <h4 style={{ margin: "0 0 6px" }}>User attributes</h4>
        <p className="adm-line">
          What fills the profile on first login.
          <AskIris topic="sso.attribute-mapping" label="user attributes" />
        </p>
        <AttrMappingTable rows={idp.attr_mappings} onChange={(rows) => set({ attr_mappings: rows })} />
      </div>

      <div style={{ marginTop: 12 }}>
        <h4 style={{ margin: "0 0 6px" }}>Group → role mapping</h4>
        <RoleMappingTable rows={idp.role_mappings} roleIds={roleIds} defaultRole={defaultRole} onChange={(rows) => set({ role_mappings: rows })} />
      </div>

      <div className="admin-actions" style={{ marginTop: 12, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button type="button" disabled={busy || isNew} title={isNew ? "Save the provider first, then test it" : ""} onClick={runTest}>Test connection</button>
        <button type="button" className="dash-btn accent" disabled={busy || !valid} title={valid ? "" : "Alias, display name and the protocol's connection fields are required"} onClick={save}>Save</button>
        {!isNew && <button type="button" disabled={busy} onClick={remove}>Delete</button>}
        {msg && <span className="adm-line" role="status">{msg}</span>}
      </div>
      {test && <IdpTestChecks result={test} />}
    </div>
  );
}

// ---- panel: list + editor --------------------------------------------------

export function SsoIdpPanel({ roleIds, defaultRole }: { roleIds: string[]; defaultRole: string }) {
  const [idps, setIdps] = useState<SsoIdP[] | null>(null);
  const [kc, setKc] = useState<{ reachable: boolean; realm: string; detail?: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ idp: SsoIdP; isNew: boolean } | null>(null);

  const load = useCallback(() => {
    api.ssoIdps()
      .then((r) => { setIdps(r.idps); setKc(r.keycloak); setErr(null); })
      .catch((e) => setErr((e as Error).message));
  }, []);
  useEffect(load, [load]);

  if (err && idps === null) return <p className="adm-line" role="alert">{err}</p>;
  if (idps === null) return <p className="adm-line">Loading…</p>;

  if (editing) {
    return (
      <IdpEditor
        initial={editing.idp}
        isNew={editing.isNew}
        realm={kc?.realm ?? ""}
        roleIds={roleIds}
        defaultRole={defaultRole}
        onBack={() => setEditing(null)}
        onSaved={load}
      />
    );
  }

  return (
    <div className="auth-form adm">
      {kc && !kc.reachable && (
        <div className="banner warn" role="alert">
          Keycloak is unreachable{kc.detail ? ` — ${kc.detail}` : ""}. Changes are saved but will only be applied once it is back.
        </div>
      )}
      {kc?.reachable && <p className="adm-line">Brokered by Keycloak realm <code className="mono">{kc.realm}</code>.</p>}

      {idps.length === 0 ? (
        <p className="adm-line">
          No identity providers yet.
          <AskIris topic="sso.no-idps" label="no identity providers" />
        </p>
      ) : (
        <table className="map-table">
          <thead>
            <tr><th>Alias</th><th>Name</th><th>Protocol</th><th>Status</th><th aria-label="actions" /></tr>
          </thead>
          <tbody>
            {idps.map((p) => (
              <tr key={p.alias}>
                <td className="mono">{p.alias}</td>
                <td>{p.display_name}</td>
                <td>{p.protocol === "saml" ? "SAML 2.0" : "OIDC"}</td>
                <td><span className={`badge ${p.enabled ? "good" : "accent-badge"}`}>{p.enabled ? "Enabled" : "Disabled"}</span></td>
                <td><button type="button" onClick={() => setEditing({ idp: p, isNew: false })}>Edit</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
        <button type="button" onClick={() => setEditing({ idp: blankIdp("saml"), isNew: true })}>+ Add SAML provider</button>
        <button type="button" onClick={() => setEditing({ idp: blankIdp("oidc"), isNew: true })}>+ Add OIDC provider</button>
      </div>
    </div>
  );
}
