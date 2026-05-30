// SNMP Credentials — manage v1/v2c community strings and full SNMPv3 USM
// profiles, assignable to devices via their credential_ref. Secrets are
// write-only (sent on save, never returned). Backed by /api/snmp/credentials.

import { useEffect, useState } from "react";
import { api, SNMPCredential, SNMPOptions } from "../services/api";

const BLANK: SNMPCredential = {
  name: "", version: "v2c", port: 161, timeout_ms: 2000, retries: 1,
  community: "", security_name: "", security_level: "authPriv",
  auth_protocol: "SHA", auth_key: "", priv_protocol: "AES128", priv_key: "", context: "",
};

export default function SnmpCredentials() {
  const [creds, setCreds] = useState<SNMPCredential[]>([]);
  const [opts, setOpts] = useState<SNMPOptions | null>(null);
  const [form, setForm] = useState<SNMPCredential | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const reload = () => api.listSnmpCreds().then(setCreds).catch((e) => setErr((e as Error).message));
  useEffect(() => {
    reload();
    api.snmpOptions().then(setOpts).catch(() => {});
  }, []);

  const edit = (c: SNMPCredential) =>
    setForm({ ...BLANK, ...c, community: "", auth_key: "", priv_key: "" }); // never prefill secrets
  const save = async () => {
    if (!form) return;
    setErr(null);
    try {
      await api.saveSnmpCred(form);
      setForm(null);
      reload();
    } catch (e) { setErr((e as Error).message); }
  };
  const remove = async (c: SNMPCredential) => {
    setErr(null);
    try { await api.deleteSnmpCred(c.id!); reload(); } catch (e) { setErr((e as Error).message); }
  };

  const set = (patch: Partial<SNMPCredential>) => setForm((f) => (f ? { ...f, ...patch } : f));
  const isV3 = form?.version === "v3";
  const lvl = (form?.security_level || "").toLowerCase();
  const needsAuth = isV3 && (lvl === "authnopriv" || lvl === "authpriv");
  const needsPriv = isV3 && lvl === "authpriv";

  return (
    <>
      <div className="admin-head">
        <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>SNMP Credentials</h2>
        <p className="admin-sub">
          Community strings (v1/v2c) and SNMPv3 USM profiles. Assign a profile to a device via its
          <code> credential_ref</code>; the poller uses it instead of the global default. Different device
          groups can use different communities.
        </p>
      </div>

      <div className="card">
        <div className="admin-card-head">
          <h2>Profiles</h2>
          <button className="dash-btn accent" onClick={() => setForm({ ...BLANK })}>+ New profile</button>
        </div>
        {err && <p style={{ color: "var(--bad)", fontSize: "var(--fs-meta)" }}>{err}</p>}
        <table>
          <thead>
            <tr><th>Name</th><th>Version</th><th>Port</th><th>Auth</th><th>Privacy</th><th>Secrets</th><th></th></tr>
          </thead>
          <tbody>
            {creds.map((c) => (
              <tr key={c.id}>
                <td style={{ fontWeight: 600 }}>{c.name}</td>
                <td><span className="badge">{c.version}</span></td>
                <td>{c.port}</td>
                <td>{c.version === "v3" ? `${c.security_level}${c.auth_protocol ? " · " + c.auth_protocol : ""}` : "—"}</td>
                <td>{c.version === "v3" ? (c.priv_protocol || "—") : "—"}</td>
                <td className="mini-meta">
                  {c.has_community ? "community ✓ " : ""}
                  {c.has_auth_key ? "auth ✓ " : ""}
                  {c.has_priv_key ? "priv ✓" : ""}
                </td>
                <td>
                  <button className="dash-btn" onClick={() => edit(c)}>Edit</button>{" "}
                  <button className="dash-btn" onClick={() => remove(c)}>Delete</button>
                </td>
              </tr>
            ))}
            {creds.length === 0 && <tr><td colSpan={7} className="panel-empty">No SNMP profiles yet — devices fall back to the global SNMP_COMMUNITY.</td></tr>}
          </tbody>
        </table>
      </div>

      {form && (
        <div className="card">
          <div className="admin-card-head"><h2>{form.id ? "Edit" : "New"} SNMP profile</h2></div>
          <div className="snmp-form">
            <label>Name<input value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. Core Switches" /></label>
            <label>Version
              <select value={form.version} onChange={(e) => set({ version: e.target.value })}>
                {(opts?.versions ?? ["v1", "v2c", "v3"]).map((v) => <option key={v} value={v}>{v}</option>)}
              </select>
            </label>
            <label>Port<input type="number" value={form.port} onChange={(e) => set({ port: Number(e.target.value) })} /></label>
            <label>Timeout (ms)<input type="number" value={form.timeout_ms} onChange={(e) => set({ timeout_ms: Number(e.target.value) })} /></label>
            <label>Retries<input type="number" value={form.retries} onChange={(e) => set({ retries: Number(e.target.value) })} /></label>

            {!isV3 && (
              <label className="snmp-wide">Community string
                <input type="password" value={form.community} onChange={(e) => set({ community: e.target.value })}
                  placeholder={form.has_community ? "•••••• (unchanged)" : "community"} />
              </label>
            )}

            {isV3 && (
              <>
                <label>Security name<input value={form.security_name} onChange={(e) => set({ security_name: e.target.value })} placeholder="USM user" /></label>
                <label>Security level
                  <select value={form.security_level} onChange={(e) => set({ security_level: e.target.value })}>
                    {(opts?.security_levels ?? ["noAuthNoPriv", "authNoPriv", "authPriv"]).map((v) => <option key={v} value={v}>{v}</option>)}
                  </select>
                </label>
                <label>Context<input value={form.context} onChange={(e) => set({ context: e.target.value })} placeholder="(optional)" /></label>
                {needsAuth && (
                  <>
                    <label>Auth protocol
                      <select value={form.auth_protocol} onChange={(e) => set({ auth_protocol: e.target.value })}>
                        {(opts?.auth_protocols ?? ["MD5", "SHA", "SHA256"]).map((v) => <option key={v} value={v}>{v}</option>)}
                      </select>
                    </label>
                    <label>Auth key<input type="password" value={form.auth_key} onChange={(e) => set({ auth_key: e.target.value })}
                      placeholder={form.has_auth_key ? "•••••• (unchanged)" : "auth passphrase"} /></label>
                  </>
                )}
                {needsPriv && (
                  <>
                    <label>Privacy protocol
                      <select value={form.priv_protocol} onChange={(e) => set({ priv_protocol: e.target.value })}>
                        {(opts?.priv_protocols ?? ["DES", "AES128", "AES256"]).map((v) => <option key={v} value={v}>{v}</option>)}
                      </select>
                    </label>
                    <label>Privacy key<input type="password" value={form.priv_key} onChange={(e) => set({ priv_key: e.target.value })}
                      placeholder={form.has_priv_key ? "•••••• (unchanged)" : "privacy passphrase"} /></label>
                  </>
                )}
              </>
            )}
          </div>
          <div style={{ marginTop: "var(--sp-3)", display: "flex", gap: "var(--sp-2)" }}>
            <button className="dash-btn accent" onClick={save}>Save profile</button>
            <button className="dash-btn" onClick={() => setForm(null)}>Cancel</button>
          </div>
        </div>
      )}
    </>
  );
}
