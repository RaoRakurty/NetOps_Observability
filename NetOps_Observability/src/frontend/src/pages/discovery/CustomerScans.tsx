// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// CustomerScans — Network Scan → "Scans for a customer" (2026-11-10).
//
// The platform administrator points a scan at a customer's network ON THAT
// CUSTOMER'S BEHALF, with the customer's own SNMP profiles. Every device the
// scan finds belongs to the customer (the scan is the channel; nothing a device
// answers decides whose it is). Owner decisions: only the platform administrator
// creates, changes or removes a customer's scan (D1); a customer's scan uses only
// that customer's SNMP profiles (D2).
//
// Two audiences, one component:
//   - platform administrator: every customer's scan, plus the numbered workflow
//     to add one (1 customer · 2 SNMP profiles · 3 addresses · 4 turn on);
//   - a customer: "Your scans", read-only — the same results, no controls.
// The server is the boundary (requirePlatformAdmin on writes, tenant-filtered
// reads); this only avoids offering a control that can only fail.

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  DiscoveryScope,
  DiscoveryScopeInput,
  DiscoveryScopesEnvelope,
  SNMPCredential,
  Tenant,
} from "../../services/api";
import { httpFailure, operatorError } from "../../lib/errors";
import { scopeCount } from "../SubnetDiscoveryCard";

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

function lastScan(iso?: string): string {
  if (!iso) return "not yet";
  const t = new Date(iso).getTime();
  if (!isFinite(t) || t < 86_400_000) return "not yet";
  const age = Date.now() - t;
  if (age < 60_000) return "just now";
  if (age < 3_600_000) return `${Math.round(age / 60_000)} min ago`;
  if (age < 86_400_000) return `${Math.round(age / 3_600_000)} h ago`;
  return new Date(iso).toLocaleString();
}

function stateOf(s: DiscoveryScope): { cls: string; label: string } {
  if (!s.enabled) return { cls: "off", label: "Off" };
  if (s.status?.last_error) return { cls: "warn", label: "Needs attention" };
  return { cls: "on", label: "On" };
}

/** Is this tenant the platform itself (never a customer)? */
function isPlatformTenant(t: Tenant): boolean {
  const id = (t.id || "").toLowerCase();
  return id === "" || id === "global";
}

type Draft = {
  id?: string; // set when editing
  tenantId: string;
  name: string;
  ranges: string;
  allowNonPrivate: boolean;
  profiles: string[];
  enabled: boolean;
};

const emptyDraft: Draft = { tenantId: "", name: "", ranges: "", allowNonPrivate: false, profiles: [], enabled: true };

function draftOf(s: DiscoveryScope): Draft {
  return {
    id: s.id, tenantId: s.tenant_id, name: s.name, ranges: s.ranges.join(", "),
    allowNonPrivate: s.allow_non_private, profiles: [...s.credential_refs], enabled: s.enabled,
  };
}

function inputOf(d: Draft, withTenant: boolean): DiscoveryScopeInput {
  const body: DiscoveryScopeInput = {
    name: d.name.trim(),
    ranges: d.ranges.split(",").map((r) => r.trim()).filter(Boolean),
    allow_non_private: d.allowNonPrivate,
    credential_refs: d.profiles,
    enabled: d.enabled,
  };
  if (withTenant) body.tenant_id = d.tenantId;
  return body;
}

export default function CustomerScans({ platformAdmin }: { platformAdmin: boolean }) {
  const [env, setEnv] = useState<DiscoveryScopesEnvelope | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [denied, setDenied] = useState(false);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [profiles, setProfiles] = useState<SNMPCredential[]>([]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const load = useCallback(async () => {
    try {
      setEnv(await api.discoveryScopes());
      setLoadErr(null);
      setDenied(false);
    } catch (e) {
      const status = httpFailure(e)?.status;
      if (status === 401 || status === 403) setDenied(true);
      else setLoadErr(operatorError(e, "The customer scans could not be loaded."));
    }
  }, []);

  useEffect(() => {
    load();
    // Names for the profile column (best effort for everyone), and the
    // customer list + every profile for the platform administrator's form.
    api.listSnmpCreds().then((l) => setProfiles(l ?? [])).catch(() => setProfiles([]));
    if (platformAdmin) {
      api.listTenants().then((l) => setTenants((l ?? []).filter((t) => !isPlatformTenant(t)))).catch(() => setTenants([]));
    }
  }, [load, platformAdmin]);

  const profileName = useMemo(() => {
    const m: Record<string, string> = {};
    for (const p of profiles) if (p.id) m[p.id] = p.name;
    return m;
  }, [profiles]);

  if (denied) return null;

  const scopes = env?.scopes ?? [];
  const maxHosts = env?.limits?.max_hosts ?? 4096;

  const startNew = () => {
    setMsg(null);
    setDraft({ ...emptyDraft, tenantId: tenants.length === 1 ? tenants[0].id : "" });
  };

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    setMsg(null);
    try {
      if (draft.id) {
        await api.updateDiscoveryScope(draft.id, inputOf(draft, false));
        setMsg({ kind: "ok", text: "Saved." + (draft.enabled ? " A scan has been scheduled." : " This scan is off.") });
      } else {
        await api.createDiscoveryScope(inputOf(draft, true));
        setMsg({ kind: "ok", text: draft.enabled ? "Scan added. It runs within a few minutes." : "Scan added. It is off until you turn it on." });
      }
      setDraft(null);
      await load();
    } catch (e) {
      setMsg({ kind: "err", text: operatorError(e, "The scan could not be saved.") });
    } finally {
      setSaving(false);
    }
  };

  const remove = async (s: DiscoveryScope) => {
    const who = s.tenant_name || s.tenant_id;
    if (!window.confirm(`Remove the scan "${s.name}" for ${who}? Its devices leave ${who}'s device list until a scan finds them again.`)) return;
    setMsg(null);
    try {
      await api.deleteDiscoveryScope(s.id);
      setMsg({ kind: "ok", text: `Scan "${s.name}" removed.` });
      await load();
    } catch (e) {
      setMsg({ kind: "err", text: operatorError(e, "The scan could not be removed.") });
    }
  };

  return (
    <div className="card disc-card cust-scans" style={{ marginBottom: 16 }}>
      <div className="disc-head">
        <div>
          <h2 className="disc-title">{platformAdmin ? "Scans for a customer" : "Your scans"}</h2>
          <p className="disc-desc">
            {platformAdmin
              ? "Scan a customer's network with the customer's own SNMP profiles. Every device found belongs to that customer."
              : "Scans your platform operator runs on your network, with your SNMP profiles. The devices they find are yours."}
          </p>
        </div>
        {platformAdmin && !draft && (
          <div className="disc-actions">
            <button className="btn primary" onClick={startNew}>New scan for a customer</button>
          </div>
        )}
      </div>

      {loadErr && (
        <div className="disc-refusal" role="alert">
          <b>Could not load</b>
          <span>{loadErr}</span>
        </div>
      )}
      {env?.scanner_view_stale && platformAdmin && (
        <div className="disc-refusal" role="alert">
          <b>Not up to date</b>
          <span>The scanner could not reload the saved scans. The last good set is still running and is retried every minute.</span>
        </div>
      )}
      {msg && <p className={`disc-msg ${msg.kind}`} role={msg.kind === "err" ? "alert" : "status"}>{msg.text}</p>}

      {platformAdmin && draft && (
        <ScanForm
          draft={draft}
          setDraft={setDraft}
          tenants={tenants}
          profiles={profiles}
          maxHosts={maxHosts}
          saving={saving}
          onSave={save}
          onCancel={() => setDraft(null)}
        />
      )}

      {env && scopes.length === 0 && (
        <div className="empty">
          {platformAdmin ? "No customer has its own scan yet." : "Your platform operator has not set up a scan for you."}
        </div>
      )}

      {scopes.map((s) => {
        const st = stateOf(s);
        const dupes = s.found.filter((f) => f.also_found_by_platform).length;
        return (
          <section key={s.id} className="cust-scan" aria-label={`Scan ${s.name}`}>
            <div className="disc-title-row">
              <h3 className="disc-step-title">
                {platformAdmin && <span className="cust-scan-tenant">{s.tenant_name || s.tenant_id} · </span>}
                {s.name}
              </h3>
              <span className={`disc-state ${st.cls}`}>
                <span className="disc-dot" aria-hidden />
                {st.label}
              </span>
              {platformAdmin && (
                <span className="cust-scan-actions">
                  <button className="btn" onClick={() => { setMsg(null); setDraft(draftOf(s)); }} aria-label={`Change scan ${s.name}`}>Change</button>
                  <button className="btn danger" onClick={() => remove(s)} aria-label={`Remove scan ${s.name}`}>Remove</button>
                </span>
              )}
            </div>
            <p className="disc-text">
              <span className="mono">{s.ranges.join(", ")}</span>
              {" · "}
              {s.credential_refs.length === 0
                ? "all of the customer's SNMP profiles"
                : s.credential_refs.map((r) => profileName[r] ?? r).join(", ")}
              {" · last scan "}
              {lastScan(s.status?.last_sweep)}
              {" · "}
              {s.found_total} {plural(s.found_total, "device", "devices")} found
            </p>
            {s.status?.last_error && (
              <div className="disc-refusal" role="alert">
                <b>Last scan stopped</b>
                <span>{s.status.last_error}</span>
              </div>
            )}
            {dupes > 0 && (
              <div className="disc-refusal cust-scan-dupes" role="note">
                <b>Also found by the platform scan</b>
                <span>
                  {dupes} {plural(dupes, "device is", "devices are")} also in the platform's own list. Telemetry from
                  {plural(dupes, " it", " them")} is not attributed to anyone until one copy is removed.
                </span>
              </div>
            )}
            {s.found.length > 0 && (
              <table aria-label={`Devices found by ${s.name}`}>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Address</th>
                    <th>Vendor</th>
                    <th>Answered with</th>
                    <th>Note</th>
                  </tr>
                </thead>
                <tbody>
                  {s.found.map((d) => (
                    <tr key={d.id} className="dt-row">
                      <td>{d.name || d.id}</td>
                      <td className="mono">{d.address}</td>
                      <td>{d.vendor || "—"}</td>
                      <td>{d.credential_ref ? profileName[d.credential_ref] ?? d.credential_ref : "—"}</td>
                      <td>
                        {d.also_found_by_platform && <span className="cust-flag">Also found by the platform scan</span>}
                        {!!d.also_found_by_other_customers && (
                          <span className="cust-flag">
                            Also found for {d.also_found_by_other_customers} other {plural(d.also_found_by_other_customers, "customer", "customers")}
                          </span>
                        )}
                        {d.stale && <span className="cust-flag">Not answering</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        );
      })}
    </div>
  );
}

function ScanForm(props: {
  draft: Draft;
  setDraft: (d: Draft) => void;
  tenants: Tenant[];
  profiles: SNMPCredential[];
  maxHosts: number;
  saving: boolean;
  onSave: () => void;
  onCancel: () => void;
}) {
  const { draft, setDraft, tenants, profiles, maxHosts, saving, onSave, onCancel } = props;
  const editing = !!draft.id;
  const own = profiles.filter((p) => p.id && (p.tenant_id || "").toLowerCase() === draft.tenantId.toLowerCase() && draft.tenantId !== "");
  const range = scopeCount(draft.ranges);
  const over = range.total > maxHosts;
  const set = (patch: Partial<Draft>) => setDraft({ ...draft, ...patch });
  const toggleProfile = (id: string) =>
    set({ profiles: draft.profiles.includes(id) ? draft.profiles.filter((p) => p !== id) : [...draft.profiles, id] });
  const customer = tenants.find((t) => t.id === draft.tenantId);
  const ready = draft.tenantId !== "" && draft.name.trim() !== "" && range.total > 0 && !range.invalid && !over;

  return (
    <ol className="disc-steps" aria-label={editing ? "Change the scan" : "Set up a scan for a customer"}>
      <li className="disc-step">
        <span className="disc-step-num" aria-hidden>1</span>
        <div className="disc-step-body">
          <h3 className="disc-step-title">Choose the customer</h3>
          {editing ? (
            <p className="disc-text">{customer?.name ?? draft.tenantId} (a scan's customer cannot be changed)</p>
          ) : (
            <label className="disc-field">
              <span>Customer</span>
              <select value={draft.tenantId} onChange={(e) => set({ tenantId: e.target.value, profiles: [] })}>
                <option value="">Choose a customer…</option>
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </select>
            </label>
          )}
          <label className="disc-field">
            <span>Name of this scan</span>
            <input value={draft.name} onChange={(e) => set({ name: e.target.value })} placeholder="Branch edges" maxLength={80} />
          </label>
        </div>
      </li>

      <li className="disc-step">
        <span className="disc-step-num" aria-hidden>2</span>
        <div className="disc-step-body">
          <h3 className="disc-step-title">SNMP profiles</h3>
          {draft.tenantId === "" ? (
            <p className="disc-text">Choose the customer first.</p>
          ) : own.length === 0 ? (
            <div className="disc-refusal" role="alert">
              <b>No SNMP profiles</b>
              <span>This customer has no SNMP profile yet. Nothing can be found until you add one for them.</span>
            </div>
          ) : (
            <>
              <p className="disc-text">Leave all unticked to try every profile this customer has, in name order.</p>
              <div className="cust-profiles" role="group" aria-label="The customer's SNMP profiles">
                {own.map((p) => (
                  <label key={p.id} className="cust-check">
                    <input type="checkbox" checked={draft.profiles.includes(p.id!)} onChange={() => toggleProfile(p.id!)} />
                    <span>{p.name} <span className="cust-muted">({p.version})</span></span>
                  </label>
                ))}
              </div>
            </>
          )}
          <a className="disc-link" href="#/admin/discovery/snmp">Open SNMP Profiles</a>
        </div>
      </li>

      <li className="disc-step">
        <span className="disc-step-num" aria-hidden>3</span>
        <div className="disc-step-body">
          <h3 className="disc-step-title">Choose the addresses</h3>
          <label className="disc-field">
            <span>Addresses to scan, comma-separated</span>
            <input
              className="mono"
              value={draft.ranges}
              onChange={(e) => set({ ranges: e.target.value })}
              placeholder="10.70.0.81/32, 10.70.1.0/28"
              spellCheck={false}
            />
          </label>
          <div className={`disc-meter${over ? " over" : ""}`}>
            <div className="disc-meter-track">
              <div className="disc-meter-fill" style={{ width: `${Math.min(100, (range.total / maxHosts) * 100)}%` }} />
            </div>
            <span className="disc-meter-read">
              {range.invalid
                ? `"${range.invalid}" is not a range like 10.0.0.0/24`
                : `${range.total.toLocaleString()} / ${maxHosts.toLocaleString()} addresses`}
            </span>
          </div>
          <p className="disc-text cust-muted">All scans share one limit of {maxHosts.toLocaleString()} addresses per sweep. The platform's own scan counts first.</p>
          <div className="disc-switches">
            <label className="uf-switch">
              <input type="checkbox" checked={draft.allowNonPrivate} onChange={(e) => set({ allowNonPrivate: e.target.checked })} />
              <span className="uf-switch-track" aria-hidden />
              <span>Allow public address ranges</span>
            </label>
          </div>
        </div>
      </li>

      <li className="disc-step">
        <span className="disc-step-num" aria-hidden>4</span>
        <div className="disc-step-body">
          <h3 className="disc-step-title">Turn it on</h3>
          <div className="disc-switches">
            <label className="uf-switch">
              <input type="checkbox" checked={draft.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
              <span className="uf-switch-track" aria-hidden />
              <span>Scanning on</span>
            </label>
            <button className="btn primary" onClick={onSave} disabled={saving || !ready}>
              {saving ? "Saving…" : editing ? "Save" : "Add scan"}
            </button>
            <button className="btn" onClick={onCancel} disabled={saving}>Cancel</button>
          </div>
        </div>
      </li>
    </ol>
  );
}
