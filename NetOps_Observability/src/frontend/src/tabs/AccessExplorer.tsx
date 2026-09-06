// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { fmtDateTime } from "../lib/time";
import { useState } from "react";
import { api, AccessExplanation } from "../services/api";
import { StatStrip, Stat, Skeleton } from "../components/ui";
import Icon from "../components/Icon";
import AskIris from "../components/AskIris";

// AccessExplorer — the L3 "Explain" view. Type a person (or service/agent) and
// see exactly what they can reach and WHY: every tenant they can act in, traced
// back to the binding that grants it. Deny and break-glass are surfaced. This is
// the decider made transparent — the answer to "why does X have this access?".
export default function AccessExplorer() {
  const [who, setWho] = useState("");
  const [exp, setExp] = useState<AccessExplanation | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (principal?: string) => {
    setErr(null); setBusy(true);
    try { setExp(await api.explainAccess(principal)); }
    catch (e) { setErr((e as Error).message.replace(/^\d+[^:]*:\s*/, "")); }
    finally { setBusy(false); }
  };

  const reaches = exp?.reaches ?? [];
  const bindings = exp?.bindings ?? [];

  return (
    <>
      <div className="admin-head">
        <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>Access Explorer</h2>
        <p className="admin-sub">
          What this account reaches, and the grant behind it.
          <AskIris topic="access.explorer" label="Access Explorer" />
        </p>
      </div>

      <div className="card">
        <div className="admin-form">
          <label className="req-field" style={{ flex: 2 }}>
            <span>Person or service</span>
            <input
              placeholder="Username — leave blank for yourself"
              value={who}
              onChange={(e) => setWho(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") run(who.trim() || undefined); }}
            />
          </label>
          <button className="dash-btn accent" disabled={busy} onClick={() => run(who.trim() || undefined)}>
            {busy ? "Resolving…" : "Explain access"}
          </button>
        </div>
        {err && <p style={{ color: "var(--bad)", fontSize: 12.5 }}>{err}</p>}
      </div>

      {exp && (
        <>
          <StatStrip>
            <Stat label="Account" value={exp.principal || "—"} />
            <Stat label="Tenants reached" value={exp.all_tenants ? "All" : reaches.length} tone="accent" />
            <Stat label="Bindings" value={busy ? <Skeleton w={20} h={20} /> : bindings.length} />
            <Stat label="Org admin of" value={(exp.org_admin_of ?? []).length || "—"} />
          </StatStrip>

          {exp.all_tenants && (
            <div className="card" style={{ borderColor: "var(--accent)" }}>
              <b>Platform operator</b> — this account reaches <b>every tenant</b> (platform scope). Cross-tenant telemetry for compliance-restricted tenants still requires a break-glass session.
            </div>
          )}

          <div className="card" style={{ paddingTop: 8 }}>
            <div className="admin-card-head"><h2>Reaches</h2></div>
            {reaches.length === 0 && !exp.all_tenants ? (
              <div className="empty">This account can't reach any tenant.</div>
            ) : (
              <table className="ds-table" style={{ width: "100%" }}>
                <thead>
                  <tr>
                    <th>Tenant</th>
                    <th style={{ width: 160 }}>Organization</th>
                    <th>Why (granting binding)</th>
                  </tr>
                </thead>
                <tbody>
                  {reaches.map((r) => (
                    <tr key={r.tenant_id}>
                      <td style={{ fontWeight: 600 }}>{r.tenant_name}</td>
                      <td style={{ color: "var(--muted)", fontSize: 12.5 }}>{r.org_name}</td>
                      <td>
                        {r.granted_by.map((g, i) => (
                          <span key={i} className="badge" style={{ marginRight: 6, color: g.effect === "deny" ? "var(--bad)" : undefined }}
                            title={g.reason || g.granted_by || ""}>
                            {g.break_glass ? "🔓 " : ""}{g.role_id} @ {g.scope_id}{g.effect === "deny" ? " (deny)" : ""}
                            {g.expires_at ? " ⏱" : ""}
                          </span>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="card" style={{ paddingTop: 8 }}>
            <div className="admin-card-head">
              <h2>All bindings</h2>
              <AskIris topic="access.bindings" label="All bindings" />
            </div>
            {bindings.length === 0 ? (
              <div className="empty">No bindings.</div>
            ) : (
              <table className="ds-table" style={{ width: "100%" }}>
                <thead>
                  <tr>
                    <th style={{ width: 130 }}>Role</th>
                    <th>Scope</th>
                    <th style={{ width: 80 }}>Effect</th>
                    <th>Granted by</th>
                    <th>Note</th>
                  </tr>
                </thead>
                <tbody>
                  {bindings.map((b) => (
                    <tr key={b.id}>
                      <td><span className="badge">{b.role_id}</span></td>
                      <td style={{ color: "var(--muted)", fontSize: 12.5 }}>{b.scope_id}</td>
                      <td>{b.effect === "deny" ? <span style={{ color: "var(--bad)" }}>Deny</span> : "Allow"}</td>
                      <td style={{ color: "var(--muted)", fontSize: 12.5 }}>{b.granted_by || "—"}</td>
                      <td style={{ color: "var(--muted)", fontSize: 12.5 }}>
                        {b.expires_at ? <span><Icon name="alerts" size={11} /> expires {fmtDateTime(b.expires_at)}</span> : (b.reason || "—")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </>
  );
}
