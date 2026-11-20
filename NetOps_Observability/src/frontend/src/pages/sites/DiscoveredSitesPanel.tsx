// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DiscoveredSitesPanel — Infrastructure → Sites → Manage Sites → "Adopt
// discovered sites". The Topology groups devices by the site id their
// controller (e.g. vManage) or the device itself reports when no operator has
// placed them; those groups are DISCOVERED, not declared. Adopting turns the
// selected ones into real sites (named "Site 50", or the controller's own site
// name) and places their devices on them, so they can be renamed and given
// coordinates like any other site.
//
// Preview FIRST (GET /api/discovered-sites — writes nothing), then one explicit
// Adopt (POST …/adopt, dry_run:false) for the ticked sites. A device that is
// already placed (by an operator or a site label) is listed and never moved.

import { useEffect, useMemo, useState } from "react";
import { api, AdoptPlan, AdoptSiteRow } from "../../services/api";
import { operatorError } from "../../lib/errors";
import AskIris from "../../components/AskIris";

/** How a site's origin reads ("vmanage" → "vManage"). */
export function originName(origin: string): string {
  switch (origin) {
    case "device": return "the device";
    case "sdwan_peers": return "SD-WAN peers";
    case "vmanage": return "vManage";
    case "catalyst_center": return "Catalyst Center";
    case "catalyst_9800": return "Catalyst 9800";
    case "meraki": return "Meraki";
    case "versa": return "Versa";
    case "": case "controller": return "a controller";
    default: return origin;
  }
}

/** One plain sentence for a plan's (or a result's) counts. */
export function planSentence(p: AdoptPlan, applied: boolean): string {
  const s = p.summary ?? {};
  const created = s.create ?? 0, reused = s.reuse ?? 0, bound = s.bind ?? 0, skipped = s.skip ?? 0;
  const parts: string[] = [];
  parts.push(`${applied ? "Created" : "Creates"} ${created} site${created === 1 ? "" : "s"}`);
  if (reused) parts.push(`${applied ? "used" : "uses"} ${reused} existing`);
  parts.push(`${applied ? "placed" : "places"} ${bound} device${bound === 1 ? "" : "s"}`);
  if (skipped) parts.push(`${applied ? "left" : "leaves"} ${skipped} already placed alone`);
  const bad = (s.refused ?? 0) + (s.error ?? 0);
  if (bad) parts.push(`${bad} could not be done`);
  return parts.join(", ") + ".";
}

const TONE: Record<string, string> = {
  create: "var(--good, #16a34a)", reuse: "var(--accent, #2563eb)", bind: "var(--good, #16a34a)",
  skip: "var(--muted)", refused: "var(--bad, #dc2626)", error: "var(--bad, #dc2626)",
};
const ACTION_TEXT: Record<string, string> = {
  create: "new site", reuse: "existing site", bind: "will be placed", skip: "left alone",
  refused: "refused", error: "failed",
};

export default function DiscoveredSitesPanel({ onDone }: { onDone: () => void }) {
  const [plan, setPlan] = useState<AdoptPlan | null>(null);
  const [reason, setReason] = useState<string | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [result, setResult] = useState<AdoptPlan | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    try {
      const r = await api.discoveredSites();
      setPlan(r.plan);
      setReason(r.adoptable ? null : r.reason ?? "Adoption is not available in this view.");
      setPicked(new Set(r.plan.sites.map((s) => s.key)));
      setErr(null);
    } catch (e) {
      setErr(operatorError(e, "The discovered sites could not be read."));
    }
  };
  useEffect(() => { load(); }, []);

  const chosen = useMemo(() => (plan?.sites ?? []).filter((s) => picked.has(s.key)), [plan, picked]);

  const toggle = (key: string) => {
    const next = new Set(picked);
    if (next.has(key)) next.delete(key); else next.add(key);
    setPicked(next);
  };

  const adopt = async () => {
    if (chosen.length === 0) return;
    setBusy(true);
    try {
      const r = await api.adoptDiscoveredSites({ dry_run: false, keys: chosen.map((s) => s.key) });
      setResult(r.plan);
      setErr(null);
      onDone();
      await load();
    } catch (e) {
      setErr(operatorError(e, "The sites could not be adopted."));
    } finally {
      setBusy(false);
    }
  };

  const binds = (s: AdoptSiteRow) => s.devices.filter((d) => d.action === "bind").length;

  return (
    <section className="card" aria-label="Adopt discovered sites" style={{ marginBottom: 14, fontSize: 14 }}>
      <h3 style={{ margin: "0 0 6px" }}>Adopt discovered sites</h3>
      <p className="mini-meta" style={{ fontSize: 14 }}>
        Sites reported by a controller or device. Adopt them to rename.
        <AskIris topic="sites.discovered" label="Discovered sites" />
      </p>
      {err && <p role="alert" style={{ color: "var(--bad)" }}>{err}</p>}
      {reason && <p role="status">{reason}</p>}
      {result && <p role="status" style={{ color: "var(--good, #16a34a)" }}>{planSentence(result, true)} You can rename the new sites below.</p>}
      {plan && !reason && plan.sites.length === 0 && (
        <p role="status">No discovered sites are waiting: every device that reports a site id is already placed.</p>
      )}
      {plan && !reason && plan.sites.length > 0 && (
        <>
          <p style={{ fontSize: 14, margin: "8px 0" }}><b>Step 1.</b> Review what will happen and untick any site you do not want.</p>
          <table className="loc-editor" style={{ fontSize: 14 }}>
            <thead>
              <tr><th aria-label="Adopt" /><th>Discovered site</th><th>New site</th><th>Devices</th></tr>
            </thead>
            <tbody>
              {plan.sites.map((s) => (
                <tr key={s.key}>
                  <td>
                    <input type="checkbox" aria-label={`Adopt ${s.label}`} checked={picked.has(s.key)} onChange={() => toggle(s.key)} />
                  </td>
                  <td>
                    <b>{s.label}</b>
                    <div className="mini-meta" style={{ fontSize: 14 }}>site id {s.site_id}, reported by {originName(s.origin)}</div>
                  </td>
                  <td>
                    {s.name} <span className="mono mini-meta">({s.slug})</span>{" "}
                    <span style={{ color: TONE[s.action] }}>· {ACTION_TEXT[s.action] ?? s.action}</span>
                  </td>
                  <td>
                    <ul style={{ margin: 0, paddingLeft: 18 }}>
                      {s.devices.map((d) => (
                        <li key={d.device_id}>
                          {d.name || d.device_id}{" "}
                          <span style={{ color: TONE[d.action] }}>— {ACTION_TEXT[d.action] ?? d.action}</span>
                          {d.detail && <span className="mini-meta"> ({d.detail})</span>}
                        </li>
                      ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p style={{ fontSize: 14, margin: "10px 0 6px" }}>
            <b>Step 2.</b>{" "}
            {chosen.length === 0
              ? "Tick at least one site."
              : planSentence({ sites: chosen, summary: {
                  create: chosen.filter((s) => s.action === "create").length,
                  reuse: chosen.filter((s) => s.action === "reuse").length,
                  bind: chosen.reduce((n, s) => n + binds(s), 0),
                  skip: chosen.reduce((n, s) => n + s.devices.length - binds(s), 0),
                } }, false)}
          </p>
          <button className="dash-btn accent" disabled={busy || chosen.length === 0} onClick={adopt}>
            {busy ? "Adopting…" : `Adopt ${chosen.length} site${chosen.length === 1 ? "" : "s"}`}
          </button>
        </>
      )}
    </section>
  );
}
