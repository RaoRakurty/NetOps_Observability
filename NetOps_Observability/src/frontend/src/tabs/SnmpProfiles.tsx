// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useMemo, useState } from "react";
import { api, SnmpProfile, SnmpMetric } from "../services/api";
import { capitalize } from "../lib/text";
import { operatorError } from "../lib/errors";
// SNMP Profiles — the vendor OID/metric library (vendor "device profiles"
// pattern): profiles grouped by category on the left, the selected profile's
// metric table on the right, with the ability to add custom metrics. Built-in
// profiles ship verified OIDs; operators extend them or add new vendors.

const CATEGORY_LABELS: Record<string, string> = {
  universal: "Universal (standard MIBs)",
  router_switch: "Routers / Switches",
  firewall: "Firewalls",
  load_balancer: "Load Balancers",
  wireless: "Wireless",
  voip: "VoIP",
  printer: "Printers",
  ups: "UPS / Power",
  server: "Servers / Hosts",
  custom: "Custom",
};

const EMPTY_METRIC: SnmpMetric = { name: "", oid: "", type: "gauge", unit: "" };

export default function SnmpProfiles() {
  const [profiles, setProfiles] = useState<SnmpProfile[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [draft, setDraft] = useState<SnmpMetric>(EMPTY_METRIC);
  const [uploadText, setUploadText] = useState("");
  const [showUpload, setShowUpload] = useState(false);
  const [newVendor, setNewVendor] = useState("");
  const [metricFilter, setMetricFilter] = useState("");
  const [profileFilter, setProfileFilter] = useState("");

  const load = async () => {
    try {
      const p = await api.snmpProfiles();
      setProfiles(p);
      setErr(null);
      setSelected((cur) => cur ?? (p[0]?.id ?? null));
    } catch (e) {
      setErr(operatorError(e, "SNMP profiles could not be loaded."));
    }
  };
  useEffect(() => {
    load();
  }, []);

  const grouped = useMemo(() => {
    const q = profileFilter.trim().toLowerCase();
    const g = new Map<string, SnmpProfile[]>();
    for (const p of profiles) {
      if (q && !p.vendor.toLowerCase().includes(q) && !p.id.includes(q)) continue;
      const arr = g.get(p.category) ?? [];
      arr.push(p);
      g.set(p.category, arr);
    }
    return g;
  }, [profiles, profileFilter]);

  const current = profiles.find((p) => p.id === selected) ?? null;

  const addMetric = async () => {
    if (!current || !draft.name.trim() || !draft.oid.trim()) return;
    try {
      const updated = await api.addSnmpProfileMetrics(current.id, [draft]);
      setProfiles((ps) => ps.map((p) => (p.id === updated.id ? updated : p)));
      setDraft(EMPTY_METRIC);
    } catch (e) {
      setErr(operatorError(e, "The metric could not be added."));
    }
  };

  // Bulk upload: accept a JSON array of {name,oid,type,unit} (paste or file).
  const uploadOIDs = async () => {
    if (!current || !uploadText.trim()) return;
    try {
      const parsed = JSON.parse(uploadText);
      const metrics: SnmpMetric[] = Array.isArray(parsed) ? parsed : parsed.metrics;
      if (!Array.isArray(metrics)) throw new Error("That file does not look like a list of metrics.");
      const updated = await api.addSnmpProfileMetrics(current.id, metrics);
      setProfiles((ps) => ps.map((p) => (p.id === updated.id ? updated : p)));
      setUploadText("");
      setShowUpload(false);
    } catch (e) {
      setErr(operatorError(e, "That OID file could not be read."));
    }
  };

  const loadFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    f.text().then(setUploadText).catch(() => setErr("could not read file"));
  };

  // Create a new custom vendor profile.
  const createProfile = async () => {
    if (!newVendor.trim()) return;
    try {
      const p = await api.upsertSnmpProfile({ vendor: newVendor, category: "custom", metrics: [] });
      setNewVendor("");
      await load();
      setSelected(p.id);
    } catch (e) {
      setErr(operatorError(e, "The profile could not be created."));
    }
  };

  if (err) return <div className="panel" style={{ padding: 20, color: "var(--muted)" }}>SNMP profiles: {err}</div>;

  return (
    <div className="split-view" style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
      {/* Profiles list, grouped by category */}
      <div className="panel" style={{ width: 280, flexShrink: 0, padding: 8, maxHeight: "calc(100vh - 160px)", overflow: "auto" }}>
        <input
          placeholder="Search profiles…"
          value={profileFilter}
          onChange={(e) => setProfileFilter(e.target.value)}
          style={{ width: "100%", marginBottom: 8 }}
        />
        <div style={{ display: "flex", gap: 6, padding: "4px 8px 10px" }}>
          <input
            placeholder="New vendor profile…"
            value={newVendor}
            onChange={(e) => setNewVendor(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && createProfile()}
            style={{ flex: 1, minWidth: 0 }}
          />
          <button className="btn" onClick={createProfile} title="Create a custom profile">+</button>
        </div>
        {[...grouped.entries()].map(([cat, ps]) => (
          <div key={cat} style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, textTransform: "uppercase", color: "var(--muted)", padding: "4px 8px" }}>
              {CATEGORY_LABELS[cat] ?? cat}
            </div>
            {ps.map((p) => (
              <button
                key={p.id}
                className={`nav-sub${p.id === selected ? " active" : ""}`}
                style={{ width: "100%", textAlign: "left", display: "flex", justifyContent: "space-between" }}
                onClick={() => setSelected(p.id)}
              >
                <span>{capitalize(p.vendor)}</span>
                <span style={{ color: "var(--muted)", fontSize: 11 }}>{p.metrics.length}</span>
              </button>
            ))}
          </div>
        ))}
      </div>

      {/* Selected profile detail */}
      <div className="panel" style={{ flex: 1, padding: 16 }}>
        {!current ? (
          <div style={{ color: "var(--muted)" }}>No profile selected.</div>
        ) : (
          <>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <h3 style={{ margin: 0 }}>
                {capitalize(current.vendor)} <span style={{ color: "var(--muted)", fontWeight: 400, fontSize: 13 }}>· {current.metrics.length} metrics</span>
              </h3>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <button className="btn" onClick={() => setShowUpload((v) => !v)}>Upload OIDs</button>
                <span className={`pill ${current.builtin ? "cell-ok" : "cell-warn"}`}>
                  {current.builtin ? "built-in" : "custom"}
                </span>
              </div>
            </div>

            {showUpload && (
              <div className="card" style={{ marginTop: 10, padding: 12 }}>
                <div style={{ color: "var(--muted)", fontSize: 12, marginBottom: 6 }}>
                  Paste or upload a JSON array of metrics, e.g.{" "}
                  <code>{`[{"name":"x","oid":"1.3.6.1...","type":"gauge","unit":"%"}]`}</code>
                </div>
                <textarea
                  value={uploadText}
                  onChange={(e) => setUploadText(e.target.value)}
                  rows={6}
                  style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
                  placeholder='[{"name":"...","oid":"...","type":"gauge","unit":"..."}]'
                />
                <div style={{ display: "flex", gap: 8, marginTop: 8, alignItems: "center" }}>
                  <input type="file" accept=".json,application/json" onChange={loadFile} />
                  <button className="btn accent" onClick={uploadOIDs}>Import metrics</button>
                </div>
              </div>
            )}
            {current.description && (
              <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 8, maxWidth: 720 }}>{current.description}</p>
            )}
            <div style={{ display: "flex", gap: 16, color: "var(--muted)", fontSize: 12, marginTop: 4, flexWrap: "wrap" }}>
              <span><strong style={{ color: "var(--fg)" }}>{current.metrics.length}</strong> enabled metrics</span>
              <span>category: {CATEGORY_LABELS[current.category] ?? current.category}</span>
              {current.sysobjectid_prefix && <span>sysObjectID: <code>{current.sysobjectid_prefix}</code></span>}
            </div>

            <input
              placeholder="Search metrics (name / OID / MIB)…"
              value={metricFilter}
              onChange={(e) => setMetricFilter(e.target.value)}
              style={{ width: "100%", marginTop: 12 }}
            />

            <table className="data-table" style={{ marginTop: 8 }}>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>OID</th>
                  <th>MIB</th>
                  <th>Category</th>
                  <th>Type</th>
                  <th>Unit</th>
                </tr>
              </thead>
              <tbody>
                {current.metrics
                  .filter((mt) => {
                    const q = metricFilter.trim().toLowerCase();
                    return !q || mt.name.toLowerCase().includes(q) || mt.oid.includes(q) || (mt.mib ?? "").toLowerCase().includes(q);
                  })
                  .map((mt) => (
                    <tr key={mt.oid + mt.name}>
                      <td>{mt.name}</td>
                      <td><code style={{ fontSize: 12 }}>{mt.oid}</code></td>
                      <td style={{ color: "var(--muted)", fontSize: 12 }}>{mt.mib || "—"}</td>
                      <td>{mt.category ? <span className="pill">{mt.category}</span> : <span style={{ color: "var(--muted)" }}>—</span>}</td>
                      <td>{mt.type}</td>
                      <td>{mt.unit}</td>
                    </tr>
                  ))}
              </tbody>
            </table>

            {/* Add a custom metric */}
            <div style={{ marginTop: 16, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <input placeholder="name" value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })} style={{ width: 140 }} />
              <input placeholder="1.3.6.1.4.1…" value={draft.oid}
                onChange={(e) => setDraft({ ...draft, oid: e.target.value })} style={{ width: 200 }} />
              <select value={draft.type} onChange={(e) => setDraft({ ...draft, type: e.target.value })}>
                <option value="gauge">gauge</option>
                <option value="counter">counter</option>
                <option value="string">string</option>
                <option value="enum">Named states</option>
              </select>
              <input placeholder="unit" value={draft.unit}
                onChange={(e) => setDraft({ ...draft, unit: e.target.value })} style={{ width: 90 }} />
              <button className="btn" onClick={addMetric}>Add metric</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
