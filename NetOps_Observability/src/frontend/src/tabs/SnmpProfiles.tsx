import { useEffect, useMemo, useState } from "react";
import { api, SnmpProfile, SnmpMetric } from "../services/api";

// SNMP Profiles — the vendor OID/metric library (Datadog "device profiles"
// pattern): profiles grouped by category on the left, the selected profile's
// metric table on the right, with the ability to add custom metrics. Built-in
// profiles ship verified OIDs; operators extend them or add new vendors.

const CATEGORY_LABELS: Record<string, string> = {
  universal: "Universal (standard MIBs)",
  router_switch: "Routers / Switches",
  firewall: "Firewalls",
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

  const load = async () => {
    try {
      const p = await api.snmpProfiles();
      setProfiles(p);
      setErr(null);
      setSelected((cur) => cur ?? (p[0]?.id ?? null));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed to load profiles");
    }
  };
  useEffect(() => {
    load();
  }, []);

  const grouped = useMemo(() => {
    const g = new Map<string, SnmpProfile[]>();
    for (const p of profiles) {
      const arr = g.get(p.category) ?? [];
      arr.push(p);
      g.set(p.category, arr);
    }
    return g;
  }, [profiles]);

  const current = profiles.find((p) => p.id === selected) ?? null;

  const addMetric = async () => {
    if (!current || !draft.name.trim() || !draft.oid.trim()) return;
    try {
      const updated = await api.addSnmpProfileMetrics(current.id, [draft]);
      setProfiles((ps) => ps.map((p) => (p.id === updated.id ? updated : p)));
      setDraft(EMPTY_METRIC);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed to add metric");
    }
  };

  if (err) return <div className="panel" style={{ padding: 20, color: "var(--muted)" }}>SNMP profiles: {err}</div>;

  return (
    <div className="split-view" style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
      {/* Profiles list, grouped by category */}
      <div className="panel" style={{ width: 280, flexShrink: 0, padding: 8 }}>
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
                <span>{p.vendor}</span>
                <span style={{ color: "var(--muted)", fontSize: 11 }}>{p.metrics.length}</span>
              </button>
            ))}
          </div>
        ))}
      </div>

      {/* Selected profile detail */}
      <div className="panel" style={{ flex: 1, padding: 16 }}>
        {!current ? (
          <div style={{ color: "var(--muted)" }}>Select a profile.</div>
        ) : (
          <>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <h3 style={{ margin: 0 }}>{current.vendor}</h3>
              <span className={`pill ${current.builtin ? "cell-ok" : "cell-warn"}`}>
                {current.builtin ? "built-in" : "custom"}
              </span>
            </div>
            {current.sysobjectid_prefix && (
              <div style={{ color: "var(--muted)", fontSize: 12, marginTop: 4 }}>
                sysObjectID prefix: <code>{current.sysobjectid_prefix}</code>
              </div>
            )}

            <table className="data-table" style={{ marginTop: 12 }}>
              <thead>
                <tr>
                  <th>Metric</th>
                  <th>OID</th>
                  <th>Type</th>
                  <th>Unit</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {current.metrics.map((mt) => (
                  <tr key={mt.oid}>
                    <td>{mt.name}</td>
                    <td><code style={{ fontSize: 12 }}>{mt.oid}</code></td>
                    <td>{mt.type}</td>
                    <td>{mt.unit}</td>
                    <td style={{ color: "var(--muted)" }}>{mt.description}</td>
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
                <option value="enum">enum</option>
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
