import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import { cssVar } from "../theme/tokens";
import { registerMap } from "echarts/core";
import { api, DeviceLocationRow, GeomapResponse, GeoSite, SiteRow, ImportResult } from "../services/api";
import { StatStrip, Stat, Segmented } from "../components/ui";
import DataTable, { Column } from "../components/DataTable";
import Icon from "../components/Icon";

// Device Geomap (Infrastructure → Maps) — the fleet plotted by site. Placement
// is INTENT data: sites and their latitude/longitude live in the Source of
// Truth (Automation → Source of Truth), never GeoIP — RFC 1918 management
// addresses don't geolocate. Each sited device rolls up into its site bubble:
// size = device count, color = health (any down device tints the site).
//
// The world basemap is Natural Earth 110m country outlines (public domain),
// bundled as a slimmed GeoJSON and registered lazily so the main bundle
// doesn't carry it.

let worldRegistered = false;
async function ensureWorldMap(): Promise<void> {
  if (worldRegistered) return;
  const world = await import("../assets/world-110m.geo.json");
  registerMap("world", world.default as never);
  worldRegistered = true;
}

function siteTone(s: GeoSite): string {
  if (s.devices === 0) return cssVar("--fg-muted", "#586173");
  if (s.down > 0 && s.up === 0) return cssVar("--crit", "#e11d48");
  if (s.down > 0) return cssVar("--warn", "#d97706");
  return cssVar("--ok", "#059669");
}

function MapPanel({ sites, height = 460 }: { sites: GeoSite[]; height?: number }) {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    let alive = true;
    ensureWorldMap().then(() => { if (alive) setReady(true); });
    return () => { alive = false; };
  }, []);

  const plotted = sites.filter((s) => s.has_coords);
  const option = useMemo(() => ({
    backgroundColor: "transparent",
    geo: {
      map: "world",
      roam: true,
      scaleLimit: { min: 1, max: 12 },
      itemStyle: { areaColor: cssVar("--surface-2", "#eef1f5"), borderColor: cssVar("--border", "#d6dbe3"), borderWidth: 0.6 },
      emphasis: { disabled: true },
      select: { disabled: true },
    },
    tooltip: {
      trigger: "item",
      backgroundColor: cssVar("--overlay", "#ffffff"),
      borderColor: cssVar("--border", "#e4e7ec"),
      textStyle: { color: cssVar("--fg", "#1a2230"), fontSize: 13 },
      formatter: (p: { data?: { site?: GeoSite } }) => {
        const s = p.data?.site;
        if (!s) return "";
        return `<b>${s.name}</b><br/>${s.devices} device${s.devices === 1 ? "" : "s"} · ${s.up} up · ${s.down} down`;
      },
    },
    series: [
      {
        type: "effectScatter",
        coordinateSystem: "geo",
        rippleEffect: { brushType: "stroke", scale: 2.6 },
        symbolSize: (val: number[]) => Math.min(34, 10 + Math.sqrt(val[2] || 1) * 5),
        itemStyle: { color: cssVar("--accent", "#4f46e5") },
        data: plotted.map((s) => ({
          name: s.name,
          value: [s.lng, s.lat, s.devices],
          site: s,
          itemStyle: { color: siteTone(s) },
        })),
        label: {
          show: true,
          position: "right",
          formatter: (p: { data?: { site?: GeoSite } }) => p.data?.site?.name ?? "",
          fontSize: 11,
          color: cssVar("--fg", "#1a2230"),
        },
      },
    ],
  }), [plotted]);

  if (!ready) return <div className="empty board-empty"><div className="board-empty-msg">Loading basemap…</div></div>;
  if (plotted.length === 0) {
    return (
      <div className="empty board-empty">
        <div className="board-empty-msg">No sites have coordinates yet.</div>
        <div className="board-empty-hint">
          Open the Source of Truth and set latitude / longitude on each site (decimal WGS 84),
          then assign devices to their sites — the map fills in from intent data.
        </div>
        <a className="board-empty-link" href="#/automation/sot">Open Source of Truth →</a>
      </div>
    );
  }
  return <ReactECharts option={option} style={{ height, width: "100%" }} notMerge />;
}

// GeomapSection — the compact embed used by the Device Monitoring board's
// "Geographic map" group. Same data + onboarding honesty, smaller frame.
export function GeomapSection() {
  const [data, setData] = useState<GeomapResponse | null>(null);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try { const d = await api.geomap(); if (alive) setData(d); } catch { /* board stays on its empty state */ }
    };
    load();
    const t = setInterval(load, 60_000);
    return () => { alive = false; clearInterval(t); };
  }, []);
  if (!data) return <div className="empty board-empty"><div className="board-empty-msg">Loading…</div></div>;
  if (!data.geo_enabled) {
    return (
      <div className="empty board-empty">
        <div className="board-empty-msg">Geomap needs the Source of Truth.</div>
        <div className="board-empty-hint">Connect it under Automation → Source of Truth, then set site coordinates.</div>
        <a className="board-empty-link" href="#/automation/sot">Open Source of Truth →</a>
      </div>
    );
  }
  return <MapPanel sites={data.sites ?? []} height={320} />;
}

// LocationsEditor — Infrastructure → Maps → "Set locations": every visible
// device with where its placement comes from. SoT-placed rows are read-only
// (coordinates are managed on the site in the Source of Truth and win by
// precedence); everything else takes a free-form site label + lat/lng that
// lands in the operator annotation layer and shows on the map immediately.
function LocationsEditor({ onChanged }: { onChanged: () => void }) {
  const [rows, setRows] = useState<DeviceLocationRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [draft, setDraft] = useState<Record<string, { site: string; lat: string; lng: string }>>({});
  const [busy, setBusy] = useState<string | null>(null);

  const load = async () => {
    try { setRows((await api.deviceLocations()).devices); setErr(null); }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
  };
  useEffect(() => { load(); }, []);

  const dv = (r: DeviceLocationRow) =>
    draft[r.id] ?? { site: r.site ?? "", lat: r.lat != null && r.source === "manual" ? String(r.lat) : "", lng: r.lng != null && r.source === "manual" ? String(r.lng) : "" };
  const edit = (r: DeviceLocationRow, patch: Partial<{ site: string; lat: string; lng: string }>) =>
    setDraft({ ...draft, [r.id]: { ...dv(r), ...patch } });

  const save = async (r: DeviceLocationRow) => {
    const d = dv(r);
    const lat = parseFloat(d.lat), lng = parseFloat(d.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) { setErr(`${r.name}: latitude and longitude are required (decimal WGS 84)`); return; }
    setBusy(r.id);
    try {
      await api.setDeviceLocation(r.id, { site: d.site.trim(), lat, lng });
      const next = { ...draft }; delete next[r.id]; setDraft(next);
      setErr(null); await load(); onChanged();
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(null); }
  };
  const clear = async (r: DeviceLocationRow) => {
    setBusy(r.id);
    try { await api.clearDeviceLocation(r.id); setErr(null); await load(); onChanged(); }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(null); }
  };

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Device locations</h3>
      <p className="mini-meta">
        Devices placed by the Source of Truth inherit their site's coordinates (set them on the site under
        Automation → Source of Truth). For everything else, type a site label + decimal latitude/longitude —
        devices sharing a label fold into one map bubble. Unplaced devices are listed first.
      </p>
      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}
      <table className="loc-editor">
        <thead><tr><th>Device</th><th>Placement</th><th>Site label</th><th>Latitude</th><th>Longitude</th><th /></tr></thead>
        <tbody>
          {rows.map((r) => {
            const d = dv(r);
            const sot = r.source === "sot";
            return (
              <tr key={r.id}>
                <td className="mono">{r.name}</td>
                <td>
                  {sot ? <span className="cat">Source of Truth · {r.site}</span>
                    : r.source === "manual" ? <span className="cat">manual</span>
                    : <span style={{ color: "var(--warn)" }}>not set</span>}
                </td>
                {sot ? (
                  <td colSpan={3} className="mini-meta">coordinates come from the site in the Source of Truth</td>
                ) : (
                  <>
                    <td><input value={d.site} placeholder="e.g. Dallas-Branch" onChange={(e) => edit(r, { site: e.target.value })} /></td>
                    <td><input value={d.lat} placeholder="32.78" inputMode="decimal" onChange={(e) => edit(r, { lat: e.target.value })} /></td>
                    <td><input value={d.lng} placeholder="-96.80" inputMode="decimal" onChange={(e) => edit(r, { lng: e.target.value })} /></td>
                  </>
                )}
                <td style={{ whiteSpace: "nowrap", textAlign: "right" }}>
                  {!sot && (
                    <>
                      <button className="dash-btn accent" disabled={busy === r.id} onClick={() => save(r)}>Save</button>
                      {r.source === "manual" && (
                        <button className="dash-btn" style={{ marginLeft: 6 }} disabled={busy === r.id} onClick={() => clear(r)}>Clear</button>
                      )}
                    </>
                  )}
                </td>
              </tr>
            );
          })}
          {rows.length === 0 && !err && <tr><td colSpan={6} className="mini-meta">No devices visible.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

// SitesManager — Infrastructure → Maps → "Sites": create and curate the platform's
// own Source-of-Truth sites (name + status + WGS-84 coordinates). The platform's
// inventory + these sites ARE the source of truth, so this is always editable —
// declare a site here, then assign devices to it (Devices → Site, or the `site`
// label) and they roll up into its map bubble. NetBox, when connected, is an
// automation connector and never takes this over (see Automation → Source of Truth).
function SitesManager({ onChanged }: { onChanged: () => void }) {
  const [sites, setSites] = useState<SiteRow[]>([]);
  const [active, setActive] = useState<string>("internal");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [add, setAdd] = useState({ name: "", status: "", owner: "", lat: "", lng: "" });
  const [drafts, setDrafts] = useState<Record<string, { name: string; status: string; owner: string; lat: string; lng: string }>>({});
  const [showImport, setShowImport] = useState(false);

  const load = async () => {
    try { const r = await api.sites(); setSites(r.sites); setActive(r.active || "internal"); setErr(null); }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
  };
  useEffect(() => { load(); }, []);

  const editable = active === "internal";

  // coordsOf parses a {lat,lng} pair: both blank → site has no coordinates (valid);
  // either filled → both must be finite decimals. Returns undefined on error (caller
  // sets err) and {} when intentionally cleared.
  const coordsOf = (lat: string, lng: string): { lat?: number; lng?: number } | undefined => {
    const hasLat = lat.trim() !== "", hasLng = lng.trim() !== "";
    if (!hasLat && !hasLng) return {};
    const la = parseFloat(lat), ln = parseFloat(lng);
    if (!Number.isFinite(la) || !Number.isFinite(ln)) return undefined;
    return { lat: la, lng: ln };
  };

  const create = async () => {
    const name = add.name.trim();
    if (!name) { setErr("Site name is required."); return; }
    const c = coordsOf(add.lat, add.lng);
    if (c === undefined) { setErr("Enter both latitude and longitude as decimals (WGS 84), or leave both blank."); return; }
    setBusy("__add__");
    try {
      await api.saveSite({ name, status: add.status.trim() || undefined, owner: add.owner.trim() || undefined, ...c });
      setAdd({ name: "", status: "", owner: "", lat: "", lng: "" }); setErr(null); await load(); onChanged();
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(null); }
  };

  const beginEdit = (s: SiteRow) =>
    setDrafts({ ...drafts, [s.slug]: { name: s.name, status: s.status ?? "", owner: s.owner ?? "", lat: s.has_coords ? String(s.lat) : "", lng: s.has_coords ? String(s.lng) : "" } });
  const cancelEdit = (slug: string) => { const next = { ...drafts }; delete next[slug]; setDrafts(next); };

  const update = async (slug: string) => {
    const d = drafts[slug];
    if (!d.name.trim()) { setErr("Site name is required."); return; }
    const c = coordsOf(d.lat, d.lng);
    if (c === undefined) { setErr("Enter both latitude and longitude as decimals (WGS 84), or leave both blank."); return; }
    setBusy(slug);
    try {
      await api.updateSite(slug, { name: d.name.trim(), status: d.status.trim() || undefined, owner: d.owner.trim() || undefined, ...c });
      cancelEdit(slug); setErr(null); await load(); onChanged();
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(null); }
  };

  const remove = async (s: SiteRow) => {
    if (!window.confirm(`Delete site "${s.name}"? Devices labelled with its slug fall back to unplaced.`)) return;
    setBusy(s.slug);
    try { await api.deleteSite(s.slug); setErr(null); await load(); onChanged(); }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(null); }
  };

  return (
    <div className="card">
      <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: 8 }}>
        Sites
        <span className="badge" style={{ fontSize: 10 }}>Source of truth</span>
        {editable && (
          <button className="dash-btn" style={{ marginLeft: "auto" }} onClick={() => setShowImport((v) => !v)}>
            {showImport ? "Close import" : "Import…"}
          </button>
        )}
      </h3>
      <p className="mini-meta">
        Declare a site with decimal latitude/longitude (WGS 84). Assign a device to it from
        Infrastructure → Devices (the <code>Site</code> column), or give it a <code>site</code> label matching the
        site's slug (shown below), and it folds into that site's map bubble, inheriting these coordinates. Leave
        coordinates blank to register a site that isn't yet on the map. Bulk-seed from an existing
        system with <b>Import</b> — it adds intent only; live discovery stays authoritative.
      </p>
      {editable && showImport && <ImportPanel onDone={() => { load(); onChanged(); }} />}
      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}
      <table className="loc-editor">
        <thead><tr><th>Site</th><th>Slug</th><th>Status</th><th>Owner</th><th>Latitude</th><th>Longitude</th><th /></tr></thead>
        <tbody>
          {sites.map((s) => {
            const d = drafts[s.slug];
            if (editable && d) {
              return (
                <tr key={s.slug}>
                  <td><input value={d.name} onChange={(e) => setDrafts({ ...drafts, [s.slug]: { ...d, name: e.target.value } })} /></td>
                  <td className="mono mini-meta">{s.slug}</td>
                  <td><input value={d.status} placeholder="active" onChange={(e) => setDrafts({ ...drafts, [s.slug]: { ...d, status: e.target.value } })} /></td>
                  <td><input value={d.owner} placeholder="NetEng NOC" onChange={(e) => setDrafts({ ...drafts, [s.slug]: { ...d, owner: e.target.value } })} /></td>
                  <td><input value={d.lat} placeholder="32.78" inputMode="decimal" onChange={(e) => setDrafts({ ...drafts, [s.slug]: { ...d, lat: e.target.value } })} /></td>
                  <td><input value={d.lng} placeholder="-96.80" inputMode="decimal" onChange={(e) => setDrafts({ ...drafts, [s.slug]: { ...d, lng: e.target.value } })} /></td>
                  <td style={{ whiteSpace: "nowrap", textAlign: "right" }}>
                    <button className="dash-btn accent" disabled={busy === s.slug} onClick={() => update(s.slug)}>Save</button>
                    <button className="dash-btn" style={{ marginLeft: 6 }} disabled={busy === s.slug} onClick={() => cancelEdit(s.slug)}>Cancel</button>
                  </td>
                </tr>
              );
            }
            return (
              <tr key={s.slug}>
                <td><b>{s.name}</b></td>
                <td className="mono mini-meta">{s.slug}</td>
                <td>{s.status || <span className="mini-meta">—</span>}</td>
                <td>{s.owner || <span className="mini-meta">—</span>}</td>
                <td colSpan={2}>
                  {s.has_coords ? <span className="mono">{s.lat.toFixed(4)}, {s.lng.toFixed(4)}</span> : <span style={{ color: "var(--warn)" }}>not set</span>}
                </td>
                <td style={{ whiteSpace: "nowrap", textAlign: "right" }}>
                  {editable && (
                    <>
                      <button className="dash-btn" disabled={busy === s.slug} onClick={() => beginEdit(s)}>Edit</button>
                      <button className="dash-btn" style={{ marginLeft: 6, color: "var(--bad)" }} disabled={busy === s.slug} onClick={() => remove(s)}>Delete</button>
                    </>
                  )}
                </td>
              </tr>
            );
          })}
          {editable && (
            <tr>
              <td><input value={add.name} placeholder="e.g. Dallas Branch" onChange={(e) => setAdd({ ...add, name: e.target.value })} /></td>
              <td className="mini-meta">{add.name.trim() ? "auto" : ""}</td>
              <td><input value={add.status} placeholder="active" onChange={(e) => setAdd({ ...add, status: e.target.value })} /></td>
              <td><input value={add.owner} placeholder="NetEng NOC" onChange={(e) => setAdd({ ...add, owner: e.target.value })} /></td>
              <td><input value={add.lat} placeholder="32.78" inputMode="decimal" onChange={(e) => setAdd({ ...add, lat: e.target.value })} /></td>
              <td><input value={add.lng} placeholder="-96.80" inputMode="decimal" onChange={(e) => setAdd({ ...add, lng: e.target.value })} /></td>
              <td style={{ whiteSpace: "nowrap", textAlign: "right" }}>
                <button className="dash-btn accent" disabled={busy === "__add__"} onClick={create}>Add site</button>
              </td>
            </tr>
          )}
          {sites.length === 0 && !editable && <tr><td colSpan={7} className="mini-meta">The external Source of Truth lists no sites.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

// Action → tone for the import plan chips/rows (honest: conflict & error stand out).
const ACTION_TONE: Record<string, string> = {
  create: "var(--good, #16a34a)", update: "var(--accent, #2563eb)",
  conflict: "var(--warn, #d97706)", error: "var(--bad, #dc2626)",
  skip: "var(--muted)", unchanged: "var(--muted)",
};

// ImportPanel — external SoT one-way import (Infrastructure → Maps → Sites).
// Seeds the internal SoT from a CSV/JSON (or GeoJSON for sites) file. Dry-run
// preview FIRST (create/update/skip/conflict counts), then an explicit Apply —
// the live discovery inventory always stays authoritative; this only adds intent.
function ImportPanel({ onDone }: { onDone: () => void }) {
  const [kind, setKind] = useState<"sites" | "device_sites">("sites");
  const [format, setFormat] = useState<"csv" | "json" | "geojson">("csv");
  const [text, setText] = useState("");
  const [overwrite, setOverwrite] = useState(false);
  const [plan, setPlan] = useState<ImportResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // GeoJSON only makes sense for sites; fall back to CSV when switching to bindings.
  const formats: ("csv" | "json" | "geojson")[] = kind === "sites" ? ["csv", "json", "geojson"] : ["csv", "json"];
  const fmt = formats.includes(format) ? format : "csv";

  const run = async (dry: boolean) => {
    if (!text.trim()) { setErr("Paste or upload a file first."); return; }
    setBusy(true); setErr(null);
    try {
      const r = await api.importSot({ kind, format: fmt, data: text, dry_run: dry, overwrite });
      setPlan(r);
      if (!dry) onDone();
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  };

  const onFile = (f: File | undefined) => {
    if (!f) return;
    const ext = f.name.toLowerCase().split(".").pop();
    if (ext === "csv" || ext === "json" || ext === "geojson") setFormat(ext as typeof format);
    f.text().then((t) => { setText(t); setPlan(null); });
  };

  const hint = kind === "sites"
    ? "Columns: name, slug (optional), status, owner, latitude, longitude. GeoJSON: a FeatureCollection of Point features (coordinates are [lng, lat])."
    : "Columns: device (id, hostname, mgmt-IP or serial — matched against discovered devices) and site (slug).";

  return (
    <div className="card" style={{ background: "var(--surface-2, #f6f8fc)", marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <strong style={{ fontSize: 13 }}>Import from a file</strong>
        <span className="mini-meta">one-way seed · discovery stays authoritative</span>
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", margin: "10px 0" }}>
        <select className="form-input" value={kind} onChange={(e) => { setKind(e.target.value as typeof kind); setPlan(null); }} style={{ height: 30 }}>
          <option value="sites">Sites</option>
          <option value="device_sites">Device → site placement</option>
        </select>
        <select className="form-input" value={fmt} onChange={(e) => { setFormat(e.target.value as typeof format); setPlan(null); }} style={{ height: 30 }}>
          {formats.map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}
        </select>
        <input type="file" accept=".csv,.json,.geojson" onChange={(e) => onFile(e.target.files?.[0])} style={{ fontSize: 12 }} />
        <label style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12 }}>
          <input type="checkbox" checked={overwrite} onChange={(e) => { setOverwrite(e.target.checked); setPlan(null); }} />
          Overwrite existing (apply changes, not just new rows)
        </label>
      </div>
      <p className="mini-meta" style={{ marginTop: 0 }}>{hint}</p>
      <textarea
        className="form-input" value={text} spellCheck={false}
        onChange={(e) => { setText(e.target.value); setPlan(null); }}
        placeholder="…or paste file contents here"
        style={{ width: "100%", minHeight: 90, fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}
      />
      <div style={{ display: "flex", gap: 8, marginTop: 8, alignItems: "center" }}>
        <button className="dash-btn" disabled={busy} onClick={() => run(true)}>Preview</button>
        <button className="dash-btn accent" disabled={busy || !plan} onClick={() => run(false)} title={plan ? "" : "Preview first"}>Apply</button>
        {plan && <span className="mini-meta">{plan.dry_run ? "Preview (nothing written yet)" : "Applied"}</span>}
      </div>
      {err && <p style={{ color: "var(--bad)", marginBottom: 0 }}>{err}</p>}
      {plan && (
        <div style={{ marginTop: 10 }}>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
            {Object.entries(plan.summary).filter(([, n]) => n > 0).map(([a, n]) => (
              <span key={a} className="badge" style={{ fontSize: 11, color: ACTION_TONE[a] ?? "var(--fg)" }}>{a}: {n}</span>
            ))}
            {Object.values(plan.summary).every((n) => n === 0) && <span className="mini-meta">No rows.</span>}
          </div>
          {plan.rows.length > 0 && (
            <div style={{ maxHeight: 200, overflow: "auto", border: "1px solid var(--panel-border, #e2e6ee)", borderRadius: 6 }}>
              <table className="loc-editor" style={{ margin: 0 }}>
                <thead><tr><th>Line</th><th>Key</th><th>Action</th><th>Detail</th></tr></thead>
                <tbody>
                  {plan.rows.map((r, i) => (
                    <tr key={i}>
                      <td className="mini-meta">{r.line}</td>
                      <td className="mono">{r.key || "—"}</td>
                      <td style={{ color: ACTION_TONE[r.action] ?? "var(--fg)", fontWeight: 600 }}>{r.action}</td>
                      <td className="mini-meta">{r.detail || ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function DeviceGeomap() {
  const [data, setData] = useState<GeomapResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [view, setView] = useState<"map" | "sites" | "locations">("map");
  const [bump, setBump] = useState(0); // re-fetch signal after a location edit

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try { const d = await api.geomap(); if (alive) { setData(d); setErr(null); } }
      catch (e) { if (alive) setErr(e instanceof Error ? e.message : String(e)); }
    };
    load();
    const t = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(t); };
  }, [bump]);

  const sites = data?.sites ?? [];
  const up = sites.reduce((a, s) => a + s.up, 0);
  const down = sites.reduce((a, s) => a + s.down, 0);

  const cols: Column<GeoSite>[] = [
    { key: "name", header: "Site", width: 200, sortable: true, render: (s) => <b>{s.name}</b> },
    { key: "status", header: "Status", width: 90, render: (s) => s.status || "—" },
    {
      key: "coords", header: "Coordinates", width: 150,
      render: (s) => (s.has_coords ? `${s.lat.toFixed(2)}, ${s.lng.toFixed(2)}` : <span style={{ color: "var(--warn, #d97706)" }}>not set</span>),
    },
    { key: "devices", header: "Devices", width: 80, sortable: true, sortValue: (s) => s.devices, render: (s) => s.devices },
    {
      key: "health", header: "Health", width: 120,
      render: (s) => (
        <span>
          <span style={{ color: "var(--good, #059669)", fontWeight: 600 }}>{s.up} up</span>
          {s.down > 0 && <span style={{ color: "var(--bad, #dc2626)", fontWeight: 600 }}> · {s.down} down</span>}
        </span>
      ),
    },
  ];

  if (err) return <div className="card"><p style={{ color: "var(--bad)" }}>Geomap unavailable: {err}</p></div>;
  if (!data) return <div className="card"><p style={{ color: "var(--muted)" }}>Loading…</p></div>;

  if (!data.geo_enabled) {
    return (
      <div className="card" style={{ maxWidth: 760 }}>
        <div className="empty-state">
          <div style={{ display: "flex", justifyContent: "center", marginBottom: 10 }}><Icon name="explore" size={40} /></div>
          <h2 style={{ marginBottom: 6 }}>Device Geomap</h2>
          <p style={{ color: "var(--muted)", maxWidth: 540, margin: "0 auto" }}>
            {data.reason === "sot"
              ? "The geomap places devices from intent data: Source-of-Truth sites with latitude/longitude, or locations you set per device right here. GeoIP is never used."
              : `Could not read sites from the Source of Truth${data.error ? `: ${data.error}` : ""}.`}
          </p>
          <div style={{ marginTop: 12, display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap" }}>
            <button className="dash-btn accent" onClick={() => setView("sites")}>Declare sites</button>
            <button className="dash-btn" onClick={() => setView("locations")}>Set device locations</button>
          </div>
        </div>
        {view === "sites" && <div style={{ marginTop: 14 }}><SitesManager onChanged={() => setBump((b) => b + 1)} /></div>}
        {view === "locations" && <div style={{ marginTop: 14 }}><LocationsEditor onChanged={() => setBump((b) => b + 1)} /></div>}
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <Segmented value={view} ariaLabel="Geomap view"
        options={[{ value: "map", label: "Map" }, { value: "sites", label: "Sites" }, { value: "locations", label: "Set locations" }]}
        onChange={setView} />
      {view === "sites" ? (
        <SitesManager onChanged={() => setBump((b) => b + 1)} />
      ) : view === "locations" ? (
        <LocationsEditor onChanged={() => setBump((b) => b + 1)} />
      ) : (
      <>
      <StatStrip>
        <Stat label="Sites" value={sites.length} />
        <Stat label="Sites on map" value={sites.filter((s) => s.has_coords).length} />
        <Stat label="Devices placed" value={data.placed ?? 0} />
        <Stat label="Unplaced devices" value={data.unplaced ?? 0} tone={(data.unplaced ?? 0) > 0 ? "warn" : ""} />
        <Stat label="Up" value={up} tone="good" />
        <Stat label="Down" value={down} tone={down > 0 ? "bad" : ""} />
      </StatStrip>

      <div className="card" style={{ padding: 8 }}>
        <MapPanel sites={sites} />
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Sites</h3>
        <DataTable rows={sites} columns={cols} rowKey={(s) => s.slug} height={320} ariaLabel="Sites" />
        {(data.unplaced ?? 0) > 0 && (
          <p className="mini-meta" style={{ marginBottom: 0 }}>
            {data.unplaced} device{data.unplaced === 1 ? " is" : "s are"} not assigned to a site (or assigned to one the
            Source of Truth no longer lists) — assign sites in the Source of Truth to place them.
          </p>
        )}
      </div>
      </>
      )}
    </div>
  );
}
