import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import { cssVar } from "../theme/tokens";
import { registerMap } from "echarts/core";
import { api, DeviceLocationRow, GeomapResponse, GeoSite } from "../services/api";
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

export default function DeviceGeomap() {
  const [data, setData] = useState<GeomapResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [view, setView] = useState<"map" | "locations">("map");
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
          <div style={{ marginTop: 12, display: "flex", gap: 14, justifyContent: "center" }}>
            <button className="dash-btn accent" onClick={() => setView("locations")}>Set device locations</button>
            <a className="board-empty-link" href="#/automation/sot">Open Source of Truth →</a>
          </div>
        </div>
        {view === "locations" && <div style={{ marginTop: 14 }}><LocationsEditor onChanged={() => setBump((b) => b + 1)} /></div>}
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <Segmented value={view} ariaLabel="Geomap view"
        options={[{ value: "map", label: "Map" }, { value: "locations", label: "Set locations" }]}
        onChange={setView} />
      {view === "locations" ? (
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
