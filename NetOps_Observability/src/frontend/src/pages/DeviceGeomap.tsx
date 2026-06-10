import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import { cssVar } from "../theme/tokens";
import { registerMap } from "echarts/core";
import { api, GeomapResponse, GeoSite } from "../services/api";
import { StatStrip, Stat } from "../components/ui";
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

export default function DeviceGeomap() {
  const [data, setData] = useState<GeomapResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try { const d = await api.geomap(); if (alive) { setData(d); setErr(null); } }
      catch (e) { if (alive) setErr(e instanceof Error ? e.message : String(e)); }
    };
    load();
    const t = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(t); };
  }, []);

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
              ? "The geomap places devices from Source-of-Truth intent data (sites with latitude/longitude). Connect the Source of Truth under Automation → Source of Truth to enable it."
              : `Could not read sites from the Source of Truth${data.error ? `: ${data.error}` : ""}.`}
          </p>
          <a className="board-empty-link" style={{ display: "inline-block", marginTop: 12 }} href="#/automation/sot">Open Source of Truth →</a>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
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
    </div>
  );
}
