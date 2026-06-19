// GeoTopologyMap — Phase 5 geographic / WAN renderer.
//
// A real ECharts world map (Natural Earth 110m basemap, the same public-domain
// GeoJSON the Device Geomap bundles — no external map tiles, fully offline) that
// plots a renderer-agnostic TopologyView as:
//   • site bubbles   — effectScatter, sized by device count, toned by health,
//   • WAN circuits    — great-circle-ish lines between sited nodes, toned by
//                       link status, widened by utilization.
//
// Renderer-agnostic in / out: it consumes a TopologyView and runs it through the
// pure topologyToEchartsGeo adapter. Calm-by-default styling (PDF §11): muted
// basemap, health rings, no full-fill alarm colours. Honest empty state when no
// node carries coordinates (geo placement is INTENT data from the Source of
// Truth — never GeoIP).

import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import { registerMap } from "echarts/core";
import { cssVar } from "../../../../theme/tokens";
import { HEALTH_COLOR, HEALTH_LABEL } from "../../utils/topologyHealth";
import { topologyToEchartsGeo, type GeoModel } from "./topologyToEchartsGeo";
import { TopologySideDrawer } from "../../components";
import type { TopologyView, TopologySelection, Health } from "../../api/topologyTypes";

// Lazily register the world basemap once (shared global ECharts map registry).
let worldRegistered = false;
async function ensureWorldMap(): Promise<void> {
  if (worldRegistered) return;
  const world = await import("../../../../assets/world-110m.geo.json");
  registerMap("world", world.default as never);
  worldRegistered = true;
}

/** Circuit line width scales calmly with utilization (1.4..4px). */
function circuitWidth(util: number | undefined): number {
  const u = Math.max(0, Math.min(100, util ?? 0));
  return 1.4 + (u / 100) * 2.6;
}

function buildOption(model: GeoModel) {
  const fg = cssVar("--fg", "#1a2230");
  const muted = cssVar("--fg-muted", "#586173");
  return {
    backgroundColor: "transparent",
    geo: {
      map: "world",
      roam: true,
      scaleLimit: { min: 1, max: 12 },
      itemStyle: {
        areaColor: cssVar("--surface-2", "#eef1f5"),
        borderColor: cssVar("--border", "#d6dbe3"),
        borderWidth: 0.6,
      },
      emphasis: { disabled: true },
      select: { disabled: true },
    },
    tooltip: {
      trigger: "item",
      backgroundColor: cssVar("--overlay", "#ffffff"),
      borderColor: cssVar("--border", "#e4e7ec"),
      textStyle: { color: fg, fontSize: 12 },
    },
    series: [
      // ── WAN circuits (drawn under the bubbles) ──────────────────────────────
      {
        type: "lines",
        coordinateSystem: "geo",
        zlevel: 1,
        polyline: false,
        // a soft curve reads as a circuit rather than a straight ruler line
        lineStyle: { curveness: 0.18, opacity: 0.55, width: 1.6 },
        effect: {
          show: true,
          period: 6,
          trailLength: 0.2,
          symbol: "arrow",
          symbolSize: 4,
        },
        data: model.circuits.map((c) => ({
          coords: [c.from, c.to],
          name: `${c.fromName} ↔ ${c.toName}`,
          lineStyle: {
            color: HEALTH_COLOR[c.health],
            width: circuitWidth(c.utilization),
            opacity: c.health === "ok" ? 0.5 : 0.85,
          },
          // tooltip payload
          _circuit: c,
        })),
        tooltip: {
          formatter: (p: { data?: { _circuit?: GeoModel["circuits"][number] } }) => {
            const c = p.data?._circuit;
            if (!c) return "";
            const util = c.utilization == null ? "—" : `${c.utilization}%`;
            return `<b>${c.fromName} ↔ ${c.toName}</b><br/>${c.status} · util ${util}`;
          },
        },
      },
      // ── site bubbles ────────────────────────────────────────────────────────
      {
        type: "effectScatter",
        coordinateSystem: "geo",
        zlevel: 2,
        rippleEffect: { brushType: "stroke", scale: 2.4 },
        symbolSize: (val: number[]) => Math.min(34, 10 + Math.sqrt(val[2] || 1) * 4.5),
        data: model.sites.map((s) => ({
          name: s.name,
          value: [s.lng, s.lat, s.devices],
          itemStyle: { color: HEALTH_COLOR[s.health] },
          _site: s,
        })),
        label: {
          show: true,
          position: "right",
          formatter: (p: { data?: { _site?: GeoModel["sites"][number] } }) => p.data?._site?.name ?? "",
          fontSize: 11,
          color: fg,
        },
        tooltip: {
          formatter: (p: { data?: { _site?: GeoModel["sites"][number] } }) => {
            const s = p.data?._site;
            if (!s) return "";
            const dev = s.devices > 0 ? `${s.devices} device${s.devices === 1 ? "" : "s"}` : "site";
            return `<b>${s.name}</b><br/>${dev} · ${s.health}`;
          },
          textStyle: { color: muted },
        },
      },
    ],
  };
}

/** Compact, calm geo legend: health bands + the circuit width cue. */
function GeoLegend() {
  const bands: Health[] = ["ok", "warning", "critical", "unknown"];
  return (
    <div className="topo-geo-legend">
      {bands.map((h) => (
        <span key={h} className="topo-geo-legend-item">
          <span className="topo-geo-legend-dot" style={{ background: HEALTH_COLOR[h] }} />
          {HEALTH_LABEL[h]}
        </span>
      ))}
      <span className="topo-geo-legend-sep" />
      <span className="topo-geo-legend-item">
        <span className="topo-geo-legend-line" /> circuit · thicker = busier
      </span>
    </div>
  );
}

// ECharts click param: only the bits we read (the data payload we attached).
type GeoClickParams = {
  data?: { _site?: GeoModel["sites"][number]; _circuit?: GeoModel["circuits"][number] };
};

export default function GeoTopologyMap({ view }: { view: TopologyView }) {
  const [ready, setReady] = useState(false);
  const [selection, setSelection] = useState<TopologySelection>({});
  useEffect(() => {
    let alive = true;
    ensureWorldMap().then(() => { if (alive) setReady(true); });
    return () => { alive = false; };
  }, []);

  // Clear any open inspector when the underlying view changes.
  useEffect(() => { setSelection({}); }, [view]);

  const model = useMemo(() => topologyToEchartsGeo(view), [view]);
  const option = useMemo(() => buildOption(model), [model]);

  const onEvents = useMemo(
    () => ({
      click: (p: GeoClickParams) => {
        if (p.data?._site) setSelection({ nodeId: p.data._site.id });
        else if (p.data?._circuit) setSelection({ edgeId: p.data._circuit.id });
      },
    }),
    [],
  );

  if (!ready) {
    return <div className="topo-geo-loading">Loading basemap…</div>;
  }

  if (model.sites.length === 0) {
    return (
      <div className="topo-geo-empty">
        <div className="topo-geo-empty-title">No sites have coordinates yet</div>
        <div className="topo-geo-empty-hint">
          The geo view places sites from intent data — latitude / longitude set on each site in the
          Source of Truth (decimal WGS-84). GeoIP is never used.
        </div>
        <a className="topo-geo-empty-link" href="#/automation/sot">Open Source of Truth →</a>
      </div>
    );
  }

  return (
    <div className="topo-geo-wrap">
      <ReactECharts
        option={option}
        style={{ height: "100%", width: "100%" }}
        notMerge
        onEvents={onEvents}
      />
      <GeoLegend />
      {model.unplaced > 0 && (
        <div className="topo-geo-note">
          {model.unplaced} node{model.unplaced === 1 ? "" : "s"} not placed (no coordinates) — set them in the Source of Truth.
        </div>
      )}
      {(selection.nodeId || selection.edgeId) && (
        <TopologySideDrawer view={view} selection={selection} onClose={() => setSelection({})} />
      )}
    </div>
  );
}
