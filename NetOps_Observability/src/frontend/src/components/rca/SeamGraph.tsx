import ReactECharts from "echarts-for-react";
import { useMemo } from "react";
import { CorrEdge, Seam } from "../../services/api";
import { chartBase } from "../../theme/charts";
import { C, entityLabel, kindLabel, seamOwnerLabel, visibilityLabel, seamOwnerColor } from "./labels";

// SeamGraph — the SECONDARY (but honest) RCA view: the engine's grounded causal
// graph. Every edge is grounded (the engine never emits an ungrounded one). When
// an edge is grounded by a SEAM (ownership-transition boundary), the seam is
// drawn as a labeled boundary node ON the causal path, annotated with its owner
// (who to call) and visibility (how much we can see across it). Direction arrows
// appear ONLY where the engine claimed direction (direction_conf + basis) — for
// blind/partial seams the engine withholds direction, so we draw undirected.
// We render engine-recorded fields only; we never infer causality here.

// Seam owner colors live in labels.ts (seamOwnerColor) — one source of truth
// shared with the summary mini-graph and the relationship preview.

// An edge is drawn directed only if the engine was confident AND it had a real
// directional basis. The visibility cap on blind/partial seams is already baked
// into direction_conf by the engine — we honor it, we don't recompute it.
const DIR_FLOOR = 0.5;

function episodeLabel(key: string, view: "operator" | "debug"): string {
  // key = "entity_type:entity_id...:kind" — entity_id may itself contain ':'.
  const parts = key.split(":");
  if (parts.length < 2) return key;
  const kind = parts[parts.length - 1];
  const entity = parts.slice(1, -1).join(":") || parts[0];
  // Operator View: friendly entity name + readable signal kind, no raw ids /
  // storage names. Debug View: raw entity + raw kind.
  const ent = view === "debug" ? entity : entityLabel(entity);
  const k = view === "debug" ? kind.replace(/_/g, " ") : kindLabel(kind);
  return `${ent}\n${k}`;
}

// entity_id embedded in an episode node key (for timeline cross-highlight).
export function episodeEntity(key: string): string {
  const parts = key.split(":");
  return parts.length < 2 ? key : parts.slice(1, -1).join(":") || parts[0];
}

function seamLabel(ref: string, seam: Seam | undefined, view: "operator" | "debug"): string {
  if (!seam) return view === "debug" ? `${ref}\n(seam)` : "provider boundary";
  if (view === "debug") return `◆ ${seam.seam_id}\n${seam.control_plane_owner} · ${seam.visibility}`;
  // Operator: NOC owner + visibility, no raw seam id / engine vocabulary.
  const head = seam.display_name || "provider boundary";
  return `◆ ${head}\n${seamOwnerLabel(seam.control_plane_owner)} · ${visibilityLabel(seam.visibility)}`;
}

export default function SeamGraph({
  edges,
  seams,
  onSelectEdge,
  view = "operator",
  height = 360,
}: {
  edges: CorrEdge[];
  seams: Record<string, Seam>;
  onSelectEdge?: (edge: CorrEdge | null) => void;
  view?: "operator" | "debug";
  height?: number;
}) {
  const { nodes, links } = useMemo(() => {
    const nodes: any[] = [];
    const links: any[] = [];
    const seen = new Set<string>();
    const addEpisode = (key: string) => {
      if (seen.has(key)) return;
      seen.add(key);
      nodes.push({
        id: key, name: episodeLabel(key, view), symbolSize: 26, category: "episode",
        itemStyle: { color: "#222a3a", borderColor: C.muted, borderWidth: 1 },
        _kind: "episode", _key: key,
      });
    };
    // color/dashed override the grounding_kind defaults — seam links are tinted by
    // the boundary OWNER (whose domain) and dashed past the boundary when our
    // visibility is limited (blind/partial), an honest "we can't fully see across".
    const mkLink = (source: string, target: string, e: CorrEdge, directed: boolean, color?: string, dashed?: boolean) => ({
      source, target,
      lineStyle: {
        width: Math.max(1, Math.min(8, e.weight * 8)),
        color: color ?? (e.grounding_kind === "seam" ? C.warn : "#5a6472"),
        type: dashed ? "dashed" : (e.grounding_kind === "seam" ? "solid" : "dashed"),
        curveness: 0.12, opacity: 0.85,
      },
      symbol: directed ? ["none", "arrow"] : ["none", "none"],
      symbolSize: 9,
      _edge: e,
    });

    for (const e of edges) {
      addEpisode(e.from_node);
      addEpisode(e.to_node);
      const directed = e.direction_conf >= DIR_FLOOR && e.direction_basis !== "none";
      if (e.grounding_kind === "seam") {
        const sid = "seam:" + e.grounding_ref;
        const seam = seams[e.grounding_ref];
        const ownerColor = seamOwnerColor(seam?.control_plane_owner);
        const vis = seam?.visibility ?? "";
        const limited = vis === "partial" || vis === "blind"; // can't fully see across
        if (!seen.has(sid)) {
          seen.add(sid);
          // Diamond filled by owner; border encodes visibility (full = solid owner,
          // partial = dashed caution, blind = dotted critical — flagged, not hidden).
          const visBorder =
            vis === "full" ? { borderColor: ownerColor, borderType: "solid", borderWidth: 1 }
            : vis === "partial" ? { borderColor: C.caution, borderType: "dashed", borderWidth: 2 }
            : vis === "blind" ? { borderColor: C.crit, borderType: "dotted", borderWidth: 2.5 }
            : { borderColor: C.muted, borderType: "solid", borderWidth: 1 };
          nodes.push({
            id: sid, name: seamLabel(e.grounding_ref, seam, view), symbol: "diamond", symbolSize: 46,
            category: "seam",
            itemStyle: { color: ownerColor, ...visBorder },
            label: { fontSize: 10, fontWeight: 600 },
            _kind: "seam", _ref: e.grounding_ref, _seam: seam,
          });
        }
        // The seam sits ON the path: from → [seam boundary] → to. Our side → boundary
        // is solid (we see it); beyond the boundary is dashed when visibility is
        // limited. Direction (if claimed) rides the exit leg, since causality crosses.
        links.push(mkLink(e.from_node, sid, e, false, ownerColor, false));
        links.push(mkLink(sid, e.to_node, e, directed, ownerColor, limited));
      } else {
        links.push(mkLink(e.from_node, e.to_node, e, directed));
      }
    }
    return { nodes, links };
  }, [edges, seams, view]);

  if (edges.length === 0) {
    return (
      <div className="empty" style={{ fontSize: 12 }}>
        {view === "debug"
          ? <>No grounded causal edges to draw. This is a <b>singleton object</b> — opened on a single high-severity episode alone. The engine admits an edge only with seam or explicit topology grounding, so a lone episode (or co-occurrences it couldn&apos;t ground) produces no graph. See the timeline above for the concurrent signals and why each was not linked.</>
          : <>Nothing to relate yet — this issue rests on a single sign, with no second piece of evidence on the same path or boundary to link it to. See the evidence timeline above for what else was seen in this window and why it wasn&apos;t related.</>}
      </div>
    );
  }

  return (
    <ReactECharts
      style={{ height }}
      notMerge
      option={{
        ...chartBase,
        tooltip: {
          ...chartBase.tooltip,
          formatter: (p: any) => {
            if (p.dataType === "node") {
              if (p.data._kind === "seam") {
                const s: Seam | undefined = p.data._seam;
                if (view === "debug") {
                  const eps = s?.endpoints ? Object.entries(s.endpoints).map(([k, v]) => `${k}=${v}`).join("<br/>") : "";
                  return `<b>seam ${p.data._ref}</b><br/>owner: <b>${s?.control_plane_owner ?? "?"}</b><br/>visibility: <b>${s?.visibility ?? "?"}</b>${eps ? "<br/>" + eps : ""}`;
                }
                // Operator: NOC owner + visibility, no raw id / endpoints.
                const head = s?.display_name || "Provider boundary";
                return `<b>${head}</b><br/>owner: <b>${seamOwnerLabel(s?.control_plane_owner)}</b><br/>${visibilityLabel(s?.visibility) || "visibility unknown"}`;
              }
              // episode node: friendly entity → kind in operator, raw key in debug.
              if (view === "debug") return `<b>${p.data._key}</b>`;
              return `<b>${episodeLabel(p.data._key, "operator").replace("\n", " · ")}</b>`;
            }
            const e: CorrEdge = p.data._edge;
            if (!e) return "";
            const dirDebug = e.direction_conf >= DIR_FLOOR && e.direction_basis !== "none"
              ? `direction: ${e.direction_basis} (conf ${e.direction_conf.toFixed(2)})`
              : "direction: unclaimed (uncertain / capped by visibility)";
            // Operator: relationship + direction, no raw ref / weight math / engine terms.
            if (view !== "debug") {
              const g = e.grounding_kind === "seam" ? "Related through provider boundary" : "Related on the same path / device area";
              const dir = e.direction_conf >= DIR_FLOOR && e.direction_basis !== "none"
                ? "direction shown (we're confident)" : "direction not shown (uncertain / limited visibility)";
              return `${g}<br/>${dir}`;
            }
            const dir = dirDebug;
            return `grounding: <b>${e.grounding_kind}</b>:${e.grounding_ref}<br/>weight ${e.weight.toFixed(2)} (t ${e.w_temporal.toFixed(2)} · topo ${e.w_topo.toFixed(2)} · ×${e.w_reinforce.toFixed(2)})<br/>${dir}`;
          },
        },
        legend: { show: false },
        series: [{
          type: "graph", layout: "force", roam: true, draggable: true,
          force: { repulsion: 220, edgeLength: 110, gravity: 0.08 },
          label: { show: true, position: "right", fontSize: 10, color: "var(--fg,#e6edf3)" },
          edgeSymbol: ["none", "arrow"], edgeSymbolSize: 9,
          emphasis: { focus: "adjacency", lineStyle: { width: 4 } },
          data: nodes, links,
        }],
      }}
      onEvents={{
        click: (p: any) => {
          if (p.dataType === "edge" && p.data?._edge) onSelectEdge?.(p.data._edge);
          else onSelectEdge?.(null);
        },
      }}
    />
  );
}
