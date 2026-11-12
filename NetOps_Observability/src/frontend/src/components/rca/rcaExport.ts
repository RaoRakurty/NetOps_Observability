// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import type { RcaCase, RcaPill, KV, Tone, CaseEvent } from "./rcaCase";
import type { ShapeKind } from "../graph/shapes";
import type { TopoGraph, TopoGraphNode, EdgeState } from "./topoGraph";
import { deriveContextModel, type ContextModel, type DevicePanelView, type OverlayTone } from "./pathModel";
import {
  type TopologyContext, topoStateLabel, topoSourcesLine, topoSourceLabel, readAndEmptySources,
  unreadSources, causalRelationLabel, topoTS, humanWord, interfaceFaults,
} from "./topologyContext";
import { fmtDateTime } from "../../lib/time";
import { rcaVerdictLine } from "./labels";
import { fidelityLabel } from "../../lib/fidelity";
import type { RcaFeedback } from "../../services/api";

// rcaExport — generates an elegant, light-themed, print-ready RCA report and
// opens it for the browser's "Save as PDF". No PDF dependency: a self-contained
// HTML document + print CSS.
//
// SINGLE SOURCE OF TRUTH: the report is rendered from the SAME `RcaCase` the
// on-screen workspace renders (see rcaCase.ts / RcaWorkspace.tsx), so the PDF
// always matches the page and includes every section — summary, impact, causal
// topology, evidence matrix, confidence ladder, hypothesis ranking, ticket, and
// next actions. The product name appears only in the report header/footer
// metadata (allowed in exports), never in the operator narrative.

const esc = (s: string) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

// tone → print colour (matches the on-screen .rca-ws palette)
const TONE: Record<Tone, { fg: string; bg: string; bd: string }> = {
  green: { fg: "#0f9f4f", bg: "#eafaf1", bd: "#bfeccf" },
  orange: { fg: "#d66a00", bg: "#fff4e8", bd: "#ffd3a9" },
  blue: { fg: "#2563eb", bg: "#eef4ff", bd: "#c9dbff" },
  red: { fg: "#d92d20", bg: "#fff0ee", bd: "#ffd0cc" },
  gray: { fg: "#667085", bg: "#eef1f6", bd: "#d8dee8" },
  purple: { fg: "#6d5dfc", bg: "#f3f1ff", bd: "#ddd7ff" },
};
const EDGE: Record<string, string> = { good: "#22c55e", warn: "#f59e0b", bad: "#ef4444" };

const pill = (p: RcaPill) => {
  const t = TONE[p.tone] ?? TONE.gray;
  return `<span style="font-size:11px;font-weight:800;padding:3px 8px;border-radius:7px;background:${t.bg};color:${t.fg};border:1px solid ${t.bd};white-space:nowrap">${esc(p.text)}</span>`;
};
const kvRows = (rows: KV[]) => rows.map((r) =>
  `<div class="kv"><span class="k">${esc(r.k)}</span><span class="v"${r.mono ? ' style="font-family:ui-monospace,monospace"' : ""}>${esc(r.v)}</span></div>`).join("");
const block = (label: string, body: string) => body ? `<section><h2>${esc(label)}</h2>${body}</section>` : "";

const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

// Event timeline (owner P1 2026-07-19) — the chronological timestamped case
// events, printed as a two-column table. UTC (documents are timezone-pinned).
const eventsTable = (evs?: CaseEvent[]): string => !evs || evs.length === 0 ? "" :
  `<table><thead><tr><th style="width:158px">Time</th><th>Event</th></tr></thead><tbody>` +
  evs.map((e) =>
    `<tr><td style="font-family:ui-monospace,monospace;white-space:nowrap">${esc(fmtDateTime(e.ts, { mode: "utc" }))}</td>` +
    `<td>${esc(e.label)}${e.detail ? ` <span style="color:#64748b">· ${esc(e.detail)}</span>` : ""}</td></tr>`).join("") +
  `</tbody></table>`;

// shapeInner — the device-type geometry in a 0 0 100 100 box, mirroring the
// on-screen shape kit (shapes.tsx): device TYPE = shape, health = colour. Light
// theme: faint tone fill + toned stroke. No glyphs (print-safe; the geometry
// alone reads the type, and missing-font glyphs would tofu).
function shapeInner(kind: ShapeKind, fill: string, stroke: string): string {
  const sw = 5;
  switch (kind) {
    case "core": return `<circle cx="50" cy="50" r="42" fill="${fill}" stroke="${stroke}" stroke-width="${sw}"/><circle cx="50" cy="50" r="29" fill="none" stroke="${stroke}" stroke-width="2.5" opacity="0.6"/>`;
    case "router": return `<circle cx="50" cy="50" r="42" fill="${fill}" stroke="${stroke}" stroke-width="${sw}"/>`;
    case "switch": case "access": return `<polygon points="50,8 88,29 88,71 50,92 12,71 12,29" fill="${fill}" stroke="${stroke}" stroke-width="${sw}" stroke-linejoin="round"/>`;
    case "firewall": return `<path d="M50 7 L86 21 V51 C86 73 69 88 50 95 C31 88 14 73 14 51 V21 Z" fill="${fill}" stroke="${stroke}" stroke-width="${sw}" stroke-linejoin="round"/>`;
    case "gateway": return `<polygon points="50,6 94,50 50,94 6,50" fill="${fill}" stroke="${stroke}" stroke-width="${sw}" stroke-linejoin="round"/>`;
    case "server": return `<rect x="22" y="12" width="56" height="76" rx="12" fill="${fill}" stroke="${stroke}" stroke-width="${sw}"/>`;
    case "cloud": return `<path d="M28 74 C16 74 12 58 24 54 C20 38 44 30 52 42 C58 30 82 34 80 52 C92 54 90 74 76 74 Z" fill="${fill}" stroke="${stroke}" stroke-width="${sw}" stroke-linejoin="round"/>`;
    case "vantage": return `<circle cx="50" cy="50" r="42" fill="none" stroke="${stroke}" stroke-width="2" opacity="0.4"/><circle cx="50" cy="50" r="28" fill="none" stroke="${stroke}" stroke-width="2.5" opacity="0.7"/><circle cx="50" cy="50" r="13" fill="${fill}" stroke="${stroke}" stroke-width="${sw}"/>`;
    case "target": return `<circle cx="50" cy="50" r="42" fill="${fill}" stroke="${stroke}" stroke-width="${sw}"/><circle cx="50" cy="50" r="26" fill="none" stroke="${stroke}" stroke-width="3" opacity="0.7"/><circle cx="50" cy="50" r="10" fill="${stroke}"/>`;
    // blind hop (no response / filtered) — dashed outline, never a solid device
    case "unknown": return `<circle cx="50" cy="50" r="40" fill="${fill}" stroke="${stroke}" stroke-width="4" stroke-dasharray="9 7" stroke-linecap="round"/>`;
    // off-spine evidence branch (metrics/logs/flows/alerts/traces) — a note, not a device
    case "evidence": return `<rect x="14" y="20" width="72" height="60" rx="9" fill="${fill}" stroke="${stroke}" stroke-width="4"/>`;
    default: return `<circle cx="50" cy="50" r="42" fill="${fill}" stroke="${stroke}" stroke-width="${sw}"/>`;
  }
}

// ── Network topology & causality — from the server's topology context ────────
// RCA document v2 §2: the print fallback draws the SAME struct the screen and
// the server PDF draw (topologyContext.ts), with the SAME geometry
// (pathModel.ts deriveContextModel mirrors rca_report_html_topology.go). The
// words are the server partial's words. The old client-side "affected devices"
// chain (topoSvg) is gone: it drew a node the server PDF denied.

// The server report's print palette (rca_report_html_topology.go).
const TP = {
  ink: "#172033", muted: "#64748b", link: "#94a3b8", linkDim: "#cbd5e1", nodeFill: "#f8fafc",
  amber: "#b45309", amberBg: "#fff4e8", red: "#b42318", redBg: "#fff0ee", unknown: "#475467",
};
function tpTone(t: OverlayTone): { fill: string; stroke: string } {
  return t === "red" ? { fill: TP.redBg, stroke: TP.red } : t === "amber" ? { fill: TP.amberBg, stroke: TP.amber } : { fill: TP.nodeFill, stroke: TP.muted };
}
function tpArrow(x1: number, y1: number, x2: number, y2: number, colour: string): string {
  const dx = x2 - x1, dy = y2 - y1, l = Math.hypot(dx, dy);
  if (l === 0) return "";
  const ux = dx / l, uy = dy / l, size = 7;
  const bx = x2 - ux * size, by = y2 - uy * size, px = -uy * size * 0.5, py = ux * size * 0.5;
  return `<polygon points="${x2.toFixed(1)},${y2.toFixed(1)} ${(bx + px).toFixed(1)},${(by + py).toFixed(1)} ${(bx - px).toFixed(1)},${(by - py).toFixed(1)}" fill="${colour}"/>`;
}
function tpCausal(x1: number, y1: number, x2: number, y2: number, rel: string, directed: boolean): string {
  let colour = TP.unknown, dash = ` stroke-dasharray="1.5 3"`;
  if (rel === "verified") { colour = TP.red; dash = ""; }
  else if (rel === "suspected") { colour = TP.amber; dash = ` stroke-dasharray="6 4"`; }
  let out = `<line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" stroke="${colour}" stroke-width="1.8"${dash}/>`;
  if (directed && rel !== "unknown") out += tpArrow(x1, y1, x2, y2, colour);
  if (rel === "unknown") {
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
    out += `<circle cx="${mx.toFixed(1)}" cy="${my.toFixed(1)}" r="6.5" fill="#fff" stroke="${colour}" stroke-width="1"/><text x="${mx.toFixed(1)}" y="${(my + 3.2).toFixed(1)}" text-anchor="middle" font-size="9" font-weight="800" fill="${colour}">?</text>`;
  }
  return out;
}
const tpSvgOpen = (w: number, h: number, label: string) =>
  `<svg viewBox="0 0 ${w} ${h.toFixed(0)}" width="100%" style="max-width:760px;display:block;margin:8px auto 2px" role="img" aria-label="${esc(label)}">`;

function egoSvg(ego: NonNullable<ContextModel["ego"]>): string {
  let b = tpSvgOpen(ego.w, ego.h, "Known topology around the affected devices with fault and causal overlays");
  for (const e of ego.edges) {
    const st = e.edge.stale ? `stroke="${TP.linkDim}" stroke-width="1.5" stroke-dasharray="2 3"` : `stroke="${TP.link}" stroke-width="1.5"`;
    b += `<line x1="${e.x1.toFixed(1)}" y1="${e.y1.toFixed(1)}" x2="${e.x2.toFixed(1)}" y2="${e.y2.toFixed(1)}" ${st}/>`;
    if (e.unknownMark) b += tpCausal(e.unknownMark.x1, e.unknownMark.y1, e.unknownMark.x2, e.unknownMark.y2, "unknown", false);
  }
  for (const c of ego.causal) b += tpCausal(c.x1, c.y1, c.x2, c.y2, c.relation, c.directed);
  for (const n of ego.nodes) {
    const { fill, stroke } = tpTone(n.tone);
    b += `<circle cx="${n.x.toFixed(1)}" cy="${n.y.toFixed(1)}" r="${n.r}" fill="${fill}" stroke="${stroke}" stroke-width="2"${n.node.managed ? "" : ` stroke-dasharray="3 2"`}/>`;
    if (n.node.stale) b += `<text x="${n.x.toFixed(1)}" y="${(n.y + 3).toFixed(1)}" text-anchor="middle" font-size="7.5" fill="${TP.muted}">stale</text>`;
    b += `<text x="${n.x.toFixed(1)}" y="${(n.y + n.r + 11).toFixed(1)}" text-anchor="middle" font-size="9" font-weight="700" fill="${TP.ink}">${esc(clip(n.node.label, 22))}</text>`;
    if (n.roleText) b += `<text x="${n.x.toFixed(1)}" y="${(n.y + n.r + 21).toFixed(1)}" text-anchor="middle" font-size="7.5" fill="${TP.muted}">${esc(clip(n.roleText, 26))}</text>`;
    if (n.anomalousPorts.length) b += `<text x="${n.x.toFixed(1)}" y="${(n.y - n.r - 5).toFixed(1)}" text-anchor="middle" font-size="7.5" font-weight="700" fill="${stroke}">anomalous: ${esc(clip(n.anomalousPorts.join(" · "), 40))}</text>`;
  }
  return b + "</svg>";
}

function panelSvg(p: DevicePanelView): string {
  let b = tpSvgOpen(p.w, p.h, "Affected device, its evidence interfaces and the causal marks between them");
  const dev = tpTone(p.devTone);
  for (const c of p.connectors) {
    b += c.relation
      ? tpCausal(c.x1, c.y1, c.x2, c.y2, c.relation, c.directed)
      : `<line x1="${c.x1.toFixed(1)}" y1="${c.y1.toFixed(1)}" x2="${c.x2.toFixed(1)}" y2="${c.y2.toFixed(1)}" stroke="${TP.linkDim}" stroke-width="1"/>`;
  }
  for (const a of p.arcs) {
    const colour = a.relation === "verified" ? TP.red : TP.amber;
    const dash = a.relation === "verified" ? "" : ` stroke-dasharray="6 4"`;
    b += `<path d="M ${a.x.toFixed(1)} ${a.y1.toFixed(1)} C ${a.bulge.toFixed(1)} ${a.y1.toFixed(1)} ${a.bulge.toFixed(1)} ${a.y2.toFixed(1)} ${(a.x + 2).toFixed(1)} ${a.y2.toFixed(1)}" fill="none" stroke="${colour}" stroke-width="1.6"${dash}/>`;
    b += tpArrow(a.bulge, a.y2, a.x + 2, a.y2, colour);
  }
  const cx = p.dev.x + p.dev.w / 2, cy = p.dev.y + p.dev.h / 2;
  b += `<rect x="${p.dev.x}" y="${p.dev.y.toFixed(1)}" width="${p.dev.w}" height="${p.dev.h}" rx="8" fill="${dev.fill}" stroke="${dev.stroke}" stroke-width="2"/>`;
  b += `<text x="${cx.toFixed(1)}" y="${(cy - 9).toFixed(1)}" text-anchor="middle" font-size="10.5" font-weight="800" fill="${TP.ink}">${esc(clip(p.node.label, 30))}</text>`;
  b += `<text x="${cx.toFixed(1)}" y="${(cy + 4).toFixed(1)}" text-anchor="middle" font-size="8" fill="${TP.muted}">${esc(clip(p.roleText, 36))}</text>`;
  if (p.devKinds.length) b += `<text x="${cx.toFixed(1)}" y="${(cy + 17).toFixed(1)}" text-anchor="middle" font-size="7.5" font-weight="700" fill="${dev.stroke}">${esc(clip("device: " + p.devKinds.map(humanWord).join(", "), 44))}</text>`;
  for (const pt of p.ports) {
    const t = tpTone(pt.tone);
    const y = pt.y + pt.h / 2;
    b += `<rect x="${pt.x}" y="${pt.y.toFixed(1)}" width="${pt.w}" height="${pt.h}" rx="5" fill="${t.fill}" stroke="${t.stroke}" stroke-width="1.6"/>`;
    b += `<text x="${pt.x + 8}" y="${(y + 3.5).toFixed(1)}" font-size="9" font-weight="800" font-family="ui-monospace,monospace" fill="${TP.ink}">${esc(clip(pt.fault.port || pt.fault.target_id, 14))}</text>`;
    b += `<text x="${pt.x + pt.w - 7}" y="${(y + 3.5).toFixed(1)}" text-anchor="end" font-size="7.5" fill="${t.stroke}">${esc(clip(pt.fault.kinds.map(humanWord).join(", ") + " · " + pt.fault.peak_severity.toUpperCase(), 30))}</text>`;
  }
  if (p.ports.length === 0) b += `<text x="470" y="${(cy + 3).toFixed(1)}" font-size="9" fill="${TP.muted}">No interface carries attached evidence.</text>`;
  b += "</svg>";
  const notes: string[] = [];
  if (p.morePorts > 0) notes.push(`${p.morePorts} more evidence interface(s) are listed in the table.`);
  if (p.undirectedPortPairs > 0) notes.push(`${p.undirectedPortPairs} undirected interface ↔ interface co-occurrence(s) (relationship unknown) are listed in the causal table.`);
  return b + (notes.length ? `<p class="note">${esc(notes.join(" "))}</p>` : "");
}

/** The print body of the topology section — exported for the parity tests. */
export function topologyContextHtml(tc: TopologyContext | undefined, spine?: TopoGraph): string {
  if (!tc) {
    return `${spine && spine.nodes.length ? topoGraphSvg(spine) : ""}<p class="note">The topology context was not built for this document.</p>`;
  }
  const m = deriveContextModel(tc);
  let b = "";
  b += `<p class="body">State: <b>${esc(topoStateLabel(tc.state))}</b> — ${esc(tc.reason)}</p>`;
  if (tc.state === "no_asset_mapping") {
    b += `<div class="decision" style="border-left-color:#b42318;background:#fff5f4;border-color:#ffb5ad"><b>Data-availability error</b> — the affected entity could not be placed in the network topology. This is a gap in the data, not a finding about the network.${tc.unmapped.length ? ` Not in the inventory: ${esc(tc.unmapped.join(", "))}.` : ""}</div>`;
  } else {
    if (tc.state === "topology_with_path" && spine && spine.nodes.length) b += `<p class="note"><b>Measured path</b></p>${topoGraphSvg(spine)}`;
    if (m.ego) {
      b += egoSvg(m.ego);
      b += `<p class="note">Legend: grey line = known link (dotted = stale) · amber/red device or port = anomalous evidence observed there (no causation implied) · <b>solid arrow</b> = verified causal link · <b>dashed arrow</b> = suspected · <b>?</b> = relationship unknown.${tc.state === "topology_only" ? " No measured path is attached: the causal path across this topology is <b>unverified</b>." : ""}${tc.more_nodes ? ` ${tc.more_nodes} more neighbour(s) not drawn.` : ""}</p>`;
    } else if (tc.state === "topology_only") {
      b += `<p class="note">No measured path is attached: the causal path across this topology is <b>unverified</b>.</p>`;
    }
    for (const p of m.panels) b += panelSvg(p);
    if (m.panelsCapped) b += `<p class="note">Detail panels are drawn for the first 3 affected devices; the tables list every one.</p>`;
    if (tc.state === "device_only") {
      const empty = readAndEmptySources(tc).map((s) => topoSourceLabel(s.kind)).join(", ") || "—";
      const unread = unreadSources(tc).map((s) => topoSourceLabel(s.kind)).join(", ") || "none";
      for (const n of tc.nodes.filter((x) => x.anchor)) {
        const ports = interfaceFaults(tc, n.id).map((f) => `${esc(f.port || f.target_id)} <span style="color:#64748b">(${esc(f.kinds.map(humanWord).join(", "))})</span>`).join(" · ") || "none";
        const seen = n.stale ? `stale${n.last_seen ? ` — last seen ${esc(topoTS(n.last_seen))}` : ""}` : n.last_seen ? `current — seen by its inventory source${n.first_seen ? ` (known since ${esc(topoTS(n.first_seen))})` : ""}` : "not recorded";
        b += `<div class="decision" style="margin-top:6px"><b>Device diagnostic — ${esc(n.label)}</b>` +
          kvRows([{ k: "Device", v: n.label }, { k: "Role", v: n.role ? humanWord(n.role) : "not classified" }, { k: "Source", v: topoSourceLabel(n.source) }]) +
          `<div class="kv"><span class="k">Last seen</span><span class="v">${seen}</span></div>` +
          `<div class="kv"><span class="k">Evidence interfaces</span><span class="v">${ports}</span></div>` +
          `<div class="kv"><span class="k">Read and empty</span><span class="v" style="font-weight:400">${esc(empty)}</span></div>` +
          `<div class="kv"><span class="k">Could not be read</span><span class="v" style="font-weight:400">${esc(unread)}</span></div></div>`;
      }
    }
    if (tc.faults.length) {
      b += `<table style="margin-top:6px"><thead><tr><th>Where (measured)</th><th>Evidence kinds</th><th>Peak severity</th><th>Observations</th></tr></thead><tbody>` +
        tc.faults.map((f) => `<tr><td>${f.target_type === "interface" ? `${esc(f.device)} · <span style="font-family:ui-monospace,monospace">${esc(f.port || "")}</span>` : `${esc(f.device)} (device)`}</td><td>${esc(f.kinds.map(humanWord).join(", "))}</td><td>${esc(f.peak_severity.toUpperCase())}</td><td>${f.evidence_refs.length}</td></tr>`).join("") +
        `</tbody></table><p class="note">Measured fault overlay: where anomalous evidence was observed. It never implies causation on its own.</p>`;
    }
    if (tc.causal.length) {
      b += `<table style="margin-top:6px"><thead><tr><th>From → to</th><th>Causal link</th><th>Basis</th></tr></thead><tbody>` +
        tc.causal.slice(0, 30).map((c) => `<tr><td>${esc(c.from)}${c.from_kind ? ` <span style="color:#64748b">(${esc(humanWord(c.from_kind))})</span>` : ""} ${c.directed ? "→" : "—"} ${esc(c.to)}${c.to_kind ? ` <span style="color:#64748b">(${esc(humanWord(c.to_kind))})</span>` : ""}</td><td>${esc(causalRelationLabel(c.relation))}</td><td style="font-size:10.5px;color:#475467">${esc(c.basis)}</td></tr>`).join("") +
        `</tbody></table>${tc.causal.length > 30 ? `<p class="note">${tc.causal.length - 30} more causal link(s) are in the full report.</p>` : ""}`;
    }
  }
  if (tc.remediation.length) b += `<p class="body" style="margin-top:6px"><b>What would complete this picture</b></p><ol>${tc.remediation.map((r) => `<li>${esc(r)}</li>`).join("")}</ol>`;
  return b;
}

// EdgeState → the legend's light-theme edge colour (good/warn/bad). A down or
// suspected-down segment reads as the "bad" red; degraded as amber; unknown as a
// faint grey; healthy as green. Mirrors the on-screen stateColor mapping into the
// print palette so the report and the page agree.
function edgeStateColor(s: EdgeState): { col: string; legend: "good" | "warn" | "bad" | "faint" } {
  if (s === "confirmed_down" || s === "suspected_down") return { col: EDGE.bad, legend: "bad" };
  if (s === "degraded") return { col: EDGE.warn, legend: "warn" };
  if (s === "unknown") return { col: "#b7c0d0", legend: "faint" };
  return { col: EDGE.good, legend: "good" };
}

// topoGraphSvg — print-safe rendering of the SHARED RcaTopology graph (the SAME
// positioned nodes/edges the on-screen React-Flow canvas draws, built by
// buildTopoGraph). It reuses the live x/y layout, normalized + scaled to fit the
// report width; node TYPE = shape (data.kind), health = colour (data.tone, a
// theme-neutral tone legible on white); edges carry the state colour + are dashed
// when degraded/down, with the same metric labels. No scripts (CSP-safe).
function topoGraphSvg(g: TopoGraph): string {
  const nodes = g.nodes;
  if (nodes.length === 0) return "";
  const byId = new Map<string, TopoGraphNode>(nodes.map((n) => [n.id, n]));

  // node footprint in source (canvas) units, then scale to the report width.
  const ICON = 46;            // rendered icon size (px)
  const SRC_ICON = 56;        // on-canvas shape size the positions are spaced for
  const NW = 132, ROWGAP = 104, PADX = 14, PADTOP = 14, FOOT = 30;
  const xs = nodes.map((n) => n.x), ys = nodes.map((n) => n.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  const minY = Math.min(...ys), maxY = Math.max(...ys);
  // map source x-span across columns of width NW; keep relative spacing. A single
  // column collapses to one position (avoid div-by-zero).
  const spanX = Math.max(1, maxX - minX), spanY = Math.max(1, maxY - minY);
  const cols = Math.max(1, Math.round(spanX / 168) + 1);   // ~COL_HOP spacing
  const rows = Math.max(1, Math.round(spanY / ROWGAP) + 1);
  const innerW = cols * NW + (cols - 1) * 58;
  const cx = (n: TopoGraphNode) => PADX + NW / 2 + ((n.x - minX) / spanX) * (innerW - NW);
  const cy = (n: TopoGraphNode) => PADTOP + ICON / 2 + ((n.y - minY) / spanY) * ((rows - 1) * ROWGAP);
  const W = PADX * 2 + innerW;
  const H = PADTOP + (rows - 1) * ROWGAP + ICON + FOOT + 34;
  const s = ICON / 100;
  void SRC_ICON;

  const markers = ["good", "warn", "bad", "faint"].map((st) =>
    `<marker id="ahg-${st}" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="${st === "faint" ? "#b7c0d0" : EDGE[st]}"/></marker>`).join("");
  let parts = "";

  // BOUNDARY BANDS (LAN / SD-WAN / CARRIER / CLOUD) — drawn FIRST so they sit
  // behind the spine, exactly like the on-screen band layer. Grouping is decided
  // server-side (contract §7 `boundaries[]`); the report only draws it.
  const laid: { from: number; to: number; lane: number }[] = [];
  for (const b of g.bands ?? []) {
    const a = byId.get(b.fromId), z = byId.get(b.toId);
    if (!a || !z) continue;
    // boundaries may overlap (SD-WAN inside CARRIER) — nest them, same as on screen
    let lane = 0;
    while (laid.some((p) => p.lane === lane && p.from <= b.to && b.from <= p.to)) lane++;
    laid.push({ from: b.from, to: b.to, lane });
    const inset = lane * 5;
    const x0 = cx(a) - NW / 2 - 4 + inset, x1 = cx(z) + NW / 2 + 4 - inset;
    const by = PADTOP - 8 + inset, bh = ICON + 62 - inset * 2;
    parts += `<rect x="${x0}" y="${by}" width="${Math.max(24, x1 - x0)}" height="${bh}" rx="10" fill="${b.color}12" stroke="${b.color}66" stroke-dasharray="5 4"/>`;
    parts += `<text x="${x0 + 8}" y="${by + 11}" font-size="8" font-weight="800" letter-spacing="0.6" fill="${b.color}">${esc(b.name.toUpperCase())}</text>`;
  }

  // edges — straight connector trimmed to each icon's EDGE along the true edge
  // direction (not just horizontally), so arrowheads never overlap the device
  // icons whether the edge runs across, down, or diagonally.
  for (const e of g.edges) {
    const from = byId.get(e.from), to = byId.get(e.to);
    if (!from || !to) continue;
    const { col, legend } = edgeStateColor(e.state);
    const fx = cx(from), fy = cy(from), tx = cx(to), ty = cy(to);
    const dx = tx - fx, dy = ty - fy, dist = Math.hypot(dx, dy) || 1;
    const ux = dx / dist, uy = dy / dist, r = ICON / 2 + 4;
    const x1 = fx + ux * r, y1 = fy + uy * r;            // start at source icon edge
    const x2 = tx - ux * (r + 7), y2 = ty - uy * (r + 7); // stop short for the arrowhead
    const dash = legend === "good" ? "" : ` stroke-dasharray="7 5"`;
    parts += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${col}" stroke-width="${legend === "good" ? 2.2 : 3}"${dash} marker-end="url(#ahg-${legend})"/>`;
    if (e.label) {
      const lx = (x1 + x2) / 2, ly = (y1 + y2) / 2 - 7, lbl = clip(e.label, 28), tw = lbl.length * 5.4 + 12;
      parts += `<rect x="${lx - tw / 2}" y="${ly - 10}" width="${tw}" height="15" rx="7.5" fill="#fff" stroke="${col}"/>`;
      parts += `<text x="${lx}" y="${ly + 1}" text-anchor="middle" font-size="9" font-weight="800" fill="${col}">${esc(lbl)}</text>`;
    }
  }

  // nodes — device-type shape (data.kind) + label + sub + badge/chips.
  for (const n of nodes) {
    const d = n.data, x = cx(n), y = cy(n);
    const stroke = d.tone, fill = d.tone + "1f";   // faint tone wash (print-safe)
    parts += `<g transform="translate(${x - ICON / 2},${y - ICON / 2}) scale(${s})">${shapeInner(d.kind, fill, stroke)}</g>`;
    parts += `<text x="${x}" y="${y + ICON / 2 + 13}" text-anchor="middle" font-size="11.5" font-weight="800" fill="#172033"${d.mono ? ' font-family="ui-monospace,monospace"' : ""}>${esc(clip(d.label, 18))}</text>`;
    let oy = y + ICON / 2 + 25;
    if (d.sub) { parts += `<text x="${x}" y="${oy}" text-anchor="middle" font-size="9" fill="#697386">${esc(clip(d.sub, 30))}</text>`; oy += 12; }
    if (d.badge) {
      const tw = d.badge.length * 5.2 + 12;
      parts += `<rect x="${x - tw / 2}" y="${oy - 9}" width="${tw}" height="14" rx="7" fill="${d.tone}1f" stroke="${d.tone}"/>`;
      parts += `<text x="${x}" y="${oy + 1}" text-anchor="middle" font-size="8.5" font-weight="800" fill="${d.tone}">${esc(d.badge)}</text>`;
      oy += 17;
    }
    for (const chip of (d.chips ?? []).slice(0, 3)) {
      const cw = chip.length * 5 + 12;
      parts += `<rect x="${x - cw / 2}" y="${oy - 9}" width="${cw}" height="13" rx="6" fill="${d.tone}14" stroke="${d.tone}66"/>`;
      parts += `<text x="${x}" y="${oy + 0.5}" text-anchor="middle" font-size="8" font-weight="600" fill="#3a4252">${esc(clip(chip, 28))}</text>`;
      oy += 15;
    }
  }

  // legend — Healthy / Degraded / Down, matching the on-screen state colours.
  const leg: [keyof typeof EDGE | "faint", string][] = [["good", "Healthy"], ["warn", "Degraded"], ["bad", "Down / fault"]];
  let lx = PADX, legend = ""; const legendY = H - 10;
  for (const [st, lbl] of leg) {
    const col = st === "faint" ? "#b7c0d0" : EDGE[st];
    legend += `<line x1="${lx}" y1="${legendY}" x2="${lx + 18}" y2="${legendY}" stroke="${col}" stroke-width="3"${st === "good" ? "" : ` stroke-dasharray="7 5"`}/>`;
    legend += `<text x="${lx + 24}" y="${legendY + 3.5}" font-size="9" fill="#697386">${lbl}</text>`;
    lx += 24 + lbl.length * 5.4 + 22;
  }

  return `<svg viewBox="0 0 ${W} ${H}" width="100%" style="max-width:${Math.min(W, 720)}px;display:block;margin:6px auto" role="img" aria-label="Network path and causal topology"><defs>${markers}</defs>${parts}${legend}</svg>`;
}

// Exported for the report regression tests (pure: RcaCase in, document out).
export function reportHtml(d: RcaCase, objId: string, verdict?: RcaFeedback | null): string {
  // Export header time is explicit-zone (UTC) so a printed report is unambiguous.
  const now = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

  const why = d.why.map((w) => {
    const t = TONE[w.tone] ?? TONE.orange;
    return `<p class="body"><b style="color:${t.fg}">${esc(w.label)}:</b> ${esc(w.text)}</p>`;
  }).join("");

  const ladder = `<div style="display:flex;align-items:center;gap:0;flex-wrap:wrap">${
    d.ladder.map((s, i) => {
      const tone = s.state === "done" ? "#16a34a" : s.state === "active" ? "#d66a00" : "#94a3b8";
      const on = s.state !== "next";
      const chip = `<span style="font-size:11.5px;font-weight:700;padding:4px 12px;border-radius:18px;${on ? `background:${tone};color:#fff;border:1px solid ${tone}` : "color:#94a3b8;border:1px solid #cbd5e1"}">${esc(s.label)}</span>`;
      const conn = i < d.ladder.length - 1 ? `<span style="width:20px;height:2px;background:#cbd5e1"></span>` : "";
      return chip + conn;
    }).join("")
  }</div>${d.ladderNote ? `<p class="body" style="margin-top:10px;color:#b45309"><b>${esc(d.ladderNote)}</b></p>` : ""}`;

  // The printed matrix carries the SAME row attribution chips and the SAME
  // fidelity wording the screen shows — a report that quietly dropped the grade
  // would let a reader over-trust a code-only rule. A row without a grade prints
  // an em dash: the platform does not know, and does not pretend to.
  const evidence = `<table><thead><tr><th>Evidence type</th><th>Covers</th><th>Finding</th><th>Rule fidelity</th><th>Status</th></tr></thead><tbody>${
    d.evidence.map((e) => {
      const chips = e.chips?.length
        ? `<div style="color:#475569;font-size:10.5px;margin-top:2px">${esc(e.chips.join(" · "))}</div>`
        : "";
      const fid = e.fidelity ? esc(fidelityLabel(e.fidelity)) : "&mdash;";
      return `<tr><td>${esc(e.title)}</td><td style="color:#64748b">${esc(e.desc)}${chips}</td><td>${esc(e.finding)}</td><td>${fid}</td><td>${pill(e.pill)}</td></tr>`;
    }).join("")
  }</tbody></table>`;

  const hypotheses = d.hypotheses.length ? `<table><thead><tr><th>Rank</th><th>Hypothesis</th><th>Confidence</th><th>Reason</th></tr></thead><tbody>${
    d.hypotheses.map((h) => `<tr><td style="font-family:ui-monospace,monospace;font-weight:800">${esc(h.rank)}</td><td><b>${esc(h.hypo)}</b><div style="color:#697386;font-size:11px">${esc(h.sub)}</div></td><td>${pill(h.conf)}</td><td>${esc(h.reason)}</td></tr>`).join("")
  }</tbody></table>` : "";

  const ticket = `<div class="decision" style="${d.ticket.callout.tone === "red" ? "border-left-color:#b91c1c" : d.ticket.callout.tone === "confirmed" ? "border-left-color:#0f9f4f;background:#f2fbf6;border-color:#b9e5c7" : ""}"><b>${esc(d.ticket.callout.strong)}</b> ${esc(d.ticket.callout.text)}</div>${kvRows(d.ticket.rows)}`;

  const actions = `<ol>${d.nextActions.map((a) => `<li><b>${esc(a.badge)}</b> — ${esc(a.text)}</li>`).join("")}</ol>`;

  // Operator verdict (Project 2 P7) — the LATEST recorded human judgement of
  // this case, printed verbatim from the same formatter the screen uses. A
  // report that an operator marked wrong must say so on its face; when nobody
  // has judged the case, nothing is printed (silence, never an invented "n/a").
  const verdictFb = verdict ? `<div class="verdict-fb">${esc(rcaVerdictLine(verdict, { utc: true }))}</div>` : "";

  return `<!doctype html><html><head><meta charset="utf-8"><title>RCA Report — ${esc(d.title)}</title>
<style>
  @page { size: A4; margin: 16mm 14mm; }
  /* force background colours/graphics (pills, callouts, table headers, topology
     node fills) to print — browsers drop backgrounds by default on Save-as-PDF. */
  * { box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  /* color-scheme: an about:blank popup/iframe INHERITS the opener's color-scheme
     (dark app theme → dark canvas). This is a light paper document — pin it. */
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; color-scheme: light; background: #fff; }
  body { font: 13px/1.5 Inter, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #172033; margin: 0; background: #fff; }
  .doc { max-width: 740px; margin: 0 auto; padding: 8px 0 32px; }
  header.rpt { display:flex; justify-content:space-between; align-items:flex-start; border-bottom: 2px solid #172033; padding-bottom: 10px; margin-bottom: 16px; }
  header.rpt .brand { font-weight: 800; letter-spacing: .5px; font-size: 13px; color:#334155; }
  header.rpt .doctype { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color:#64748b; }
  h1 { font-size: 21px; margin: 0 0 8px; }
  .badges { display:flex; gap:6px; flex-wrap:wrap; align-items:center; margin-bottom: 8px; }
  .meta { font-size:11.5px; color:#64748b; margin-bottom: 12px; }
  .meta b { color:#172033; font-family:ui-monospace,monospace; }
  section { margin: 13px 0; }
  h2 { font-size: 11px; text-transform: uppercase; letter-spacing: .7px; color:#64748b; margin: 0 0 6px; border-bottom:1px solid #e2e8f0; padding-bottom:3px; }
  .kv { display:flex; gap:10px; padding:1px 0; }
  .kv .k { color:#64748b; min-width: 150px; }
  .kv .v { color:#172033; font-weight:600; }
  p.body { margin: 3px 0; }
  p.note { margin: 3px 0; font-size: 11px; color: #64748b; }
  .verdict-fb { font-size:11.5px; color:#334155; background:#f8fafc; border:1px solid #e2e8f0; border-left:3px solid #64748b; border-radius:6px; padding:7px 11px; margin-bottom:12px; }
  .decision { background:#fff7ed; border:1px solid #fed7aa; border-left:3px solid #d66a00; border-radius:6px; padding:9px 12px; margin-bottom:6px; }
  table { width:100%; border-collapse: collapse; font-size:12px; }
  th, td { text-align:left; padding:5px 8px; border-bottom:1px solid #e2e8f0; vertical-align:top; }
  th { color:#64748b; font-weight:700; font-size:10.5px; text-transform:uppercase; letter-spacing:.5px; background:#f8fafc; }
  ol { margin:4px 0; padding-left: 20px; } ol li { margin: 3px 0; }
  ol li b { color:#1d55d7; font-size:11px; }
  footer.rpt { margin-top: 22px; border-top:1px solid #e2e8f0; padding-top:8px; font-size:10.5px; color:#94a3b8; display:flex; justify-content:space-between; }
  .toolbar { position: sticky; top: 0; z-index: 10; display:flex; gap:8px; justify-content:flex-end; padding:10px 14px; background:#f1f5f9; border-bottom:1px solid #e2e8f0; }
  .toolbar button { font:600 13px/1 inherit; padding:8px 16px; border-radius:6px; cursor:pointer; border:1px solid #cbd5e1; background:#fff; color:#172033; }
  .toolbar button.primary { background:#4f46e5; color:#fff; border-color:#4f46e5; }
  @media print { .no-print { display:none !important; } body { background:#fff; } section { break-inside: avoid; page-break-inside: avoid; } svg { max-width:100%; } table { break-inside:auto; } }
</style></head><body>
  <div class="toolbar no-print">
    <button id="rca-save" class="primary">⤓ Save as PDF</button>
    <button id="rca-close">Close</button>
  </div>
  <div class="doc">
  <header class="rpt"><span class="brand">CORRELIX</span><span class="doctype">Root Cause Analysis Report</span></header>
  <h1>${esc(d.title)}</h1>
  <div class="badges">${d.pills.map(pill).join("")}</div>
  <div class="meta">Detected at: <b>${esc(d.observedAt)}</b> &middot; RCA ID: <b>${esc(d.rcaId)}</b></div>
  ${verdictFb}

  ${d.decision.text ? block("Decision", `<div class="decision"${d.decision.tone === "confirmed" ? ' style="border-left-color:#0f9f4f;background:#f2fbf6;border-color:#b9e5c7"' : ""}>${esc(d.decision.text)}</div>`) : ""}
  ${block("Case", kvRows(d.aside))}
  ${block("Executive summary", `<p class="body">${esc(d.summary)}</p>${why}`)}
  ${block("Impact & blast radius", kvRows(d.impact))}
  ${block("Event timeline", eventsTable(d.events))}
  ${block(d.topologyContext ? `Network topology & causality — sources: ${topoSourcesLine(d.topologyContext)}` : "Network topology & causality", topologyContextHtml(d.topologyContext, d.topoGraph))}
  ${block("Evidence matrix", evidence)}
  ${block("Confidence ladder", ladder)}
  ${block("Hypothesis ranking", hypotheses)}
  ${block("Ticket & escalation", ticket)}
  ${block("Next actions", actions)}

  <footer class="rpt"><span>Generated ${esc(now)} UTC &middot; Correlix RCA</span><span>Object ${esc(objId.slice(0, 8))} &middot; Confidential</span></footer>
</div>
</body></html>`;
  // NB: no inline <script>/onclick — the app CSP (script-src 'self') blocks inline
  // script in the popup. The parent wires the buttons + print via the DOM API below.
}

// exportRcaPdf renders the print-ready report from the RcaCase and opens it for
// "Save as PDF". Prefers a new tab (preview + working toolbar); falls back to a
// real-size off-screen iframe when pop-ups are blocked. Always returns true.
export function exportRcaPdf(data: RcaCase, objId: string, verdict?: RcaFeedback | null): boolean {
  const html = reportHtml(data, objId, verdict);

  const win = window.open("", "_blank", "width=920,height=1040");
  if (win) {
    win.document.open();
    win.document.write(html);
    win.document.close();
    const wire = () => {
      try {
        const dd = win.document;
        // onclick (idempotent) NOT addEventListener — wire() runs twice (now + on
        // load) and a stacked listener would fire print() twice → two Save dialogs.
        const save = dd.getElementById("rca-save");
        if (save) (save as HTMLElement).onclick = () => { win.focus(); win.print(); };
        const close = dd.getElementById("rca-close");
        if (close) (close as HTMLElement).onclick = () => win.close();
        // close the preview tab once the Save/print dialog is dismissed, so it
        // doesn't linger after the PDF is saved.
        win.onafterprint = () => { try { win.close(); } catch { /* ignore */ } };
      } catch { /* same-origin — fine */ }
    };
    wire();
    win.addEventListener("load", wire);
    win.focus();
    return true;
  }

  // Pop-up blocked → real-size off-screen iframe (a 0×0 iframe clips the print).
  const iframe = document.createElement("iframe");
  iframe.setAttribute("aria-hidden", "true");
  iframe.style.cssText = "position:fixed;left:-10000px;top:0;width:820px;height:1160px;border:0;";
  document.body.appendChild(iframe);
  const cw = iframe.contentWindow;
  const doc = cw?.document;
  if (!cw || !doc) { iframe.remove(); return false; }
  doc.open();
  doc.write(html);
  doc.close();
  const printIframe = () => { try { cw.focus(); cw.print(); } catch { /* ignore */ } };
  iframe.addEventListener("load", () => setTimeout(printIframe, 400));
  setTimeout(printIframe, 700);
  setTimeout(() => iframe.remove(), 60000);
  return true;
}
