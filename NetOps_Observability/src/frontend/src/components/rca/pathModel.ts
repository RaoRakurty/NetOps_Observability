import type {
  CorrTimeline, RcaPathAttribution, RcaTypedSegment, RcaPathKeyDevice,
  RcaAttributedFault, RcaDiscountedFault, RcaPathHead,
} from "../../services/api";
import { readServicePath, type SpineKind } from "./servicePath";
import { isRoutingKind, mentionsInternal, kindLabel, entityLabel } from "./labels";

// pathModel.ts — the SINGLE data-derivation for the RCA case path view (owner
// P1 2026-07-19: "Path causality duplicates Network path and causal topology —
// merge this and make it single logic"). Every RCA path render goes through
// derivePathModel(); RcaPathCausality is the only component that draws it.
//
// Sources, in order of authority (never mixed, never invented):
//  1. TYPED — the engine's path_attribution render contract (rca_path_attribution.go):
//     the discovered typed SRC→DST path + the named on-path cause. Authoritative.
//  2. DERIVED — the backend's measured service-path spine (contract §7, via
//     readServicePath): hop-by-hop measurement grouped into boundary segments,
//     with the backend's own fault/health marks. The hop ORDER is backend data;
//     this module only GROUPS consecutive hops by their declared boundary.
//  3. ADJACENCY — a routing signal that names a device + peer: the adjacency is
//     known even without a path; we say exactly that, nothing more.
//  4. INTERNAL — the platform observing itself; never dressed as a customer path.
//  5. NONE — an honest "path not fully discovered". No hop, break or segment is
//     ever fabricated.

export type PathMode = "typed" | "derived" | "adjacency" | "internal" | "none";
export type SegmentHealth = "degraded" | "down";

export interface PathModel {
  mode: PathMode;
  head: RcaPathHead | null;
  dstName: string;
  segments: RcaTypedSegment[];
  // Per-segment health overlay (segment index → state). Only segments whose
  // health the backend actually measured appear — absence stays quiet.
  segmentHealth: Record<number, SegmentHealth>;
  cause: RcaAttributedFault | null;
  explainedAway: RcaAttributedFault[];
  discounted: RcaDiscountedFault[];
  verdict: string;
  baseline: string;
  lifted: boolean;
  capped: boolean;
  capReason?: string;
  ambiguous: boolean;
  notes: string[];
  adjacency?: { device: string; peer: string; kindText: string };
}

// Spine boundary name → typed segment_type (labels.ts SEGMENT_META vocabulary).
const BOUNDARY_SEG: Record<string, string> = {
  LAN: "lan", "SD-WAN": "wan", SDWAN: "wan", WAN: "wan",
  CARRIER: "internet", INTERNET: "internet", CLOUD: "cloud", DC: "dc",
};
// Spine hop kind → device role token (labels.ts ROLE_LABEL vocabulary).
const SPINE_ROLE: Record<SpineKind, string> = {
  client: "client", lan_gateway: "gateway", wan_edge: "edge", nva: "nva",
  cloud_edge: "gateway", app_endpoint: "app", service_endpoint: "app",
  application: "app", transit: "router", unknown: "unknown",
};

function emptyModel(mode: PathMode, verdict: string): PathModel {
  return {
    mode, head: null, dstName: "application", segments: [], segmentHealth: {},
    cause: null, explainedAway: [], discounted: [], verdict, baseline: verdict,
    lifted: false, capped: false, ambiguous: false, notes: [],
  };
}

// The routing-context read (device + peer off a routing signal) — the honest
// adjacency fallback when no path exists. Internal entities are never surfaced.
function routingContext(timeline: CorrTimeline): { device: string; peer: string; kindText: string } | null {
  for (const s of timeline.signals) {
    if (!s.attached || s.kind.endsWith("_clear") || !isRoutingKind(s.kind)) continue;
    let device = s.entity_id, peer = "";
    try { const a = JSON.parse((s as { attrs?: string }).attrs || "{}"); peer = a.peer || a.neighbor || ""; } catch { /* no attrs */ }
    const ci = s.entity_id.indexOf(":");
    if (ci > 0) { device = s.entity_id.slice(0, ci); if (!peer) peer = s.entity_id.slice(ci + 1); }
    if (mentionsInternal(device)) return null;
    return { device: entityLabel(device), peer, kindText: kindLabel(s.kind) };
  }
  return null;
}

// Internal/self-probe-only object → never dressed as a customer path.
function internalOnly(timeline: CorrTimeline): boolean {
  const attached = timeline.signals.filter((s) => s.attached && !s.kind.endsWith("_clear"));
  if (attached.length === 0) return false;
  const probes = attached.filter((s) => s.modality_class === "active_probe");
  const others = attached.filter((s) => s.modality_class !== "active_probe");
  return others.length === 0 && probes.length > 0 &&
    probes.every((s) => s.probe_authority === "debug_only" || s.probe_scope === "internal_self_probe" || s.probe_scope === "synthetic_lab_probe");
}

// Derive segments from the backend's measured spine: consecutive hops grouped by
// their declared boundary; responding hops become key devices, silent hops fold
// into the segment's unknown-hop count; the backend's fault mark (if any)
// becomes the cause. Health comes only from the backend's edge states.
function fromSpine(timeline: CorrTimeline): PathModel | null {
  const sp = readServicePath(timeline);
  if (!sp) return null;
  const spine = [...sp.spine].sort((a, b) => a.index - b.index);

  const segments: RcaTypedSegment[] = [];
  const hopSeg = new Map<number, number>();   // spine index → segment index
  let curKey: string | null = null;
  for (const n of spine) {
    const key = (n.boundary || "").toUpperCase();
    if (curKey === null || key !== curKey) {
      curKey = key;
      segments.push({
        index: segments.length,
        segment_type: BOUNDARY_SEG[key] ?? (key ? "unknown" : "unknown"),
        boundary: n.boundary,
        provider: n.provider,
        key_devices: [], unknown_hops: [], ambiguous: false,
      });
    }
    const seg = segments[segments.length - 1];
    if (!seg.provider && n.provider) seg.provider = n.provider;
    hopSeg.set(n.index, seg.index);
    if (n.state === "responding") {
      (seg.key_devices as RcaPathKeyDevice[]).push({
        address: n.address, role: SPINE_ROLE[n.kind] ?? "unknown", label: n.label,
      });
    } else {
      (seg.unknown_hops as number[]).push(n.index);
      if (!seg.reason) seg.reason = n.state === "filtered"
        ? "This hop filters path probes — not visible from here."
        : "This hop did not respond to path measurement — not visible from here.";
    }
  }

  // The backend's fault mark → the cause; "last_response" is a measurement
  // fact (where the run stopped answering), never blame.
  let cause: RcaAttributedFault | null = null;
  const notes: string[] = [];
  for (const n of spine) {
    if (n.fault === "broken" || n.fault === "suspected" || n.fault === "possible") {
      const si = hopSeg.get(n.index) ?? 0;
      cause = {
        device: {
          address: n.address, role: SPINE_ROLE[n.kind] ?? "unknown", label: n.label,
          segment_index: si, segment_type: segments[si]?.segment_type, upstream_rank: 0, ambiguous: false,
        },
        kind: "",
      };
      break;
    }
    if (n.fault === "last_response") {
      notes.push(`Path measurement stopped answering after ${n.label} — a measurement fact, not an attribution.`);
    }
  }

  // Segment health overlay from the backend's edge states only.
  const segmentHealth: Record<number, SegmentHealth> = {};
  for (const e of sp.edges) {
    const si = hopSeg.get(e.to) ?? hopSeg.get(e.from);
    if (si === undefined || !e.state) continue;
    if (e.state === "confirmed_down" || e.state === "suspected_down") segmentHealth[si] = "down";
    else if (e.state === "degraded" && segmentHealth[si] !== "down") segmentHealth[si] = "degraded";
  }
  if (cause) {
    const si = cause.device.segment_index;
    if (!segmentHealth[si]) segmentHealth[si] = "down";
  }

  const last = spine[spine.length - 1];
  const verdict = timeline.verdict_tier || "suspected";
  return {
    mode: "derived", head: null,
    dstName: last?.kind === "application" || last?.kind === "app_endpoint" || last?.kind === "service_endpoint"
      ? last.label : (last?.label || "destination"),
    segments, segmentHealth, cause,
    explainedAway: [], discounted: [],
    verdict, baseline: verdict, lifted: false, capped: false,
    ambiguous: false, notes,
  };
}

// derivePathModel — the ONE derivation every RCA case path render consumes.
export function derivePathModel(
  data: RcaPathAttribution | null | undefined,
  timeline?: CorrTimeline | null,
): PathModel {
  // 1) TYPED: the engine's decoded path-causality attribution.
  const typedSegments = data?.path?.segments ?? [];
  if (data && (data.attributed || typedSegments.length > 0)) {
    const verdict = data.verdict_tier;
    const cause = data.attributed ?? null;
    const segmentHealth: Record<number, SegmentHealth> = {};
    if (cause) segmentHealth[cause.device.segment_index] = "down";
    return {
      mode: "typed",
      head: data.path?.head ?? null,
      dstName: data.path?.head?.query_name || "application",
      segments: typedSegments,
      segmentHealth,
      cause,
      explainedAway: data.explained_away ?? [],
      discounted: data.discounted ?? [],
      verdict,
      baseline: data.baseline_verdict_tier,
      lifted: !!data.confidence_lifted && !!data.baseline_verdict_tier && data.baseline_verdict_tier !== verdict,
      capped: !!data.capped, capReason: data.cap_reason,
      ambiguous: !!data.path?.ambiguous,
      notes: data.path?.notes ?? [],
    };
  }

  if (!timeline) return emptyModel("none", data?.verdict_tier || "suspected");
  if (internalOnly(timeline)) return emptyModel("internal", timeline.verdict_tier || "suspected");

  // 2) DERIVED: the backend's measured spine, grouped into boundary segments.
  const spineModel = fromSpine(timeline);
  if (spineModel) return spineModel;

  // 3) ADJACENCY: routing evidence names a device + peer — say exactly that.
  const adj = routingContext(timeline);
  if (adj) return { ...emptyModel("adjacency", timeline.verdict_tier || "suspected"), adjacency: adj };

  // 4) NONE — honest absence.
  return emptyModel("none", timeline.verdict_tier || "suspected");
}
