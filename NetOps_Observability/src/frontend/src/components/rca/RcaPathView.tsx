import { useMemo } from "react";
import { CorrTimeline, Seam } from "../../services/api";
import { C, MODALITY_ORDER, modalityLabel, entityLabel, kindLabel, seamOwnerLabel, visibilityLabel, ownerLabel, seamOwnerColor, mentionsInternal, isRoutingKind } from "./labels";
import { episodeEntity } from "./SeamGraph";

// episodeKind pulls the signal kind off a graph node key ("type:entity…:kind").
function episodeKind(key: string): string {
  const parts = key.split(":");
  return parts.length >= 2 ? kindLabel(parts[parts.length - 1]) : "";
}

// RcaPathView — the Operator-View "where is the issue" view, between Evidence and
// the Evidence timeline. OVERLAY MODEL (owner-specified): the grounded path
// structure (source → ownership boundary → target) comes from the correlation
// object's edges + seams; RCA overlays verdict / confidence / evidence status on
// top. Symbolic + NOC language only — NO raw entity ids, seam ids, topology tokens
// or backend names (those stay in Debug View's full SeamGraph). RCA never invents a
// broken segment: with no grounded mapping it says "path location unknown".
//
// Symbols: ● observed · ○ missing · ⚠ possible issue · ❌ confirmed issue ·
//          ◆ ownership/provider boundary · ? limited visibility · ✅ no issue seen

const SYM = { observed: "●", missing: "○", possible: "⚠", confirmed: "❌", unknown: "?", boundary: "◆", ok: "✅" };

// Which planes carry attached (used) evidence — drives the ●/○ status row.
function attachedPlanes(timeline: CorrTimeline): Record<string, boolean> {
  const att = timeline.counts?.attached_by_modality ?? {};
  const out: Record<string, boolean> = {};
  for (const m of MODALITY_ORDER) out[m] = (att[m] ?? 0) > 0;
  return out;
}

const PLANE_OBSERVED: Record<string, string> = {
  active_probe: "Active checks changed",
  device_telemetry: "Device health observed",
  control_plane: "Routing / link event seen",
  passive_flow: "Traffic-flow change seen",
};
const PLANE_MISSING: Record<string, string> = {
  active_probe: "No active-check evidence",
  device_telemetry: "Device health missing / not tied",
  control_plane: "No routing / link event",
  passive_flow: "No traffic-flow evidence",
};

export default function RcaPathView({ timeline, seams, owner }: {
  timeline: CorrTimeline;
  seams: Record<string, Seam>;
  owner?: string;
}) {
  const confirmed = timeline.verdict_tier === "confirmed";
  const edges = timeline.edges ?? [];

  // Internal/test-only object → "Internal monitoring path" (don't dress a self-probe
  // up as a customer fault).
  const internalOnly = useMemo(() => {
    const probes = timeline.signals.filter((s) => s.attached && s.modality_class === "active_probe");
    const others = timeline.signals.filter((s) => s.attached && s.modality_class !== "active_probe");
    return probes.length > 0 && others.length === 0 &&
      probes.every((s) => s.probe_authority === "debug_only" || s.probe_scope === "internal_self_probe" || s.probe_scope === "synthetic_lab_probe");
  }, [timeline.signals]);

  const title = internalOnly ? "Internal monitoring path"
    : confirmed ? "Likely fault location"
    : "Where evidence points — not confirmed";

  const planes = attachedPlanes(timeline);

  // Primary grounded segment: prefer a seam (ownership boundary) edge, else the
  // first edge. The seam carries owner + visibility.
  const primary = useMemo(() => edges.find((e) => e.grounding_kind === "seam") ?? edges[0], [edges]);
  const seam = primary && primary.grounding_kind === "seam" ? seams[primary.grounding_ref] : undefined;
  const visLimited = seam ? (seam.visibility === "partial" || seam.visibility === "blind") : false;

  const card: React.CSSProperties = {
    border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "10px 14px",
    background: "var(--panel,#11151c)", display: "flex", flexDirection: "column", gap: 9, minWidth: 0,
  };
  const titleStyle: React.CSSProperties = { fontWeight: 700, fontSize: 14, color: C.fg };
  const muted: React.CSSProperties = { color: C.muted };
  const chip: React.CSSProperties = {
    fontSize: 12.5, background: "var(--bg,#0d1117)", padding: "2px 8px", borderRadius: 5,
    overflowWrap: "anywhere", minWidth: 0, fontWeight: 600,
  };

  // verdict → segment marker (the "broken link" treatment on the boundary).
  const segTone = confirmed ? C.crit : internalOnly ? C.faint : C.caution;
  const segSym = confirmed ? SYM.confirmed : internalOnly ? SYM.unknown : SYM.possible;

  // Routing context: a routing/peer signal (BGP/OSPF/…) names a device + peer even
  // with no grounded edge. We DO know the adjacency involved — don't say "location
  // unknown" (the contradiction). Show the peer/session and what's still needed.
  const routing = (() => {
    for (const s of timeline.signals) {
      if (!s.attached || s.kind.endsWith("_clear") || !isRoutingKind(s.kind)) continue;
      let device = s.entity_id, peer = "";
      try { const a = JSON.parse((s as { attrs?: string }).attrs || "{}"); peer = a.peer || a.neighbor || ""; } catch { /* no attrs */ }
      const ci = s.entity_id.indexOf(":");
      if (ci > 0) { device = s.entity_id.slice(0, ci); if (!peer) peer = s.entity_id.slice(ci + 1); }
      if (mentionsInternal(device)) return null;
      return { device, peer, kind: s.kind };
    }
    return null;
  })();

  // Fallback: no grounded path mapping. With routing context we name the
  // adjacency; otherwise we say the location isn't known yet (never invent one).
  if (!primary) {
    if (routing) {
      return (
        <div style={card}>
          <div style={titleStyle}>Routing context</div>
          <div style={{ ...muted, fontSize: 12.5 }}>The routing peer/session involved in this issue.</div>
          <div style={{ fontSize: 14, lineHeight: 1.5, color: C.fg }}>
            A {kindLabel(routing.kind)} was observed on <b>{entityLabel(routing.device)}</b>
            {routing.peer ? <> with peer <b>{routing.peer}</b></> : null}.
          </div>
          <div style={{ fontSize: 14, lineHeight: 1.5, color: C.caution, fontWeight: 700 }}>
            {SYM.possible} Evidence localizes to: <span style={{ ...chip, color: C.caution, background: C.caution + "1c", border: `1px solid ${C.caution}66` }}>{entityLabel(routing.device)}</span>
          </div>
          <div style={{ ...muted, fontSize: 13, lineHeight: 1.5 }}>
            This identifies the routing adjacency involved, but does not confirm customer impact.
            Independent evidence is needed — peer-side BGP/routing state, device health,
            traffic-flow loss, downstream service impact, or an active check from an independent vantage.
          </div>
        </div>
      );
    }
    const trig = timeline.signals.find((s) => s.is_trigger) ?? timeline.signals[0];
    return (
      <div style={card}>
        <div style={titleStyle}>{title}</div>
        <div style={{ fontSize: 14, lineHeight: 1.5, color: C.fg }}>
          {SYM.unknown} Issue observed, path location unknown — not enough evidence to place it on a path or boundary yet.
        </div>
        {trig && !mentionsInternal(trig.entity_id) && (
          <div style={{ ...muted, fontSize: 13 }}>
            Strongest sign: <b style={{ color: C.fg }}>{entityLabel(trig.entity_id)}</b>
          </div>
        )}
      </div>
    );
  }

  const ownerColor = seam ? seamOwnerColor(seam.control_plane_owner) : C.faint;

  // Fault locus = the entity the grounded edges converge on (topo "shared:X"),
  // or the seam boundary — i.e. WHERE on the path the failure sits.
  const locus = (() => {
    const counts: Record<string, number> = {};
    for (const e of edges) {
      if (e.grounding_kind === "topo" && e.grounding_ref.startsWith("shared:")) {
        const x = e.grounding_ref.slice(7);
        if (!mentionsInternal(x)) counts[x] = (counts[x] || 0) + 1; // #76: never a platform/agent locus
      }
    }
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    if (top) return entityLabel(top[0]);
    return seam ? `${seamOwnerLabel(seam.control_plane_owner)} boundary` : "";
  })();

  // #76: only customer-facing grounded relationships in the operator path list.
  const visibleEdges = edges.filter((e) => !mentionsInternal(episodeEntity(e.from_node)) && !mentionsInternal(episodeEntity(e.to_node)));

  return (
    <div style={card}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={titleStyle}>{title}</span>
        {owner && !internalOnly && (
          <span style={{ ...muted, fontSize: 12.5 }}>likely owner: <b style={{ color: C.fg }}>{ownerLabel(owner)}</b></span>
        )}
      </div>

      {/* WHERE it sits: localization (confirmed → "Likely fault location",
          suspected → "Evidence localizes to") + the grounded relationships, in NOC
          language — edge weights/strength stay in Debug View. */}
      {locus && (
        <div style={{ fontSize: 14, lineHeight: 1.5, color: segTone, fontWeight: 700 }}>
          {segSym} {confirmed ? "Likely fault location" : internalOnly ? "Internal check path" : "Evidence localizes to"}: <span style={{ ...chip, color: segTone, background: segTone + "1c", border: `1px solid ${segTone}66` }}>{locus}</span>
          {visLimited ? ` · ${SYM.unknown} limited visibility past this boundary` : ""}
        </div>
      )}
      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        {visibleEdges.slice(0, 6).map((e, i) => {
          const a = entityLabel(episodeEntity(e.from_node));
          const b = entityLabel(episodeEntity(e.to_node));
          const directed = Number(e.direction_conf ?? 0) >= 0.5 && e.direction_basis !== "none";
          const s = e.grounding_kind === "seam" ? seams[e.grounding_ref] : undefined;
          const gk = e.grounding_kind === "seam"
            ? `${SYM.boundary} ${s ? seamOwnerLabel(s.control_plane_owner) : "provider"} boundary`
            : "related on the same path";
          return (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, flexWrap: "wrap", minWidth: 0 }}>
              <span style={chip}>{a}{episodeKind(e.from_node) ? <span style={{ ...muted, marginLeft: 4 }}>{episodeKind(e.from_node)}</span> : null}</span>
              <span style={muted}>{directed ? "→" : "──"}</span>
              <span style={{ fontSize: 11, color: C.muted }}>{gk}</span>
              <span style={muted}>{directed ? "→" : "──"}</span>
              <span style={chip}>{b}{episodeKind(e.to_node) ? <span style={{ ...muted, marginLeft: 4 }}>{episodeKind(e.to_node)}</span> : null}</span>
            </div>
          );
        })}
      </div>

      {/* The default view stays a clean path + break + ownership boundary (owner
          directive 2026-07-18: no observed/none box parade). The per-source
          evidence checklist is real information for the verifying engineer, so
          it lives behind a disclosure instead of the primary read. */}
      {seam && (
        <div style={{ fontSize: 12.5, color: ownerColor, fontWeight: 600 }}>
          {SYM.boundary} {seamOwnerLabel(seam.control_plane_owner)} boundary
          {visLimited ? ` · ${SYM.unknown} ${visibilityLabel(seam.visibility)}` : ""}
        </div>
      )}
      <details style={{ fontSize: 12.5 }}>
        <summary style={{ cursor: "pointer", fontSize: 12, fontWeight: 600, color: C.muted }}>
          How was this verified?
        </summary>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: "2px 12px", marginTop: 4 }}>
          {MODALITY_ORDER.map((m) => {
            const seen = planes[m];
            return (
              <div key={m} style={{ color: seen ? C.fg : C.muted }}>
                <span style={{ color: seen ? C.ok : C.faint, fontWeight: 700 }}>{seen ? SYM.observed : SYM.missing}</span>{" "}
                {seen ? (PLANE_OBSERVED[m] ?? modalityLabel(m)) : (PLANE_MISSING[m] ?? `No ${modalityLabel(m).toLowerCase()}`)}
              </div>
            );
          })}
        </div>
      </details>
    </div>
  );
}
