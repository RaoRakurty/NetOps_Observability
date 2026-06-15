import { useMemo } from "react";
import { CorrTimeline, Seam } from "../../services/api";
import { C, MODALITY_ORDER, modalityLabel, entityLabel, seamOwnerLabel, visibilityLabel, ownerLabel, seamOwnerColor } from "./labels";
import { episodeEntity } from "./SeamGraph";

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
  const titleStyle: React.CSSProperties = { fontWeight: 700, fontSize: 13.5, color: C.fg };
  const muted: React.CSSProperties = { color: C.muted };
  const chip: React.CSSProperties = {
    fontSize: 12.5, background: "var(--bg,#0d1117)", padding: "2px 8px", borderRadius: 5,
    overflowWrap: "anywhere", minWidth: 0, fontWeight: 600,
  };

  // verdict → segment marker (the "broken link" treatment on the boundary).
  const segTone = confirmed ? C.crit : internalOnly ? C.faint : C.caution;
  const segSym = confirmed ? SYM.confirmed : internalOnly ? SYM.unknown : SYM.possible;
  const segLabel = confirmed ? "Confirmed issue here"
    : internalOnly ? "Internal monitoring — not a customer fault"
    : "Possible issue area";

  // Fallback: no grounded path mapping → never invent a segment.
  if (!primary) {
    const trig = timeline.signals.find((s) => s.is_trigger) ?? timeline.signals[0];
    return (
      <div style={card}>
        <div style={titleStyle}>{title}</div>
        <div style={{ fontSize: 13, color: C.fg }}>
          {SYM.unknown} Issue observed, path location unknown — not enough evidence to place it on a path or boundary yet.
        </div>
        {trig && (
          <div style={{ ...muted, fontSize: 12.5 }}>
            Strongest sign: <b style={{ color: C.fg }}>{entityLabel(trig.entity_id)}</b>
          </div>
        )}
      </div>
    );
  }

  const src = entityLabel(episodeEntity(primary.from_node));
  const dst = entityLabel(episodeEntity(primary.to_node));
  const ownerColor = seam ? seamOwnerColor(seam.control_plane_owner) : C.faint;
  const boundaryText = seam
    ? `${SYM.boundary} ${seamOwnerLabel(seam.control_plane_owner)} boundary · ${visibilityLabel(seam.visibility)}`
    : "same path / device area";

  return (
    <div style={card}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={titleStyle}>{title}</span>
        {owner && !internalOnly && (
          <span style={{ ...muted, fontSize: 12.5 }}>likely owner: <b style={{ color: C.fg }}>{ownerLabel(owner)}</b></span>
        )}
      </div>

      {/* symbolic path: source ● → ◆ boundary (marked by verdict) → target */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={chip}><span style={{ color: C.ok }}>{SYM.observed}</span> {src}</span>
        <span style={muted}>──</span>
        <span style={{
          ...chip, background: segTone + "1c", border: `1px solid ${segTone}66`, color: segTone,
          fontWeight: 700,
        }} title={segLabel}>
          {segSym} {boundaryText}
        </span>
        <span style={muted}>──</span>
        <span style={chip}><span style={{ color: C.ok }}>{SYM.observed}</span> {dst}</span>
      </div>
      <div style={{ fontSize: 12.5, color: segTone, fontWeight: 600 }}>
        {segSym} {segLabel}{visLimited ? ` · ${SYM.unknown} limited visibility past this boundary` : ""}
      </div>

      {/* evidence status across the path (NOC language, ● observed / ○ missing) */}
      <div>
        <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 3 }}>Evidence along the path</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: "2px 12px", fontSize: 12.5 }}>
          {MODALITY_ORDER.map((m) => {
            const seen = planes[m];
            return (
              <div key={m} style={{ color: seen ? C.fg : C.muted }}>
                <span style={{ color: seen ? C.ok : C.faint, fontWeight: 700 }}>{seen ? SYM.observed : SYM.missing}</span>{" "}
                {seen ? (PLANE_OBSERVED[m] ?? modalityLabel(m)) : (PLANE_MISSING[m] ?? `No ${modalityLabel(m).toLowerCase()}`)}
              </div>
            );
          })}
          {seam && (
            <div style={{ color: ownerColor, fontWeight: 600 }}>
              {SYM.boundary} {seamOwnerLabel(seam.control_plane_owner)} boundary
              {visLimited ? ` · ${SYM.unknown} ${visibilityLabel(seam.visibility)}` : ""}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
