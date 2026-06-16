import { useMemo } from "react";
import { CorrTimeline, Seam } from "../../services/api";
import {
  C, MODALITY_META, MODALITY_ORDER, modalityLabel, modalityHelp,
  signatureName, signatureNocTitle, PLANE_NOC_TITLE, kindMeta, kindLabel,
  entityLabel, ownerLabel, seamOwnerLabel, visibilityLabel, isRoutingKind,
  AFFECTED_LABEL, OWNER_EXTERNAL, seamOwnerColor, mentionsInternal,
} from "./labels";
import { episodeEntity } from "./SeamGraph";

// hex+alpha tint helper for calm severity backgrounds.
const tint = (hex: string, a = "1f") => hex + a;

// Reason shown on hover for the "not tied to this issue" count + badge (item 4).
const NOT_TIED_HELP =
  "Seen in the same window but not linked to this issue — a different path or device area, or not strong/corroborated enough to link.";

// RcaSummary — the operator-facing RCA story (not an engine dump). In Operator
// View it speaks NOC/customer language only and answers four questions: what did
// we see, is it confirmed, why not, what should NOC do next. It must NOT leak
// backend component / storage / service names, raw entity or signature ids, or
// engine vocabulary (seam, modality, grounding, …) — Debug View shows those.
// Read-only: every value is engine-recorded.

// dominant plane → the "what we saw" lead sentence (NOC language).
const PLANE_SEEN_LEAD: Record<string, string> = {
  active_probe: "Active checks showed slower response on this path",
  device_telemetry: "Device-health signals changed on this device",
  control_plane: "Routing & link events were seen",
  passive_flow: "Traffic-flow changes were seen on this path",
};
// plane → short NOC noun for "no ___ evidence confirms it yet".
const PLANE_NOC_SHORT: Record<string, string> = {
  device_telemetry: "device health",
  control_plane: "routing/link event",
  passive_flow: "traffic-flow",
  active_probe: "active-check",
};
// plane → countable noun for the evidence cards ("15 checks seen").
const PLANE_NOUN: Record<string, string> = {
  device_telemetry: "signals", control_plane: "events", passive_flow: "flow signals", active_probe: "checks",
};
// missing plane → the concrete check that would confirm it (item 11 checklist).
const PLANE_CONFIRM: Record<string, { what: string; plane: string }> = {
  device_telemetry: { what: "Interface errors or drops", plane: "Device health" },
  control_plane: { what: "BGP / link / syslog event", plane: "Routing & link events" },
  passive_flow: { what: "Traffic loss or drop", plane: "Traffic flow evidence" },
  active_probe: { what: "Re-test from a trusted customer path", plane: "Active checks" },
};

type Quality = "strong" | "candidate" | "weak/noisy";
const QUALITY_TONE: Record<Quality, string> = {
  strong: C.ok, candidate: C.warn, "weak/noisy": C.faint,
};
const VERDICT_TONE: Record<string, string> = {
  confirmed: C.crit, suspected: C.warn, undetermined: C.faint,
};

// A high-contrast filled badge — for the headline verdict/quality only.
function strongBadge(tone: string): React.CSSProperties {
  return {
    fontSize: 11.5, fontWeight: 800, letterSpacing: 0.4, padding: "2px 9px",
    borderRadius: 5, color: "#ffffff", background: tone, lineHeight: 1.4,
    whiteSpace: "nowrap",
  };
}

// A subtle outlined badge — for per-card evidence states (not alarm-heavy).
function softBadge(tone: string): React.CSSProperties {
  return {
    fontSize: 11, fontWeight: 700, padding: "1px 7px", borderRadius: 4,
    color: tone, background: tone + "18", border: `1px solid ${tone}55`, whiteSpace: "nowrap",
  };
}

// seam_type → friendly story phrase when no signature has matched yet.
const SEAM_STORY: Record<string, string> = {
  DIA: "ISP / DIA egress latency",
  DX: "DX path degradation",
  VPN: "VPN tunnel degradation",
  SDWAN: "SD-WAN overlay degradation",
  CLOUD_BACKBONE: "cloud backbone degradation",
};

// dominant plane → degradation noun, used as the headline title when no signature
// has matched and no seam grounds the object ("Probe degradation", "Device
// degradation", …). Keeps the header concrete instead of generic "RCA Candidate".
const PLANE_DEGRADATION: Record<string, string> = {
  active_probe: "Probe",
  device_telemetry: "Device",
  control_plane: "Control-plane",
  passive_flow: "Flow",
};
const cap = (s: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

type MissingItem = { signature: string; needs: string[]; note: string };

function parseMissing(raw: string): MissingItem[] {
  let lines: string[] = [];
  try { lines = JSON.parse(raw || "[]"); } catch { lines = []; }
  return lines.map((line) => {
    const i = line.indexOf(": ");
    const signature = i >= 0 ? line.slice(0, i) : line;
    const rest = i >= 0 ? line.slice(i + 2) : "";
    if (rest.startsWith("needs ")) {
      return { signature, needs: rest.slice(6).split("|").map((s) => s.trim()).filter(Boolean), note: "" };
    }
    return { signature, needs: [], note: rest };
  });
}

// "a, b, or c"
function orList(items: string[]): string {
  if (items.length <= 1) return items[0] ?? "";
  if (items.length === 2) return `${items[0]} or ${items[1]}`;
  return `${items.slice(0, -1).join(", ")}, or ${items[items.length - 1]}`;
}

export default function RcaSummary({
  timeline, seams, view, state, version, nodeCount, recommendedSteps = [], owner = "", affected = "",
}: {
  timeline: CorrTimeline;
  seams: Record<string, Seam>;
  view: "operator" | "debug";
  state: string;
  version: number;
  nodeCount: number;
  recommendedSteps?: string[];
  owner?: string;
  affected?: string;          // engine `affected` JSON {devices,paths,sites,...} (item 1)
}) {
  const c = timeline.counts;
  const muted: React.CSSProperties = { color: C.muted };

  // Observed window + duration (item 2). Times are operator-safe in both views.
  const windowInfo = useMemo(() => {
    const t0 = Date.parse(timeline.window_start.replace(" ", "T") + "Z");
    const t1 = Date.parse(timeline.window_end.replace(" ", "T") + "Z");
    const dur = Number.isFinite(t0) && Number.isFinite(t1) ? Math.max(0, Math.round((t1 - t0) / 1000)) : 0;
    const mm = Math.floor(dur / 60), ss = dur % 60;
    return {
      start: timeline.window_start.slice(0, 19),
      end: timeline.window_end.slice(0, 19),
      dur: mm > 0 ? `${mm}m ${ss}s` : `${ss}s`,
    };
  }, [timeline.window_start, timeline.window_end]);

  // Affected scope (item 1) — only the buckets the engine populated. Entity ids
  // are made customer-safe (entityLabel) in Operator View and de-duped after
  // mapping (several internal names can collapse to one role label); Debug shows
  // the raw ids.
  const affectedGroups = useMemo(() => {
    let obj: Record<string, unknown> = {};
    try { obj = JSON.parse(affected || "{}"); } catch { obj = {}; }
    return Object.entries(obj)
      .filter(([, v]) => Array.isArray(v) && v.length)
      .map(([k, v]) => {
        const ids = v as string[];
        // Operator View (decision #76): drop internal platform/agent entities so
        // the affected scope shows only customer network entities.
        const visible = view === "debug" ? ids : ids.filter((i) => !mentionsInternal(i));
        const shown = view === "debug" ? visible : [...new Set(visible.map((i) => entityLabel(i)))];
        return { key: k, label: AFFECTED_LABEL[k] ?? k, items: shown, raw: ids.length };
      })
      .filter((g) => g.items.length > 0);
  }, [affected, view]);

  // Display-plane buckets. Operator View groups a signal by the DOMAIN a NOC reads
  // it as (so a polled BGP metric files under "Routing & link events", not "Device
  // health"), keeping timeline lanes, evidence cards, dominant plane, and the
  // summary all consistent. Debug View groups by the true modality_class. The
  // engine's independence/verdict math always uses modality_class, never this.
  const planeOf = (s: { kind: string; modality_class: string }) =>
    view === "operator" && isRoutingKind(s.kind) ? "control_plane" : s.modality_class;
  const { byPlane, attByPlane } = useMemo(() => {
    const by: Record<string, number> = {}; const att: Record<string, number> = {};
    for (const s of timeline.signals) {
      if (s.kind.endsWith("_clear")) continue;
      const p = planeOf(s);
      by[p] = (by[p] ?? 0) + 1;
      if (s.attached) att[p] = (att[p] ?? 0) + 1;
    }
    return { byPlane: by, attByPlane: att };
  }, [timeline.signals, view]);

  const presentKinds = useMemo(() => {
    const s = new Set<string>();
    for (const sig of timeline.signals) if (!sig.kind.endsWith("_clear")) s.add(sig.kind);
    return s;
  }, [timeline.signals]);

  // Verdict-relevant count uses the TRUE modality_class (the engine's independence
  // basis), so quality/confidence never contradicts a confirmed verdict even when
  // two true modalities (e.g. a BGP metric + a BGP syslog) share one display lane.
  const attachedModalities = useMemo(
    () => Object.values(c.attached_by_modality ?? {}).filter((v) => v > 0).length,
    [c.attached_by_modality],
  );
  const grounded = timeline.edges.length > 0;
  const confirmed = timeline.verdict_tier === "confirmed";
  const crossPlane = attachedModalities >= 2;
  const observers = c.attached_observers ?? 0;
  const probeOnly = useMemo(() => {
    const present = Object.entries(attByPlane).filter(([, v]) => v > 0).map(([k]) => k);
    return present.length === 1 && present[0] === "active_probe";
  }, [attByPlane]);

  // Probe authority (Step 3): how trustworthy is the probe evidence, and were
  // any debug/lab probes excluded from this customer-facing verdict?
  const probe = useMemo(() => {
    const probes = timeline.signals.filter((s) => s.modality_class === "active_probe" && !s.kind.endsWith("_clear"));
    const debugExcluded = probes.filter((s) => s.probe_authority === "debug_only").length;
    const attachedAuth = new Set(timeline.signals.filter((s) => s.attached && s.modality_class === "active_probe").map((s) => s.probe_authority));
    const hasConfirmProbe = attachedAuth.has("high") || attachedAuth.has("medium");
    const lowOnly = probeOnly && !hasConfirmProbe;
    return { debugExcluded, hasConfirmProbe, lowOnly };
  }, [timeline.signals, probeOnly]);

  const quality: Quality =
    confirmed && grounded && attachedModalities >= 2 && observers >= 2 ? "strong"
    : !grounded || c.attached <= 1 || attachedModalities <= 1 || probeOnly ? "weak/noisy"
    : "candidate";

  const missing = useMemo(() => parseMissing(timeline.evidence_missing), [timeline.evidence_missing]);

  const seamRefs = useMemo(() => {
    const refs = new Set<string>();
    for (const e of timeline.edges) if (e.grounding_kind === "seam") refs.add(e.grounding_ref);
    return [...refs];
  }, [timeline.edges]);
  const primarySeam = seamRefs.length ? seams[seamRefs[0]] : undefined;

  const dominant = useMemo(() => {
    const by = Object.values(attByPlane).some((v) => v > 0) ? attByPlane : byPlane;
    return Object.entries(by ?? {}).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "active_probe";
  }, [attByPlane, byPlane]);

  // planes with NO linked evidence (candidates to corroborate)
  const missingPlanes = useMemo(
    () => MODALITY_ORDER.filter((m) => (attByPlane[m] ?? 0) === 0),
    [attByPlane],
  );
  const requiredModalities = useMemo(() => {
    const s = new Set<string>();
    for (const mi of missing) for (const k of mi.needs) s.add(isRoutingKind(k) ? "control_plane" : kindMeta(k).modality);
    return s;
  }, [missing]);

  // ---- Operator headline (NOC "Possible …" phrasing; never a raw id) ----------
  const nocTitle = timeline.top_hypothesis !== "undetermined"
    ? signatureNocTitle(timeline.top_hypothesis)
    : (PLANE_NOC_TITLE[dominant] ?? "Possible network issue");

  // Debug headline keeps the technical story (matched signature / plane noun).
  const debugStory = useMemo(() => {
    if (timeline.top_hypothesis !== "undetermined") return signatureName(timeline.top_hypothesis);
    if (primarySeam) return SEAM_STORY[primarySeam.seam_type ?? ""]
      ?? `${primarySeam.control_plane_owner.toUpperCase()} / ${primarySeam.seam_type ?? "seam"} degradation`;
    return `${PLANE_DEGRADATION[dominant] ?? cap(modalityLabel(dominant).toLowerCase())} degradation`;
  }, [timeline.top_hypothesis, primarySeam, dominant]);

  const titleText = view === "debug"
    ? (confirmed ? cap(debugStory) : `${cap(debugStory)} candidate`)
    : nocTitle;

  // Status line (item 1): "Not confirmed · Confidence: Low".
  const confidenceWord = confirmed ? "High" : quality === "candidate" ? "Medium" : "Low";
  // Object state — never say "resolved" (it implies the incident is closed). Only
  // say "Cleared" when a signal actually cleared; otherwise plain Open / inactive.
  const cleared = useMemo(
    () => timeline.signals.some((s) => s.clear_ts && s.clear_ts.length > 0) || (c.recovery ?? 0) > 0,
    [timeline.signals, c.recovery],
  );
  // "Cleared" is scoped to the SIGNAL so it never reads as "incident resolved"
  // next to a Not-confirmed verdict.
  const stateText = state === "open" ? "Current state: Open"
    : cleared ? "Signal state: Cleared"
    : "Current state: No longer active";

  // ---- the plain-English RCA summary — NOC language, answers "what did we see"
  // + "is it confirmed / why not" (items 1 & 12) ------------------------------
  const nocSummary = useMemo(() => {
    const lead = PLANE_SEEN_LEAD[dominant] ?? `${modalityLabel(dominant)} changed`;
    if (confirmed) return `${lead}. Independent evidence confirms a real network issue.`;
    const miss = missingPlanes.filter((m) => m !== dominant).map((m) => PLANE_NOC_SHORT[m] ?? modalityLabel(m).toLowerCase());
    if (crossPlane) {
      const have = MODALITY_ORDER.filter((m) => (attByPlane[m] ?? 0) > 0)
        .map((m) => PLANE_NOC_SHORT[m] ?? modalityLabel(m).toLowerCase());
      return `${lead}. Partial agreement from ${orList(have)} evidence, but not enough to confirm a real network issue yet.`;
    }
    return miss.length
      ? `${lead}. No ${orList(miss)} evidence confirms a real network issue yet.`
      : `${lead}. The evidence does not yet confirm a real network issue.`;
  }, [dominant, confirmed, crossPlane, missingPlanes, attByPlane]);

  const card: React.CSSProperties = {
    border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "10px 14px",
    background: "var(--panel,#11151c)", display: "flex", flexDirection: "column", gap: 9,
    minWidth: 0, maxWidth: "100%", overflow: "hidden",
  };
  const title: React.CSSProperties = { fontWeight: 600, fontSize: 12 };
  const chip: React.CSSProperties = {
    fontFamily: "ui-monospace, monospace", fontSize: 12.5, background: "var(--bg,#0d1117)",
    padding: "1px 6px", borderRadius: 4, overflowWrap: "anywhere", minWidth: 0,
  };

  // corroboration suggestions = absent non-probe planes (what to add to confirm)
  const corroborate = missingPlanes.filter((m) => m !== "active_probe" && (byPlane[m] ?? 0) === 0);
  // Dedupe "Possible signature" — group all needs per signature, show each once.
  const clauseItems = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const mi of missing) if (mi.needs.length) {
      const set = m.get(mi.signature) ?? new Set<string>();
      mi.needs.forEach((n) => set.add(n));
      m.set(mi.signature, set);
    }
    return [...m.entries()].map(([signature, needs]) => ({ signature, needs: [...needs] }));
  }, [missing]);

  // planes that actually carry linked evidence (for "why suspected") — NOC labels
  const attachedPlaneLabels = MODALITY_ORDER
    .filter((m) => (attByPlane[m] ?? 0) > 0)
    .map((m) => modalityLabel(m).toLowerCase());
  // Independence gap: control-plane evidence reported by a single observer (the
  // device describing its own state) can't confirm customer impact on its own —
  // surface this specific reason (the engine's actual confirm-gate basis).
  const controlObservers = useMemo(() => new Set(
    timeline.signals.filter((s) => s.attached && s.modality_class === "control_plane" && !s.kind.endsWith("_clear"))
      .map((s) => s.observer_id || s.entity_id),
  ).size, [timeline.signals]);
  const singleObserverControl = controlObservers <= 1 && (attByPlane["control_plane"] ?? 0) > 0;

  const whyNotConfirmed = probe.lowOnly
    ? "the only evidence is internal/test checks — they can't confirm a customer-impacting issue on their own. Needs device health, a routing/link event, or traffic loss."
    : singleObserverControl
      ? "the control-plane evidence comes from a single observer (the device reporting on itself). One observer can't confirm a customer-impacting issue — an independent view is needed."
      : corroborate.length
        ? `no independent ${orList(corroborate.map((p) => modalityLabel(p).toLowerCase()))} evidence yet.`
        : "needs a second, independent source to confirm.";

  const confidenceTone = confirmed ? C.ok : quality === "candidate" ? C.warn : C.faint;

  // NOC decision line (item 5): a confirmed issue is escalated to whoever owns it
  // (external provider vs internal team); anything weaker is held with the reason.
  // Mirrors the verdict/authority logic the rest of the card already trusts.
  const decision = (() => {
    if (confirmed) {
      if (owner && OWNER_EXTERNAL.has(owner))
        return { verb: "Escalate", tone: C.crit, text: `${ownerLabel(owner)} — confirmed boundary issue; independent evidence agrees.` };
      if (owner === "app_team")
        return { verb: "Escalate", tone: C.crit, text: "App team — confirmed, owned by the application layer." };
      return { verb: "Escalate", tone: C.crit, text: "Network team — confirmed network issue." };
    }
    if (probe.lowOnly || probeOnly)
      return { verb: "Hold", tone: C.caution, text: "Only active/test checks changed. Re-test from a trusted customer path, or corroborate with device health, a routing/link event, or traffic loss." };
    if (timeline.verdict_tier === "suspected") {
      const add = corroborate.length ? orList(corroborate.map((p) => modalityLabel(p).toLowerCase())) : "a second, independent source";
      const then = owner && OWNER_EXTERNAL.has(owner) ? `, then escalate to ${ownerLabel(owner)}` : "";
      return { verb: "Hold", tone: C.caution, text: `Suspected only. Confirm with ${add}${then}.` };
    }
    return { verb: "Hold", tone: C.faint, text: "Not enough evidence to confirm a network issue." };
  })();

  // Ranked Next-Actions queue (NOC workflow) — replaces the text-heavy paragraph.
  // Ordered by what the operator should do first; verb = the action class.
  const nextActions: { verb: string; detail: string; primary?: boolean }[] = (() => {
    const acts: { verb: string; detail: string; primary?: boolean }[] = [];
    if (confirmed) {
      const who = owner ? ownerLabel(owner) : "the network team";
      acts.push({ verb: "Escalate", detail: `Hand off to ${who} — confirmed ${nocTitle.replace(/^Possible /, "").toLowerCase()}.`, primary: true });
      recommendedSteps.slice(0, 2).forEach((s) => acts.push({ verb: "Do", detail: s }));
      acts.push({ verb: "Create incident", detail: "Open or relate an incident to track resolution." });
      acts.push({ verb: "Open evidence", detail: "Review the cascade in the timeline below." });
      return acts;
    }
    if (recommendedSteps.length) recommendedSteps.slice(0, 2).forEach((s, i) => acts.push({ verb: "Investigate", detail: s, primary: i === 0 }));
    else acts.push({ verb: "Investigate", detail: "Check the affected interface admin/oper state and recent changes on the device.", primary: true });
    if (singleObserverControl) acts.push({ verb: "Run check", detail: "Run an active path check from an independent vantage, and verify the peer-side BGP / routing state." });
    acts.push({ verb: "Open evidence", detail: "Review the cascade + which signals are / aren't tied, in the timeline below." });
    acts.push({ verb: "Acknowledge", detail: "Mark under investigation — don't open a customer incident until confirmed." });
    return acts;
  })();

  return (
    <div style={card}>
      {/* clean header — NOC cause title; status pill + confidence carry certainty.
          Debug View adds the technical quality/verdict badges + engine meta. */}
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <span style={{ fontSize: 15, fontWeight: 700, color: C.fg }}>{titleText}</span>
        {view === "debug" && (
          <>
            <span style={{ ...strongBadge(QUALITY_TONE[quality]) }}>
              {quality === "weak/noisy" ? "WEAK" : quality.toUpperCase()}
            </span>
            <span style={{ ...strongBadge(VERDICT_TONE[timeline.verdict_tier] ?? C.faint), textTransform: "uppercase" }}>
              {timeline.verdict_tier}
            </span>
            <span style={{ ...muted, fontSize: 12.5, marginLeft: "auto" }}>
              {state === "open" ? "Open" : "Closed"} · v{version} · {nodeCount} node{nodeCount === 1 ? "" : "s"} · {timeline.edges.length} grounded edge{timeline.edges.length === 1 ? "" : "s"}
            </span>
          </>
        )}
      </div>

      {/* status line — "Not confirmed · Confidence: Low" (item 1) */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: -4 }}>
        <span style={{ ...strongBadge(confirmed ? C.ok : C.faint) }}>{confirmed ? "CONFIRMED" : "NOT CONFIRMED"}</span>
        <span style={{ fontSize: 13, color: confidenceTone, fontWeight: 700 }}>Confidence: {confidenceWord}</span>
        <span style={{ ...muted, fontSize: 12.5 }}>· {stateText}</span>
      </div>

      {/* recovery tracking — when link/BGP/probe restore, show resolving vs closed */}
      {(c.recovery ?? 0) > 0 && (
        <div style={{ fontSize: 12.5, color: C.ok, fontWeight: 600, marginTop: -4 }}>
          ↩ Recovering — {c.recovery} signal{c.recovery === 1 ? "" : "s"} cleared{state !== "open" ? " · object closing" : " · watching for full recovery"}.
        </div>
      )}

      {/* observed window + duration (item 2) — near the top, both views */}
      <div style={{ ...muted, fontSize: 12.5, marginTop: -2 }}>
        Observed window: <span style={{ color: C.fg }}>{windowInfo.start} → {windowInfo.end} UTC</span>
        {" · duration "}<b style={{ color: C.fg }}>{windowInfo.dur}</b>
      </div>

      {/* affected scope (item 1) — what/where this issue touches, when known */}
      {affectedGroups.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <div style={title}>Affected</div>
          {affectedGroups.map((g) => (
            <div key={g.key} style={{ fontSize: 12.5, display: "flex", gap: 8, flexWrap: "wrap" }}>
              <span style={{ ...muted, minWidth: 118, flexShrink: 0 }}>{g.label}</span>
              <span style={{ color: C.fg, minWidth: 0, overflowWrap: "anywhere" }}>
                {g.items.slice(0, 6).join(", ")}{g.items.length > 6 ? ` +${g.items.length - 6} more` : ""}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* NOC decision line (item 5) — the punchline: escalate (and to whom) or hold */}
      <div style={{
        display: "flex", alignItems: "baseline", gap: 8, padding: "7px 10px", borderRadius: 6,
        border: `1px solid ${decision.tone}55`, background: decision.tone + "14",
      }}>
        <span style={{ fontSize: 11.5, fontWeight: 800, letterSpacing: 0.4, color: decision.tone, textTransform: "uppercase", flexShrink: 0 }}>
          {decision.verb}
        </span>
        <span style={{ fontSize: 13, color: C.fg, fontWeight: 600, lineHeight: 1.45 }}>{decision.text}</span>
      </div>

      {/* the precise plain-English story — primary readable text */}
      <div style={{ fontSize: 14.5, lineHeight: 1.55, color: C.fg, fontWeight: 500 }}>{nocSummary}</div>

      {/* why suspected / why not confirmed — makes the verdict trustable */}
      {timeline.verdict_tier === "suspected" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 3, fontSize: 12.5, borderLeft: `3px solid ${C.caution}`, paddingLeft: 8 }}>
          {timeline.top_hypothesis !== "undetermined" && (
            <div><b style={{ color: C.caution }}>Why suspected:</b> the signs match a <b>{nocTitle.replace(/^Possible /, "")}</b> using {attachedPlaneLabels.length ? attachedPlaneLabels.join(" + ") : "the available"} evidence.</div>
          )}
          <div><b style={{ color: C.caution }}>Why not confirmed:</b> {whyNotConfirmed}</div>
          {singleObserverControl && (
            <div><b style={{ color: C.info }}>To confirm:</b> add an independent observer — a remote probe, the peer-side BGP / routing state, downstream service impact, or second-device telemetry.</div>
          )}
        </div>
      )}
      {probeOnly && (
        <div style={{ fontSize: 12.5, color: C.caution, fontWeight: 600 }}>⚠ Only active checks changed. This is not enough to confirm root cause.</div>
      )}
      {probe.lowOnly && (
        <div style={{ fontSize: 12.5, color: C.caution, fontWeight: 600 }}>
          ⚠ These are internal/test checks. They are useful for troubleshooting, but they cannot confirm customer impact.
        </div>
      )}
      {probe.debugExcluded > 0 && (
        <div style={{ fontSize: 12.5, color: C.faint }}>
          {probe.debugExcluded} test check{probe.debugExcluded === 1 ? " was" : "s were"} ignored for the final verdict. They are shown only for troubleshooting context.
        </div>
      )}

      {/* mini seam/topo graph preview — above the fold */}
      {grounded && (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {[...timeline.edges]
            .filter((e) => view === "debug" || (!mentionsInternal(episodeEntity(e.from_node)) && !mentionsInternal(episodeEntity(e.to_node))))
            .sort((a, b) => (a.grounding_kind === "seam" ? -1 : 1) - (b.grounding_kind === "seam" ? -1 : 1)).slice(0, 3).map((e, i) => {
            const s = e.grounding_kind === "seam" ? seams[e.grounding_ref] : undefined;
            // Seam chip tinted by boundary owner (whose domain), grey for same-path.
            const oc = e.grounding_kind === "seam" ? seamOwnerColor(s?.control_plane_owner) : C.faint;
            return (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12.5, flexWrap: "wrap", minWidth: 0 }}>
                <span style={chip}>{view === "debug" ? episodeEntity(e.from_node) : entityLabel(episodeEntity(e.from_node))}</span>
                <span style={muted}>──</span>
                <span style={{
                  background: tint(oc, "22"),
                  border: `1px solid ${tint(oc, "66")}`,
                  borderRadius: 4, padding: "1px 6px", fontWeight: 600,
                  color: e.grounding_kind === "seam" ? oc : C.muted,
                }} title={view === "debug" ? e.grounding_ref : undefined}>
                  {e.grounding_kind === "seam"
                    ? `◆ ${s ? `${seamOwnerLabel(s.control_plane_owner)} · ${visibilityLabel(s.visibility)}` : "provider boundary"}`
                    : "same path / device area"}
                </span>
                <span style={muted}>──</span>
                <span style={chip}>{view === "debug" ? episodeEntity(e.to_node) : entityLabel(episodeEntity(e.to_node))}</span>
              </div>
            );
          })}
        </div>
      )}

      {/* ranked Next-Actions queue — scannable NOC workflow (not a paragraph) */}
      <div style={{ border: "1px solid var(--border)", borderLeft: `3px solid ${C.info}`, background: "var(--hover)", borderRadius: 6, padding: "8px 10px" }}>
        <div style={{ ...title, color: C.info }}>
          Next actions{owner ? <span style={{ ...muted, fontWeight: 400 }}> · likely owner: <b style={{ color: "var(--fg)" }}>{ownerLabel(owner)}</b></span> : null}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 5 }}>
          {nextActions.map((a, i) => (
            <div key={i} style={{ display: "flex", gap: 8, alignItems: "baseline", fontSize: 12.5 }}>
              <span style={{ ...muted, fontFamily: "ui-monospace,monospace", minWidth: 14, textAlign: "right" }}>{i + 1}</span>
              <span style={{
                fontSize: 10, fontWeight: 800, letterSpacing: 0.4, textTransform: "uppercase", padding: "1px 6px",
                borderRadius: 4, whiteSpace: "nowrap", flexShrink: 0,
                color: a.primary ? "#fff" : C.info, background: a.primary ? C.info : C.info + "1c", border: `1px solid ${C.info}55`,
              }}>{a.verb}</span>
              <span style={{ color: "var(--fg)", lineHeight: 1.45 }}>{a.detail}</span>
            </div>
          ))}
        </div>
      </div>

      {/* evidence coverage — what each kind of evidence showed (NOC language) */}
      <div>
        <div style={title}>Evidence</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(168px,1fr))", gap: 8, marginTop: 6 }}>
          {MODALITY_ORDER.map((key) => {
            const total = byPlane[key] ?? 0;
            const att = attByPlane[key] ?? 0;
            const isProbe = key === "active_probe";
            const lowAuthProbe = isProbe && att > 0 && !probe.hasConfirmProbe;
            const debugExcludedHere = isProbe && total > att && probe.debugExcluded > 0;
            const isMain = key === dominant && att > 0;
            const noun = PLANE_NOUN[key] ?? "signals";
            // state → {tone, badge}. Card stays NEUTRAL; the badge + a tinted
            // left-border carry the state, so the grid doesn't read as all-alarm.
            // "Needed to confirm" is informational (blue), not alarm (orange):
            // an absent plane is a corroboration opportunity, not a fault.
            let tone: string = C.faint, badge = "Not observed", used = false;
            if (att > 0 && lowAuthProbe) { tone = C.caution; badge = "Weak evidence only"; used = true; }
            else if (att > 0) { tone = C.ok; badge = "Used"; used = true; }
            else if (total > 0) { tone = C.info; badge = "Not tied to this issue"; }
            else if (requiredModalities.has(key)) { tone = C.info; badge = "Needed to confirm"; }
            return (
              <div key={key} style={{
                border: "1px solid var(--border)", borderLeft: `3px solid ${tone}`,
                background: used ? "var(--hover)" : "transparent", borderRadius: 6, padding: "7px 9px", minWidth: 0,
              }}>
                <div style={{ fontSize: 12.5, display: "flex", alignItems: "center", gap: 6, fontWeight: 600, color: "var(--fg)", flexWrap: "wrap" }}>
                  <span style={{ width: 9, height: 9, borderRadius: 2, background: MODALITY_META[key].color, display: "inline-block" }} />
                  {modalityLabel(key, view)}
                  {isMain && <span style={{ ...softBadge(C.ok), fontSize: 10, fontWeight: 700 }}>Main evidence</span>}
                </div>
                <div style={{ ...muted, fontSize: 11, marginTop: 2 }}>{modalityHelp(key)}</div>
                <div style={{ fontSize: 12.5, marginTop: 4, display: "flex", flexDirection: "column", gap: 1, color: "var(--fg)" }}>
                  {total === 0 ? (
                    <span style={muted}>No {noun} seen</span>
                  ) : (() => {
                    // Make the counts ADD UP (item 3): seen = used + test-ignored +
                    // not-tied. Without the residual line, "15 seen / 3 used" reads
                    // as a missing-arithmetic bug to the NOC.
                    const testIgnored = isProbe ? probe.debugExcluded : 0;
                    const notTied = Math.max(0, total - att - testIgnored);
                    return (
                      <>
                        <span><b>{total}</b> {noun} seen</span>
                        {att > 0 && <span><b style={{ color: tone }}>{att}</b> used{lowAuthProbe ? " (weak)" : ""}</span>}
                        {testIgnored > 0 && <span><b style={{ color: C.faint }}>{testIgnored}</b> test {testIgnored === 1 ? "check" : "checks"} ignored</span>}
                        {notTied > 0 && (
                          <span title={NOT_TIED_HELP}><b style={{ color: C.faint }}>{notTied}</b> not tied to this issue</span>
                        )}
                        {lowAuthProbe && <span style={{ color: C.caution, fontWeight: 600 }}>Internal/test checks only</span>}
                      </>
                    );
                  })()}
                </div>
                <div style={{ marginTop: 4, display: "flex", gap: 5, flexWrap: "wrap" }}>
                  <span style={softBadge(tone)} title={badge === "Not tied to this issue" ? NOT_TIED_HELP : undefined}>{badge}</span>
                  {debugExcludedHere && <span style={softBadge(C.faint)}>Test check ignored</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* confirmation checklist — what evidence would confirm this (item 11) */}
      {(corroborate.length > 0 || (view === "debug" && clauseItems.length > 0)) && (
        <div>
          <div style={title}>What evidence would confirm this?</div>

          {/* actionable corroboration from absent planes (the common case) */}
          {corroborate.length > 0 && (
            <div style={{ marginTop: 4 }}>
              <div style={{ ...muted, fontSize: 12.5 }}>To confirm this issue, collect one of:</div>
              {corroborate.map((p) => {
                const cf = PLANE_CONFIRM[p];
                return (
                  <div key={p} style={{ fontSize: 12.5, padding: "1px 0", color: "var(--fg)" }}>
                    ○ {cf?.what ?? modalityHelp(p)} <span style={muted}>— {cf?.plane ?? modalityLabel(p)}</span>
                  </div>
                );
              })}
            </div>
          )}

          {/* specific signature clause gaps — Debug View only (raw signature detail) */}
          {view === "debug" && clauseItems.map((mi, i) => (
            <div key={i} style={{ marginTop: 5 }}>
              <div style={{ fontSize: 12.5 }}>
                Possible signature: <b>{signatureName(mi.signature)}</b>
                {view === "debug" && <span style={{ ...muted, fontSize: 11.5, marginLeft: 6, fontFamily: "ui-monospace,monospace" }}>{mi.signature}</span>}
              </div>
              {mi.needs.map((kind) => {
                const present = presentKinds.has(kind);
                const meta = kindMeta(kind);
                return (
                  <div key={kind} style={{ fontSize: 12.5, padding: "1px 0", color: present ? C.warn : "var(--fg,#e6edf3)" }}>
                    {present ? "⚠" : "○"} {kindLabel(kind)} <span style={muted}>— {modalityLabel(meta.modality).toLowerCase()}</span>
                    {present && <span style={{ color: C.warn, fontSize: 11.5 }}> (present, did not qualify)</span>}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      )}

      {/* engine wording — Debug View only (engine vocabulary stays out of Operator) */}
      {view === "debug" && (
        <div style={{ ...muted, fontSize: 12.5, borderTop: "1px solid var(--border,#2a2f3a)", paddingTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
          <div>
            {grounded
              ? `Engine grounded ${timeline.edges.length} causal edge${timeline.edges.length === 1 ? "" : "s"} across ${attachedModalities} plane${attachedModalities === 1 ? "" : "s"}; ${c.attached} of ${c.total} window signals linked into the graph.`
              : `Singleton — opened on a single high-severity episode; no grounded cross-evidence.`}
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {Object.entries(c.by_status ?? {}).sort().map(([k, v]) => (
              <span key={k} style={{ border: "1px solid var(--border,#2a2f3a)", borderRadius: 4, padding: "0 6px" }}>
                <b style={{ color: "var(--fg,#e6edf3)" }}>{v}</b> {k}
              </span>
            ))}
            <span>{observers} distinct observer{observers === 1 ? "" : "s"} on linked evidence</span>
            {grounded && <span>grounding: {Object.entries(c.by_grounding ?? {}).map(([k, v]) => `${v} ${k}`).join(" · ")}</span>}
          </div>
          {seamRefs.map((ref) => {
            const s = seams[ref];
            return (
              <div key={ref} style={{ fontFamily: "ui-monospace,monospace", overflowWrap: "anywhere" }}>
                ◆ {ref}{s ? ` — owner ${s.control_plane_owner} · visibility ${s.visibility}${s.display_name ? ` · ${s.display_name}` : ""}` : " — seam metadata unavailable (file backend)"}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
