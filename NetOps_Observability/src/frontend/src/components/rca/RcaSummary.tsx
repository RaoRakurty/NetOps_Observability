import { useMemo, useState } from "react";
import { CorrTimeline, Seam } from "../../services/api";
import {
  C, MODALITY_META, MODALITY_ORDER, modalityLabel,
  signatureName, kindMeta, kindLabel, entityLabel, ownerLabel,
} from "./labels";
import { episodeEntity } from "./SeamGraph";

// hex+alpha tint helper for calm severity backgrounds.
const tint = (hex: string, a = "1f") => hex + a;

// RcaSummary — the operator-facing RCA story (not an engine dump). Leads with a
// precise plain-English sentence, then a clean header, a mini seam preview, per-
// plane diagnostic coverage, and an actionable "what would corroborate this"
// list. Engine wording lives under "Why?" / Debug view. Read-only.

type Quality = "strong" | "candidate" | "weak/noisy";
const QUALITY_TONE: Record<Quality, string> = {
  strong: C.ok, candidate: C.warn, "weak/noisy": C.faint,
};
const VERDICT_TONE: Record<string, string> = {
  confirmed: C.crit, suspected: C.warn, undetermined: C.faint,
};

// A high-contrast filled badge (operator-readable across a room).
function strongBadge(tone: string): React.CSSProperties {
  return {
    fontSize: 11.5, fontWeight: 800, letterSpacing: 0.4, padding: "2px 9px",
    borderRadius: 5, color: "#0E1320", background: tone, lineHeight: 1.4,
    whiteSpace: "nowrap",
  };
}

// Coverage-card semantics (operator legend).
const COV = {
  linked: { color: C.ok, bg: tint(C.ok) },          // green — linked evidence
  present: { color: C.info, bg: tint(C.info) },      // blue — present, not linked
  absent: { color: C.faint, bg: "transparent" },     // gray — absent
  required: { color: C.warn, bg: tint(C.warn) },     // amber — missing & required
};

// seam_type → friendly story phrase when no signature has matched yet.
const SEAM_STORY: Record<string, string> = {
  DIA: "ISP / DIA egress latency",
  DX: "DX path degradation",
  VPN: "VPN tunnel degradation",
  SDWAN: "SD-WAN overlay degradation",
  CLOUD_BACKBONE: "cloud backbone degradation",
};

// absent plane → the concrete evidence that would corroborate it (operator action).
const PLANE_SUGGEST: Record<string, string> = {
  device_telemetry: "WAN interface errors / discards / utilization",
  control_plane: "BGP / link-state / syslog event",
  passive_flow: "flow loss / drop on the path",
  active_probe: "probe RTT / loss from an independent vantage",
};

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
  timeline, seams, view, state, version, nodeCount, recommendedSteps = [], owner = "",
}: {
  timeline: CorrTimeline;
  seams: Record<string, Seam>;
  view: "operator" | "debug";
  state: string;
  version: number;
  nodeCount: number;
  recommendedSteps?: string[];
  owner?: string;
}) {
  const c = timeline.counts;
  const [showWhy, setShowWhy] = useState(false);
  const muted: React.CSSProperties = { color: C.muted };

  const presentKinds = useMemo(() => {
    const s = new Set<string>();
    for (const sig of timeline.signals) if (!sig.kind.endsWith("_clear")) s.add(sig.kind);
    return s;
  }, [timeline.signals]);

  const attachedModalities = useMemo(
    () => Object.entries(c.attached_by_modality ?? {}).filter(([, v]) => v > 0).length,
    [c.attached_by_modality],
  );
  const grounded = timeline.edges.length > 0;
  const confirmed = timeline.verdict_tier === "confirmed";
  const crossPlane = attachedModalities >= 2;
  const observers = c.attached_observers ?? 0;
  const probeOnly = useMemo(() => {
    const present = Object.entries(c.attached_by_modality ?? {}).filter(([, v]) => v > 0).map(([k]) => k);
    return present.length === 1 && present[0] === "active_probe";
  }, [c.attached_by_modality]);

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
    const by = c.attached_by_modality && Object.values(c.attached_by_modality).some((v) => v > 0)
      ? c.attached_by_modality : c.by_modality;
    return Object.entries(by ?? {}).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "active_probe";
  }, [c.attached_by_modality, c.by_modality]);

  // planes with NO linked evidence (candidates to corroborate)
  const missingPlanes = useMemo(
    () => MODALITY_ORDER.filter((m) => (c.attached_by_modality?.[m] ?? 0) === 0),
    [c.attached_by_modality],
  );
  const requiredModalities = useMemo(() => {
    const s = new Set<string>();
    for (const mi of missing) for (const k of mi.needs) s.add(kindMeta(k).modality);
    return s;
  }, [missing]);

  // ---- the plain-English RCA sentence (precise about corroboration) ----------
  const narrative = useMemo(() => {
    const domLabel = modalityLabel(dominant).toLowerCase();
    const story = timeline.top_hypothesis !== "undetermined"
      ? signatureName(timeline.top_hypothesis)
      : primarySeam
        ? (SEAM_STORY[primarySeam.seam_type ?? ""] ?? `${primarySeam.control_plane_owner.toUpperCase()} / ${primarySeam.seam_type ?? "seam"} degradation`)
        : `${domLabel} degradation`;
    const conn = primarySeam ? "across" : "on";
    const seamPhrase = primarySeam
      ? `a ${primarySeam.visibility} ${primarySeam.control_plane_owner.toUpperCase()}/${primarySeam.seam_type ?? "seam"} boundary`
      : grounded
        ? "the same local topology context"
        : "no grounded boundary";
    const otherPlanes = missingPlanes.filter((m) => m !== "active_probe").map((m) => modalityLabel(m).toLowerCase());
    let tail: string;
    if (confirmed) {
      tail = "and independent cross-plane evidence corroborates it.";
    } else if (crossPlane) {
      tail = `with partial corroboration across ${attachedModalities} planes, pending confirmation.`;
    } else {
      tail = otherPlanes.length
        ? `but no ${orList(otherPlanes)} evidence corroborates it yet.`
        : "but the evidence has not yet cleared the confirmation bar.";
    }
    const qual = quality === "weak/noisy" ? "weak" : quality;
    const noun = c.attached === 1 ? "anomaly" : "anomalies";
    return `This appears to be a ${qual} ${story} candidate. `
      + `The engine linked ${c.attached} ${domLabel} ${noun} ${conn} ${seamPhrase}, ${tail}`;
  }, [quality, timeline.top_hypothesis, primarySeam, grounded, dominant, c, confirmed, crossPlane, attachedModalities, missingPlanes]);

  const card: React.CSSProperties = {
    border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "12px 14px",
    background: "var(--panel,#11151c)", display: "flex", flexDirection: "column", gap: 12,
    minWidth: 0, maxWidth: "100%", overflow: "hidden",
  };
  const title: React.CSSProperties = { fontWeight: 600, fontSize: 12 };
  const chip: React.CSSProperties = {
    fontFamily: "ui-monospace, monospace", fontSize: 12.5, background: "var(--bg,#0d1117)",
    padding: "1px 6px", borderRadius: 4, overflowWrap: "anywhere", minWidth: 0,
  };

  // corroboration suggestions = absent non-probe planes (what to add to confirm)
  const corroborate = missingPlanes.filter((m) => m !== "active_probe" && (c.by_modality?.[m] ?? 0) === 0);
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

  // planes that actually carry linked evidence (for "why suspected")
  const attachedPlaneLabels = MODALITY_ORDER
    .filter((m) => (c.attached_by_modality?.[m] ?? 0) > 0)
    .map((m) => modalityLabel(m).toLowerCase());
  const whyNotConfirmed = probe.lowOnly
    ? "the only evidence is low-authority probes — needs an independent, trusted modality (device telemetry, control plane, or flow)."
    : corroborate.length
      ? `missing an independent ${orList(corroborate.map((p) => modalityLabel(p).toLowerCase()))} witness.`
      : "needs a second independent modality to corroborate.";

  return (
    <div style={card}>
      {/* clean header — stronger verdict + quality badges */}
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <span style={{ fontSize: 14, fontWeight: 700 }}>RCA Candidate</span>
        <span style={{ ...strongBadge(QUALITY_TONE[quality]) }}>
          {quality === "weak/noisy" ? "WEAK" : quality.toUpperCase()}
        </span>
        <span style={{ ...strongBadge(VERDICT_TONE[timeline.verdict_tier] ?? C.faint), textTransform: "uppercase" }}>
          {timeline.verdict_tier}
        </span>
        <span style={{ ...muted, fontSize: 12.5, marginLeft: "auto" }}>
          {state === "open" ? "Open" : "Closed"} · v{version} · {nodeCount} node{nodeCount === 1 ? "" : "s"} · {timeline.edges.length} grounded edge{timeline.edges.length === 1 ? "" : "s"}
        </span>
      </div>

      {/* the precise plain-English story */}
      <div style={{ fontSize: 14.5, lineHeight: 1.55, color: C.fg }}>{narrative}</div>

      {/* why suspected / why not confirmed — makes the verdict trustable */}
      {timeline.verdict_tier === "suspected" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 3, fontSize: 12.5, borderLeft: `3px solid ${C.warn}`, paddingLeft: 8 }}>
          {timeline.top_hypothesis !== "undetermined" && (
            <div><b style={{ color: C.warn }}>Why suspected:</b> matched part of the <b>{signatureName(timeline.top_hypothesis)}</b> signature using {attachedPlaneLabels.length ? attachedPlaneLabels.join(" + ") : "the available"} evidence.</div>
          )}
          <div><b style={{ color: C.warn }}>Why not confirmed:</b> {whyNotConfirmed}</div>
        </div>
      )}
      {probeOnly && (
        <div style={{ fontSize: 12.5, color: C.warn }}>⚠ Single-plane probe evidence only — not yet a cross-plane corroborated RCA.</div>
      )}
      {probe.lowOnly && (
        <div style={{ fontSize: 12.5, color: C.warn }}>
          ⚠ Probe evidence is low-authority (self / internal / unclassified) — supports a suspicion but <b>cannot confirm</b> without an independent, non-fate-shared trusted modality.
        </div>
      )}
      {probe.debugExcluded > 0 && (
        <div style={{ fontSize: 12.5, color: C.faint }}>
          {probe.debugExcluded} debug / lab probe{probe.debugExcluded === 1 ? "" : "s"} excluded from this verdict (shown in the timeline for context only).
        </div>
      )}

      {/* mini seam/topo graph preview — above the fold */}
      {grounded && (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {[...timeline.edges].sort((a, b) => (a.grounding_kind === "seam" ? -1 : 1) - (b.grounding_kind === "seam" ? -1 : 1)).slice(0, 3).map((e, i) => {
            const s = e.grounding_kind === "seam" ? seams[e.grounding_ref] : undefined;
            return (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12.5, flexWrap: "wrap", minWidth: 0 }}>
                <span style={chip}>{view === "debug" ? episodeEntity(e.from_node) : entityLabel(episodeEntity(e.from_node))}</span>
                <span style={muted}>──</span>
                <span style={{
                  background: e.grounding_kind === "seam" ? tint(C.warn, "22") : tint(C.faint, "22"),
                  border: `1px solid ${e.grounding_kind === "seam" ? tint(C.warn, "66") : tint(C.faint, "66")}`,
                  borderRadius: 4, padding: "1px 6px", fontWeight: 600,
                  color: e.grounding_kind === "seam" ? C.warn : C.muted,
                }} title={e.grounding_ref}>
                  {e.grounding_kind === "seam" ? `◆ ${s ? `${s.control_plane_owner.toUpperCase()} · ${s.visibility}` : "ownership boundary"}` : "topology"}
                </span>
                <span style={muted}>──</span>
                <span style={chip}>{view === "debug" ? episodeEntity(e.to_node) : entityLabel(episodeEntity(e.to_node))}</span>
              </div>
            );
          })}
        </div>
      )}

      {/* recommended next action (from the matched signature's playbook) */}
      {recommendedSteps.length > 0 && (
        <div style={{ border: `1px solid ${C.info}55`, background: tint(C.info, "14"), borderRadius: 6, padding: "8px 10px" }}>
          <div style={{ ...title, color: C.info }}>
            Recommended next action{owner ? <span style={{ ...muted, fontWeight: 400 }}> · likely owner: <b style={{ color: C.fg }}>{ownerLabel(owner)}</b></span> : null}
          </div>
          <ol style={{ margin: "4px 0 0", paddingLeft: 18, fontSize: 12.5, lineHeight: 1.5 }}>
            {recommendedSteps.slice(0, 3).map((s, i) => <li key={i}>{s}</li>)}
          </ol>
        </div>
      )}

      {/* per-plane diagnostic coverage — strong state badges */}
      <div>
        <div style={title}>Evidence coverage by plane</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 8, marginTop: 6 }}>
          {MODALITY_ORDER.map((key) => {
            const total = c.by_modality?.[key] ?? 0;
            const att = c.attached_by_modality?.[key] ?? 0;
            const isProbe = key === "active_probe";
            const lowAuthProbe = isProbe && att > 0 && !probe.hasConfirmProbe;
            const debugExcludedHere = isProbe && total > att && probe.debugExcluded > 0;
            // state → {tone, label}
            let tone: string = COV.absent.color, badge = "ABSENT", bg = "transparent";
            if (att > 0 && lowAuthProbe) { tone = C.warn; badge = "USED · LOW-AUTH"; bg = tint(C.warn); }
            else if (att > 0) { tone = C.ok; badge = "USED"; bg = tint(C.ok); }
            else if (total > 0) { tone = C.info; badge = "PRESENT · NOT LINKED"; bg = tint(C.info); }
            else if (requiredModalities.has(key)) { tone = C.warn; badge = "MISSING · REQUIRED"; bg = tint(C.warn); }
            return (
              <div key={key} style={{ border: `1px solid ${tone}77`, background: bg, borderRadius: 6, padding: "7px 9px", minWidth: 0 }}>
                <div style={{ fontSize: 12.5, display: "flex", alignItems: "center", gap: 6, fontWeight: 600 }}>
                  <span style={{ width: 9, height: 9, borderRadius: 2, background: MODALITY_META[key].color, display: "inline-block" }} />
                  {modalityLabel(key)}
                </div>
                <div style={{ fontSize: 13.5, marginTop: 3 }}>
                  {total > 0
                    ? <><b style={{ color: tone }}>{att}</b> <span style={muted}>linked / {total} in window</span></>
                    : <span style={muted}>0 signals</span>}
                </div>
                <div style={{ marginTop: 4, display: "flex", gap: 5, flexWrap: "wrap" }}>
                  <span style={strongBadge(tone)}>{badge}</span>
                  {debugExcludedHere && <span style={strongBadge(C.faint)}>DEBUG EXCLUDED</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* what would upgrade — actionable */}
      {(corroborate.length > 0 || clauseItems.length > 0) && (
        <div>
          <div style={title}>What would {confirmed ? "strengthen" : "upgrade"} this verdict</div>

          {/* actionable corroboration from absent planes (the common case) */}
          {corroborate.length > 0 && (
            <div style={{ marginTop: 4 }}>
              <div style={{ ...muted, fontSize: 12.5 }}>Add corroborating evidence from another plane:</div>
              {corroborate.map((p) => (
                <div key={p} style={{ fontSize: 12.5, padding: "1px 0" }}>
                  ○ {PLANE_SUGGEST[p]} <span style={muted}>— {modalityLabel(p).toLowerCase()}</span>
                </div>
              ))}
            </div>
          )}

          {/* specific signature clause gaps (cloud/dns-style look-alikes) */}
          {clauseItems.map((mi, i) => (
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

      {/* engine wording — expandable in operator, always-on in debug */}
      {view === "operator" && (
        <button onClick={() => setShowWhy((v) => !v)} style={{
          alignSelf: "flex-start", background: "none", border: "none", color: "var(--accent,#4c8dff)",
          fontSize: 12, cursor: "pointer", padding: 0,
        }}>{showWhy ? "Hide engine detail ▲" : "Why? (engine detail) ▼"}</button>
      )}
      {(view === "debug" || showWhy) && (
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
